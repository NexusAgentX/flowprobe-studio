use std::collections::BTreeMap;

use flowprobe_model::{
    HttpRequestMetadata, HttpResponseMetadata, HttpStatus, HttpTransactionMetadata,
};

use crate::{CaptureError, CaptureLimits, HttpSide};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FLAG_ACK: u8 = 0x01;
const FLAG_END_STREAM: u8 = 0x01;
const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;

pub(crate) fn is_client_preface(input: &[u8]) -> bool {
    input.starts_with(CLIENT_PREFACE)
}

pub(crate) fn decode(
    client: &[u8],
    server: &[u8],
    limits: &CaptureLimits,
) -> Result<HttpTransactionMetadata, CaptureError> {
    let request_side = decode_direction(
        &client[CLIENT_PREFACE.len()..],
        HttpSide::Request,
        None,
        limits,
    )?;
    let request_headers = request_side
        .headers
        .as_ref()
        .ok_or(CaptureError::MalformedHttp2(
            "request HEADERS frame is missing",
        ))?;
    let request = request_metadata(&request_headers.fields, request_side.body_bytes)?;

    let response_side = decode_direction(
        server,
        HttpSide::Response,
        Some(request_headers.stream_id),
        limits,
    )?;
    let response = response_side
        .headers
        .as_ref()
        .map(|headers| {
            response_metadata(&headers.fields, response_side.body_bytes, &request.method)
        })
        .transpose()?;

    Ok(HttpTransactionMetadata {
        stream_id: Some(u64::from(request_headers.stream_id)),
        request,
        response,
        extensions: BTreeMap::new(),
    })
}

struct ParsedDirection {
    headers: Option<HeaderBlock>,
    body_bytes: u64,
}

struct HeaderBlock {
    stream_id: u32,
    fields: Vec<HeaderField>,
}

struct HeaderField {
    name: Vec<u8>,
    value: Vec<u8>,
}

fn decode_direction(
    input: &[u8],
    side: HttpSide,
    expected_stream: Option<u32>,
    limits: &CaptureLimits,
) -> Result<ParsedDirection, CaptureError> {
    let mut remaining = input;
    let mut frame_count = 0usize;
    let mut headers: Option<HeaderBlock> = None;
    let mut body_bytes = 0u64;
    let mut stream_ended = false;
    while !remaining.is_empty() {
        frame_count = frame_count
            .checked_add(1)
            .ok_or(CaptureError::SizeOverflow("HTTP/2 frame count"))?;
        if frame_count > limits.max_http2_frames {
            return Err(CaptureError::Http2FrameLimitExceeded {
                limit: limits.max_http2_frames,
            });
        }
        if remaining.len() < 9 {
            return Err(CaptureError::MalformedHttp2("truncated frame header"));
        }
        let payload_length = read_u24(&remaining[..3]);
        if payload_length > limits.max_http2_frame_payload_bytes {
            return Err(CaptureError::Http2FramePayloadLimitExceeded {
                declared: payload_length,
                limit: limits.max_http2_frame_payload_bytes,
            });
        }
        let frame_length = 9usize
            .checked_add(payload_length)
            .ok_or(CaptureError::SizeOverflow("HTTP/2 frame"))?;
        if remaining.len() < frame_length {
            return Err(CaptureError::TruncatedHttp2Frame {
                declared: payload_length,
                available: remaining.len() - 9,
            });
        }

        let frame_type = remaining[3];
        let flags = remaining[4];
        let raw_stream_id =
            u32::from_be_bytes([remaining[5], remaining[6], remaining[7], remaining[8]]);
        if raw_stream_id & 0x8000_0000 != 0 {
            return Err(CaptureError::MalformedHttp2(
                "reserved stream identifier bit is set",
            ));
        }
        let stream_id = raw_stream_id;
        let payload = &remaining[9..frame_length];
        if frame_count == 1 && (frame_type != 4 || flags & FLAG_ACK != 0) {
            return Err(CaptureError::MalformedHttp2(
                "connection preface is not followed by initial SETTINGS",
            ));
        }
        match frame_type {
            0 => {
                if stream_ended {
                    return Err(CaptureError::MalformedHttp2(
                        "DATA frame follows END_STREAM",
                    ));
                }
                validate_data_stream(stream_id, expected_stream, headers.as_ref())?;
                let data = unpad_payload(payload, flags)?;
                body_bytes = body_bytes
                    .checked_add(
                        u64::try_from(data.len())
                            .map_err(|_| CaptureError::SizeOverflow("HTTP/2 DATA payload"))?,
                    )
                    .ok_or(CaptureError::SizeOverflow("HTTP/2 body"))?;
                if body_bytes > limits.max_http_body_bytes as u64 {
                    return Err(CaptureError::HttpBodyLimitExceeded {
                        side,
                        declared: usize::try_from(body_bytes).unwrap_or(usize::MAX),
                        limit: limits.max_http_body_bytes,
                    });
                }
                if flags & FLAG_END_STREAM != 0 {
                    stream_ended = true;
                }
            }
            1 => {
                if stream_id == 0 {
                    return Err(CaptureError::MalformedHttp2(
                        "HEADERS frame uses stream zero",
                    ));
                }
                if expected_stream.is_some_and(|expected| expected != stream_id) {
                    return Err(CaptureError::UnsupportedHttp2(
                        "response on a different stream",
                    ));
                }
                if side == HttpSide::Request && stream_id.is_multiple_of(2) {
                    return Err(CaptureError::MalformedHttp2(
                        "client request uses an even stream identifier",
                    ));
                }
                if headers.is_some() {
                    return Err(CaptureError::UnsupportedHttp2(
                        "trailers or multiple transactions",
                    ));
                }
                if flags & FLAG_END_HEADERS == 0 {
                    return Err(CaptureError::UnsupportedHttp2("HEADERS continuation"));
                }
                let block = headers_payload(payload, flags)?;
                headers = Some(HeaderBlock {
                    stream_id,
                    fields: decode_hpack(block, side, limits)?,
                });
                if flags & FLAG_END_STREAM != 0 {
                    stream_ended = true;
                }
            }
            4 => validate_settings_frame(stream_id, flags, payload)?,
            9 => {
                return Err(CaptureError::UnsupportedHttp2(
                    "standalone CONTINUATION frame",
                ));
            }
            _ => {}
        }
        remaining = &remaining[frame_length..];
    }

    if headers.is_some() && !stream_ended {
        return Err(CaptureError::UnsupportedHttp2(
            "incomplete stream without END_STREAM",
        ));
    }

    Ok(ParsedDirection {
        headers,
        body_bytes,
    })
}

fn validate_data_stream(
    stream_id: u32,
    expected_stream: Option<u32>,
    headers: Option<&HeaderBlock>,
) -> Result<(), CaptureError> {
    if stream_id == 0 {
        return Err(CaptureError::MalformedHttp2("DATA frame uses stream zero"));
    }
    let Some(headers) = headers else {
        return Err(CaptureError::MalformedHttp2(
            "DATA frame precedes request or response HEADERS",
        ));
    };
    if headers.stream_id != stream_id
        || expected_stream.is_some_and(|expected| expected != stream_id)
    {
        return Err(CaptureError::UnsupportedHttp2(
            "DATA for multiple transactions",
        ));
    }
    Ok(())
}

fn validate_settings_frame(stream_id: u32, flags: u8, payload: &[u8]) -> Result<(), CaptureError> {
    if stream_id != 0 {
        return Err(CaptureError::MalformedHttp2(
            "SETTINGS frame uses a non-zero stream",
        ));
    }
    if flags & FLAG_ACK != 0 && !payload.is_empty() {
        return Err(CaptureError::MalformedHttp2(
            "acknowledged SETTINGS frame has a payload",
        ));
    }
    if !payload.len().is_multiple_of(6) {
        return Err(CaptureError::MalformedHttp2(
            "SETTINGS payload is not a sequence of six-byte parameters",
        ));
    }
    Ok(())
}

fn headers_payload(payload: &[u8], flags: u8) -> Result<&[u8], CaptureError> {
    let (padding, mut start) = if flags & FLAG_PADDED != 0 {
        let Some(padding) = payload.first().copied() else {
            return Err(CaptureError::MalformedHttp2(
                "padded HEADERS frame has no pad length",
            ));
        };
        (usize::from(padding), 1usize)
    } else {
        (0usize, 0usize)
    };
    if flags & FLAG_PRIORITY != 0 {
        start = start
            .checked_add(5)
            .ok_or(CaptureError::SizeOverflow("HTTP/2 HEADERS prefix"))?;
    }
    let end = payload
        .len()
        .checked_sub(padding)
        .ok_or(CaptureError::MalformedHttp2(
            "HEADERS padding exceeds payload",
        ))?;
    if start > end {
        return Err(CaptureError::MalformedHttp2(
            "HEADERS prefix exceeds payload",
        ));
    }
    Ok(&payload[start..end])
}

fn unpad_payload(payload: &[u8], flags: u8) -> Result<&[u8], CaptureError> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload);
    }
    let Some(padding) = payload.first().copied() else {
        return Err(CaptureError::MalformedHttp2(
            "padded DATA frame has no pad length",
        ));
    };
    let end = payload
        .len()
        .checked_sub(usize::from(padding))
        .ok_or(CaptureError::MalformedHttp2("DATA padding exceeds payload"))?;
    if end < 1 {
        return Err(CaptureError::MalformedHttp2(
            "DATA padding leaves no pad length byte",
        ));
    }
    Ok(&payload[1..end])
}

fn decode_hpack(
    block: &[u8],
    side: HttpSide,
    limits: &CaptureLimits,
) -> Result<Vec<HeaderField>, CaptureError> {
    let mut cursor = 0usize;
    let mut fields = Vec::new();
    let mut decoded_bytes = 0usize;
    let mut regular_header_seen = false;
    while cursor < block.len() {
        let first = block[cursor];
        if first & 0x80 != 0 {
            let index = decode_integer(block, &mut cursor, 7)?;
            let (name, value) = static_header(index).ok_or(CaptureError::UnsupportedHpack(
                "dynamic or zero indexed header",
            ))?;
            push_header(
                &mut fields,
                name.to_vec(),
                value.to_vec(),
                side,
                limits,
                &mut decoded_bytes,
                &mut regular_header_seen,
            )?;
        } else if first & 0x40 != 0 {
            let name = decode_name(block, &mut cursor, 6, limits)?;
            let value = decode_string(block, &mut cursor, limits)?;
            push_header(
                &mut fields,
                name,
                value,
                side,
                limits,
                &mut decoded_bytes,
                &mut regular_header_seen,
            )?;
        } else if first & 0x20 != 0 {
            let size = decode_integer(block, &mut cursor, 5)?;
            if size > limits.max_hpack_dynamic_table_bytes {
                return Err(CaptureError::UnsupportedHpack(
                    "dynamic table size exceeds configured limit",
                ));
            }
        } else {
            let name = decode_name(block, &mut cursor, 4, limits)?;
            let value = decode_string(block, &mut cursor, limits)?;
            push_header(
                &mut fields,
                name,
                value,
                side,
                limits,
                &mut decoded_bytes,
                &mut regular_header_seen,
            )?;
        }
    }
    Ok(fields)
}

#[allow(clippy::too_many_arguments)]
fn push_header(
    fields: &mut Vec<HeaderField>,
    name: Vec<u8>,
    value: Vec<u8>,
    side: HttpSide,
    limits: &CaptureLimits,
    decoded_bytes: &mut usize,
    regular_header_seen: &mut bool,
) -> Result<(), CaptureError> {
    if fields.len() >= limits.max_http_headers {
        return Err(CaptureError::HttpHeaderCountLimitExceeded {
            side,
            limit: limits.max_http_headers,
        });
    }
    let name_without_pseudo_prefix = name.strip_prefix(b":").unwrap_or(&name);
    if name_without_pseudo_prefix.is_empty()
        || name_without_pseudo_prefix
            .iter()
            .any(|byte| byte.is_ascii_uppercase() || !is_h2_name_byte(*byte))
    {
        return Err(CaptureError::MalformedHttp2("invalid HTTP/2 header name"));
    }
    if name.starts_with(b":") {
        let known_for_side = match side {
            HttpSide::Request => matches!(
                name.as_slice(),
                b":method" | b":scheme" | b":authority" | b":path" | b":protocol"
            ),
            HttpSide::Response => name == b":status",
        };
        if !known_for_side {
            return Err(CaptureError::MalformedHttp2(
                "unknown or misplaced pseudo-header",
            ));
        }
        if *regular_header_seen {
            return Err(CaptureError::MalformedHttp2(
                "pseudo-header follows a regular header",
            ));
        }
    } else {
        *regular_header_seen = true;
    }
    *decoded_bytes = decoded_bytes
        .checked_add(name.len())
        .and_then(|length| length.checked_add(value.len()))
        .ok_or(CaptureError::SizeOverflow("HTTP/2 header list"))?;
    if *decoded_bytes > limits.max_http_header_bytes {
        return Err(CaptureError::HttpHeaderBytesLimitExceeded {
            side,
            limit: limits.max_http_header_bytes,
        });
    }
    fields.push(HeaderField { name, value });
    Ok(())
}

fn decode_name(
    block: &[u8],
    cursor: &mut usize,
    prefix: u8,
    limits: &CaptureLimits,
) -> Result<Vec<u8>, CaptureError> {
    let index = decode_integer(block, cursor, prefix)?;
    if index == 0 {
        decode_string(block, cursor, limits)
    } else {
        static_header(index)
            .map(|(name, _)| name.to_vec())
            .ok_or(CaptureError::UnsupportedHpack(
                "dynamic indexed header name",
            ))
    }
}

fn decode_integer(input: &[u8], cursor: &mut usize, prefix: u8) -> Result<usize, CaptureError> {
    let Some(first) = input.get(*cursor).copied() else {
        return Err(CaptureError::MalformedHttp2("truncated HPACK integer"));
    };
    let mask = (1u8 << prefix) - 1;
    let mut value = usize::from(first & mask);
    *cursor = cursor
        .checked_add(1)
        .ok_or(CaptureError::HpackIntegerOverflow)?;
    if value < usize::from(mask) {
        return Ok(value);
    }

    let mut shift = 0u32;
    loop {
        let Some(byte) = input.get(*cursor).copied() else {
            return Err(CaptureError::MalformedHttp2("truncated HPACK integer"));
        };
        *cursor = cursor
            .checked_add(1)
            .ok_or(CaptureError::HpackIntegerOverflow)?;
        let component = usize::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(CaptureError::HpackIntegerOverflow)?;
        value = value
            .checked_add(component)
            .ok_or(CaptureError::HpackIntegerOverflow)?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift = shift
            .checked_add(7)
            .filter(|shift| *shift < usize::BITS)
            .ok_or(CaptureError::HpackIntegerOverflow)?;
    }
}

fn decode_string(
    input: &[u8],
    cursor: &mut usize,
    limits: &CaptureLimits,
) -> Result<Vec<u8>, CaptureError> {
    let huffman = input.get(*cursor).is_some_and(|first| first & 0x80 != 0);
    let length = decode_integer(input, cursor, 7)?;
    if length > limits.max_hpack_string_bytes {
        return Err(CaptureError::HpackStringLimitExceeded {
            declared: length,
            limit: limits.max_hpack_string_bytes,
        });
    }
    let end = cursor
        .checked_add(length)
        .ok_or(CaptureError::SizeOverflow("HPACK string"))?;
    let value = input
        .get(*cursor..end)
        .ok_or(CaptureError::MalformedHttp2("truncated HPACK string"))?;
    *cursor = end;
    if huffman {
        return Err(CaptureError::UnsupportedHpack(
            "Huffman-coded string in the minimum v0 path",
        ));
    }
    Ok(value.to_vec())
}

fn request_metadata(
    fields: &[HeaderField],
    byte_count: u64,
) -> Result<HttpRequestMetadata, CaptureError> {
    let method = required_unique_text(fields, b":method", HttpSide::Request, "method")?;
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err(CaptureError::UnsupportedHttp2(
            "CONNECT request in the minimum v0 path",
        ));
    }
    let path = required_unique_text(fields, b":path", HttpSide::Request, "path")?;
    let scheme = required_unique_text(fields, b":scheme", HttpSide::Request, "scheme")?;
    let authority = optional_unique_text(fields, b":authority", HttpSide::Request, "authority")?
        .or(optional_unique_text(
            fields,
            b"host",
            HttpSide::Request,
            "host",
        )?)
        .ok_or(CaptureError::MalformedHttp2("request authority is missing"))?;
    let content_type =
        optional_unique_text(fields, b"content-type", HttpSide::Request, "content-type")?;
    validate_content_length(fields, byte_count, HttpSide::Request)?;
    Ok(HttpRequestMetadata {
        method,
        scheme,
        authority,
        path,
        version: "HTTP/2".to_owned(),
        content_type,
        byte_count,
        body_ref: None,
        extensions: BTreeMap::new(),
    })
}

fn response_metadata(
    fields: &[HeaderField],
    byte_count: u64,
    request_method: &str,
) -> Result<HttpResponseMetadata, CaptureError> {
    let status = required_unique_text(fields, b":status", HttpSide::Response, "status")?;
    let status = status
        .parse::<u16>()
        .map_err(|_| CaptureError::MalformedHttp2("invalid response status"))?;
    if (100..=199).contains(&status) {
        return Err(CaptureError::UnsupportedHttp2(
            "informational response in the minimum v0 path",
        ));
    }
    let head_response = request_method.eq_ignore_ascii_case("HEAD");
    if byte_count != 0 && (head_response || matches!(status, 204 | 304)) {
        return Err(CaptureError::MalformedHttp2(
            "response semantics forbid a message body",
        ));
    }
    if !head_response && status != 304 {
        validate_content_length(fields, byte_count, HttpSide::Response)?;
    }
    let content_type =
        optional_unique_text(fields, b"content-type", HttpSide::Response, "content-type")?;
    Ok(HttpResponseMetadata {
        status: HttpStatus::new(status)?,
        version: "HTTP/2".to_owned(),
        content_type,
        byte_count,
        body_ref: None,
        extensions: BTreeMap::new(),
    })
}

fn validate_content_length(
    fields: &[HeaderField],
    byte_count: u64,
    side: HttpSide,
) -> Result<(), CaptureError> {
    let Some(value) = optional_unique_text(fields, b"content-length", side, "content-length")?
    else {
        return Ok(());
    };
    let declared = value
        .parse::<u64>()
        .map_err(|_| CaptureError::MalformedHttp2("invalid content-length"))?;
    if declared != byte_count {
        return Err(CaptureError::MalformedHttp2(
            "content-length does not match DATA payload bytes",
        ));
    }
    Ok(())
}

fn required_unique_text(
    fields: &[HeaderField],
    name: &[u8],
    side: HttpSide,
    field: &'static str,
) -> Result<String, CaptureError> {
    optional_unique_text(fields, name, side, field)?.ok_or(CaptureError::MalformedHttp2(
        "required pseudo-header is missing",
    ))
}

fn optional_unique_text(
    fields: &[HeaderField],
    name: &[u8],
    _side: HttpSide,
    field: &'static str,
) -> Result<Option<String>, CaptureError> {
    let mut value = None;
    for header in fields.iter().filter(|header| header.name == name) {
        if value.is_some() {
            return Err(CaptureError::MalformedHttp2("duplicate singleton header"));
        }
        let text = std::str::from_utf8(&header.value).map_err(|_| CaptureError::InvalidText {
            protocol: "HTTP/2",
            field,
        })?;
        if text.is_empty() {
            return Err(CaptureError::MalformedHttp2(
                "empty required metadata header",
            ));
        }
        value = Some(text.to_owned());
    }
    Ok(value)
}

fn read_u24(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

fn is_h2_name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn static_header(index: usize) -> Option<(&'static [u8], &'static [u8])> {
    Some(match index {
        1 => (b":authority", b""),
        2 => (b":method", b"GET"),
        3 => (b":method", b"POST"),
        4 => (b":path", b"/"),
        5 => (b":path", b"/index.html"),
        6 => (b":scheme", b"http"),
        7 => (b":scheme", b"https"),
        8 => (b":status", b"200"),
        9 => (b":status", b"204"),
        10 => (b":status", b"206"),
        11 => (b":status", b"304"),
        12 => (b":status", b"400"),
        13 => (b":status", b"404"),
        14 => (b":status", b"500"),
        15 => (b"accept-charset", b""),
        16 => (b"accept-encoding", b"gzip, deflate"),
        17 => (b"accept-language", b""),
        18 => (b"accept-ranges", b""),
        19 => (b"accept", b""),
        20 => (b"access-control-allow-origin", b""),
        21 => (b"age", b""),
        22 => (b"allow", b""),
        23 => (b"authorization", b""),
        24 => (b"cache-control", b""),
        25 => (b"content-disposition", b""),
        26 => (b"content-encoding", b""),
        27 => (b"content-language", b""),
        28 => (b"content-length", b""),
        29 => (b"content-location", b""),
        30 => (b"content-range", b""),
        31 => (b"content-type", b""),
        32 => (b"cookie", b""),
        33 => (b"date", b""),
        34 => (b"etag", b""),
        35 => (b"expect", b""),
        36 => (b"expires", b""),
        37 => (b"from", b""),
        38 => (b"host", b""),
        39 => (b"if-match", b""),
        40 => (b"if-modified-since", b""),
        41 => (b"if-none-match", b""),
        42 => (b"if-range", b""),
        43 => (b"if-unmodified-since", b""),
        44 => (b"last-modified", b""),
        45 => (b"link", b""),
        46 => (b"location", b""),
        47 => (b"max-forwards", b""),
        48 => (b"proxy-authenticate", b""),
        49 => (b"proxy-authorization", b""),
        50 => (b"range", b""),
        51 => (b"referer", b""),
        52 => (b"refresh", b""),
        53 => (b"retry-after", b""),
        54 => (b"server", b""),
        55 => (b"set-cookie", b""),
        56 => (b"strict-transport-security", b""),
        57 => (b"transfer-encoding", b""),
        58 => (b"user-agent", b""),
        59 => (b"vary", b""),
        60 => (b"via", b""),
        61 => (b"www-authenticate", b""),
        _ => return None,
    })
}
