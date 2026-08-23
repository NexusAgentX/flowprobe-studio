use std::collections::BTreeMap;

use flowprobe_model::{
    DestinationMetadata, HttpRequestMetadata, HttpResponseMetadata, HttpStatus,
    HttpTransactionMetadata,
};

use crate::{CaptureContext, CaptureError, CaptureLimits, HttpSide};

pub(crate) fn looks_like_request(input: &[u8]) -> bool {
    let line = input
        .split(|byte| *byte == b'\r' || *byte == b'\n')
        .next()
        .unwrap_or_default();
    let mut parts = line.split(|byte| *byte == b' ');
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    !method.is_empty()
        && method.len() <= 32
        && method.iter().copied().all(is_http_token_byte)
        && !target.is_empty()
        && parts.next().is_none()
        && matches!(version, b"HTTP/1.0" | b"HTTP/1.1")
}

pub(crate) fn decode(
    client: &[u8],
    server: &[u8],
    context: &CaptureContext,
    is_tls: bool,
    limits: &CaptureLimits,
) -> Result<HttpTransactionMetadata, CaptureError> {
    let parsed_request = parse_request(client, context, is_tls, limits)?;
    let response = if server.is_empty() {
        None
    } else {
        Some(parse_response(
            server,
            &parsed_request.metadata.method,
            limits,
        )?)
    };
    Ok(HttpTransactionMetadata {
        stream_id: None,
        request: parsed_request.metadata,
        response,
        extensions: BTreeMap::new(),
    })
}

struct ParsedRequest {
    metadata: HttpRequestMetadata,
}

fn parse_request(
    input: &[u8],
    context: &CaptureContext,
    is_tls: bool,
    limits: &CaptureLimits,
) -> Result<ParsedRequest, CaptureError> {
    ensure_header_terminator(input, HttpSide::Request, limits.max_http_header_bytes)?;
    let mut headers = vec![httparse::EMPTY_HEADER; limits.max_http_headers];
    let mut request = httparse::Request::new(&mut headers);
    let header_end = match request.parse(input) {
        Ok(httparse::Status::Complete(length)) => length,
        Ok(httparse::Status::Partial) => {
            return Err(CaptureError::TruncatedHttpHeaders(HttpSide::Request));
        }
        Err(error) => return Err(map_httparse_error(HttpSide::Request, error, limits)),
    };
    if header_end > limits.max_http_header_bytes {
        return Err(CaptureError::HttpHeaderBytesLimitExceeded {
            side: HttpSide::Request,
            limit: limits.max_http_header_bytes,
        });
    }

    let method = request
        .method
        .ok_or(CaptureError::MalformedHttp1 {
            side: HttpSide::Request,
            reason: "missing request method",
        })?
        .to_owned();
    if method == "CONNECT" {
        return Err(CaptureError::UnsupportedHttp1Framing {
            side: HttpSide::Request,
            framing: "CONNECT tunnel in the minimum v0 path",
        });
    }
    let target = request.path.ok_or(CaptureError::MalformedHttp1 {
        side: HttpSide::Request,
        reason: "missing request target",
    })?;
    let version = request.version.ok_or(CaptureError::MalformedHttp1 {
        side: HttpSide::Request,
        reason: "missing request version",
    })?;
    let default_scheme = if is_tls { "https" } else { "http" };
    let (scheme, target_authority, path) = split_request_target(target, default_scheme)?;
    let host = optional_header_value(request.headers, "host", HttpSide::Request)?;
    let authority = target_authority
        .or(host)
        .unwrap_or_else(|| destination_authority(&context.destination, &scheme));
    if authority.trim().is_empty() {
        return Err(CaptureError::MalformedHttp1 {
            side: HttpSide::Request,
            reason: "request authority is empty",
        });
    }
    let content_type = optional_header_value(request.headers, "content-type", HttpSide::Request)?;
    let byte_count = body_byte_count(
        &input[header_end..],
        request.headers,
        HttpSide::Request,
        false,
        limits,
    )?;

    Ok(ParsedRequest {
        metadata: HttpRequestMetadata {
            method,
            scheme,
            authority,
            path,
            version: format!("HTTP/1.{version}"),
            content_type,
            byte_count,
            body_ref: None,
            extensions: BTreeMap::new(),
        },
    })
}

fn parse_response(
    input: &[u8],
    request_method: &str,
    limits: &CaptureLimits,
) -> Result<HttpResponseMetadata, CaptureError> {
    ensure_header_terminator(input, HttpSide::Response, limits.max_http_header_bytes)?;
    let mut headers = vec![httparse::EMPTY_HEADER; limits.max_http_headers];
    let mut response = httparse::Response::new(&mut headers);
    let header_end = match response.parse(input) {
        Ok(httparse::Status::Complete(length)) => length,
        Ok(httparse::Status::Partial) => {
            return Err(CaptureError::TruncatedHttpHeaders(HttpSide::Response));
        }
        Err(error) => return Err(map_httparse_error(HttpSide::Response, error, limits)),
    };
    if header_end > limits.max_http_header_bytes {
        return Err(CaptureError::HttpHeaderBytesLimitExceeded {
            side: HttpSide::Response,
            limit: limits.max_http_header_bytes,
        });
    }

    let status = response.code.ok_or(CaptureError::MalformedHttp1 {
        side: HttpSide::Response,
        reason: "missing response status",
    })?;
    if (100..200).contains(&status) {
        return Err(CaptureError::UnsupportedHttp1Framing {
            side: HttpSide::Response,
            framing: "informational response sequence in the minimum v0 path",
        });
    }
    let status = HttpStatus::new(status)?;
    let version = response.version.ok_or(CaptureError::MalformedHttp1 {
        side: HttpSide::Response,
        reason: "missing response version",
    })?;
    let content_type = optional_header_value(response.headers, "content-type", HttpSide::Response)?;
    let body_forbidden = request_method == "HEAD" || matches!(status.get(), 204 | 304);
    let byte_count = body_byte_count(
        &input[header_end..],
        response.headers,
        HttpSide::Response,
        body_forbidden,
        limits,
    )?;
    Ok(HttpResponseMetadata {
        status,
        version: format!("HTTP/1.{version}"),
        content_type,
        byte_count,
        body_ref: None,
        extensions: BTreeMap::new(),
    })
}

fn ensure_header_terminator(
    input: &[u8],
    side: HttpSide,
    limit: usize,
) -> Result<(), CaptureError> {
    if let Some(offset) = input.windows(4).position(|window| window == b"\r\n\r\n") {
        let end = offset
            .checked_add(4)
            .ok_or(CaptureError::SizeOverflow("HTTP/1 header length"))?;
        if end > limit {
            return Err(CaptureError::HttpHeaderBytesLimitExceeded { side, limit });
        }
        Ok(())
    } else if input.len() >= limit {
        Err(CaptureError::HttpHeaderBytesLimitExceeded { side, limit })
    } else {
        Err(CaptureError::TruncatedHttpHeaders(side))
    }
}

fn map_httparse_error(
    side: HttpSide,
    error: httparse::Error,
    limits: &CaptureLimits,
) -> CaptureError {
    match error {
        httparse::Error::TooManyHeaders => CaptureError::HttpHeaderCountLimitExceeded {
            side,
            limit: limits.max_http_headers,
        },
        httparse::Error::HeaderName => CaptureError::MalformedHttp1 {
            side,
            reason: "invalid header name",
        },
        httparse::Error::HeaderValue => CaptureError::MalformedHttp1 {
            side,
            reason: "invalid header value",
        },
        httparse::Error::NewLine => CaptureError::MalformedHttp1 {
            side,
            reason: "invalid newline",
        },
        httparse::Error::Status => CaptureError::MalformedHttp1 {
            side,
            reason: "invalid response status",
        },
        httparse::Error::Token => CaptureError::MalformedHttp1 {
            side,
            reason: "invalid token",
        },
        httparse::Error::Version => CaptureError::MalformedHttp1 {
            side,
            reason: "invalid HTTP version",
        },
    }
}

fn optional_header_value(
    headers: &[httparse::Header<'_>],
    name: &str,
    side: HttpSide,
) -> Result<Option<String>, CaptureError> {
    let mut value = None;
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
    {
        if value.is_some() {
            return Err(CaptureError::MalformedHttp1 {
                side,
                reason: "duplicate singleton metadata header",
            });
        }
        let text = std::str::from_utf8(trim_ascii(header.value)).map_err(|_| {
            CaptureError::InvalidText {
                protocol: "HTTP/1",
                field: "header value",
            }
        })?;
        if text.is_empty() {
            return Err(CaptureError::MalformedHttp1 {
                side,
                reason: "empty singleton metadata header",
            });
        }
        value = Some(text.to_owned());
    }
    Ok(value)
}

fn body_byte_count(
    body: &[u8],
    headers: &[httparse::Header<'_>],
    side: HttpSide,
    body_forbidden: bool,
    limits: &CaptureLimits,
) -> Result<u64, CaptureError> {
    let content_length = content_length(headers, side)?;
    let transfer_encoding = transfer_encoding(headers, side)?;
    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(CaptureError::MalformedHttp1 {
            side,
            reason: "content-length and transfer-encoding cannot be combined",
        });
    }
    if body_forbidden {
        if !body.is_empty() {
            return Err(CaptureError::TrailingHttp1Data {
                side,
                bytes: body.len(),
            });
        }
        return Ok(0);
    }

    let length = if let Some(framing) = transfer_encoding {
        if framing.eq_ignore_ascii_case(b"chunked") {
            parse_chunked_body(body, side, limits)?
        } else {
            return Err(CaptureError::UnsupportedHttp1Framing {
                side,
                framing: "transfer coding other than a single chunked coding",
            });
        }
    } else if let Some(declared) = content_length {
        if declared > limits.max_http_body_bytes {
            return Err(CaptureError::HttpBodyLimitExceeded {
                side,
                declared,
                limit: limits.max_http_body_bytes,
            });
        }
        if body.len() < declared {
            return Err(CaptureError::TruncatedHttpBody {
                side,
                declared,
                available: body.len(),
            });
        }
        if body.len() > declared {
            return Err(CaptureError::TrailingHttp1Data {
                side,
                bytes: body.len() - declared,
            });
        }
        declared
    } else if side == HttpSide::Response {
        body.len()
    } else if body.is_empty() {
        0
    } else {
        return Err(CaptureError::UnsupportedHttp1Framing {
            side,
            framing: "request body without content-length or chunked transfer-encoding",
        });
    };

    if length > limits.max_http_body_bytes {
        return Err(CaptureError::HttpBodyLimitExceeded {
            side,
            declared: length,
            limit: limits.max_http_body_bytes,
        });
    }
    u64::try_from(length).map_err(|_| CaptureError::SizeOverflow("HTTP body"))
}

fn content_length(
    headers: &[httparse::Header<'_>],
    side: HttpSide,
) -> Result<Option<usize>, CaptureError> {
    let mut parsed = None;
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
    {
        if parsed.is_some() {
            return Err(CaptureError::MalformedHttp1 {
                side,
                reason: "duplicate content-length header",
            });
        }
        let text = std::str::from_utf8(trim_ascii(header.value)).map_err(|_| {
            CaptureError::MalformedHttp1 {
                side,
                reason: "content-length is not ASCII",
            }
        })?;
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CaptureError::MalformedHttp1 {
                side,
                reason: "invalid content-length",
            });
        }
        parsed = Some(
            text.parse::<usize>()
                .map_err(|_| CaptureError::MalformedHttp1 {
                    side,
                    reason: "invalid content-length",
                })?,
        );
    }
    Ok(parsed)
}

fn transfer_encoding<'a>(
    headers: &'a [httparse::Header<'a>],
    side: HttpSide,
) -> Result<Option<&'a [u8]>, CaptureError> {
    let mut value = None;
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        if value.is_some() {
            return Err(CaptureError::MalformedHttp1 {
                side,
                reason: "duplicate transfer-encoding header",
            });
        }
        value = Some(trim_ascii(header.value));
    }
    Ok(value)
}

fn parse_chunked_body(
    body: &[u8],
    side: HttpSide,
    limits: &CaptureLimits,
) -> Result<usize, CaptureError> {
    let mut cursor = 0usize;
    let mut decoded = 0usize;
    loop {
        let remaining = body.get(cursor..).ok_or(CaptureError::MalformedHttp1 {
            side,
            reason: "invalid chunk cursor",
        })?;
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(CaptureError::TruncatedHttpBody {
                side,
                declared: decoded,
                available: body.len(),
            })?;
        if line_end > limits.max_http_header_bytes {
            return Err(CaptureError::HttpHeaderBytesLimitExceeded {
                side,
                limit: limits.max_http_header_bytes,
            });
        }
        let size_text = remaining[..line_end]
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default();
        if size_text.is_empty() {
            return Err(CaptureError::MalformedHttp1 {
                side,
                reason: "empty chunk size",
            });
        }
        let size_text =
            std::str::from_utf8(size_text).map_err(|_| CaptureError::MalformedHttp1 {
                side,
                reason: "chunk size is not ASCII",
            })?;
        let chunk_size =
            usize::from_str_radix(size_text, 16).map_err(|_| CaptureError::MalformedHttp1 {
                side,
                reason: "invalid chunk size",
            })?;
        cursor = cursor
            .checked_add(line_end + 2)
            .ok_or(CaptureError::SizeOverflow("chunk cursor"))?;
        if chunk_size == 0 {
            let trailers = body.get(cursor..).ok_or(CaptureError::MalformedHttp1 {
                side,
                reason: "invalid trailer cursor",
            })?;
            let trailer_length = if trailers.starts_with(b"\r\n") {
                2
            } else {
                trailers
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .and_then(|offset| offset.checked_add(4))
                    .ok_or(CaptureError::TruncatedHttpBody {
                        side,
                        declared: decoded,
                        available: body.len(),
                    })?
            };
            if trailer_length > limits.max_http_header_bytes {
                return Err(CaptureError::HttpHeaderBytesLimitExceeded {
                    side,
                    limit: limits.max_http_header_bytes,
                });
            }
            cursor = cursor
                .checked_add(trailer_length)
                .ok_or(CaptureError::SizeOverflow("chunk trailer cursor"))?;
            if cursor != body.len() {
                return Err(CaptureError::TrailingHttp1Data {
                    side,
                    bytes: body.len() - cursor,
                });
            }
            return Ok(decoded);
        }

        decoded = decoded
            .checked_add(chunk_size)
            .ok_or(CaptureError::SizeOverflow("chunked HTTP body"))?;
        if decoded > limits.max_http_body_bytes {
            return Err(CaptureError::HttpBodyLimitExceeded {
                side,
                declared: decoded,
                limit: limits.max_http_body_bytes,
            });
        }
        let chunk_end = cursor
            .checked_add(chunk_size)
            .ok_or(CaptureError::SizeOverflow("chunk cursor"))?;
        let suffix_end = chunk_end
            .checked_add(2)
            .ok_or(CaptureError::SizeOverflow("chunk cursor"))?;
        if suffix_end > body.len() {
            return Err(CaptureError::TruncatedHttpBody {
                side,
                declared: decoded,
                available: body.len(),
            });
        }
        if body.get(chunk_end..suffix_end) != Some(b"\r\n") {
            return Err(CaptureError::MalformedHttp1 {
                side,
                reason: "chunk data is missing its terminator",
            });
        }
        cursor = suffix_end;
    }
}

fn split_request_target(
    target: &str,
    default_scheme: &str,
) -> Result<(String, Option<String>, String), CaptureError> {
    if let Some(scheme_end) = target.find("://") {
        let scheme = &target[..scheme_end];
        let remainder = &target[scheme_end + 3..];
        if scheme.is_empty() || remainder.is_empty() {
            return Err(CaptureError::MalformedHttp1 {
                side: HttpSide::Request,
                reason: "invalid absolute request target",
            });
        }
        let (authority, path) = match remainder.find('/') {
            Some(path_start) => (&remainder[..path_start], &remainder[path_start..]),
            None => (remainder, "/"),
        };
        if authority.is_empty() {
            return Err(CaptureError::MalformedHttp1 {
                side: HttpSide::Request,
                reason: "absolute request target has no authority",
            });
        }
        Ok((
            scheme.to_owned(),
            Some(authority.to_owned()),
            path.to_owned(),
        ))
    } else {
        Ok((default_scheme.to_owned(), None, target.to_owned()))
    }
}

fn destination_authority(destination: &DestinationMetadata, scheme: &str) -> String {
    let host = if let Some(host) = &destination.host {
        host.clone()
    } else if let Some(ip) = destination.ip {
        if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        }
    } else {
        String::new()
    };
    if (scheme == "http" && destination.port == 80)
        || (scheme == "https" && destination.port == 443)
    {
        host
    } else {
        format!("{host}:{}", destination.port)
    }
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
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
