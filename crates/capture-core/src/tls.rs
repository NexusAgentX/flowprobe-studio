use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{CaptureError, CaptureLimits, Direction, InputLayer};

const TLS_RECORD_HEADER_BYTES: usize = 5;
const TLS_HANDSHAKE_HEADER_BYTES: usize = 4;
const MAX_CLIENT_HELLO_RECORDS: usize = 256;

pub(crate) struct TlsObservation {
    pub(crate) sni: Option<String>,
    pub(crate) extensions: BTreeMap<String, Value>,
}

pub(crate) fn inspect_client_stream(
    input: &[u8],
    limits: &CaptureLimits,
) -> Result<Option<TlsObservation>, CaptureError> {
    let Some(content_type) = input.first().copied() else {
        return Ok(None);
    };
    if !(20..=24).contains(&content_type) {
        return Ok(None);
    }
    if input.get(1).is_some_and(|major| *major != 3) {
        return Ok(None);
    }
    let first_record = read_record(input, 0, limits)?;

    let mut extensions = BTreeMap::new();
    extensions.insert(
        "record_version".to_owned(),
        Value::String(tls_version(first_record.version)),
    );
    if first_record.content_type != 22 {
        return Ok(Some(TlsObservation {
            sni: None,
            extensions,
        }));
    }

    let mut record = first_record;
    let mut handshake_header = [0u8; TLS_HANDSHAKE_HEADER_BYTES];
    let mut handshake_header_bytes = 0usize;
    let mut handshake_length = None;
    let mut hello = Vec::new();
    let mut record_count = 1usize;
    let parsed = loop {
        let mut payload = record.payload;
        if handshake_header_bytes < TLS_HANDSHAKE_HEADER_BYTES {
            let header_bytes =
                (TLS_HANDSHAKE_HEADER_BYTES - handshake_header_bytes).min(payload.len());
            handshake_header[handshake_header_bytes..handshake_header_bytes + header_bytes]
                .copy_from_slice(&payload[..header_bytes]);
            handshake_header_bytes += header_bytes;
            payload = &payload[header_bytes..];

            if handshake_header_bytes == TLS_HANDSHAKE_HEADER_BYTES {
                let handshake_type = handshake_header[0];
                if handshake_type != 1 {
                    extensions.insert(
                        "handshake_type".to_owned(),
                        Value::from(u64::from(handshake_type)),
                    );
                    return Ok(Some(TlsObservation {
                        sni: None,
                        extensions,
                    }));
                }

                let declared = read_u24(&handshake_header[1..]);
                let total = declared
                    .checked_add(TLS_HANDSHAKE_HEADER_BYTES)
                    .ok_or(CaptureError::SizeOverflow("TLS ClientHello"))?;
                if total > limits.max_pending_bytes_per_direction {
                    return Err(CaptureError::UnsupportedTls(
                        "ClientHello exceeds the configured capture buffering limit",
                    ));
                }
                handshake_length = Some(declared);
            }
        }

        if let Some(declared) = handshake_length {
            let missing = declared - hello.len();
            let copy_bytes = missing.min(payload.len());
            hello
                .try_reserve(copy_bytes)
                .map_err(|_| CaptureError::AllocationFailed {
                    direction: Direction::ClientToServer,
                    layer: InputLayer::Wire,
                })?;
            hello.extend_from_slice(&payload[..copy_bytes]);
            if hello.len() == declared {
                break parse_client_hello(&hello, limits)?;
            }
        }

        if record.next_offset == input.len() {
            let reason = if handshake_header_bytes < TLS_HANDSHAKE_HEADER_BYTES {
                "truncated handshake header"
            } else {
                "truncated ClientHello across TLS records"
            };
            return Err(CaptureError::MalformedTls(reason));
        }

        record_count = record_count
            .checked_add(1)
            .ok_or(CaptureError::SizeOverflow("TLS ClientHello record count"))?;
        if record_count > MAX_CLIENT_HELLO_RECORDS {
            return Err(CaptureError::UnsupportedTls(
                "ClientHello exceeds the record fragmentation limit",
            ));
        }
        record = read_record(input, record.next_offset, limits)?;
        if record.content_type != 22 {
            return Err(CaptureError::MalformedTls(
                "non-handshake TLS record interleaved before complete ClientHello",
            ));
        }
        if record.version[0] != 3 {
            return Err(CaptureError::MalformedTls(
                "invalid TLS record version while reassembling ClientHello",
            ));
        }
    };
    extensions.insert(
        "client_hello_legacy_version".to_owned(),
        Value::String(tls_version(parsed.legacy_version)),
    );
    if !parsed.offered_alpn.is_empty() {
        extensions.insert(
            "offered_alpn".to_owned(),
            Value::Array(parsed.offered_alpn.into_iter().map(Value::String).collect()),
        );
    }
    if !parsed.offered_versions.is_empty() {
        extensions.insert(
            "offered_versions".to_owned(),
            Value::Array(
                parsed
                    .offered_versions
                    .into_iter()
                    .map(|version| Value::String(tls_version(version)))
                    .collect(),
            ),
        );
    }

    Ok(Some(TlsObservation {
        sni: parsed.sni,
        extensions,
    }))
}

struct TlsRecord<'a> {
    content_type: u8,
    version: [u8; 2],
    payload: &'a [u8],
    next_offset: usize,
}

fn read_record<'a>(
    input: &'a [u8],
    offset: usize,
    limits: &CaptureLimits,
) -> Result<TlsRecord<'a>, CaptureError> {
    let remaining = input
        .get(offset..)
        .ok_or(CaptureError::SizeOverflow("TLS record offset"))?;
    if remaining.len() < TLS_RECORD_HEADER_BYTES {
        return Err(CaptureError::MalformedTls("truncated record header"));
    }

    let declared = usize::from(u16::from_be_bytes([remaining[3], remaining[4]]));
    if declared > limits.max_tls_record_bytes {
        return Err(CaptureError::TlsRecordLimitExceeded {
            declared,
            limit: limits.max_tls_record_bytes,
        });
    }
    let available = remaining.len() - TLS_RECORD_HEADER_BYTES;
    if available < declared {
        return Err(CaptureError::TruncatedTlsRecord {
            declared,
            available,
        });
    }

    let next_offset = offset
        .checked_add(TLS_RECORD_HEADER_BYTES)
        .and_then(|value| value.checked_add(declared))
        .ok_or(CaptureError::SizeOverflow("TLS record offset"))?;
    Ok(TlsRecord {
        content_type: remaining[0],
        version: [remaining[1], remaining[2]],
        payload: &remaining[TLS_RECORD_HEADER_BYTES..TLS_RECORD_HEADER_BYTES + declared],
        next_offset,
    })
}

struct ParsedClientHello {
    legacy_version: [u8; 2],
    sni: Option<String>,
    offered_alpn: Vec<String>,
    offered_versions: Vec<[u8; 2]>,
}

fn parse_client_hello(
    hello: &[u8],
    limits: &CaptureLimits,
) -> Result<ParsedClientHello, CaptureError> {
    let mut cursor = Cursor::new(hello);
    let legacy_version = cursor.array_2("missing ClientHello legacy version")?;
    cursor.take(32, "truncated ClientHello random")?;
    let session_id_length = usize::from(cursor.u8("missing ClientHello session ID length")?);
    if session_id_length > 32 {
        return Err(CaptureError::MalformedTls(
            "ClientHello session ID exceeds 32 bytes",
        ));
    }
    cursor.take(session_id_length, "truncated ClientHello session ID")?;
    let cipher_suites_length = usize::from(cursor.u16("missing cipher suite list length")?);
    if cipher_suites_length == 0 || cipher_suites_length % 2 != 0 {
        return Err(CaptureError::MalformedTls(
            "cipher suite list must contain complete entries",
        ));
    }
    cursor.take(cipher_suites_length, "truncated cipher suite list")?;
    let compression_length = usize::from(cursor.u8("missing compression method list length")?);
    if compression_length == 0 {
        return Err(CaptureError::MalformedTls(
            "compression method list is empty",
        ));
    }
    cursor.take(compression_length, "truncated compression method list")?;

    if cursor.remaining() == 0 {
        return Ok(ParsedClientHello {
            legacy_version,
            sni: None,
            offered_alpn: Vec::new(),
            offered_versions: Vec::new(),
        });
    }

    let extension_bytes = usize::from(cursor.u16("missing extension block length")?);
    if extension_bytes != cursor.remaining() {
        return Err(CaptureError::MalformedTls(
            "ClientHello extension block length mismatch",
        ));
    }
    let extension_block = cursor.take(extension_bytes, "truncated extension block")?;
    let mut extension_cursor = Cursor::new(extension_block);
    let mut extension_count = 0usize;
    let mut extension_types = BTreeSet::new();
    let mut sni = None;
    let mut offered_alpn = Vec::new();
    let mut offered_versions = Vec::new();
    while extension_cursor.remaining() > 0 {
        extension_count = extension_count
            .checked_add(1)
            .ok_or(CaptureError::SizeOverflow("TLS extension count"))?;
        if extension_count > limits.max_tls_extensions {
            return Err(CaptureError::TlsExtensionLimitExceeded {
                limit: limits.max_tls_extensions,
            });
        }
        let extension_type = extension_cursor.u16("truncated extension type")?;
        if !extension_types.insert(extension_type) {
            return Err(CaptureError::MalformedTls(
                "duplicate ClientHello extension type",
            ));
        }
        let extension_length = usize::from(extension_cursor.u16("truncated extension length")?);
        let data = extension_cursor.take(extension_length, "truncated extension data")?;
        match extension_type {
            0 => {
                sni = parse_sni(data)?;
            }
            16 => {
                offered_alpn = parse_alpn(data)?;
            }
            43 => {
                offered_versions = parse_supported_versions(data)?;
            }
            _ => {}
        }
    }

    Ok(ParsedClientHello {
        legacy_version,
        sni,
        offered_alpn,
        offered_versions,
    })
}

fn parse_sni(data: &[u8]) -> Result<Option<String>, CaptureError> {
    let mut cursor = Cursor::new(data);
    let list_length = usize::from(cursor.u16("missing server name list length")?);
    if list_length == 0 || list_length != cursor.remaining() {
        return Err(CaptureError::MalformedTls(
            "server name list length mismatch",
        ));
    }
    let mut host = None;
    let mut seen_name_types = [false; 256];
    while cursor.remaining() > 0 {
        let name_type = cursor.u8("truncated server name type")?;
        let name_type_index = usize::from(name_type);
        if seen_name_types[name_type_index] {
            return Err(CaptureError::MalformedTls("duplicate server name type"));
        }
        seen_name_types[name_type_index] = true;
        let name_length = usize::from(cursor.u16("truncated server name length")?);
        let name = cursor.take(name_length, "truncated server name")?;
        if name.is_empty() {
            return Err(CaptureError::MalformedTls("empty server name"));
        }
        if name_type == 0 {
            if !name.is_ascii()
                || name.ends_with(b".")
                || name
                    .iter()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            {
                return Err(CaptureError::MalformedTls("invalid SNI host name"));
            }
            host = Some(
                std::str::from_utf8(name)
                    .map_err(|_| CaptureError::InvalidText {
                        protocol: "TLS",
                        field: "SNI",
                    })?
                    .to_owned(),
            );
        }
    }
    Ok(host)
}

fn parse_alpn(data: &[u8]) -> Result<Vec<String>, CaptureError> {
    let mut cursor = Cursor::new(data);
    let list_length = usize::from(cursor.u16("missing ALPN list length")?);
    if list_length < 2 || list_length != cursor.remaining() {
        return Err(CaptureError::MalformedTls("ALPN list length mismatch"));
    }
    let mut protocols = Vec::new();
    while cursor.remaining() > 0 {
        let protocol_length = usize::from(cursor.u8("truncated ALPN protocol length")?);
        if protocol_length == 0 {
            return Err(CaptureError::MalformedTls("empty ALPN protocol"));
        }
        let protocol = cursor.take(protocol_length, "truncated ALPN protocol")?;
        protocols.push(
            std::str::from_utf8(protocol)
                .map_err(|_| {
                    CaptureError::UnsupportedTls(
                        "non-UTF-8 ALPN protocol identifier in the minimum v0 path",
                    )
                })?
                .to_owned(),
        );
    }
    Ok(protocols)
}

fn parse_supported_versions(data: &[u8]) -> Result<Vec<[u8; 2]>, CaptureError> {
    let mut cursor = Cursor::new(data);
    let list_length = usize::from(cursor.u8("missing supported versions list length")?);
    if list_length != cursor.remaining() || list_length == 0 || list_length % 2 != 0 {
        return Err(CaptureError::MalformedTls(
            "supported versions list length mismatch",
        ));
    }
    let mut versions = Vec::with_capacity(list_length / 2);
    while cursor.remaining() > 0 {
        versions.push(cursor.array_2("truncated supported TLS version")?);
    }
    Ok(versions)
}

fn read_u24(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

fn tls_version(version: [u8; 2]) -> String {
    match version {
        [3, 0] => "SSLv3".to_owned(),
        [3, 1] => "TLSv1.0".to_owned(),
        [3, 2] => "TLSv1.1".to_owned(),
        [3, 3] => "TLSv1.2".to_owned(),
        [3, 4] => "TLSv1.3".to_owned(),
        [major, minor] => format!("0x{major:02x}{minor:02x}"),
    }
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }

    const fn remaining(&self) -> usize {
        self.remaining.len()
    }

    fn take(&mut self, length: usize, reason: &'static str) -> Result<&'a [u8], CaptureError> {
        if self.remaining.len() < length {
            return Err(CaptureError::MalformedTls(reason));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self, reason: &'static str) -> Result<u8, CaptureError> {
        Ok(self.take(1, reason)?[0])
    }

    fn u16(&mut self, reason: &'static str) -> Result<u16, CaptureError> {
        let value = self.take(2, reason)?;
        Ok(u16::from_be_bytes([value[0], value[1]]))
    }

    fn array_2(&mut self, reason: &'static str) -> Result<[u8; 2], CaptureError> {
        let value = self.take(2, reason)?;
        Ok([value[0], value[1]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_client_hello_header_and_body_across_records() {
        let handshake = client_hello("fragmented.test");
        let mut wire = tls_record(22, &handshake[..2]);
        wire.extend(tls_record(22, &handshake[2..11]));
        wire.extend(tls_record(22, &handshake[11..]));

        let observation = inspect_client_stream(&wire, &CaptureLimits::default())
            .expect("fragmented ClientHello must parse")
            .expect("TLS input must produce an observation");

        assert_eq!(observation.sni.as_deref(), Some("fragmented.test"));
        assert_eq!(
            observation
                .extensions
                .get("record_version")
                .and_then(Value::as_str),
            Some("TLSv1.2")
        );
    }

    #[test]
    fn rejects_non_handshake_record_before_client_hello_is_complete() {
        let handshake = client_hello("interleaved.test");
        let mut wire = tls_record(22, &handshake[..12]);
        wire.extend(tls_record(23, b"application data"));
        wire.extend(tls_record(22, &handshake[12..]));

        assert_eq!(
            inspect_client_stream(&wire, &CaptureLimits::default()).err(),
            Some(CaptureError::MalformedTls(
                "non-handshake TLS record interleaved before complete ClientHello"
            ))
        );
    }

    #[test]
    fn applies_tls_record_limit_to_continuation_records() {
        let handshake = client_hello("record-limit.test");
        let mut wire = tls_record(22, &handshake[..4]);
        wire.extend(tls_record(22, &handshake[4..21]));
        let limits = CaptureLimits {
            max_tls_record_bytes: 16,
            ..CaptureLimits::default()
        };

        assert_eq!(
            inspect_client_stream(&wire, &limits).err(),
            Some(CaptureError::TlsRecordLimitExceeded {
                declared: 17,
                limit: 16,
            })
        );
    }

    #[test]
    fn rejects_declared_client_hello_beyond_capture_buffer_limit() {
        let limits = CaptureLimits {
            max_pending_bytes_per_direction: 64,
            max_tls_record_bytes: 64,
            ..CaptureLimits::default()
        };
        let wire = tls_record(22, &[1, 0, 0, 61]);

        assert_eq!(
            inspect_client_stream(&wire, &limits).err(),
            Some(CaptureError::UnsupportedTls(
                "ClientHello exceeds the configured capture buffering limit"
            ))
        );
    }

    #[test]
    fn reports_truncated_fragmented_client_hello() {
        let handshake = client_hello("truncated.test");
        let wire = tls_record(22, &handshake[..12]);

        assert_eq!(
            inspect_client_stream(&wire, &CaptureLimits::default()).err(),
            Some(CaptureError::MalformedTls(
                "truncated ClientHello across TLS records"
            ))
        );
    }

    #[test]
    fn bounds_empty_record_fragmentation() {
        let mut wire = tls_record(22, &[1, 0, 0, 1]);
        for _ in 1..=MAX_CLIENT_HELLO_RECORDS {
            wire.extend(tls_record(22, &[]));
        }

        assert_eq!(
            inspect_client_stream(&wire, &CaptureLimits::default()).err(),
            Some(CaptureError::UnsupportedTls(
                "ClientHello exceeds the record fragmentation limit"
            ))
        );
    }

    fn client_hello(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut server_name = vec![0];
        push_u16(&mut server_name, host.len());
        server_name.extend_from_slice(host);

        let mut sni = Vec::new();
        push_u16(&mut sni, server_name.len());
        sni.extend_from_slice(&server_name);

        let mut extensions = Vec::new();
        push_u16(&mut extensions, 0);
        push_u16(&mut extensions, sni.len());
        extensions.extend_from_slice(&sni);

        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        push_u16(&mut body, extensions.len());
        body.extend_from_slice(&extensions);

        let body_len = u32::try_from(body.len()).expect("test ClientHello body fits u24");
        assert!(body_len <= 0x00ff_ffff, "test ClientHello body fits u24");
        let length_bytes = body_len.to_be_bytes();
        let mut handshake = vec![1, length_bytes[1], length_bytes[2], length_bytes[3]];
        handshake.extend_from_slice(&body);
        handshake
    }

    fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let declared = u16::try_from(payload.len()).expect("test TLS record payload fits u16");
        let mut record = vec![content_type, 3, 3];
        record.extend_from_slice(&declared.to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn push_u16(output: &mut Vec<u8>, value: usize) {
        output.extend_from_slice(
            &u16::try_from(value)
                .expect("test value fits u16")
                .to_be_bytes(),
        );
    }
}
