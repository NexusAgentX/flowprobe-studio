use std::collections::BTreeMap;

use serde_json::Value;

use crate::{CaptureError, CaptureLimits};

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
    if input.len() < 5 {
        return Err(CaptureError::MalformedTls("truncated record header"));
    }

    let record_version = [input[1], input[2]];
    let declared = usize::from(u16::from_be_bytes([input[3], input[4]]));
    if declared > limits.max_tls_record_bytes {
        return Err(CaptureError::TlsRecordLimitExceeded {
            declared,
            limit: limits.max_tls_record_bytes,
        });
    }
    let available = input.len() - 5;
    if available < declared {
        return Err(CaptureError::TruncatedTlsRecord {
            declared,
            available,
        });
    }

    let mut extensions = BTreeMap::new();
    extensions.insert(
        "record_version".to_owned(),
        Value::String(tls_version(record_version)),
    );
    if content_type != 22 {
        return Ok(Some(TlsObservation {
            sni: None,
            extensions,
        }));
    }

    let payload = &input[5..5 + declared];
    if payload.len() < 4 {
        return Err(CaptureError::MalformedTls("truncated handshake header"));
    }
    let handshake_type = payload[0];
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

    let handshake_length = read_u24(&payload[1..4]);
    let handshake_available = payload.len() - 4;
    if handshake_available < handshake_length {
        return Err(CaptureError::UnsupportedTls(
            "ClientHello fragmented across TLS records",
        ));
    }
    let hello = &payload[4..4 + handshake_length];
    let parsed = parse_client_hello(hello, limits)?;
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
        let extension_length = usize::from(extension_cursor.u16("truncated extension length")?);
        let data = extension_cursor.take(extension_length, "truncated extension data")?;
        match extension_type {
            0 => {
                if sni.is_some() {
                    return Err(CaptureError::MalformedTls("duplicate SNI extension"));
                }
                sni = parse_sni(data)?;
            }
            16 => {
                if !offered_alpn.is_empty() {
                    return Err(CaptureError::MalformedTls("duplicate ALPN extension"));
                }
                offered_alpn = parse_alpn(data)?;
            }
            43 => {
                if !offered_versions.is_empty() {
                    return Err(CaptureError::MalformedTls(
                        "duplicate supported versions extension",
                    ));
                }
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
    if list_length != cursor.remaining() {
        return Err(CaptureError::MalformedTls(
            "server name list length mismatch",
        ));
    }
    let mut host = None;
    while cursor.remaining() > 0 {
        let name_type = cursor.u8("truncated server name type")?;
        let name_length = usize::from(cursor.u16("truncated server name length")?);
        let name = cursor.take(name_length, "truncated server name")?;
        if name_type == 0 && host.is_none() {
            if name.is_empty() || name.iter().any(|byte| byte.is_ascii_control()) {
                return Err(CaptureError::MalformedTls("invalid empty or control SNI"));
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
    if list_length != cursor.remaining() {
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
                .map_err(|_| CaptureError::InvalidText {
                    protocol: "TLS",
                    field: "ALPN",
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
