use std::{collections::BTreeMap, fmt};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, Error as _},
    ser::{Error as _, SerializeMap},
};
use serde_json::Value;

use crate::{
    BlobRef, BodyRef, ExtensionFields, ModelValidationError, RelativeTimestampNs,
    ensure_extensions, ensure_non_empty_text, ensure_token,
};

const EVENT_RESERVED_FIELDS: &[&str] = &["kind", "metadata"];

/// Metadata about an opaque TCP or UDP connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionMetadata {
    pub client_to_server_bytes: u64,
    pub server_to_client_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl ConnectionMetadata {
    pub(crate) fn validate(&self) -> Result<(), ModelValidationError> {
        if let Some(reason) = &self.close_reason {
            ensure_non_empty_text("protocol.connection.close_reason", reason)?;
        }
        ensure_extensions(
            "protocol.connection",
            &self.extensions,
            &[
                "client_to_server_bytes",
                "server_to_client_bytes",
                "close_reason",
            ],
        )
    }
}

/// Result of the capture plane's TLS interception decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsInterceptionState {
    NotAttempted,
    Intercepted,
    PassedThrough,
    Failed,
}

/// TLS handshake metadata that does not include secret key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated_version: Option<String>,
    pub interception_state: TlsInterceptionState,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl TlsMetadata {
    pub(crate) fn validate(&self) -> Result<(), ModelValidationError> {
        for (field, value) in [
            ("protocol.tls.sni", self.sni.as_deref()),
            ("protocol.tls.alpn", self.alpn.as_deref()),
            (
                "protocol.tls.negotiated_version",
                self.negotiated_version.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                ensure_non_empty_text(field, value)?;
            }
        }

        ensure_extensions(
            "protocol.tls",
            &self.extensions,
            &["sni", "alpn", "negotiated_version", "interception_state"],
        )
    }
}

/// Metadata for a normalized HTTP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestMetadata {
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub byte_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_ref: Option<BodyRef>,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl HttpRequestMetadata {
    fn validate(&self) -> Result<(), ModelValidationError> {
        for (field, value) in [
            ("protocol.http.request.method", self.method.as_str()),
            ("protocol.http.request.scheme", self.scheme.as_str()),
            ("protocol.http.request.authority", self.authority.as_str()),
            ("protocol.http.request.path", self.path.as_str()),
            ("protocol.http.request.version", self.version.as_str()),
        ] {
            ensure_non_empty_text(field, value)?;
        }
        if let Some(content_type) = &self.content_type {
            ensure_non_empty_text("protocol.http.request.content_type", content_type)?;
        }
        ensure_extensions(
            "protocol.http.request",
            &self.extensions,
            &[
                "method",
                "scheme",
                "authority",
                "path",
                "version",
                "content_type",
                "byte_count",
                "body_ref",
            ],
        )
    }
}

/// Validated HTTP response status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct HttpStatus(u16);

impl HttpStatus {
    /// Creates an HTTP status in the protocol-defined 100 through 599 range.
    pub fn new(value: u16) -> Result<Self, ModelValidationError> {
        if (100..=599).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ModelValidationError::InvalidHttpStatus(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for HttpStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Metadata for a normalized HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponseMetadata {
    pub status: HttpStatus,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub byte_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_ref: Option<BodyRef>,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl HttpResponseMetadata {
    fn validate(&self) -> Result<(), ModelValidationError> {
        ensure_non_empty_text("protocol.http.response.version", &self.version)?;
        if let Some(content_type) = &self.content_type {
            ensure_non_empty_text("protocol.http.response.content_type", content_type)?;
        }
        ensure_extensions(
            "protocol.http.response",
            &self.extensions,
            &[
                "status",
                "version",
                "content_type",
                "byte_count",
                "body_ref",
            ],
        )
    }
}

/// One HTTP request/response transaction, including in-progress requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpTransactionMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<u64>,
    pub request: HttpRequestMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpResponseMetadata>,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl HttpTransactionMetadata {
    pub(crate) fn validate(&self) -> Result<(), ModelValidationError> {
        self.request.validate()?;
        if let Some(response) = &self.response {
            response.validate()?;
        }
        ensure_extensions(
            "protocol.http",
            &self.extensions,
            &["stream_id", "request", "response"],
        )
    }
}

/// Direction of a streaming protocol event or chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamDirection {
    ClientToServer,
    ServerToClient,
}

/// Relative-timing metadata for an SSE, WebSocket, or other stream chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamMetadata {
    pub stream_kind: String,
    pub direction: StreamDirection,
    pub sequence: u64,
    pub relative_at: RelativeTimestampNs,
    pub byte_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_name: Option<String>,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl StreamMetadata {
    pub(crate) fn validate(&self) -> Result<(), ModelValidationError> {
        ensure_non_empty_text("protocol.stream.stream_kind", &self.stream_kind)?;
        if let Some(event_name) = &self.event_name {
            ensure_non_empty_text("protocol.stream.event_name", event_name)?;
        }
        ensure_extensions(
            "protocol.stream",
            &self.extensions,
            &[
                "stream_kind",
                "direction",
                "sequence",
                "relative_at",
                "byte_count",
                "blob_ref",
                "event_name",
            ],
        )
    }
}

trait ExtensibleMetadata {
    fn extensions_mut(&mut self) -> &mut ExtensionFields;
}

macro_rules! extensible_metadata {
    ($($metadata:ty),+ $(,)?) => {
        $(
            impl ExtensibleMetadata for $metadata {
                fn extensions_mut(&mut self) -> &mut ExtensionFields {
                    &mut self.extensions
                }
            }
        )+
    };
}

extensible_metadata!(
    ConnectionMetadata,
    TlsMetadata,
    HttpRequestMetadata,
    HttpResponseMetadata,
    StreamMetadata,
);

fn split_json_fields(
    value: Value,
    known_fields: &[&str],
) -> Result<(serde_json::Map<String, Value>, ExtensionFields), serde_json::Error> {
    let Value::Object(mut fields) = value else {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "protocol metadata must be a JSON object",
        ));
    };

    let mut known = serde_json::Map::new();
    for field in known_fields {
        if let Some(value) = fields.remove(*field) {
            known.insert((*field).to_owned(), value);
        }
    }

    Ok((known, fields.into_iter().collect()))
}

fn decode_extensible_metadata<T>(
    value: Value,
    known_fields: &[&str],
) -> Result<T, serde_json::Error>
where
    T: DeserializeOwned + ExtensibleMetadata,
{
    let (known, extensions) = split_json_fields(value, known_fields)?;
    let mut metadata: T = serde_json::from_value(Value::Object(known))?;
    *metadata.extensions_mut() = extensions;
    Ok(metadata)
}

fn decode_http_metadata(value: Value) -> Result<HttpTransactionMetadata, serde_json::Error> {
    let (mut known, extensions) = split_json_fields(value, &["stream_id", "request", "response"])?;
    let stream_id = known
        .remove("stream_id")
        .map(serde_json::from_value)
        .transpose()?;
    let request = known.remove("request").ok_or_else(|| {
        <serde_json::Error as serde::de::Error>::custom("missing HTTP request metadata")
    })?;
    let request = decode_extensible_metadata(
        request,
        &[
            "method",
            "scheme",
            "authority",
            "path",
            "version",
            "content_type",
            "byte_count",
            "body_ref",
        ],
    )?;
    let response = known
        .remove("response")
        .filter(|value| !value.is_null())
        .map(|value| {
            decode_extensible_metadata(
                value,
                &[
                    "status",
                    "version",
                    "content_type",
                    "byte_count",
                    "body_ref",
                ],
            )
        })
        .transpose()?;

    Ok(HttpTransactionMetadata {
        stream_id,
        request,
        response,
        extensions,
    })
}

/// Protocol-specific payload of a tagged protocol event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolMetadata {
    Connection(ConnectionMetadata),
    Tls(TlsMetadata),
    Http(Box<HttpTransactionMetadata>),
    Stream(StreamMetadata),
    /// A future protocol kind retained without interpreting its metadata.
    Unknown {
        kind: String,
        metadata: Value,
    },
}

/// Tagged protocol event plus additive envelope fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolEvent {
    pub metadata: ProtocolMetadata,
    pub extensions: ExtensionFields,
}

impl ProtocolEvent {
    #[must_use]
    pub fn connection(metadata: ConnectionMetadata) -> Self {
        Self {
            metadata: ProtocolMetadata::Connection(metadata),
            extensions: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn tls(metadata: TlsMetadata) -> Self {
        Self {
            metadata: ProtocolMetadata::Tls(metadata),
            extensions: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn http(metadata: HttpTransactionMetadata) -> Self {
        Self {
            metadata: ProtocolMetadata::Http(Box::new(metadata)),
            extensions: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn stream(metadata: StreamMetadata) -> Self {
        Self {
            metadata: ProtocolMetadata::Stream(metadata),
            extensions: BTreeMap::new(),
        }
    }

    /// Creates an event for a protocol kind this v0 library does not understand.
    pub fn unknown(kind: impl Into<String>, metadata: Value) -> Result<Self, ModelValidationError> {
        let event = Self {
            metadata: ProtocolMetadata::Unknown {
                kind: kind.into(),
                metadata,
            },
            extensions: BTreeMap::new(),
        };
        event.validate()?;
        Ok(event)
    }

    pub(crate) fn validate(&self) -> Result<(), ModelValidationError> {
        ensure_extensions("protocol.event", &self.extensions, EVENT_RESERVED_FIELDS)?;
        match &self.metadata {
            ProtocolMetadata::Connection(metadata) => metadata.validate(),
            ProtocolMetadata::Tls(metadata) => metadata.validate(),
            ProtocolMetadata::Http(metadata) => metadata.validate(),
            ProtocolMetadata::Stream(metadata) => metadata.validate(),
            ProtocolMetadata::Unknown { kind, metadata } => {
                ensure_token("protocol.unknown.kind", kind)?;
                if matches!(kind.as_str(), "connection" | "tls" | "http" | "stream") {
                    return Err(ModelValidationError::KnownKindMarkedUnknown(kind.clone()));
                }
                if !metadata.is_object() {
                    return Err(ModelValidationError::UnknownProtocolMetadataNotObject(
                        kind.clone(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn kind(&self) -> &str {
        match &self.metadata {
            ProtocolMetadata::Connection(_) => "connection",
            ProtocolMetadata::Tls(_) => "tls",
            ProtocolMetadata::Http(_) => "http",
            ProtocolMetadata::Stream(_) => "stream",
            ProtocolMetadata::Unknown { kind, .. } => kind,
        }
    }
}

impl Serialize for ProtocolEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let metadata = match &self.metadata {
            ProtocolMetadata::Connection(metadata) => serde_json::to_value(metadata),
            ProtocolMetadata::Tls(metadata) => serde_json::to_value(metadata),
            ProtocolMetadata::Http(metadata) => serde_json::to_value(metadata),
            ProtocolMetadata::Stream(metadata) => serde_json::to_value(metadata),
            ProtocolMetadata::Unknown { metadata, .. } => Ok(metadata.clone()),
        }
        .map_err(S::Error::custom)?;

        let mut map = serializer.serialize_map(Some(2 + self.extensions.len()))?;
        map.serialize_entry("kind", self.kind())?;
        map.serialize_entry("metadata", &metadata)?;
        for (key, value) in &self.extensions {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[derive(Deserialize)]
struct WireProtocolEvent {
    kind: String,
    metadata: Value,
    #[serde(default, flatten)]
    extensions: ExtensionFields,
}

impl<'de> Deserialize<'de> for ProtocolEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireProtocolEvent::deserialize(deserializer)?;
        let metadata = match wire.kind.as_str() {
            "connection" => ProtocolMetadata::Connection(
                decode_extensible_metadata(
                    wire.metadata,
                    &[
                        "client_to_server_bytes",
                        "server_to_client_bytes",
                        "close_reason",
                    ],
                )
                .map_err(D::Error::custom)?,
            ),
            "tls" => ProtocolMetadata::Tls(
                decode_extensible_metadata(
                    wire.metadata,
                    &["sni", "alpn", "negotiated_version", "interception_state"],
                )
                .map_err(D::Error::custom)?,
            ),
            "http" => ProtocolMetadata::Http(Box::new(
                decode_http_metadata(wire.metadata).map_err(D::Error::custom)?,
            )),
            "stream" => ProtocolMetadata::Stream(
                decode_extensible_metadata(
                    wire.metadata,
                    &[
                        "stream_kind",
                        "direction",
                        "sequence",
                        "relative_at",
                        "byte_count",
                        "blob_ref",
                        "event_name",
                    ],
                )
                .map_err(D::Error::custom)?,
            ),
            _ => ProtocolMetadata::Unknown {
                kind: wire.kind,
                metadata: wire.metadata,
            },
        };

        Ok(Self {
            metadata,
            extensions: wire.extensions,
        })
    }
}

impl fmt::Display for ProtocolMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Connection(_) => "connection",
            Self::Tls(_) => "tls",
            Self::Http(_) => "http",
            Self::Stream(_) => "stream",
            Self::Unknown { kind, .. } => kind,
        };
        formatter.write_str(kind)
    }
}
