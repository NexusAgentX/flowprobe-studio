//! NormalizedFlow v0 shared data boundary.
//!
//! The model is independent of capture and storage implementations. Payload
//! material is represented only by validated opaque references, and additive
//! JSON fields are preserved in deterministic key order.

mod protocol;
mod reference;

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr};

pub use protocol::{
    ConnectionMetadata, HttpRequestMetadata, HttpResponseMetadata, HttpStatus,
    HttpTransactionMetadata, ProtocolEvent, ProtocolMetadata, StreamDirection, StreamMetadata,
    TlsInterceptionState, TlsMetadata,
};
pub use reference::{BlobRef, BodyRef, InvalidOpaqueReference};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;

/// Sorted additive JSON fields retained for forward-compatible round trips.
pub type ExtensionFields = BTreeMap<String, Value>;

/// Wire version serialized by this contract crate.
pub const NORMALIZED_FLOW_CONTRACT_VERSION: &str = "0";

/// A nanosecond Unix timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimestampNs(pub u64);

/// A nanosecond offset from the flow's `started_at` timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelativeTimestampNs(pub u64);

macro_rules! identifier {
    ($name:ident, $field:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelValidationError> {
                let value = value.into();
                validate_identifier($field, &value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
    };
}

identifier!(FlowId, "flow_id", "Stable identity of one normalized flow.");
identifier!(
    ConnectionId,
    "connection_id",
    "Identity of the underlying transport connection."
);
identifier!(
    CaptureSessionId,
    "capture_session_id",
    "Identity of the optional explicit capture session."
);

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ModelValidationError> {
    if value.is_empty() {
        return Err(ModelValidationError::InvalidIdentifier {
            field,
            reason: "identifier is empty",
        });
    }
    if value.trim() != value {
        return Err(ModelValidationError::InvalidIdentifier {
            field,
            reason: "identifier has leading or trailing whitespace",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ModelValidationError::InvalidIdentifier {
            field,
            reason: "identifier contains control characters",
        });
    }
    Ok(())
}

/// Confidence percentage attached to process attribution provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct AttributionConfidence(u8);

impl AttributionConfidence {
    /// Creates a confidence percentage from 0 through 100.
    pub fn new(value: u8) -> Result<Self, ModelValidationError> {
        if value <= 100 {
            Ok(Self(value))
        } else {
            Err(ModelValidationError::InvalidAttributionConfidence(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for AttributionConfidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Open provenance token for the source of process attribution evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct AttributionSource(String);

impl AttributionSource {
    pub const OPERATING_SYSTEM: &'static str = "operating_system";
    pub const NETWORK_RUNTIME: &'static str = "network_runtime";
    pub const SOCKET_CORRELATION: &'static str = "socket_correlation";

    pub fn new(value: impl Into<String>) -> Result<Self, ModelValidationError> {
        let value = value.into();
        ensure_token("process.source", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for AttributionSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Process metadata plus explicit attribution provenance and confidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessAttribution {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_name: Option<String>,
    pub source: AttributionSource,
    pub confidence: AttributionConfidence,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl ProcessAttribution {
    fn validate(&self) -> Result<(), ModelValidationError> {
        if self.process_id.is_none() && self.executable_name.is_none() {
            return Err(ModelValidationError::EmptyProcessAttribution);
        }
        if let Some(name) = &self.executable_name {
            ensure_non_empty_text("process.executable_name", name)?;
        }
        ensure_extensions(
            "process",
            &self.extensions,
            &["process_id", "executable_name", "source", "confidence"],
        )
    }
}

/// Open transport protocol token. v0 producers use `tcp` or `udp`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct TransportProtocol(String);

impl TransportProtocol {
    pub const TCP: &'static str = "tcp";
    pub const UDP: &'static str = "udp";

    pub fn new(value: impl Into<String>) -> Result<Self, ModelValidationError> {
        let value = value.into();
        ensure_token("transport.protocol", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TransportProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Transport-level source metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportMetadata {
    pub protocol: TransportProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl TransportMetadata {
    fn validate(&self) -> Result<(), ModelValidationError> {
        if self.source_port == Some(0) {
            return Err(ModelValidationError::ZeroPort("transport.source_port"));
        }
        ensure_extensions(
            "transport",
            &self.extensions,
            &["protocol", "source_ip", "source_port"],
        )
    }
}

/// Original network destination independent of the selected egress runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    pub port: u16,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl DestinationMetadata {
    fn validate(&self) -> Result<(), ModelValidationError> {
        if self.host.is_none() && self.ip.is_none() {
            return Err(ModelValidationError::MissingDestinationAddress);
        }
        if let Some(host) = &self.host {
            ensure_non_empty_text("destination.host", host)?;
        }
        if self.port == 0 {
            return Err(ModelValidationError::ZeroPort("destination.port"));
        }
        ensure_extensions("destination", &self.extensions, &["host", "ip", "port"])
    }
}

/// Absolute timing metadata for a flow that may still be in progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowTiming {
    pub started_at: TimestampNs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_byte_at: Option<TimestampNs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<TimestampNs>,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl FlowTiming {
    fn validate(&self) -> Result<(), ModelValidationError> {
        if self
            .first_byte_at
            .is_some_and(|first| first < self.started_at)
        {
            return Err(ModelValidationError::InvalidTiming(
                "first_byte_at precedes started_at",
            ));
        }
        if self.ended_at.is_some_and(|ended| ended < self.started_at) {
            return Err(ModelValidationError::InvalidTiming(
                "ended_at precedes started_at",
            ));
        }
        if self
            .first_byte_at
            .zip(self.ended_at)
            .is_some_and(|(first, ended)| first > ended)
        {
            return Err(ModelValidationError::InvalidTiming(
                "first_byte_at follows ended_at",
            ));
        }
        ensure_extensions(
            "timing",
            &self.extensions,
            &["started_at", "first_byte_at", "ended_at"],
        )
    }
}

/// NormalizedFlow v0 record shared across capture, storage, UI, and analyzers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedFlowV0 {
    pub contract_version: String,
    pub flow_id: FlowId,
    pub connection_id: ConnectionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_session_id: Option<CaptureSessionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessAttribution>,
    pub timing: FlowTiming,
    pub transport: TransportMetadata,
    pub destination: DestinationMetadata,
    pub protocols: Vec<ProtocolEvent>,
    #[serde(default, flatten)]
    pub extensions: ExtensionFields,
}

impl NormalizedFlowV0 {
    /// Decodes and validates a NormalizedFlow v0 JSON document.
    pub fn from_json(input: &str) -> Result<Self, FlowDecodeError> {
        let flow: Self = serde_json::from_str(input).map_err(FlowDecodeError::Json)?;
        flow.validate().map_err(FlowDecodeError::Validation)?;
        Ok(flow)
    }

    /// Emits stable pretty JSON with sorted additive fields and a trailing newline.
    pub fn to_canonical_json(&self) -> Result<String, FlowEncodeError> {
        self.validate().map_err(FlowEncodeError::Validation)?;
        let mut encoded = serde_json::to_string_pretty(self).map_err(FlowEncodeError::Json)?;
        encoded.push('\n');
        Ok(encoded)
    }

    /// Validates cross-field invariants after programmatic construction.
    pub fn validate(&self) -> Result<(), ModelValidationError> {
        if self.contract_version != NORMALIZED_FLOW_CONTRACT_VERSION {
            return Err(ModelValidationError::UnsupportedContractVersion(
                self.contract_version.clone(),
            ));
        }
        if let Some(process) = &self.process {
            process.validate()?;
        }
        self.timing.validate()?;
        self.transport.validate()?;
        self.destination.validate()?;
        if self.protocols.is_empty() {
            return Err(ModelValidationError::EmptyProtocolEvents);
        }
        for protocol in &self.protocols {
            protocol.validate()?;
        }
        ensure_extensions(
            "normalized_flow",
            &self.extensions,
            &[
                "contract_version",
                "flow_id",
                "connection_id",
                "capture_session_id",
                "process",
                "timing",
                "transport",
                "destination",
                "protocols",
            ],
        )
    }
}

/// A semantic validation failure in NormalizedFlow v0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelValidationError {
    InvalidIdentifier {
        field: &'static str,
        reason: &'static str,
    },
    InvalidAttributionConfidence(u8),
    InvalidToken {
        field: &'static str,
        reason: &'static str,
    },
    EmptyText(&'static str),
    EmptyProcessAttribution,
    MissingDestinationAddress,
    ZeroPort(&'static str),
    InvalidTiming(&'static str),
    InvalidHttpStatus(u16),
    EmptyProtocolEvents,
    UnsupportedContractVersion(String),
    ReservedExtensionKey {
        scope: &'static str,
        key: String,
    },
    InvalidExtensionKey {
        scope: &'static str,
    },
    KnownKindMarkedUnknown(String),
    UnknownProtocolMetadataNotObject(String),
}

impl fmt::Display for ModelValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::InvalidAttributionConfidence(value) => write!(
                formatter,
                "invalid process attribution confidence {value}; expected 0 through 100"
            ),
            Self::InvalidToken { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::EmptyText(field) => write!(formatter, "{field} must not be empty"),
            Self::EmptyProcessAttribution => {
                formatter.write_str("process attribution requires process_id or executable_name")
            }
            Self::MissingDestinationAddress => {
                formatter.write_str("destination requires a host or IP address")
            }
            Self::ZeroPort(field) => write!(formatter, "{field} must not be zero"),
            Self::InvalidTiming(reason) => write!(formatter, "invalid flow timing: {reason}"),
            Self::InvalidHttpStatus(value) => write!(
                formatter,
                "invalid HTTP status {value}; expected 100 through 599"
            ),
            Self::EmptyProtocolEvents => {
                formatter.write_str("normalized flow requires at least one protocol event")
            }
            Self::UnsupportedContractVersion(version) => write!(
                formatter,
                "unsupported NormalizedFlow contract version {version:?}"
            ),
            Self::ReservedExtensionKey { scope, key } => {
                write!(formatter, "extension key {key:?} is reserved in {scope}")
            }
            Self::InvalidExtensionKey { scope } => {
                write!(formatter, "extension keys in {scope} must not be empty")
            }
            Self::KnownKindMarkedUnknown(kind) => {
                write!(
                    formatter,
                    "known protocol kind {kind:?} cannot be marked unknown"
                )
            }
            Self::UnknownProtocolMetadataNotObject(kind) => write!(
                formatter,
                "metadata for unknown protocol kind {kind:?} must be a JSON object"
            ),
        }
    }
}

impl Error for ModelValidationError {}

/// Failure while decoding or validating boundary JSON.
#[derive(Debug)]
pub enum FlowDecodeError {
    Json(serde_json::Error),
    Validation(ModelValidationError),
}

impl fmt::Display for FlowDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid NormalizedFlow JSON: {error}"),
            Self::Validation(error) => write!(formatter, "invalid NormalizedFlow value: {error}"),
        }
    }
}

impl Error for FlowDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Validation(error) => Some(error),
        }
    }
}

/// Failure while validating or serializing canonical boundary JSON.
#[derive(Debug)]
pub enum FlowEncodeError {
    Json(serde_json::Error),
    Validation(ModelValidationError),
}

impl fmt::Display for FlowEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "could not encode NormalizedFlow JSON: {error}"),
            Self::Validation(error) => write!(formatter, "invalid NormalizedFlow value: {error}"),
        }
    }
}

impl Error for FlowEncodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Validation(error) => Some(error),
        }
    }
}

pub(crate) fn ensure_non_empty_text(
    field: &'static str,
    value: &str,
) -> Result<(), ModelValidationError> {
    if value.trim().is_empty() {
        Err(ModelValidationError::EmptyText(field))
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_token(field: &'static str, value: &str) -> Result<(), ModelValidationError> {
    if value.is_empty() {
        return Err(ModelValidationError::InvalidToken {
            field,
            reason: "token is empty",
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ModelValidationError::InvalidToken {
            field,
            reason: "token contains unsupported characters",
        });
    }
    Ok(())
}

pub(crate) fn ensure_extensions(
    scope: &'static str,
    extensions: &ExtensionFields,
    reserved: &[&str],
) -> Result<(), ModelValidationError> {
    for key in extensions.keys() {
        if key.is_empty() {
            return Err(ModelValidationError::InvalidExtensionKey { scope });
        }
        if reserved.contains(&key.as_str()) {
            return Err(ModelValidationError::ReservedExtensionKey {
                scope,
                key: key.clone(),
            });
        }
    }
    Ok(())
}
