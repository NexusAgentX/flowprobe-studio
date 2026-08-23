use std::{error::Error, fmt};

use flowprobe_model::ModelValidationError;

use crate::{Direction, InputLayer};

/// Whether an HTTP/1 parsing error belongs to the request or response half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpSide {
    Request,
    Response,
}

impl fmt::Display for HttpSide {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Request => "request",
            Self::Response => "response",
        })
    }
}

/// Structured failures produced while buffering or decoding one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    InvalidLimit {
        name: &'static str,
        reason: &'static str,
    },
    Backpressure {
        direction: Direction,
        layer: InputLayer,
        buffered: usize,
        incoming: usize,
        limit: usize,
    },
    AllocationFailed {
        direction: Direction,
        layer: InputLayer,
    },
    SizeOverflow(&'static str),
    InvalidTlsBoundary(&'static str),
    InvalidTlsBoundaryValue(&'static str),
    TlsRecordLimitExceeded {
        declared: usize,
        limit: usize,
    },
    TruncatedTlsRecord {
        declared: usize,
        available: usize,
    },
    MalformedTls(&'static str),
    UnsupportedTls(&'static str),
    TlsExtensionLimitExceeded {
        limit: usize,
    },
    HttpHeaderBytesLimitExceeded {
        side: HttpSide,
        limit: usize,
    },
    HttpHeaderCountLimitExceeded {
        side: HttpSide,
        limit: usize,
    },
    HttpBodyLimitExceeded {
        side: HttpSide,
        declared: usize,
        limit: usize,
    },
    TruncatedHttpHeaders(HttpSide),
    TruncatedHttpBody {
        side: HttpSide,
        declared: usize,
        available: usize,
    },
    MalformedHttp1 {
        side: HttpSide,
        reason: &'static str,
    },
    UnsupportedHttp1Framing {
        side: HttpSide,
        framing: &'static str,
    },
    TrailingHttp1Data {
        side: HttpSide,
        bytes: usize,
    },
    Http2FrameLimitExceeded {
        limit: usize,
    },
    Http2FramePayloadLimitExceeded {
        declared: usize,
        limit: usize,
    },
    TruncatedHttp2Frame {
        declared: usize,
        available: usize,
    },
    MalformedHttp2(&'static str),
    UnsupportedHttp2(&'static str),
    HpackIntegerOverflow,
    HpackStringLimitExceeded {
        declared: usize,
        limit: usize,
    },
    UnsupportedHpack(&'static str),
    InvalidText {
        protocol: &'static str,
        field: &'static str,
    },
    Model(ModelValidationError),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { name, reason } => {
                write!(formatter, "invalid capture limit {name}: {reason}")
            }
            Self::Backpressure {
                direction,
                layer,
                buffered,
                incoming,
                limit,
            } => write!(
                formatter,
                "capture backpressure for {direction} {layer}: {buffered} buffered bytes plus {incoming} incoming bytes exceeds {limit}"
            ),
            Self::AllocationFailed { direction, layer } => {
                write!(
                    formatter,
                    "could not reserve capture buffer for {direction} {layer}"
                )
            }
            Self::SizeOverflow(scope) => {
                write!(formatter, "byte count overflow while decoding {scope}")
            }
            Self::InvalidTlsBoundary(reason) => write!(formatter, "invalid TLS boundary: {reason}"),
            Self::InvalidTlsBoundaryValue(field) => {
                write!(formatter, "invalid TLS boundary value for {field}")
            }
            Self::TlsRecordLimitExceeded { declared, limit } => write!(
                formatter,
                "TLS record declares {declared} bytes, exceeding the {limit}-byte limit"
            ),
            Self::TruncatedTlsRecord {
                declared,
                available,
            } => write!(
                formatter,
                "truncated TLS record: declares {declared} bytes but only {available} are available"
            ),
            Self::MalformedTls(reason) => write!(formatter, "malformed TLS input: {reason}"),
            Self::UnsupportedTls(feature) => {
                write!(
                    formatter,
                    "unsupported TLS feature in v0 metadata decoder: {feature}"
                )
            }
            Self::TlsExtensionLimitExceeded { limit } => {
                write!(
                    formatter,
                    "TLS ClientHello exceeds the {limit}-extension limit"
                )
            }
            Self::HttpHeaderBytesLimitExceeded { side, limit } => write!(
                formatter,
                "HTTP/1 {side} headers exceed the {limit}-byte limit"
            ),
            Self::HttpHeaderCountLimitExceeded { side, limit } => {
                write!(formatter, "HTTP/1 {side} exceeds the {limit}-header limit")
            }
            Self::HttpBodyLimitExceeded {
                side,
                declared,
                limit,
            } => write!(
                formatter,
                "HTTP {side} body has {declared} bytes, exceeding the {limit}-byte limit"
            ),
            Self::TruncatedHttpHeaders(side) => {
                write!(formatter, "truncated HTTP/1 {side} headers")
            }
            Self::TruncatedHttpBody {
                side,
                declared,
                available,
            } => write!(
                formatter,
                "truncated HTTP {side} body: declares {declared} bytes but only {available} are available"
            ),
            Self::MalformedHttp1 { side, reason } => {
                write!(formatter, "malformed HTTP/1 {side}: {reason}")
            }
            Self::UnsupportedHttp1Framing { side, framing } => {
                write!(formatter, "unsupported HTTP/1 {side} framing: {framing}")
            }
            Self::TrailingHttp1Data { side, bytes } => {
                write!(formatter, "HTTP/1 {side} has {bytes} trailing bytes")
            }
            Self::Http2FrameLimitExceeded { limit } => {
                write!(formatter, "HTTP/2 input exceeds the {limit}-frame limit")
            }
            Self::Http2FramePayloadLimitExceeded { declared, limit } => write!(
                formatter,
                "HTTP/2 frame declares {declared} bytes, exceeding the {limit}-byte limit"
            ),
            Self::TruncatedHttp2Frame {
                declared,
                available,
            } => write!(
                formatter,
                "truncated HTTP/2 frame: declares {declared} bytes but only {available} are available"
            ),
            Self::MalformedHttp2(reason) => write!(formatter, "malformed HTTP/2 input: {reason}"),
            Self::UnsupportedHttp2(feature) => {
                write!(
                    formatter,
                    "unsupported HTTP/2 feature in v0 decoder: {feature}"
                )
            }
            Self::HpackIntegerOverflow => formatter.write_str("HPACK integer overflow"),
            Self::HpackStringLimitExceeded { declared, limit } => write!(
                formatter,
                "HPACK string declares {declared} bytes, exceeding the {limit}-byte limit"
            ),
            Self::UnsupportedHpack(feature) => {
                write!(
                    formatter,
                    "unsupported HPACK feature in v0 decoder: {feature}"
                )
            }
            Self::InvalidText { protocol, field } => {
                write!(formatter, "{protocol} {field} is not valid text")
            }
            Self::Model(error) => write!(formatter, "invalid normalized flow: {error}"),
        }
    }
}

impl Error for CaptureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ModelValidationError> for CaptureError {
    fn from(error: ModelValidationError) -> Self {
        Self::Model(error)
    }
}
