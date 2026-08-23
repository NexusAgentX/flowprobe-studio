//! Protocol-oriented capture core for deterministic connection streams.
//!
//! The crate accepts generic directional bytes, applies explicit buffering and
//! parser limits, and emits the shared [`flowprobe_model::NormalizedFlowV0`]
//! type. It has no dependency on a network runtime or product endpoint.

mod error;
mod http1;
mod http2;
mod tls;

use std::{collections::BTreeMap, fmt};

pub use error::{CaptureError, HttpSide};
use flowprobe_model::{
    CaptureSessionId, ConnectionId, ConnectionMetadata, DestinationMetadata, FlowId, FlowTiming,
    NORMALIZED_FLOW_CONTRACT_VERSION, NormalizedFlowV0, ProcessAttribution, ProtocolEvent,
    TlsInterceptionState, TlsMetadata, TransportMetadata, TransportProtocol,
};
use serde_json::Value;

const HARD_MAX_PENDING_BYTES_PER_DIRECTION: usize = 64 * 1024 * 1024;
const HARD_MAX_HEADER_BYTES: usize = 1024 * 1024;
const HARD_MAX_HEADERS: usize = 4096;
const HARD_MAX_HTTP2_FRAMES: usize = 65_536;
const HARD_MAX_HPACK_DYNAMIC_TABLE_BYTES: usize = 1024 * 1024;
const HARD_MAX_TLS_EXTENSIONS: usize = 4096;

/// Direction of bytes relative to the captured client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl fmt::Display for Direction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ClientToServer => "client-to-server",
            Self::ServerToClient => "server-to-client",
        })
    }
}

/// Byte layer supplied to a capture session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputLayer {
    /// Bytes observed on the transport connection.
    Wire,
    /// Application bytes supplied by an explicit successful TLS interception boundary.
    DecryptedTls,
}

impl fmt::Display for InputLayer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Wire => "wire",
            Self::DecryptedTls => "decrypted-tls",
        })
    }
}

/// Explicit resource ceilings for one captured connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureLimits {
    pub max_pending_bytes_per_direction: usize,
    pub max_http_header_bytes: usize,
    pub max_http_headers: usize,
    pub max_http_body_bytes: usize,
    pub max_http2_frame_payload_bytes: usize,
    pub max_http2_frames: usize,
    pub max_hpack_string_bytes: usize,
    pub max_hpack_dynamic_table_bytes: usize,
    pub max_tls_record_bytes: usize,
    pub max_tls_extensions: usize,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_pending_bytes_per_direction: 4 * 1024 * 1024,
            max_http_header_bytes: 64 * 1024,
            max_http_headers: 128,
            max_http_body_bytes: 2 * 1024 * 1024,
            max_http2_frame_payload_bytes: 64 * 1024,
            max_http2_frames: 2048,
            max_hpack_string_bytes: 16 * 1024,
            max_hpack_dynamic_table_bytes: 4096,
            max_tls_record_bytes: 18 * 1024,
            max_tls_extensions: 256,
        }
    }
}

impl CaptureLimits {
    fn validate(&self) -> Result<(), CaptureError> {
        for (name, value) in [
            (
                "max_pending_bytes_per_direction",
                self.max_pending_bytes_per_direction,
            ),
            ("max_http_header_bytes", self.max_http_header_bytes),
            ("max_http_headers", self.max_http_headers),
            ("max_http_body_bytes", self.max_http_body_bytes),
            (
                "max_http2_frame_payload_bytes",
                self.max_http2_frame_payload_bytes,
            ),
            ("max_http2_frames", self.max_http2_frames),
            ("max_hpack_string_bytes", self.max_hpack_string_bytes),
            ("max_tls_record_bytes", self.max_tls_record_bytes),
            ("max_tls_extensions", self.max_tls_extensions),
        ] {
            if value == 0 {
                return Err(CaptureError::InvalidLimit {
                    name,
                    reason: "must be greater than zero",
                });
            }
        }

        for (name, value) in [
            ("max_http_header_bytes", self.max_http_header_bytes),
            ("max_http_body_bytes", self.max_http_body_bytes),
            (
                "max_http2_frame_payload_bytes",
                self.max_http2_frame_payload_bytes,
            ),
            ("max_hpack_string_bytes", self.max_hpack_string_bytes),
            ("max_tls_record_bytes", self.max_tls_record_bytes),
        ] {
            if value > self.max_pending_bytes_per_direction {
                return Err(CaptureError::InvalidLimit {
                    name,
                    reason: "must not exceed max_pending_bytes_per_direction",
                });
            }
        }

        for (name, value, hard_limit) in [
            (
                "max_pending_bytes_per_direction",
                self.max_pending_bytes_per_direction,
                HARD_MAX_PENDING_BYTES_PER_DIRECTION,
            ),
            (
                "max_http_header_bytes",
                self.max_http_header_bytes,
                HARD_MAX_HEADER_BYTES,
            ),
            ("max_http_headers", self.max_http_headers, HARD_MAX_HEADERS),
            (
                "max_http2_frames",
                self.max_http2_frames,
                HARD_MAX_HTTP2_FRAMES,
            ),
            (
                "max_hpack_dynamic_table_bytes",
                self.max_hpack_dynamic_table_bytes,
                HARD_MAX_HPACK_DYNAMIC_TABLE_BYTES,
            ),
            (
                "max_tls_extensions",
                self.max_tls_extensions,
                HARD_MAX_TLS_EXTENSIONS,
            ),
        ] {
            if value > hard_limit {
                return Err(CaptureError::InvalidLimit {
                    name,
                    reason: "exceeds the capture core hard ceiling",
                });
            }
        }

        Ok(())
    }
}

/// Identity, timing, transport, and original-destination data supplied by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureContext {
    pub flow_id: FlowId,
    pub connection_id: ConnectionId,
    pub capture_session_id: Option<CaptureSessionId>,
    pub process: Option<ProcessAttribution>,
    pub timing: FlowTiming,
    pub transport: TransportMetadata,
    pub destination: DestinationMetadata,
    pub close_reason: Option<String>,
}

/// Host-reported result at the boundary between TLS handling and decoding.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TlsInterception {
    /// TLS was detected but no interception decision was attempted.
    #[default]
    NotAttempted,
    /// Decrypted application bytes may be supplied through [`InputLayer::DecryptedTls`].
    Intercepted {
        negotiated_version: Option<String>,
        alpn: Option<String>,
    },
    /// Connectivity continued without decrypted application bytes.
    PassedThrough { reason: String },
    /// Interception failed; the encrypted transport may still be recorded.
    Failed { reason: String },
}

impl TlsInterception {
    fn validate(&self) -> Result<(), CaptureError> {
        match self {
            Self::NotAttempted => Ok(()),
            Self::Intercepted {
                negotiated_version,
                alpn,
            } => {
                for (field, value) in [
                    ("negotiated_version", negotiated_version.as_deref()),
                    ("alpn", alpn.as_deref()),
                ] {
                    if value.is_some_and(|value| {
                        value.trim().is_empty() || value.chars().any(char::is_control)
                    }) {
                        return Err(CaptureError::InvalidTlsBoundaryValue(field));
                    }
                }
                Ok(())
            }
            Self::PassedThrough { reason } | Self::Failed { reason } => {
                if reason.is_empty()
                    || !reason.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    })
                {
                    return Err(CaptureError::InvalidTlsBoundaryValue("reason"));
                }
                Ok(())
            }
        }
    }
}

/// Borrowed directional bytes for the batch convenience API.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DirectionalData<'a> {
    pub client_to_server: &'a [u8],
    pub server_to_client: &'a [u8],
}

impl fmt::Debug for DirectionalData<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectionalData")
            .field("client_to_server_bytes", &self.client_to_server.len())
            .field("server_to_client_bytes", &self.server_to_client.len())
            .finish()
    }
}

impl DirectionalData<'_> {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            client_to_server: &[],
            server_to_client: &[],
        }
    }
}

/// Stateless factory carrying validated limits for connection decoders.
#[derive(Debug, Clone, Default)]
pub struct CaptureCore {
    limits: CaptureLimits,
}

impl CaptureCore {
    pub fn new(limits: CaptureLimits) -> Result<Self, CaptureError> {
        limits.validate()?;
        Ok(Self { limits })
    }

    #[must_use]
    pub fn limits(&self) -> &CaptureLimits {
        &self.limits
    }

    #[must_use]
    pub fn begin(
        &self,
        context: CaptureContext,
        tls_interception: TlsInterception,
    ) -> CaptureSession {
        CaptureSession {
            context,
            limits: self.limits.clone(),
            tls_interception,
            wire_client: Vec::new(),
            wire_server: Vec::new(),
            decrypted_client: Vec::new(),
            decrypted_server: Vec::new(),
        }
    }

    /// Captures a complete deterministic input using the same bounded session API.
    pub fn capture(
        &self,
        context: CaptureContext,
        wire: DirectionalData<'_>,
        tls_interception: TlsInterception,
        decrypted: Option<DirectionalData<'_>>,
    ) -> Result<NormalizedFlowV0, CaptureError> {
        let mut session = self.begin(context, tls_interception);
        session.try_push(
            Direction::ClientToServer,
            InputLayer::Wire,
            wire.client_to_server,
        )?;
        session.try_push(
            Direction::ServerToClient,
            InputLayer::Wire,
            wire.server_to_client,
        )?;
        if let Some(decrypted) = decrypted {
            session.try_push(
                Direction::ClientToServer,
                InputLayer::DecryptedTls,
                decrypted.client_to_server,
            )?;
            session.try_push(
                Direction::ServerToClient,
                InputLayer::DecryptedTls,
                decrypted.server_to_client,
            )?;
        }
        session.finish()
    }
}

/// Bounded per-connection accumulator. A backpressure error leaves buffers unchanged.
pub struct CaptureSession {
    context: CaptureContext,
    limits: CaptureLimits,
    tls_interception: TlsInterception,
    wire_client: Vec<u8>,
    wire_server: Vec<u8>,
    decrypted_client: Vec<u8>,
    decrypted_server: Vec<u8>,
}

impl CaptureSession {
    pub fn try_push(
        &mut self,
        direction: Direction,
        layer: InputLayer,
        bytes: &[u8],
    ) -> Result<(), CaptureError> {
        if layer == InputLayer::DecryptedTls
            && !bytes.is_empty()
            && !matches!(self.tls_interception, TlsInterception::Intercepted { .. })
        {
            return Err(CaptureError::InvalidTlsBoundary(
                "decrypted bytes require an intercepted TLS state",
            ));
        }
        let (wire, decrypted) = match direction {
            Direction::ClientToServer => (&mut self.wire_client, &mut self.decrypted_client),
            Direction::ServerToClient => (&mut self.wire_server, &mut self.decrypted_server),
        };
        let buffered = wire
            .len()
            .checked_add(decrypted.len())
            .ok_or(CaptureError::SizeOverflow("capture buffer"))?;
        let required = buffered
            .checked_add(bytes.len())
            .ok_or(CaptureError::SizeOverflow("capture buffer"))?;
        if required > self.limits.max_pending_bytes_per_direction {
            return Err(CaptureError::Backpressure {
                direction,
                layer,
                buffered,
                incoming: bytes.len(),
                limit: self.limits.max_pending_bytes_per_direction,
            });
        }

        let target = match layer {
            InputLayer::Wire => wire,
            InputLayer::DecryptedTls => decrypted,
        };
        target
            .try_reserve(bytes.len())
            .map_err(|_| CaptureError::AllocationFailed { direction, layer })?;
        target.extend_from_slice(bytes);
        Ok(())
    }

    pub fn finish(self) -> Result<NormalizedFlowV0, CaptureError> {
        self.tls_interception.validate()?;

        let stream_transport = self.context.transport.protocol.as_str() == TransportProtocol::TCP;
        let tls_observation = if stream_transport {
            tls::inspect_client_stream(&self.wire_client, &self.limits)?
        } else {
            None
        };
        let has_decrypted = !self.decrypted_client.is_empty() || !self.decrypted_server.is_empty();
        if tls_observation.is_none() {
            if !matches!(self.tls_interception, TlsInterception::NotAttempted) {
                return Err(CaptureError::InvalidTlsBoundary(
                    "an interception result was supplied for a non-TLS connection",
                ));
            }
            if has_decrypted {
                return Err(CaptureError::InvalidTlsBoundary(
                    "decrypted bytes were supplied for a non-TLS connection",
                ));
            }
        } else if has_decrypted
            && !matches!(self.tls_interception, TlsInterception::Intercepted { .. })
        {
            return Err(CaptureError::InvalidTlsBoundary(
                "decrypted bytes require an intercepted TLS state",
            ));
        }

        let client_to_server_bytes = u64::try_from(self.wire_client.len())
            .map_err(|_| CaptureError::SizeOverflow("client-to-server connection bytes"))?;
        let server_to_client_bytes = u64::try_from(self.wire_server.len())
            .map_err(|_| CaptureError::SizeOverflow("server-to-client connection bytes"))?;
        let mut protocols = vec![ProtocolEvent::connection(ConnectionMetadata {
            client_to_server_bytes,
            server_to_client_bytes,
            close_reason: self.context.close_reason.clone(),
            extensions: BTreeMap::new(),
        })];

        if let Some(observation) = tls_observation {
            protocols.push(ProtocolEvent::tls(tls_metadata(
                observation,
                &self.tls_interception,
            )));
        }

        let (application_client, application_server) = if has_decrypted {
            (
                self.decrypted_client.as_slice(),
                self.decrypted_server.as_slice(),
            )
        } else if protocols.len() == 1 {
            (self.wire_client.as_slice(), self.wire_server.as_slice())
        } else {
            (&[][..], &[][..])
        };

        let http = if stream_transport && http2::is_client_preface(application_client) {
            Some(http2::decode(
                application_client,
                application_server,
                &self.limits,
            )?)
        } else if stream_transport && http1::looks_like_request(application_client) {
            Some(http1::decode(
                application_client,
                application_server,
                &self.context,
                protocols.len() > 1,
                &self.limits,
            )?)
        } else {
            None
        };
        if let Some(http) = http {
            protocols.push(ProtocolEvent::http(http));
        }

        let flow = NormalizedFlowV0 {
            contract_version: NORMALIZED_FLOW_CONTRACT_VERSION.to_owned(),
            flow_id: self.context.flow_id,
            connection_id: self.context.connection_id,
            capture_session_id: self.context.capture_session_id,
            process: self.context.process,
            timing: self.context.timing,
            transport: self.context.transport,
            destination: self.context.destination,
            protocols,
            extensions: BTreeMap::new(),
        };
        flow.validate()?;
        Ok(flow)
    }
}

fn tls_metadata(observation: tls::TlsObservation, interception: &TlsInterception) -> TlsMetadata {
    let (interception_state, negotiated_version, alpn, reason) = match interception {
        TlsInterception::NotAttempted => (TlsInterceptionState::NotAttempted, None, None, None),
        TlsInterception::Intercepted {
            negotiated_version,
            alpn,
        } => (
            TlsInterceptionState::Intercepted,
            negotiated_version.clone(),
            alpn.clone(),
            None,
        ),
        TlsInterception::PassedThrough { reason } => (
            TlsInterceptionState::PassedThrough,
            None,
            None,
            Some(reason.clone()),
        ),
        TlsInterception::Failed { reason } => (
            TlsInterceptionState::Failed,
            None,
            None,
            Some(reason.clone()),
        ),
    };

    let mut extensions = observation.extensions;
    if let Some(reason) = reason {
        extensions.insert("interception_reason".to_owned(), Value::String(reason));
    }
    TlsMetadata {
        sni: observation.sni,
        alpn,
        negotiated_version,
        interception_state,
        extensions,
    }
}
