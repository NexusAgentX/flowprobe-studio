use std::{
    cell::Cell,
    error::Error,
    fmt,
    io::{self, Read, Write},
    net::TcpStream,
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use flowprobe_model::NormalizedFlowV0;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::{
    ClientConfig, ClientConnection, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::Acceptor,
};
use time::{Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroize;

use crate::{
    CaptureContext, CaptureCore, CaptureError, Direction, DirectionalData, HttpSide, InputLayer,
    TlsInterception,
};

const HTTP_1_1: &[u8] = b"http/1.1";
const CA_CERTIFICATE_VALIDITY: TimeDuration = TimeDuration::days(365);
const LEAF_CERTIFICATE_VALIDITY: TimeDuration = TimeDuration::days(7);
const CLOCK_SKEW: TimeDuration = TimeDuration::minutes(5);

/// Resource and progress ceilings for one intercepted TLS transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptionLimits {
    pub io_timeout: Duration,
    pub max_handshake_iterations: usize,
}

impl Default for InterceptionLimits {
    fn default() -> Self {
        Self {
            io_timeout: Duration::from_secs(5),
            max_handshake_iterations: 1024,
        }
    }
}

/// Stage at which a network or TLS failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptionFailureStage {
    DownstreamClientHello,
    DownstreamHandshake,
    UpstreamHandshake,
    DownstreamRequest,
    UpstreamRequest,
    UpstreamResponse,
    DownstreamResponse,
}

impl fmt::Display for InterceptionFailureStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DownstreamClientHello => "downstream ClientHello",
            Self::DownstreamHandshake => "downstream handshake",
            Self::UpstreamHandshake => "upstream handshake",
            Self::DownstreamRequest => "downstream request",
            Self::UpstreamRequest => "upstream request",
            Self::UpstreamResponse => "upstream response",
            Self::DownstreamResponse => "downstream response",
        })
    }
}

/// Secret-safe failures for the TLS interception boundary.
#[derive(Debug)]
pub enum InterceptionError {
    InvalidConfiguration(&'static str),
    InvalidServerName,
    MissingServerName,
    ServerNameMismatch,
    CertificateGeneration,
    InvalidTrustAnchor,
    Io {
        stage: InterceptionFailureStage,
        kind: io::ErrorKind,
    },
    UnexpectedEof(InterceptionFailureStage),
    NoProgress(InterceptionFailureStage),
    TranscriptLimit {
        direction: Direction,
        limit: usize,
    },
    DownstreamTls,
    UpstreamTls,
    UnsupportedAlpn,
    HttpFraming {
        side: HttpSide,
        reason: &'static str,
    },
    Capture(CaptureError),
}

impl fmt::Display for InterceptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(reason) => {
                write!(
                    formatter,
                    "invalid TLS interception configuration: {reason}"
                )
            }
            Self::InvalidServerName => formatter.write_str("invalid TLS server name"),
            Self::MissingServerName => formatter.write_str("downstream ClientHello has no SNI"),
            Self::ServerNameMismatch => {
                formatter.write_str("downstream SNI does not match the interception target")
            }
            Self::CertificateGeneration => formatter.write_str("TLS certificate generation failed"),
            Self::InvalidTrustAnchor => formatter.write_str("invalid upstream TLS trust anchor"),
            Self::Io { stage, kind } => write!(formatter, "I/O failure during {stage}: {kind}"),
            Self::UnexpectedEof(stage) => write!(formatter, "unexpected EOF during {stage}"),
            Self::NoProgress(stage) => write!(formatter, "no progress during {stage}"),
            Self::TranscriptLimit { direction, limit } => write!(
                formatter,
                "TLS transcript for {direction} exceeds the {limit}-byte capture limit"
            ),
            Self::DownstreamTls => formatter.write_str("downstream TLS handshake failed"),
            Self::UpstreamTls => formatter.write_str("upstream TLS authentication failed"),
            Self::UnsupportedAlpn => {
                formatter.write_str("TLS peer did not negotiate the required HTTP/1.1 ALPN")
            }
            Self::HttpFraming { side, reason } => {
                write!(
                    formatter,
                    "unsupported HTTP/1 {side} relay framing: {reason}"
                )
            }
            Self::Capture(error) => write!(formatter, "captured interception is invalid: {error}"),
        }
    }
}

impl Error for InterceptionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Capture(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CaptureError> for InterceptionError {
    fn from(error: CaptureError) -> Self {
        Self::Capture(error)
    }
}

/// In-memory interception CA. Its private key is never serialized by `Debug`.
pub struct CertificateAuthority {
    params: CertificateParams,
    certificate: Certificate,
    key_pair: KeyPair,
}

impl fmt::Debug for CertificateAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateAuthority")
            .field("certificate_der_bytes", &self.certificate.der().len())
            .finish_non_exhaustive()
    }
}

impl Drop for CertificateAuthority {
    fn drop(&mut self) {
        self.key_pair.zeroize();
    }
}

impl CertificateAuthority {
    /// Creates a path-length-zero CA that may issue only end-entity certificates.
    pub fn generate() -> Result<Self, InterceptionError> {
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|_| InterceptionError::CertificateGeneration)?;
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + CA_CERTIFICATE_VALIDITY;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|_| InterceptionError::CertificateGeneration)?;
        let certificate = match params.self_signed(&key_pair) {
            Ok(certificate) => certificate,
            Err(_) => {
                key_pair.zeroize();
                return Err(InterceptionError::CertificateGeneration);
            }
        };
        Ok(Self {
            params,
            certificate,
            key_pair,
        })
    }

    /// DER certificate clients can add to an isolated root store.
    #[must_use]
    pub fn certificate_der(&self) -> CertificateDer<'static> {
        self.certificate.der().clone()
    }

    fn issue_server(
        &self,
        server_name: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), InterceptionError> {
        ServerName::try_from(server_name.to_owned())
            .map_err(|_| InterceptionError::InvalidServerName)?;
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(vec![server_name.to_owned()])
            .map_err(|_| InterceptionError::CertificateGeneration)?;
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + LEAF_CERTIFICATE_VALIDITY;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let mut key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|_| InterceptionError::CertificateGeneration)?;
        let issuer = Issuer::from_params(&self.params, &self.key_pair);
        let certificate = match params.signed_by(&key_pair, &issuer) {
            Ok(certificate) => certificate,
            Err(_) => {
                key_pair.zeroize();
                return Err(InterceptionError::CertificateGeneration);
            }
        };
        let mut private_der = key_pair.serialize_der();
        key_pair.zeroize();
        let private_key = PrivatePkcs8KeyDer::from(private_der.clone()).into();
        private_der.zeroize();
        Ok((certificate.der().clone(), private_key))
    }
}

/// Trusted names and roots for the two independently authenticated TLS legs.
#[derive(Clone)]
pub struct InterceptionTarget {
    downstream_server_name: String,
    upstream_server_name: ServerName<'static>,
    upstream_roots: RootCertStore,
}

impl fmt::Debug for InterceptionTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InterceptionTarget")
            .field("downstream_server_name", &self.downstream_server_name)
            .field("upstream_server_name", &self.upstream_server_name)
            .field("upstream_root_count", &self.upstream_roots.len())
            .finish()
    }
}

impl InterceptionTarget {
    pub fn new(
        downstream_server_name: impl Into<String>,
        upstream_server_name: impl Into<String>,
        upstream_trust_anchors: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Result<Self, InterceptionError> {
        let downstream_server_name = downstream_server_name.into();
        if !matches!(
            ServerName::try_from(downstream_server_name.clone()),
            Ok(ServerName::DnsName(_))
        ) {
            return Err(InterceptionError::InvalidServerName);
        }
        let upstream_server_name = ServerName::try_from(upstream_server_name.into())
            .map_err(|_| InterceptionError::InvalidServerName)?;
        let mut upstream_roots = RootCertStore::empty();
        for certificate in upstream_trust_anchors {
            upstream_roots
                .add(certificate)
                .map_err(|_| InterceptionError::InvalidTrustAnchor)?;
        }
        if upstream_roots.is_empty() {
            return Err(InterceptionError::InvalidConfiguration(
                "at least one upstream trust anchor is required",
            ));
        }
        Ok(Self {
            downstream_server_name,
            upstream_server_name,
            upstream_roots,
        })
    }
}

/// Actual bytes observed and decrypted while relaying a TLS transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct TlsTranscript {
    downstream_wire_client_to_server: Vec<u8>,
    downstream_wire_server_to_client: Vec<u8>,
    decrypted_client_to_server: Vec<u8>,
    decrypted_server_to_client: Vec<u8>,
}

impl fmt::Debug for TlsTranscript {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsTranscript")
            .field(
                "downstream_wire_client_to_server_bytes",
                &self.downstream_wire_client_to_server.len(),
            )
            .field(
                "downstream_wire_server_to_client_bytes",
                &self.downstream_wire_server_to_client.len(),
            )
            .field(
                "decrypted_client_to_server_bytes",
                &self.decrypted_client_to_server.len(),
            )
            .field(
                "decrypted_server_to_client_bytes",
                &self.decrypted_server_to_client.len(),
            )
            .finish()
    }
}

impl TlsTranscript {
    #[must_use]
    pub fn downstream_wire(&self) -> DirectionalData<'_> {
        DirectionalData {
            client_to_server: &self.downstream_wire_client_to_server,
            server_to_client: &self.downstream_wire_server_to_client,
        }
    }

    #[must_use]
    pub fn decrypted(&self) -> DirectionalData<'_> {
        DirectionalData {
            client_to_server: &self.decrypted_client_to_server,
            server_to_client: &self.decrypted_server_to_client,
        }
    }
}

/// Successful relay output, with metadata derived from the real TLS connection.
pub struct InterceptionResult {
    pub flow: NormalizedFlowV0,
    pub transcript: TlsTranscript,
    pub interception: TlsInterception,
    pub issued_leaf_certificate: CertificateDer<'static>,
}

impl fmt::Debug for InterceptionResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InterceptionResult")
            .field("flow_id", &self.flow.flow_id)
            .field("protocol_event_count", &self.flow.protocols.len())
            .field("transcript", &self.transcript)
            .field("interception", &self.interception)
            .field(
                "issued_leaf_certificate_der_bytes",
                &self.issued_leaf_certificate.len(),
            )
            .finish()
    }
}

/// Generic TLS interception boundary owned by Capture Core.
pub struct TlsInterceptor {
    core: CaptureCore,
    authority: CertificateAuthority,
    limits: InterceptionLimits,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl fmt::Debug for TlsInterceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsInterceptor")
            .field("capture_limits", self.core.limits())
            .field("interception_limits", &self.limits)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

impl TlsInterceptor {
    pub fn new(
        core: CaptureCore,
        authority: CertificateAuthority,
        limits: InterceptionLimits,
    ) -> Result<Self, InterceptionError> {
        if limits.io_timeout.is_zero() {
            return Err(InterceptionError::InvalidConfiguration(
                "I/O timeout must be greater than zero",
            ));
        }
        if limits.max_handshake_iterations == 0 {
            return Err(InterceptionError::InvalidConfiguration(
                "handshake iteration limit must be greater than zero",
            ));
        }
        Ok(Self {
            core,
            authority,
            limits,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }

    #[must_use]
    pub fn authority_certificate_der(&self) -> CertificateDer<'static> {
        self.authority.certificate_der()
    }

    /// Terminates downstream TLS, authenticates upstream TLS, and relays one HTTP/1.1 exchange.
    pub fn intercept(
        &self,
        context: CaptureContext,
        mut downstream: TcpStream,
        upstream: TcpStream,
        target: &InterceptionTarget,
    ) -> Result<InterceptionResult, InterceptionError> {
        configure_socket(
            &downstream,
            self.limits.io_timeout,
            InterceptionFailureStage::DownstreamHandshake,
        )?;
        configure_socket(
            &upstream,
            self.limits.io_timeout,
            InterceptionFailureStage::UpstreamHandshake,
        )?;

        let per_direction_limit = self.core.limits().max_pending_bytes_per_direction;
        let client_budget = ByteBudget::new(Direction::ClientToServer, per_direction_limit);
        let server_budget = ByteBudget::new(Direction::ServerToClient, per_direction_limit);
        let mut wire_client = Vec::new();
        let mut wire_server = Vec::new();
        let accepted = accept_client_hello(
            &mut downstream,
            &mut wire_client,
            &client_budget,
            self.limits.max_handshake_iterations,
        )?;
        let client_hello = accepted.client_hello();
        let supplied_sni = client_hello
            .server_name()
            .ok_or(InterceptionError::MissingServerName)?;
        if supplied_sni != target.downstream_server_name {
            return Err(InterceptionError::ServerNameMismatch);
        }

        let (leaf_certificate, leaf_key) = self
            .authority
            .issue_server(&target.downstream_server_name)?;
        let mut server_config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| InterceptionError::InvalidConfiguration("TLS protocol versions"))?
            .with_no_client_auth()
            .with_single_cert(vec![leaf_certificate.clone()], leaf_key)
            .map_err(|_| InterceptionError::CertificateGeneration)?;
        server_config.alpn_protocols = vec![HTTP_1_1.to_vec()];
        let downstream_connection = accepted
            .into_connection(Arc::new(server_config))
            .map_err(|_| InterceptionError::DownstreamTls)?;
        let downstream_transport = RecordingStream::new(
            downstream,
            &mut wire_client,
            &mut wire_server,
            client_budget.clone(),
            server_budget.clone(),
        );
        let mut downstream_tls = StreamOwned::new(downstream_connection, downstream_transport);
        complete_server_handshake(&mut downstream_tls, self.limits.max_handshake_iterations)?;
        require_http_1_1(downstream_tls.conn.alpn_protocol())?;

        let mut client_config = ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| InterceptionError::InvalidConfiguration("TLS protocol versions"))?
            .with_root_certificates(target.upstream_roots.clone())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![HTTP_1_1.to_vec()];
        let upstream_connection =
            ClientConnection::new(Arc::new(client_config), target.upstream_server_name.clone())
                .map_err(|_| InterceptionError::UpstreamTls)?;
        let mut upstream_tls = StreamOwned::new(upstream_connection, upstream);
        complete_client_handshake(&mut upstream_tls, self.limits.max_handshake_iterations)?;
        require_http_1_1(upstream_tls.conn.alpn_protocol())?;

        let request = read_http_message(
            &mut downstream_tls,
            HttpSide::Request,
            self.core.limits(),
            InterceptionFailureStage::DownstreamRequest,
            &client_budget,
        )?;
        write_all(
            &mut upstream_tls,
            &request,
            InterceptionFailureStage::UpstreamRequest,
        )?;
        let response = read_http_message(
            &mut upstream_tls,
            HttpSide::Response,
            self.core.limits(),
            InterceptionFailureStage::UpstreamResponse,
            &server_budget,
        )?;
        write_all(
            &mut downstream_tls,
            &response,
            InterceptionFailureStage::DownstreamResponse,
        )?;

        let negotiated_version = downstream_tls.conn.protocol_version().map(protocol_version);
        let alpn = downstream_tls
            .conn
            .alpn_protocol()
            .map(|value| String::from_utf8_lossy(value).into_owned());
        drop(downstream_tls);
        let interception = TlsInterception::Intercepted {
            negotiated_version,
            alpn,
        };
        let transcript = TlsTranscript {
            downstream_wire_client_to_server: wire_client,
            downstream_wire_server_to_client: wire_server,
            decrypted_client_to_server: request,
            decrypted_server_to_client: response,
        };
        debug_assert_eq!(
            client_budget.used(),
            transcript.downstream_wire_client_to_server.len()
                + transcript.decrypted_client_to_server.len()
        );
        debug_assert_eq!(
            server_budget.used(),
            transcript.downstream_wire_server_to_client.len()
                + transcript.decrypted_server_to_client.len()
        );
        let flow = self.core.capture(
            context,
            transcript.downstream_wire(),
            interception.clone(),
            Some(transcript.decrypted()),
        )?;
        Ok(InterceptionResult {
            flow,
            transcript,
            interception,
            issued_leaf_certificate: leaf_certificate,
        })
    }
}

fn configure_socket(
    stream: &TcpStream,
    timeout: Duration,
    stage: InterceptionFailureStage,
) -> Result<(), InterceptionError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| io_failure(stage, error))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| io_failure(stage, error))?;
    Ok(())
}

#[derive(Clone)]
struct ByteBudget(Rc<ByteBudgetState>);

struct ByteBudgetState {
    direction: Direction,
    limit: usize,
    used: Cell<usize>,
}

impl ByteBudget {
    fn new(direction: Direction, limit: usize) -> Self {
        Self(Rc::new(ByteBudgetState {
            direction,
            limit,
            used: Cell::new(0),
        }))
    }

    fn used(&self) -> usize {
        self.0.used.get()
    }

    fn remaining(&self) -> usize {
        self.0.limit.saturating_sub(self.used())
    }

    fn reserve(&self, bytes: usize) -> Result<(), InterceptionError> {
        let required =
            self.used()
                .checked_add(bytes)
                .ok_or(InterceptionError::TranscriptLimit {
                    direction: self.0.direction,
                    limit: self.0.limit,
                })?;
        if required > self.0.limit {
            return Err(InterceptionError::TranscriptLimit {
                direction: self.0.direction,
                limit: self.0.limit,
            });
        }
        self.0.used.set(required);
        Ok(())
    }

    fn reserve_io(&self, bytes: usize) -> io::Result<()> {
        self.reserve(bytes).map_err(io::Error::other)
    }
}

struct RecordingStream<'a> {
    stream: TcpStream,
    read_bytes: &'a mut Vec<u8>,
    written_bytes: &'a mut Vec<u8>,
    read_budget: ByteBudget,
    write_budget: ByteBudget,
}

#[derive(Debug)]
struct AllocationFailure {
    direction: Direction,
    layer: InputLayer,
}

impl fmt::Display for AllocationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("capture buffer allocation failed")
    }
}

impl Error for AllocationFailure {}

impl<'a> RecordingStream<'a> {
    fn new(
        stream: TcpStream,
        read_bytes: &'a mut Vec<u8>,
        written_bytes: &'a mut Vec<u8>,
        read_budget: ByteBudget,
        write_budget: ByteBudget,
    ) -> Self {
        Self {
            stream,
            read_bytes,
            written_bytes,
            read_budget,
            write_budget,
        }
    }
}

impl Read for RecordingStream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.read_budget.remaining();
        if remaining == 0 {
            return self.read_budget.reserve_io(1).map(|()| 0);
        }
        let allowed = buffer.len().min(remaining);
        self.read_bytes.try_reserve(allowed).map_err(|_| {
            io::Error::other(AllocationFailure {
                direction: self.read_budget.0.direction,
                layer: InputLayer::Wire,
            })
        })?;
        let count = self.stream.read(&mut buffer[..allowed])?;
        self.read_budget.reserve_io(count)?;
        self.read_bytes.extend_from_slice(&buffer[..count]);
        Ok(count)
    }
}

impl Write for RecordingStream<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.write_budget.remaining();
        if remaining == 0 {
            return self.write_budget.reserve_io(1).map(|()| 0);
        }
        let allowed = buffer.len().min(remaining);
        self.written_bytes.try_reserve(allowed).map_err(|_| {
            io::Error::other(AllocationFailure {
                direction: self.write_budget.0.direction,
                layer: InputLayer::Wire,
            })
        })?;
        let count = self.stream.write(&buffer[..allowed])?;
        self.write_budget.reserve_io(count)?;
        self.written_bytes.extend_from_slice(&buffer[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn accept_client_hello(
    stream: &mut TcpStream,
    wire_client: &mut Vec<u8>,
    budget: &ByteBudget,
    max_iterations: usize,
) -> Result<rustls::server::Accepted, InterceptionError> {
    let mut acceptor = Acceptor::default();
    for _ in 0..max_iterations {
        let before = wire_client.len();
        let remaining = budget.remaining();
        if remaining == 0 {
            return budget.reserve(1).and_then(|()| {
                Err(InterceptionError::NoProgress(
                    InterceptionFailureStage::DownstreamClientHello,
                ))
            });
        }
        let mut buffer = [0_u8; 16 * 1024];
        let allowed = remaining.min(buffer.len());
        let count = stream
            .read(&mut buffer[..allowed])
            .map_err(|error| io_failure(InterceptionFailureStage::DownstreamClientHello, error))?;
        if count == 0 {
            return Err(InterceptionError::UnexpectedEof(
                InterceptionFailureStage::DownstreamClientHello,
            ));
        }
        budget.reserve(count)?;
        wire_client.try_reserve(count).map_err(|_| {
            InterceptionError::Capture(CaptureError::AllocationFailed {
                direction: Direction::ClientToServer,
                layer: InputLayer::Wire,
            })
        })?;
        wire_client.extend_from_slice(&buffer[..count]);
        let mut cursor = io::Cursor::new(&buffer[..count]);
        acceptor
            .read_tls(&mut cursor)
            .map_err(|error| io_failure(InterceptionFailureStage::DownstreamClientHello, error))?;
        match acceptor.accept() {
            Ok(Some(accepted)) => return Ok(accepted),
            Ok(None) => {}
            Err((_, mut alert)) => {
                let _ = alert.write_all(stream);
                return Err(InterceptionError::DownstreamTls);
            }
        }
        if wire_client.len() == before {
            return Err(InterceptionError::NoProgress(
                InterceptionFailureStage::DownstreamClientHello,
            ));
        }
    }
    Err(InterceptionError::NoProgress(
        InterceptionFailureStage::DownstreamClientHello,
    ))
}

fn complete_server_handshake(
    stream: &mut StreamOwned<ServerConnection, RecordingStream<'_>>,
    max_iterations: usize,
) -> Result<(), InterceptionError> {
    complete_handshake(
        stream,
        max_iterations,
        InterceptionFailureStage::DownstreamHandshake,
        InterceptionError::DownstreamTls,
    )
}

fn complete_client_handshake(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    max_iterations: usize,
) -> Result<(), InterceptionError> {
    complete_handshake(
        stream,
        max_iterations,
        InterceptionFailureStage::UpstreamHandshake,
        InterceptionError::UpstreamTls,
    )
}

trait CompleteIo {
    fn is_handshaking(&self) -> bool;
    fn complete_io_once(&mut self) -> io::Result<(usize, usize)>;
}

impl<T: Read + Write> CompleteIo for StreamOwned<ServerConnection, T> {
    fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    fn complete_io_once(&mut self) -> io::Result<(usize, usize)> {
        self.conn.complete_io(&mut self.sock)
    }
}

impl<T: Read + Write> CompleteIo for StreamOwned<ClientConnection, T> {
    fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    fn complete_io_once(&mut self) -> io::Result<(usize, usize)> {
        self.conn.complete_io(&mut self.sock)
    }
}

fn complete_handshake(
    stream: &mut impl CompleteIo,
    max_iterations: usize,
    stage: InterceptionFailureStage,
    tls_error: InterceptionError,
) -> Result<(), InterceptionError> {
    for _ in 0..max_iterations {
        if !stream.is_handshaking() {
            return Ok(());
        }
        match stream.complete_io_once() {
            Ok((0, 0)) => return Err(InterceptionError::NoProgress(stage)),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::InvalidData => return Err(tls_error),
            Err(error) => return Err(io_failure(stage, error)),
        }
    }
    Err(InterceptionError::NoProgress(stage))
}

fn require_http_1_1(alpn: Option<&[u8]>) -> Result<(), InterceptionError> {
    if alpn == Some(HTTP_1_1) {
        Ok(())
    } else {
        Err(InterceptionError::UnsupportedAlpn)
    }
}

fn protocol_version(version: ProtocolVersion) -> String {
    match version {
        ProtocolVersion::TLSv1_2 => "TLSv1.2".to_owned(),
        ProtocolVersion::TLSv1_3 => "TLSv1.3".to_owned(),
        _ => "unknown".to_owned(),
    }
}

fn read_http_message(
    reader: &mut impl Read,
    side: HttpSide,
    limits: &crate::CaptureLimits,
    stage: InterceptionFailureStage,
    budget: &ByteBudget,
) -> Result<Vec<u8>, InterceptionError> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if bytes.len() >= limits.max_http_header_bytes {
            return Err(InterceptionError::Capture(
                CaptureError::HttpHeaderBytesLimitExceeded {
                    side,
                    limit: limits.max_http_header_bytes,
                },
            ));
        }
        let mut buffer = [0_u8; 4096];
        let allowed = buffer
            .len()
            .min(limits.max_http_header_bytes - bytes.len())
            .min(budget.remaining());
        if allowed == 0 {
            budget.reserve(1)?;
            return Err(InterceptionError::NoProgress(stage));
        }
        let count = reader
            .read(&mut buffer[..allowed])
            .map_err(|error| io_failure(stage, error))?;
        if count == 0 {
            return Err(InterceptionError::UnexpectedEof(stage));
        }
        budget.reserve(count)?;
        bytes
            .try_reserve(count)
            .map_err(|_| relay_allocation_error(side))?;
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };

    let content_length = parse_content_length(&bytes[..header_end], side, limits.max_http_headers)?;
    if content_length > limits.max_http_body_bytes {
        return Err(InterceptionError::Capture(
            CaptureError::HttpBodyLimitExceeded {
                side,
                declared: content_length,
                limit: limits.max_http_body_bytes,
            },
        ));
    }
    let total = header_end
        .checked_add(content_length)
        .ok_or(InterceptionError::Capture(CaptureError::SizeOverflow(
            "HTTP relay message",
        )))?;
    if bytes.len() > total {
        return Err(InterceptionError::HttpFraming {
            side,
            reason: "pipelining or trailing bytes",
        });
    }
    while bytes.len() < total {
        let mut buffer = [0_u8; 4096];
        let allowed = buffer
            .len()
            .min(total - bytes.len())
            .min(budget.remaining());
        if allowed == 0 {
            budget.reserve(1)?;
            return Err(InterceptionError::NoProgress(stage));
        }
        let count = reader
            .read(&mut buffer[..allowed])
            .map_err(|error| io_failure(stage, error))?;
        if count == 0 {
            return Err(InterceptionError::UnexpectedEof(stage));
        }
        budget.reserve(count)?;
        bytes
            .try_reserve(count)
            .map_err(|_| relay_allocation_error(side))?;
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

fn parse_content_length(
    headers: &[u8],
    side: HttpSide,
    max_headers: usize,
) -> Result<usize, InterceptionError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(max_headers)
        .map_err(|_| relay_allocation_error(side))?;
    slots.resize(max_headers, httparse::EMPTY_HEADER);
    let parsed_headers = match side {
        HttpSide::Request => {
            let mut message = httparse::Request::new(&mut slots);
            let status = message
                .parse(headers)
                .map_err(|error| http_parse_error(side, error, max_headers))?;
            if !status.is_complete() {
                return Err(InterceptionError::HttpFraming {
                    side,
                    reason: "incomplete headers",
                });
            }
            if message.version != Some(1) {
                return Err(InterceptionError::HttpFraming {
                    side,
                    reason: "HTTP version other than 1.1",
                });
            }
            message.headers
        }
        HttpSide::Response => {
            let mut message = httparse::Response::new(&mut slots);
            let status = message
                .parse(headers)
                .map_err(|error| http_parse_error(side, error, max_headers))?;
            if !status.is_complete() {
                return Err(InterceptionError::HttpFraming {
                    side,
                    reason: "incomplete headers",
                });
            }
            if message.version != Some(1) {
                return Err(InterceptionError::HttpFraming {
                    side,
                    reason: "HTTP version other than 1.1",
                });
            }
            message.headers
        }
    };
    let mut content_length = None;
    for header in parsed_headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(InterceptionError::HttpFraming {
                side,
                reason: "transfer encoding",
            });
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(InterceptionError::HttpFraming {
                    side,
                    reason: "multiple content lengths",
                });
            }
            let value = std::str::from_utf8(header.value)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(InterceptionError::HttpFraming {
                    side,
                    reason: "invalid content length",
                })?;
            content_length = Some(value);
        }
    }
    match (side, content_length) {
        (HttpSide::Request, None) => Ok(0),
        (HttpSide::Response, None) => Err(InterceptionError::HttpFraming {
            side,
            reason: "response without content length",
        }),
        (_, Some(content_length)) => Ok(content_length),
    }
}

fn http_parse_error(
    side: HttpSide,
    error: httparse::Error,
    max_headers: usize,
) -> InterceptionError {
    if error == httparse::Error::TooManyHeaders {
        InterceptionError::Capture(CaptureError::HttpHeaderCountLimitExceeded {
            side,
            limit: max_headers,
        })
    } else {
        InterceptionError::HttpFraming {
            side,
            reason: "malformed headers",
        }
    }
}

fn relay_allocation_error(side: HttpSide) -> InterceptionError {
    InterceptionError::Capture(CaptureError::AllocationFailed {
        direction: match side {
            HttpSide::Request => Direction::ClientToServer,
            HttpSide::Response => Direction::ServerToClient,
        },
        layer: InputLayer::DecryptedTls,
    })
}

fn write_all(
    writer: &mut impl Write,
    bytes: &[u8],
    stage: InterceptionFailureStage,
) -> Result<(), InterceptionError> {
    writer
        .write_all(bytes)
        .and_then(|()| writer.flush())
        .map_err(|error| io_failure(stage, error))
}

fn io_failure(stage: InterceptionFailureStage, error: io::Error) -> InterceptionError {
    if let Some(limit) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<InterceptionError>())
        && let InterceptionError::TranscriptLimit { direction, limit } = limit
    {
        return InterceptionError::TranscriptLimit {
            direction: *direction,
            limit: *limit,
        };
    }
    if let Some(allocation) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<AllocationFailure>())
    {
        return InterceptionError::Capture(CaptureError::AllocationFailed {
            direction: allocation.direction,
            layer: allocation.layer,
        });
    }
    InterceptionError::Io {
        stage,
        kind: error.kind(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_without_content_length_is_a_zero_length_message() {
        assert_eq!(
            parse_content_length(
                b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
                HttpSide::Request,
                8,
            )
            .expect("a bodyless request is supported"),
            0
        );
    }

    #[test]
    fn response_without_content_length_fails_instead_of_truncating() {
        assert!(matches!(
            parse_content_length(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
                HttpSide::Response,
                8,
            ),
            Err(InterceptionError::HttpFraming {
                side: HttpSide::Response,
                reason: "response without content length",
            })
        ));
    }

    #[test]
    fn header_slot_exhaustion_is_a_typed_capture_limit() {
        assert!(matches!(
            parse_content_length(
                b"GET / HTTP/1.1\r\nHost: example.test\r\nAccept: */*\r\n\r\n",
                HttpSide::Request,
                1,
            ),
            Err(InterceptionError::Capture(
                CaptureError::HttpHeaderCountLimitExceeded {
                    side: HttpSide::Request,
                    limit: 1,
                }
            ))
        ));
    }

    #[test]
    fn transfer_encoding_is_rejected_by_the_minimum_relay() {
        assert!(matches!(
            parse_content_length(
                b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
                HttpSide::Request,
                8,
            ),
            Err(InterceptionError::HttpFraming {
                side: HttpSide::Request,
                reason: "transfer encoding",
            })
        ));
    }
}
