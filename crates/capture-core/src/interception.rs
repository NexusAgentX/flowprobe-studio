use std::{
    cell::Cell,
    error::Error,
    fmt,
    io::{self, Read, Write},
    net::TcpStream,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use flowprobe_model::NormalizedFlowV0;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::{
    ClientConfig, ClientConnection, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    StreamOwned,
    pki_types::{
        CertificateDer, DnsName, InvalidDnsNameError, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
    },
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
    /// Maximum idle duration of an individual socket read or write.
    pub io_timeout: Duration,
    /// Maximum number of explicit TLS read or write steps for either handshake.
    pub max_handshake_iterations: usize,
    /// Monotonic wall-clock limit shared by both TLS legs and the HTTP relay.
    pub max_transaction_duration: Duration,
}

impl Default for InterceptionLimits {
    fn default() -> Self {
        Self {
            io_timeout: Duration::from_secs(5),
            max_handshake_iterations: 1024,
            max_transaction_duration: Duration::from_secs(30),
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
    TransactionDeadlineExceeded(InterceptionFailureStage),
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
            Self::TransactionDeadlineExceeded(stage) => {
                write!(
                    formatter,
                    "TLS interception transaction deadline exceeded during {stage}"
                )
            }
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
        server_name: &DnsName<'_>,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), InterceptionError> {
        let server_name = server_name.as_ref();
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
    downstream_server_name: DnsName<'static>,
    upstream_server_name: ServerName<'static>,
    upstream_roots: RootCertStore,
}

fn normalize_dns_name(server_name: &DnsName<'_>) -> Result<DnsName<'static>, InvalidDnsNameError> {
    let server_name = server_name
        .as_ref()
        .strip_suffix('.')
        .unwrap_or(server_name.as_ref());
    DnsName::try_from(server_name.to_owned()).map(|server_name| server_name.to_lowercase_owned())
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
        let downstream_server_name = DnsName::try_from(downstream_server_name.into())
            .map_err(|_| InterceptionError::InvalidServerName)?;
        let downstream_server_name = normalize_dns_name(&downstream_server_name)
            .map_err(|_| InterceptionError::InvalidServerName)?;
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
        if limits.max_transaction_duration.is_zero() {
            return Err(InterceptionError::InvalidConfiguration(
                "transaction duration must be greater than zero",
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
        downstream: TcpStream,
        upstream: TcpStream,
        target: &InterceptionTarget,
    ) -> Result<InterceptionResult, InterceptionError> {
        let deadline = Instant::now()
            .checked_add(self.limits.max_transaction_duration)
            .ok_or(InterceptionError::InvalidConfiguration(
                "transaction duration is too large",
            ))?;
        let downstream = DeadlineStream::new(downstream, self.limits.io_timeout, deadline);
        let mut upstream = DeadlineStream::new(upstream, self.limits.io_timeout, deadline);

        let per_direction_limit = self.core.limits().max_pending_bytes_per_direction;
        let client_budget = ByteBudget::new(Direction::ClientToServer, per_direction_limit);
        let server_budget = ByteBudget::new(Direction::ServerToClient, per_direction_limit);
        let mut wire_client = Vec::new();
        let mut wire_server = Vec::new();
        let mut downstream_transport = RecordingStream::new(
            downstream,
            &mut wire_client,
            &mut wire_server,
            client_budget.clone(),
            server_budget.clone(),
        );
        let accepted = accept_client_hello(
            &mut downstream_transport,
            self.limits.max_handshake_iterations,
        )?;
        let client_hello = accepted.client_hello();
        let supplied_sni = client_hello
            .server_name()
            .ok_or(InterceptionError::MissingServerName)?;
        let supplied_sni =
            DnsName::try_from(supplied_sni).map_err(|_| InterceptionError::ServerNameMismatch)?;
        let supplied_sni =
            normalize_dns_name(&supplied_sni).map_err(|_| InterceptionError::ServerNameMismatch)?;
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
        let mut downstream_connection = accepted
            .into_connection(Arc::new(server_config))
            .map_err(|_| InterceptionError::DownstreamTls)?;
        complete_server_handshake(
            &mut downstream_connection,
            &mut downstream_transport,
            self.limits.max_handshake_iterations,
        )?;
        let mut downstream_tls = StreamOwned::new(downstream_connection, downstream_transport);
        require_http_1_1(downstream_tls.conn.alpn_protocol())?;

        let mut client_config = ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| InterceptionError::InvalidConfiguration("TLS protocol versions"))?
            .with_root_certificates(target.upstream_roots.clone())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![HTTP_1_1.to_vec()];
        let mut upstream_connection =
            ClientConnection::new(Arc::new(client_config), target.upstream_server_name.clone())
                .map_err(|_| InterceptionError::UpstreamTls)?;
        complete_client_handshake(
            &mut upstream_connection,
            &mut upstream,
            self.limits.max_handshake_iterations,
        )?;
        let mut upstream_tls = StreamOwned::new(upstream_connection, upstream);
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
        ensure_transaction_deadline(deadline, InterceptionFailureStage::DownstreamResponse)?;
        Ok(InterceptionResult {
            flow,
            transcript,
            interception,
            issued_leaf_certificate: leaf_certificate,
        })
    }
}

struct DeadlineStream {
    stream: TcpStream,
    idle_timeout: Duration,
    deadline: Instant,
}

impl DeadlineStream {
    fn new(stream: TcpStream, idle_timeout: Duration, deadline: Instant) -> Self {
        Self {
            stream,
            idle_timeout,
            deadline,
        }
    }

    fn operation_timeout(&self) -> io::Result<(Duration, bool)> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(transaction_deadline_error)?;
        Ok((
            self.idle_timeout.min(remaining),
            remaining <= self.idle_timeout,
        ))
    }

    fn map_deadline<T>(&self, result: io::Result<T>, deadline_limited: bool) -> io::Result<T> {
        if Instant::now() >= self.deadline {
            return Err(transaction_deadline_error());
        }
        match result {
            Err(error)
                if deadline_limited
                    && matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
            {
                Err(transaction_deadline_error())
            }
            result => result,
        }
    }
}

#[derive(Debug)]
struct TransactionDeadlineExpired;

impl fmt::Display for TransactionDeadlineExpired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TLS interception transaction deadline expired")
    }
}

impl Error for TransactionDeadlineExpired {}

fn transaction_deadline_error() -> io::Error {
    io::Error::other(TransactionDeadlineExpired)
}

fn ensure_transaction_deadline(
    deadline: Instant,
    stage: InterceptionFailureStage,
) -> Result<(), InterceptionError> {
    if Instant::now() >= deadline {
        Err(InterceptionError::TransactionDeadlineExceeded(stage))
    } else {
        Ok(())
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let (timeout, deadline_limited) = self.operation_timeout()?;
        let configured = self.stream.set_read_timeout(Some(timeout));
        self.map_deadline(configured, deadline_limited)?;
        let result = self.stream.read(buffer);
        self.map_deadline(result, deadline_limited)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let (timeout, deadline_limited) = self.operation_timeout()?;
        let configured = self.stream.set_write_timeout(Some(timeout));
        self.map_deadline(configured, deadline_limited)?;
        let result = self.stream.write(buffer);
        self.map_deadline(result, deadline_limited)
    }

    fn flush(&mut self) -> io::Result<()> {
        let (timeout, deadline_limited) = self.operation_timeout()?;
        let configured = self.stream.set_write_timeout(Some(timeout));
        self.map_deadline(configured, deadline_limited)?;
        let result = self.stream.flush();
        self.map_deadline(result, deadline_limited)
    }
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

struct RecordingStream<'a, T> {
    stream: T,
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

impl<'a, T> RecordingStream<'a, T> {
    fn new(
        stream: T,
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

impl<T: Read> Read for RecordingStream<'_, T> {
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

impl<T: Write> Write for RecordingStream<'_, T> {
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
    stream: &mut (impl Read + Write),
    max_iterations: usize,
) -> Result<rustls::server::Accepted, InterceptionError> {
    let stage = InterceptionFailureStage::DownstreamClientHello;
    let mut acceptor = Acceptor::default();
    let mut operations = 0;
    while operations < max_iterations {
        operations += 1;
        let consumed = acceptor
            .read_tls(stream)
            .map_err(|error| io_failure(stage, error))?;
        if consumed == 0 {
            return Err(InterceptionError::UnexpectedEof(stage));
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => return Ok(accepted),
            Ok(None) => {}
            Err((_, mut alert)) => {
                while operations < max_iterations {
                    operations += 1;
                    let count = match alert.write(stream) {
                        Ok(count) => count,
                        Err(error) => return Err(client_hello_alert_failure(stage, error)),
                    };
                    if count == 0 {
                        return Err(InterceptionError::DownstreamTls);
                    }
                }
                return Err(InterceptionError::DownstreamTls);
            }
        }
    }
    Err(InterceptionError::NoProgress(stage))
}

fn complete_server_handshake(
    connection: &mut ServerConnection,
    stream: &mut (impl Read + Write),
    max_iterations: usize,
) -> Result<(), InterceptionError> {
    connection
        .process_new_packets()
        .map_err(|_| InterceptionError::DownstreamTls)?;
    complete_handshake(
        connection,
        stream,
        max_iterations,
        InterceptionFailureStage::DownstreamHandshake,
    )
}

fn complete_client_handshake(
    connection: &mut ClientConnection,
    stream: &mut (impl Read + Write),
    max_iterations: usize,
) -> Result<(), InterceptionError> {
    complete_handshake(
        connection,
        stream,
        max_iterations,
        InterceptionFailureStage::UpstreamHandshake,
    )
}

trait HandshakeConnection {
    fn handshake_in_progress(&self) -> bool;
    fn needs_read(&self) -> bool;
    fn needs_write(&self) -> bool;
    fn read_tls_once(&mut self, reader: &mut dyn Read) -> io::Result<usize>;
    fn write_tls_once(&mut self, writer: &mut dyn Write) -> io::Result<usize>;
    fn process_new_packets_once(&mut self) -> Result<(), rustls::Error>;
}

impl HandshakeConnection for ServerConnection {
    fn handshake_in_progress(&self) -> bool {
        self.is_handshaking()
    }

    fn needs_read(&self) -> bool {
        self.wants_read()
    }

    fn needs_write(&self) -> bool {
        self.wants_write()
    }

    fn read_tls_once(&mut self, reader: &mut dyn Read) -> io::Result<usize> {
        self.read_tls(reader)
    }

    fn write_tls_once(&mut self, writer: &mut dyn Write) -> io::Result<usize> {
        self.write_tls(writer)
    }

    fn process_new_packets_once(&mut self) -> Result<(), rustls::Error> {
        self.process_new_packets().map(|_| ())
    }
}

impl HandshakeConnection for ClientConnection {
    fn handshake_in_progress(&self) -> bool {
        self.is_handshaking()
    }

    fn needs_read(&self) -> bool {
        self.wants_read()
    }

    fn needs_write(&self) -> bool {
        self.wants_write()
    }

    fn read_tls_once(&mut self, reader: &mut dyn Read) -> io::Result<usize> {
        self.read_tls(reader)
    }

    fn write_tls_once(&mut self, writer: &mut dyn Write) -> io::Result<usize> {
        self.write_tls(writer)
    }

    fn process_new_packets_once(&mut self) -> Result<(), rustls::Error> {
        self.process_new_packets().map(|_| ())
    }
}

fn complete_handshake(
    connection: &mut impl HandshakeConnection,
    stream: &mut (impl Read + Write),
    max_iterations: usize,
    stage: InterceptionFailureStage,
) -> Result<(), InterceptionError> {
    for _ in 0..max_iterations {
        if connection.needs_write() {
            let count = connection
                .write_tls_once(stream)
                .map_err(|error| io_failure(stage, error))?;
            if count == 0 {
                return Err(InterceptionError::NoProgress(stage));
            }
            continue;
        }
        if !connection.handshake_in_progress() {
            return Ok(());
        }
        if !connection.needs_read() {
            return Err(InterceptionError::NoProgress(stage));
        }
        let count = connection
            .read_tls_once(stream)
            .map_err(|error| io_failure(stage, error))?;
        if count == 0 {
            return Err(InterceptionError::UnexpectedEof(stage));
        }
        connection
            .process_new_packets_once()
            .map_err(|_| tls_failure(stage))?;
    }
    if !connection.needs_write() && !connection.handshake_in_progress() {
        Ok(())
    } else {
        Err(InterceptionError::NoProgress(stage))
    }
}

fn tls_failure(stage: InterceptionFailureStage) -> InterceptionError {
    match stage {
        InterceptionFailureStage::DownstreamHandshake => InterceptionError::DownstreamTls,
        InterceptionFailureStage::UpstreamHandshake => InterceptionError::UpstreamTls,
        _ => InterceptionError::NoProgress(stage),
    }
}

fn client_hello_alert_failure(
    stage: InterceptionFailureStage,
    error: io::Error,
) -> InterceptionError {
    match io_failure(stage, error) {
        failure @ (InterceptionError::TransactionDeadlineExceeded(_)
        | InterceptionError::TranscriptLimit { .. }
        | InterceptionError::Capture(CaptureError::AllocationFailed { .. })) => failure,
        _ => InterceptionError::DownstreamTls,
    }
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
    if error
        .get_ref()
        .and_then(|source| source.downcast_ref::<TransactionDeadlineExpired>())
        .is_some()
    {
        return InterceptionError::TransactionDeadlineExceeded(stage);
    }
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

    struct ScriptedIo {
        input: io::Cursor<Vec<u8>>,
        read_calls: usize,
        output: Vec<u8>,
        write_failure: Option<io::ErrorKind>,
    }

    struct PendingWritesHandshake {
        remaining_writes: usize,
    }

    impl HandshakeConnection for PendingWritesHandshake {
        fn handshake_in_progress(&self) -> bool {
            false
        }

        fn needs_read(&self) -> bool {
            false
        }

        fn needs_write(&self) -> bool {
            self.remaining_writes > 0
        }

        fn read_tls_once(&mut self, _reader: &mut dyn Read) -> io::Result<usize> {
            Ok(0)
        }

        fn write_tls_once(&mut self, writer: &mut dyn Write) -> io::Result<usize> {
            if self.remaining_writes == 0 {
                return Ok(0);
            }
            self.remaining_writes -= 1;
            writer.write(&[0])
        }

        fn process_new_packets_once(&mut self) -> Result<(), rustls::Error> {
            Ok(())
        }
    }

    impl ScriptedIo {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: io::Cursor::new(input),
                read_calls: 0,
                output: Vec::new(),
                write_failure: None,
            }
        }

        fn failing_writes(input: Vec<u8>, kind: io::ErrorKind) -> Self {
            Self {
                write_failure: Some(kind),
                ..Self::new(input)
            }
        }
    }

    impl Read for ScriptedIo {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.read_calls += 1;
            self.input.read(buffer)
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if let Some(kind) = self.write_failure {
                return Err(kind.into());
            }
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn acceptor_consumes_a_client_hello_larger_than_its_initial_buffer() {
        let client_hello = client_hello_with_alpn(large_alpn_protocols());
        assert!(client_hello.len() > 4096);
        let input_len = client_hello.len();
        let mut recorded = Vec::new();
        let mut written = Vec::new();
        let mut stream = RecordingStream::new(
            ScriptedIo::new(client_hello.clone()),
            &mut recorded,
            &mut written,
            ByteBudget::new(Direction::ClientToServer, input_len + 1024),
            ByteBudget::new(Direction::ServerToClient, 1024),
        );

        let accepted = accept_client_hello(&mut stream, 64).expect("ClientHello must be accepted");

        assert_eq!(accepted.client_hello().server_name(), Some("capture.test"));
        assert!(stream.stream.read_calls > 1);
        assert_eq!(stream.stream.input.position(), input_len as u64);
        assert_eq!(&*stream.read_bytes, &client_hello);
    }

    #[test]
    fn alert_write_failure_does_not_hide_a_client_hello_tls_failure() {
        let invalid_empty_client_hello = vec![22, 3, 3, 0, 4, 1, 0, 0, 0];
        let mut stream =
            ScriptedIo::failing_writes(invalid_empty_client_hello, io::ErrorKind::BrokenPipe);

        assert!(matches!(
            accept_client_hello(&mut stream, 8),
            Err(InterceptionError::DownstreamTls)
        ));
    }

    #[test]
    fn acceptor_reassembles_multiple_records_delivered_by_one_read() {
        let client_hello = client_hello_with_alpn(vec![HTTP_1_1.to_vec()]);
        let fragmented = fragment_tls_records(&client_hello, 64);
        assert!(fragmented.len() < 4096);
        assert!(fragmented.len() > client_hello.len());
        let mut recorded = Vec::new();
        let mut written = Vec::new();
        let mut stream = RecordingStream::new(
            ScriptedIo::new(fragmented.clone()),
            &mut recorded,
            &mut written,
            ByteBudget::new(Direction::ClientToServer, 4096),
            ByteBudget::new(Direction::ServerToClient, 1024),
        );

        let accepted = accept_client_hello(&mut stream, 8).expect("ClientHello must be accepted");

        assert_eq!(accepted.client_hello().server_name(), Some("capture.test"));
        assert_eq!(stream.stream.read_calls, 1);
        assert_eq!(&*stream.read_bytes, &fragmented);
    }

    #[test]
    fn accepted_connection_processes_prefetched_tail_before_another_read() {
        let client_hello = client_hello_with_alpn(vec![HTTP_1_1.to_vec()]);
        let mut input = fragment_tls_records(&client_hello, 64);
        input.extend_from_slice(&[23, 3, 3, 16, 0]);
        input.extend(std::iter::repeat_n(0, 4096));
        assert!(input.len() > 4096);
        let input_len = input.len();
        let mut recorded = Vec::new();
        let mut written = Vec::new();
        let mut stream = RecordingStream::new(
            ScriptedIo::new(input.clone()),
            &mut recorded,
            &mut written,
            ByteBudget::new(Direction::ClientToServer, input_len + 1024),
            ByteBudget::new(Direction::ServerToClient, 16 * 1024),
        );
        let accepted = accept_client_hello(&mut stream, 8).expect("ClientHello must be accepted");
        assert_eq!(stream.stream.read_calls, 1);
        assert!(stream.stream.input.position() < input_len as u64);
        let reads_after_accept = stream.stream.read_calls;
        let mut connection = accepted
            .into_connection(test_server_config())
            .expect("the accepted ClientHello must match the server config");

        assert!(matches!(
            complete_server_handshake(&mut connection, &mut stream, 8),
            Err(InterceptionError::DownstreamTls)
        ));
        assert!(stream.stream.read_calls > reads_after_accept);
        assert_eq!(stream.stream.input.position(), input_len as u64);
        assert_eq!(&*stream.read_bytes, &input);
    }

    #[test]
    fn handshake_flushes_all_pending_writes_after_completion() {
        let mut connection = PendingWritesHandshake {
            remaining_writes: 2,
        };
        let mut stream = ScriptedIo::new(Vec::new());

        complete_handshake(
            &mut connection,
            &mut stream,
            2,
            InterceptionFailureStage::DownstreamHandshake,
        )
        .expect("the operation limit must count writes, not a final state check");

        assert_eq!(stream.output, vec![0, 0]);
        assert_eq!(connection.remaining_writes, 0);
    }

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

    fn client_hello_with_alpn(alpn_protocols: Vec<Vec<u8>>) -> Vec<u8> {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("test protocol versions must be available")
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;
        let server_name =
            ServerName::try_from("capture.test".to_owned()).expect("test SNI must be valid");
        let mut connection = ClientConnection::new(Arc::new(config), server_name)
            .expect("test client connection must initialize");
        let mut wire = Vec::new();
        while connection.wants_write() {
            let written = connection
                .write_tls(&mut wire)
                .expect("initial ClientHello must serialize");
            assert!(written > 0);
        }
        wire
    }

    fn large_alpn_protocols() -> Vec<Vec<u8>> {
        let mut protocols = vec![HTTP_1_1.to_vec()];
        for index in 0_u16..32 {
            let mut protocol = vec![b'x'; 200];
            protocol[..2].copy_from_slice(&index.to_be_bytes());
            protocols.push(protocol);
        }
        protocols
    }

    fn fragment_tls_records(wire: &[u8], fragment_size: usize) -> Vec<u8> {
        let mut fragmented = Vec::new();
        let mut offset = 0;
        while offset < wire.len() {
            assert!(wire.len() - offset >= 5);
            let payload_len = usize::from(u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]));
            let payload_start = offset + 5;
            let payload_end = payload_start + payload_len;
            assert!(payload_end <= wire.len());
            for fragment in wire[payload_start..payload_end].chunks(fragment_size) {
                fragmented.extend_from_slice(&wire[offset..offset + 3]);
                fragmented.extend_from_slice(
                    &u16::try_from(fragment.len())
                        .expect("test TLS fragment must fit")
                        .to_be_bytes(),
                );
                fragmented.extend_from_slice(fragment);
            }
            offset = payload_end;
        }
        fragmented
    }

    fn test_server_config() -> Arc<ServerConfig> {
        let authority = CertificateAuthority::generate().expect("test CA generation must work");
        let server_name = DnsName::try_from("capture.test").expect("test DNS name must be valid");
        let (certificate, private_key) = authority
            .issue_server(&server_name)
            .expect("test leaf issuance must work");
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("test protocol versions must be available")
                .with_no_client_auth()
                .with_single_cert(vec![certificate], private_key)
                .expect("test leaf certificate must configure");
        config.alpn_protocols = vec![HTTP_1_1.to_vec()];
        Arc::new(config)
    }
}
