use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};

use flowprobe_capture_core::{
    CaptureContext, CaptureCore, CaptureLimits, CertificateAuthority, Direction, InterceptionError,
    InterceptionFailureStage, InterceptionLimits, InterceptionResult, InterceptionTarget,
    TlsInterceptor,
};
use flowprobe_model::{
    ConnectionId, DestinationMetadata, FlowId, FlowTiming, ProtocolMetadata, TimestampNs,
    TlsInterceptionState, TransportMetadata, TransportProtocol,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};

const DOWNSTREAM_HOST: &str = "capture.test";
const ORIGIN_HOST: &str = "origin.test";
const WRONG_HOST: &str = "wrong.test";
const REQUEST: &[u8] = b"POST /proof HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 17\r\nConnection: close\r\n\r\ngenuine-plaintext";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 16\r\nConnection: close\r\n\r\ninterception-ok!";
const IO_TIMEOUT: Duration = Duration::from_secs(5);

struct OriginIdentity {
    root: CertificateDer<'static>,
    certificate: CertificateDer<'static>,
    private_key: PrivateKeyDer<'static>,
}

struct OriginObservation {
    requests: Vec<Vec<u8>>,
}

#[test]
fn generated_ca_terminates_and_independently_authenticates_a_loopback_origin() {
    let origin_identity = origin_identity(ORIGIN_HOST);
    let origin_root = origin_identity.root.clone();
    let origin_leaf = origin_identity.certificate.clone();
    let (origin_address, origin_thread) = spawn_origin(origin_identity);
    let (interceptor, interception_root) = interceptor();
    let target = InterceptionTarget::new(DOWNSTREAM_HOST, ORIGIN_HOST, [origin_root.clone()])
        .expect("independent origin root must be valid");
    let (interception_address, interception_thread) =
        spawn_interceptor(interceptor, target, origin_address);

    let response = run_client(
        interception_address,
        DOWNSTREAM_HOST,
        [interception_root.clone()],
        Some(REQUEST),
    )
    .expect("a client trusting the generated interception CA must succeed");
    assert_eq!(response, RESPONSE);

    let result = interception_thread
        .join()
        .expect("interception thread must not panic")
        .expect("interception must produce a normalized flow");
    let origin = origin_thread.join().expect("origin thread must not panic");
    assert_eq!(origin.requests, vec![REQUEST]);
    assert_ne!(origin_root, interception_root);
    assert_ne!(result.issued_leaf_certificate, interception_root);
    assert_ne!(result.issued_leaf_certificate, origin_leaf);
    assert_successful_capture(&result);
}

#[test]
fn wrong_sni_is_rejected_before_the_upstream_is_used() {
    let (interceptor, interception_root) = interceptor();
    let unrelated_origin = origin_identity(ORIGIN_HOST);
    let target = InterceptionTarget::new(
        DOWNSTREAM_HOST,
        ORIGIN_HOST,
        [unrelated_origin.root.clone()],
    )
    .expect("target must be valid");
    let (upstream_for_interceptor, _unused_peer) = tcp_pair();
    let (address, relay) =
        spawn_interceptor_with_stream(interceptor, target, upstream_for_interceptor);

    assert!(
        run_client(address, WRONG_HOST, [interception_root], None).is_err(),
        "the downstream connection must fail closed"
    );
    assert!(matches!(
        relay.join().expect("interception thread must not panic"),
        Err(InterceptionError::ServerNameMismatch)
    ));
}

#[test]
fn a_client_without_the_interception_root_rejects_the_leaf() {
    let (interceptor, _interception_root) = interceptor();
    let unrelated_client_ca = CertificateAuthority::generate()
        .expect("an unrelated in-memory client root must be generated");
    let origin = origin_identity(ORIGIN_HOST);
    let target = InterceptionTarget::new(DOWNSTREAM_HOST, ORIGIN_HOST, [origin.root.clone()])
        .expect("target must be valid");
    let (upstream_for_interceptor, _unused_peer) = tcp_pair();
    let (address, relay) =
        spawn_interceptor_with_stream(interceptor, target, upstream_for_interceptor);

    assert!(
        run_client(
            address,
            DOWNSTREAM_HOST,
            [unrelated_client_ca.certificate_der()],
            None,
        )
        .is_err(),
        "a client without the generated interception root must reject the leaf"
    );
    assert!(matches!(
        relay.join().expect("interception thread must not panic"),
        Err(InterceptionError::DownstreamTls)
    ));
}

#[test]
fn an_untrusted_origin_certificate_aborts_before_forwarding_http() {
    let origin_server_identity = origin_identity(ORIGIN_HOST);
    let (origin_address, origin_thread) = spawn_origin(origin_server_identity);
    let unrelated_origin_ca = origin_identity("unrelated-origin.test");
    let (interceptor, interception_root) = interceptor();
    let target = InterceptionTarget::new(
        DOWNSTREAM_HOST,
        ORIGIN_HOST,
        [unrelated_origin_ca.root.clone()],
    )
    .expect("target with an unrelated root is structurally valid");
    let (address, relay) = spawn_interceptor(interceptor, target, origin_address);

    assert!(
        run_client(address, DOWNSTREAM_HOST, [interception_root], Some(REQUEST),).is_err(),
        "the downstream client must not receive a false success"
    );
    assert!(matches!(
        relay.join().expect("interception thread must not panic"),
        Err(InterceptionError::UpstreamTls)
    ));
    let origin = origin_thread.join().expect("origin thread must not panic");
    assert!(
        origin.requests.is_empty(),
        "origin authentication must finish before any HTTP request is relayed"
    );
}

#[test]
fn private_key_holders_have_secret_safe_debug_output() {
    let authority = CertificateAuthority::generate().expect("CA generation must succeed");
    let interceptor = TlsInterceptor::new(
        CaptureCore::default(),
        authority,
        InterceptionLimits::default(),
    )
    .expect("default interceptor limits must be valid");

    let debug = format!("{interceptor:?}");
    assert!(debug.contains("certificate_der_bytes"));
    assert!(!debug.contains("PRIVATE KEY"));
    assert!(!debug.contains("secret_der"));
}

#[test]
fn transcript_budget_stops_an_oversized_client_hello() {
    let capture_limits = CaptureLimits {
        max_pending_bytes_per_direction: 128,
        max_http_header_bytes: 64,
        max_http_body_bytes: 64,
        max_http2_frame_payload_bytes: 64,
        max_hpack_string_bytes: 32,
        max_tls_record_bytes: 128,
        ..CaptureLimits::default()
    };
    let core = CaptureCore::new(capture_limits).expect("small coherent limits must be valid");
    let authority = CertificateAuthority::generate().expect("CA generation must succeed");
    let root = authority.certificate_der();
    let interceptor = TlsInterceptor::new(core, authority, InterceptionLimits::default())
        .expect("interceptor must accept the bounded capture core");
    let origin = origin_identity(ORIGIN_HOST);
    let target = InterceptionTarget::new(DOWNSTREAM_HOST, ORIGIN_HOST, [origin.root])
        .expect("target must be valid");
    let (upstream, _unused_peer) = tcp_pair();
    let (address, relay) = spawn_interceptor_with_stream(interceptor, target, upstream);

    assert!(run_client(address, DOWNSTREAM_HOST, [root], None).is_err());
    assert!(matches!(
        relay.join().expect("interception thread must not panic"),
        Err(InterceptionError::TranscriptLimit {
            direction: Direction::ClientToServer,
            limit: 128,
        })
    ));
}

#[test]
fn silent_client_is_stopped_by_the_configured_timeout() {
    let authority = CertificateAuthority::generate().expect("CA generation must succeed");
    let interceptor = TlsInterceptor::new(
        CaptureCore::default(),
        authority,
        InterceptionLimits {
            io_timeout: Duration::from_millis(100),
            max_handshake_iterations: 16,
        },
    )
    .expect("short positive limits must be valid");
    let origin = origin_identity(ORIGIN_HOST);
    let target = InterceptionTarget::new(DOWNSTREAM_HOST, ORIGIN_HOST, [origin.root])
        .expect("target must be valid");
    let (upstream, _unused_peer) = tcp_pair();
    let (address, relay) = spawn_interceptor_with_stream(interceptor, target, upstream);
    let _silent_client = TcpStream::connect(address).expect("silent loopback client must connect");

    assert!(matches!(
        relay.join().expect("interception thread must not panic"),
        Err(InterceptionError::Io {
            stage: InterceptionFailureStage::DownstreamClientHello,
            kind: std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock,
        })
    ));
}

fn interceptor() -> (TlsInterceptor, CertificateDer<'static>) {
    let authority = CertificateAuthority::generate().expect("interception CA generation must work");
    let root = authority.certificate_der();
    let interceptor = TlsInterceptor::new(
        CaptureCore::default(),
        authority,
        InterceptionLimits::default(),
    )
    .expect("default interception limits must be valid");
    (interceptor, root)
}

fn origin_identity(server_name: &str) -> OriginIdentity {
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("origin CA parameters must be valid");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("origin CA key generation must work");
    let ca_certificate = ca_params
        .self_signed(&ca_key)
        .expect("origin CA signing must work");

    let mut leaf_params = CertificateParams::new(vec![server_name.to_owned()])
        .expect("origin leaf parameters must be valid");
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .expect("origin leaf key generation must work");
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("origin leaf signing must work");
    OriginIdentity {
        root: ca_certificate.der().clone(),
        certificate: leaf.der().clone(),
        private_key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
    }
}

fn spawn_origin(identity: OriginIdentity) -> (SocketAddr, JoinHandle<OriginObservation>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback origin must bind");
    let address = listener.local_addr().expect("origin address must exist");
    let thread = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("origin must accept one relay");
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("origin read timeout must be set");
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .expect("origin write timeout must be set");
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("origin protocol versions must be valid")
            .with_no_client_auth()
            .with_single_cert(vec![identity.certificate], identity.private_key)
            .expect("origin certificate must be accepted");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connection = ServerConnection::new(Arc::new(config))
            .expect("origin server connection must initialize");
        let mut tls = StreamOwned::new(connection, stream);
        let mut requests = Vec::new();
        if let Ok(request) = read_http_message(&mut tls) {
            requests.push(request);
            let _ = tls.write_all(RESPONSE).and_then(|()| tls.flush());
        }
        OriginObservation { requests }
    });
    (address, thread)
}

fn spawn_interceptor(
    interceptor: TlsInterceptor,
    target: InterceptionTarget,
    origin_address: SocketAddr,
) -> (
    SocketAddr,
    JoinHandle<Result<InterceptionResult, InterceptionError>>,
) {
    let upstream =
        TcpStream::connect(origin_address).expect("relay must connect to loopback origin");
    spawn_interceptor_with_stream(interceptor, target, upstream)
}

fn spawn_interceptor_with_stream(
    interceptor: TlsInterceptor,
    target: InterceptionTarget,
    upstream: TcpStream,
) -> (
    SocketAddr,
    JoinHandle<Result<InterceptionResult, InterceptionError>>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("interceptor must bind loopback");
    let address = listener
        .local_addr()
        .expect("interceptor address must exist");
    let relay = thread::spawn(move || {
        let (downstream, _) = listener
            .accept()
            .expect("interceptor must accept one client");
        interceptor.intercept(capture_context(), downstream, upstream, &target)
    });
    (address, relay)
}

fn run_client(
    address: SocketAddr,
    server_name: &str,
    roots: impl IntoIterator<Item = CertificateDer<'static>>,
    request: Option<&[u8]>,
) -> std::io::Result<Vec<u8>> {
    let mut root_store = RootCertStore::empty();
    for root in roots {
        root_store.add(root).expect("test root must be valid");
    }
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("client protocol versions must be valid")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name =
        ServerName::try_from(server_name.to_owned()).expect("test server name must be valid");
    let connection =
        ClientConnection::new(Arc::new(config), name).expect("client connection must initialize");
    let stream = TcpStream::connect(address).expect("client must connect to loopback interceptor");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("client read timeout must be set");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("client write timeout must be set");
    let mut tls = StreamOwned::new(connection, stream);
    tls.conn.complete_io(&mut tls.sock)?;
    if let Some(request) = request {
        tls.write_all(request)?;
        tls.flush()?;
        read_http_message(&mut tls)
    } else {
        Ok(Vec::new())
    }
}

fn read_http_message(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut buffer = [0_u8; 512];
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP message ended before framing was complete",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
    };
    let content_length = bytes[..header_end]
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = std::str::from_utf8(line).ok()?;
            line.strip_prefix("Content-Length: ")?
                .trim()
                .parse::<usize>()
                .ok()
        })
        .unwrap_or(0);
    let total = header_end + content_length;
    while bytes.len() < total {
        let mut buffer = [0_u8; 512];
        let allowed = buffer.len().min(total - bytes.len());
        let count = reader.read(&mut buffer[..allowed])?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP body ended early",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback socket pair must bind");
    let address = listener
        .local_addr()
        .expect("socket pair address must exist");
    let client = TcpStream::connect(address).expect("socket pair must connect");
    let (server, _) = listener.accept().expect("socket pair must accept");
    (client, server)
}

fn capture_context() -> CaptureContext {
    CaptureContext {
        flow_id: FlowId::new("tls_001_flow").expect("flow ID must be valid"),
        connection_id: ConnectionId::new("tls_001_connection")
            .expect("connection ID must be valid"),
        capture_session_id: None,
        process: None,
        timing: FlowTiming {
            started_at: TimestampNs(1_720_000_000_000_000_000),
            first_byte_at: Some(TimestampNs(1_720_000_000_000_001_000)),
            ended_at: Some(TimestampNs(1_720_000_000_000_010_000)),
            extensions: BTreeMap::new(),
        },
        transport: TransportMetadata {
            protocol: TransportProtocol::new(TransportProtocol::TCP)
                .expect("TCP token must be valid"),
            source_ip: Some(
                "127.0.0.1"
                    .parse::<IpAddr>()
                    .expect("loopback IP must parse"),
            ),
            source_port: Some(52_001),
            extensions: BTreeMap::new(),
        },
        destination: DestinationMetadata {
            host: Some(DOWNSTREAM_HOST.to_owned()),
            ip: Some(
                "127.0.0.1"
                    .parse::<IpAddr>()
                    .expect("loopback IP must parse"),
            ),
            port: 443,
            extensions: BTreeMap::new(),
        },
        close_reason: Some("tls_001_complete".to_owned()),
    }
}

fn assert_successful_capture(result: &InterceptionResult) {
    assert_eq!(result.transcript.decrypted().client_to_server, REQUEST);
    assert_eq!(result.transcript.decrypted().server_to_client, RESPONSE);
    let wire = result.transcript.downstream_wire();
    assert_eq!(wire.client_to_server.first(), Some(&22));
    assert!(!wire.server_to_client.is_empty());
    assert!(
        !wire
            .client_to_server
            .windows(REQUEST.len())
            .any(|window| window == REQUEST),
        "downstream wire capture must be ciphertext, not substituted request plaintext"
    );
    assert!(
        !wire
            .client_to_server
            .windows(b"genuine-plaintext".len())
            .any(|window| window == b"genuine-plaintext"),
        "downstream TLS ciphertext must not expose the body canary"
    );
    assert!(
        !wire
            .server_to_client
            .windows(RESPONSE.len())
            .any(|window| window == RESPONSE),
        "downstream wire capture must not contain substituted response plaintext"
    );

    let tls = result
        .flow
        .protocols
        .iter()
        .find_map(|event| match &event.metadata {
            ProtocolMetadata::Tls(metadata) => Some(metadata),
            _ => None,
        })
        .expect("normalized flow must contain TLS metadata");
    assert_eq!(tls.sni.as_deref(), Some(DOWNSTREAM_HOST));
    assert_eq!(tls.alpn.as_deref(), Some("http/1.1"));
    assert!(matches!(
        tls.negotiated_version.as_deref(),
        Some("TLSv1.2" | "TLSv1.3")
    ));
    assert_eq!(tls.interception_state, TlsInterceptionState::Intercepted);
    let http = result
        .flow
        .protocols
        .iter()
        .find_map(|event| match &event.metadata {
            ProtocolMetadata::Http(metadata) => Some(metadata.as_ref()),
            _ => None,
        })
        .expect("genuinely decrypted HTTP bytes must produce HTTP metadata");
    assert_eq!(http.request.scheme, "https");
    assert_eq!(http.request.authority, ORIGIN_HOST);
    assert_eq!(http.request.path, "/proof");
    assert_eq!(
        http.response
            .as_ref()
            .expect("origin response must normalize")
            .status
            .get(),
        200
    );
    let debug = format!("{result:?}");
    assert!(!debug.contains("genuine-plaintext"));
    assert!(!debug.contains("Content-Length"));
}
