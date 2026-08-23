use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
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

struct CountedClientStream {
    stream: TcpStream,
    written: Option<Arc<AtomicUsize>>,
}

impl Read for CountedClientStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buffer)
    }
}

impl Write for CountedClientStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let count = self.stream.write(buffer)?;
        if let Some(written) = &self.written {
            written.fetch_add(count, Ordering::Relaxed);
        }
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
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
fn mixed_case_absolute_dns_name_matches_wire_sni_and_leaf_identity() {
    const TARGET_NAME: &str = "CAPTURE.TEST.";
    const CLIENT_NAME: &str = "CaPtUrE.TeSt.";

    let origin_identity = origin_identity(ORIGIN_HOST);
    let origin_root = origin_identity.root.clone();
    assert!(matches!(
        InterceptionTarget::new("capture..test", ORIGIN_HOST, [origin_root.clone()]),
        Err(InterceptionError::InvalidServerName)
    ));
    assert!(matches!(
        InterceptionTarget::new("capture.test..", ORIGIN_HOST, [origin_root.clone()]),
        Err(InterceptionError::InvalidServerName)
    ));
    let (origin_address, origin_thread) = spawn_origin(origin_identity);
    let (interceptor, interception_root) = interceptor();
    let target = InterceptionTarget::new(TARGET_NAME, ORIGIN_HOST, [origin_root])
        .expect("a valid mixed-case absolute DNS name must be normalized");
    let (interception_address, interception_thread) =
        spawn_interceptor(interceptor, target, origin_address);

    let response = run_client(
        interception_address,
        CLIENT_NAME,
        [interception_root],
        Some(REQUEST),
    )
    .expect("rustls must verify the normalized leaf for an equivalent absolute DNS name");
    assert_eq!(response, RESPONSE);

    let result = interception_thread
        .join()
        .expect("interception thread must not panic")
        .expect("equivalent DNS identities must complete interception");
    let origin = origin_thread.join().expect("origin thread must not panic");
    assert_eq!(origin.requests, vec![REQUEST]);
    assert_eq!(result.transcript.decrypted().client_to_server, REQUEST);
    let observed_sni = result
        .flow
        .protocols
        .iter()
        .find_map(|event| match &event.metadata {
            ProtocolMetadata::Tls(metadata) => metadata.sni.as_deref(),
            _ => None,
        })
        .expect("the real wire ClientHello SNI must be present in the flow");
    assert!(observed_sni.eq_ignore_ascii_case(DOWNSTREAM_HOST));
    assert!(!observed_sni.ends_with('.'));
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
    let (upstream_for_interceptor, mut unused_peer) = tcp_pair();
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
    let relay_result = relay.join().expect("interception thread must not panic");
    assert!(
        matches!(
            relay_result,
            Err(InterceptionError::DownstreamTls)
                | Err(InterceptionError::UnexpectedEof(
                    InterceptionFailureStage::DownstreamHandshake
                ))
        ),
        "an untrusted client must fail only in the downstream handshake, got {relay_result:?}"
    );
    let mut upstream_bytes = Vec::new();
    unused_peer
        .read_to_end(&mut upstream_bytes)
        .expect("the unused upstream peer must close cleanly");
    assert!(
        upstream_bytes.is_empty(),
        "client certificate rejection must happen before upstream TLS is used"
    );
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
fn shared_transcript_budget_combines_wire_and_decrypted_request_bytes() {
    const BODY_BYTES: usize = 12 * 1024;
    const PLAINTEXT_HEADROOM: usize = 4095;

    let large_request = request_with_body(BODY_BYTES);
    let calibration_origin = origin_identity(ORIGIN_HOST);
    let calibration_root = calibration_origin.root.clone();
    let (calibration_origin_address, calibration_origin_thread) = spawn_origin(calibration_origin);
    let (calibration_interceptor, calibration_interception_root) = interceptor();
    let calibration_target =
        InterceptionTarget::new(DOWNSTREAM_HOST, ORIGIN_HOST, [calibration_root])
            .expect("calibration target must be valid");
    let (calibration_address, calibration_relay) = spawn_interceptor(
        calibration_interceptor,
        calibration_target,
        calibration_origin_address,
    );
    let calibration_response = run_client(
        calibration_address,
        DOWNSTREAM_HOST,
        [calibration_interception_root],
        Some(&large_request),
    )
    .expect("the unbounded calibration exchange must succeed");
    assert_eq!(calibration_response, RESPONSE);
    let calibration = calibration_relay
        .join()
        .expect("calibration relay must not panic")
        .expect("calibration relay must succeed");
    let calibration_origin = calibration_origin_thread
        .join()
        .expect("calibration origin must not panic");
    assert_eq!(calibration_origin.requests, vec![large_request.clone()]);

    let downstream_wire = calibration.transcript.downstream_wire();
    let client_wire_bytes = downstream_wire.client_to_server.len();
    let client_plaintext_bytes = large_request.len();
    let server_combined_bytes = downstream_wire
        .server_to_client
        .len()
        .checked_add(RESPONSE.len())
        .expect("test server transcript size must fit usize");
    assert!(
        tls_record_payload_lengths(downstream_wire.client_to_server)
            .into_iter()
            .any(|length| length >= large_request.len()),
        "the calibration request must occupy one approximately 12 KiB TLS fragment"
    );
    let shared_limit = client_wire_bytes
        .checked_add(PLAINTEXT_HEADROOM)
        .expect("test transcript limit must fit usize");
    let client_combined_bytes = client_wire_bytes
        .checked_add(client_plaintext_bytes)
        .expect("test client transcript size must fit usize");
    assert!(client_wire_bytes <= shared_limit);
    assert!(client_plaintext_bytes <= shared_limit);
    assert!(
        client_combined_bytes > shared_limit,
        "wire and plaintext must each fit while their combination exceeds the shared budget"
    );
    assert!(
        server_combined_bytes < shared_limit,
        "the opposite direction must remain below the shared limit"
    );

    let capture_limits = CaptureLimits {
        max_pending_bytes_per_direction: shared_limit,
        max_http_header_bytes: 4096,
        max_http_body_bytes: BODY_BYTES,
        max_http2_frame_payload_bytes: shared_limit,
        max_hpack_string_bytes: 4096,
        max_tls_record_bytes: shared_limit,
        ..CaptureLimits::default()
    };
    let core = CaptureCore::new(capture_limits).expect("calibrated limits must be coherent");
    let authority = CertificateAuthority::generate().expect("CA generation must succeed");
    let interception_root = authority.certificate_der();
    let limited_interceptor = TlsInterceptor::new(core, authority, InterceptionLimits::default())
        .expect("limited interceptor must initialize");
    let limited_origin = origin_identity(ORIGIN_HOST);
    let limited_origin_root = limited_origin.root.clone();
    let (limited_origin_address, limited_origin_thread) = spawn_origin(limited_origin);
    let limited_target =
        InterceptionTarget::new(DOWNSTREAM_HOST, ORIGIN_HOST, [limited_origin_root])
            .expect("limited target must be valid");
    let (limited_address, limited_relay) =
        spawn_interceptor(limited_interceptor, limited_target, limited_origin_address);
    let mut handshake_completed = false;
    let limited_wire_bytes = Arc::new(AtomicUsize::new(0));

    let client_result = run_client_observed(
        limited_address,
        DOWNSTREAM_HOST,
        [interception_root],
        Some(&large_request),
        Some(limited_wire_bytes.clone()),
        &mut handshake_completed,
    );
    assert!(
        handshake_completed,
        "the downstream TLS handshake must fit before the HTTP relay hits the shared budget"
    );
    assert!(client_result.is_err());
    let limited_wire_bytes = limited_wire_bytes.load(Ordering::Relaxed);
    assert_eq!(
        limited_wire_bytes, client_wire_bytes,
        "client TLS framing length must be deterministic across the two runs"
    );
    assert!(limited_wire_bytes <= shared_limit);
    assert!(
        limited_wire_bytes + client_plaintext_bytes > shared_limit,
        "the limited run must independently prove the combined client budget overflow"
    );
    assert!(matches!(
        limited_relay.join().expect("limited relay must not panic"),
        Err(InterceptionError::TranscriptLimit {
            direction: Direction::ClientToServer,
            limit,
        }) if limit == shared_limit
    ));
    let limited_origin = limited_origin_thread
        .join()
        .expect("limited origin must not panic");
    assert_eq!(
        limited_origin.requests,
        Vec::<Vec<u8>>::new(),
        "the shared budget must fail before an incomplete decrypted request is forwarded"
    );
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
            max_transaction_duration: Duration::from_secs(1),
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

#[test]
fn slow_trickle_client_cannot_extend_the_transaction_deadline() {
    let authority = CertificateAuthority::generate().expect("CA generation must succeed");
    let interceptor = TlsInterceptor::new(
        CaptureCore::default(),
        authority,
        InterceptionLimits {
            io_timeout: Duration::from_secs(1),
            max_handshake_iterations: 1024,
            max_transaction_duration: Duration::from_millis(300),
        },
    )
    .expect("positive interception limits must be valid");
    let origin = origin_identity(ORIGIN_HOST);
    let target = InterceptionTarget::new(DOWNSTREAM_HOST, ORIGIN_HOST, [origin.root])
        .expect("target must be valid");
    let (upstream, _unused_peer) = tcp_pair();
    let (address, relay) = spawn_interceptor_with_stream(interceptor, target, upstream);
    let mut client = TcpStream::connect(address).expect("slow loopback client must connect");
    let started = Instant::now();
    client
        .write_all(&[22, 3, 3, 16, 0])
        .expect("the incomplete record prefix must be delivered");
    let delivered_drips = Arc::new(AtomicUsize::new(0));
    for _ in 0..3 {
        thread::sleep(Duration::from_millis(20));
        client
            .write_all(&[0])
            .expect("initial drip bytes must arrive before the deadline");
        delivered_drips.fetch_add(1, Ordering::Relaxed);
    }
    let keep_writing = Arc::new(AtomicBool::new(true));
    let writer_flag = keep_writing.clone();
    let writer_drips = delivered_drips.clone();
    let writer = thread::spawn(move || {
        for _ in 0..64 {
            if !writer_flag.load(Ordering::Relaxed) || client.write_all(&[0]).is_err() {
                break;
            }
            writer_drips.fetch_add(1, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(20));
        }
    });

    let result = relay.join().expect("interception thread must not panic");
    let elapsed = started.elapsed();
    keep_writing.store(false, Ordering::Relaxed);
    writer.join().expect("slow writer thread must not panic");

    assert!(delivered_drips.load(Ordering::Relaxed) >= 3);
    assert!(matches!(
        result,
        Err(InterceptionError::TransactionDeadlineExceeded(
            InterceptionFailureStage::DownstreamClientHello,
        ))
    ));
    assert!(
        elapsed < Duration::from_millis(800),
        "the transaction deadline must expire before the one-second idle timeout"
    );
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
    let mut handshake_completed = false;
    run_client_observed(
        address,
        server_name,
        roots,
        request,
        None,
        &mut handshake_completed,
    )
}

fn run_client_observed(
    address: SocketAddr,
    server_name: &str,
    roots: impl IntoIterator<Item = CertificateDer<'static>>,
    request: Option<&[u8]>,
    written: Option<Arc<AtomicUsize>>,
    handshake_completed: &mut bool,
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
    let mut tls = StreamOwned::new(connection, CountedClientStream { stream, written });
    tls.conn.complete_io(&mut tls.sock)?;
    *handshake_completed = true;
    if let Some(request) = request {
        tls.write_all(request)?;
        tls.flush()?;
        read_http_message(&mut tls)
    } else {
        Ok(Vec::new())
    }
}

fn request_with_body(body_bytes: usize) -> Vec<u8> {
    let mut request = format!(
        "POST /proof HTTP/1.1\r\nHost: {ORIGIN_HOST}\r\nContent-Length: {body_bytes}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    request.resize(request.len() + body_bytes, b'x');
    request
}

fn tls_record_payload_lengths(wire: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut offset = 0;
    while offset < wire.len() {
        assert!(
            wire.len() - offset >= 5,
            "TLS record header must be complete"
        );
        let payload_bytes = usize::from(u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]));
        let record_end = offset
            .checked_add(5 + payload_bytes)
            .expect("test TLS record length must fit usize");
        assert!(
            record_end <= wire.len(),
            "TLS record payload must be complete"
        );
        lengths.push(payload_bytes);
        offset = record_end;
    }
    lengths
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
