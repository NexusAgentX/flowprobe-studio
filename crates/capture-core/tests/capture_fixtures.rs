use std::{collections::BTreeMap, net::IpAddr, panic::AssertUnwindSafe};

use flowprobe_capture_core::{
    CaptureContext, CaptureCore, CaptureError, CaptureLimits, Direction, DirectionalData,
    InputLayer, TlsInterception,
};
use flowprobe_model::{
    ConnectionId, DestinationMetadata, FlowId, FlowTiming, HttpStatus, NormalizedFlowV0,
    ProtocolMetadata, TimestampNs, TlsInterceptionState, TransportMetadata, TransportProtocol,
};

const HTTP1_REQUEST: &str = include_str!("../../../tests/fixtures/http1/basic-request.http");
const HTTP1_RESPONSE: &str = include_str!("../../../tests/fixtures/http1/basic-response.http");
const CHUNKED_HTTP1_REQUEST: &str =
    include_str!("../../../tests/fixtures/http1/chunked-request.http");
const CHUNKED_HTTP1_RESPONSE: &str =
    include_str!("../../../tests/fixtures/http1/chunked-response.http");
const TRUNCATED_HTTP1_REQUEST: &str =
    include_str!("../../../tests/fixtures/http1/truncated-request.http");
const HTTP2_CLIENT: &str = include_str!("../../../tests/fixtures/http2/basic-client.hex");
const HTTP2_SERVER: &str = include_str!("../../../tests/fixtures/http2/basic-server.hex");
const TRUNCATED_HTTP2_FRAME: &str =
    include_str!("../../../tests/fixtures/http2/truncated-frame.hex");
const TLS_CLIENT_HELLO: &str = include_str!("../../../tests/fixtures/tls/client-hello.hex");
const TRUNCATED_TLS_RECORD: &str = include_str!("../../../tests/fixtures/tls/truncated-record.hex");

#[test]
fn http1_request_response_fixture_emits_expected_normalized_transaction() {
    let request = escaped_http(HTTP1_REQUEST);
    let response = escaped_http(HTTP1_RESPONSE);
    let flow = CaptureCore::default()
        .capture(
            context("http1", 80),
            DirectionalData {
                client_to_server: &request,
                server_to_client: &response,
            },
            TlsInterception::NotAttempted,
            None,
        )
        .expect("valid HTTP/1 fixture must decode");

    assert_valid_round_trip(&flow);
    assert_eq!(flow.protocols.len(), 2);
    let transaction = http_transaction(&flow);
    assert_eq!(transaction.stream_id, None);
    assert_eq!(transaction.request.method, "POST");
    assert_eq!(transaction.request.scheme, "http");
    assert_eq!(transaction.request.authority, "fixture.test");
    assert_eq!(transaction.request.path, "/resource");
    assert_eq!(transaction.request.version, "HTTP/1.1");
    assert_eq!(
        transaction.request.content_type.as_deref(),
        Some("text/plain")
    );
    assert_eq!(transaction.request.byte_count, 5);
    let response = transaction
        .response
        .as_ref()
        .expect("fixture has a response");
    assert_eq!(response.status, HttpStatus::new(201).expect("valid status"));
    assert_eq!(response.version, "HTTP/1.1");
    assert_eq!(
        response.content_type.as_deref(),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(response.byte_count, 7);
}

#[test]
fn http1_chunked_fixtures_count_payload_without_framing_or_trailers() {
    let request = escaped_http(CHUNKED_HTTP1_REQUEST);
    let response = escaped_http(CHUNKED_HTTP1_RESPONSE);
    let flow = CaptureCore::default()
        .capture(
            context("http1_chunked", 80),
            DirectionalData {
                client_to_server: &request,
                server_to_client: &response,
            },
            TlsInterception::NotAttempted,
            None,
        )
        .expect("valid chunked fixtures must decode");

    assert_valid_round_trip(&flow);
    let transaction = http_transaction(&flow);
    assert_eq!(transaction.request.path, "/chunked");
    assert_eq!(transaction.request.byte_count, 9);
    assert_eq!(
        transaction
            .response
            .as_ref()
            .expect("fixture has a response")
            .byte_count,
        3
    );
}

#[test]
fn http2_fixture_emits_expected_normalized_transaction() {
    let client = decode_hex(HTTP2_CLIENT);
    let server = decode_hex(HTTP2_SERVER);
    let flow = CaptureCore::default()
        .capture(
            context("http2", 443),
            DirectionalData {
                client_to_server: &client,
                server_to_client: &server,
            },
            TlsInterception::NotAttempted,
            None,
        )
        .expect("valid HTTP/2 fixture must decode");

    assert_valid_round_trip(&flow);
    let transaction = http_transaction(&flow);
    assert_eq!(transaction.stream_id, Some(1));
    assert_eq!(transaction.request.method, "POST");
    assert_eq!(transaction.request.scheme, "https");
    assert_eq!(transaction.request.authority, "fixture.test");
    assert_eq!(transaction.request.path, "/resource");
    assert_eq!(transaction.request.version, "HTTP/2");
    assert_eq!(
        transaction.request.content_type.as_deref(),
        Some("text/plain")
    );
    assert_eq!(transaction.request.byte_count, 5);
    let response = transaction
        .response
        .as_ref()
        .expect("fixture has a response");
    assert_eq!(response.status.get(), 200);
    assert_eq!(response.version, "HTTP/2");
    assert_eq!(response.content_type.as_deref(), Some("text/plain"));
    assert_eq!(response.byte_count, 7);
}

#[test]
fn tls_passthrough_and_intercepted_boundaries_are_explicit() {
    let client_hello = decode_hex(TLS_CLIENT_HELLO);
    let passthrough = CaptureCore::default()
        .capture(
            context("tls_passthrough", 443),
            DirectionalData {
                client_to_server: &client_hello,
                server_to_client: &[],
            },
            TlsInterception::PassedThrough {
                reason: "policy".to_owned(),
            },
            None,
        )
        .expect("valid pass-through ClientHello must produce metadata");
    assert_eq!(passthrough.protocols.len(), 2);
    let tls = tls_metadata(&passthrough);
    assert_eq!(tls.sni.as_deref(), Some("fixture.test"));
    assert_eq!(tls.interception_state, TlsInterceptionState::PassedThrough);
    assert_eq!(tls.alpn, None);
    assert_eq!(tls.extensions["interception_reason"], "policy");
    assert_eq!(tls.extensions["offered_alpn"][0], "h2");

    let request = escaped_http(HTTP1_REQUEST);
    let response = escaped_http(HTTP1_RESPONSE);
    let intercepted = CaptureCore::default()
        .capture(
            context("tls_intercepted", 443),
            DirectionalData {
                client_to_server: &client_hello,
                server_to_client: &[],
            },
            TlsInterception::Intercepted {
                negotiated_version: Some("TLSv1.3".to_owned()),
                alpn: Some("http/1.1".to_owned()),
            },
            Some(DirectionalData {
                client_to_server: &request,
                server_to_client: &response,
            }),
        )
        .expect("explicit intercepted TLS boundary must decode supplied plaintext");
    assert_eq!(intercepted.protocols.len(), 3);
    let tls = tls_metadata(&intercepted);
    assert_eq!(tls.interception_state, TlsInterceptionState::Intercepted);
    assert_eq!(tls.negotiated_version.as_deref(), Some("TLSv1.3"));
    assert_eq!(tls.alpn.as_deref(), Some("http/1.1"));
    assert_eq!(http_transaction(&intercepted).request.scheme, "https");

    let rejected = CaptureCore::default().capture(
        context("tls_invalid_boundary", 443),
        DirectionalData {
            client_to_server: &client_hello,
            server_to_client: &[],
        },
        TlsInterception::PassedThrough {
            reason: "policy".to_owned(),
        },
        Some(DirectionalData {
            client_to_server: &request,
            server_to_client: &response,
        }),
    );
    assert!(matches!(rejected, Err(CaptureError::InvalidTlsBoundary(_))));
}

#[test]
fn malformed_and_truncated_fixtures_return_typed_errors() {
    let request = escaped_http(TRUNCATED_HTTP1_REQUEST);
    let http1 = CaptureCore::default().capture(
        context("bad_http1", 80),
        DirectionalData {
            client_to_server: &request,
            server_to_client: &[],
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        http1,
        Err(CaptureError::TruncatedHttpBody {
            declared: 5,
            available: 2,
            ..
        })
    ));

    let h2 = decode_hex(TRUNCATED_HTTP2_FRAME);
    let http2 = CaptureCore::default().capture(
        context("bad_http2", 80),
        DirectionalData {
            client_to_server: &h2,
            server_to_client: &[],
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        http2,
        Err(CaptureError::TruncatedHttp2Frame {
            declared: 8,
            available: 2
        })
    ));

    let tls = decode_hex(TRUNCATED_TLS_RECORD);
    let truncated_tls = CaptureCore::default().capture(
        context("bad_tls", 443),
        DirectionalData {
            client_to_server: &tls,
            server_to_client: &[],
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        truncated_tls,
        Err(CaptureError::TruncatedTlsRecord {
            declared: 8,
            available: 2
        })
    ));
}

#[test]
fn backpressure_rejects_without_mutating_the_session() {
    let limits = CaptureLimits {
        max_pending_bytes_per_direction: 64,
        max_http_header_bytes: 32,
        max_http_headers: 8,
        max_http_body_bytes: 32,
        max_http2_frame_payload_bytes: 32,
        max_http2_frames: 8,
        max_hpack_string_bytes: 16,
        max_hpack_dynamic_table_bytes: 64,
        max_tls_record_bytes: 32,
        max_tls_extensions: 8,
    };
    let core = CaptureCore::new(limits).expect("test limits are valid");
    let mut session = core.begin(context("backpressure", 9000), TlsInterception::NotAttempted);
    session
        .try_push(Direction::ClientToServer, InputLayer::Wire, &[b'x'; 40])
        .expect("first chunk fits");
    assert!(matches!(
        session.try_push(Direction::ClientToServer, InputLayer::Wire, &[b'y'; 30]),
        Err(CaptureError::Backpressure {
            buffered: 40,
            incoming: 30,
            limit: 64,
            ..
        })
    ));
    session
        .try_push(Direction::ClientToServer, InputLayer::Wire, &[b'z'; 24])
        .expect("rejected chunk did not mutate the buffer");
    let flow = session
        .finish()
        .expect("opaque bounded input must normalize");
    match &flow.protocols[0].metadata {
        ProtocolMetadata::Connection(metadata) => {
            assert_eq!(metadata.client_to_server_bytes, 64);
        }
        other => panic!("expected connection metadata, got {other:?}"),
    }
}

#[test]
fn parser_resource_limits_and_opaque_fallback_are_enforced() {
    let request = escaped_http(HTTP1_REQUEST);
    let header_limited = CaptureCore::new(CaptureLimits {
        max_http_header_bytes: 32,
        ..CaptureLimits::default()
    })
    .expect("header-limited configuration is valid")
    .capture(
        context("header_limit", 80),
        DirectionalData {
            client_to_server: &request,
            server_to_client: &[],
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        header_limited,
        Err(CaptureError::HttpHeaderBytesLimitExceeded { limit: 32, .. })
    ));

    let h2 = decode_hex(HTTP2_CLIENT);
    let frame_limited = CaptureCore::new(CaptureLimits {
        max_http2_frames: 1,
        ..CaptureLimits::default()
    })
    .expect("frame-limited configuration is valid")
    .capture(
        context("frame_limit", 80),
        DirectionalData {
            client_to_server: &h2,
            server_to_client: &[],
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        frame_limited,
        Err(CaptureError::Http2FrameLimitExceeded { limit: 1 })
    ));

    let opaque = CaptureCore::default()
        .capture(
            context("opaque", 9000),
            DirectionalData {
                client_to_server: &[0x00, 0xff, 0x7f, 0x01],
                server_to_client: &[0x02, 0x03],
            },
            TlsInterception::NotAttempted,
            None,
        )
        .expect("unrecognized bounded bytes must fall back to connection metadata");
    assert_eq!(opaque.protocols.len(), 1);
    assert!(matches!(
        opaque.protocols[0].metadata,
        ProtocolMetadata::Connection(_)
    ));
}

#[test]
fn non_http_text_protocols_fall_back_to_opaque_connection_metadata() {
    for (suffix, client, server) in [
        (
            "smtp",
            b"EHLO mail.example\r\n".as_slice(),
            b"250 hello\r\n".as_slice(),
        ),
        (
            "redis",
            b"GET key\r\n".as_slice(),
            b"$5\r\nvalue\r\n".as_slice(),
        ),
    ] {
        let flow = CaptureCore::default()
            .capture(
                context(suffix, 9000),
                DirectionalData {
                    client_to_server: client,
                    server_to_client: server,
                },
                TlsInterception::NotAttempted,
                None,
            )
            .expect("non-HTTP text protocols must remain opaque");
        assert_eq!(flow.protocols.len(), 1);
        assert!(matches!(
            flow.protocols[0].metadata,
            ProtocolMetadata::Connection(_)
        ));
    }
}

#[test]
fn http1_tunnels_interim_responses_and_invalid_lengths_are_typed_errors() {
    let connect = CaptureCore::default().capture(
        context("http1_connect", 443),
        DirectionalData {
            client_to_server: b"CONNECT fixture.test:443 HTTP/1.1\r\nHost: fixture.test\r\n\r\n",
            server_to_client: b"HTTP/1.1 200 Connection Established\r\n\r\n0123456789",
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        connect,
        Err(CaptureError::UnsupportedHttp1Framing {
            side: flowprobe_capture_core::HttpSide::Request,
            ..
        })
    ));

    for (suffix, response) in [
        ("lone", b"HTTP/1.1 100 Continue\r\n\r\n".as_slice()),
        (
            "followed_by_final",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
        ),
    ] {
        let result = CaptureCore::default().capture(
            context(&format!("http1_interim_{suffix}"), 80),
            DirectionalData {
                client_to_server:
                    b"POST / HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: 0\r\n\r\n",
                server_to_client: response,
            },
            TlsInterception::NotAttempted,
            None,
        );
        assert!(matches!(
            result,
            Err(CaptureError::UnsupportedHttp1Framing {
                side: flowprobe_capture_core::HttpSide::Response,
                ..
            })
        ));
    }

    for (suffix, request, response) in [
        (
            "request",
            b"POST / HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: +1\r\n\r\nx".as_slice(),
            b"".as_slice(),
        ),
        (
            "bodyless_response",
            b"GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n".as_slice(),
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: +1\r\n\r\n".as_slice(),
        ),
    ] {
        let result = CaptureCore::default().capture(
            context(&format!("http1_signed_length_{suffix}"), 80),
            DirectionalData {
                client_to_server: request,
                server_to_client: response,
            },
            TlsInterception::NotAttempted,
            None,
        );
        assert!(matches!(result, Err(CaptureError::MalformedHttp1 { .. })));
    }
}

#[test]
fn http2_minimum_stream_state_and_pseudo_headers_are_enforced() {
    let missing_scheme = h2_request(1, 0x05, &[0x82, 0x84], None);
    let valid_headers = [
        0x82, 0x87, 0x84, 0x01, 0x0c, b'f', b'i', b'x', b't', b'u', b'r', b'e', b'.', b't', b'e',
        b's', b't',
    ];
    let even_stream = h2_request(2, 0x05, &valid_headers, None);
    let data_after_end = h2_request(1, 0x05, &valid_headers, Some((0x01, b"x")));
    let incomplete_stream = h2_request(1, 0x04, &valid_headers, None);
    let missing_client_settings = h2_request_without_settings(1, 0x05, &valid_headers);
    let connect_request = h2_request(1, 0x05, b"\x02\x07CONNECT\x01\x0cfixture.test", None);
    let mut mismatched_length_headers = valid_headers.to_vec();
    mismatched_length_headers.extend_from_slice(b"\x00\x0econtent-length\x012");
    let mismatched_length = h2_request(1, 0x04, &mismatched_length_headers, Some((0x01, b"x")));
    let mut signed_length_headers = valid_headers.to_vec();
    signed_length_headers.extend_from_slice(b"\x00\x0econtent-length\x02+1");
    let signed_length = h2_request(1, 0x04, &signed_length_headers, Some((0x01, b"x")));

    for (suffix, bytes, expected) in [
        ("h2_missing_scheme", missing_scheme, "malformed"),
        ("h2_even_stream", even_stream, "malformed"),
        ("h2_data_after_end", data_after_end, "malformed"),
        ("h2_incomplete", incomplete_stream, "unsupported"),
        (
            "h2_missing_client_settings",
            missing_client_settings,
            "malformed",
        ),
        (
            "h2_mismatched_content_length",
            mismatched_length,
            "malformed",
        ),
        ("h2_signed_content_length", signed_length, "malformed"),
        ("h2_connect", connect_request, "unsupported"),
    ] {
        let result = CaptureCore::default().capture(
            context(suffix, 443),
            DirectionalData {
                client_to_server: &bytes,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        );
        match expected {
            "malformed" => assert!(matches!(result, Err(CaptureError::MalformedHttp2(_)))),
            "unsupported" => assert!(matches!(result, Err(CaptureError::UnsupportedHttp2(_)))),
            _ => unreachable!("test expectation is fixed"),
        }
    }

    let valid_client = h2_request(1, 0x05, &valid_headers, None);
    let missing_server_settings = h2_frame(1, 0x05, 1, &[0x88]);
    let missing_server_result = CaptureCore::default().capture(
        context("h2_missing_server_settings", 443),
        DirectionalData {
            client_to_server: &valid_client,
            server_to_client: &missing_server_settings,
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        missing_server_result,
        Err(CaptureError::MalformedHttp2(_))
    ));

    let mut forbidden_body_response = h2_frame(4, 0, 0, &[]);
    forbidden_body_response.extend(h2_frame(1, 0x04, 1, &[0x89]));
    forbidden_body_response.extend(h2_frame(0, 0x01, 1, b"x"));
    let forbidden_body_result = CaptureCore::default().capture(
        context("h2_204_body", 443),
        DirectionalData {
            client_to_server: &valid_client,
            server_to_client: &forbidden_body_response,
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        forbidden_body_result,
        Err(CaptureError::MalformedHttp2(_))
    ));

    let mut informational_response = h2_frame(4, 0, 0, &[]);
    informational_response.extend(h2_frame(1, 0x05, 1, b"\x08\x03100"));
    let informational_result = CaptureCore::default().capture(
        context("h2_informational", 443),
        DirectionalData {
            client_to_server: &valid_client,
            server_to_client: &informational_response,
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        informational_result,
        Err(CaptureError::UnsupportedHttp2(_))
    ));

    for (suffix, client_headers, status_header) in [
        (
            "h2_head_content_length",
            b"\x02\x04HEAD\x87\x84\x01\x0cfixture.test".as_slice(),
            0x88,
        ),
        ("h2_304_content_length", valid_headers.as_slice(), 0x8b),
    ] {
        let client = h2_request(1, 0x05, client_headers, None);
        let mut response_headers = vec![status_header];
        response_headers.extend_from_slice(b"\x00\x0econtent-length\x0212");
        let mut server = h2_frame(4, 0, 0, &[]);
        server.extend(h2_frame(1, 0x05, 1, &response_headers));
        let flow = CaptureCore::default()
            .capture(
                context(suffix, 443),
                DirectionalData {
                    client_to_server: &client,
                    server_to_client: &server,
                },
                TlsInterception::NotAttempted,
                None,
            )
            .expect("HEAD and 304 may describe representation length without DATA");
        assert_eq!(
            http_transaction(&flow)
                .response
                .as_ref()
                .expect("response metadata")
                .byte_count,
            0
        );
    }

    let lowercase_connect = h2_request(
        1,
        0x05,
        b"\x02\x07connect\x87\x84\x01\x0cfixture.test",
        None,
    );
    let lowercase_connect_flow = CaptureCore::default()
        .capture(
            context("h2_lowercase_connect", 443),
            DirectionalData {
                client_to_server: &lowercase_connect,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        )
        .expect("lowercase extension method is distinct from CONNECT");
    assert_eq!(
        http_transaction(&lowercase_connect_flow).request.method,
        "connect"
    );

    let lowercase_head = h2_request(1, 0x05, b"\x02\x04head\x87\x84\x01\x0cfixture.test", None);
    let mut lowercase_head_response = h2_frame(4, 0, 0, &[]);
    lowercase_head_response.extend(h2_frame(1, 0x04, 1, &[0x88]));
    lowercase_head_response.extend(h2_frame(0, 0x01, 1, b"x"));
    let lowercase_head_flow = CaptureCore::default()
        .capture(
            context("h2_lowercase_head", 443),
            DirectionalData {
                client_to_server: &lowercase_head,
                server_to_client: &lowercase_head_response,
            },
            TlsInterception::NotAttempted,
            None,
        )
        .expect("lowercase extension method is distinct from HEAD");
    assert_eq!(
        http_transaction(&lowercase_head_flow)
            .response
            .as_ref()
            .expect("response metadata")
            .byte_count,
        1
    );

    for (suffix, client_headers, status_header, length_headers) in [
        (
            "h2_head_signed_content_length",
            b"\x02\x04HEAD\x87\x84\x01\x0cfixture.test".as_slice(),
            0x88,
            b"\x00\x0econtent-length\x02+1".as_slice(),
        ),
        (
            "h2_304_signed_content_length",
            valid_headers.as_slice(),
            0x8b,
            b"\x00\x0econtent-length\x02+1".as_slice(),
        ),
        (
            "h2_head_duplicate_content_length",
            b"\x02\x04HEAD\x87\x84\x01\x0cfixture.test".as_slice(),
            0x88,
            b"\x00\x0econtent-length\x011\x00\x0econtent-length\x011".as_slice(),
        ),
    ] {
        let client = h2_request(1, 0x05, client_headers, None);
        let mut response_headers = vec![status_header];
        response_headers.extend_from_slice(length_headers);
        let mut server = h2_frame(4, 0, 0, &[]);
        server.extend(h2_frame(1, 0x05, 1, &response_headers));
        let result = CaptureCore::default().capture(
            context(suffix, 443),
            DirectionalData {
                client_to_server: &client,
                server_to_client: &server,
            },
            TlsInterception::NotAttempted,
            None,
        );
        assert!(matches!(result, Err(CaptureError::MalformedHttp2(_))));
    }
}

#[test]
fn directional_data_debug_reports_only_lengths() {
    let secret = b"Authorization: Bearer must-not-appear\r\n";
    let debug = format!(
        "{:?}",
        DirectionalData {
            client_to_server: secret,
            server_to_client: b"Cookie: also-secret\r\n",
        }
    );
    assert!(!debug.contains("Authorization"));
    assert!(!debug.contains("must-not-appear"));
    assert!(!debug.contains("also-secret"));
    assert!(debug.contains(&secret.len().to_string()));
}

#[test]
fn deterministic_arbitrary_inputs_never_panic() {
    for length in 0..=512usize {
        let mut state = u64::try_from(length).expect("fixture length fits") + 1;
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            bytes.push(state.to_be_bytes()[0]);
        }
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            CaptureCore::default().capture(
                context("arbitrary", 9000),
                DirectionalData {
                    client_to_server: &bytes,
                    server_to_client: bytes.get(..length / 2).unwrap_or_default(),
                },
                TlsInterception::NotAttempted,
                None,
            )
        }));
        assert!(
            result.is_ok(),
            "decoder panicked for deterministic length {length}"
        );
    }
}

fn context(suffix: &str, port: u16) -> CaptureContext {
    CaptureContext {
        flow_id: FlowId::new(format!("flow_{suffix}")).expect("fixture flow ID is valid"),
        connection_id: ConnectionId::new(format!("connection_{suffix}"))
            .expect("fixture connection ID is valid"),
        capture_session_id: None,
        process: None,
        timing: FlowTiming {
            started_at: TimestampNs(1_720_000_000_000_000_000),
            first_byte_at: Some(TimestampNs(1_720_000_000_000_001_000)),
            ended_at: Some(TimestampNs(1_720_000_000_000_010_000)),
            extensions: BTreeMap::new(),
        },
        transport: TransportMetadata {
            protocol: TransportProtocol::new(TransportProtocol::TCP).expect("TCP token is valid"),
            source_ip: Some("192.0.2.10".parse::<IpAddr>().expect("fixture IP is valid")),
            source_port: Some(52_000),
            extensions: BTreeMap::new(),
        },
        destination: DestinationMetadata {
            host: Some("fixture.test".to_owned()),
            ip: Some(
                "198.51.100.20"
                    .parse::<IpAddr>()
                    .expect("fixture IP is valid"),
            ),
            port,
            extensions: BTreeMap::new(),
        },
        close_reason: Some("fixture_complete".to_owned()),
    }
}

fn escaped_http(fixture: &str) -> Vec<u8> {
    fixture
        .strip_suffix('\n')
        .unwrap_or(fixture)
        .replace("\\r\\n", "\r\n")
        .into_bytes()
}

fn decode_hex(fixture: &str) -> Vec<u8> {
    let digits: String = fixture
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let (pairs, remainder) = digits.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "hex fixture must contain byte pairs");
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex pair is ASCII");
            u8::from_str_radix(text, 16).expect("fixture contains valid hex")
        })
        .collect()
}

fn h2_request(
    stream_id: u32,
    header_flags: u8,
    header_block: &[u8],
    trailing_data: Option<(u8, &[u8])>,
) -> Vec<u8> {
    let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    bytes.extend(h2_frame(4, 0, 0, &[]));
    bytes.extend(h2_frame(1, header_flags, stream_id, header_block));
    if let Some((flags, payload)) = trailing_data {
        bytes.extend(h2_frame(0, flags, stream_id, payload));
    }
    bytes
}

fn h2_request_without_settings(stream_id: u32, header_flags: u8, header_block: &[u8]) -> Vec<u8> {
    let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    bytes.extend(h2_frame(1, header_flags, stream_id, header_block));
    bytes
}

fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("test frame payload length fits u32");
    assert!(length <= 0x00ff_ffff, "test frame payload fits u24");
    let length_bytes = length.to_be_bytes();
    let stream_bytes = stream_id.to_be_bytes();
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(&length_bytes[1..]);
    frame.push(frame_type);
    frame.push(flags);
    frame.extend_from_slice(&stream_bytes);
    frame.extend_from_slice(payload);
    frame
}

fn http_transaction(flow: &NormalizedFlowV0) -> &flowprobe_model::HttpTransactionMetadata {
    flow.protocols
        .iter()
        .find_map(|event| match &event.metadata {
            ProtocolMetadata::Http(metadata) => Some(metadata.as_ref()),
            _ => None,
        })
        .expect("flow must contain HTTP metadata")
}

fn tls_metadata(flow: &NormalizedFlowV0) -> &flowprobe_model::TlsMetadata {
    flow.protocols
        .iter()
        .find_map(|event| match &event.metadata {
            ProtocolMetadata::Tls(metadata) => Some(metadata),
            _ => None,
        })
        .expect("flow must contain TLS metadata")
}

fn assert_valid_round_trip(flow: &NormalizedFlowV0) {
    flow.validate()
        .expect("capture output must satisfy the shared model");
    let encoded = flow
        .to_canonical_json()
        .expect("capture output must encode canonically");
    let decoded = NormalizedFlowV0::from_json(&encoded).expect("canonical output must decode");
    assert_eq!(&decoded, flow);
}
