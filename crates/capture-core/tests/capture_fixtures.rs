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
fn tls_client_hello_structure_constraints_are_enforced() {
    let cases = [
        ("session_id_too_long", tls_client_hello(&[0; 33], &[])),
        ("empty_alpn", tls_client_hello(&[], &[(16, b"\0\0")])),
        (
            "duplicate_extension",
            tls_client_hello(&[], &[(0xff00, b""), (0xff00, b"")]),
        ),
        (
            "duplicate_sni_extension_after_unknown_name",
            tls_client_hello(&[], &[(0, b"\0\x04\x01\0\x01x"), (0, b"\0\x04\0\0\x01a")]),
        ),
        (
            "duplicate_alpn_extension_after_empty_list",
            tls_client_hello(&[], &[(16, b"\0\0"), (16, b"\0\x03\x02h2")]),
        ),
        ("empty_sni", tls_client_hello(&[], &[(0, b"\0\0")])),
        (
            "empty_unknown_server_name",
            tls_client_hello(&[], &[(0, b"\0\x03\x01\0\0")]),
        ),
        (
            "duplicate_sni_name_type",
            tls_client_hello(&[], &[(0, b"\0\x08\0\0\x01a\0\0\x01b")]),
        ),
        (
            "sni_trailing_dot",
            tls_client_hello(&[], &[(0, b"\0\x05\0\0\x02a.")]),
        ),
        (
            "sni_non_ascii",
            tls_client_hello(&[], &[(0, b"\0\x04\0\0\x01\xff")]),
        ),
    ];

    for (suffix, hello) in cases {
        let result = CaptureCore::default().capture(
            context(&format!("tls_{suffix}"), 443),
            DirectionalData {
                client_to_server: &hello,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        );
        assert!(matches!(result, Err(CaptureError::MalformedTls(_))));
    }

    let opaque_alpn = tls_client_hello(&[], &[(16, b"\0\x02\x01\xff")]);
    let opaque_alpn_result = CaptureCore::default().capture(
        context("tls_opaque_alpn", 443),
        DirectionalData {
            client_to_server: &opaque_alpn,
            server_to_client: &[],
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        opaque_alpn_result,
        Err(CaptureError::UnsupportedTls(_))
    ));
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
fn http2_field_semantics_and_push_promise_are_enforced() {
    let valid_headers = [
        0x82, 0x87, 0x84, 0x01, 0x0c, b'f', b'i', b'x', b't', b'u', b'r', b'e', b'.', b't', b'e',
        b's', b't',
    ];

    for (suffix, value) in [
        ("nul", b"a\0b".as_slice()),
        ("crlf", b"a\r\nb".as_slice()),
        ("other_control", b"a\x01b".as_slice()),
        ("delete", b"a\x7fb".as_slice()),
        ("leading_space", b" value".as_slice()),
        ("trailing_tab", b"value\t".as_slice()),
    ] {
        let mut headers = valid_headers.to_vec();
        headers.extend(hpack_literal(b"x-test", value));
        let request = h2_request(1, 0x05, &headers, None);
        let result = CaptureCore::default().capture(
            context(&format!("h2_field_value_{suffix}"), 443),
            DirectionalData {
                client_to_server: &request,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        );
        assert!(matches!(result, Err(CaptureError::MalformedHttp2(_))));
    }

    for (suffix, name, value) in [
        (
            "connection",
            b"connection".as_slice(),
            b"keep-alive".as_slice(),
        ),
        (
            "proxy_connection",
            b"proxy-connection".as_slice(),
            b"keep-alive".as_slice(),
        ),
        (
            "keep_alive",
            b"keep-alive".as_slice(),
            b"timeout=5".as_slice(),
        ),
        (
            "transfer_encoding",
            b"transfer-encoding".as_slice(),
            b"chunked".as_slice(),
        ),
        ("upgrade", b"upgrade".as_slice(), b"websocket".as_slice()),
        ("te", b"te".as_slice(), b"gzip".as_slice()),
    ] {
        let mut headers = valid_headers.to_vec();
        headers.extend(hpack_literal(name, value));
        let request = h2_request(1, 0x05, &headers, None);
        let result = CaptureCore::default().capture(
            context(&format!("h2_forbidden_{suffix}"), 443),
            DirectionalData {
                client_to_server: &request,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        );
        assert!(matches!(result, Err(CaptureError::MalformedHttp2(_))));
    }

    let mut trailers_headers = valid_headers.to_vec();
    trailers_headers.extend(hpack_literal(b"te", b"Trailers"));
    let trailers_request = h2_request(1, 0x05, &trailers_headers, None);
    CaptureCore::default()
        .capture(
            context("h2_te_trailers", 443),
            DirectionalData {
                client_to_server: &trailers_request,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        )
        .expect("te: trailers is the sole HTTP/2 exception");

    for (suffix, method_headers) in [
        (
            "method_token",
            b"\x02\x05GET X\x87\x84\x01\x0cfixture.test".as_slice(),
        ),
        (
            "protocol_without_connect",
            b"\x82\x87\x84\x01\x0cfixture.test\x00\x09:protocol\x09websocket".as_slice(),
        ),
        (
            "missing_authority_with_host",
            b"\x82\x87\x84\x00\x04host\x0cfixture.test".as_slice(),
        ),
        (
            "scheme",
            b"\x82\x06\x05ht tp\x84\x01\x0cfixture.test".as_slice(),
        ),
        (
            "relative_path",
            b"\x82\x87\x04\x08relative\x01\x0cfixture.test".as_slice(),
        ),
        (
            "path_percent_encoding",
            b"\x82\x87\x04\x04/%ZZ\x01\x0cfixture.test".as_slice(),
        ),
        (
            "authority_whitespace",
            b"\x82\x87\x84\x01\x08bad host".as_slice(),
        ),
        (
            "authority_port",
            b"\x82\x87\x84\x01\x12fixture.test:70000".as_slice(),
        ),
        (
            "host_mismatch",
            b"\x82\x87\x84\x01\x0cfixture.test\x00\x04host\x0aother.test".as_slice(),
        ),
    ] {
        let request = h2_request(1, 0x05, method_headers, None);
        let result = CaptureCore::default().capture(
            context(&format!("h2_invalid_{suffix}"), 443),
            DirectionalData {
                client_to_server: &request,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        );
        assert!(matches!(result, Err(CaptureError::MalformedHttp2(_))));
    }

    let options_request = h2_request(1, 0x05, b"\x02\x07OPTIONS\x87\x04\x01*", None);
    let options_result = CaptureCore::default().capture(
        context("h2_options_asterisk", 443),
        DirectionalData {
            client_to_server: &options_request,
            server_to_client: &[],
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        options_result,
        Err(CaptureError::UnsupportedHttp2(_))
    ));

    let valid_client = h2_request(1, 0x05, &valid_headers, None);
    let mut invalid_status_server = h2_frame(4, 0, 0, &[]);
    invalid_status_server.extend(h2_frame(1, 0x05, 1, b"\x08\x04+200"));
    let invalid_status = CaptureCore::default().capture(
        context("h2_invalid_status", 443),
        DirectionalData {
            client_to_server: &valid_client,
            server_to_client: &invalid_status_server,
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        invalid_status,
        Err(CaptureError::MalformedHttp2(_))
    ));

    let mut te_response_server = h2_frame(4, 0, 0, &[]);
    let mut te_response_headers = vec![0x88];
    te_response_headers.extend(hpack_literal(b"te", b"trailers"));
    te_response_server.extend(h2_frame(1, 0x05, 1, &te_response_headers));
    let te_response = CaptureCore::default().capture(
        context("h2_response_te", 443),
        DirectionalData {
            client_to_server: &valid_client,
            server_to_client: &te_response_server,
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(te_response, Err(CaptureError::MalformedHttp2(_))));

    let mut push_payload = vec![0, 0, 0, 2];
    push_payload.extend_from_slice(&valid_headers);
    let mut push_server = h2_frame(4, 0, 0, &[]);
    push_server.extend(h2_frame(5, 0x04, 1, &push_payload));
    push_server.extend(h2_frame(1, 0x05, 1, &[0x88]));
    let push = CaptureCore::default().capture(
        context("h2_push_promise", 443),
        DirectionalData {
            client_to_server: &valid_client,
            server_to_client: &push_server,
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(push, Err(CaptureError::UnsupportedHttp2(_))));

    for (suffix, settings) in [
        ("enable_push", [0, 2, 0, 0, 0, 2]),
        ("initial_window", [0, 4, 0x80, 0, 0, 0]),
        ("max_frame", [0, 5, 0, 0, 0, 100]),
    ] {
        let request = h2_request_with_settings(&settings, 1, 0x05, &valid_headers, None);
        let result = CaptureCore::default().capture(
            context(&format!("h2_settings_{suffix}"), 443),
            DirectionalData {
                client_to_server: &request,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        );
        assert!(matches!(result, Err(CaptureError::MalformedHttp2(_))));
    }

    let client_push_enabled =
        h2_request_with_settings(&[0, 2, 0, 0, 0, 1], 1, 0x05, &valid_headers, None);
    CaptureCore::default()
        .capture(
            context("h2_client_push_enabled", 443),
            DirectionalData {
                client_to_server: &client_push_enabled,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        )
        .expect("a client may advertise SETTINGS_ENABLE_PUSH=1");

    let mut server_push_enabled = h2_frame(4, 0, 0, &[0, 2, 0, 0, 0, 1]);
    server_push_enabled.extend(h2_frame(1, 0x05, 1, &[0x88]));
    let server_push_enabled_result = CaptureCore::default().capture(
        context("h2_server_push_enabled", 443),
        DirectionalData {
            client_to_server: &valid_client,
            server_to_client: &server_push_enabled,
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        server_push_enabled_result,
        Err(CaptureError::MalformedHttp2(_))
    ));

    for (suffix, ping_payload, expected_ok) in [
        ("empty", b"".as_slice(), false),
        ("eight_bytes", b"12345678".as_slice(), true),
    ] {
        let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        request.extend(h2_frame(4, 0, 0, &[]));
        request.extend(h2_frame(6, 0, 0, ping_payload));
        request.extend(h2_frame(1, 0x05, 1, &valid_headers));
        let result = CaptureCore::default().capture(
            context(&format!("h2_ping_{suffix}"), 443),
            DirectionalData {
                client_to_server: &request,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        );
        if expected_ok {
            result.expect("eight-byte PING is valid and semantically ignorable");
        } else {
            assert!(matches!(result, Err(CaptureError::MalformedHttp2(_))));
        }
    }

    for (suffix, dependency, expected_ok) in [("self", 1u32, false), ("root", 0u32, true)] {
        let mut priority_headers = dependency.to_be_bytes().to_vec();
        priority_headers.push(0);
        priority_headers.extend_from_slice(&valid_headers);
        let request = h2_request(1, 0x25, &priority_headers, None);
        let result = CaptureCore::default().capture(
            context(&format!("h2_headers_priority_{suffix}"), 443),
            DirectionalData {
                client_to_server: &request,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        );
        if expected_ok {
            result.expect("HEADERS may depend on the root stream");
        } else {
            assert!(matches!(result, Err(CaptureError::MalformedHttp2(_))));
        }
    }

    let mut late_table_update_headers = valid_headers.to_vec();
    late_table_update_headers.push(0x20);
    let late_table_update = h2_request(1, 0x05, &late_table_update_headers, None);
    let late_table_update_result = CaptureCore::default().capture(
        context("h2_late_table_update", 443),
        DirectionalData {
            client_to_server: &late_table_update,
            server_to_client: &[],
        },
        TlsInterception::NotAttempted,
        None,
    );
    assert!(matches!(
        late_table_update_result,
        Err(CaptureError::MalformedHttp2(_))
    ));

    let mut leading_table_update_headers = vec![0x20];
    leading_table_update_headers.extend_from_slice(&valid_headers);
    let leading_table_update = h2_request(1, 0x05, &leading_table_update_headers, None);
    CaptureCore::default()
        .capture(
            context("h2_leading_table_update", 443),
            DirectionalData {
                client_to_server: &leading_table_update,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        )
        .expect("an HPACK table size update is valid at the start of a field block");

    let reserved_stream_bit = h2_request(0x8000_0001, 0x05, &valid_headers, None);
    CaptureCore::default()
        .capture(
            context("h2_reserved_stream_bit", 443),
            DirectionalData {
                client_to_server: &reserved_stream_bit,
                server_to_client: &[],
            },
            TlsInterception::NotAttempted,
            None,
        )
        .expect("receivers ignore the reserved stream identifier bit");
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

fn tls_client_hello(session_id: &[u8], extensions: &[(u16, &[u8])]) -> Vec<u8> {
    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[0; 32]);
    hello.push(u8::try_from(session_id.len()).expect("test session ID length fits u8"));
    hello.extend_from_slice(session_id);
    hello.extend_from_slice(&[0, 2, 0x13, 0x01]);
    hello.extend_from_slice(&[1, 0]);

    let extension_bytes = extensions.iter().fold(0usize, |total, (_, data)| {
        total
            .checked_add(4 + data.len())
            .expect("test extension length fits usize")
    });
    hello.extend_from_slice(
        &u16::try_from(extension_bytes)
            .expect("test extension block fits u16")
            .to_be_bytes(),
    );
    for (extension_type, data) in extensions {
        hello.extend_from_slice(&extension_type.to_be_bytes());
        hello.extend_from_slice(
            &u16::try_from(data.len())
                .expect("test extension data fits u16")
                .to_be_bytes(),
        );
        hello.extend_from_slice(data);
    }

    let mut handshake = vec![1];
    let hello_length = u32::try_from(hello.len()).expect("test ClientHello fits u24");
    assert!(hello_length <= 0x00ff_ffff, "test ClientHello fits u24");
    handshake.extend_from_slice(&hello_length.to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);

    let mut record = vec![22, 0x03, 0x01];
    record.extend_from_slice(
        &u16::try_from(handshake.len())
            .expect("test TLS record fits u16")
            .to_be_bytes(),
    );
    record.extend_from_slice(&handshake);
    record
}

fn h2_request(
    stream_id: u32,
    header_flags: u8,
    header_block: &[u8],
    trailing_data: Option<(u8, &[u8])>,
) -> Vec<u8> {
    h2_request_with_settings(&[], stream_id, header_flags, header_block, trailing_data)
}

fn h2_request_with_settings(
    settings: &[u8],
    stream_id: u32,
    header_flags: u8,
    header_block: &[u8],
    trailing_data: Option<(u8, &[u8])>,
) -> Vec<u8> {
    let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    bytes.extend(h2_frame(4, 0, 0, settings));
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

fn hpack_literal(name: &[u8], value: &[u8]) -> Vec<u8> {
    assert!(name.len() < 127, "test HPACK name uses one-byte length");
    assert!(value.len() < 127, "test HPACK value uses one-byte length");
    let mut field = Vec::with_capacity(3 + name.len() + value.len());
    field.push(0);
    field.push(u8::try_from(name.len()).expect("test name length fits u8"));
    field.extend_from_slice(name);
    field.push(u8::try_from(value.len()).expect("test value length fits u8"));
    field.extend_from_slice(value);
    field
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
