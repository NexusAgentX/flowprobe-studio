use flowprobe_model::{
    AttributionSource, BlobRef, BodyRef, ExtensionFields, FlowDecodeError, ModelValidationError,
    NormalizedFlowV0, ProtocolMetadata,
};
use serde_json::{Value, json};

const GOLDEN_FLOW: &str = include_str!("../../../tests/fixtures/normalized-flow-v0.json");
const HUGE_JSON_INTEGER: &str = "184467440737095516170";
const PRECISE_JSON_DECIMAL: &str = "1234567890.000000000000000000000000000000001";

fn fixture_value() -> Value {
    serde_json::from_str(GOLDEN_FLOW).expect("checked-in fixture must be JSON")
}

fn decode_value(value: &Value) -> Result<NormalizedFlowV0, FlowDecodeError> {
    NormalizedFlowV0::from_json(
        &serde_json::to_string(value).expect("JSON value must serialize for the contract test"),
    )
}

#[test]
fn checked_in_fixture_round_trip_is_byte_deterministic() {
    let flow = NormalizedFlowV0::from_json(GOLDEN_FLOW).expect("golden flow must decode");
    let first = flow
        .to_canonical_json()
        .expect("valid golden flow must encode");
    let second = NormalizedFlowV0::from_json(&first)
        .expect("canonical flow must decode")
        .to_canonical_json()
        .expect("canonical flow must re-encode");

    assert_eq!(first, GOLDEN_FLOW);
    assert_eq!(second, first);
}

#[test]
fn fixture_covers_identity_timing_transport_destination_and_process_provenance() {
    let flow = NormalizedFlowV0::from_json(GOLDEN_FLOW).expect("golden flow must decode");
    let process = flow
        .process
        .expect("fixture must include process attribution");

    assert_eq!(flow.flow_id.as_str(), "flow_fixture_0001");
    assert_eq!(flow.connection_id.as_str(), "connection_fixture_0001");
    assert_eq!(
        flow.capture_session_id
            .as_ref()
            .expect("fixture must have a session")
            .as_str(),
        "session_fixture_0001"
    );
    assert_eq!(
        process.source.as_str(),
        AttributionSource::SOCKET_CORRELATION
    );
    assert_eq!(process.confidence.get(), 95);
    assert!(flow.timing.started_at < flow.timing.first_byte_at.expect("first byte"));
    assert!(flow.timing.first_byte_at.expect("first byte") < flow.timing.ended_at.expect("end"));
    assert_eq!(flow.transport.protocol.as_str(), "tcp");
    assert_eq!(flow.destination.host.as_deref(), Some("fixture.example"));
    assert_eq!(flow.destination.port, 443);
}

#[test]
fn opaque_udp_connection_round_trip_is_deterministic() {
    let mut value = fixture_value();
    value["flow_id"] = json!("flow_udp_fixture_0001");
    value["connection_id"] = json!("connection_udp_fixture_0001");
    value["transport"]["protocol"] = json!("udp");
    value["destination"]["host"] = json!("dns.fixture.example");
    value["destination"]["port"] = json!(53);
    value["protocols"] = json!([{
        "kind": "connection",
        "metadata": {
            "client_to_server_bytes": 32,
            "server_to_client_bytes": 96,
            "datagram_count": 2
        }
    }]);

    let flow = decode_value(&value).expect("synthetic UDP flow must decode");
    assert_eq!(flow.transport.protocol.as_str(), "udp");
    match &flow.protocols[0].metadata {
        ProtocolMetadata::Connection(metadata) => {
            assert_eq!(metadata.client_to_server_bytes, 32);
            assert_eq!(metadata.server_to_client_bytes, 96);
            assert_eq!(metadata.extensions["datagram_count"], 2);
        }
        other => panic!("expected opaque UDP connection metadata, got {other}"),
    }

    let first = flow
        .to_canonical_json()
        .expect("synthetic UDP flow must encode");
    let second = NormalizedFlowV0::from_json(&first)
        .expect("canonical UDP flow must decode")
        .to_canonical_json()
        .expect("canonical UDP flow must re-encode");
    assert_eq!(second, first);
}

#[test]
fn process_is_optional_but_flow_and_connection_identity_are_required() {
    let mut without_process = fixture_value();
    without_process
        .as_object_mut()
        .expect("fixture must be an object")
        .remove("process");

    let flow = decode_value(&without_process).expect("process-less flow must decode");
    assert!(flow.process.is_none());
    let first = flow
        .to_canonical_json()
        .expect("process-less flow must encode");
    let second = NormalizedFlowV0::from_json(&first)
        .expect("canonical process-less flow must decode")
        .to_canonical_json()
        .expect("canonical process-less flow must re-encode");
    assert_eq!(second, first);
    assert!(!first.contains("\"process\""));

    for required_identity in ["flow_id", "connection_id"] {
        let mut missing_identity = fixture_value();
        missing_identity
            .as_object_mut()
            .expect("fixture must be an object")
            .remove(required_identity);
        assert!(
            matches!(
                decode_value(&missing_identity),
                Err(FlowDecodeError::Json(_))
            ),
            "missing {required_identity} must fail decoding"
        );
    }
}

#[test]
fn opaque_payload_references_reject_filesystem_and_uri_shapes() {
    for candidate in [
        "/tmp/request.bin",
        "body_/tmp/request.bin",
        "body_../request.bin",
        "file:///tmp/request.bin",
        "C:\\capture\\request.bin",
    ] {
        assert!(
            BodyRef::new(candidate).is_err(),
            "BodyRef unexpectedly accepted {candidate:?}"
        );
    }
    for candidate in [
        "/var/lib/flowprobe/blob",
        "blob_payloads/chunk.bin",
        "blob_..\\chunk.bin",
        "file://blob",
    ] {
        assert!(
            BlobRef::new(candidate).is_err(),
            "BlobRef unexpectedly accepted {candidate:?}"
        );
    }

    let flow = NormalizedFlowV0::from_json(GOLDEN_FLOW).expect("golden flow must decode");
    let encoded = flow.to_canonical_json().expect("golden flow must encode");
    assert!(!encoded.contains("/tmp/"));
    assert!(!encoded.contains("file://"));
    assert!(!encoded.contains("storage_path"));
    assert!(!encoded.contains("filesystem_path"));
}

#[test]
fn additive_fields_and_unknown_protocols_survive_round_trip() {
    let flow = NormalizedFlowV0::from_json(GOLDEN_FLOW).expect("golden flow must decode");

    assert_eq!(
        flow.extensions["trace_correlation"]["source"],
        "golden_fixture"
    );
    match &flow.protocols[1].metadata {
        ProtocolMetadata::Tls(metadata) => {
            assert_eq!(
                metadata.extensions["cipher_suite"],
                "TLS_AES_128_GCM_SHA256"
            );
        }
        other => panic!("expected TLS fixture event, got {other}"),
    }
    match &flow.protocols[4].metadata {
        ProtocolMetadata::Unknown { kind, metadata } => {
            assert_eq!(kind, "future_datagram_summary");
            assert_eq!(metadata["metrics"]["datagrams"], 3);
            assert_eq!(flow.protocols[4].extensions["producer_revision"], 2);
        }
        other => panic!("expected unknown fixture event, got {other}"),
    }

    let canonical = flow
        .to_canonical_json()
        .expect("forward-compatible flow must encode");
    let reparsed = NormalizedFlowV0::from_json(&canonical)
        .expect("forward-compatible canonical flow must decode");
    assert_eq!(reparsed, flow);
}

#[test]
fn new_additive_fields_are_preserved_in_known_and_unknown_metadata() {
    let mut value = fixture_value();
    value["new_top_level_hint"] = json!({"revision": 7});
    value["protocols"][2]["metadata"]["new_http_hint"] = json!(["a", "b"]);
    value["protocols"]
        .as_array_mut()
        .expect("protocols must be an array")
        .push(json!({
            "kind": "future_quic_transaction",
            "metadata": {
                "connection_epoch": 9,
                "nested": {"kept": true}
            },
            "future_envelope_flag": "retained"
        }));

    let decoded = decode_value(&value).expect("additive flow must decode");
    let canonical = decoded
        .to_canonical_json()
        .expect("additive flow must encode");
    let round_trip =
        NormalizedFlowV0::from_json(&canonical).expect("canonical additive flow must decode");

    assert_eq!(round_trip.extensions["new_top_level_hint"]["revision"], 7);
    match &round_trip.protocols[2].metadata {
        ProtocolMetadata::Http(metadata) => {
            assert_eq!(metadata.extensions["new_http_hint"], json!(["a", "b"]));
        }
        other => panic!("expected HTTP fixture event, got {other}"),
    }
    let future = round_trip.protocols.last().expect("future protocol event");
    match &future.metadata {
        ProtocolMetadata::Unknown { kind, metadata } => {
            assert_eq!(kind, "future_quic_transaction");
            assert_eq!(metadata["nested"]["kept"], true);
            assert_eq!(future.extensions["future_envelope_flag"], "retained");
        }
        other => panic!("expected future protocol event, got {other}"),
    }
}

#[test]
fn nested_unknown_protocol_is_byte_stable_and_preserves_protocol_order() {
    let mut value = fixture_value();
    value["protocols"]
        .as_array_mut()
        .expect("protocols must be an array")
        .insert(
            2,
            json!({
                "kind": "future_multiplexed_stream",
                "metadata": {
                    "frames": [
                        {
                            "name": "first",
                            "values": [1, {"nested": [true, false, {"depth": 3}]}]
                        },
                        {
                            "name": "second",
                            "values": [2, 3]
                        }
                    ],
                    "options": {
                        "compression": {"algorithm": "future-z", "enabled": true},
                        "revision": 4
                    }
                },
                "producer": {"name": "future-decoder", "version": 8}
            }),
        );

    let decoded = decode_value(&value).expect("nested future protocol must decode");
    let expected_order = [
        "connection",
        "tls",
        "future_multiplexed_stream",
        "http",
        "stream",
        "future_datagram_summary",
    ];
    let first_order: Vec<_> = decoded
        .protocols
        .iter()
        .map(|event| event.metadata.to_string())
        .collect();
    assert_eq!(first_order, expected_order);

    match &decoded.protocols[2].metadata {
        ProtocolMetadata::Unknown { metadata, .. } => {
            assert_eq!(metadata["frames"][0]["name"], "first");
            assert_eq!(metadata["frames"][0]["values"][1]["nested"][2]["depth"], 3);
            assert_eq!(metadata["frames"][1]["name"], "second");
        }
        other => panic!("expected nested unknown protocol, got {other}"),
    }

    let first = decoded
        .to_canonical_json()
        .expect("nested future protocol must encode");
    let reparsed =
        NormalizedFlowV0::from_json(&first).expect("canonical nested future protocol must decode");
    let second_order: Vec<_> = reparsed
        .protocols
        .iter()
        .map(|event| event.metadata.to_string())
        .collect();
    let second = reparsed
        .to_canonical_json()
        .expect("canonical nested future protocol must re-encode");

    assert_eq!(second_order, expected_order);
    assert_eq!(second, first);
}

#[test]
fn arbitrary_precision_numbers_survive_known_and_unknown_metadata() {
    let huge_integer: Value =
        serde_json::from_str(HUGE_JSON_INTEGER).expect("arbitrary-precision integer must parse");
    let precise_decimal: Value =
        serde_json::from_str(PRECISE_JSON_DECIMAL).expect("arbitrary-precision decimal must parse");
    let mut value = fixture_value();

    value["protocols"][1]["metadata"]["future_handshake_counter"] = huge_integer.clone();
    value["protocols"][1]["metadata"]["future_precision_ratio"] = precise_decimal.clone();
    value["protocols"][4]["metadata"]["future_datagram_counter"] = huge_integer.clone();
    value["protocols"][4]["metadata"]["future_precision_ratio"] = precise_decimal.clone();

    let decoded = decode_value(&value).expect("arbitrary-precision metadata must decode");
    match &decoded.protocols[1].metadata {
        ProtocolMetadata::Tls(metadata) => {
            assert_eq!(
                metadata.extensions["future_handshake_counter"],
                huge_integer
            );
            assert_eq!(
                metadata.extensions["future_precision_ratio"],
                precise_decimal
            );
            assert_eq!(
                metadata.extensions["future_handshake_counter"].to_string(),
                HUGE_JSON_INTEGER
            );
            assert_eq!(
                metadata.extensions["future_precision_ratio"].to_string(),
                PRECISE_JSON_DECIMAL
            );
        }
        other => panic!("expected TLS metadata with future numbers, got {other}"),
    }
    match &decoded.protocols[4].metadata {
        ProtocolMetadata::Unknown { metadata, .. } => {
            assert_eq!(metadata["future_datagram_counter"], huge_integer);
            assert_eq!(metadata["future_precision_ratio"], precise_decimal);
            assert_eq!(
                metadata["future_datagram_counter"].to_string(),
                HUGE_JSON_INTEGER
            );
            assert_eq!(
                metadata["future_precision_ratio"].to_string(),
                PRECISE_JSON_DECIMAL
            );
        }
        other => panic!("expected unknown metadata with future numbers, got {other}"),
    }

    let first = decoded
        .to_canonical_json()
        .expect("arbitrary-precision metadata must encode");
    assert!(first.contains(HUGE_JSON_INTEGER));
    assert!(first.contains(PRECISE_JSON_DECIMAL));
    let reparsed = NormalizedFlowV0::from_json(&first)
        .expect("canonical arbitrary-precision metadata must decode");
    let second = reparsed
        .to_canonical_json()
        .expect("canonical arbitrary-precision metadata must re-encode");

    assert_eq!(second, first);
    match &reparsed.protocols[4].metadata {
        ProtocolMetadata::Unknown { metadata, .. } => {
            assert_eq!(
                metadata["future_datagram_counter"].to_string(),
                HUGE_JSON_INTEGER
            );
            assert_eq!(
                metadata["future_precision_ratio"].to_string(),
                PRECISE_JSON_DECIMAL
            );
        }
        other => panic!("expected reparsed unknown metadata, got {other}"),
    }
}

fn assert_precision_extensions(extensions: &ExtensionFields, scope: &str) {
    assert_eq!(
        extensions["future_integer"].to_string(),
        HUGE_JSON_INTEGER,
        "integer precision changed in {scope}"
    );
    assert_eq!(
        extensions["future_decimal"].to_string(),
        PRECISE_JSON_DECIMAL,
        "decimal precision changed in {scope}"
    );
}

#[test]
fn raw_json_preserves_precision_at_every_additive_scope() {
    let raw = r#"
{
  "contract_version": "0",
  "flow_id": "flow_precision_scopes",
  "connection_id": "connection_precision_scopes",
  "process": {
    "process_id": 7,
    "source": "operating_system",
    "confidence": 100,
    "future_integer": __BIG__,
    "future_decimal": __DECIMAL__
  },
  "timing": {
    "started_at": 1000,
    "first_byte_at": 1100,
    "ended_at": 2000,
    "future_integer": __BIG__,
    "future_decimal": __DECIMAL__
  },
  "transport": {
    "protocol": "tcp",
    "source_ip": "192.0.2.40",
    "source_port": 53040,
    "future_integer": __BIG__,
    "future_decimal": __DECIMAL__
  },
  "destination": {
    "host": "precision.fixture.example",
    "ip": "198.51.100.40",
    "port": 443,
    "future_integer": __BIG__,
    "future_decimal": __DECIMAL__
  },
  "protocols": [
    {
      "kind": "connection",
      "metadata": {
        "client_to_server_bytes": 20,
        "server_to_client_bytes": 40,
        "future_integer": __BIG__,
        "future_decimal": __DECIMAL__
      }
    },
    {
      "kind": "tls",
      "metadata": {
        "sni": "precision.fixture.example",
        "alpn": "h2",
        "negotiated_version": "TLSv1.3",
        "interception_state": "intercepted",
        "future_integer": __BIG__,
        "future_decimal": __DECIMAL__
      }
    },
    {
      "kind": "http",
      "metadata": {
        "stream_id": 1,
        "request": {
          "method": "GET",
          "scheme": "https",
          "authority": "precision.fixture.example",
          "path": "/precision",
          "version": "HTTP/2",
          "byte_count": 0,
          "future_integer": __BIG__,
          "future_decimal": __DECIMAL__
        },
        "response": {
          "status": 200,
          "version": "HTTP/2",
          "byte_count": 8,
          "future_integer": __BIG__,
          "future_decimal": __DECIMAL__
        },
        "future_integer": __BIG__,
        "future_decimal": __DECIMAL__
      },
      "future_integer": __BIG__,
      "future_decimal": __DECIMAL__
    },
    {
      "kind": "stream",
      "metadata": {
        "stream_kind": "sse",
        "direction": "server_to_client",
        "sequence": 0,
        "relative_at": 500,
        "byte_count": 8,
        "future_integer": __BIG__,
        "future_decimal": __DECIMAL__
      }
    },
    {
      "kind": "future_precision_protocol",
      "metadata": {
        "future_integer": __BIG__,
        "future_decimal": __DECIMAL__,
        "nested": [__BIG__, {"decimal": __DECIMAL__}]
      }
    }
  ],
  "future_integer": __BIG__,
  "future_decimal": __DECIMAL__
}
"#
    .replace("__BIG__", HUGE_JSON_INTEGER)
    .replace("__DECIMAL__", PRECISE_JSON_DECIMAL);

    let flow = NormalizedFlowV0::from_json(&raw)
        .expect("raw JSON with arbitrary-precision extensions must decode");
    assert_precision_extensions(&flow.extensions, "normalized flow");
    assert_precision_extensions(
        &flow.process.as_ref().expect("process metadata").extensions,
        "process",
    );
    assert_precision_extensions(&flow.timing.extensions, "timing");
    assert_precision_extensions(&flow.transport.extensions, "transport");
    assert_precision_extensions(&flow.destination.extensions, "destination");

    match &flow.protocols[0].metadata {
        ProtocolMetadata::Connection(metadata) => {
            assert_precision_extensions(&metadata.extensions, "connection metadata");
        }
        other => panic!("expected connection metadata, got {other}"),
    }
    match &flow.protocols[1].metadata {
        ProtocolMetadata::Tls(metadata) => {
            assert_precision_extensions(&metadata.extensions, "TLS metadata");
        }
        other => panic!("expected TLS metadata, got {other}"),
    }
    assert_precision_extensions(&flow.protocols[2].extensions, "protocol event envelope");
    match &flow.protocols[2].metadata {
        ProtocolMetadata::Http(metadata) => {
            assert_precision_extensions(&metadata.extensions, "HTTP transaction metadata");
            assert_precision_extensions(&metadata.request.extensions, "HTTP request metadata");
            assert_precision_extensions(
                &metadata
                    .response
                    .as_ref()
                    .expect("HTTP response")
                    .extensions,
                "HTTP response metadata",
            );
        }
        other => panic!("expected HTTP metadata, got {other}"),
    }
    match &flow.protocols[3].metadata {
        ProtocolMetadata::Stream(metadata) => {
            assert_precision_extensions(&metadata.extensions, "stream metadata");
        }
        other => panic!("expected stream metadata, got {other}"),
    }
    match &flow.protocols[4].metadata {
        ProtocolMetadata::Unknown { metadata, .. } => {
            assert_eq!(metadata["future_integer"].to_string(), HUGE_JSON_INTEGER);
            assert_eq!(metadata["future_decimal"].to_string(), PRECISE_JSON_DECIMAL);
            assert_eq!(metadata["nested"][0].to_string(), HUGE_JSON_INTEGER);
            assert_eq!(
                metadata["nested"][1]["decimal"].to_string(),
                PRECISE_JSON_DECIMAL
            );
        }
        other => panic!("expected unknown metadata, got {other}"),
    }

    let first = flow
        .to_canonical_json()
        .expect("precision-scoped flow must encode");
    let reparsed =
        NormalizedFlowV0::from_json(&first).expect("canonical precision-scoped flow must decode");
    let second = reparsed
        .to_canonical_json()
        .expect("canonical precision-scoped flow must re-encode");

    assert_eq!(reparsed, flow);
    assert_eq!(second, first);
}

#[test]
fn malformed_json_and_semantically_invalid_flows_return_errors() {
    assert!(matches!(
        NormalizedFlowV0::from_json("{not-json"),
        Err(FlowDecodeError::Json(_))
    ));

    let mut unsupported_version = fixture_value();
    unsupported_version["contract_version"] = json!("1");
    assert!(matches!(
        decode_value(&unsupported_version),
        Err(FlowDecodeError::Validation(
            ModelValidationError::UnsupportedContractVersion(_)
        ))
    ));

    let mut reversed_timing = fixture_value();
    reversed_timing["timing"]["ended_at"] = json!(1);
    assert!(matches!(
        decode_value(&reversed_timing),
        Err(FlowDecodeError::Validation(
            ModelValidationError::InvalidTiming(_)
        ))
    ));

    let mut invalid_reference = fixture_value();
    invalid_reference["protocols"][2]["metadata"]["request"]["body_ref"] =
        json!("/tmp/request.bin");
    assert!(matches!(
        decode_value(&invalid_reference),
        Err(FlowDecodeError::Json(_))
    ));

    let mut missing_known_field = fixture_value();
    missing_known_field["protocols"][2]["metadata"]
        .as_object_mut()
        .expect("HTTP metadata must be an object")
        .remove("request");
    assert!(matches!(
        decode_value(&missing_known_field),
        Err(FlowDecodeError::Json(_))
    ));

    let mut scalar_unknown_metadata = fixture_value();
    scalar_unknown_metadata["protocols"][4]["metadata"] = json!("not-an-object");
    assert!(matches!(
        decode_value(&scalar_unknown_metadata),
        Err(FlowDecodeError::Validation(
            ModelValidationError::UnknownProtocolMetadataNotObject(_)
        ))
    ));

    let mut malformed_unknown_kind = fixture_value();
    malformed_unknown_kind["protocols"][4]["kind"] = json!("future kind/with spaces");
    assert!(matches!(
        decode_value(&malformed_unknown_kind),
        Err(FlowDecodeError::Validation(
            ModelValidationError::InvalidToken { .. }
        ))
    ));
}
