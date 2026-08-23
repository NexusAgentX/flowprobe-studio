use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::{Arc, Mutex},
};

use flowprobe_analyzer_runtime::{
    AnalyzerError, AnalyzerHost, AnalyzerLimits, AnalyzerLogEntry, AnalyzerPermissions,
    AnalyzerRuntime, EventRef, HostErrorCode, SemanticEvent,
};
use flowprobe_capture_core::{CaptureContext, CaptureCore, DirectionalData, TlsInterception};
use flowprobe_config_compiler::{ConfigCompiler, RuntimeOverlay, SystemBase, UserProfile};
use flowprobe_ipc::{SemanticPageRequest, TrafficDetailRequest, TrafficPageRequest};
use flowprobe_model::{
    BlobRef, CaptureSessionId, ConnectionId, DestinationMetadata, FlowId, FlowTiming, TimestampNs,
    TransportMetadata, TransportProtocol,
};
use flowprobe_runtime_api::{FakeNetworkRuntime, RuntimeHealth, RuntimeOperation, RuntimePhase};
use flowprobe_storage::{
    DeterministicMemoryBlobStore, OpaquePayloadStore, PageSize, SemanticEventId,
    SemanticEventInput, SemanticQuery, SemanticSource, SqliteMetadataStore,
};
use flowprobe_supervisor::{Supervisor, TrafficService};
use serde_json::{Value, json};

const DEMO_COMPONENT: &[u8] =
    include_bytes!("../../../plugins/demo/artifacts/flowprobe_demo_analyzer.wasm");
const ADVERSARIAL_COMPONENT: &[u8] =
    include_bytes!("../../contract/analyzer/artifacts/adversarial_analyzer.wasm");
const TLS_CLIENT_HELLO: &str = include_str!("../../fixtures/tls/client-hello.hex");

const FLOW_ID: &str = "flow_v0_1_vertical";
const CONNECTION_ID: &str = "connection_v0_1_vertical";
const CAPTURE_SESSION_ID: &str = "capture_v0_1_vertical";
const SEMANTIC_EVENT_ID: &str = "semantic_flow_v0_1_vertical_0000";
const STARTED_AT_NS: u64 = 1_720_000_000_000_000_000;

// These are deliberately synthetic canaries, never real credentials.
const AUTHORIZATION_SENTINEL: &str = "INT001_FAKE_AUTHORIZATION_SENTINEL";
const COOKIE_SENTINEL: &str = "INT001_FAKE_COOKIE_SENTINEL";
const BODY_SENTINEL: &str = "INT001_FAKE_BODY_SENTINEL";

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedSemantic {
    namespace: String,
    kind: String,
    timestamp_ns: u64,
    attributes: Value,
}

#[derive(Debug, Default)]
struct HostRecording {
    event_json: String,
    staged: Vec<StagedSemantic>,
    logs: Vec<AnalyzerLogEntry>,
    reject_after: Option<usize>,
}

#[derive(Clone)]
struct StagingHost(Arc<Mutex<HostRecording>>);

impl StagingHost {
    fn new(event_json: impl Into<String>) -> Self {
        Self(Arc::new(Mutex::new(HostRecording {
            event_json: event_json.into(),
            ..HostRecording::default()
        })))
    }

    fn rejecting_after(event_json: impl Into<String>, accepted: usize) -> Self {
        Self(Arc::new(Mutex::new(HostRecording {
            event_json: event_json.into(),
            reject_after: Some(accepted),
            ..HostRecording::default()
        })))
    }

    fn staged(&self) -> Vec<StagedSemantic> {
        self.0
            .lock()
            .expect("staging host mutex must not be poisoned")
            .staged
            .clone()
    }

    fn log_text(&self) -> String {
        let recording = self
            .0
            .lock()
            .expect("staging host mutex must not be poisoned");
        recording
            .logs
            .iter()
            .map(|entry| format!("{}:{}", entry.level, entry.message))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl AnalyzerHost for StagingHost {
    fn get_event_json(&mut self, _event: &EventRef) -> Result<String, HostErrorCode> {
        Ok(self
            .0
            .lock()
            .expect("staging host mutex must not be poisoned")
            .event_json
            .clone())
    }

    fn emit_semantic(&mut self, event: &SemanticEvent) -> Result<(), HostErrorCode> {
        let mut recording = self
            .0
            .lock()
            .expect("staging host mutex must not be poisoned");
        if recording
            .reject_after
            .is_some_and(|accepted| recording.staged.len() >= accepted)
        {
            return Err(HostErrorCode::Rejected);
        }
        let attributes =
            serde_json::from_str(&event.json_attributes).map_err(|_| HostErrorCode::Rejected)?;
        recording.staged.push(StagedSemantic {
            namespace: event.namespace.clone(),
            kind: event.kind.clone(),
            timestamp_ns: event.timestamp_ns,
            attributes,
        });
        Ok(())
    }

    fn log(&mut self, entry: AnalyzerLogEntry) -> Result<(), HostErrorCode> {
        self.0
            .lock()
            .expect("staging host mutex must not be poisoned")
            .logs
            .push(entry);
        Ok(())
    }
}

struct StoredSources {
    store: SqliteMetadataStore,
    blobs: DeterministicMemoryBlobStore,
    flow_id: FlowId,
    raw_ref: BlobRef,
    normalized_ref: BlobRef,
    canonical: String,
    raw: Vec<u8>,
}

#[test]
fn vertical_architecture_path_is_deterministic_and_redacted() {
    let first = run_success_scenario();
    let second = run_success_scenario();

    assert_eq!(first, second, "two clean runs must produce one snapshot");
}

#[test]
fn guest_trap_discards_derived_output_and_preserves_sources() {
    let sources = stored_sources();
    let runtime = AnalyzerRuntime::new(AnalyzerLimits::default())
        .expect("default analyzer limits must be valid");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("checked-in adversarial component must compile");
    let host = StagingHost::new(sources.canonical.clone());

    let error = runtime
        .analyze(&analyzer, adversarial_event("fixture.trap"), host.clone())
        .expect_err("the adversarial guest must trap");

    assert_eq!(error, AnalyzerError::GuestTrap);
    assert!(host.staged().is_empty());
    assert_sources_and_no_semantics(&sources);
}

#[test]
fn semantic_limit_discards_a_partially_staged_run_and_preserves_sources() {
    let sources = stored_sources();
    let runtime = AnalyzerRuntime::new(AnalyzerLimits {
        max_semantic_events: 1,
        ..AnalyzerLimits::default()
    })
    .expect("bounded analyzer limits must be valid");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("checked-in adversarial component must compile");
    let host = StagingHost::new(sources.canonical.clone());

    let error = runtime
        .analyze(
            &analyzer,
            adversarial_event("fixture.outputs"),
            host.clone(),
        )
        .expect_err("the second semantic event must cross the output limit");

    assert_eq!(error, AnalyzerError::SemanticOutputLimitExceeded);
    assert_eq!(host.staged().len(), 1, "the first event is only staged");
    assert_sources_and_no_semantics(&sources);
}

#[test]
fn host_rejection_discards_a_partially_staged_run_and_preserves_sources() {
    let sources = stored_sources();
    let runtime = AnalyzerRuntime::new(AnalyzerLimits::default())
        .expect("default analyzer limits must be valid");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("checked-in adversarial component must compile");
    let host = StagingHost::rejecting_after(sources.canonical.clone(), 1);

    let error = runtime
        .analyze(
            &analyzer,
            adversarial_event("fixture.outputs"),
            host.clone(),
        )
        .expect_err("the host must reject the second semantic event");

    assert_eq!(error, AnalyzerError::GuestRejected);
    assert_eq!(host.staged().len(), 1, "the first event is only staged");
    assert_sources_and_no_semantics(&sources);
}

fn run_success_scenario() -> Value {
    let fake_runtime = Arc::new(FakeNetworkRuntime::default());
    let compiled = ConfigCompiler::new(fake_runtime.as_ref().clone())
        .compile(
            &SystemBase::parse(
                r#"{
                  "inbounds": [{
                    "type": "http",
                    "tag": "__flowprobe_capture",
                    "listen": "127.0.0.1",
                    "listen_port": 0,
                    "set_system_proxy": false
                  }],
                  "outbounds": [{"type": "direct", "tag": "__flowprobe_direct"}],
                  "route": {"final": "__flowprobe_direct"}
                }"#,
            )
            .expect("system configuration must parse"),
            &UserProfile::parse(r#"{"log":{"level":"warn"}}"#).expect("user profile must parse"),
            &RuntimeOverlay::parse(
                r#"{"inbounds":[{"tag":"__flowprobe_capture","listen_port":18181}]}"#,
            )
            .expect("runtime overlay must parse"),
        )
        .expect("fake runtime must validate the compiled configuration");

    let supervisor = Supervisor::with_network_runtime(fake_runtime.clone());
    supervisor
        .validate_network_config(&compiled)
        .expect("supervisor must forward explicit validation");
    assert_eq!(
        supervisor
            .start_network_runtime(&compiled)
            .expect("fake runtime must start")
            .phase(),
        RuntimePhase::Running
    );
    assert_eq!(
        supervisor
            .network_health()
            .expect("fake runtime health must be queryable"),
        RuntimeHealth::Healthy
    );
    assert_eq!(
        supervisor
            .network_status()
            .expect("fake runtime status must be queryable")
            .state
            .phase(),
        RuntimePhase::Running
    );

    // NetworkRuntime deliberately has no capture-stream API. Once readiness is
    // proven, deterministic synthetic transport/application bytes enter the
    // generic Capture Core boundary explicitly.
    let mut sources = stored_sources();
    assert_no_secret(&sources.canonical);
    assert!(contains_bytes(&sources.raw, AUTHORIZATION_SENTINEL));
    assert!(contains_bytes(&sources.raw, COOKIE_SENTINEL));
    assert!(contains_bytes(&sources.raw, BODY_SENTINEL));
    assert_opaque_ref(&sources.raw_ref);
    assert_opaque_ref(&sources.normalized_ref);

    let analyzer_runtime = AnalyzerRuntime::new(AnalyzerLimits::default())
        .expect("default analyzer limits must be valid");
    let analyzer = analyzer_runtime
        .compile(DEMO_COMPONENT, AnalyzerPermissions::new(true, true, false))
        .expect("checked-in demo component must compile");
    let host = StagingHost::new(sources.canonical.clone());
    let outcome = analyzer_runtime
        .analyze(
            &analyzer,
            EventRef {
                id: sources.flow_id.as_str().to_owned(),
                kind: "normalized-flow-v0".to_owned(),
            },
            host.clone(),
        )
        .expect("demo analyzer must complete before any semantic commit");
    let staged = host.staged();
    let expected_attributes = json!({
        "event_id": FLOW_ID,
        "event_kind": "normalized-flow-v0",
        "source": "deterministic-fixture",
    });
    assert_eq!(outcome.analyzer.id, "flowprobe.demo");
    assert_eq!(outcome.analyzer.version, "0.1.0");
    assert_eq!(outcome.semantic_events, 1);
    assert_eq!(
        staged,
        vec![StagedSemantic {
            namespace: "flowprobe.demo".to_owned(),
            kind: "fixture-observed".to_owned(),
            timestamp_ns: STARTED_AT_NS,
            attributes: expected_attributes.clone(),
        }],
        "the demo artifact must satisfy the v0.1 semantic oracle before commit"
    );
    assert!(host.log_text().is_empty());

    let semantic = &staged[0];
    sources
        .store
        .upsert_semantic_event(&SemanticEventInput {
            event_id: SemanticEventId::new(SEMANTIC_EVENT_ID)
                .expect("deterministic semantic event identity must be valid"),
            source: SemanticSource::Flow(sources.flow_id.clone()),
            analyzer_id: outcome.analyzer.id.clone(),
            analyzer_version: outcome.analyzer.version.clone(),
            namespace: semantic.namespace.clone(),
            kind: semantic.kind.clone(),
            timestamp: TimestampNs(semantic.timestamp_ns),
            attributes: semantic.attributes.clone(),
        })
        .expect("successful staged output must commit");

    let direct_semantics = sources
        .store
        .query_semantic_events(&SemanticQuery::new(
            PageSize::new(10).expect("page size must be valid"),
        ))
        .expect("direct semantic storage query must succeed");
    assert_eq!(direct_semantics.items.len(), 1);
    let stored_semantic = &direct_semantics.items[0];
    assert_eq!(stored_semantic.event_id.as_str(), SEMANTIC_EVENT_ID);
    assert_eq!(
        stored_semantic
            .capture_session_id
            .as_ref()
            .map(CaptureSessionId::as_str),
        Some(CAPTURE_SESSION_ID)
    );
    assert_eq!(
        stored_semantic.source_flow_id.as_ref().map(FlowId::as_str),
        Some(FLOW_ID)
    );
    assert_eq!(stored_semantic.analyzer_id, "flowprobe.demo");
    assert_eq!(stored_semantic.analyzer_version, "0.1.0");
    assert_eq!(stored_semantic.namespace, "flowprobe.demo");
    assert_eq!(stored_semantic.kind, "fixture-observed");
    assert_eq!(stored_semantic.timestamp, TimestampNs(STARTED_AT_NS));
    assert_eq!(stored_semantic.attributes, expected_attributes);

    let traffic = TrafficService::new(sources.store);
    let page = traffic
        .query_traffic(TrafficPageRequest {
            page_size: 10,
            cursor: None,
        })
        .expect("Traffic list query must succeed");
    let detail = traffic
        .get_traffic_detail(TrafficDetailRequest {
            flow_id: sources.flow_id.as_str().to_owned(),
        })
        .expect("Traffic detail query must succeed");
    let semantic_page = traffic
        .query_semantic_output(SemanticPageRequest {
            page_size: 10,
            cursor: None,
        })
        .expect("Traffic semantic query must succeed");
    assert_eq!(semantic_page.items.len(), 1);
    let semantic_dto = &semantic_page.items[0];
    assert_eq!(semantic_dto.event_id, SEMANTIC_EVENT_ID);
    assert_eq!(
        semantic_dto.capture_session_id.as_deref(),
        Some(CAPTURE_SESSION_ID)
    );
    assert_eq!(semantic_dto.source_flow_id.as_deref(), Some(FLOW_ID));
    assert_eq!(semantic_dto.analyzer_id, "flowprobe.demo");
    assert_eq!(semantic_dto.analyzer_version, "0.1.0");
    assert_eq!(semantic_dto.namespace, "flowprobe.demo");
    assert_eq!(semantic_dto.kind, "fixture-observed");
    assert_eq!(semantic_dto.timestamp_ns, STARTED_AT_NS.to_string());

    let page_json = serde_json::to_value(&page).expect("Traffic page must serialize");
    let detail_json = serde_json::to_value(&detail).expect("Traffic detail must serialize");
    let semantic_json = serde_json::to_value(&semantic_page).expect("semantic page must serialize");
    assert_ui_shapes(&page_json, &detail_json, &semantic_json);
    for ordinary_output in [&page_json, &detail_json, &semantic_json] {
        let encoded = ordinary_output.to_string();
        assert_no_secret(&encoded);
        assert!(!encoded.contains(sources.raw_ref.as_str()));
        assert!(!encoded.contains(sources.normalized_ref.as_str()));
        assert!(!encoded.contains("attributes"));
    }

    assert_eq!(
        supervisor
            .stop_network_runtime()
            .expect("fake runtime must stop")
            .phase(),
        RuntimePhase::Stopped
    );
    let operations = fake_runtime
        .operation_records()
        .expect("fake runtime operation records must be queryable")
        .into_iter()
        .map(|record| format!("{:?}", record.operation))
        .collect::<Vec<_>>();
    assert_eq!(
        operations,
        [
            RuntimeOperation::ValidateConfig,
            RuntimeOperation::ValidateConfig,
            RuntimeOperation::Start,
            RuntimeOperation::Health,
            RuntimeOperation::Status,
            RuntimeOperation::Stop,
        ]
        .map(|operation| format!("{operation:?}"))
    );

    let diagnostic_text = format!(
        "compiled={compiled:?}; flow={:?}; semantics={direct_semantics:?}; logs={}",
        detail,
        host.log_text()
    );
    assert_no_secret(&diagnostic_text);
    assert!(!diagnostic_text.contains(sources.raw_ref.as_str()));
    assert!(!diagnostic_text.contains(sources.normalized_ref.as_str()));

    json!({
        "compiledRuntime": compiled.runtime_json(),
        "normalized": sources.canonical,
        "rawRef": sources.raw_ref.as_str(),
        "normalizedRef": sources.normalized_ref.as_str(),
        "analyzer": {
            "id": outcome.analyzer.id,
            "version": outcome.analyzer.version,
            "semanticEvents": outcome.semantic_events,
            "staged": staged.iter().map(|semantic| json!({
                "namespace": semantic.namespace,
                "kind": semantic.kind,
                "timestampNs": semantic.timestamp_ns,
                "attributes": semantic.attributes,
            })).collect::<Vec<_>>(),
        },
        "storageSemantic": {
            "eventId": direct_semantics.items[0].event_id.as_str(),
            "attributes": direct_semantics.items[0].attributes,
        },
        "ui": {
            "list": page_json,
            "detail": detail_json,
            "semantic": semantic_json,
        },
        "runtimeOperations": operations,
    })
}

fn stored_sources() -> StoredSources {
    let client_hello = decode_hex(TLS_CLIENT_HELLO);
    let request_body = BODY_SENTINEL.as_bytes();
    let request = format!(
        concat!(
            "POST /integration-proof HTTP/1.1\r\n",
            "Host: fixture.test\r\n",
            "Authorization: Bearer {}\r\n",
            "Cookie: proof={}\r\n",
            "Content-Type: text/plain\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}"
        ),
        AUTHORIZATION_SENTINEL,
        COOKIE_SENTINEL,
        request_body.len(),
        BODY_SENTINEL,
    )
    .into_bytes();
    let response_body = b"vertical-proof-ok";
    let mut response = format!(
        concat!(
            "HTTP/1.1 201 Created\r\n",
            "Content-Type: text/plain\r\n",
            "Content-Length: {}\r\n",
            "\r\n"
        ),
        response_body.len()
    )
    .into_bytes();
    response.extend_from_slice(response_body);

    let session_id =
        CaptureSessionId::new(CAPTURE_SESSION_ID).expect("capture session identity must be valid");
    let flow_id = FlowId::new(FLOW_ID).expect("flow identity must be valid");
    let normalized = CaptureCore::default()
        .capture(
            CaptureContext {
                flow_id: flow_id.clone(),
                connection_id: ConnectionId::new(CONNECTION_ID)
                    .expect("connection identity must be valid"),
                capture_session_id: Some(session_id.clone()),
                process: None,
                timing: FlowTiming {
                    started_at: TimestampNs(STARTED_AT_NS),
                    first_byte_at: Some(TimestampNs(STARTED_AT_NS + 1_000)),
                    ended_at: Some(TimestampNs(STARTED_AT_NS + 10_000)),
                    extensions: BTreeMap::new(),
                },
                transport: TransportMetadata {
                    protocol: TransportProtocol::new(TransportProtocol::TCP)
                        .expect("TCP token must be valid"),
                    source_ip: Some(
                        "192.0.2.10"
                            .parse::<IpAddr>()
                            .expect("fixture source address must parse"),
                    ),
                    source_port: Some(52_000),
                    extensions: BTreeMap::new(),
                },
                destination: DestinationMetadata {
                    host: Some("fixture.test".to_owned()),
                    ip: Some(
                        "198.51.100.20"
                            .parse::<IpAddr>()
                            .expect("fixture destination address must parse"),
                    ),
                    port: 443,
                    extensions: BTreeMap::new(),
                },
                close_reason: Some("fixture_complete".to_owned()),
            },
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
        .expect("generic synthetic TLS/HTTP input must normalize");
    let canonical = normalized
        .to_canonical_json()
        .expect("normalized flow must have canonical JSON");
    assert_no_secret(&canonical);

    let mut raw = Vec::new();
    raw.extend_from_slice(&client_hello);
    raw.extend_from_slice(&request);
    raw.extend_from_slice(&response);

    let mut blobs = DeterministicMemoryBlobStore::default();
    let raw_ref = blobs
        .put_blob(Some(&session_id), &raw)
        .expect("raw source material must persist behind an opaque reference");
    let normalized_ref = blobs
        .put_blob(Some(&session_id), canonical.as_bytes())
        .expect("normalized source must persist behind an opaque reference");
    let mut store = SqliteMetadataStore::open_in_memory().expect("SQLite metadata store must open");
    store
        .create_capture_session(
            &session_id,
            TimestampNs(STARTED_AT_NS),
            Some("INT-001 proof"),
        )
        .expect("capture session must persist");
    store
        .upsert_flow_metadata(&normalized)
        .expect("normalized metadata projection must persist");
    store
        .set_normalized_source_ref(&flow_id, Some(&normalized_ref))
        .expect("normalized source reference must link to the metadata row");

    StoredSources {
        store,
        blobs,
        flow_id,
        raw_ref,
        normalized_ref,
        canonical,
        raw,
    }
}

fn adversarial_event(kind: &str) -> EventRef {
    EventRef {
        id: FLOW_ID.to_owned(),
        kind: kind.to_owned(),
    }
}

fn assert_sources_and_no_semantics(sources: &StoredSources) {
    let index = sources
        .store
        .get_flow_index(&sources.flow_id)
        .expect("source flow query must succeed")
        .expect("source flow must remain present");
    assert_eq!(
        index.normalized_source_ref.as_ref().map(BlobRef::as_str),
        Some(sources.normalized_ref.as_str())
    );
    assert_eq!(
        sources
            .blobs
            .read_blob(&sources.raw_ref)
            .expect("raw source read must succeed")
            .as_deref(),
        Some(sources.raw.as_slice())
    );
    assert_eq!(
        sources
            .blobs
            .read_blob(&sources.normalized_ref)
            .expect("normalized source read must succeed")
            .as_deref(),
        Some(sources.canonical.as_bytes())
    );
    let semantics = sources
        .store
        .query_semantic_events(&SemanticQuery::new(
            PageSize::new(10).expect("page size must be valid"),
        ))
        .expect("semantic query must succeed");
    assert!(
        semantics.items.is_empty(),
        "a failed analyzer run must not commit partially staged output"
    );
}

fn assert_ui_shapes(page: &Value, detail: &Value, semantic_page: &Value) {
    assert_exact_keys(page, &["items", "nextCursor"]);
    let list_item = &page["items"][0];
    assert_exact_keys(
        list_item,
        &[
            "flowId",
            "startedAtNs",
            "transportProtocol",
            "destinationHost",
            "destinationIp",
            "destinationPort",
            "protocols",
            "httpMethod",
            "httpStatus",
        ],
    );
    assert_exact_keys(
        detail,
        &[
            "summary",
            "connectionId",
            "captureSessionId",
            "firstByteAtNs",
            "endedAtNs",
            "normalizedSourceAvailable",
        ],
    );
    assert_exact_keys(&detail["summary"], &object_keys(list_item));
    assert_exact_keys(semantic_page, &["items", "nextCursor"]);
    assert_exact_keys(
        &semantic_page["items"][0],
        &[
            "eventId",
            "captureSessionId",
            "sourceFlowId",
            "analyzerId",
            "analyzerVersion",
            "namespace",
            "kind",
            "timestampNs",
        ],
    );
}

fn object_keys(value: &Value) -> Vec<&str> {
    value
        .as_object()
        .expect("DTO must be a JSON object")
        .keys()
        .map(String::as_str)
        .collect()
}

fn assert_exact_keys(value: &Value, expected: &[&str]) {
    let actual = object_keys(value).into_iter().collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}

fn assert_no_secret(output: &str) {
    for sentinel in [AUTHORIZATION_SENTINEL, COOKIE_SENTINEL, BODY_SENTINEL] {
        assert!(
            !output.contains(sentinel),
            "ordinary output must not expose the synthetic {sentinel} canary"
        );
    }
}

fn assert_opaque_ref(reference: &BlobRef) {
    let value = reference.as_str();
    assert!(value.starts_with("blob_"));
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    assert!(!value.contains('/') && !value.contains('\\') && !value.contains(':'));
}

fn contains_bytes(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

fn decode_hex(fixture: &str) -> Vec<u8> {
    let digits = fixture
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let (pairs, remainder) = digits.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "hex fixture must contain byte pairs");
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex pair must be ASCII");
            u8::from_str_radix(text, 16).expect("hex fixture must contain valid digits")
        })
        .collect()
}
