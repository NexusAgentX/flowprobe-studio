use std::sync::{Arc, Mutex};

use flowprobe_analyzer_runtime::{
    AnalyzerError, AnalyzerHost, AnalyzerLimits, AnalyzerLogEntry, AnalyzerPermissions,
    AnalyzerRuntime, EventRef, HostErrorCode, SemanticEvent,
};

const DEMO_COMPONENT: &[u8] =
    include_bytes!("../../../plugins/demo/artifacts/flowprobe_demo_analyzer.wasm");
const ADVERSARIAL_COMPONENT: &[u8] =
    include_bytes!("../../../tests/contract/analyzer/artifacts/adversarial_analyzer.wasm");
const INVALID_INFO_COMPONENT: &[u8] =
    include_bytes!("../../../tests/contract/analyzer/artifacts/invalid_info_analyzer.wasm");
const HOSTILE_INFO_COMPONENT: &[u8] =
    include_bytes!("../../../tests/contract/analyzer/artifacts/hostile_info_analyzer.wasm");
const NORMALIZED_FIXTURE: &str = include_str!("../../../tests/fixtures/normalized-flow-v0.json");

#[derive(Debug, Clone, PartialEq, Eq)]
struct SemanticSnapshot {
    namespace: String,
    kind: String,
    timestamp_ns: u64,
    json_attributes: String,
}

#[derive(Default)]
struct Recording {
    event_json: String,
    semantics: Vec<SemanticSnapshot>,
    logs: Vec<AnalyzerLogEntry>,
    event_reads: usize,
    event_error: Option<HostErrorCode>,
    emit_error: Option<HostErrorCode>,
    log_error: Option<HostErrorCode>,
}

#[derive(Clone)]
struct RecordingHost(Arc<Mutex<Recording>>);

impl RecordingHost {
    fn with_event_json(json: impl Into<String>) -> Self {
        Self(Arc::new(Mutex::new(Recording {
            event_json: json.into(),
            ..Recording::default()
        })))
    }

    fn semantics(&self) -> Vec<SemanticSnapshot> {
        self.0
            .lock()
            .expect("recording host mutex poisoned")
            .semantics
            .clone()
    }

    fn event_reads(&self) -> usize {
        self.0
            .lock()
            .expect("recording host mutex poisoned")
            .event_reads
    }

    fn log_entries(&self) -> usize {
        self.0
            .lock()
            .expect("recording host mutex poisoned")
            .logs
            .len()
    }

    fn set_event_error(&self, error: HostErrorCode) {
        self.0
            .lock()
            .expect("recording host mutex poisoned")
            .event_error = Some(error);
    }

    fn set_emit_error(&self, error: HostErrorCode) {
        self.0
            .lock()
            .expect("recording host mutex poisoned")
            .emit_error = Some(error);
    }

    fn set_log_error(&self, error: HostErrorCode) {
        self.0
            .lock()
            .expect("recording host mutex poisoned")
            .log_error = Some(error);
    }
}

impl AnalyzerHost for RecordingHost {
    fn get_event_json(&mut self, _event: &EventRef) -> Result<String, HostErrorCode> {
        let mut recording = self.0.lock().expect("recording host mutex poisoned");
        recording.event_reads += 1;
        if let Some(error) = recording.event_error {
            return Err(error);
        }
        Ok(recording.event_json.clone())
    }

    fn emit_semantic(&mut self, event: &SemanticEvent) -> Result<(), HostErrorCode> {
        let mut recording = self.0.lock().expect("recording host mutex poisoned");
        if let Some(error) = recording.emit_error {
            return Err(error);
        }
        recording.semantics.push(SemanticSnapshot {
            namespace: event.namespace.clone(),
            kind: event.kind.clone(),
            timestamp_ns: event.timestamp_ns,
            json_attributes: event.json_attributes.clone(),
        });
        Ok(())
    }

    fn log(&mut self, entry: AnalyzerLogEntry) -> Result<(), HostErrorCode> {
        let mut recording = self.0.lock().expect("recording host mutex poisoned");
        if let Some(error) = recording.log_error {
            return Err(error);
        }
        recording.logs.push(entry);
        Ok(())
    }
}

fn event_ref() -> EventRef {
    EventRef {
        id: "flow_fixture_0001".into(),
        kind: "normalized-flow-v0".into(),
    }
}

fn fixture_event(kind: &str) -> EventRef {
    EventRef {
        id: "flow_fixture_0001".into(),
        kind: kind.into(),
    }
}

fn demo_permissions() -> AnalyzerPermissions {
    AnalyzerPermissions::new(true, true, false)
}

#[test]
fn demo_component_emits_the_same_semantic_event_for_the_golden_fixture() {
    let runtime = AnalyzerRuntime::new(AnalyzerLimits::default()).expect("runtime configuration");
    let analyzer = runtime
        .compile(DEMO_COMPONENT, demo_permissions())
        .expect("demo component");
    let first_host = RecordingHost::with_event_json(NORMALIZED_FIXTURE);
    let second_host = RecordingHost::with_event_json(NORMALIZED_FIXTURE);

    let first = runtime
        .analyze(&analyzer, event_ref(), first_host.clone())
        .expect("first deterministic run");
    let second = runtime
        .analyze(&analyzer, event_ref(), second_host.clone())
        .expect("second deterministic run");

    assert_eq!(first.analyzer.id, "flowprobe.demo");
    assert_eq!(first.analyzer.version, "0.1.0");
    assert_eq!(first.event_reads, 1);
    assert_eq!(first.semantic_events, 1);
    assert!(first.fuel_consumed > 0);
    assert_eq!(first.fuel_consumed, second.fuel_consumed);
    assert_eq!(first_host.semantics(), second_host.semantics());
    assert_eq!(
        first_host.semantics(),
        vec![SemanticSnapshot {
            namespace: "flowprobe.demo".into(),
            kind: "fixture-observed".into(),
            timestamp_ns: 1_720_000_000_000_000_000,
            json_attributes:
                r#"{"event_id":"flow_fixture_0001","event_kind":"normalized-flow-v0","source":"deterministic-fixture"}"#
                    .into(),
        }]
    );
}

#[test]
fn only_the_exact_versioned_analyzer_interfaces_can_be_imported() {
    let runtime = AnalyzerRuntime::new(AnalyzerLimits::default()).expect("runtime configuration");

    for import in [
        "wasi:filesystem/types@0.2.0",
        "wasi:sockets/tcp@0.2.0",
        "wasi:cli/run@0.2.0",
    ] {
        let component = wat::parse_str(format!(r#"(component (import "{import}" (instance)))"#))
            .expect("valid ambient-import test component");
        let error = runtime
            .compile(&component, AnalyzerPermissions::NONE)
            .expect_err("ambient import must be rejected");
        assert_eq!(error, AnalyzerError::AmbientCapabilityDenied);
        assert!(!error.to_string().contains(import));
    }

    let wrong_version =
        wat::parse_str(r#"(component (import "flowprobe:analyzer/host@0.2.0" (instance)))"#)
            .expect("valid wrong-version test component");
    assert_eq!(
        runtime
            .compile(&wrong_version, AnalyzerPermissions::NONE)
            .expect_err("wrong WIT version must be rejected"),
        AnalyzerError::UnsupportedContractVersion
    );

    let wrong_exact_import_shape = wat::parse_str(
        r#"(component
            (type $wrong-get (func (param "event" string) (result string)))
            (type $wrong-host (instance
                (export "get-event-json" (func (type $wrong-get)))
            ))
            (import "flowprobe:analyzer/host@0.1.0"
                (instance (type $wrong-host)))
        )"#,
    )
    .expect("valid exact-name wrong-import-shape component");
    assert_eq!(
        runtime
            .compile(&wrong_exact_import_shape, AnalyzerPermissions::NONE)
            .expect_err("an exact import name cannot bypass its function shape"),
        AnalyzerError::ContractMismatch
    );

    let wrong_export_signature = wat::parse_str(
        r#"(component
            (core module $module
                (func (export "wrong-info"))
            )
            (core instance $instance (instantiate $module))
            (alias core export $instance "wrong-info" (core func $wrong-core-info))
            (type $wrong-info-type (func))
            (func $wrong-info (type $wrong-info-type)
                (canon lift (core func $wrong-core-info)))
            (export "info" (func $wrong-info))
        )"#,
    )
    .expect("valid wrong-export-signature component");
    assert_eq!(
        runtime
            .compile(&wrong_export_signature, AnalyzerPermissions::NONE)
            .expect_err("the exact export name still requires its WIT signature"),
        AnalyzerError::ContractMismatch
    );

    let missing_exports = wat::parse_str("(component)").expect("valid empty component");
    assert_eq!(
        runtime
            .compile(&missing_exports, AnalyzerPermissions::NONE)
            .expect_err("missing Analyzer exports must be rejected"),
        AnalyzerError::ContractMismatch
    );
    assert_eq!(
        runtime
            .compile(b"not wasm", AnalyzerPermissions::NONE)
            .expect_err("malformed bytes must be rejected"),
        AnalyzerError::InvalidComponent
    );
}

#[test]
fn component_and_event_inputs_are_bounded_before_execution() {
    let limits = AnalyzerLimits {
        max_component_bytes: 16,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    assert_eq!(
        runtime
            .compile(DEMO_COMPONENT, demo_permissions())
            .expect_err("oversized component must be rejected"),
        AnalyzerError::ComponentTooLarge { max_bytes: 16 }
    );

    let runtime = AnalyzerRuntime::new(AnalyzerLimits::default()).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");
    let host = RecordingHost::with_event_json("{}");
    let error = runtime
        .analyze(
            &analyzer,
            EventRef {
                id: String::new(),
                kind: "fixture.event-json".into(),
            },
            host.clone(),
        )
        .expect_err("empty event identity must be rejected");
    assert_eq!(error, AnalyzerError::InvalidEventRef { field: "id" });
    assert_eq!(host.event_reads(), 0);

    let limits = AnalyzerLimits {
        max_event_id_bytes: 4,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                EventRef {
                    id: "identifier-too-long".into(),
                    kind: "kind".into(),
                },
                RecordingHost::with_event_json("{}"),
            )
            .expect_err("event id byte limit must be enforced"),
        AnalyzerError::InvalidEventRef { field: "id" }
    );

    let limits = AnalyzerLimits {
        max_event_kind_bytes: 4,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                EventRef {
                    id: "id".into(),
                    kind: "event-kind-too-long".into(),
                },
                RecordingHost::with_event_json("{}"),
            )
            .expect_err("event kind byte limit must be enforced"),
        AnalyzerError::InvalidEventRef { field: "kind" }
    );
}

#[test]
fn analyzer_metadata_requires_a_bounded_semantic_version() {
    let runtime = AnalyzerRuntime::new(AnalyzerLimits::default()).expect("runtime configuration");
    let analyzer = runtime
        .compile(INVALID_INFO_COMPONENT, AnalyzerPermissions::NONE)
        .expect("invalid-info fixture still has the correct WIT shape");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.guest-error"),
                RecordingHost::with_event_json("{}")
            )
            .expect_err("invalid analyzer version must be rejected before analyze"),
        AnalyzerError::InvalidAnalyzerInfo { field: "version" }
    );

    let limits = AnalyzerLimits {
        max_analyzer_id_bytes: 4,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::NONE)
        .expect("adversarial fixture has valid metadata shape");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.guest-error"),
                RecordingHost::with_event_json("{}"),
            )
            .expect_err("analyzer id byte limit must be enforced"),
        AnalyzerError::InvalidAnalyzerInfo { field: "id" }
    );

    let limits = AnalyzerLimits {
        max_analyzer_version_bytes: 4,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::NONE)
        .expect("adversarial fixture has valid metadata shape");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.guest-error"),
                RecordingHost::with_event_json("{}"),
            )
            .expect_err("analyzer version byte limit must be enforced"),
        AnalyzerError::InvalidAnalyzerInfo { field: "version" }
    );
}

#[test]
fn analyzer_info_cannot_use_real_host_capabilities_before_metadata_validation() {
    let runtime = AnalyzerRuntime::new(AnalyzerLimits::default()).expect("runtime configuration");
    let analyzer = runtime
        .compile(HOSTILE_INFO_COMPONENT, AnalyzerPermissions::all())
        .expect("hostile-info fixture has the correct WIT shape");
    let host = RecordingHost::with_event_json("{}");

    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.guest-error"),
                host.clone()
            )
            .expect_err("metadata phase must not receive host capabilities"),
        AnalyzerError::MetadataCapabilityDenied
    );
    assert_eq!(host.event_reads(), 0);
    assert!(host.semantics().is_empty());
    assert_eq!(host.log_entries(), 0);
}

#[test]
fn host_event_json_is_authorized_bounded_and_structurally_validated() {
    let limits = AnalyzerLimits {
        max_event_json_bytes: 32,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");

    let invalid = RecordingHost::with_event_json("not-json");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.event-json"),
                invalid.clone()
            )
            .expect_err("malformed host JSON must trap with a typed error"),
        AnalyzerError::InvalidEventJson
    );
    assert_eq!(invalid.event_reads(), 1);

    let non_object = RecordingHost::with_event_json("[]");
    assert_eq!(
        runtime
            .analyze(&analyzer, fixture_event("fixture.event-json"), non_object)
            .expect_err("non-object host JSON must be rejected"),
        AnalyzerError::InvalidEventJson
    );

    let oversized = RecordingHost::with_event_json(format!(r#"{{"x":"{}"}}"#, "x".repeat(64)));
    assert_eq!(
        runtime
            .analyze(&analyzer, fixture_event("fixture.event-json"), oversized)
            .expect_err("oversized host JSON must be rejected"),
        AnalyzerError::EventJsonTooLarge
    );
}

#[test]
fn analyzer_cannot_query_an_unrelated_event_or_exhaust_host_reads() {
    let limits = AnalyzerLimits {
        max_event_reads: 2,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");

    let unauthorized = RecordingHost::with_event_json("{}");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.unauthorized-event"),
                unauthorized.clone()
            )
            .expect_err("unrelated event reference must be rejected"),
        AnalyzerError::UnauthorizedEventReference
    );
    assert_eq!(unauthorized.event_reads(), 0);

    let repeated = RecordingHost::with_event_json("{}");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.event-reads"),
                repeated.clone()
            )
            .expect_err("event-read budget must be enforced"),
        AnalyzerError::EventReadLimitExceeded
    );
    assert_eq!(repeated.event_reads(), 2);
}

#[test]
fn semantic_outputs_are_validated_canonicalized_and_bounded() {
    let limits = AnalyzerLimits {
        max_semantic_events: 2,
        max_semantic_attributes_bytes: 128,
        max_total_semantic_bytes: 256,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");

    let invalid = RecordingHost::with_event_json("{}");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.invalid-output"),
                invalid.clone()
            )
            .expect_err("invalid semantic JSON must be rejected"),
        AnalyzerError::InvalidSemanticEvent {
            field: "json-attributes"
        }
    );
    assert!(invalid.semantics().is_empty());

    let too_many = RecordingHost::with_event_json("{}");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.outputs"),
                too_many.clone()
            )
            .expect_err("semantic event count must be bounded"),
        AnalyzerError::SemanticOutputLimitExceeded
    );
    assert_eq!(too_many.semantics().len(), 2);

    let oversized = RecordingHost::with_event_json("{}");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.oversized-output"),
                oversized.clone()
            )
            .expect_err("semantic attributes must be bounded"),
        AnalyzerError::SemanticOutputLimitExceeded
    );
    assert!(oversized.semantics().is_empty());

    let canonical = RecordingHost::with_event_json("{}");
    runtime
        .analyze(
            &analyzer,
            fixture_event("fixture.unsorted-output"),
            canonical.clone(),
        )
        .expect("valid semantic output");
    assert_eq!(
        canonical.semantics()[0].json_attributes,
        r#"{"a":{"x":3,"y":2},"z":1}"#
    );

    for (max_semantic_field_bytes, expected_field) in [(8, "namespace"), (16, "kind")] {
        let limits = AnalyzerLimits {
            max_semantic_field_bytes,
            ..AnalyzerLimits::default()
        };
        let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
        let analyzer = runtime
            .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
            .expect("adversarial fixture component");
        assert_eq!(
            runtime
                .analyze(
                    &analyzer,
                    fixture_event("fixture.host-emit-error"),
                    RecordingHost::with_event_json("{}"),
                )
                .expect_err("semantic namespace and kind must honor the field limit"),
            AnalyzerError::InvalidSemanticEvent {
                field: expected_field
            }
        );
    }

    let limits = AnalyzerLimits {
        max_total_semantic_bytes: 24,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.host-emit-error"),
                RecordingHost::with_event_json("{}"),
            )
            .expect_err("total semantic byte budget must be enforced"),
        AnalyzerError::SemanticOutputLimitExceeded
    );
}

#[test]
fn logs_are_bounded_and_host_log_failures_are_typed() {
    let limits = AnalyzerLimits {
        max_log_entries: 2,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");

    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.logs"),
                RecordingHost::with_event_json("{}")
            )
            .expect_err("log count must be bounded"),
        AnalyzerError::LogLimitExceeded
    );

    let rejected = RecordingHost::with_event_json("{}");
    rejected.set_log_error(HostErrorCode::Unavailable);
    assert_eq!(
        runtime
            .analyze(&analyzer, fixture_event("fixture.host-log-error"), rejected)
            .expect_err("host log failure must remain typed"),
        AnalyzerError::HostCapabilityFailed(HostErrorCode::Unavailable)
    );

    for limits in [
        AnalyzerLimits {
            max_log_level_bytes: 3,
            ..AnalyzerLimits::default()
        },
        AnalyzerLimits {
            max_log_message_bytes: 8,
            ..AnalyzerLimits::default()
        },
        AnalyzerLimits {
            max_total_log_bytes: 8,
            ..AnalyzerLimits::default()
        },
    ] {
        let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
        let analyzer = runtime
            .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
            .expect("adversarial fixture component");
        assert_eq!(
            runtime
                .analyze(
                    &analyzer,
                    fixture_event("fixture.host-log-error"),
                    RecordingHost::with_event_json("{}"),
                )
                .expect_err("log level, message, and total bytes must each be bounded"),
            AnalyzerError::LogLimitExceeded
        );
    }
}

#[test]
fn table_element_limit_is_a_typed_public_runtime_failure() {
    let limits = AnalyzerLimits {
        max_table_elements: 1,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.guest-error"),
                RecordingHost::with_event_json("{}"),
            )
            .expect_err("component table allocation must hit the element limiter"),
        AnalyzerError::TableLimitExceeded
    );
}

#[test]
fn fuel_memory_guest_traps_and_guest_errors_do_not_crash_the_host() {
    let limits = AnalyzerLimits {
        fuel_per_invocation: 1_000_000,
        ..AnalyzerLimits::default()
    };
    let runtime = AnalyzerRuntime::new(limits).expect("runtime configuration");
    let adversarial = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");
    let demo = runtime
        .compile(DEMO_COMPONENT, demo_permissions())
        .expect("demo component");

    assert_eq!(
        runtime
            .analyze(
                &adversarial,
                fixture_event("fixture.loop"),
                RecordingHost::with_event_json("{}")
            )
            .expect_err("infinite loop must exhaust fuel"),
        AnalyzerError::FuelExhausted
    );
    assert_eq!(
        runtime
            .analyze(
                &adversarial,
                fixture_event("fixture.memory"),
                RecordingHost::with_event_json("{}")
            )
            .expect_err("large allocation must hit the memory limiter"),
        AnalyzerError::MemoryLimitExceeded
    );
    assert_eq!(
        runtime
            .analyze(
                &adversarial,
                fixture_event("fixture.trap"),
                RecordingHost::with_event_json("{}")
            )
            .expect_err("guest trap must not unwind into the host"),
        AnalyzerError::GuestTrap
    );
    assert_eq!(
        runtime
            .analyze(
                &adversarial,
                fixture_event("fixture.guest-error"),
                RecordingHost::with_event_json("{}")
            )
            .expect_err("guest error result must be typed"),
        AnalyzerError::GuestRejected
    );

    runtime
        .analyze(
            &demo,
            event_ref(),
            RecordingHost::with_event_json(NORMALIZED_FIXTURE),
        )
        .expect("runtime remains usable after hostile components");
}

#[test]
fn undeclared_wit_capabilities_are_denied_before_the_real_host_is_called() {
    let runtime = AnalyzerRuntime::new(AnalyzerLimits::default()).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::NONE)
        .expect("adversarial fixture component");

    let read_host = RecordingHost::with_event_json("{}");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.event-json"),
                read_host.clone()
            )
            .expect_err("undeclared event read must be denied"),
        AnalyzerError::GuestRejected
    );
    assert_eq!(read_host.event_reads(), 0);

    let emit_host = RecordingHost::with_event_json("{}");
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.host-emit-error"),
                emit_host.clone()
            )
            .expect_err("undeclared semantic emit must be denied"),
        AnalyzerError::GuestRejected
    );
    assert!(emit_host.semantics().is_empty());

    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.host-log-error"),
                RecordingHost::with_event_json("{}")
            )
            .expect_err("undeclared log capability must be denied"),
        AnalyzerError::HostCapabilityFailed(HostErrorCode::PermissionDenied)
    );
}

#[test]
fn wit_result_failures_are_visible_to_the_guest_without_leaking_host_details() {
    let runtime = AnalyzerRuntime::new(AnalyzerLimits::default()).expect("runtime configuration");
    let analyzer = runtime
        .compile(ADVERSARIAL_COMPONENT, AnalyzerPermissions::all())
        .expect("adversarial fixture component");

    let read_failure = RecordingHost::with_event_json("{}");
    read_failure.set_event_error(HostErrorCode::PermissionDenied);
    assert_eq!(
        runtime
            .analyze(&analyzer, fixture_event("fixture.event-json"), read_failure)
            .expect_err("guest propagates bounded WIT host error"),
        AnalyzerError::GuestRejected
    );

    let emit_failure = RecordingHost::with_event_json("{}");
    emit_failure.set_emit_error(HostErrorCode::Rejected);
    assert_eq!(
        runtime
            .analyze(
                &analyzer,
                fixture_event("fixture.host-emit-error"),
                emit_failure
            )
            .expect_err("guest propagates bounded WIT emit error"),
        AnalyzerError::GuestRejected
    );
}
