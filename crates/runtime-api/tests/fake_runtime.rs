use flowprobe_config_compiler::{
    ConfigCompiler, RuntimeConfigValidator, RuntimeOverlay, RuntimeValidationFailure, SystemBase,
    UserProfile,
};
use flowprobe_runtime_api::{
    CompiledConfig, DirectEgressStatus, FakeNetworkRuntime, FakeRuntimeOptions, NetworkRuntime,
    OperationDetail, ProxyGroup, ProxyGroupId, ProxyId, RuntimeCapabilities, RuntimeCapability,
    RuntimeConnection, RuntimeConnectionId, RuntimeError, RuntimeHealth, RuntimeOperation,
    RuntimePhase, RuntimeResource, RuntimeState, RuntimeTransport, RuntimeUnavailableReason,
    RuntimeVersion,
};

struct AcceptConfig;

impl RuntimeConfigValidator for AcceptConfig {
    fn validate(&self, _canonical_runtime_json: &str) -> Result<(), RuntimeValidationFailure> {
        Ok(())
    }
}

fn compiled_config(user_json: &str) -> CompiledConfig {
    ConfigCompiler::new(AcceptConfig)
        .compile(
            &SystemBase::parse("{}").expect("system layer should parse"),
            &UserProfile::parse(user_json).expect("user layer should parse"),
            &RuntimeOverlay::parse("{}").expect("overlay layer should parse"),
        )
        .expect("test configuration should compile")
}

fn proxy_group() -> ProxyGroup {
    ProxyGroup::new(
        ProxyGroupId::new("egress").expect("group id should be valid"),
        vec![
            ProxyId::new("direct").expect("proxy id should be valid"),
            ProxyId::new("relay").expect("proxy id should be valid"),
        ],
        Some(ProxyId::new("direct").expect("proxy id should be valid")),
    )
    .expect("group should be valid")
}

fn connection() -> RuntimeConnection {
    RuntimeConnection {
        id: RuntimeConnectionId::new("connection-1").expect("connection id should be valid"),
        transport: RuntimeTransport::Tcp,
        uploaded_bytes: 17,
        downloaded_bytes: 29,
    }
}

#[test]
fn fake_runtime_exercises_every_supported_operation_and_records_order() {
    let runtime = FakeNetworkRuntime::new(FakeRuntimeOptions {
        version: RuntimeVersion::new("fake 1.2.3").expect("version should be valid"),
        proxy_groups: vec![proxy_group()],
        connections: vec![connection()],
        ..FakeRuntimeOptions::default()
    });
    let first = compiled_config(r#"{"outbounds":[{"tag":"direct","type":"direct"}]}"#);
    let second = compiled_config(r#"{"log":{"level":"warn"}}"#);

    runtime
        .validate_config(&first)
        .expect("fake validation should succeed");
    assert_eq!(
        runtime.state().expect("state should be available"),
        RuntimeState::Stopped { generation: 0 }
    );
    assert_eq!(
        runtime.health().expect("health should be available"),
        RuntimeHealth::Inactive
    );
    assert_eq!(
        runtime
            .version()
            .expect("version should be available")
            .as_str(),
        "fake 1.2.3"
    );
    let capabilities = runtime
        .capabilities()
        .expect("capabilities should be available");
    assert!(capabilities.supports(RuntimeCapability::DirectEgress));

    let started = runtime.start(&first).expect("start should succeed");
    assert_eq!(started.phase(), RuntimePhase::Running);
    assert_eq!(started.generation(), 1);
    assert_eq!(
        runtime
            .start(&first)
            .expect("same start should be idempotent"),
        started
    );
    assert_eq!(
        runtime.health().expect("health should succeed"),
        RuntimeHealth::Healthy
    );

    let groups = runtime.proxy_groups().expect("groups should be queryable");
    assert_eq!(groups, vec![proxy_group()]);
    let selected = runtime
        .select_proxy(
            &ProxyGroupId::new("egress").expect("group id should be valid"),
            &ProxyId::new("relay").expect("proxy id should be valid"),
        )
        .expect("selection should succeed");
    assert_eq!(
        selected
            .selected()
            .expect("selection should be present")
            .as_str(),
        "relay"
    );
    assert_eq!(
        runtime
            .connections()
            .expect("connections should be available"),
        vec![connection()]
    );
    let status = runtime.status().expect("status should be available");
    assert_eq!(status.state, started);
    assert_eq!(status.health, RuntimeHealth::Healthy);
    assert_eq!(status.active_connections, Some(1));
    assert_eq!(status.uploaded_bytes, Some(17));
    assert_eq!(status.downloaded_bytes, Some(29));
    assert_eq!(
        runtime
            .probe_direct_egress()
            .expect("direct probe should succeed"),
        DirectEgressStatus::Ready
    );

    let applied = runtime
        .apply_config(&second)
        .expect("reload should be supported by the fake");
    assert_eq!(applied.generation, 2);
    assert_eq!(
        runtime.stop().expect("stop should succeed"),
        RuntimeState::Stopped { generation: 2 }
    );
    assert_eq!(
        runtime.stop().expect("second stop should be idempotent"),
        RuntimeState::Stopped { generation: 2 }
    );

    let records = runtime
        .operation_records()
        .expect("operation records should be available");
    assert_eq!(
        records
            .iter()
            .map(|record| record.operation)
            .collect::<Vec<_>>(),
        vec![
            RuntimeOperation::ValidateConfig,
            RuntimeOperation::State,
            RuntimeOperation::Health,
            RuntimeOperation::Version,
            RuntimeOperation::Capabilities,
            RuntimeOperation::Start,
            RuntimeOperation::Start,
            RuntimeOperation::Health,
            RuntimeOperation::ProxyGroups,
            RuntimeOperation::SelectProxy,
            RuntimeOperation::Connections,
            RuntimeOperation::Status,
            RuntimeOperation::ProbeDirectEgress,
            RuntimeOperation::ApplyConfig,
            RuntimeOperation::Stop,
            RuntimeOperation::Stop,
        ]
    );
    assert!(
        records
            .iter()
            .enumerate()
            .all(|(index, record)| record.sequence == u64::try_from(index).expect("index fits"))
    );
    let selection = records
        .iter()
        .find(|record| record.operation == RuntimeOperation::SelectProxy)
        .expect("selection should be recorded");
    assert_eq!(
        selection.detail,
        OperationDetail::ProxySelection {
            group: ProxyGroupId::new("egress").expect("group id should be valid"),
            proxy: ProxyId::new("relay").expect("proxy id should be valid"),
        }
    );
}

#[test]
fn fake_runtime_reports_invalid_state_and_lookup_failures() {
    let runtime = FakeNetworkRuntime::new(FakeRuntimeOptions {
        proxy_groups: vec![proxy_group()],
        ..FakeRuntimeOptions::default()
    });
    let config = compiled_config("{}");

    assert_eq!(
        runtime.proxy_groups(),
        Err(RuntimeError::InvalidState {
            operation: RuntimeOperation::ProxyGroups,
            actual: RuntimePhase::Stopped,
            required: RuntimePhase::Running,
        })
    );
    runtime.start(&config).expect("start should succeed");
    assert_eq!(
        runtime.start(&compiled_config(r#"{"log":{"level":"error"}}"#)),
        Err(RuntimeError::InvalidState {
            operation: RuntimeOperation::Start,
            actual: RuntimePhase::Running,
            required: RuntimePhase::Stopped,
        })
    );
    assert_eq!(
        runtime.select_proxy(
            &ProxyGroupId::new("missing").expect("group id should be valid"),
            &ProxyId::new("direct").expect("proxy id should be valid"),
        ),
        Err(RuntimeError::NotFound {
            operation: RuntimeOperation::SelectProxy,
            resource: RuntimeResource::ProxyGroup,
        })
    );
    assert_eq!(
        runtime.select_proxy(
            &ProxyGroupId::new("egress").expect("group id should be valid"),
            &ProxyId::new("missing").expect("proxy id should be valid"),
        ),
        Err(RuntimeError::NotFound {
            operation: RuntimeOperation::SelectProxy,
            resource: RuntimeResource::Proxy,
        })
    );

    runtime
        .simulate_exit(Some(41))
        .expect("exit should be simulated");
    assert_eq!(
        runtime.state().expect("crash state should be available"),
        RuntimeState::Crashed {
            generation: 1,
            exit_code: Some(41),
        }
    );
    assert_eq!(
        runtime.health().expect("crash health should be available"),
        RuntimeHealth::Unhealthy {
            exit_code: Some(41),
        }
    );
}

#[test]
fn fake_runtime_returns_typed_unsupported_results_for_each_optional_surface() {
    let runtime = FakeNetworkRuntime::new(FakeRuntimeOptions {
        capabilities: RuntimeCapabilities::default(),
        ..FakeRuntimeOptions::default()
    });
    let config = compiled_config("{}");

    let cases = [
        runtime
            .validate_config(&config)
            .expect_err("validation is unsupported"),
        runtime.start(&config).expect_err("start is unsupported"),
        runtime.stop().expect_err("stop is unsupported"),
        runtime.health().expect_err("health is unsupported"),
        runtime
            .apply_config(&config)
            .expect_err("reload is unsupported"),
        runtime.version().expect_err("version is unsupported"),
        runtime
            .proxy_groups()
            .expect_err("proxy groups are unsupported"),
        runtime
            .select_proxy(
                &ProxyGroupId::new("group").expect("group id should be valid"),
                &ProxyId::new("proxy").expect("proxy id should be valid"),
            )
            .expect_err("proxy selection is unsupported"),
        runtime
            .connections()
            .expect_err("connections are unsupported"),
        runtime.status().expect_err("status is unsupported"),
        runtime
            .probe_direct_egress()
            .expect_err("direct probe is unsupported"),
    ];

    assert!(
        cases
            .iter()
            .all(|error| matches!(error, RuntimeError::Unsupported { .. }))
    );
    assert_eq!(
        runtime.state().expect("base state is always queryable"),
        RuntimeState::Stopped { generation: 0 }
    );
    assert_eq!(
        runtime
            .capabilities()
            .expect("capability discovery is always queryable"),
        RuntimeCapabilities::default()
    );
    assert_eq!(
        RuntimeConfigValidator::validate(&runtime, "{}"),
        Err(RuntimeValidationFailure::Unavailable)
    );
}

#[test]
fn injected_failures_are_one_shot_ordered_and_do_not_change_state() {
    let runtime = FakeNetworkRuntime::default();
    let injected = RuntimeError::Unavailable {
        operation: RuntimeOperation::Version,
        reason: RuntimeUnavailableReason::ControlSurfaceUnavailable,
    };
    runtime
        .inject_failure(RuntimeOperation::Version, injected.clone())
        .expect("failure should be queued");

    assert_eq!(
        runtime.health().expect("unrelated call should succeed"),
        RuntimeHealth::Inactive
    );
    assert_eq!(runtime.version(), Err(injected));
    assert_eq!(
        runtime
            .version()
            .expect("failure should only apply once")
            .as_str(),
        "fake-network-runtime-v0"
    );
    assert_eq!(
        runtime.state().expect("state should not change"),
        RuntimeState::Stopped { generation: 0 }
    );
    assert!(matches!(
        runtime.inject_failure(RuntimeOperation::Health, RuntimeError::ValidationRejected),
        Err(RuntimeError::InvalidInput {
            operation: RuntimeOperation::Health,
            field: "injected_failure",
            ..
        })
    ));
}

#[test]
fn compiler_validation_failure_and_fake_records_never_expose_secret_json() {
    let runtime = FakeNetworkRuntime::default();
    runtime
        .inject_failure(
            RuntimeOperation::ValidateConfig,
            RuntimeError::ValidationRejected,
        )
        .expect("failure should be queued");
    let secret = "not-a-real-user-secret";
    let result = ConfigCompiler::new(runtime.clone()).compile(
        &SystemBase::parse("{}").expect("system layer should parse"),
        &UserProfile::parse(&format!(r#"{{"password":"{secret}"}}"#))
            .expect("user layer should parse"),
        &RuntimeOverlay::parse("{}").expect("overlay layer should parse"),
    );

    let error = result.expect_err("injected validation should fail");
    assert!(!format!("{error:?} {error}").contains(secret));
    assert!(
        error
            .report()
            .diagnostics()
            .iter()
            .all(|diagnostic| !format!("{diagnostic:?}").contains(secret))
    );
    assert!(
        runtime
            .operation_records()
            .expect("records should be available")
            .iter()
            .all(|record| !format!("{record:?}").contains(secret))
    );
}

#[test]
fn public_identifiers_reject_ambiguous_or_unbounded_values() {
    assert!(ProxyId::new("").is_err());
    assert!(ProxyGroupId::new(" leading").is_err());
    assert!(RuntimeConnectionId::new("line\nbreak").is_err());
    assert!(RuntimeVersion::new("x".repeat(257)).is_err());
    assert!(
        ProxyGroup::new(
            ProxyGroupId::new("group").expect("group id should be valid"),
            vec![ProxyId::new("proxy").expect("proxy id should be valid"); 2],
            None,
        )
        .is_err()
    );
}
