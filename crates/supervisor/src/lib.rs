//! Non-renderer lifecycle boundary for desktop IPC.

use std::{fmt, sync::Arc};

use flowprobe_ipc::{AppStatus, SubsystemAvailability, SupervisorLifecycle};
use flowprobe_runtime_api::{
    ApplyOutcome, CompiledConfig, DirectEgressStatus, NetworkRuntime, ProxyGroup, ProxyGroupId,
    ProxyId, RuntimeCapabilities, RuntimeConnection, RuntimeError, RuntimeHealth, RuntimeOperation,
    RuntimeResult, RuntimeState, RuntimeStatus, RuntimeUnavailableReason, RuntimeVersion,
};

mod traffic;

pub use traffic::TrafficService;

/// Owns process and privileged-service coordination outside the renderer.
pub struct Supervisor {
    lifecycle: SupervisorLifecycle,
    network_runtime: Option<Arc<dyn NetworkRuntime>>,
}

impl fmt::Debug for Supervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Supervisor")
            .field("lifecycle", &self.lifecycle)
            .field(
                "network_runtime_configured",
                &self.network_runtime.is_some(),
            )
            .finish()
    }
}

impl Supervisor {
    /// Creates an idle supervisor without claiming that any runtime is available.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lifecycle: SupervisorLifecycle::Idle,
            network_runtime: None,
        }
    }

    /// Creates a supervisor that controls a runtime only through [`NetworkRuntime`].
    #[must_use]
    pub fn with_network_runtime(network_runtime: Arc<dyn NetworkRuntime>) -> Self {
        Self {
            lifecycle: SupervisorLifecycle::Idle,
            network_runtime: Some(network_runtime),
        }
    }

    /// Reports the actual wiring state of the foundation shell.
    ///
    /// The v0 IPC availability enum does not yet have a configured state, so runtime
    /// details remain on the typed supervisor methods below instead of being guessed.
    #[must_use]
    pub const fn status(&self) -> AppStatus {
        AppStatus {
            supervisor: self.lifecycle,
            network_runtime: SubsystemAvailability::NotConfigured,
            capture_core: SubsystemAvailability::NotConfigured,
            analyzer_runtime: SubsystemAvailability::NotConfigured,
        }
    }

    pub fn validate_network_config(&self, config: &CompiledConfig) -> RuntimeResult<()> {
        self.runtime(RuntimeOperation::ValidateConfig)?
            .validate_config(config)
    }

    pub fn start_network_runtime(&self, config: &CompiledConfig) -> RuntimeResult<RuntimeState> {
        self.runtime(RuntimeOperation::Start)?.start(config)
    }

    pub fn stop_network_runtime(&self) -> RuntimeResult<RuntimeState> {
        self.runtime(RuntimeOperation::Stop)?.stop()
    }

    pub fn network_health(&self) -> RuntimeResult<RuntimeHealth> {
        self.runtime(RuntimeOperation::Health)?.health()
    }

    pub fn network_state(&self) -> RuntimeResult<RuntimeState> {
        self.runtime(RuntimeOperation::State)?.state()
    }

    pub fn apply_network_config(&self, config: &CompiledConfig) -> RuntimeResult<ApplyOutcome> {
        self.runtime(RuntimeOperation::ApplyConfig)?
            .apply_config(config)
    }

    pub fn network_version(&self) -> RuntimeResult<RuntimeVersion> {
        self.runtime(RuntimeOperation::Version)?.version()
    }

    pub fn network_capabilities(&self) -> RuntimeResult<RuntimeCapabilities> {
        self.runtime(RuntimeOperation::Capabilities)?.capabilities()
    }

    pub fn network_proxy_groups(&self) -> RuntimeResult<Vec<ProxyGroup>> {
        self.runtime(RuntimeOperation::ProxyGroups)?.proxy_groups()
    }

    pub fn select_network_proxy(
        &self,
        group: &ProxyGroupId,
        proxy: &ProxyId,
    ) -> RuntimeResult<ProxyGroup> {
        self.runtime(RuntimeOperation::SelectProxy)?
            .select_proxy(group, proxy)
    }

    pub fn network_connections(&self) -> RuntimeResult<Vec<RuntimeConnection>> {
        self.runtime(RuntimeOperation::Connections)?.connections()
    }

    pub fn network_status(&self) -> RuntimeResult<RuntimeStatus> {
        self.runtime(RuntimeOperation::Status)?.status()
    }

    pub fn probe_direct_egress(&self) -> RuntimeResult<DirectEgressStatus> {
        self.runtime(RuntimeOperation::ProbeDirectEgress)?
            .probe_direct_egress()
    }

    fn runtime(&self, operation: RuntimeOperation) -> RuntimeResult<&dyn NetworkRuntime> {
        self.network_runtime
            .as_deref()
            .ok_or(RuntimeError::Unavailable {
                operation,
                reason: RuntimeUnavailableReason::NotConfigured,
            })
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use flowprobe_config_compiler::{ConfigCompiler, RuntimeOverlay, SystemBase, UserProfile};
    use flowprobe_ipc::{SubsystemAvailability, SupervisorLifecycle};
    use flowprobe_runtime_api::{
        DirectEgressStatus, FakeNetworkRuntime, RuntimeCapability, RuntimeError, RuntimeOperation,
        RuntimePhase, RuntimeUnavailableReason,
    };

    use super::Supervisor;

    #[test]
    fn foundation_status_does_not_report_unwired_subsystems_as_ready() {
        let status = Supervisor::new().status();

        assert_eq!(status.supervisor, SupervisorLifecycle::Idle);
        assert_eq!(status.network_runtime, SubsystemAvailability::NotConfigured);
        assert_eq!(status.capture_core, SubsystemAvailability::NotConfigured);
        assert_eq!(
            status.analyzer_runtime,
            SubsystemAvailability::NotConfigured
        );
    }

    #[test]
    fn unconfigured_runtime_returns_a_typed_unavailable_result() {
        let supervisor = Supervisor::new();

        assert_eq!(
            supervisor.network_state(),
            Err(RuntimeError::Unavailable {
                operation: RuntimeOperation::State,
                reason: RuntimeUnavailableReason::NotConfigured,
            })
        );
    }

    #[test]
    fn supervisor_controls_a_fake_only_through_the_runtime_trait() {
        let runtime = Arc::new(FakeNetworkRuntime::default());
        let supervisor = Supervisor::with_network_runtime(runtime.clone());
        let first = ConfigCompiler::new(runtime.as_ref().clone())
            .compile(
                &SystemBase::parse("{}").expect("system layer should parse"),
                &UserProfile::parse(r#"{"outbounds":[{"tag":"direct","type":"direct"}]}"#)
                    .expect("user layer should parse"),
                &RuntimeOverlay::parse("{}").expect("overlay layer should parse"),
            )
            .expect("the same runtime validator should accept the first config");
        let second = ConfigCompiler::new(runtime.as_ref().clone())
            .compile(
                &SystemBase::parse("{}").expect("system layer should parse"),
                &UserProfile::parse(r#"{"log":{"level":"warn"}}"#)
                    .expect("user layer should parse"),
                &RuntimeOverlay::parse("{}").expect("overlay layer should parse"),
            )
            .expect("the same runtime validator should accept the second config");

        supervisor
            .validate_network_config(&first)
            .expect("validation should be forwarded");
        assert!(
            supervisor
                .network_capabilities()
                .expect("capabilities should be forwarded")
                .supports(RuntimeCapability::DirectEgress)
        );
        assert_eq!(
            supervisor
                .network_version()
                .expect("version should be forwarded")
                .as_str(),
            "fake-network-runtime-v0"
        );
        assert_eq!(
            supervisor
                .start_network_runtime(&first)
                .expect("start should be forwarded")
                .phase(),
            RuntimePhase::Running
        );
        assert_eq!(
            supervisor
                .probe_direct_egress()
                .expect("direct probe should be forwarded"),
            DirectEgressStatus::Ready
        );
        assert!(
            supervisor
                .network_proxy_groups()
                .expect("group query should be forwarded")
                .is_empty()
        );
        assert!(
            supervisor
                .network_connections()
                .expect("connection query should be forwarded")
                .is_empty()
        );
        assert_eq!(
            supervisor
                .network_status()
                .expect("status should be forwarded")
                .state
                .phase(),
            RuntimePhase::Running
        );
        assert_eq!(
            supervisor
                .network_health()
                .expect("health should be forwarded"),
            flowprobe_runtime_api::RuntimeHealth::Healthy
        );
        assert_eq!(
            supervisor
                .apply_network_config(&second)
                .expect("reload should be forwarded")
                .generation,
            2
        );
        assert_eq!(
            supervisor
                .stop_network_runtime()
                .expect("stop should be forwarded")
                .phase(),
            RuntimePhase::Stopped
        );
        assert_eq!(
            supervisor
                .network_state()
                .expect("state should be forwarded")
                .phase(),
            RuntimePhase::Stopped
        );
    }
}
