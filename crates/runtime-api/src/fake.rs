use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use flowprobe_config_compiler::{RuntimeConfigValidator, RuntimeValidationFailure};

use crate::{
    ApplyOutcome, CompiledConfig, DirectEgressStatus, NetworkRuntime, ProxyGroup, ProxyGroupId,
    ProxyId, RuntimeCapabilities, RuntimeCapability, RuntimeConnection, RuntimeError,
    RuntimeHealth, RuntimeOperation, RuntimePhase, RuntimeResult, RuntimeState, RuntimeStatus,
    RuntimeVersion,
};

/// Non-secret detail retained with a fake runtime operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationDetail {
    None,
    ProxySelection { group: ProxyGroupId, proxy: ProxyId },
}

/// Deterministic operation record emitted by [`FakeNetworkRuntime`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOperationRecord {
    pub sequence: u64,
    pub operation: RuntimeOperation,
    pub detail: OperationDetail,
}

/// Initial capabilities and deterministic control-surface data for a fake runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeRuntimeOptions {
    pub version: RuntimeVersion,
    pub capabilities: RuntimeCapabilities,
    pub proxy_groups: Vec<ProxyGroup>,
    pub connections: Vec<RuntimeConnection>,
}

impl Default for FakeRuntimeOptions {
    fn default() -> Self {
        Self {
            version: RuntimeVersion::from_trusted("fake-network-runtime-v0"),
            capabilities: RuntimeCapabilities::new([
                RuntimeCapability::ConfigValidation,
                RuntimeCapability::ProcessLifecycle,
                RuntimeCapability::Health,
                RuntimeCapability::ConfigReload,
                RuntimeCapability::Version,
                RuntimeCapability::DirectEgress,
                RuntimeCapability::DirectEgressProbe,
                RuntimeCapability::ProxyGroups,
                RuntimeCapability::ConnectionListing,
                RuntimeCapability::RuntimeStatus,
            ]),
            proxy_groups: Vec::new(),
            connections: Vec::new(),
        }
    }
}

/// Shared deterministic NetworkRuntime implementation for host tests.
#[derive(Clone)]
pub struct FakeNetworkRuntime {
    inner: Arc<Mutex<FakeState>>,
}

struct FakeState {
    version: RuntimeVersion,
    capabilities: RuntimeCapabilities,
    proxy_groups: Vec<ProxyGroup>,
    connections: Vec<RuntimeConnection>,
    runtime_state: RuntimeState,
    active_config: Option<String>,
    records: Vec<RuntimeOperationRecord>,
    failures: VecDeque<InjectedFailure>,
    next_sequence: u64,
}

struct InjectedFailure {
    operation: RuntimeOperation,
    error: RuntimeError,
}

impl FakeNetworkRuntime {
    #[must_use]
    pub fn new(options: FakeRuntimeOptions) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeState {
                version: options.version,
                capabilities: options.capabilities,
                proxy_groups: options.proxy_groups,
                connections: options.connections,
                runtime_state: RuntimeState::Stopped { generation: 0 },
                active_config: None,
                records: Vec::new(),
                failures: VecDeque::new(),
                next_sequence: 0,
            })),
        }
    }

    /// Queues a one-shot failure for the next matching operation.
    pub fn inject_failure(
        &self,
        operation: RuntimeOperation,
        error: RuntimeError,
    ) -> RuntimeResult<()> {
        if error.operation() != operation {
            return Err(RuntimeError::InvalidInput {
                operation,
                field: "injected_failure",
                reason: "error operation does not match the injection point",
            });
        }
        let mut state = self.lock(operation)?;
        state
            .failures
            .push_back(InjectedFailure { operation, error });
        Ok(())
    }

    /// Simulates an external process exit without calling a host-facing operation.
    pub fn simulate_exit(&self, exit_code: Option<i32>) -> RuntimeResult<()> {
        let mut state = self.lock(RuntimeOperation::State)?;
        let generation = state.runtime_state.generation();
        if state.runtime_state.phase() != RuntimePhase::Running {
            return Err(RuntimeError::InvalidState {
                operation: RuntimeOperation::State,
                actual: state.runtime_state.phase(),
                required: RuntimePhase::Running,
            });
        }
        state.runtime_state = RuntimeState::Crashed {
            generation,
            exit_code,
        };
        Ok(())
    }

    pub fn operation_records(&self) -> RuntimeResult<Vec<RuntimeOperationRecord>> {
        Ok(self.lock(RuntimeOperation::Status)?.records.clone())
    }

    fn lock(&self, operation: RuntimeOperation) -> RuntimeResult<MutexGuard<'_, FakeState>> {
        self.inner
            .lock()
            .map_err(|_| RuntimeError::InternalState { operation })
    }

    fn begin_operation<'a>(
        &'a self,
        operation: RuntimeOperation,
        detail: OperationDetail,
    ) -> RuntimeResult<MutexGuard<'a, FakeState>> {
        let mut state = self.lock(operation)?;
        let sequence = state.next_sequence;
        state.next_sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or(RuntimeError::InternalState { operation })?;
        state.records.push(RuntimeOperationRecord {
            sequence,
            operation,
            detail,
        });
        if let Some(index) = state
            .failures
            .iter()
            .position(|failure| failure.operation == operation)
        {
            let failure = state
                .failures
                .remove(index)
                .ok_or(RuntimeError::InternalState { operation })?;
            return Err(failure.error);
        }
        Ok(state)
    }

    fn require_capability(
        state: &FakeState,
        operation: RuntimeOperation,
        capability: RuntimeCapability,
    ) -> RuntimeResult<()> {
        if state.capabilities.supports(capability) {
            Ok(())
        } else {
            Err(RuntimeError::Unsupported {
                operation,
                capability,
            })
        }
    }

    fn require_running(state: &FakeState, operation: RuntimeOperation) -> RuntimeResult<()> {
        if state.runtime_state.phase() == RuntimePhase::Running {
            Ok(())
        } else {
            Err(RuntimeError::InvalidState {
                operation,
                actual: state.runtime_state.phase(),
                required: RuntimePhase::Running,
            })
        }
    }
}

impl Default for FakeNetworkRuntime {
    fn default() -> Self {
        Self::new(FakeRuntimeOptions::default())
    }
}

impl RuntimeConfigValidator for FakeNetworkRuntime {
    fn validate(&self, _canonical_runtime_json: &str) -> Result<(), RuntimeValidationFailure> {
        match self.begin_operation(RuntimeOperation::ValidateConfig, OperationDetail::None) {
            Ok(state) => Self::require_capability(
                &state,
                RuntimeOperation::ValidateConfig,
                RuntimeCapability::ConfigValidation,
            )
            .map_err(|_| RuntimeValidationFailure::Unavailable),
            Err(RuntimeError::ValidationRejected) => Err(RuntimeValidationFailure::Rejected),
            Err(_) => Err(RuntimeValidationFailure::Unavailable),
        }
    }
}

impl NetworkRuntime for FakeNetworkRuntime {
    fn validate_config(&self, _config: &CompiledConfig) -> RuntimeResult<()> {
        let state =
            self.begin_operation(RuntimeOperation::ValidateConfig, OperationDetail::None)?;
        Self::require_capability(
            &state,
            RuntimeOperation::ValidateConfig,
            RuntimeCapability::ConfigValidation,
        )
    }

    fn start(&self, config: &CompiledConfig) -> RuntimeResult<RuntimeState> {
        let mut state = self.begin_operation(RuntimeOperation::Start, OperationDetail::None)?;
        Self::require_capability(
            &state,
            RuntimeOperation::Start,
            RuntimeCapability::ProcessLifecycle,
        )?;
        if state.runtime_state.phase() == RuntimePhase::Running {
            if state.active_config.as_deref() == Some(config.runtime_json()) {
                return Ok(state.runtime_state.clone());
            }
            return Err(RuntimeError::InvalidState {
                operation: RuntimeOperation::Start,
                actual: RuntimePhase::Running,
                required: RuntimePhase::Stopped,
            });
        }
        let generation =
            state
                .runtime_state
                .generation()
                .checked_add(1)
                .ok_or(RuntimeError::InternalState {
                    operation: RuntimeOperation::Start,
                })?;
        state.active_config = Some(config.runtime_json().to_owned());
        state.runtime_state = RuntimeState::Running {
            generation,
            process_id: None,
        };
        Ok(state.runtime_state.clone())
    }

    fn stop(&self) -> RuntimeResult<RuntimeState> {
        let mut state = self.begin_operation(RuntimeOperation::Stop, OperationDetail::None)?;
        Self::require_capability(
            &state,
            RuntimeOperation::Stop,
            RuntimeCapability::ProcessLifecycle,
        )?;
        let generation = state.runtime_state.generation();
        state.active_config = None;
        state.runtime_state = RuntimeState::Stopped { generation };
        Ok(state.runtime_state.clone())
    }

    fn health(&self) -> RuntimeResult<RuntimeHealth> {
        let state = self.begin_operation(RuntimeOperation::Health, OperationDetail::None)?;
        Self::require_capability(&state, RuntimeOperation::Health, RuntimeCapability::Health)?;
        Ok(health_for_state(&state.runtime_state))
    }

    fn state(&self) -> RuntimeResult<RuntimeState> {
        let state = self.begin_operation(RuntimeOperation::State, OperationDetail::None)?;
        Ok(state.runtime_state.clone())
    }

    fn apply_config(&self, config: &CompiledConfig) -> RuntimeResult<ApplyOutcome> {
        let mut state =
            self.begin_operation(RuntimeOperation::ApplyConfig, OperationDetail::None)?;
        Self::require_capability(
            &state,
            RuntimeOperation::ApplyConfig,
            RuntimeCapability::ConfigReload,
        )?;
        Self::require_running(&state, RuntimeOperation::ApplyConfig)?;
        let generation =
            state
                .runtime_state
                .generation()
                .checked_add(1)
                .ok_or(RuntimeError::InternalState {
                    operation: RuntimeOperation::ApplyConfig,
                })?;
        state.active_config = Some(config.runtime_json().to_owned());
        state.runtime_state = RuntimeState::Running {
            generation,
            process_id: None,
        };
        Ok(ApplyOutcome { generation })
    }

    fn version(&self) -> RuntimeResult<RuntimeVersion> {
        let state = self.begin_operation(RuntimeOperation::Version, OperationDetail::None)?;
        Self::require_capability(
            &state,
            RuntimeOperation::Version,
            RuntimeCapability::Version,
        )?;
        Ok(state.version.clone())
    }

    fn capabilities(&self) -> RuntimeResult<RuntimeCapabilities> {
        let state = self.begin_operation(RuntimeOperation::Capabilities, OperationDetail::None)?;
        Ok(state.capabilities.clone())
    }

    fn proxy_groups(&self) -> RuntimeResult<Vec<ProxyGroup>> {
        let state = self.begin_operation(RuntimeOperation::ProxyGroups, OperationDetail::None)?;
        Self::require_capability(
            &state,
            RuntimeOperation::ProxyGroups,
            RuntimeCapability::ProxyGroups,
        )?;
        Self::require_running(&state, RuntimeOperation::ProxyGroups)?;
        Ok(state.proxy_groups.clone())
    }

    fn select_proxy(&self, group: &ProxyGroupId, proxy: &ProxyId) -> RuntimeResult<ProxyGroup> {
        let mut state = self.begin_operation(
            RuntimeOperation::SelectProxy,
            OperationDetail::ProxySelection {
                group: group.clone(),
                proxy: proxy.clone(),
            },
        )?;
        Self::require_capability(
            &state,
            RuntimeOperation::SelectProxy,
            RuntimeCapability::ProxyGroups,
        )?;
        Self::require_running(&state, RuntimeOperation::SelectProxy)?;
        let selected_group = state
            .proxy_groups
            .iter_mut()
            .find(|candidate| candidate.id() == group)
            .ok_or(RuntimeError::NotFound {
                operation: RuntimeOperation::SelectProxy,
                resource: crate::RuntimeResource::ProxyGroup,
            })?;
        if !selected_group.proxies().contains(proxy) {
            return Err(RuntimeError::NotFound {
                operation: RuntimeOperation::SelectProxy,
                resource: crate::RuntimeResource::Proxy,
            });
        }
        selected_group.select(proxy.clone());
        Ok(selected_group.clone())
    }

    fn connections(&self) -> RuntimeResult<Vec<RuntimeConnection>> {
        let state = self.begin_operation(RuntimeOperation::Connections, OperationDetail::None)?;
        Self::require_capability(
            &state,
            RuntimeOperation::Connections,
            RuntimeCapability::ConnectionListing,
        )?;
        Self::require_running(&state, RuntimeOperation::Connections)?;
        Ok(state.connections.clone())
    }

    fn status(&self) -> RuntimeResult<RuntimeStatus> {
        let state = self.begin_operation(RuntimeOperation::Status, OperationDetail::None)?;
        Self::require_capability(
            &state,
            RuntimeOperation::Status,
            RuntimeCapability::RuntimeStatus,
        )?;
        let detailed = state.runtime_state.phase() == RuntimePhase::Running
            && state
                .capabilities
                .supports(RuntimeCapability::ConnectionListing);
        let (active_connections, uploaded_bytes, downloaded_bytes) = if detailed {
            let uploaded = state
                .connections
                .iter()
                .try_fold(0u64, |total, connection| {
                    total.checked_add(connection.uploaded_bytes)
                });
            let downloaded = state
                .connections
                .iter()
                .try_fold(0u64, |total, connection| {
                    total.checked_add(connection.downloaded_bytes)
                });
            (
                Some(u64::try_from(state.connections.len()).map_err(|_| {
                    RuntimeError::InternalState {
                        operation: RuntimeOperation::Status,
                    }
                })?),
                Some(uploaded.ok_or(RuntimeError::InternalState {
                    operation: RuntimeOperation::Status,
                })?),
                Some(downloaded.ok_or(RuntimeError::InternalState {
                    operation: RuntimeOperation::Status,
                })?),
            )
        } else {
            (None, None, None)
        };
        Ok(RuntimeStatus {
            state: state.runtime_state.clone(),
            health: health_for_state(&state.runtime_state),
            active_connections,
            uploaded_bytes,
            downloaded_bytes,
        })
    }

    fn probe_direct_egress(&self) -> RuntimeResult<DirectEgressStatus> {
        let state =
            self.begin_operation(RuntimeOperation::ProbeDirectEgress, OperationDetail::None)?;
        Self::require_capability(
            &state,
            RuntimeOperation::ProbeDirectEgress,
            RuntimeCapability::DirectEgressProbe,
        )?;
        Self::require_capability(
            &state,
            RuntimeOperation::ProbeDirectEgress,
            RuntimeCapability::DirectEgress,
        )?;
        Self::require_running(&state, RuntimeOperation::ProbeDirectEgress)?;
        Ok(DirectEgressStatus::Ready)
    }
}

fn health_for_state(state: &RuntimeState) -> RuntimeHealth {
    match state {
        RuntimeState::Stopped { .. } => RuntimeHealth::Inactive,
        RuntimeState::Running { .. } => RuntimeHealth::Healthy,
        RuntimeState::Crashed { exit_code, .. } => RuntimeHealth::Unhealthy {
            exit_code: *exit_code,
        },
    }
}
