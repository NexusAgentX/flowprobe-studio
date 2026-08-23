//! Capability-oriented NetworkRuntime v0 boundary.

mod error;
mod fake;
mod types;

pub use error::{
    ProcessIoKind, RuntimeError, RuntimeResource, RuntimeResult, RuntimeUnavailableReason,
};
pub use fake::{FakeNetworkRuntime, FakeRuntimeOptions, OperationDetail, RuntimeOperationRecord};
pub use flowprobe_config_compiler::CompiledConfig;
pub use types::{
    ApplyOutcome, DirectEgressStatus, IdentifierError, ProxyGroup, ProxyGroupId, ProxyId,
    RuntimeCapabilities, RuntimeCapability, RuntimeConnection, RuntimeConnectionId, RuntimeHealth,
    RuntimeOperation, RuntimePhase, RuntimeState, RuntimeStatus, RuntimeTransport, RuntimeVersion,
};

/// Host-facing contract implemented by fake and managed process runtimes.
pub trait NetworkRuntime: Send + Sync {
    fn validate_config(&self, config: &CompiledConfig) -> RuntimeResult<()>;
    fn start(&self, config: &CompiledConfig) -> RuntimeResult<RuntimeState>;
    fn stop(&self) -> RuntimeResult<RuntimeState>;
    fn health(&self) -> RuntimeResult<RuntimeHealth>;
    fn state(&self) -> RuntimeResult<RuntimeState>;
    fn apply_config(&self, config: &CompiledConfig) -> RuntimeResult<ApplyOutcome>;
    fn version(&self) -> RuntimeResult<RuntimeVersion>;
    fn capabilities(&self) -> RuntimeResult<RuntimeCapabilities>;
    fn proxy_groups(&self) -> RuntimeResult<Vec<ProxyGroup>>;
    fn select_proxy(&self, group: &ProxyGroupId, proxy: &ProxyId) -> RuntimeResult<ProxyGroup>;
    fn connections(&self) -> RuntimeResult<Vec<RuntimeConnection>>;
    fn status(&self) -> RuntimeResult<RuntimeStatus>;
    fn probe_direct_egress(&self) -> RuntimeResult<DirectEgressStatus>;
}
