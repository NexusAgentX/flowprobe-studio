//! Capability-oriented execution of Analyzer v0.1 WebAssembly components.
//!
//! Components are linked only to the exact versioned Analyzer host interface.
//! No WASI linker is installed, so filesystem, network, clocks, randomness,
//! environment variables, and process APIs are unavailable unless a future
//! contract explicitly adds them. Each invocation receives a fresh store with
//! deterministic fuel and explicit memory, table, host-call, output, and log
//! limits.

use std::{error::Error, fmt};

use serde_json::Value;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, ResourceLimiter, Store, Trap};

mod bindings {
    wasmtime::component::bindgen!({
        path: "../../docs/contracts",
        world: "analyzer",
        imports: { default: trappable },
    });
}

pub use bindings::flowprobe::analyzer::types::{AnalyzerInfo, EventRef, SemanticEvent};

const HOST_IMPORT_V0_1: &str = "flowprobe:analyzer/host@0.1.0";
const HOST_IMPORT_PREFIX: &str = "flowprobe:analyzer/host@";
const TYPES_IMPORT_V0_1: &str = "flowprobe:analyzer/types@0.1.0";
const TYPES_IMPORT_PREFIX: &str = "flowprobe:analyzer/types@";
const WASM_PAGE_BYTES: usize = 65_536;

/// Stable contract identifier implemented by this runtime.
pub const ANALYZER_CONTRACT: &str = "flowprobe:analyzer@0.1.0";

/// Per-component and per-invocation resource limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerLimits {
    pub max_component_bytes: usize,
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
    pub max_instances: usize,
    pub max_tables: usize,
    pub max_memories: usize,
    pub fuel_per_invocation: u64,
    pub max_event_id_bytes: usize,
    pub max_event_kind_bytes: usize,
    pub max_event_json_bytes: usize,
    pub max_event_reads: usize,
    pub max_analyzer_id_bytes: usize,
    pub max_analyzer_version_bytes: usize,
    pub max_semantic_field_bytes: usize,
    pub max_semantic_attributes_bytes: usize,
    pub max_semantic_events: usize,
    pub max_total_semantic_bytes: usize,
    pub max_log_level_bytes: usize,
    pub max_log_message_bytes: usize,
    pub max_log_entries: usize,
    pub max_total_log_bytes: usize,
}

impl Default for AnalyzerLimits {
    fn default() -> Self {
        Self {
            max_component_bytes: 4 * 1024 * 1024,
            max_memory_bytes: 16 * 1024 * 1024,
            max_table_elements: 4_096,
            max_instances: 16,
            max_tables: 16,
            max_memories: 8,
            fuel_per_invocation: 5_000_000,
            max_event_id_bytes: 1_024,
            max_event_kind_bytes: 128,
            max_event_json_bytes: 512 * 1024,
            max_event_reads: 4,
            max_analyzer_id_bytes: 128,
            max_analyzer_version_bytes: 64,
            max_semantic_field_bytes: 256,
            max_semantic_attributes_bytes: 256 * 1024,
            max_semantic_events: 256,
            max_total_semantic_bytes: 512 * 1024,
            max_log_level_bytes: 16,
            max_log_message_bytes: 4 * 1024,
            max_log_entries: 128,
            max_total_log_bytes: 64 * 1024,
        }
    }
}

impl AnalyzerLimits {
    fn validate(&self) -> Result<(), AnalyzerError> {
        let nonzero = [
            ("max_component_bytes", self.max_component_bytes),
            ("max_memory_bytes", self.max_memory_bytes),
            ("max_table_elements", self.max_table_elements),
            ("max_instances", self.max_instances),
            ("max_tables", self.max_tables),
            ("max_memories", self.max_memories),
            ("max_event_id_bytes", self.max_event_id_bytes),
            ("max_event_kind_bytes", self.max_event_kind_bytes),
            ("max_event_json_bytes", self.max_event_json_bytes),
            ("max_event_reads", self.max_event_reads),
            ("max_analyzer_id_bytes", self.max_analyzer_id_bytes),
            (
                "max_analyzer_version_bytes",
                self.max_analyzer_version_bytes,
            ),
            ("max_semantic_field_bytes", self.max_semantic_field_bytes),
            (
                "max_semantic_attributes_bytes",
                self.max_semantic_attributes_bytes,
            ),
            ("max_semantic_events", self.max_semantic_events),
            ("max_total_semantic_bytes", self.max_total_semantic_bytes),
            ("max_log_level_bytes", self.max_log_level_bytes),
            ("max_log_message_bytes", self.max_log_message_bytes),
            ("max_log_entries", self.max_log_entries),
            ("max_total_log_bytes", self.max_total_log_bytes),
        ];
        if let Some((field, _)) = nonzero.into_iter().find(|(_, value)| *value == 0) {
            return Err(AnalyzerError::InvalidLimits { field });
        }
        if self.fuel_per_invocation == 0 {
            return Err(AnalyzerError::InvalidLimits {
                field: "fuel_per_invocation",
            });
        }
        if self.max_memory_bytes < WASM_PAGE_BYTES {
            return Err(AnalyzerError::InvalidLimits {
                field: "max_memory_bytes",
            });
        }
        Ok(())
    }
}

/// Stable, non-sensitive host capability failure exposed to a guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostErrorCode {
    NotFound,
    PermissionDenied,
    Unavailable,
    Rejected,
}

impl HostErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::PermissionDenied => "permission-denied",
            Self::Unavailable => "unavailable",
            Self::Rejected => "rejected",
        }
    }
}

/// One bounded log request from an analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerLogEntry {
    pub level: String,
    pub message: String,
}

/// Host capabilities granted to one compiled analyzer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnalyzerPermissions {
    read_current_event: bool,
    emit_semantic: bool,
    write_log: bool,
}

impl AnalyzerPermissions {
    pub const NONE: Self = Self::new(false, false, false);

    #[must_use]
    pub const fn new(read_current_event: bool, emit_semantic: bool, write_log: bool) -> Self {
        Self {
            read_current_event,
            emit_semantic,
            write_log,
        }
    }

    #[must_use]
    pub const fn all() -> Self {
        Self::new(true, true, true)
    }

    #[must_use]
    pub const fn can_read_current_event(self) -> bool {
        self.read_current_event
    }

    #[must_use]
    pub const fn can_emit_semantic(self) -> bool {
        self.emit_semantic
    }

    #[must_use]
    pub const fn can_write_log(self) -> bool {
        self.write_log
    }
}

/// Explicit Analyzer v0.1 host capabilities.
///
/// Implementations may query host-owned storage, but analyzers never receive a
/// database connection, path, or general filesystem capability.
/// Persistence adapters should stage semantic events and commit them only after
/// [`AnalyzerRuntime::analyze`] succeeds so a later guest trap cannot leave a
/// partial derived-data run. Analyzer log messages are untrusted captured-data
/// adjacent input and must not be forwarded to ordinary application logs
/// without the host's redaction policy.
pub trait AnalyzerHost: Send {
    fn get_event_json(&mut self, event: &EventRef) -> Result<String, HostErrorCode>;
    fn emit_semantic(&mut self, event: &SemanticEvent) -> Result<(), HostErrorCode>;
    fn log(&mut self, entry: AnalyzerLogEntry) -> Result<(), HostErrorCode>;
}

/// A component that passed size, import-capability, and WIT shape validation.
pub struct CompiledAnalyzer {
    pre: bindings::AnalyzerPre<StoreState>,
    permissions: AnalyzerPermissions,
}

impl fmt::Debug for CompiledAnalyzer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompiledAnalyzer { contract: ")?;
        formatter.write_str(ANALYZER_CONTRACT)?;
        formatter.write_str(", permissions: ")?;
        self.permissions.fmt(formatter)?;
        formatter.write_str(" }")
    }
}

/// Successful invocation metadata. Semantic outputs are delivered only through
/// [`AnalyzerHost::emit_semantic`].
#[derive(Debug, Clone)]
pub struct AnalyzerOutcome {
    pub analyzer: AnalyzerInfo,
    pub fuel_consumed: u64,
    pub event_reads: usize,
    pub semantic_events: usize,
    pub semantic_bytes: usize,
    pub log_entries: usize,
    pub log_bytes: usize,
}

/// Typed failures that never embed raw traffic, plugin logs, or engine details.
#[derive(Clone, PartialEq, Eq)]
pub enum AnalyzerError {
    InvalidLimits { field: &'static str },
    ComponentTooLarge { max_bytes: usize },
    InvalidComponent,
    AmbientCapabilityDenied,
    UnsupportedContractVersion,
    ContractMismatch,
    WrongRuntime,
    InvalidEventRef { field: &'static str },
    InvalidAnalyzerInfo { field: &'static str },
    MetadataCapabilityDenied,
    InstantiationFailed,
    FuelExhausted,
    MemoryLimitExceeded,
    TableLimitExceeded,
    UnauthorizedEventReference,
    EventReadLimitExceeded,
    EventJsonTooLarge,
    InvalidEventJson,
    SemanticOutputLimitExceeded,
    InvalidSemanticEvent { field: &'static str },
    LogLimitExceeded,
    HostCapabilityFailed(HostErrorCode),
    GuestRejected,
    GuestTrap,
}

impl fmt::Debug for AnalyzerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for AnalyzerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits { field } => write!(formatter, "invalid analyzer limit {field}"),
            Self::ComponentTooLarge { max_bytes } => {
                write!(formatter, "analyzer component exceeds {max_bytes} bytes")
            }
            Self::InvalidComponent => formatter.write_str("invalid WebAssembly component"),
            Self::AmbientCapabilityDenied => {
                formatter.write_str("analyzer requested a forbidden ambient capability")
            }
            Self::UnsupportedContractVersion => {
                formatter.write_str("analyzer uses an unsupported contract version")
            }
            Self::ContractMismatch => formatter.write_str("analyzer WIT contract mismatch"),
            Self::WrongRuntime => {
                formatter.write_str("compiled analyzer belongs to a different runtime")
            }
            Self::InvalidEventRef { field } => write!(formatter, "invalid event reference {field}"),
            Self::InvalidAnalyzerInfo { field } => {
                write!(formatter, "invalid analyzer metadata {field}")
            }
            Self::MetadataCapabilityDenied => {
                formatter.write_str("analyzer metadata function requested a host capability")
            }
            Self::InstantiationFailed => formatter.write_str("analyzer instantiation failed"),
            Self::FuelExhausted => formatter.write_str("analyzer fuel limit exceeded"),
            Self::MemoryLimitExceeded => formatter.write_str("analyzer memory limit exceeded"),
            Self::TableLimitExceeded => formatter.write_str("analyzer table limit exceeded"),
            Self::UnauthorizedEventReference => {
                formatter.write_str("analyzer requested an unauthorized event")
            }
            Self::EventReadLimitExceeded => {
                formatter.write_str("analyzer event-read limit exceeded")
            }
            Self::EventJsonTooLarge => formatter.write_str("host event JSON limit exceeded"),
            Self::InvalidEventJson => formatter.write_str("host returned invalid event JSON"),
            Self::SemanticOutputLimitExceeded => {
                formatter.write_str("analyzer semantic-output limit exceeded")
            }
            Self::InvalidSemanticEvent { field } => {
                write!(formatter, "invalid semantic event {field}")
            }
            Self::LogLimitExceeded => formatter.write_str("analyzer log limit exceeded"),
            Self::HostCapabilityFailed(code) => {
                write!(
                    formatter,
                    "analyzer host capability failed: {}",
                    code.as_str()
                )
            }
            Self::GuestRejected => formatter.write_str("analyzer rejected the event"),
            Self::GuestTrap => formatter.write_str("analyzer trapped"),
        }
    }
}

impl Error for AnalyzerError {}

/// Wasmtime engine configured for deterministic Analyzer v0.1 execution.
pub struct AnalyzerRuntime {
    engine: Engine,
    limits: AnalyzerLimits,
}

impl fmt::Debug for AnalyzerRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnalyzerRuntime")
            .field("contract", &ANALYZER_CONTRACT)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl AnalyzerRuntime {
    pub fn new(limits: AnalyzerLimits) -> Result<Self, AnalyzerError> {
        limits.validate()?;
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.cranelift_nan_canonicalization(true);
        let engine = Engine::new(&config).map_err(|_| AnalyzerError::InvalidLimits {
            field: "engine_configuration",
        })?;
        Ok(Self { engine, limits })
    }

    #[must_use]
    pub fn limits(&self) -> &AnalyzerLimits {
        &self.limits
    }

    pub fn compile(
        &self,
        bytes: &[u8],
        permissions: AnalyzerPermissions,
    ) -> Result<CompiledAnalyzer, AnalyzerError> {
        if bytes.len() > self.limits.max_component_bytes {
            return Err(AnalyzerError::ComponentTooLarge {
                max_bytes: self.limits.max_component_bytes,
            });
        }
        let component =
            Component::new(&self.engine, bytes).map_err(|_| AnalyzerError::InvalidComponent)?;
        for (import, _) in component.component_type().imports(&self.engine) {
            if import == HOST_IMPORT_V0_1 || import == TYPES_IMPORT_V0_1 {
                continue;
            }
            if import.starts_with(HOST_IMPORT_PREFIX) || import.starts_with(TYPES_IMPORT_PREFIX) {
                return Err(AnalyzerError::UnsupportedContractVersion);
            }
            return Err(AnalyzerError::AmbientCapabilityDenied);
        }

        let mut linker = Linker::<StoreState>::new(&self.engine);
        bindings::Analyzer::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(|_| AnalyzerError::ContractMismatch)?;
        let instance_pre = linker
            .instantiate_pre(&component)
            .map_err(|_| AnalyzerError::ContractMismatch)?;
        let pre = bindings::AnalyzerPre::new(instance_pre)
            .map_err(|_| AnalyzerError::ContractMismatch)?;
        Ok(CompiledAnalyzer { pre, permissions })
    }

    pub fn analyze(
        &self,
        analyzer: &CompiledAnalyzer,
        event: EventRef,
        host: impl AnalyzerHost + 'static,
    ) -> Result<AnalyzerOutcome, AnalyzerError> {
        if !Engine::same(&self.engine, analyzer.pre.engine()) {
            return Err(AnalyzerError::WrongRuntime);
        }
        validate_event_ref(&event, &self.limits)?;

        let state = StoreState::new(
            Box::new(host),
            event.clone(),
            analyzer.permissions,
            self.limits.clone(),
        );
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limiter);
        store
            .set_fuel(self.limits.fuel_per_invocation)
            .map_err(|_| AnalyzerError::InvalidLimits {
                field: "fuel_per_invocation",
            })?;

        let instance = analyzer
            .pre
            .instantiate(&mut store)
            .map_err(|error| classify_runtime_error(&error, true))?;
        let info = instance
            .call_info(&mut store)
            .map_err(|error| classify_runtime_error(&error, false))?;
        validate_analyzer_info(&info, &self.limits)?;
        store.data_mut().phase = ExecutionPhase::Analyze;
        match instance.call_analyze(&mut store, &event) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(AnalyzerError::GuestRejected),
            Err(error) => return Err(classify_runtime_error(&error, false)),
        }

        let remaining_fuel = store.get_fuel().unwrap_or(0);
        let fuel_consumed = self
            .limits
            .fuel_per_invocation
            .saturating_sub(remaining_fuel);
        let state = store.into_data();
        Ok(AnalyzerOutcome {
            analyzer: info,
            fuel_consumed,
            event_reads: state.event_reads,
            semantic_events: state.semantic_events,
            semantic_bytes: state.semantic_bytes,
            log_entries: state.log_entries,
            log_bytes: state.log_bytes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SandboxTrap {
    MetadataCapability,
    MemoryLimit,
    TableLimit,
    UnauthorizedEvent,
    EventReadLimit,
    EventJsonLimit,
    InvalidEventJson,
    SemanticOutputLimit,
    InvalidSemantic(&'static str),
    LogLimit,
    HostCapability(HostErrorCode),
}

impl fmt::Display for SandboxTrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("analyzer sandbox policy violation")
    }
}

impl Error for SandboxTrap {}

struct SandboxLimiter {
    max_memory_bytes: usize,
    max_table_elements: usize,
    max_instances: usize,
    max_tables: usize,
    max_memories: usize,
}

impl SandboxLimiter {
    fn new(limits: &AnalyzerLimits) -> Self {
        Self {
            max_memory_bytes: limits.max_memory_bytes,
            max_table_elements: limits.max_table_elements,
            max_instances: limits.max_instances,
            max_tables: limits.max_tables,
            max_memories: limits.max_memories,
        }
    }
}

impl ResourceLimiter for SandboxLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_memory_bytes {
            Err(wasmtime::Error::new(SandboxTrap::MemoryLimit))
        } else {
            Ok(true)
        }
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_table_elements {
            Err(wasmtime::Error::new(SandboxTrap::TableLimit))
        } else {
            Ok(true)
        }
    }

    fn instances(&self) -> usize {
        self.max_instances
    }

    fn tables(&self) -> usize {
        self.max_tables
    }

    fn memories(&self) -> usize {
        self.max_memories
    }
}

struct StoreState {
    host: Box<dyn AnalyzerHost>,
    authorized_event: EventRef,
    permissions: AnalyzerPermissions,
    phase: ExecutionPhase,
    limits: AnalyzerLimits,
    limiter: SandboxLimiter,
    event_reads: usize,
    semantic_events: usize,
    semantic_bytes: usize,
    log_entries: usize,
    log_bytes: usize,
}

impl StoreState {
    fn new(
        host: Box<dyn AnalyzerHost>,
        authorized_event: EventRef,
        permissions: AnalyzerPermissions,
        limits: AnalyzerLimits,
    ) -> Self {
        let limiter = SandboxLimiter::new(&limits);
        Self {
            host,
            authorized_event,
            permissions,
            phase: ExecutionPhase::Metadata,
            limits,
            limiter,
            event_reads: 0,
            semantic_events: 0,
            semantic_bytes: 0,
            log_entries: 0,
            log_bytes: 0,
        }
    }

    fn add_semantic_bytes(&mut self, bytes: usize) -> Result<(), SandboxTrap> {
        let total = self
            .semantic_bytes
            .checked_add(bytes)
            .ok_or(SandboxTrap::SemanticOutputLimit)?;
        if total > self.limits.max_total_semantic_bytes {
            return Err(SandboxTrap::SemanticOutputLimit);
        }
        self.semantic_bytes = total;
        Ok(())
    }

    fn add_log_bytes(&mut self, bytes: usize) -> Result<(), SandboxTrap> {
        let total = self
            .log_bytes
            .checked_add(bytes)
            .ok_or(SandboxTrap::LogLimit)?;
        if total > self.limits.max_total_log_bytes {
            return Err(SandboxTrap::LogLimit);
        }
        self.log_bytes = total;
        Ok(())
    }
}

impl bindings::flowprobe::analyzer::types::Host for StoreState {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionPhase {
    Metadata,
    Analyze,
}

impl bindings::flowprobe::analyzer::host::Host for StoreState {
    fn get_event_json(&mut self, event: EventRef) -> wasmtime::Result<Result<String, String>> {
        if self.phase != ExecutionPhase::Analyze {
            return Err(wasmtime::Error::new(SandboxTrap::MetadataCapability));
        }
        if !self.permissions.can_read_current_event() {
            return Ok(Err(HostErrorCode::PermissionDenied.as_str().to_owned()));
        }
        if event.id != self.authorized_event.id || event.kind != self.authorized_event.kind {
            return Err(wasmtime::Error::new(SandboxTrap::UnauthorizedEvent));
        }
        self.event_reads = self
            .event_reads
            .checked_add(1)
            .ok_or_else(|| wasmtime::Error::new(SandboxTrap::EventReadLimit))?;
        if self.event_reads > self.limits.max_event_reads {
            return Err(wasmtime::Error::new(SandboxTrap::EventReadLimit));
        }

        let json = match self.host.get_event_json(&event) {
            Ok(json) => json,
            Err(code) => return Ok(Err(code.as_str().to_owned())),
        };
        if json.len() > self.limits.max_event_json_bytes {
            return Err(wasmtime::Error::new(SandboxTrap::EventJsonLimit));
        }
        match serde_json::from_str::<Value>(&json) {
            Ok(Value::Object(_)) => Ok(Ok(json)),
            Ok(_) | Err(_) => Err(wasmtime::Error::new(SandboxTrap::InvalidEventJson)),
        }
    }

    fn emit_semantic(&mut self, mut event: SemanticEvent) -> wasmtime::Result<Result<(), String>> {
        if self.phase != ExecutionPhase::Analyze {
            return Err(wasmtime::Error::new(SandboxTrap::MetadataCapability));
        }
        if !self.permissions.can_emit_semantic() {
            return Ok(Err(HostErrorCode::PermissionDenied.as_str().to_owned()));
        }
        self.semantic_events = self
            .semantic_events
            .checked_add(1)
            .ok_or_else(|| wasmtime::Error::new(SandboxTrap::SemanticOutputLimit))?;
        if self.semantic_events > self.limits.max_semantic_events {
            return Err(wasmtime::Error::new(SandboxTrap::SemanticOutputLimit));
        }
        validate_token(
            "namespace",
            &event.namespace,
            self.limits.max_semantic_field_bytes,
        )
        .map_err(|field| wasmtime::Error::new(SandboxTrap::InvalidSemantic(field)))?;
        validate_token("kind", &event.kind, self.limits.max_semantic_field_bytes)
            .map_err(|field| wasmtime::Error::new(SandboxTrap::InvalidSemantic(field)))?;
        if event.json_attributes.len() > self.limits.max_semantic_attributes_bytes {
            return Err(wasmtime::Error::new(SandboxTrap::SemanticOutputLimit));
        }
        let attributes: Value = serde_json::from_str(&event.json_attributes)
            .map_err(|_| wasmtime::Error::new(SandboxTrap::InvalidSemantic("json-attributes")))?;
        if !attributes.is_object() {
            return Err(wasmtime::Error::new(SandboxTrap::InvalidSemantic(
                "json-attributes",
            )));
        }
        event.json_attributes = serde_json::to_string(&attributes)
            .map_err(|_| wasmtime::Error::new(SandboxTrap::InvalidSemantic("json-attributes")))?;
        let bytes = event
            .namespace
            .len()
            .checked_add(event.kind.len())
            .and_then(|total| total.checked_add(event.json_attributes.len()))
            .ok_or_else(|| wasmtime::Error::new(SandboxTrap::SemanticOutputLimit))?;
        self.add_semantic_bytes(bytes)
            .map_err(wasmtime::Error::new)?;
        match self.host.emit_semantic(&event) {
            Ok(()) => Ok(Ok(())),
            Err(code) => Ok(Err(code.as_str().to_owned())),
        }
    }

    fn log(&mut self, level: String, message: String) -> wasmtime::Result<()> {
        if self.phase != ExecutionPhase::Analyze {
            return Err(wasmtime::Error::new(SandboxTrap::MetadataCapability));
        }
        if !self.permissions.can_write_log() {
            return Err(wasmtime::Error::new(SandboxTrap::HostCapability(
                HostErrorCode::PermissionDenied,
            )));
        }
        self.log_entries = self
            .log_entries
            .checked_add(1)
            .ok_or_else(|| wasmtime::Error::new(SandboxTrap::LogLimit))?;
        if self.log_entries > self.limits.max_log_entries
            || level.is_empty()
            || level.len() > self.limits.max_log_level_bytes
            || message.len() > self.limits.max_log_message_bytes
            || level.chars().any(char::is_control)
        {
            return Err(wasmtime::Error::new(SandboxTrap::LogLimit));
        }
        let bytes = level
            .len()
            .checked_add(message.len())
            .ok_or_else(|| wasmtime::Error::new(SandboxTrap::LogLimit))?;
        self.add_log_bytes(bytes).map_err(wasmtime::Error::new)?;
        self.host
            .log(AnalyzerLogEntry { level, message })
            .map_err(|code| wasmtime::Error::new(SandboxTrap::HostCapability(code)))
    }
}

fn validate_event_ref(event: &EventRef, limits: &AnalyzerLimits) -> Result<(), AnalyzerError> {
    validate_token("id", &event.id, limits.max_event_id_bytes)
        .map_err(|field| AnalyzerError::InvalidEventRef { field })?;
    validate_token("kind", &event.kind, limits.max_event_kind_bytes)
        .map_err(|field| AnalyzerError::InvalidEventRef { field })
}

fn validate_analyzer_info(
    info: &AnalyzerInfo,
    limits: &AnalyzerLimits,
) -> Result<(), AnalyzerError> {
    validate_token("id", &info.id, limits.max_analyzer_id_bytes)
        .map_err(|field| AnalyzerError::InvalidAnalyzerInfo { field })?;
    if info.version.is_empty()
        || info.version.len() > limits.max_analyzer_version_bytes
        || semver::Version::parse(&info.version).is_err()
    {
        return Err(AnalyzerError::InvalidAnalyzerInfo { field: "version" });
    }
    Ok(())
}

fn validate_token(field: &'static str, value: &str, max_bytes: usize) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(field)
    } else {
        Ok(())
    }
}

fn classify_runtime_error(error: &wasmtime::Error, during_instantiation: bool) -> AnalyzerError {
    if let Some(trap) = error.downcast_ref::<SandboxTrap>() {
        return match trap {
            SandboxTrap::MetadataCapability => AnalyzerError::MetadataCapabilityDenied,
            SandboxTrap::MemoryLimit => AnalyzerError::MemoryLimitExceeded,
            SandboxTrap::TableLimit => AnalyzerError::TableLimitExceeded,
            SandboxTrap::UnauthorizedEvent => AnalyzerError::UnauthorizedEventReference,
            SandboxTrap::EventReadLimit => AnalyzerError::EventReadLimitExceeded,
            SandboxTrap::EventJsonLimit => AnalyzerError::EventJsonTooLarge,
            SandboxTrap::InvalidEventJson => AnalyzerError::InvalidEventJson,
            SandboxTrap::SemanticOutputLimit => AnalyzerError::SemanticOutputLimitExceeded,
            SandboxTrap::InvalidSemantic(field) => AnalyzerError::InvalidSemanticEvent { field },
            SandboxTrap::LogLimit => AnalyzerError::LogLimitExceeded,
            SandboxTrap::HostCapability(code) => AnalyzerError::HostCapabilityFailed(*code),
        };
    }
    if error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
        return AnalyzerError::FuelExhausted;
    }
    if during_instantiation {
        AnalyzerError::InstantiationFailed
    } else {
        AnalyzerError::GuestTrap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_count_limit(component_text: &str, limits: AnalyzerLimits) -> AnalyzerError {
        let runtime = AnalyzerRuntime::new(limits.clone()).expect("valid test limits");
        let component_bytes = wat::parse_str(component_text).expect("valid component text");
        let component =
            Component::new(&runtime.engine, component_bytes).expect("valid component binary");
        let mut store = Store::new(&runtime.engine, SandboxLimiter::new(&limits));
        store.limiter(|limiter| limiter);
        let linker = Linker::new(&runtime.engine);
        let error = linker
            .instantiate(&mut store, &component)
            .expect_err("resource count must reject instantiation");
        classify_runtime_error(&error, true)
    }

    #[test]
    fn wasmtime_resource_count_limits_have_generic_stable_classification() {
        let instance_limits = AnalyzerLimits {
            max_instances: 1,
            ..AnalyzerLimits::default()
        };
        assert_eq!(
            classify_count_limit(
                "(component
                    (core module $module)
                    (core instance (instantiate $module))
                    (core instance (instantiate $module))
                )",
                instance_limits,
            ),
            AnalyzerError::InstantiationFailed
        );

        let memory_limits = AnalyzerLimits {
            max_memories: 1,
            ..AnalyzerLimits::default()
        };
        assert_eq!(
            classify_count_limit(
                "(component
                    (core module $module
                        (memory 1)
                        (memory 1)
                    )
                    (core instance (instantiate $module))
                )",
                memory_limits,
            ),
            AnalyzerError::InstantiationFailed
        );

        let table_limits = AnalyzerLimits {
            max_tables: 1,
            ..AnalyzerLimits::default()
        };
        assert_eq!(
            classify_count_limit(
                "(component
                    (core module $module
                        (table 1 funcref)
                        (table 1 funcref)
                    )
                    (core instance (instantiate $module))
                )",
                table_limits,
            ),
            AnalyzerError::InstantiationFailed
        );
    }
}
