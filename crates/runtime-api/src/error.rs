use std::{error::Error, fmt, io};

use crate::{RuntimeCapability, RuntimeOperation, RuntimePhase};

/// Stable categories for process and filesystem failures without leaking paths or output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessIoKind {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    InvalidData,
    Interrupted,
    Other,
}

impl From<io::ErrorKind> for ProcessIoKind {
    fn from(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            io::ErrorKind::InvalidData => Self::InvalidData,
            io::ErrorKind::Interrupted => Self::Interrupted,
            _ => Self::Other,
        }
    }
}

/// A resource type used by typed lookup failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeResource {
    ProxyGroup,
    Proxy,
    Connection,
}

/// Redaction-safe failure returned by a NetworkRuntime operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    Unsupported {
        operation: RuntimeOperation,
        capability: RuntimeCapability,
    },
    InvalidState {
        operation: RuntimeOperation,
        actual: RuntimePhase,
        required: RuntimePhase,
    },
    InvalidInput {
        operation: RuntimeOperation,
        field: &'static str,
        reason: &'static str,
    },
    NotFound {
        operation: RuntimeOperation,
        resource: RuntimeResource,
    },
    ValidationRejected,
    Unavailable {
        operation: RuntimeOperation,
        reason: RuntimeUnavailableReason,
    },
    TimedOut {
        operation: RuntimeOperation,
        timeout_ms: u64,
    },
    ProcessExited {
        operation: RuntimeOperation,
        exit_code: Option<i32>,
    },
    ProcessIo {
        operation: RuntimeOperation,
        kind: ProcessIoKind,
    },
    OutputLimitExceeded {
        operation: RuntimeOperation,
        limit: usize,
    },
    InvalidOutput {
        operation: RuntimeOperation,
    },
    InternalState {
        operation: RuntimeOperation,
    },
}

/// Stable reasons that a runtime/control surface is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeUnavailableReason {
    NotConfigured,
    ExecutableMissing,
    PermissionDenied,
    ControlSurfaceUnavailable,
    ProcessStateUnavailable,
    Other,
}

impl RuntimeError {
    #[must_use]
    pub const fn operation(&self) -> RuntimeOperation {
        match self {
            Self::Unsupported { operation, .. }
            | Self::InvalidState { operation, .. }
            | Self::InvalidInput { operation, .. }
            | Self::NotFound { operation, .. }
            | Self::Unavailable { operation, .. }
            | Self::TimedOut { operation, .. }
            | Self::ProcessExited { operation, .. }
            | Self::ProcessIo { operation, .. }
            | Self::OutputLimitExceeded { operation, .. }
            | Self::InvalidOutput { operation }
            | Self::InternalState { operation } => *operation,
            Self::ValidationRejected => RuntimeOperation::ValidateConfig,
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported {
                operation,
                capability,
            } => write!(
                formatter,
                "runtime operation {operation:?} is unsupported without capability {capability:?}"
            ),
            Self::InvalidState {
                operation,
                actual,
                required,
            } => write!(
                formatter,
                "runtime operation {operation:?} requires {required:?}, current state is {actual:?}"
            ),
            Self::InvalidInput {
                operation,
                field,
                reason,
            } => write!(
                formatter,
                "invalid {field} for runtime operation {operation:?}: {reason}"
            ),
            Self::NotFound {
                operation,
                resource,
            } => write!(
                formatter,
                "runtime resource {resource:?} was not found for {operation:?}"
            ),
            Self::ValidationRejected => {
                formatter.write_str("runtime rejected the generated configuration")
            }
            Self::Unavailable { operation, reason } => {
                write!(
                    formatter,
                    "runtime operation {operation:?} is unavailable: {reason:?}"
                )
            }
            Self::TimedOut {
                operation,
                timeout_ms,
            } => write!(
                formatter,
                "runtime operation {operation:?} timed out after {timeout_ms} ms"
            ),
            Self::ProcessExited {
                operation,
                exit_code,
            } => write!(
                formatter,
                "runtime process exited during {operation:?} with code {exit_code:?}"
            ),
            Self::ProcessIo { operation, kind } => write!(
                formatter,
                "runtime process I/O failed during {operation:?}: {kind:?}"
            ),
            Self::OutputLimitExceeded { operation, limit } => write!(
                formatter,
                "runtime output for {operation:?} exceeded the {limit}-byte limit"
            ),
            Self::InvalidOutput { operation } => {
                write!(
                    formatter,
                    "runtime returned invalid output for {operation:?}"
                )
            }
            Self::InternalState { operation } => {
                write!(
                    formatter,
                    "runtime internal state is unavailable for {operation:?}"
                )
            }
        }
    }
}

impl Error for RuntimeError {}

pub type RuntimeResult<T> = Result<T, RuntimeError>;
