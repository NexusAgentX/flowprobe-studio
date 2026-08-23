use std::{collections::BTreeSet, error::Error, fmt};

/// One operation in the NetworkRuntime v0 boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeOperation {
    Initialize,
    ValidateConfig,
    Start,
    Stop,
    Health,
    State,
    ApplyConfig,
    Version,
    Capabilities,
    ProxyGroups,
    SelectProxy,
    Connections,
    Status,
    ProbeDirectEgress,
}

/// Independently reportable runtime capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeCapability {
    ConfigValidation,
    ProcessLifecycle,
    Health,
    ConfigReload,
    Version,
    DirectEgress,
    DirectEgressProbe,
    ProxyGroups,
    ConnectionListing,
    RuntimeStatus,
}

/// Capability set returned by a runtime implementation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeCapabilities {
    supported: BTreeSet<RuntimeCapability>,
}

impl RuntimeCapabilities {
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = RuntimeCapability>) -> Self {
        Self {
            supported: capabilities.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn supports(&self, capability: RuntimeCapability) -> bool {
        self.supported.contains(&capability)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = RuntimeCapability> + '_ {
        self.supported.iter().copied()
    }
}

/// Coarse lifecycle phase used in state errors and health reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePhase {
    Stopped,
    Running,
    Crashed,
}

/// Observable process state without exposing process handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeState {
    Stopped {
        generation: u64,
    },
    Running {
        generation: u64,
        process_id: Option<u32>,
    },
    Crashed {
        generation: u64,
        exit_code: Option<i32>,
    },
}

impl RuntimeState {
    #[must_use]
    pub const fn phase(&self) -> RuntimePhase {
        match self {
            Self::Stopped { .. } => RuntimePhase::Stopped,
            Self::Running { .. } => RuntimePhase::Running,
            Self::Crashed { .. } => RuntimePhase::Crashed,
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        match self {
            Self::Stopped { generation }
            | Self::Running { generation, .. }
            | Self::Crashed { generation, .. } => *generation,
        }
    }
}

/// Health derived from the managed process state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeHealth {
    Healthy,
    Inactive,
    Unhealthy { exit_code: Option<i32> },
}

/// Result of applying a configuration through a supported reload surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub generation: u64,
}

/// Bounded, printable runtime version text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeVersion(String);

impl RuntimeVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        validate_text("runtime version", &value, 256)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_trusted(value: &'static str) -> Self {
        Self(value.to_owned())
    }
}

/// Why a public runtime identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifierError {
    kind: &'static str,
    reason: &'static str,
}

impl IdentifierError {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}: {}", self.kind, self.reason)
    }
}

impl Error for IdentifierError {}

fn validate_text(kind: &'static str, value: &str, max_bytes: usize) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError {
            kind,
            reason: "value is empty",
        });
    }
    if value.trim() != value {
        return Err(IdentifierError {
            kind,
            reason: "value has leading or trailing whitespace",
        });
    }
    if value.len() > max_bytes {
        return Err(IdentifierError {
            kind,
            reason: "value exceeds its byte limit",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(IdentifierError {
            kind,
            reason: "value contains control characters",
        });
    }
    Ok(())
}

macro_rules! identifier {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                validate_text($kind, &value, 255)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

identifier!(ProxyGroupId, "proxy group identifier");
identifier!(ProxyId, "proxy identifier");
identifier!(RuntimeConnectionId, "runtime connection identifier");

/// One selectable proxy group exposed by a supported control surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyGroup {
    id: ProxyGroupId,
    proxies: Vec<ProxyId>,
    selected: Option<ProxyId>,
}

impl ProxyGroup {
    pub fn new(
        id: ProxyGroupId,
        proxies: Vec<ProxyId>,
        selected: Option<ProxyId>,
    ) -> Result<Self, IdentifierError> {
        if proxies.is_empty() {
            return Err(IdentifierError {
                kind: "proxy group",
                reason: "group has no proxy candidates",
            });
        }
        let unique: BTreeSet<_> = proxies.iter().collect();
        if unique.len() != proxies.len() {
            return Err(IdentifierError {
                kind: "proxy group",
                reason: "group has duplicate proxy candidates",
            });
        }
        if selected
            .as_ref()
            .is_some_and(|selected| !proxies.contains(selected))
        {
            return Err(IdentifierError {
                kind: "proxy group",
                reason: "selected proxy is not a group candidate",
            });
        }
        Ok(Self {
            id,
            proxies,
            selected,
        })
    }

    #[must_use]
    pub fn id(&self) -> &ProxyGroupId {
        &self.id
    }

    #[must_use]
    pub fn proxies(&self) -> &[ProxyId] {
        &self.proxies
    }

    #[must_use]
    pub fn selected(&self) -> Option<&ProxyId> {
        self.selected.as_ref()
    }

    pub(crate) fn select(&mut self, proxy: ProxyId) {
        self.selected = Some(proxy);
    }
}

/// Transport category for runtime connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTransport {
    Tcp,
    Udp,
    Other,
}

/// Redaction-safe connection summary from a supported runtime control surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConnection {
    pub id: RuntimeConnectionId,
    pub transport: RuntimeTransport,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
}

/// Process/status snapshot. Optional counters are absent when no supported surface exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub state: RuntimeState,
    pub health: RuntimeHealth,
    pub active_connections: Option<u64>,
    pub uploaded_bytes: Option<u64>,
    pub downloaded_bytes: Option<u64>,
}

/// Explicit result of an end-to-end direct-egress probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectEgressStatus {
    Ready,
}
