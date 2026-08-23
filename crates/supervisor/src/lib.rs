//! Non-renderer lifecycle boundary for desktop IPC.

use flowprobe_ipc::{AppStatus, SubsystemAvailability, SupervisorLifecycle};

/// Owns process and privileged-service coordination outside the renderer.
#[derive(Debug)]
pub struct Supervisor {
    lifecycle: SupervisorLifecycle,
}

impl Supervisor {
    /// Creates an idle supervisor without claiming that any runtime is available.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lifecycle: SupervisorLifecycle::Idle,
        }
    }

    /// Reports the actual wiring state of the foundation shell.
    #[must_use]
    pub const fn status(&self) -> AppStatus {
        AppStatus {
            supervisor: self.lifecycle,
            network_runtime: SubsystemAvailability::NotConfigured,
            capture_core: SubsystemAvailability::NotConfigured,
            analyzer_runtime: SubsystemAvailability::NotConfigured,
        }
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use flowprobe_ipc::{SubsystemAvailability, SupervisorLifecycle};

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
}
