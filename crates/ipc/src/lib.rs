//! Versioned data transfer types for the local desktop-to-supervisor boundary.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Stable command identifier used by the renderer wrapper and the Tauri host.
pub const GET_APP_STATUS_COMMAND: &str = "get_app_status";

/// Lifecycle state of the non-renderer supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub enum SupervisorLifecycle {
    /// The supervisor is running but no networking session has been started.
    Idle,
}

/// Availability of a subsystem at the current foundation milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub enum SubsystemAvailability {
    /// The subsystem has not yet been wired into the supervisor.
    NotConfigured,
}

/// Read-only status returned across the local IPC boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    pub supervisor: SupervisorLifecycle,
    pub network_runtime: SubsystemAvailability,
    pub capture_core: SubsystemAvailability,
    pub analyzer_runtime: SubsystemAvailability,
}

/// Produces the checked-in renderer binding from the Rust DTO definitions.
#[must_use]
pub fn typescript_bindings() -> String {
    let config = ts_rs::Config::default();

    format!(
        r#"// Generated from flowprobe-ipc. Run the Rust binding test after changing IPC DTOs.
import {{ invoke }} from "@tauri-apps/api/core";

export {supervisor}

export {availability}

export {status}

export const GET_APP_STATUS_COMMAND = "{command}" as const;

export function getAppStatus(): Promise<AppStatus> {{
  return invoke<AppStatus>(GET_APP_STATUS_COMMAND);
}}
"#,
        supervisor = SupervisorLifecycle::decl(&config),
        availability = SubsystemAvailability::decl(&config),
        status = AppStatus::decl(&config),
        command = GET_APP_STATUS_COMMAND,
    )
}

#[cfg(test)]
mod tests {
    use super::{AppStatus, SubsystemAvailability, SupervisorLifecycle, typescript_bindings};

    #[test]
    fn status_serializes_with_renderer_field_names() {
        let status = AppStatus {
            supervisor: SupervisorLifecycle::Idle,
            network_runtime: SubsystemAvailability::NotConfigured,
            capture_core: SubsystemAvailability::NotConfigured,
            analyzer_runtime: SubsystemAvailability::NotConfigured,
        };

        let value = serde_json::to_value(status).expect("status should serialize");

        assert_eq!(value["supervisor"], "idle");
        assert_eq!(value["networkRuntime"], "notConfigured");
        assert_eq!(value["captureCore"], "notConfigured");
        assert_eq!(value["analyzerRuntime"], "notConfigured");
    }

    #[test]
    fn checked_in_typescript_binding_matches_rust_contract() {
        let checked_in = include_str!("../../../apps/desktop/src/ipc/generated.ts");

        assert_eq!(typescript_bindings(), checked_in);
    }
}
