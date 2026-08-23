//! Versioned data transfer types for the local desktop-to-supervisor boundary.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Stable command identifier used by the renderer wrapper and the Tauri host.
pub const GET_APP_STATUS_COMMAND: &str = "get_app_status";
/// Queries one bounded page of normalized traffic metadata.
pub const QUERY_TRAFFIC_COMMAND: &str = "query_traffic";
/// Queries one normalized traffic metadata detail record.
pub const GET_TRAFFIC_DETAIL_COMMAND: &str = "get_traffic_detail";
/// Queries one bounded page of rebuildable semantic analyzer output.
pub const QUERY_SEMANTIC_OUTPUT_COMMAND: &str = "query_semantic_output";

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

/// Stable, renderer-actionable failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub enum IpcErrorCode {
    InvalidRequest,
    InvalidCursor,
    NotFound,
    StorageUnavailable,
    Internal,
}

/// Redacted typed IPC failure. Messages never include SQL or request values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub code: IpcErrorCode,
    pub message: String,
}

impl IpcError {
    #[must_use]
    pub fn new(code: IpcErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message: message.to_owned(),
        }
    }
}

/// Bounded Traffic index request. The cursor is opaque to the renderer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct TrafficPageRequest {
    pub page_size: u16,
    pub cursor: Option<String>,
}

/// One metadata-only row in the Traffic index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct TrafficListItem {
    pub flow_id: String,
    pub started_at_ns: String,
    pub transport_protocol: String,
    pub destination_host: Option<String>,
    pub destination_ip: Option<String>,
    pub destination_port: u16,
    pub protocols: Vec<String>,
    pub http_method: Option<String>,
    pub http_status: Option<u16>,
}

/// One bounded Traffic index page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct TrafficPage {
    pub items: Vec<TrafficListItem>,
    pub next_cursor: Option<String>,
}

/// Traffic detail identity request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct TrafficDetailRequest {
    pub flow_id: String,
}

/// Metadata-only normalized detail. Payload references stay host-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct TrafficDetail {
    pub summary: TrafficListItem,
    pub connection_id: String,
    pub capture_session_id: Option<String>,
    pub first_byte_at_ns: Option<String>,
    pub ended_at_ns: Option<String>,
    pub normalized_source_available: bool,
}

/// Bounded semantic-output request. The cursor is opaque to the renderer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct SemanticPageRequest {
    pub page_size: u16,
    pub cursor: Option<String>,
}

/// One rebuildable semantic event produced by an analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct SemanticOutputItem {
    pub event_id: String,
    pub capture_session_id: Option<String>,
    pub source_flow_id: Option<String>,
    pub analyzer_id: String,
    pub analyzer_version: String,
    pub namespace: String,
    pub kind: String,
    pub timestamp_ns: String,
}

/// One bounded semantic-output page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct SemanticOutputPage {
    pub items: Vec<SemanticOutputItem>,
    pub next_cursor: Option<String>,
}

/// Produces the checked-in renderer binding from the Rust DTO definitions.
#[must_use]
pub fn typescript_bindings() -> String {
    let config = ts_rs::Config::default();
    let declarations = [
        SupervisorLifecycle::decl(&config),
        SubsystemAvailability::decl(&config),
        AppStatus::decl(&config),
        IpcErrorCode::decl(&config),
        IpcError::decl(&config),
        TrafficPageRequest::decl(&config),
        TrafficListItem::decl(&config),
        TrafficPage::decl(&config),
        TrafficDetailRequest::decl(&config),
        TrafficDetail::decl(&config),
        SemanticPageRequest::decl(&config),
        SemanticOutputItem::decl(&config),
        SemanticOutputPage::decl(&config),
    ]
    .map(|declaration| format!("export {declaration}"))
    .join("\n\n");

    format!(
        r#"// Generated from flowprobe-ipc. Run the Rust binding test after changing IPC DTOs.
import {{ invoke }} from "@tauri-apps/api/core";

{declarations}

export const GET_APP_STATUS_COMMAND = "{status_command}" as const;
export const QUERY_TRAFFIC_COMMAND = "{traffic_command}" as const;
export const GET_TRAFFIC_DETAIL_COMMAND = "{detail_command}" as const;
export const QUERY_SEMANTIC_OUTPUT_COMMAND = "{semantic_command}" as const;

export function getAppStatus(): Promise<AppStatus> {{
  return invoke<AppStatus>(GET_APP_STATUS_COMMAND);
}}

export function queryTraffic(request: TrafficPageRequest): Promise<TrafficPage> {{
  return invoke<TrafficPage>(QUERY_TRAFFIC_COMMAND, {{ request }});
}}

export function getTrafficDetail(request: TrafficDetailRequest): Promise<TrafficDetail> {{
  return invoke<TrafficDetail>(GET_TRAFFIC_DETAIL_COMMAND, {{ request }});
}}

export function querySemanticOutput(request: SemanticPageRequest): Promise<SemanticOutputPage> {{
  return invoke<SemanticOutputPage>(QUERY_SEMANTIC_OUTPUT_COMMAND, {{ request }});
}}
"#,
        status_command = GET_APP_STATUS_COMMAND,
        traffic_command = QUERY_TRAFFIC_COMMAND,
        detail_command = GET_TRAFFIC_DETAIL_COMMAND,
        semantic_command = QUERY_SEMANTIC_OUTPUT_COMMAND,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AppStatus, IpcError, IpcErrorCode, SemanticOutputItem, SubsystemAvailability,
        SupervisorLifecycle, TrafficPageRequest, typescript_bindings,
    };

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
    fn request_and_error_shapes_are_stable_and_redacted() {
        let request = TrafficPageRequest {
            page_size: 25,
            cursor: Some("opaque-cursor".to_owned()),
        };
        let request_value = serde_json::to_value(request).expect("request should serialize");
        assert_eq!(request_value["pageSize"], 25);
        assert_eq!(request_value["cursor"], "opaque-cursor");

        let error = IpcError::new(IpcErrorCode::InvalidCursor, "traffic cursor is invalid");
        let error_value = serde_json::to_value(error).expect("error should serialize");
        assert_eq!(error_value["code"], "invalidCursor");
        assert_eq!(error_value["message"], "traffic cursor is invalid");
    }

    #[test]
    fn ordinary_semantic_output_excludes_arbitrary_analyzer_attributes() {
        let output = SemanticOutputItem {
            event_id: "event-1".to_owned(),
            capture_session_id: Some("session-1".to_owned()),
            source_flow_id: Some("flow-1".to_owned()),
            analyzer_id: "demo".to_owned(),
            analyzer_version: "0.1.0".to_owned(),
            namespace: "flowprobe.demo".to_owned(),
            kind: "summary".to_owned(),
            timestamp_ns: "42".to_owned(),
        };

        let value = serde_json::to_value(output).expect("semantic output should serialize");
        assert_eq!(
            value
                .as_object()
                .expect("semantic output is an object")
                .len(),
            8
        );
        assert!(value.get("attributesJson").is_none());
        assert!(value.get("attributes_json").is_none());
    }

    #[test]
    fn checked_in_typescript_binding_matches_rust_contract() {
        let checked_in = include_str!("../../../apps/desktop/src/ipc/generated.ts");

        assert_eq!(typescript_bindings(), checked_in);
    }
}
