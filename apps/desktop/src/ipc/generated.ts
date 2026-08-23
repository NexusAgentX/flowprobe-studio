// Generated from flowprobe-ipc. Run the Rust binding test after changing IPC DTOs.
import { invoke } from "@tauri-apps/api/core";

export type SupervisorLifecycle = "idle";

export type SubsystemAvailability = "notConfigured";

export type AppStatus = { supervisor: SupervisorLifecycle, networkRuntime: SubsystemAvailability, captureCore: SubsystemAvailability, analyzerRuntime: SubsystemAvailability, };

export type IpcErrorCode = "invalidRequest" | "invalidCursor" | "notFound" | "storageUnavailable" | "internal";

export type IpcError = { code: IpcErrorCode, message: string, };

export type TrafficPageRequest = { pageSize: number, cursor: string | null, };

export type TrafficListItem = { flowId: string, startedAtNs: string, transportProtocol: string, destinationHost: string | null, destinationIp: string | null, destinationPort: number, protocols: Array<string>, httpMethod: string | null, httpStatus: number | null, };

export type TrafficPage = { items: Array<TrafficListItem>, nextCursor: string | null, };

export type TrafficDetailRequest = { flowId: string, };

export type TrafficDetail = { summary: TrafficListItem, connectionId: string, captureSessionId: string | null, firstByteAtNs: string | null, endedAtNs: string | null, normalizedSourceAvailable: boolean, };

export type SemanticPageRequest = { pageSize: number, cursor: string | null, };

export type SemanticOutputItem = { eventId: string, captureSessionId: string | null, sourceFlowId: string | null, analyzerId: string, analyzerVersion: string, namespace: string, kind: string, timestampNs: string, };

export type SemanticOutputPage = { items: Array<SemanticOutputItem>, nextCursor: string | null, };

export const GET_APP_STATUS_COMMAND = "get_app_status" as const;
export const QUERY_TRAFFIC_COMMAND = "query_traffic" as const;
export const GET_TRAFFIC_DETAIL_COMMAND = "get_traffic_detail" as const;
export const QUERY_SEMANTIC_OUTPUT_COMMAND = "query_semantic_output" as const;

export function getAppStatus(): Promise<AppStatus> {
  return invoke<AppStatus>(GET_APP_STATUS_COMMAND);
}

export function queryTraffic(request: TrafficPageRequest): Promise<TrafficPage> {
  return invoke<TrafficPage>(QUERY_TRAFFIC_COMMAND, { request });
}

export function getTrafficDetail(request: TrafficDetailRequest): Promise<TrafficDetail> {
  return invoke<TrafficDetail>(GET_TRAFFIC_DETAIL_COMMAND, { request });
}

export function querySemanticOutput(request: SemanticPageRequest): Promise<SemanticOutputPage> {
  return invoke<SemanticOutputPage>(QUERY_SEMANTIC_OUTPUT_COMMAND, { request });
}
