// Generated from flowprobe-ipc. Run the Rust binding test after changing IPC DTOs.
import { invoke } from "@tauri-apps/api/core";

export type SupervisorLifecycle = "idle";

export type SubsystemAvailability = "notConfigured";

export type AppStatus = { supervisor: SupervisorLifecycle, networkRuntime: SubsystemAvailability, captureCore: SubsystemAvailability, analyzerRuntime: SubsystemAvailability, };

export const GET_APP_STATUS_COMMAND = "get_app_status" as const;

export function getAppStatus(): Promise<AppStatus> {
  return invoke<AppStatus>(GET_APP_STATUS_COMMAND);
}
