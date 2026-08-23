import type { AppStatus } from "./ipc";

export type StatusTone = "loading" | "idle" | "error";

export interface StatusSummary {
  label: string;
  tone: StatusTone;
}

export function summarizeStatus(status: AppStatus | null, error: string | null): StatusSummary {
  if (error !== null) {
    return { label: `Supervisor unavailable: ${error}`, tone: "error" };
  }

  if (status === null) {
    return { label: "Connecting to supervisor", tone: "loading" };
  }

  return { label: "Supervisor idle", tone: "idle" };
}
