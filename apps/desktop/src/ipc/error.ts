import type { IpcError } from "./generated";

const IPC_ERROR_CODES = new Set([
  "invalidRequest",
  "invalidCursor",
  "notFound",
  "storageUnavailable",
  "internal",
]);

export function isIpcError(value: unknown): value is IpcError {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const candidate = value as Partial<IpcError>;
  return (
    typeof candidate.code === "string" &&
    IPC_ERROR_CODES.has(candidate.code) &&
    typeof candidate.message === "string"
  );
}

export function describeIpcFailure(reason: unknown): string {
  if (isIpcError(reason)) {
    return reason.message;
  }
  return "The local supervisor did not return a readable error.";
}
