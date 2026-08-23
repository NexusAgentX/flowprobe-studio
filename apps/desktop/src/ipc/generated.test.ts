import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));

import { GET_APP_STATUS_COMMAND, getAppStatus, type AppStatus } from "./generated";

const response: AppStatus = {
  supervisor: "idle",
  networkRuntime: "notConfigured",
  captureCore: "notConfigured",
  analyzerRuntime: "notConfigured",
};

describe("generated IPC client", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("invokes the Rust command literal and preserves the typed response", async () => {
    invokeMock.mockResolvedValue(response);

    await expect(getAppStatus()).resolves.toEqual(response);
    expect(GET_APP_STATUS_COMMAND).toBe("get_app_status");
    expect(invokeMock).toHaveBeenCalledWith("get_app_status");
  });

  it("propagates IPC failures to the renderer", async () => {
    invokeMock.mockRejectedValue(new Error("IPC closed"));

    await expect(getAppStatus()).rejects.toThrow("IPC closed");
  });
});
