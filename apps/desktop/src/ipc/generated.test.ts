import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));

import {
  GET_APP_STATUS_COMMAND,
  GET_TRAFFIC_DETAIL_COMMAND,
  QUERY_SEMANTIC_OUTPUT_COMMAND,
  QUERY_TRAFFIC_COMMAND,
  getAppStatus,
  getTrafficDetail,
  querySemanticOutput,
  queryTraffic,
  type AppStatus,
} from "./generated";

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

  it("invokes the status command literal and preserves the typed response", async () => {
    invokeMock.mockResolvedValue(response);

    await expect(getAppStatus()).resolves.toEqual(response);
    expect(GET_APP_STATUS_COMMAND).toBe("get_app_status");
    expect(invokeMock).toHaveBeenCalledWith("get_app_status");
  });

  it("passes bounded traffic, detail, and semantic requests under the typed request key", async () => {
    invokeMock.mockResolvedValueOnce({ items: [], nextCursor: null });
    await queryTraffic({ pageSize: 20, cursor: null });
    expect(QUERY_TRAFFIC_COMMAND).toBe("query_traffic");
    expect(invokeMock).toHaveBeenLastCalledWith("query_traffic", {
      request: { pageSize: 20, cursor: null },
    });

    invokeMock.mockResolvedValueOnce({ flowId: "flow-1" });
    await getTrafficDetail({ flowId: "flow-1" });
    expect(GET_TRAFFIC_DETAIL_COMMAND).toBe("get_traffic_detail");
    expect(invokeMock).toHaveBeenLastCalledWith("get_traffic_detail", {
      request: { flowId: "flow-1" },
    });

    invokeMock.mockResolvedValueOnce({ items: [], nextCursor: null });
    await querySemanticOutput({ pageSize: 12, cursor: "semantic-cursor" });
    expect(QUERY_SEMANTIC_OUTPUT_COMMAND).toBe("query_semantic_output");
    expect(invokeMock).toHaveBeenLastCalledWith("query_semantic_output", {
      request: { pageSize: 12, cursor: "semantic-cursor" },
    });
  });

  it("propagates structured IPC failures to the renderer", async () => {
    const failure = { code: "invalidCursor", message: "traffic cursor is invalid or expired" };
    invokeMock.mockRejectedValue(failure);

    await expect(queryTraffic({ pageSize: 20, cursor: "expired" })).rejects.toEqual(failure);
  });
});
