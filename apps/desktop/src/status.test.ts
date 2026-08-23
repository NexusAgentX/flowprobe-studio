import { describe, expect, it } from "vitest";

import type { AppStatus } from "./ipc";
import { summarizeStatus } from "./status";

const foundationStatus: AppStatus = {
  supervisor: "idle",
  networkRuntime: "notConfigured",
  captureCore: "notConfigured",
  analyzerRuntime: "notConfigured",
};

describe("summarizeStatus", () => {
  it("reports the supervisor as idle without claiming runtime readiness", () => {
    expect(summarizeStatus(foundationStatus, null)).toEqual({
      label: "Supervisor idle",
      tone: "idle",
    });
  });

  it("keeps an IPC failure visible", () => {
    expect(summarizeStatus(null, "IPC closed")).toEqual({
      label: "Supervisor unavailable: IPC closed",
      tone: "error",
    });
  });
});
