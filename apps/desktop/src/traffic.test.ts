import { describe, expect, it } from "vitest";

import type { SemanticOutputItem, TrafficListItem } from "./ipc";
import {
  appendSemanticItems,
  appendTrafficItems,
  destinationLabel,
  timestampLabel,
} from "./traffic";

function traffic(flowId: string, host: string | null = "fixture.example"): TrafficListItem {
  return {
    flowId,
    startedAtNs: "1720000000000000000",
    transportProtocol: "tcp",
    destinationHost: host,
    destinationIp: "198.51.100.20",
    destinationPort: 443,
    protocols: ["tls", "http"],
    httpMethod: "GET",
    httpStatus: 200,
  };
}

function semantic(eventId: string): SemanticOutputItem {
  return {
    eventId,
    captureSessionId: null,
    sourceFlowId: "flow-1",
    analyzerId: "demo",
    analyzerVersion: "0.1.0",
    namespace: "flowprobe.demo",
    kind: "summary",
    timestampNs: "1720000000000000000",
  };
}

describe("Traffic presentation", () => {
  it("appends pages in order and replaces duplicate identities", () => {
    const updated = { ...traffic("flow-2"), httpStatus: 204 };
    expect(appendTrafficItems([traffic("flow-1"), traffic("flow-2")], [updated, traffic("flow-3")])).toEqual([
      traffic("flow-1"),
      updated,
      traffic("flow-3"),
    ]);
    expect(appendSemanticItems([semantic("event-1")], [semantic("event-1"), semantic("event-2")])).toEqual([
      semantic("event-1"),
      semantic("event-2"),
    ]);
  });

  it("uses host then IP for destinations and formats nanoseconds without number precision loss", () => {
    expect(destinationLabel(traffic("flow-1"))).toBe("fixture.example:443");
    expect(destinationLabel(traffic("flow-1", null))).toBe("198.51.100.20:443");
    expect(destinationLabel({ ...traffic("flow-1", null), destinationIp: "2001:db8::1" })).toBe(
      "[2001:db8::1]:443",
    );
    expect(timestampLabel("1720000000000000000")).toBe("2024-07-03T09:46:40.000Z");
    expect(timestampLabel("invalid")).toBe("invalid ns");
  });
});
