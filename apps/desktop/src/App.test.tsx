import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AnalyzeSurface, App, CaptureSurface, type DesktopIpcClient } from "./App";
import type { SemanticOutputItem, TrafficDetail, TrafficListItem } from "./ipc";

const pending = new Promise<never>(() => undefined);
const client: DesktopIpcClient = {
  getAppStatus: () => pending,
  queryTraffic: () => pending,
  getTrafficDetail: () => pending,
  querySemanticOutput: () => pending,
};
const noop = () => undefined;

const trafficItem: TrafficListItem = {
  flowId: "flow-fixture",
  startedAtNs: "1720000000000000000",
  transportProtocol: "tcp",
  destinationHost: "fixture.example",
  destinationIp: "198.51.100.20",
  destinationPort: 443,
  protocols: ["connection", "tls", "http"],
  httpMethod: "POST",
  httpStatus: 200,
};

const detail: TrafficDetail = {
  summary: trafficItem,
  connectionId: "connection-fixture",
  captureSessionId: "session-fixture",
  firstByteAtNs: "1720000000001000000",
  endedAtNs: "1720000000004000000",
  normalizedSourceAvailable: true,
};

const semanticItem: SemanticOutputItem = {
  eventId: "semantic-fixture",
  captureSessionId: "session-fixture",
  sourceFlowId: "flow-fixture",
  analyzerId: "demo-analyzer",
  analyzerVersion: "0.1.0",
  namespace: "flowprobe.demo",
  kind: "request-summary",
  timestampNs: "1720000000004000000",
  attributesJson: '{\n  "summary": "fixture analyzed"\n}',
};

describe("desktop shell accessibility boundaries", () => {
  it("renders operable Proxy, Capture, Analyze, and Settings navigation", () => {
    const html = renderToStaticMarkup(<App client={client} />);

    for (const label of ["Proxy", "Capture", "Analyze", "Settings"]) {
      expect(html).toContain(`>${label}<`);
    }
    expect(html).toContain('aria-label="Product surfaces"');
    expect(html).toContain('aria-keyshortcuts="Meta+1 Control+1"');
    expect(html).toContain('aria-keyshortcuts="Meta+4 Control+4"');
    expect(html).toContain('aria-current="page"');
  });

  it("starts on a real Traffic query surface with status and keyboard-safe controls", () => {
    const html = renderToStaticMarkup(<App client={client} />);

    expect(html).toContain('id="surface-capture"');
    expect(html).toContain("Normalized flows");
    expect(html).toContain("Querying local traffic metadata");
    expect(html).toContain('role="status"');
    expect(html).toContain('href="#workspace"');
    expect(html).not.toContain("Authorization");
    expect(html).not.toContain("Cookie");
  });

  it("wires every navigation target to its real surface", () => {
    expect(renderToStaticMarkup(<App client={client} initialSurface="proxy" />)).toContain(
      'id="surface-proxy"',
    );
    expect(renderToStaticMarkup(<App client={client} initialSurface="capture" />)).toContain(
      'id="surface-capture"',
    );
    expect(renderToStaticMarkup(<App client={client} initialSurface="analyze" />)).toContain(
      'id="surface-analyze"',
    );
    expect(renderToStaticMarkup(<App client={client} initialSurface="settings" />)).toContain(
      'id="surface-settings"',
    );
  });

  it("renders Traffic list and detail DTO fields through the actual Capture view", () => {
    const html = renderToStaticMarkup(
      <CaptureSurface
        items={[trafficItem]}
        cursor="next-flow-page"
        phase="ready"
        error={null}
        selectedFlowId={trafficItem.flowId}
        detail={detail}
        detailPhase="ready"
        detailError={null}
        onRefresh={noop}
        onLoadMore={noop}
        onSelectFlow={noop}
        onRetryDetail={noop}
        onCloseDetail={noop}
      />,
    );

    expect(html).toContain("fixture.example:443");
    expect(html).toContain("flow-fixture");
    expect(html).toContain("connection-fixture");
    expect(html).toContain("session-fixture");
    expect(html).toContain("1720000000004000000");
    expect(html).toContain("Available to host");
    expect(html).toContain("Load next page");
  });

  it("renders persisted semantic DTO fields through the actual Analyze view", () => {
    const html = renderToStaticMarkup(
      <AnalyzeSurface
        items={[semanticItem]}
        cursor="next-semantic-page"
        phase="ready"
        error={null}
        onRefresh={noop}
        onLoadMore={noop}
      />,
    );

    expect(html).toContain("flowprobe.demo");
    expect(html).toContain("request-summary");
    expect(html).toContain("demo-analyzer");
    expect(html).toContain("fixture analyzed");
    expect(html).toContain("Load next page");
  });
});
