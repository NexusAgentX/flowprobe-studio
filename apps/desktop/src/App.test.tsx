// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App, type DesktopIpcClient } from "./App";
import type {
  AppStatus,
  SemanticOutputItem,
  SemanticOutputPage,
  TrafficDetail,
  TrafficListItem,
  TrafficPage,
} from "./ipc";

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return { promise, resolve, reject };
}

const status: AppStatus = {
  supervisor: "idle",
  networkRuntime: "notConfigured",
  captureCore: "notConfigured",
  analyzerRuntime: "notConfigured",
};

function trafficItem(flowId: string, host = "fixture.example"): TrafficListItem {
  return {
    flowId,
    startedAtNs: "1720000000000000000",
    transportProtocol: "tcp",
    destinationHost: host,
    destinationIp: "198.51.100.20",
    destinationPort: 443,
    protocols: ["connection", "tls", "http"],
    httpMethod: "POST",
    httpStatus: 200,
  };
}

function trafficDetail(item: TrafficListItem, connectionId = `connection-${item.flowId}`): TrafficDetail {
  return {
    summary: item,
    connectionId,
    captureSessionId: "session-fixture",
    firstByteAtNs: "1720000000001000000",
    endedAtNs: "1720000000004000000",
    normalizedSourceAvailable: true,
  };
}

function semanticItem(eventId: string, kind = "request-summary"): SemanticOutputItem {
  return {
    eventId,
    captureSessionId: "session-fixture",
    sourceFlowId: "flow-fixture",
    analyzerId: "demo-analyzer",
    analyzerVersion: "0.1.0",
    namespace: "flowprobe.demo",
    kind,
    timestampNs: "1720000000004000000",
  };
}

function clientWith(overrides: Partial<DesktopIpcClient> = {}): DesktopIpcClient {
  return {
    getAppStatus: vi.fn().mockResolvedValue(status),
    queryTraffic: vi.fn().mockResolvedValue({ items: [], nextCursor: null }),
    getTrafficDetail: vi.fn().mockRejectedValue({ code: "notFound", message: "traffic flow was not found" }),
    querySemanticOutput: vi.fn().mockResolvedValue({ items: [], nextCursor: null }),
    ...overrides,
  };
}

afterEach(() => {
  cleanup();
});

describe("desktop shell behavior", () => {
  it("operates all four product surfaces by click and keyboard", async () => {
    const user = userEvent.setup();
    const getAppStatus = vi.fn().mockResolvedValue(status);
    render(<App client={clientWith({ getAppStatus })} />);

    await screen.findByRole("heading", { name: "No normalized flows stored" });
    await user.click(screen.getByRole("button", { name: "Proxy" }));
    expect(screen.getByRole("heading", { name: "Network runtime" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Refresh supervisor status" }));
    await waitFor(() => {
      expect(getAppStatus).toHaveBeenCalledTimes(2);
    });

    await user.click(screen.getByRole("button", { name: "Capture" }));
    expect(screen.getByRole("heading", { name: "Normalized flows" })).toBeTruthy();

    fireEvent.keyDown(window, { key: "3", ctrlKey: true });
    expect(screen.getByRole("heading", { name: "Analyzer events" })).toBeTruthy();
    fireEvent.keyDown(window, { key: "4", metaKey: true });
    expect(screen.getByRole("heading", { name: "Local data and privileges" })).toBeTruthy();

    const activeNavigation = screen.getByRole("button", { name: "Settings" });
    expect(activeNavigation.getAttribute("aria-current")).toBe("page");
    expect(screen.getByRole("navigation", { name: "Product surfaces" })).toBeTruthy();
  });

  it("shows loading and typed errors, then retries to an honest empty state", async () => {
    const user = userEvent.setup();
    const firstTraffic = deferred<TrafficPage>();
    const queryTraffic = vi
      .fn()
      .mockReturnValueOnce(firstTraffic.promise)
      .mockResolvedValueOnce({ items: [], nextCursor: null });
    render(<App client={clientWith({ queryTraffic })} />);

    expect(screen.getByText("Querying local traffic metadata…")).toBeTruthy();
    await act(async () => {
      firstTraffic.reject({ code: "storageUnavailable", message: "traffic metadata store is unavailable" });
    });

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("traffic metadata store is unavailable");
    await user.click(screen.getByRole("button", { name: "Retry from first page" }));
    await screen.findByRole("heading", { name: "No normalized flows stored" });
    expect(queryTraffic).toHaveBeenNthCalledWith(2, { pageSize: 20, cursor: null });
  });

  it("paginates with opaque cursors, opens detail, closes by keyboard, and refreshes", async () => {
    const user = userEvent.setup();
    const first = trafficItem("flow-one");
    const second = trafficItem("flow-two", "second.example");
    const queryTraffic = vi
      .fn()
      .mockResolvedValueOnce({ items: [first], nextCursor: "flow-cursor-1" })
      .mockResolvedValueOnce({ items: [second], nextCursor: null })
      .mockResolvedValueOnce({ items: [], nextCursor: null });
    const getTrafficDetail = vi.fn().mockResolvedValue(trafficDetail(first));
    render(<App client={clientWith({ queryTraffic, getTrafficDetail })} />);

    await screen.findByRole("button", { name: /flow-one/ });
    await user.click(screen.getByRole("button", { name: "Load next page" }));
    await screen.findByRole("button", { name: /flow-two/ });
    expect(queryTraffic).toHaveBeenNthCalledWith(2, { pageSize: 20, cursor: "flow-cursor-1" });

    await user.click(screen.getByRole("button", { name: /flow-one/ }));
    expect(await screen.findByText("connection-flow-one")).toBeTruthy();
    expect(getTrafficDetail).toHaveBeenCalledWith({ flowId: "flow-one" });
    await user.keyboard("{Escape}");
    expect(screen.queryByText("connection-flow-one")).toBeNull();
    expect(screen.getByText("Select a flow to query its normalized metadata through IPC.")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("heading", { name: "No normalized flows stored" });
    expect(queryTraffic).toHaveBeenNthCalledWith(3, { pageSize: 20, cursor: null });
  });

  it("keeps the newest detail when an older detail response arrives late", async () => {
    const user = userEvent.setup();
    const first = trafficItem("flow-one");
    const second = trafficItem("flow-two", "second.example");
    const firstDetail = deferred<TrafficDetail>();
    const secondDetail = deferred<TrafficDetail>();
    const getTrafficDetail = vi
      .fn()
      .mockReturnValueOnce(firstDetail.promise)
      .mockReturnValueOnce(secondDetail.promise);
    render(
      <App
        client={clientWith({
          queryTraffic: vi.fn().mockResolvedValue({ items: [first, second], nextCursor: null }),
          getTrafficDetail,
        })}
      />,
    );

    await user.click(await screen.findByRole("button", { name: /flow-one/ }));
    await user.click(screen.getByRole("button", { name: /flow-two/ }));
    await act(async () => {
      secondDetail.resolve(trafficDetail(second, "connection-two"));
    });
    expect(await screen.findByText("connection-two")).toBeTruthy();

    await act(async () => {
      firstDetail.resolve(trafficDetail(first, "connection-one"));
    });
    expect(screen.getByText("connection-two")).toBeTruthy();
    expect(screen.queryByText("connection-one")).toBeNull();
  });

  it("invalidates old status, Traffic, and Analyze work during effect cleanup", async () => {
    const user = userEvent.setup();
    const oldStatus = deferred<AppStatus>();
    const oldTraffic = deferred<TrafficPage>();
    const oldSemantic = deferred<SemanticOutputPage>();
    const oldClient = clientWith({
      getAppStatus: vi.fn().mockReturnValue(oldStatus.promise),
      queryTraffic: vi.fn().mockReturnValue(oldTraffic.promise),
      querySemanticOutput: vi.fn().mockReturnValue(oldSemantic.promise),
    });

    const freshTraffic = trafficItem("flow-fresh", "fresh.example");
    const queryFreshTraffic = vi
      .fn()
      .mockResolvedValueOnce({ items: [freshTraffic], nextCursor: "fresh-cursor" })
      .mockResolvedValueOnce({ items: [], nextCursor: null });
    const freshClient = clientWith({
      queryTraffic: queryFreshTraffic,
      querySemanticOutput: vi.fn().mockResolvedValue({
        items: [semanticItem("semantic-fresh", "fresh-summary")],
        nextCursor: null,
      }),
    });

    const view = render(<App client={oldClient} />);
    view.rerender(<App client={freshClient} />);

    expect(await screen.findByText("fresh.example:443")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Analyze" }));
    expect(await screen.findByRole("heading", { name: "fresh-summary" })).toBeTruthy();
    expect(view.container.querySelector("pre")).toBeNull();

    await act(async () => {
      oldStatus.reject({ code: "internal", message: "stale status error" });
      oldTraffic.resolve({
        items: [trafficItem("flow-stale", "stale.example")],
        nextCursor: "stale-cursor",
      });
      oldSemantic.reject({ code: "internal", message: "stale semantic error" });
    });

    expect(screen.queryByText("stale semantic error")).toBeNull();
    expect(screen.getByText("Supervisor idle")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Capture" }));
    expect(screen.getByText("fresh.example:443")).toBeTruthy();
    expect(screen.queryByText("stale.example:443")).toBeNull();

    await user.click(screen.getByRole("button", { name: "Load next page" }));
    await waitFor(() => {
      expect(queryFreshTraffic).toHaveBeenNthCalledWith(2, { pageSize: 20, cursor: "fresh-cursor" });
    });
  });
});
