import { useCallback, useEffect, useRef, useState } from "react";

import {
  describeIpcFailure,
  getAppStatus,
  getTrafficDetail,
  querySemanticOutput,
  queryTraffic,
  type AppStatus,
  type SemanticOutputItem,
  type SemanticOutputPage,
  type SemanticPageRequest,
  type TrafficDetail,
  type TrafficDetailRequest,
  type TrafficListItem,
  type TrafficPage,
  type TrafficPageRequest,
} from "./ipc";
import { PRODUCT_SURFACES, surfaceForShortcut, type SurfaceId } from "./navigation";
import { summarizeStatus } from "./status";
import {
  appendSemanticItems,
  appendTrafficItems,
  destinationLabel,
  SEMANTIC_PAGE_SIZE,
  timestampLabel,
  TRAFFIC_PAGE_SIZE,
} from "./traffic";

type LoadPhase = "loading" | "loadingMore" | "ready" | "error";

export interface DesktopIpcClient {
  getAppStatus: () => Promise<AppStatus>;
  queryTraffic: (request: TrafficPageRequest) => Promise<TrafficPage>;
  getTrafficDetail: (request: TrafficDetailRequest) => Promise<TrafficDetail>;
  querySemanticOutput: (request: SemanticPageRequest) => Promise<SemanticOutputPage>;
}

export interface AppProps {
  client?: DesktopIpcClient;
  initialSurface?: SurfaceId;
}

const desktopClient: DesktopIpcClient = {
  getAppStatus,
  queryTraffic,
  getTrafficDetail,
  querySemanticOutput,
};

const surfaceHeadings: Record<SurfaceId, { eyebrow: string; heading: string; description: string }> = {
  proxy: {
    eyebrow: "Network plane",
    heading: "Proxy runtime boundary",
    description: "Inspect lifecycle state without granting the renderer privileged network access.",
  },
  capture: {
    eyebrow: "Capture plane",
    heading: "Traffic",
    description: "Browse bounded NormalizedFlow metadata through the local supervisor boundary.",
  },
  analyze: {
    eyebrow: "Analysis plane",
    heading: "Semantic output",
    description: "Review rebuildable analyzer events persisted by the host.",
  },
  settings: {
    eyebrow: "Local controls",
    heading: "Settings boundaries",
    description: "See the privacy and privilege rules that apply to this architecture proof.",
  },
};

export function App({ client = desktopClient, initialSurface = "capture" }: AppProps = {}) {
  const [activeSurface, setActiveSurface] = useState<SurfaceId>(initialSurface);
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [trafficItems, setTrafficItems] = useState<TrafficListItem[]>([]);
  const [trafficCursor, setTrafficCursor] = useState<string | null>(null);
  const [trafficPhase, setTrafficPhase] = useState<LoadPhase>("loading");
  const [trafficError, setTrafficError] = useState<string | null>(null);
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(null);
  const [trafficDetail, setTrafficDetail] = useState<TrafficDetail | null>(null);
  const [detailPhase, setDetailPhase] = useState<LoadPhase>("ready");
  const [detailError, setDetailError] = useState<string | null>(null);
  const [semanticItems, setSemanticItems] = useState<SemanticOutputItem[]>([]);
  const [semanticCursor, setSemanticCursor] = useState<string | null>(null);
  const [semanticPhase, setSemanticPhase] = useState<LoadPhase>("loading");
  const [semanticError, setSemanticError] = useState<string | null>(null);
  const statusRequestSequence = useRef(0);
  const trafficRequestSequence = useRef(0);
  const detailRequestSequence = useRef(0);
  const semanticRequestSequence = useRef(0);

  const refreshStatus = useCallback(() => {
    const sequence = statusRequestSequence.current + 1;
    statusRequestSequence.current = sequence;
    setStatus(null);
    setStatusError(null);
    void client
      .getAppStatus()
      .then((nextStatus) => {
        if (statusRequestSequence.current === sequence) {
          setStatus(nextStatus);
        }
      })
      .catch((reason: unknown) => {
        if (statusRequestSequence.current === sequence) {
          setStatus(null);
          setStatusError(describeIpcFailure(reason));
        }
      });
  }, [client]);

  const requestTraffic = useCallback(
    (cursor: string | null, append: boolean) => {
      const sequence = trafficRequestSequence.current + 1;
      trafficRequestSequence.current = sequence;
      setTrafficPhase(append ? "loadingMore" : "loading");
      setTrafficError(null);
      setTrafficCursor(null);
      void client
        .queryTraffic({ pageSize: TRAFFIC_PAGE_SIZE, cursor })
        .then((page) => {
          if (trafficRequestSequence.current === sequence) {
            setTrafficItems((current) => (append ? appendTrafficItems(current, page.items) : page.items));
            setTrafficCursor(page.nextCursor);
            setTrafficPhase("ready");
          }
        })
        .catch((reason: unknown) => {
          if (trafficRequestSequence.current === sequence) {
            setTrafficError(describeIpcFailure(reason));
            setTrafficPhase("error");
          }
        });
    },
    [client],
  );

  const requestSemanticOutput = useCallback(
    (cursor: string | null, append: boolean) => {
      const sequence = semanticRequestSequence.current + 1;
      semanticRequestSequence.current = sequence;
      setSemanticPhase(append ? "loadingMore" : "loading");
      setSemanticError(null);
      setSemanticCursor(null);
      void client
        .querySemanticOutput({ pageSize: SEMANTIC_PAGE_SIZE, cursor })
        .then((page) => {
          if (semanticRequestSequence.current === sequence) {
            setSemanticItems((current) => (append ? appendSemanticItems(current, page.items) : page.items));
            setSemanticCursor(page.nextCursor);
            setSemanticPhase("ready");
          }
        })
        .catch((reason: unknown) => {
          if (semanticRequestSequence.current === sequence) {
            setSemanticError(describeIpcFailure(reason));
            setSemanticPhase("error");
          }
        });
    },
    [client],
  );

  const requestDetail = useCallback(
    (flowId: string) => {
      const sequence = detailRequestSequence.current + 1;
      detailRequestSequence.current = sequence;
      setSelectedFlowId(flowId);
      setTrafficDetail(null);
      setDetailError(null);
      setDetailPhase("loading");
      void client
        .getTrafficDetail({ flowId })
        .then((detail) => {
          if (detailRequestSequence.current === sequence) {
            setTrafficDetail(detail);
            setDetailPhase("ready");
          }
        })
        .catch((reason: unknown) => {
          if (detailRequestSequence.current === sequence) {
            setDetailError(describeIpcFailure(reason));
            setDetailPhase("error");
          }
        });
    },
    [client],
  );

  const closeDetail = useCallback(() => {
    detailRequestSequence.current += 1;
    setSelectedFlowId(null);
    setTrafficDetail(null);
    setDetailError(null);
    setDetailPhase("ready");
  }, []);

  useEffect(() => {
    refreshStatus();
    requestTraffic(null, false);
    requestSemanticOutput(null, false);

    return () => {
      statusRequestSequence.current += 1;
      trafficRequestSequence.current += 1;
      detailRequestSequence.current += 1;
      semanticRequestSequence.current += 1;
    };
  }, [refreshStatus, requestSemanticOutput, requestTraffic]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const destination = surfaceForShortcut(event);
      if (destination !== null) {
        event.preventDefault();
        setActiveSurface(destination);
        return;
      }
      if (event.key === "Escape" && selectedFlowId !== null) {
        closeDetail();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [closeDetail, selectedFlowId]);

  const heading = surfaceHeadings[activeSurface];
  const statusSummary = summarizeStatus(status, statusError);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#workspace">
        Skip to workspace
      </a>
      <aside className="sidebar">
        <div className="brand" aria-label="FlowProbe Studio">
          <span className="brand-mark" aria-hidden="true" />
          <span>FlowProbe</span>
        </div>
        <nav aria-label="Product surfaces">
          <ul className="surface-list">
            {PRODUCT_SURFACES.map((surface) => (
              <li key={surface.id}>
                <button
                  type="button"
                  className="nav-item"
                  aria-controls={activeSurface === surface.id ? `surface-${surface.id}` : undefined}
                  aria-current={activeSurface === surface.id ? "page" : undefined}
                  aria-keyshortcuts={`Meta+${surface.shortcut} Control+${surface.shortcut}`}
                  onClick={() => {
                    setActiveSurface(surface.id);
                  }}
                >
                  <span>{surface.label}</span>
                  <kbd aria-hidden="true">{surface.shortcut}</kbd>
                </button>
              </li>
            ))}
          </ul>
        </nav>
        <p className="sidebar-note">Local metadata stays behind the supervisor boundary.</p>
      </aside>

      <main id="workspace" tabIndex={-1}>
        <header className="workspace-header">
          <div>
            <p className="eyebrow">{heading.eyebrow}</p>
            <h1>{heading.heading}</h1>
            <p className="lede">{heading.description}</p>
          </div>
          <div className={`status ${statusSummary.tone}`} role="status" aria-live="polite">
            <span aria-hidden="true" />
            {statusSummary.label}
          </div>
        </header>

        {activeSurface === "proxy" ? (
          <ProxySurface status={status} onRefreshStatus={refreshStatus} />
        ) : null}
        {activeSurface === "capture" ? (
          <CaptureSurface
            items={trafficItems}
            cursor={trafficCursor}
            phase={trafficPhase}
            error={trafficError}
            selectedFlowId={selectedFlowId}
            detail={trafficDetail}
            detailPhase={detailPhase}
            detailError={detailError}
            onRefresh={() => {
              closeDetail();
              requestTraffic(null, false);
            }}
            onLoadMore={() => {
              if (trafficCursor !== null) {
                requestTraffic(trafficCursor, true);
              }
            }}
            onSelectFlow={requestDetail}
            onRetryDetail={() => {
              if (selectedFlowId !== null) {
                requestDetail(selectedFlowId);
              }
            }}
            onCloseDetail={closeDetail}
          />
        ) : null}
        {activeSurface === "analyze" ? (
          <AnalyzeSurface
            items={semanticItems}
            cursor={semanticCursor}
            phase={semanticPhase}
            error={semanticError}
            onRefresh={() => {
              requestSemanticOutput(null, false);
            }}
            onLoadMore={() => {
              if (semanticCursor !== null) {
                requestSemanticOutput(semanticCursor, true);
              }
            }}
          />
        ) : null}
        {activeSurface === "settings" ? <SettingsSurface /> : null}
      </main>
    </div>
  );
}

interface ProxySurfaceProps {
  status: AppStatus | null;
  onRefreshStatus: () => void;
}

function ProxySurface({ status, onRefreshStatus }: ProxySurfaceProps) {
  return (
    <section className="panel boundary-panel" id="surface-proxy" aria-labelledby="proxy-title">
      <div>
        <p className="section-kicker">Read-only status</p>
        <h2 id="proxy-title">Network runtime</h2>
        <p>
          The architecture proof does not start, stop, or reconfigure privileged networking from the renderer.
          Runtime operations remain behind typed supervisor commands.
        </p>
      </div>
      <dl className="boundary-grid">
        <div>
          <dt>Supervisor</dt>
          <dd>{status?.supervisor ?? "checking"}</dd>
        </div>
        <div>
          <dt>Network runtime</dt>
          <dd>{status?.networkRuntime ?? "checking"}</dd>
        </div>
        <div>
          <dt>Capture core</dt>
          <dd>{status?.captureCore ?? "checking"}</dd>
        </div>
      </dl>
      <button className="secondary-button" type="button" onClick={onRefreshStatus}>
        Refresh supervisor status
      </button>
    </section>
  );
}

interface CaptureSurfaceProps {
  items: readonly TrafficListItem[];
  cursor: string | null;
  phase: LoadPhase;
  error: string | null;
  selectedFlowId: string | null;
  detail: TrafficDetail | null;
  detailPhase: LoadPhase;
  detailError: string | null;
  onRefresh: () => void;
  onLoadMore: () => void;
  onSelectFlow: (flowId: string) => void;
  onRetryDetail: () => void;
  onCloseDetail: () => void;
}

export function CaptureSurface(props: CaptureSurfaceProps) {
  const isBusy = props.phase === "loading" || props.phase === "loadingMore";

  return (
    <section className="capture-layout" id="surface-capture" aria-label="Traffic metadata">
      <div className="panel traffic-panel">
        <div className="panel-toolbar">
          <div>
            <p className="section-kicker">Metadata only</p>
            <h2>Normalized flows</h2>
          </div>
          <button className="secondary-button" type="button" disabled={isBusy} onClick={props.onRefresh}>
            Refresh
          </button>
        </div>

        {props.error !== null ? (
          <div className="notice error-notice" role="alert">
            <strong>Traffic query failed.</strong>
            <span>{props.error}</span>
            <button type="button" onClick={props.onRefresh}>
              Retry from first page
            </button>
          </div>
        ) : null}

        {props.phase === "loading" && props.items.length === 0 ? (
          <p className="loading-copy" role="status">
            Querying local traffic metadata…
          </p>
        ) : null}

        {props.phase === "ready" && props.items.length === 0 ? (
          <div className="empty-state">
            <h3>No normalized flows stored</h3>
            <p>Start a capture or run the v0.1 integration proof to populate this local metadata index.</p>
          </div>
        ) : null}

        {props.items.length > 0 ? (
          <div className="table-scroll">
            <table>
              <caption className="sr-only">Normalized traffic metadata, newest first</caption>
              <thead>
                <tr>
                  <th scope="col">Started</th>
                  <th scope="col">Request</th>
                  <th scope="col">Destination</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {props.items.map((item) => (
                  <tr key={item.flowId}>
                    <td>
                      <button
                        className="flow-link"
                        type="button"
                        aria-pressed={props.selectedFlowId === item.flowId}
                        onClick={() => {
                          props.onSelectFlow(item.flowId);
                        }}
                      >
                        <span>{timestampLabel(item.startedAtNs)}</span>
                        <code>{item.flowId}</code>
                      </button>
                    </td>
                    <td>
                      <strong>{item.httpMethod ?? item.transportProtocol.toUpperCase()}</strong>
                      <span className="subtle">{item.protocols.join(" · ")}</span>
                    </td>
                    <td>
                      <span>{destinationLabel(item)}</span>
                    </td>
                    <td>
                      <span className="status-code">{item.httpStatus ?? "—"}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}

        {props.cursor !== null ? (
          <button className="load-more" type="button" disabled={isBusy} onClick={props.onLoadMore}>
            {props.phase === "loadingMore" ? "Loading next page…" : "Load next page"}
          </button>
        ) : null}
      </div>

      <TrafficDetailPanel
        flowId={props.selectedFlowId}
        detail={props.detail}
        phase={props.detailPhase}
        error={props.detailError}
        onRetry={props.onRetryDetail}
        onClose={props.onCloseDetail}
      />
    </section>
  );
}

interface TrafficDetailPanelProps {
  flowId: string | null;
  detail: TrafficDetail | null;
  phase: LoadPhase;
  error: string | null;
  onRetry: () => void;
  onClose: () => void;
}

function TrafficDetailPanel({ flowId, detail, phase, error, onRetry, onClose }: TrafficDetailPanelProps) {
  return (
    <aside className="panel detail-panel" aria-labelledby="detail-title">
      <div className="panel-toolbar compact">
        <div>
          <p className="section-kicker">Normalized detail</p>
          <h2 id="detail-title">Flow fields</h2>
        </div>
        {flowId !== null ? (
          <button className="icon-button" type="button" aria-label="Close traffic detail" onClick={onClose}>
            ×
          </button>
        ) : null}
      </div>

      {flowId === null ? (
        <div className="empty-state compact-empty">
          <p>Select a flow to query its normalized metadata through IPC.</p>
        </div>
      ) : null}
      {flowId !== null && phase === "loading" ? (
        <p className="loading-copy" role="status">
          Loading flow detail…
        </p>
      ) : null}
      {flowId !== null && error !== null ? (
        <div className="notice error-notice" role="alert">
          <strong>Detail query failed.</strong>
          <span>{error}</span>
          <button type="button" onClick={onRetry}>
            Retry detail
          </button>
        </div>
      ) : null}
      {detail !== null ? <TrafficFields detail={detail} /> : null}
    </aside>
  );
}

function TrafficFields({ detail }: { detail: TrafficDetail }) {
  return (
    <dl className="detail-grid">
      <div>
        <dt>Flow ID</dt>
        <dd>{detail.summary.flowId}</dd>
      </div>
      <div>
        <dt>Connection ID</dt>
        <dd>{detail.connectionId}</dd>
      </div>
      <div>
        <dt>Capture session</dt>
        <dd>{detail.captureSessionId ?? "None"}</dd>
      </div>
      <div>
        <dt>Started at (ns)</dt>
        <dd>{detail.summary.startedAtNs}</dd>
      </div>
      <div>
        <dt>First byte (ns)</dt>
        <dd>{detail.firstByteAtNs ?? "Unknown"}</dd>
      </div>
      <div>
        <dt>Ended at (ns)</dt>
        <dd>{detail.endedAtNs ?? "In progress"}</dd>
      </div>
      <div>
        <dt>Transport</dt>
        <dd>{detail.summary.transportProtocol}</dd>
      </div>
      <div>
        <dt>Destination</dt>
        <dd>{destinationLabel(detail.summary)}</dd>
      </div>
      <div>
        <dt>Protocols</dt>
        <dd>{detail.summary.protocols.join(", ")}</dd>
      </div>
      <div>
        <dt>HTTP</dt>
        <dd>
          {detail.summary.httpMethod ?? "—"} / {detail.summary.httpStatus ?? "—"}
        </dd>
      </div>
      <div>
        <dt>Retained normalized source</dt>
        <dd>{detail.normalizedSourceAvailable ? "Available to host" : "Not retained"}</dd>
      </div>
    </dl>
  );
}

interface AnalyzeSurfaceProps {
  items: readonly SemanticOutputItem[];
  cursor: string | null;
  phase: LoadPhase;
  error: string | null;
  onRefresh: () => void;
  onLoadMore: () => void;
}

export function AnalyzeSurface({ items, cursor, phase, error, onRefresh, onLoadMore }: AnalyzeSurfaceProps) {
  const isBusy = phase === "loading" || phase === "loadingMore";
  return (
    <section className="panel semantic-panel" id="surface-analyze" aria-labelledby="semantic-title">
      <div className="panel-toolbar">
        <div>
          <p className="section-kicker">Derived and rebuildable</p>
          <h2 id="semantic-title">Analyzer events</h2>
        </div>
        <button className="secondary-button" type="button" disabled={isBusy} onClick={onRefresh}>
          Refresh
        </button>
      </div>

      {error !== null ? (
        <div className="notice error-notice" role="alert">
          <strong>Semantic query failed.</strong>
          <span>{error}</span>
          <button type="button" onClick={onRefresh}>
            Retry from first page
          </button>
        </div>
      ) : null}
      {phase === "loading" && items.length === 0 ? (
        <p className="loading-copy" role="status">
          Querying semantic output…
        </p>
      ) : null}
      {phase === "ready" && items.length === 0 ? (
        <div className="empty-state">
          <h3>No semantic events stored</h3>
          <p>Run the demo analyzer proof to persist rebuildable semantic output in the host index.</p>
        </div>
      ) : null}

      <div className="semantic-list">
        {items.map((item) => (
          <article className="semantic-card" key={item.eventId}>
            <header>
              <div>
                <p>{item.namespace}</p>
                <h3>{item.kind}</h3>
              </div>
              <time>{timestampLabel(item.timestampNs)}</time>
            </header>
            <p className="semantic-source">
              {item.analyzerId} {item.analyzerVersion} · source {item.sourceFlowId ?? item.captureSessionId ?? "global"}
            </p>
          </article>
        ))}
      </div>

      {cursor !== null ? (
        <button className="load-more" type="button" disabled={isBusy} onClick={onLoadMore}>
          {phase === "loadingMore" ? "Loading next page…" : "Load next page"}
        </button>
      ) : null}
    </section>
  );
}

function SettingsSurface() {
  return (
    <section className="panel settings-panel" id="surface-settings" aria-labelledby="settings-title">
      <p className="section-kicker">Enforced boundaries</p>
      <h2 id="settings-title">Local data and privileges</h2>
      <div className="settings-grid">
        <article>
          <span aria-hidden="true">01</span>
          <h3>Metadata by default</h3>
          <p>Traffic queries expose indexed normalized fields, not request or response payload bytes.</p>
        </article>
        <article>
          <span aria-hidden="true">02</span>
          <h3>Host-owned storage</h3>
          <p>The renderer cannot open the SQLite file or infer the blob-store filesystem layout.</p>
        </article>
        <article>
          <span aria-hidden="true">03</span>
          <h3>Typed privilege boundary</h3>
          <p>Network and trust-store operations remain outside the React renderer.</p>
        </article>
      </div>
    </section>
  );
}
