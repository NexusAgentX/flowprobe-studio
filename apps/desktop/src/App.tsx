import { useEffect, useState } from "react";

import { getAppStatus, type AppStatus } from "./ipc";
import { summarizeStatus } from "./status";

const surfaces = ["Proxy", "Capture", "Analyze", "Settings"] as const;

export function App() {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    void getAppStatus()
      .then((nextStatus) => {
        if (active) {
          setStatus(nextStatus);
          setError(null);
        }
      })
      .catch((reason: unknown) => {
        if (active) {
          setError(reason instanceof Error ? reason.message : String(reason));
        }
      });

    return () => {
      active = false;
    };
  }, []);

  const summary = summarizeStatus(status, error);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span>FlowProbe</span>
        </div>
        <nav aria-label="Product surfaces">
          <ul className="surface-list">
            {surfaces.map((surface, index) => (
              <li className={index === 0 ? "nav-item active" : "nav-item"} key={surface}>
                {surface}
              </li>
            ))}
          </ul>
        </nav>
      </aside>

      <main>
        <header>
          <div>
            <p className="eyebrow">Architecture proof</p>
            <h1>Local network observability, ready to connect.</h1>
          </div>
          <div className={`status ${summary.tone}`} role="status">
            <span aria-hidden="true" />
            {summary.label}
          </div>
        </header>

        <section className="foundation-card" aria-labelledby="foundation-title">
          <p className="eyebrow">Foundation</p>
          <h2 id="foundation-title">Desktop and supervisor boundary</h2>
          <p>
            The renderer can query typed status data. Network, capture, and analyzer runtimes remain explicitly
            unconfigured until their task contracts are implemented.
          </p>
          <dl>
            <div>
              <dt>Network runtime</dt>
              <dd>{status?.networkRuntime ?? "checking"}</dd>
            </div>
            <div>
              <dt>Capture core</dt>
              <dd>{status?.captureCore ?? "checking"}</dd>
            </div>
            <div>
              <dt>Analyzer runtime</dt>
              <dd>{status?.analyzerRuntime ?? "checking"}</dd>
            </div>
          </dl>
        </section>
      </main>
    </div>
  );
}
