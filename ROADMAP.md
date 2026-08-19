# Roadmap

Roadmap versions are capability milestones, not calendar promises. Each version must finish its acceptance gates before work begins on dependent milestones.

## v0.1 — Architecture Proof

Goal: prove the complete vertical slice without pretending to be feature-complete.

Deliver:
- monorepo/toolchain scaffolding;
- Tauri desktop shell and local IPC boundary;
- managed sing-box runtime adapter with fake runtime for tests;
- minimal system/user/runtime config compiler and protected `__flowprobe_*` namespace;
- direct egress vertical slice;
- Capture Core connection model;
- minimum TLS interception proof with generated local CA (development install may remain manual on unsupported hosts);
- HTTP/1.x and minimum HTTP/2 normalized flow path;
- SQLite metadata store;
- Traffic list/detail proof UI;
- WASM analyzer runtime proof using `analyzer.wit`;
- demo analyzer transforms a deterministic fixture into a semantic event;
- golden fixture framework and integration test from captured fixture to semantic event.

Explicitly not complete: production TUN installers on all OSes, full proxy protocols UI, advanced capture debugger, Codex-specific parsing.

## v0.2 — Reliable TUN & System Integration

Goal: make FlowProbe a safe daily network layer.

Deliver:
- Windows, macOS, Linux TUN lifecycle implementations;
- transactional network start/stop and rollback;
- privileged helper/service design per platform;
- one-click local CA install/uninstall per platform where platform policy permits;
- process attribution capability reporting;
- process/path loop-exclusion rules;
- direct mode and external HTTP/HTTPS/SOCKS5 upstream;
- upstream connectivity test and local proxy process detection;
- UDP metadata/pass-through baseline and DNS visibility;
- crash recovery/watchdog tests.

## v0.3 — Full Proxy Client Foundation

Goal: become a credible daily sing-box client.

Deliver:
- local sing-box profiles;
- remote sing-box profile import/update;
- profile switching;
- selector and URLTest control through supported sing-box control surfaces;
- node/group status UI;
- connection view;
- visual DNS/routing basics;
- advanced raw JSON editor;
- format/validate/diff/apply workflow;
- compiled-config viewer;
- protected system overlay and reserved namespace enforcement;
- subscription/profile refresh policy and cache.

Later compatibility importers (Clash YAML, individual URI schemes) are optional follow-ups, not required for v0.3.

## v0.4 — Capture Workbench

Goal: reach a strong passive capture/debugging experience.

Deliver:
- robust HTTP/1.x and HTTP/2;
- TLS/SNI/ALPN metadata and interception fallback policy;
- SSE timeline;
- WebSocket frames;
- gRPC visibility where decodable;
- request/response body viewers (text, JSON, form, hex; images where practical);
- filtering/search by host/path/process/method/status/protocol/time;
- capture sessions, markers, retention and storage limits;
- raw/discovery capture mode;
- HAR import/export and FlowProbe session format;
- deterministic replay of saved session data through decoders.

## v0.5 — Replay & Active Debugging

Goal: expand from observation to deliberate debugging while keeping mutation opt-in.

Deliver:
- repeat request;
- edit-and-send;
- request/response compare;
- rewrite rules;
- breakpoint/intercept workflow;
- map local / map remote;
- delay/throttle/drop primitives;
- rule enable/disable visibility;
- explicit Passive vs Debug mode separation;
- audit trail of active mutation rules.

## v0.6 — Analyzer Platform v1

Goal: freeze a useful third-party analyzer SDK.

Deliver:
- Analyzer Component Model/WIT v1;
- manifest format and permission model;
- Wasmtime sandbox with no ambient network/filesystem by default;
- normalized event query APIs;
- semantic event emission API;
- analyzer-scoped storage;
- declarative cards/tables/timeseries/timeline/detail-panel schemas;
- plugin install/enable/disable/update workflow;
- analyzer replay against stored sessions;
- compatibility/version negotiation and contract tests;
- SDK examples and plugin author documentation.

## v0.7 — Codex Analyzer

Goal: prove product-semantic analysis with a real, evolving agent product.

Deliver after controlled discovery captures:
- traffic matcher with confidence rather than hard-coded assumptions alone;
- endpoint/protocol schema discovery notes and fixtures;
- Codex request/stream decoding where observable;
- turn correlation;
- request counts and timing;
- model extraction where observable;
- exact/estimated/unknown token provenance model;
- tool-call/event timeline where observable;
- hourly/daily/device-local analytics;
- graceful degradation when wire format changes;
- no dependency on replacing native OAuth or endpoints.

## v0.8 — Analytics & Data Scale

Goal: make long-running local observability practical.

Deliver:
- Parquet normalized/semantic event archives;
- DuckDB query layer;
- retention tiers;
- hourly/daily materialization;
- analyzer-defined analytics queries with resource limits;
- fast aggregate dashboards;
- export to CSV/JSON/Parquet;
- storage-health diagnostics and compaction.

## v0.9 — Plugin Ecosystem & Product Polish

Goal: make analyzers a real ecosystem and the desktop app pleasant for power users.

Deliver:
- signed/trusted plugin metadata model;
- local plugin registry UI;
- permission review UX;
- plugin developer CLI/templates;
- additional first-party/reference analyzer(s);
- polished proxy/capture/analyze navigation;
- diagnostics bundle;
- accessibility and keyboard workflows;
- update/migration framework.

## v1.0 — Production Hardening

Goal: stable public release baseline.

Deliver:
- supported Windows/macOS/Linux installation and upgrade path;
- network rollback reliability and destructive-failure tests;
- CA lifecycle hardening;
- secure local IPC and privilege separation review;
- fuzzing for protocol parsers and hostile captures;
- performance/memory limits for large sessions;
- plugin sandbox security review;
- release signing/notarization plan;
- migration/backward-compatibility policy;
- documented privacy/security model;
- end-to-end acceptance suite for Proxy Only, Capture+Direct, Capture+Built-in Proxy, and Capture+External Proxy modes.

## Post-1.0 candidates

- additional import formats and proxy ecosystem compatibility;
- mobile platforms where architecture/security model is acceptable;
- team/shareable sanitized capture bundles;
- OpenTelemetry/Prometheus export adapters;
- remote controlled lab agents without making cloud mandatory;
- richer protocol decoders and analyzer marketplace mechanisms.
