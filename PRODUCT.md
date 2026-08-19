# Product Definition

## One sentence

FlowProbe Studio is a local-first programmable network debugging platform that acts as a complete proxy client, a complete traffic capture/debugging tool, and a host for extensible semantic analyzers.

## Product thesis

Traditional proxy clients decide **where traffic goes**. Traditional packet/HTTP debugging tools explain **what traffic looks like**. FlowProbe Studio additionally explains **what traffic means inside a product**.

The core transformation is:

`Packet -> Connection -> Protocol -> Transaction -> Semantic Event`

Examples:

- HTTP tool: `POST /endpoint, 200, 12.4s`
- FlowProbe + Codex analyzer: `Codex turn, model X, 42k input tokens, 2.1k output tokens, 6 tool calls, 12.4s`

## Target users

- developers debugging desktop/CLI/networked products;
- power users who already use sing-box/Mihomo/Clash-like proxy tooling;
- researchers reverse-engineering their own application traffic;
- plugin authors building product-specific observability;
- AI-agent users who want local request/usage visibility without changing the agent's native authentication or endpoints.

## Core product surfaces

### Proxy

- TUN mode
- direct egress
- external HTTP/HTTPS/SOCKS5 upstream
- built-in sing-box runtime
- local and remote sing-box profiles
- DNS and route rules
- rule sets
- selector and URLTest control
- connection view
- safe process-based loop prevention
- advanced raw sing-box configuration with a protected system overlay

### Capture

- local root CA lifecycle
- TLS interception when compatible
- transparent pass-through when interception is unavailable
- HTTP/1.x and HTTP/2
- SSE and WebSocket visibility
- generic TCP/UDP metadata
- sessions and markers
- request/response viewer
- timing and byte accounting
- process attribution where supported
- raw capture mode with explicit storage limits
- replay/edit-and-send
- HAR/session import-export
- later: rewrite, breakpoint, map-local/map-remote, delay/throttle

### Analyze

- normalized protocol event model
- versioned Analyzer ABI
- WASM sandbox
- least-privilege plugin permissions
- semantic events and derived entities
- analyzer-specific dashboards/tables/timelines rendered by the host
- offline replay of historical captures through newer analyzer versions
- first-party Codex analyzer as reference implementation

## Product principles

1. **Local-first:** no cloud service is required for core functionality.
2. **Connectivity first:** inability to inspect must not unnecessarily break connectivity.
3. **Passive by default:** observation and debugging mutations are separate modes.
4. **Minimal persistence by default:** metadata is stored by default; sensitive payload capture is explicit.
5. **Reversible:** stopping TUN and uninstalling the CA restores the machine to ordinary networking.
6. **Protocol-agnostic core:** product knowledge belongs in analyzers, not Capture Core.
7. **Inspectable configuration:** users can view the final compiled sing-box runtime configuration.
8. **Power-user friendly:** advanced users retain access to native sing-box routing/DNS constructs.
9. **Contract-first plugins:** plugins never depend directly on internal databases or UI implementation.
10. **Safe extensibility:** plugin capabilities are declared and sandboxed.

## Non-goals

- account credential brokerage or OAuth replacement;
- bypassing service quotas, rate limits, protections, or access controls;
- covert interception of traffic the user does not control or have authorization to inspect;
- a remote SaaS dependency for basic capture/proxy/analyzer operation;
- treating private product wire formats as stable public APIs;
- coupling the product lifecycle to a fork of sing-box.

## Modes

### Proxy Only
`TUN -> sing-box -> egress`

### Capture + Direct
`TUN -> Capture Core -> direct egress`

### Capture + Built-in Proxy
`TUN -> Capture Core -> sing-box user routing -> selected node -> Internet`

### Capture + External Proxy
`TUN -> Capture Core -> external HTTP/SOCKS5 proxy -> Internet`

### Discovery / Raw Capture
Explicit temporary mode that preserves additional protocol/payload/timing material for reverse engineering and analyzer development.

## Success criteria for 1.0

- stable Windows/macOS/Linux desktop application;
- safe start/stop and crash recovery for TUN;
- useful proxy-client parity for common sing-box workflows;
- high-quality HTTP/TLS capture workflow;
- analyzer SDK usable without modifying the host;
- at least one mature first-party semantic analyzer;
- deterministic capture fixtures and replayable analyzer tests;
- no required cloud account.
