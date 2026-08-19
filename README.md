# FlowProbe Studio

FlowProbe Studio is a programmable local network debugging platform that combines three first-class capabilities:

1. **Full proxy client** — TUN capture, direct/external proxy egress, sing-box profiles, routing, DNS, selectors, URL tests, and subscription/profile management.
2. **Full traffic debugging workbench** — TLS interception, HTTP traffic inspection, sessions, replay, raw capture, filtering, timing, streaming protocol visibility, and later active debugging features.
3. **Extensible semantic analyzers** — sandboxed plugins turn generic network flows into product-level concepts such as agent turns, token usage, tool calls, models, errors, and product-specific analytics.

The first product-specific analyzer will target Codex, but FlowProbe Studio itself is product-agnostic.

## Architectural constitution

Three decisions are frozen unless changed by a dedicated Architecture Decision Record (ADR):

- **sing-box runs as an independent Network Runtime process.** Do not fork or embed it into Capture Core.
- **Capture Core is self-owned, protocol-oriented, and independent of sing-box internals.**
- **Third-party analyzers run in a WASM sandbox through a versioned contract.** Do not load arbitrary Python/native plugins in-process.

See [PRODUCT.md](PRODUCT.md), [ARCHITECTURE.md](ARCHITECTURE.md), [ROADMAP.md](ROADMAP.md), and [AGENTS.md](AGENTS.md) before making implementation changes.

## Development model

This repository is designed for AI-assisted, contract-first development. Architecture, product scope, task contracts, acceptance commands, and protected paths are versioned in the repository. Implementation agents work one milestone/task contract at a time and must not redefine product or architecture while implementing.

Start with `docs/milestones/v0.1.md` and the task contracts under `specs/tasks/v0.1/`.
