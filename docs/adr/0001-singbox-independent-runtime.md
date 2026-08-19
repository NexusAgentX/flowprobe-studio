# ADR-0001: sing-box is an independent Network Runtime

Status: Accepted

## Decision

Use sing-box as a managed independent process/runtime responsible for TUN, routing, DNS, proxy protocols, selectors and user proxy profiles. Do not fork sing-box and do not link its internal implementation into Capture Core.

## Rationale

- preserves upstream evolution and feature velocity;
- isolates licensing/distribution review from proprietary/internal modules;
- gives users native sing-box configuration power;
- makes the Capture Plane replaceable/testable through a fake runtime;
- prevents capture/analyzer architecture from depending on sing-box internals.

## Consequences

- a versioned Runtime Control boundary is required;
- process lifecycle/config compilation/health checks belong to Supervisor;
- integration tests must cover supported sing-box versions;
- the product must tolerate upstream configuration migrations through a compatibility layer.
