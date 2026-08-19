# ADR-0002: FlowProbe owns a protocol-agnostic Rust Capture Core

Status: Accepted

## Decision

Capture, TLS interception, protocol decoding, normalized flow generation, recording and replay primitives are implemented in a FlowProbe-owned Rust subsystem. Capture Core consumes generic original-destination connections/streams and does not know sing-box routing semantics or product-specific agent semantics.

## Rationale

- creates a stable debugging product independent of proxy engine churn;
- Rust is appropriate for untrusted protocol parsing, desktop/native integration and Wasmtime embedding;
- generic capture fixtures can be tested without privileged TUN access;
- product-specific reverse engineering remains in analyzer plugins.

## Consequences

- protocol contracts and fixtures are first-class assets;
- Capture Core needs explicit backpressure/resource limits;
- malformed input must not panic the host;
- real TUN tests are integration gates, not unit-test dependencies.
