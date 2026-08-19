# Capture Core AGENTS.md

- Rust subsystem; do not import/link sing-box implementation internals.
- No Codex/Claude/Gemini/product-specific endpoint logic belongs here.
- Protocol decoding emits normalized contract types.
- Payload persistence uses opaque storage references; do not assume filesystem layout.
- Untrusted/malformed network input must return structured errors and must not panic the host.
- New protocol behavior requires deterministic fixtures/tests.
- Resource/backpressure limits must be explicit for unbounded streams.
