# Contract: Network Runtime Control v0

Status: Draft for v0.1

The Supervisor controls a Network Runtime through capability-oriented operations rather than sing-box internals.

Required conceptual operations:
- validate generated runtime configuration;
- start runtime;
- stop runtime;
- query health/state;
- apply/reload configuration when supported;
- report runtime version/capabilities;
- query/select proxy groups through supported control surfaces;
- expose connection/status information when available.

A `FakeNetworkRuntime` must implement the same host-facing contract for tests.

Runtime-specific configuration structures stay behind the adapter/config compiler boundary. Other crates must not parse sing-box internal state directly.
