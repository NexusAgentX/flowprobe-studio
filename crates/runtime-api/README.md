# FlowProbe Network Runtime API

`flowprobe-runtime-api` is the supervisor-facing NetworkRuntime v0 boundary.
It describes lifecycle, health, configuration, capability, proxy-group,
connection, status, and direct-egress-probe operations without exposing
sing-box implementation details.

Runtime commit operations accept only `CompiledConfig`, so arbitrary JSON
cannot bypass the configuration compiler. Optional operations report typed
`Unsupported` errors. `FakeNetworkRuntime` implements the same trait with a
deterministic lifecycle, one-shot failure injection, and redaction-safe
operation records for unit and integration tests.
