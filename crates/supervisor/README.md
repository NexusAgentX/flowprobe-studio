# Supervisor runtime boundary

The supervisor owns an `Arc<dyn NetworkRuntime>` and forwards lifecycle and
capability-oriented operations through that trait. It has no dependency on the
sing-box adapter or its process/configuration representation, so host tests use
the deterministic `FakeNetworkRuntime` without spawning a network process.

The host must call `stop_network_runtime` during its bounded shutdown sequence.
Dropping a supervisor is not treated as a successful shutdown because another
owner may still hold the shared runtime; the final managed adapter owner retains
only a best-effort process cleanup fallback.

The existing foundation IPC status DTO cannot represent a configured subsystem.
Until that versioned IPC contract grows such a state, runtime health and status are
returned only through the typed supervisor methods and are never inferred.
