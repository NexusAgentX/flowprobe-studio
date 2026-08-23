# Managed sing-box Runtime Adapter

This crate manages sing-box as an independent process through its documented
CLI surface. It invokes the configured executable directly with fixed argument
positions; no shell is involved. Generated configuration is written to a
mode-`0600` file in a non-writable-by-others state directory and removed on
validation completion or managed process cleanup. Cleanup failures are typed
and retryable instead of being reported as success.

The adapter implements configuration checking, version reporting, start,
health/state/status, and idempotent stop. It reports direct-egress support as a
configuration/runtime capability after the generated direct outbound passes the
same `check` and `run` path. This does not claim external reachability. Reload,
caller-provided direct reachability probes, proxy groups, and connection listing
return typed unsupported results until an explicit documented control surface is
configured. The real local-target end-to-end direct-path proof belongs to
`INT-001`, where the caller can supply a temporary target without hard-coding a
product endpoint.

On Unix, the adapter uses the MIT-licensed `nix` crate only for process-group
`SIGTERM`/`SIGKILL` cleanup. It adds no privileged networking, TLS, or sing-box
library dependency. Non-Unix builds still bound and clean up the managed child,
but platform-specific descendant-tree lifecycle hardening remains part of the
cross-platform runtime work in v0.2.
