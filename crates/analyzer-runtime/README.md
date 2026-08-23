# FlowProbe Analyzer Runtime proof

This crate executes the protected `flowprobe:analyzer@0.1.0` WIT world with
Wasmtime's Component Model. A component is accepted only when it imports the
exact v0.1 `types` and `host` instances and exports the required `info` and
`analyze` functions.

The linker does not install WASI. Ambient filesystem, network, socket, clock,
randomness, environment, and process imports are rejected before
instantiation. The remaining WIT capabilities are granted independently with
`AnalyzerPermissions`: read the current authorized event, emit a semantic
event, and write a bounded analyzer log. An analyzer cannot select an unrelated
event reference, receive a database path, or open SQLite through this API.

Every call receives a fresh Wasmtime store. Deterministic fuel, canonical NaN
handling, linear-memory/table/instance limits, component/input limits,
host-call limits, semantic-output limits, and log limits are applied before
data reaches the host. Host event JSON must be a bounded object. Semantic
attributes must be a bounded JSON object and are reserialized in canonical key
order. Wasmtime details and guest error strings are mapped to typed errors
without embedding captured traffic or plugin-provided log text.

Analyzer v0.1 keeps ordinary WebAssembly SIMD but disables relaxed SIMD because
its permitted results can vary across CPU architectures. Wasmtime is also built
with default features disabled and a narrow feature allowlist that omits its
`threads` feature; otherwise an untrusted component could execute an indefinite
atomic wait without consuming fuel. Contract tests require components requesting
either proposal to be rejected during compilation.

Memory and table growth rejected by the runtime limiter have stable typed
errors. Wasmtime also enforces the configured counts of core instances, tables,
and memories during instantiation. Count-limit failures are deliberately
reported as the deterministic generic `InstantiationFailed` error: the runtime
does not parse unstable engine error strings to manufacture a more specific
classification.

The v0.1 runtime deliberately depends on a host capability trait instead of
`flowprobe-storage`. A later integration layer may implement that trait using
the host-owned storage crate; a WASM component never receives SQLite handles,
SQL, or a database path. A persistence adapter should buffer semantic events
and commit them only after a successful invocation, using the returned analyzer
identity plus the authorized source event to construct host-owned storage
identity/provenance. This avoids partial derived output when a guest traps.

The runtime uses Wasmtime 48 (`Apache-2.0 WITH LLVM-exception`) with default
features disabled and only the synchronous Component Model, Cranelift, runtime,
standard-library, and error support enabled. WAT parsing is a test-only
dependency, so production component loading accepts WebAssembly binary rather
than expanding the input surface to text format. `semver` and
`serde_json` are dual `MIT OR Apache-2.0`. `wit-component`, used only by the
artifact regeneration example, is
`Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`.
