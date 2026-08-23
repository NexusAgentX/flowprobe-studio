# Deterministic demo analyzer

The demo implements the protected Analyzer v0.1 WIT world. It reads one
sanitized NormalizedFlow fixture through the authorized host capability and
emits one `flowprobe.demo/fixture-observed` semantic event. It has no direct
filesystem, network, process, clock, randomness, or SQLite access.

`manifest.json` declares the two capabilities used by the component. The
`proof-v0` manifest marker is intentionally not the future v0.6 stable plugin
manifest contract.

The checked-in component lets `cargo test` run from a clean checkout without a
second Rust target. Regenerate it with the pinned mise Rust toolchain:

```sh
mise exec -- rustup target add wasm32-unknown-unknown
mise exec -- python tests/contract/analyzer/verify_artifacts.py --write
```

This is the only supported artifact-writing path. It performs locked offline
builds in isolated temporary targets, remaps local source/toolchain paths, and
rejects local absolute paths in the resulting component.

`wit-bindgen` generates canonical-ABI export shims containing unsafe code, so
this guest package narrowly allows generated unsafe code. The analyzer
implementation has no handwritten unsafe block. `wit-bindgen` is
`Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`.

Verify without writing that the demo and adversarial checked-in artifacts are
byte-for-byte outputs of their current source with:

```sh
mise exec -- python tests/contract/analyzer/verify_artifacts.py
```
