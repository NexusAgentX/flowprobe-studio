# Analyzer sandbox contract fixtures

`artifacts/adversarial_analyzer.wasm` is built from the adjacent `guest` crate.
It contains deterministic branches that request excess fuel, memory, host
reads, semantic output, and logs, plus explicit guest errors and traps. The
runtime tests prove that each failure remains typed and the host remains usable.
`artifacts/invalid_info_analyzer.wasm` is the same source built with the
`invalid-info` feature to verify analyzer metadata/version validation.
`artifacts/hostile_info_analyzer.wasm` uses `hostile-info` to prove `info()`
cannot call real host capabilities before its metadata is validated.

Regenerate the fixture after changing its source:

```sh
mise exec -- rustup target add wasm32-unknown-unknown
mise exec -- cargo build \
  --manifest-path tests/contract/analyzer/guest/Cargo.toml \
  --target wasm32-unknown-unknown --release
mise exec -- cargo run -p flowprobe-analyzer-runtime --example componentize -- \
  tests/contract/analyzer/guest/target/wasm32-unknown-unknown/release/flowprobe_adversarial_analyzer_fixture.wasm \
  tests/contract/analyzer/artifacts/adversarial_analyzer.wasm

mise exec -- cargo build \
  --manifest-path tests/contract/analyzer/guest/Cargo.toml \
  --target wasm32-unknown-unknown --release --features invalid-info
mise exec -- cargo run -p flowprobe-analyzer-runtime --example componentize -- \
  tests/contract/analyzer/guest/target/wasm32-unknown-unknown/release/flowprobe_adversarial_analyzer_fixture.wasm \
  tests/contract/analyzer/artifacts/invalid_info_analyzer.wasm

mise exec -- cargo build \
  --manifest-path tests/contract/analyzer/guest/Cargo.toml \
  --target wasm32-unknown-unknown --release --features hostile-info
mise exec -- cargo run -p flowprobe-analyzer-runtime --example componentize -- \
  tests/contract/analyzer/guest/target/wasm32-unknown-unknown/release/flowprobe_adversarial_analyzer_fixture.wasm \
  tests/contract/analyzer/artifacts/hostile_info_analyzer.wasm
```

The WAT contract cases remain inline in the Rust tests so forbidden ambient
filesystem, network, and process imports and wrong WIT versions are readable in
review.

After regeneration, verify every checked-in component byte-for-byte:

```sh
mise exec -- python tests/contract/analyzer/verify_artifacts.py
```
