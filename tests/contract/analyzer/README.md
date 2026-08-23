# Analyzer sandbox contract fixtures

`artifacts/adversarial_analyzer.wasm` is built from the adjacent `guest` crate.
It contains deterministic branches that request excess fuel, memory, host
reads, semantic output, and logs, plus explicit guest errors and traps. The
runtime tests prove that each failure remains typed and the host remains usable.
`artifacts/invalid_info_analyzer.wasm` is the same source built with the
`invalid-info` feature to verify analyzer metadata/version validation.
`artifacts/hostile_info_analyzer.wasm` uses `hostile-info` to prove `info()`
cannot call real host capabilities before its metadata is validated.

The checked-in components are produced only by `verify_artifacts.py`. The
script builds with the locked dependency graphs in offline mode, disables
incremental compilation, gives every artifact/feature an independent temporary
Cargo target directory, and componentizes from a separate temporary target.
It sets `CARGO_ENCODED_RUSTFLAGS` with stable `--remap-path-prefix` mappings for
the checkout root, the actual Cargo registry source and Cargo home, and the
active rustc sysroot. Neither verification nor regeneration leaves `target` or
temporary build directories in the repository.

Install the pinned target once, then regenerate all four artifacts:

```sh
mise exec -- rustup target add wasm32-unknown-unknown
mise exec -- python tests/contract/analyzer/verify_artifacts.py --write
```

Verify every checked-in component byte-for-byte without modifying it:

```sh
mise exec -- python tests/contract/analyzer/verify_artifacts.py
```

Both modes actively reject a generated or checked-in artifact containing the
current checkout, home, Cargo home/registry, or rustc sysroot absolute path.
Reproducibility review should run verification from two real checkout paths and
two distinct (non-symlink) Cargo homes; matching printed SHA-256 values prove
that all four component bytes are independent of those local paths.

The WAT contract cases remain inline in the Rust tests so forbidden ambient
filesystem, network, and process imports, exact-name imports with the wrong
function shape, wrong exports, and wrong WIT versions are readable in review.
