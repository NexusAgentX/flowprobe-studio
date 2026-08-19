# Analyzer Runtime AGENTS.md

- Use Wasmtime/WASM boundary; do not add native dynamic-library or arbitrary Python plugin execution as a shortcut.
- Plugins get explicit host capabilities only.
- No ambient filesystem/network/process access by default.
- ABI/contract changes require a dedicated contract task and compatibility discussion.
- Plugins cannot open SQLite/Parquet files directly; expose host query/storage capabilities.
- Enforce execution/resource limits and deterministic error reporting.
