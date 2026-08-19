# Repository Layout

The repository grows into this monorepo shape as milestone tasks scaffold real code. Do not create fake code solely to make directories exist.

```text
flowprobe-studio/
├── apps/
│   └── desktop/                 # Tauri + React/TypeScript desktop UI
├── crates/
│   ├── supervisor/              # lifecycle, IPC coordination, privileged boundary
│   ├── runtime-api/             # NetworkRuntime host-facing contract
│   ├── config-compiler/         # system + user + runtime sing-box configuration
│   ├── model/                   # normalized/shared DTOs
│   ├── protocol/                # protocol-neutral event/model helpers
│   ├── capture-core/            # TLS/protocol capture and recording
│   ├── storage/                 # SQLite/blob then Parquet/DuckDB adapters
│   ├── analyzer-runtime/        # Wasmtime host
│   ├── plugin-sdk/              # analyzer SDK bindings/helpers
│   └── ipc/                     # typed local IPC schema/bindings
├── runtime/
│   └── singbox/                 # independent sing-box process adapter/resources
├── plugins/
│   ├── demo/                    # v0.1 architecture-proof analyzer
│   └── codex/                   # introduced in v0.7
├── tests/
│   ├── contract/
│   ├── fixtures/
│   │   ├── tls/
│   │   ├── http1/
│   │   ├── http2/
│   │   └── golden/
│   ├── integration/
│   └── e2e/
├── docs/
│   ├── adr/
│   ├── contracts/
│   ├── development/
│   └── milestones/
├── specs/
│   └── tasks/                   # machine-readable milestone DAGs
├── scripts/                     # deterministic validation/developer tooling
└── tools/
    └── ai/                      # future Foreman/orchestration tooling
```

Directory ownership is enforced primarily through task `allowed_paths`/`forbidden_paths` and nearest `AGENTS.md`, not by social convention alone.
