# Storage AGENTS.md

- SQLite is the v0.x operational metadata/index store; storage APIs must hide concrete file layout from analyzers/UI.
- Raw bodies/streams are stored as opaque blob references rather than oversized SQLite rows by default.
- Semantic events are derived and rebuildable from retained source data.
- Tests must cover schema migration from the first persisted version onward.
- Never persist sensitive payloads in metadata-only mode by accident.
