# FlowProbe local storage

`flowprobe-storage` is a host-only boundary. It stores bounded settings,
capture-session metadata, NormalizedFlow indexes, and rebuildable semantic
event indexes in SQLite. The crate never exposes a SQLite connection, SQL, or
database path to analyzers; WASM analyzers must use versioned host capabilities.

The metadata write path deliberately projects only typed, indexable
NormalizedFlow fields. It does not serialize protocol extensions, HTTP paths,
headers, request/response bodies, or full flow JSON into SQLite. If the host
chooses to retain full normalized/raw material, it explicitly writes bytes
through `OpaquePayloadStore` and may link an opaque `BlobRef` to the flow index.
Metadata-only writes never call that API.

Semantic attributes are bounded derived data. They can be cleared or deleted
by capture session without deleting retained normalized indexes. Session
deletion cascades SQLite metadata; the host coordinator must also invoke the
payload backend's session deletion operation so its independently retained
opaque material follows the same retention boundary. For scheduled retention,
`retention_candidates` returns at most one validated page of session identities
so the coordinator can apply the payload and metadata deletions to the same
explicit set; incomplete sessions are never selected. An existing semantic
event ID cannot be reassigned to a different source boundary during an upsert.

The v0 deterministic payload backend is memory-backed and bounded by item,
byte, and entry limits. It exposes only `BodyRef`/`BlobRef`, never a storage
location. A durable filesystem/session backend can implement the same host
trait without changing consumers.

SQLite paths are treated as literal host paths rather than SQLite URIs, and a
symbolic link in the final path component is rejected. On Unix the initialized
database is restricted to owner read/write permissions. Secure deletion is
enabled so deleted values are overwritten in live SQLite pages; filesystem
snapshots, backups, and physical-media recovery remain host responsibilities.

SQLite is supplied by `rusqlite` 0.40 with the `bundled` feature for a
reproducible cross-platform schema/runtime. `rusqlite` is MIT licensed and
SQLite is public domain. This choice increases the shipped native binary size
and must be included in distribution license notices.
