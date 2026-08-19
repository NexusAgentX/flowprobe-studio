# Contract: Local Storage v0

Status: Draft for v0.1

Storage is accessed through host abstractions, not by plugins opening database files.

v0.1 responsibilities:
- SQLite for settings, capture-session metadata, normalized-flow indexes and semantic event indexes;
- opaque blob references for optional request/response/raw payload material;
- deterministic test backend for contract tests.

Longer-term extension:
- Parquet archives for normalized/semantic event history;
- DuckDB analytical query layer.

Rules:
- raw/normalized source material can be retained independently of analyzer output;
- semantic output is rebuildable;
- deletion/retention policies operate by capture/session boundaries where practical;
- ordinary metadata mode must not silently persist full sensitive payloads.
