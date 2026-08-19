# Plugin AGENTS.md

- Plugins target the versioned Analyzer WASM contract.
- Product-specific traffic knowledge belongs here, not in Capture Core.
- Each analyzer must use fixtures and expose confidence/provenance when inference is uncertain.
- Never label estimated values as exact.
- Plugin manifests declare required capture permissions.
- Test fixtures must be sanitized and contain no real credentials, private source code or user secrets.
