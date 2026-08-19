# ADR-0003: Analyzers use a versioned WASM sandbox

Status: Accepted

## Decision

Third-party semantic analyzers execute as WebAssembly components/modules behind a versioned Analyzer contract. The host provides explicit capabilities for normalized events, approved historical queries, analyzer-scoped storage and semantic output.

Do not make arbitrary in-process Python scripts or native dynamic libraries the primary plugin system.

## Rationale

Analyzers may inspect highly sensitive traffic. A capability-oriented WASM boundary enables stronger isolation, deterministic contracts, cross-language plugin development and controlled resource limits.

## Consequences

- the Analyzer ABI must be deliberately versioned;
- plugins declare permissions in a manifest;
- no ambient network/filesystem/process execution by default;
- host UI is declarative for third-party plugins rather than arbitrary injected JavaScript.
