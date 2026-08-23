# FlowProbe desktop architecture proof

The v0.1 desktop shell is a Tauri host with a React renderer. The renderer has
no SQLite, filesystem, network-runtime, or trust-store capability. It can only:

- query supervisor status;
- request bounded pages of normalized flow metadata;
- request one metadata-only flow detail by identity;
- request bounded pages of rebuildable semantic analyzer output.

The local `main` window capability has an empty permission list and no remote
origins. This denies Tauri core and plugin permissions by default. The four
application-specific commands above remain explicit local
`invoke_handler` commands in the Tauri host; each command accepts a typed,
host-validated request rather than granting a general renderer capability.

Rust DTOs in `crates/ipc` generate the checked-in TypeScript client under
`src/ipc/generated.ts`. The Rust binding test fails if those two sides drift.
Traffic cursors are opaque, bounded host-side tokens; request/response payload
references and database layout do not cross into the renderer. Arbitrary
analyzer attribute objects also remain host-side: the ordinary Analyze list
only receives event identity, provenance, namespace, kind, and timestamp.

The Tauri host opens the host-owned metadata database in the platform app-data
directory. Empty stores produce honest empty states; the UI does not seed demo
records or report unconfigured runtimes as ready.

Run the renderer gates with:

```sh
mise exec -- pnpm --dir apps/desktop lint
mise exec -- pnpm --dir apps/desktop test
mise exec -- pnpm --dir apps/desktop build
```

Keyboard navigation uses Command/Control + 1 through 4 for Proxy, Capture,
Analyze, and Settings. Escape closes an open Traffic detail panel.
