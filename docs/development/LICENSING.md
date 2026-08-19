# Licensing and Distribution Boundary

No project-wide LICENSE is selected during architecture bootstrap. A release/distribution milestone must choose and review project licensing deliberately.

## sing-box

The architecture intentionally treats sing-box as an independent managed runtime/process rather than linking/forking its internals into Capture Core. This is an engineering boundary and may reduce coupling, but it is **not legal advice** and does not by itself settle distribution obligations.

Before distributing binaries that bundle or download sing-box, perform a license review covering:
- the exact sing-box version and license terms;
- whether/how it is bundled, downloaded or invoked;
- source/notice obligations;
- installer/update behavior;
- any modifications or patches.

## Dependency review

PRs adding dependencies that materially affect distribution, cryptography/TLS, privileged networking or plugin sandboxing must record:
- dependency/version;
- license;
- reason for use;
- whether it is linked into shipped binaries;
- relevant attribution/source obligations.

Release automation should eventually generate a third-party notices/SBOM artifact from locked dependencies rather than maintaining a hand-written list.
