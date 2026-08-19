# Security Model

FlowProbe is privileged local networking and traffic-debugging software. Security is a product requirement, not a later hardening step.

## Trust boundaries

- untrusted network input;
- TLS certificate/private-key material;
- privileged TUN/routes/trust-store helper;
- desktop webview/UI;
- sing-box managed process/configuration;
- captured payloads containing credentials/source code/private data;
- third-party analyzer WASM modules;
- imported remote profiles and rule sets.

## Baseline requirements

- CA private keys remain local and are never exposed through ordinary UI/RPC APIs.
- ordinary logs redact Authorization, Cookie, Set-Cookie, proxy credentials, and known secret fields.
- full payload/raw capture is explicit, bounded by duration/size, and visibly active.
- analyzer permissions are least privilege and reviewed at install/enable time.
- plugin runtime has no ambient filesystem/network/process access by default.
- config/profile content is treated as untrusted input and validated before activation.
- network route changes are transactional and recoverable after crashes.
- active traffic mutation is disabled in passive capture mode.

## Security-sensitive change classes

PRs touching any of these require explicit security review:
- CA generation/storage/trust installation;
- privileged helper/service;
- TUN/routes/firewall/DNS changes;
- TLS interception;
- plugin sandbox/permissions;
- raw payload persistence;
- profile download/update verification;
- updater/signing/notarization;
- IPC authentication/authorization.

## Responsible use

FlowProbe is intended for traffic the user owns or is authorized to inspect. Product features must not be framed or optimized around bypassing third-party authentication, quotas, rate limits, or protective controls.
