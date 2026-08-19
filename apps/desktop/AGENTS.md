# Desktop AGENTS.md

- Desktop UI uses Tauri + React/TypeScript unless an explicit architecture task changes it.
- Renderer/UI must not directly perform privileged network/trust-store operations.
- All privileged actions cross a typed local IPC boundary.
- UI may consume normalized DTOs but must not parse sing-box runtime internals directly.
- Third-party analyzer UI is declarative; do not inject arbitrary plugin JavaScript into the host renderer.
- Keep Proxy, Capture, Analyze and Settings as separable product surfaces even when navigation is initially minimal.
