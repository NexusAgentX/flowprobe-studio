# Contract: Runtime Config Compiler v0

Status: Draft for v0.1

Input layers:
1. System Base owned by FlowProbe.
2. User Profile containing supported sing-box configuration.
3. Runtime Overlay containing ephemeral ports/interfaces/process exclusions/mode state.

Output: a validated compiled sing-box configuration plus a structured diagnostic report and redacted display form.

Rules:
- names beginning `__flowprobe_` are reserved;
- user input cannot overwrite/delete protected internal objects;
- user configuration retains ordinary sing-box DNS/routing/outbound/group capabilities;
- compilation is deterministic for identical normalized inputs;
- secrets are redacted from diagnostics/UI representations;
- validation occurs before TUN/routes are committed;
- users can inspect the final compiled configuration (with sensitive values redacted where appropriate).
