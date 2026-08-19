# sing-box Runtime Adapter AGENTS.md

- sing-box remains an independent managed runtime/process.
- Do not fork upstream or copy internal packages into FlowProbe.
- User configuration and FlowProbe system overlay are compiled through the config-compiler contract.
- `__flowprobe_*` is reserved for internal runtime objects.
- Runtime version/capability differences must be isolated here.
- Use supported control/config surfaces where possible; undocumented coupling requires an explicit ADR.
- Loop prevention and interface/process exclusion behavior must be covered by platform integration tests.
