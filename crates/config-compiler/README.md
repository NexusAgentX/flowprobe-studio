# FlowProbe Config Compiler

This crate compiles three JSON object layers in fixed order:

1. FlowProbe-owned `SystemBase`;
2. user-owned `UserProfile`;
3. trusted ephemeral `RuntimeOverlay`.

Objects merge recursively. Arrays append in layer order; entries with the same string `tag` or `name` merge recursively so the runtime overlay can fill fields on a protected system object without guessing version-specific field names. When both identities are present they must resolve to the same existing item, and an existing secondary identity cannot be changed; a missing non-conflicting secondary identity may be added. A user layer cannot define an object key or `tag`/`name` beginning `__flowprobe_`, or mutate any field of an existing protected object; ordinary text, credential values, and routing references may contain that prefix. Neither layer can replace a non-empty object/array parent with `null`, a scalar, or another JSON type. Protected object keys also fail closed even when their object is empty. Equal protected identity leaves are preserved, while matching protected objects can receive new ordinary runtime fields without changing their existing `tag`/`name` identities. The compiled result receives a final duplicate-identity validation pass before runtime validation.

The compiler normalizes object key order and emits compact canonical JSON. It deliberately preserves unknown keys and ordinary native sing-box structures instead of maintaining a partial version-specific schema. A `RuntimeConfigValidator` supplied by the independent runtime adapter must accept the canonical JSON before the compiler constructs `CompiledConfig`. Runtime commit APIs should require `CompiledConfig`, not arbitrary JSON.

`CompiledConfig::runtime_json()` is operational material and can contain credentials. Ordinary UI and diagnostic paths must use `redacted_display_json()` and `report()`. Layer and compiled-config `Debug` implementations also use the redacted representation. Sensitive fields, header values, URI userinfo, credential query/fragment parameters, common proxy share links, and token-shaped strings are redacted.
