# Task Contract Format

Task contracts are TOML files under `specs/tasks/<milestone>/` and are machine-checked by `scripts/validate_tasks.py`.

Required fields:
- `id`
- `milestone`
- `title`
- `goal`
- `depends_on`
- `allowed_paths`
- `forbidden_paths`
- `acceptance`
- `definition_of_done`

Optional fields may add notes/security/reviewer guidance but cannot weaken root AGENTS rules.

## Semantics

`depends_on` creates the task DAG. An implementation task is ready only when every dependency is complete/merged.

`allowed_paths` describes expected edit scope. Small supporting changes outside it require explanation; protected paths remain forbidden unless explicitly authorized.

`forbidden_paths` is a hard guard for ordinary implementation tasks.

`acceptance` must be concrete commands or deterministic checks, not subjective claims such as "works well".

`definition_of_done` lists required deliverables/evidence beyond command success.

## Architecture tasks

Architecture tasks use an `ARCH-*` ID and may explicitly list protected paths in `allowed_paths`. They require an ADR/contract migration rationale and cannot be bundled into an ordinary feature task.
