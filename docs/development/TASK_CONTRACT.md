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

`allowed_paths` is a hard edit boundary. Every added, modified, deleted, copied,
or renamed endpoint must match it. Root manifests, lockfiles, mise configuration,
generated bindings, and other supporting files have no implicit exception: add
them to a task contract before implementation if the task needs to change them.
Explaining an out-of-scope change in a pull request does not authorize it.

`forbidden_paths` is a hard guard for ordinary implementation tasks and takes
precedence if a path also matches `allowed_paths`.

Path entries are repository-relative exact paths or directory prefixes ending
in `/**`. Absolute paths, parent traversal, backslashes, control characters,
and other wildcard forms are invalid.

`acceptance` must be concrete commands or deterministic checks, not subjective claims such as "works well".

`definition_of_done` lists required deliverables/evidence beyond command success.

## Pull-request scope gate

Each task pull request body contains exactly one line in this form:

```text
Task ID: SCOPE-001
```

The trusted-base CI gate reads an ordinary task contract from the pull
request's base revision, not from its head or the runner working tree. It uses
the merge base for the proposed diff, checks both endpoints of renames and
copies, and fails closed when Git history, identity, contracts, patterns, or
paths cannot be read unambiguously.

A planning bootstrap is the only missing-base-contract case. A `PLAN-NNN`
pull request may add regular `specs/tasks/v*/NNN.toml` files and nothing else.
The new contracts must validate as one acyclic DAG with the trusted base. The
bootstrap never authorizes implementation, documentation, workflow, manifest,
or lockfile changes in the same pull request.

Run a task-scope check locally from its branch with explicit trusted refs:

```text
python -B scripts/check_task_scope.py check \
  --task SCOPE-001 --base-ref origin/main --head-ref HEAD
```

Historic nonconformance records are evidence, not waivers. The canonical v0.1
record is verified offline with:

```text
python -B scripts/check_task_scope.py audit \
  --ledger specs/nonconformance/v0.1/task-scope.toml
```

## Architecture tasks

Architecture tasks use an `ARCH-*` ID and may explicitly list protected paths in `allowed_paths`. They require an ADR/contract migration rationale and cannot be bundled into an ordinary feature task.
