# AGENTS.md — Repository Constitution for AI Development

This file governs every coding agent operating in this repository. More specific `AGENTS.md` files may add constraints but may not weaken these rules.

## Read order before implementation

1. `PRODUCT.md`
2. `ARCHITECTURE.md`
3. `ROADMAP.md`
4. relevant accepted ADRs in `docs/adr/`
5. relevant contracts in `docs/contracts/`
6. current milestone file in `docs/milestones/`
7. assigned task contract in `specs/tasks/`
8. nearest directory-specific `AGENTS.md`

Do not begin implementation before resolving contradictions among these artifacts.

## Frozen architectural constraints

- sing-box is an independent managed Network Runtime process.
- Capture Core is owned by FlowProbe, protocol-oriented, and independent from sing-box internals.
- Third-party analyzers execute in a WASM sandbox through versioned contracts.
- User sing-box configuration is compiled with protected system/runtime overlays; user config may not redefine `__flowprobe_*` objects.
- raw/normalized capture data is source material; semantic analyzer output is derived/rebuildable.

Changing any of these requires an explicit architecture task and ADR. An implementation agent must not make such a change for convenience.

## Task discipline

- Work only on the assigned task/milestone scope.
- Respect `allowed_paths` and `forbidden_paths` in task contracts.
- Do not opportunistically refactor unrelated modules.
- Existing contracts and accepted ADRs are read-only unless the task explicitly authorizes architecture changes.
- Existing golden fixtures are read-only unless the task is specifically a fixture/test-maintenance task.
- Do not change tests merely to make an incorrect implementation pass.

## Definition of done

A task is complete only when:
- all acceptance commands in its task contract pass;
- implementation and tests are present;
- relevant documentation is updated without changing protected contracts;
- no new unjustified TODO/FIXME/placeholder/stub is introduced;
- error paths are handled intentionally;
- `git diff` contains only task-scoped changes;
- the agent reports concrete verification evidence.

## Forbidden shortcuts

Production code must not contain unapproved:
- `TODO`, `FIXME`, placeholder or fake implementation;
- `unimplemented!()` / equivalent unimplemented branches reachable in supported paths;
- ignored/skipped tests used to hide failures;
- empty exception handlers;
- test-only mocks wired into production runtime;
- hard-coded product-specific endpoint assumptions inside generic Capture Core;
- direct analyzer access to internal SQLite files;
- arbitrary native/Python plugin loading;
- changes to architecture contracts hidden inside feature PRs.

Scaffolding tasks may create explicit interfaces with intentionally unsupported operations only when the task contract says so; unsupported behavior must return typed errors rather than pretend success.

## Testing expectations

Prefer behavior/contract tests over implementation-detail tests. Network-heavy features must be testable using fake runtimes and deterministic fixtures whenever possible. Real privileged/TUN integration tests are separate gates, not excuses to leave core logic untested.

Critical parsers must eventually receive malformed-input tests and fuzz coverage.

## Git / PR discipline

- One logical task per branch/worktree.
- Agents do not push directly to `main`.
- Every PR states task ID, scope, tests run, contract impact, security impact, and follow-up work.
- If implementation discovers a contract flaw, stop expanding scope and propose an architecture/contract change separately.

## Dependency policy

Prefer mature, actively maintained dependencies with compatible licensing. Do not add large frameworks to avoid implementing a small well-defined function. Any dependency that affects distribution licensing, privileged networking, TLS, or sandboxing must be called out in the PR.

## Security

Traffic capture software handles secrets. Never log full Authorization/Cookie headers, CA private keys, or captured credentials in normal application logs/tests. Test fixtures containing real user secrets are prohibited.
