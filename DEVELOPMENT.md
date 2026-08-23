# Development Workflow

## Principle

FlowProbe is developed as a contract-first system. Repository state is the long-term memory; individual AI conversations are disposable.

## Fresh-checkout bootstrap

The repository pins its local toolchain in `mise.toml` and independently pins Rust for Cargo/CI in `rust-toolchain.toml`.

Prerequisites:

- [mise](https://mise.jdx.dev/) with project configuration enabled;
- macOS Command Line Tools, or the platform dependencies required by Tauri;
- Git.

From a fresh checkout:

```sh
mise trust
mise install
mise run bootstrap
mise run check
```

`mise run bootstrap` installs exactly the packages in `pnpm-lock.yaml`. It does not install or start sing-box, create a TUN device, install a CA, or change system networking.

Develop the desktop shell with:

```sh
mise run dev
```

The renderer development server can also be run without the native shell:

```sh
pnpm --dir apps/desktop dev
```

### Direct acceptance commands

The foundation task's contract commands can be run directly after bootstrap:

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
python scripts/validate_tasks.py
```

The stronger local/CI gate additionally runs Clippy, the anti-shortcut checker, and desktop lint, tests, and build:

```sh
mise run check
```

The initial shell reports Network Runtime, Capture Core, and Analyzer Runtime as `notConfigured`. That is deliberate: their behavior is implemented only by their own task contracts.

## Normal implementation loop

1. Select exactly one milestone/task contract whose dependencies are satisfied.
2. Create a branch/worktree for that task.
3. Start a fresh implementation-agent context.
4. Agent reads repository constitution, contracts, milestone, task, and relevant code.
5. Implement only allowed scope.
6. Run acceptance commands and inspect diff.
7. Open a PR using the template.
8. CI runs contract, quality, unit, integration, and platform-appropriate checks.
9. Independent reviewer/verifier checks the PR against the task contract.
10. Merge only when gates pass.

## Recommended Codex invocation prompt

Use a fresh Codex context per milestone or task, for example:

> Implement the next ready task for v0.1. Read AGENTS.md, PRODUCT.md, ARCHITECTURE.md, ROADMAP.md, docs/milestones/v0.1.md, the assigned task contract, relevant contracts and nearest AGENTS.md. Do not change architecture contracts or expand scope. Run every acceptance command. Stop when the task contract is satisfied and report evidence.

For an entire version, the orchestrator/lead agent should schedule independent ready tasks into separate worktrees rather than letting one agent edit all modules concurrently in one checkout.

## Roles

- Product Owner: accepts product behavior and architecture proposals.
- Architect agent: authors/updates ADRs/contracts through explicit architecture tasks.
- Implementer agent: implements one task contract.
- Test agent: may independently author black-box/contract tests for critical tasks.
- Reviewer agent: reviews architecture/security/test quality.
- Verifier agent: re-reads task contract and independently checks acceptance evidence.

## Parallelism rule

Parallelize only across stable interfaces. If two tasks need to edit the same contract/API, sequence them or first freeze the shared contract.

## Protected artifacts

Implementation tasks treat these as read-only unless explicitly authorized:
- `PRODUCT.md`
- `ARCHITECTURE.md`
- accepted `docs/adr/**`
- `docs/contracts/**`
- existing `tests/fixtures/golden/**`

## Version completion

A version is complete only when:
- every required task contract is closed;
- milestone acceptance tests pass;
- no unresolved blocker/security issue remains;
- documentation describes actual behavior rather than intended behavior;
- an integration/verifier pass confirms the milestone end-to-end.
