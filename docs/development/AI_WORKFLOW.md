# AI Development Workflow

## Goal

Make AI implementation fast and parallel without allowing agents to redefine the product, silently weaken tests, or accumulate cross-module coupling.

## Repository is the memory

Do not depend on a long-lived chat context. Every fresh agent must be able to reconstruct the current contract from repository files.

The authoritative order is:
1. product definition;
2. accepted ADRs;
3. architecture/contracts;
4. milestone contract;
5. task contract;
6. code/tests.

If lower layers conflict with higher layers, the task is blocked until the conflict is resolved explicitly.

## One task, one worktree

Each implementation task runs in a separate Git worktree/branch. Parallel work is allowed only when task dependencies are satisfied and interfaces are already frozen.

Suggested branch form: `task/<task-id>-short-name`.

## Agent roles

### Architect
May change ADRs/contracts only through an explicit architecture task. Does not opportunistically implement broad product features.

### Implementer
Owns one task contract. Cannot expand scope or alter protected architecture artifacts unless authorized.

### Independent test agent
For critical networking/TLS/sandbox tasks, writes black-box tests from the contract rather than from the implementer's reasoning.

### Reviewer
Checks architecture boundary, security impact, dependency quality, test quality, and unnecessary complexity.

### Verifier
Reads the task contract from scratch and confirms every acceptance command/evidence item. The verifier must not rely solely on the implementer's completion claim.

## Recommended Codex loop for one task

1. Open fresh worktree.
2. Prompt Codex to read root and local AGENTS files plus task dependencies/contracts.
3. Ask it to implement only the selected task.
4. Require acceptance commands before completion.
5. Inspect diff and open PR.
6. Use a fresh Codex/reviewer context for review/verifier.

## Recommended Codex loop for one version

A lead/orchestrator context may:
- parse all task contracts for the milestone;
- identify tasks with all dependencies complete;
- allocate independent tasks to worktrees/subagents;
- never allow two agents to edit a shared contract concurrently;
- collect PR/CI status;
- schedule integration/verifier tasks only after dependencies merge.

The lead agent must not bypass task contracts to "finish the version faster".

## Standard version prompt

> Implement milestone vX.Y from this repository. First read AGENTS.md, PRODUCT.md, ARCHITECTURE.md, ROADMAP.md, docs/milestones/vX.Y.md, docs/contracts, accepted ADRs, and specs/tasks/vX.Y. Build the task DAG from depends_on. Work only on ready tasks, preferably one worktree per independent task. Never modify protected architecture/contracts unless a task explicitly permits it. For each task run all acceptance commands and open/review a task-scoped PR. Complete the milestone only after every required task and milestone exit criterion passes.

## Anti-shortcut rules

CI and reviewers should reject:
- production TODO/FIXME/placeholder code outside explicitly scoped scaffolding;
- tests disabled to get green CI;
- existing golden fixtures altered by ordinary feature tasks;
- fake implementations returning success;
- generic Capture Core logic containing product-specific hosts/endpoints;
- direct plugin access to internal database files;
- architecture changes buried in implementation commits.

## Future Foreman

A later developer-tooling task may implement `tools/ai/foreman` that:
- loads task TOML files;
- validates dependencies;
- creates worktrees;
- invokes Codex non-interactively;
- runs acceptance commands;
- pushes task branches/opens PRs;
- dispatches independent reviewers.

Foreman is an orchestrator, not a replacement coding agent. Repository contracts remain authoritative.
