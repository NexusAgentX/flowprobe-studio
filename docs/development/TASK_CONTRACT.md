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

## Trusted repository governance

This disposable sentence exercises the GOV-001 protected-branch canary and is
intentionally never merged.

The repository governance boundary trusts current NexusAgentX organization
owners and repository administrators. Those actors can change workflows,
CODEOWNERS, and remote protection settings, so this mechanism does not claim
to withstand a malicious or compromised owner or administrator. Pull-request
code and every other actor are untrusted.

The proposed-head and trusted-base signals are intentionally isolated:

- `.github/workflows/contract.yml` listens only to `pull_request` and pushes
  to `main`. It is the only workflow that emits `contracts`, `Rust workspace`,
  and `Desktop renderer`.
- `.github/workflows/task-scope-trusted.yml` listens only to
  `pull_request_target` activity types `opened`, `synchronize`, `reopened`, and
  `edited` for base branch `main`. It is the only base workflow that emits
  `Task scope (trusted base)`.
- The trusted job has no job-level condition or `continue-on-error`. Its
  checkout, exact-head attestation, and scope-enforcement steps are mandatory.
  It checks out and executes only the pull request's base revision; it fetches
  the proposed head solely as Git objects for the base-owned scope checker.
- Every workflow grants only `contents: read` and pins third-party Actions to
  full commit identities. No workflow may approve a pull request.

GitHub records a skipped or neutral job as successful for required-check
purposes, and classic branch protection binds a required check to an app and
context name rather than to a workflow path. Therefore workflow separation is
necessary but not sufficient evidence by itself. The live canaries below must
prove fail-closed behavior for body-only edits, duplicate same-app check names,
and proposed-head failures.

### Post-merge remote enforcement

Apply remote settings only after both workflows and CODEOWNERS are present on
`main`. Repository files describe the desired policy; they are not evidence
that GitHub is enforcing it.

Restrict Actions to read-only workflow tokens, full-SHA pins, and the five
repositories used by the checked-in workflows:

```text
gh api --method PUT \
  repos/NexusAgentX/flowprobe-studio/actions/permissions \
  -F enabled=true \
  -f allowed_actions=selected \
  -F sha_pinning_required=true

gh api --method PUT \
  repos/NexusAgentX/flowprobe-studio/actions/permissions/selected-actions \
  -F github_owned_allowed=false \
  -F verified_allowed=false \
  -f 'patterns_allowed[]=actions/checkout@*' \
  -f 'patterns_allowed[]=actions/setup-python@*' \
  -f 'patterns_allowed[]=actions/setup-node@*' \
  -f 'patterns_allowed[]=dtolnay/rust-toolchain@*' \
  -f 'patterns_allowed[]=pnpm/action-setup@*'

gh api --method PUT \
  repos/NexusAgentX/flowprobe-studio/actions/permissions/workflow \
  -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=false
```

Protect `main` with strict checks from GitHub Actions app id `15368`, an
independent code-owner approval, stale-review dismissal, last-push approval by
someone other than the pusher, administrator enforcement, and no bypass,
force-push, or deletion allowance:

```text
jq -n '{
  required_status_checks: {
    strict: true,
    checks: [
      {context: "contracts", app_id: 15368},
      {context: "Rust workspace", app_id: 15368},
      {context: "Desktop renderer", app_id: 15368},
      {context: "Task scope (trusted base)", app_id: 15368}
    ]
  },
  enforce_admins: true,
  required_pull_request_reviews: {
    dismissal_restrictions: {},
    dismiss_stale_reviews: true,
    require_code_owner_reviews: true,
    required_approving_review_count: 1,
    require_last_push_approval: true,
    bypass_pull_request_allowances: {users: [], teams: [], apps: []}
  },
  restrictions: null,
  required_linear_history: false,
  allow_force_pushes: false,
  allow_deletions: false,
  block_creations: false,
  required_conversation_resolution: false,
  lock_branch: false,
  allow_fork_syncing: false
}' | gh api --method PUT \
  repos/NexusAgentX/flowprobe-studio/branches/main/protection \
  --input -
```

Capture live evidence with these read-only endpoints after configuration:

```text
gh api repos/NexusAgentX/flowprobe-studio/branches/main/protection
gh api repos/NexusAgentX/flowprobe-studio/actions/permissions
gh api repos/NexusAgentX/flowprobe-studio/actions/permissions/selected-actions
gh api repos/NexusAgentX/flowprobe-studio/actions/permissions/workflow
gh api repos/NexusAgentX/flowprobe-studio/codeowners/errors
gh api repos/NexusAgentX/flowprobe-studio/collaborators --paginate
```

The GOV-001 live acceptance uses disposable pull requests that are all closed
unmerged and whose branches are deleted:

1. A valid allowed-path pull request proves all four required checks are bound
   to its exact head and app id, remains blocked before code-owner approval,
   becomes eligible after approval, becomes blocked after a new push, and is
   eligible only after a different trusted owner approves that latest push.
2. On one unchanged head SHA, edit a previously valid body to a backticked or
   otherwise invalid task identity. The `edited` event must create a new
   blocking trusted failure despite the earlier success on that SHA. A separate
   out-of-scope change must also remain unmergeable.
3. An allowed proposed-head workflow change emits a forged successful
   `Task scope (trusted base)` from `pull_request` while the real
   `pull_request_target` check fails on the same SHA. Both checks come from app
   id `15368`; run and check APIs must distinguish their workflow paths/events,
   and branch protection must remain blocking.
4. A proposed-head `contracts` failure with a successful trusted scope check
   must remain blocking. No target run may create skipped-success duplicates of
   `contracts`, `Rust workspace`, or `Desktop renderer`.

GOV-001 and the v0.1 release remain open until the exact API snapshots,
canaries, merged-main release audit, and an independent P0-P2-zero review all
pass.

## Architecture tasks

Architecture tasks use an `ARCH-*` ID and may explicitly list protected paths in `allowed_paths`. They require an ADR/contract migration rationale and cannot be bundled into an ordinary feature task.
