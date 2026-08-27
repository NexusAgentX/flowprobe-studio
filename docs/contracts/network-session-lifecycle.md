# Contract: Transactional Network Session Lifecycle v0.2

Status: Normative for v0.2

This contract defines the shared lifecycle for a FlowProbe system-network
session. It is a new layer above the v0.1 Network Runtime Control contract. A
runtime process being `Running` or `Stopped` does not prove that a network
session is active, rolled back, or safe.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## Scope and preserved boundaries

This contract owns:

- single-writer session orchestration;
- generation and lease fencing;
- transactional activation and rollback;
- durable resource ownership and crash/boot recovery;
- typed capability, readiness, state, and failure reporting; and
- common extension envelopes for later v0.2 architecture contracts.

It does not define proxy egress or loop-exclusion policy, CA/trust-store
semantics, or UDP/DNS visibility. Those belong to ARCH-002, ARCH-003, and
ARCH-004 respectively.

The following accepted boundaries remain unchanged:

- sing-box is an independent managed Network Runtime process behind the
  versioned Network Runtime Control boundary;
- Capture Core is protocol-oriented and independent of sing-box internals;
- protected `__flowprobe_*` configuration is produced by the Config Compiler;
- third-party analyzers execute through the versioned WASM sandbox; and
- raw and normalized capture data are source material while analyzer output is
  derived and rebuildable.

The renderer MUST NOT gain ambient network privilege. It sends typed product
intent to the desktop host; it never invokes the helper or operating-system
network APIs directly.

## Actors and authority

| Actor | Authority | Explicitly lacks authority |
| --- | --- | --- |
| Renderer | Request preview, start, stop, status, and user-mediated recovery through typed IPC | Helper transport, shell, arbitrary paths, raw OS operations, fencing credentials |
| Supervisor session controller | The only unprivileged orchestration writer; compile plans, sequence actors, hold the live lease, and publish state | Direct privileged OS mutation and untyped helper operations |
| Config Compiler | Produce and validate protected runtime configuration | Activate OS resources |
| Network Runtime adapter | Manage the independent sing-box process through Network Runtime Control | Session commit, helper journal, or independent route/DNS ownership |
| Capture Core | Own capture/protocol services and normalized events | sing-box internals, system route/DNS ownership, or helper access |
| Privileged helper | The only privileged mutation executor and authoritative durable network journal writer | Product policy, arbitrary commands, arbitrary paths, renderer payloads, or a replacement Network Runtime |
| Helper watchdog/reconciler | Enforce the helper-issued lease and recover journaled resources after owner loss or boot | A second mutation policy or a second journal writer |
| Platform backend | Implement a versioned, allowlisted set of typed resource operations | Domain behavior not registered by an accepted contract |

“One writer” is defined at each boundary: exactly one Supervisor controller owns
a session generation, and exactly one helper journal/fence domain owns its
privileged mutations. The watchdog is part of that helper domain, not a second
writer. sing-box MUST remain behind `NetworkRuntime`; the helper MUST NOT embed
libbox or take over runtime process semantics.

## Identifiers and durable records

Every start attempt MUST use the following opaque identifiers:

- `InstallationId`: stable for one installed FlowProbe instance;
- `BackendId` and `BackendProtocolVersion`: select one audited helper backend;
- `SessionId`: product-visible logical session identifier;
- `AttemptId`: unique start attempt identifier;
- `Generation`: monotonically increasing durable counter scoped to the
  installation and never reused, including after reboot;
- `ControllerId`: helper-assigned random identity of one Supervisor instance,
  bound to proof of possession of an ephemeral instance key and a helper-
  controlled connection-binding epoch; another process cannot choose or claim
  it even under the same dedicated OS service identity;
- `PreparationTicketId`: short-lived, non-mutating helper discovery authority;
- `PreparedPlanId` and `PlanDigest`: immutable helper-sealed activation plan;
- `ActivationLeaseId` and `LeaseEpoch`: helper-issued random lease identity and
  durable monotonic lease epoch created only when that plan is sealed;
- `FenceToken`: monotonically ordered helper token bound to generation,
  activation lease, controller, and plan digest;
- `RecoveryEpoch`, `RecoveryFenceToken`, `RecoveryBaseRootDigest`,
  `RecoveryPlanId`, and `RecoveryPlanDigest`: helper-owned recovery authority
  sealed only after the old activation fence is durably invalidated; the base
  root is immutable while the journal head/revision advances;
- `RecoveryDelegateLeaseId`, `RecoveryDelegateEpoch`, and
  `RecoveryDelegateFenceToken`: bounded external recovery authority separately
  issued to one controller/connection and plan-node subset; it can observe/
  compensate but cannot apply or commit, and helper-internal recovery never uses
  or shares it;
- `PreparedAtBootEpoch` and `ContinuousExpiresAt`: plan validity in a
  suspend-aware monotonic clock domain; and
- `CapabilitySnapshotId`: exact capability/readiness evidence used by the plan.

Each process or service node also has a random `RuntimeInstanceId`, generated by
the trusted adapter during plan construction and sealed before launch rather
than derived from a PID. Its authenticated runtime
control handshake binds the ID to installation, session generation, executable
identity, helper-assigned `ControllerId`, and launch evidence. A process handle
or pidfd is only a live locator and corroborating observation. If a later
Supervisor cannot rediscover an exact instance through the protected runtime
control identity, it MUST NOT kill a same-name/PID candidate and the session
cannot become `Inactive`.

A process ID, Windows interface index, macOS `utun` name, Linux interface name,
service restart, or current boot-local handle MUST NOT be used as any durable
identifier above.

The prepared plan digest MUST bind at least the compiled-config digest, backend
and protocol versions, capability snapshot, normalized baseline digest,
registered resource graph, downstream extension digests, requested mode, and
the `ControllerId` and mandatory/optional actor and health-predicate sets. Plan
expiry is expressed in a helper-defined suspend-aware monotonic clock plus boot
epoch. Any boot, suspend/resume, or clock-domain discontinuity invalidates an
uncommitted plan.
Secrets, full user configuration, CA private material, captured traffic, and
proxy credentials MUST NOT be included in a plan or journal.

## Capability and readiness model

Each requested operation and resource kind MUST report all of these independent
dimensions:

1. `StaticSupport`: `SupportedByDesign`, `UnsupportedPendingArchitecture`, or
   `UnsupportedByPlatform`;
2. `Readiness`: `Ready`, `Degraded`, `PermissionMissing`,
   `UserActionRequired`, `PolicyProhibited`, `TemporarilyUnavailable`,
   `BackendVersionMismatch`, `Unsafe`, `RecoveryRequired`, or `NotInstalled`;
3. `Evidence`: `DesignOnly`, `DeterministicFakeVerified`, or
   `RealHostVerified`; and
4. a bounded, stable reason code plus backend and evidence versions.

Static support MUST NOT be inferred from a successful API probe. `Ready` MUST
NOT be inferred from static support. A platform/mode MAY be described as
supported only when all mandatory resources are `Ready` and `RealHostVerified`
for the release matrix. Unsupported or unsafe activation MUST fail before any
system-network mutation and ordinary connectivity MUST remain unchanged.

`Degraded` is not equivalent to `Ready` for the requested mode. A prepared plan
MAY select a separately defined reduced mode only when its accepted owning
contract defines the reduction and the user requests it. Refusing the requested
mode, losing a mandatory actor, or remaining in recovery MUST NOT be reported as
an active degraded version of that mode. `PolicyProhibited` represents an
administrator/product policy refusal and also fails before mutation.

Preflight maps capability state deterministically: static unsupported to
`Unsupported`; `PolicyProhibited` to the same error;
`PermissionMissing`/`UserActionRequired` to
`PermissionMissing`/`InteractionRequired`; `Degraded` to `Degraded` for the
refused requested mode; `BackendVersionMismatch` to
`BackendProtocolMismatch`; `RecoveryRequired` to the same error; and other
non-ready states to `NotReady` with their bounded reason. No mapping may discard
the four capability dimensions.

## Resource record

Every resource in a prepared plan is a typed node in a dependency graph. Its
durable record contains:

- `ResourceKind` and the accepted contract that registered it;
- `ResourceExecutor`: Supervisor, runtime adapter, Capture Core, helper, or an
  accepted extension owner;
- `StableResourceIdentity` or a deterministic discovery recipe when the OS
  allocates the final identity;
- `OwnerMarker` containing at least installation, generation, and resource key;
- `StepId` and dependency `StepId` values;
- a normalized, schema-versioned `BeforeImage` and digest;
- a normalized `IntendedPostcondition`;
- a bounded `ObservationSchema`, verifier identity, nonce binding, and freshness
  window for non-helper executors;
- after execution, a normalized `ObservedAfterImage` and digest;
- a typed, bounded `CompensatingOperation`;
- `MutationPhase`, idempotency key, deadline, and bounded reason code; and
- the backend schema/version that can interpret all fields.

These records describe session-scoped resources only. A future persistent
resource lifecycle, especially `trust.ca.*`, may reuse the helper's
authentication, durable journal, stable identity, and compare-before-restore
primitives, but it MUST use an ARCH-003-defined transaction/generation and MUST
NOT become a node compensated by network stop or lease loss.

Images contain only fields FlowProbe is authorized to compare or restore.
Backend discovery MAY include ephemeral handles, but the durable identity MUST
include a stable platform identity or an unambiguous owner marker that can be
rediscovered after process restart and boot. If neither exists, that resource
kind is unsupported.

Each mutating operation MUST define:

1. an idempotency rule;
2. an observable success predicate;
3. a bounded timeout and typed failure result; and
4. a compensating action that restores the before image or removes a resource
   created by FlowProbe.

An operation that updates or deletes an externally mutable object MUST also
have one of: an OS-enforced atomic conditional mutation, an OS revision/version
token consumed by the mutation, or an object proven to be exclusively owned by
the exact FlowProbe resource instance. A read/compare followed by an
unconditional setter is not compare-and-swap: an administrator could change the
object between those calls and be overwritten. Such an operation is
unsupported at preflight; if the missing guarantee is discovered during
recovery, the resource is preserved in `RecoveryRequired`.

For whole-object deletion, `exclusive ownership` includes the entire deletion
domain and every dependent object or attachment the OS would remove
transitively. The recorded after image therefore contains a normalized whole-
object/dependent-closure graph, not only FlowProbe-managed fields. Deletion is
allowed only when an atomic condition covers that complete graph or the backend
prevents foreign additions and still proves the current graph exactly matches.
A foreign address, route, rule, attachment, child, or passthrough change blocks
deletion as `ExternalDrift`, even when the owner marker and managed fields match.

## Ordinary-connectivity baseline

The ordinary-connectivity oracle compares against an observed baseline; it does
not mean “the Internet must currently be reachable.” The baseline records
normalized OS route/DNS/link state and bounded control outcomes for IPv4, IPv6
when present, DNS, and a non-FlowProbe path. Each outcome is
`Reachable`, `Unreachable`, or `NotApplicable`, with provenance and deadline.

The terminal predicate is `BaselineEquivalent`, meaning:

- every session-scoped managed field is restored or every exact FlowProbe-
  created object is safely absent;
- control outcomes are no worse than the observed baseline; or any later
  degradation is independently attributable to external network state rather
  than a remaining/overwritten FlowProbe resource; and
- no identity, ownership, or conditional-mutation result is ambiguous.

An offline host can therefore be safely `Inactive` after its offline baseline
and OS state are restored. A public endpoint outage alone does not retain the
journal forever. If FlowProbe-caused degradation cannot be distinguished from
external failure, the result is `RecoveryRequired`, not a fabricated success.

## Session states

The normative states are:

| State | Meaning |
| --- | --- |
| `Inactive` | No session-scoped owned resource or runtime instance remains, rollback is verified, and the `BaselineEquivalent` terminal predicate holds |
| `Preflighting` | Read-only discovery, validation, and plan construction are in progress |
| `Prepared` | A non-expired immutable plan and required before images are durably bound to a fenced generation |
| `Applying` | Internal services and resource graph steps are being applied |
| `Verifying` | All mandatory postconditions exist; end-to-end health and ownership are being verified |
| `Active` | Commit is durable, the lease is live, and all requested mandatory resources and health predicates remain satisfied |
| `Stopping` | New product work is refused and the data plane is held available while rollback is prepared; runtime/service shutdown has not yet made an owned route a black hole |
| `RollingBack` | Owned resources are being compensated in reverse dependency order |
| `Recovering` | A helper start, boot, or owner-loss reconciliation is examining a durable journal |
| `RecoveryRequired` | Safe automatic reconciliation cannot prove or restore the terminal invariant without overwriting drift or exceeding a bound |

`Inactive` and `RecoveryRequired` are terminal safe-reporting states. Only
`Inactive` accepts a new start. `RecoveryRequired` MUST refuse activation and
MUST NOT be reported as inactive, stopped, or active.

The common transitions are:

```text
Inactive -> Preflighting -> Prepared -> Applying -> Verifying -> Active
Preflighting -> Inactive
Prepared/Applying/Verifying -> RollingBack -> Inactive | RecoveryRequired
Active -> Stopping -> RollingBack -> Inactive | RecoveryRequired
any journaled state -> Recovering -> RollingBack -> Inactive | RecoveryRequired
```

Unexpected process loss does not itself change durable truth. A new controller
MUST enter `Recovering` and reconcile the journal before publishing a terminal
state.

## Start transaction

A start request MUST execute these phases in order:

1. Acquire the installation-scoped controller lock. Concurrent starts receive
   `Busy` without side effects.
2. Allocate and durably advance `Generation`; obtain a non-mutating
   `PreparationTicketId`. A preparation ticket cannot authorize an OS call.
3. Discover a normalized platform baseline and ordinary-connectivity oracle.
4. Resolve the capability snapshot. Reject unsupported, unsafe, permission-
   blocked, recovery-blocked, or unavailable mandatory resources.
5. Compile and validate protected runtime configuration. Invoke the ARCH-002
   egress-validation extension when registered; this contract does not define
   its probe policy.
6. Build and validate an acyclic resource graph with stable identities,
   ownership markers, before images, intended postconditions, compensations,
   bounded timeouts, exact `RequestedMode`, and mandatory/optional actor and
   health-predicate sets.
7. Ask the helper to validate and durably seal that exact graph. The helper
   atomically returns `PreparedPlanId`, `PlanDigest`, `ActivationLeaseId`,
   `LeaseEpoch`, and a plan/controller-bound `FenceToken`; only now enter
   `Prepared`. No internal service or OS resource has started before this point.
8. Enter `Applying` and execute sealed internal-service nodes first. Before an
   external executor may launch one, the helper fsyncs
   `ExternalIntentDurable` with its pre-sealed `RuntimeInstanceId` and issues a
   one-use plan/generation/controller/fence-bound redeem ticket. Issuance is not
   launch authority. The adapter redeems it online while the helper holds the
   mutation lock; any new process starts inert, and the protected runtime
   control handshake validates the ticket and instance identity before the
   helper authorizes attach/activation. The helper holds the gate until it
   fsyncs the bounded authenticated observation. The helper does not execute
   unprivileged process operations, but this gated record lives in the same
   session journal; there is no second recovery journal.
9. Before the first privileged mutation, fsync the plan header, generation,
   activation lease, fence, backend, graph, all known normalized before images,
   intended postconditions, and already observed internal-node results.
10. Apply TUN and other registered resources in dependency order. Route and DNS
   are generic registered resource kinds here; their domain policy is owned by
   ARCH-004.
11. Verify every postcondition, every mandatory actor and health predicate for
    the exact requested mode, the requested data path, and the active control
    outcomes. Capture Core is mandatory only for a mode whose sealed actor set
    includes it; for example, its failure cannot invalidate a Proxy Only plan
    that does not use it.
12. Fsync the commit record, then publish `Active`. Publication before durable
    commit is forbidden.

Preflight MUST be free of system-network mutation. Failure before any applied
resource returns to `Inactive` after the preparation ticket or sealed plan is
durably fenced and released. Failure after an internal or privileged resource
might have changed enters `RollingBack`.

A prepared plan uses a suspend-aware monotonic deadline within one boot epoch.
Expiry, explicit cancellation, boot, suspend/resume, or clock-domain
discontinuity first durably invalidates its activation lease/fence. If still
`Prepared`, its unused graph is tombstoned and the session returns to
`Inactive`; after `Applying` begins, the normal rollback graph runs. A prepared
plan is never reconstructed from renderer data or reused after restart.

## Mutation write-ahead protocol

For every mutation, the helper MUST perform this sequence:

1. acquire the helper domain's cross-process mutation lock, reread the durable
   fence/state revision, rediscover the target by stable identity, and verify
   the expected before fields, owner precondition, generation, live activation-
   or recovery-only authority, sealed plan, step digest, and applicable fence;
2. append `IntentDurable`, including the normalized current before image and
   intended postcondition, and fsync the journal and containing directory when
   required by the platform filesystem contract;
3. issue exactly one registered, bounded backend mutation;
4. query the operating system rather than trusting a command exit status;
5. verify the success predicate and ownership marker;
6. append the direction-specific observed result and closed terminal phase—
   after image plus `AppliedDurable` for apply, or restored-before image/
   tombstone/absence proof plus `CompensatedDurable` for compensate—then fsync;
   and
7. only then release the mutation lock and permit a dependent step or commit.

An operation whose success cannot be queried is unsupported. A timeout or
transport loss after step 3 is `MutationAmbiguous`, not an automatic retry.
The same exclusive lock spans fence verification, intent fsync, OS call,
read-back, and direction-specific terminal-result fsync so a takeover cannot
advance the fence between check and mutation. Helper IPC success is likewise
withheld until `AppliedDurable` or `CompensatedDurable`. A backend call that
cannot be bounded/cancelled or whose ownership cannot be kept exclusive for that
interval is unsupported. The complete closed `MutationPhase` enum is defined by
the Privileged Network Helper contract; arbitrary phase strings are forbidden.

For a node executed outside the helper, the sealed plan defines a bounded typed
observation rather than accepting `true`, arbitrary text, or opaque health. The
observation binds a fresh helper nonce, plan digest, generation, step digest,
`RuntimeInstanceId`, measured values, verifier identity, and freshness window.
The helper independently queries OS-owned resources and runs or verifies the
fixed ordinary-connectivity safety predicates. A runtime/Capture actor supplies
evidence through its protected instance control identity; the Supervisor may
relay but cannot manufacture or rewrite it. If a mandatory postcondition or
health predicate cannot be independently queried or cryptographically/channel-
bound to its exact executor, commit and platform support are forbidden.

An external executor MUST NOT act from the sealed plan or an issued ticket
alone. Each `ExternalExecutionPermit` has `Direction=Apply | Compensate` and an
authority union: activation authority for apply and normal-stop compensation,
or helper-recovery-plan plus controller-delegate authority for takeover
compensation. It binds `ControllerId`, connection-binding epoch, exact
activation plan or immutable recovery base/plan and current journal head as
applicable, generation, fences, step, state revision, `RuntimeInstanceId`,
executor identity, nonce, and expiry.

Issuance itself is a locked conditional transition. The helper acquires the same
cross-process mutation lock as takeover, rereads the authority, fences, revision,
and journal head, then fsyncs intent, complete issued permit, idempotency result,
and next revision atomically. The permit seals its immutable authority plus the
parent and issued journal heads/revision, all returned by the issue response.
Takeover therefore observes the permit in the recovery plan, or wins the lock
first and causes issue to fail without appending an old-authority intent.

The executor redeems the ticket on a live helper gate by sending `PermitId`,
direction, exact current head/revision expectation, and the gate binding; it
does not resubmit authority. The helper acquires the same cross-process mutation
lock as takeover, loads authority from the permit, proves its issued head remains
an authenticated ancestor with no superseding/revocation/conflict record,
rereads every live binding, and fsyncs `Redeeming` before any instruction.
Unrelated journal advancement is allowed only through a fresh current-head/
revision expectation; a stale expectation fails before action. Every helper
success, typed error, and status response returns its authenticated revision and
journal head at that response's linearization point, so renewal, recovery, or a
stale attempt always provides a protocol path to the next exact expectation.
The helper retains the lock through the bounded
external action, protected exact-instance handshake, typed read-back, durable
presence/absence observation, and permit consumption. Apply may create only an
inert process before the gate; any staged attach remains unable to process
session traffic until the helper fsyncs `AppliedDurable` and sends the durable-
result acknowledgement while still holding the lock. Gate/helper loss before
that acknowledgement forces immediate detach/quiescence and self-termination.
Compensate may stop or prove absent only the sealed instance and requires
`ExternalCompensationIntentDurable` before the instruction. A fence after
issuance rejects redemption without launch; a fence cannot advance while
redemption holds the lock; after release, takeover sees the durable result. If
an executor cannot provide this online fail-closed gate, the node is unsupported.

A crash in any external phase is resolved from the durable permit state and
exact `RuntimeInstanceId`; recovery searches only through protected executor
control and never guesses by PID/name. The node is compensated when proven,
absent when proven, and otherwise `RecoveryRequired`. Reuse, expiry, controller/
connection mismatch, stale fence, response loss, or already-consumed redemption
never repeats launch, attach, control, or stop.

## Commit, lease, and active health

The commit point is the durable helper record that names the exact plan digest,
generation, fence, all mandatory applied-step and verified-observation digests,
mode-specific health evidence, and lease deadline. `Active` is valid only while:

- the same generation/fence remains authoritative;
- the helper watchdog observes timely authenticated lease renewal;
- mandatory resource postconditions and owner markers remain valid;
- every actor in the sealed mode's mandatory actor set satisfies its health
  contract; and
- the requested end-to-end and ordinary-connectivity predicates pass within
  their specified windows.

Lease renewal MUST be idempotent and MUST use a platform clock that advances
through suspend, plus a durable boot/suspend epoch. Wall-clock time may be
logged but cannot decide ownership. A stale or superseded controller cannot
renew, stop, or mutate a later generation.

Renewal is not a bare heartbeat. `renew_activation_lease` binds an idempotency
key, `ControllerId`, connection-binding epoch, plan, generation,
`ActivationLeaseId`, `LeaseEpoch`, `FenceToken`, a fresh helper challenge,
current state revision, and freshness-window-valid observation digests for every
mandatory actor, resource postcondition, and mode-specific connectivity
predicate. The helper independently re-queries safety-critical OS ownership/
postconditions on their sealed cadence. Missing, stale, substituted, or failed
mandatory evidence denies renewal and begins fenced rollback.

`PlanPrepared` supplies the initial one-use renewal challenge and expiry. Each
successful `LeaseRenewed` atomically consumes it and returns the next challenge/
expiry; replay of the same idempotency key returns the recorded response without
consuming another challenge.

Renewal and watchdog takeover serialize under the same cross-process mutation
lock and conditional state revision. After acquiring it, renewal rereads every
authority/expiry field and validates fresh evidence. Immediately before the
renewal fsync it rereads the suspend-aware clock/epoch and again requires `now <
old ContinuousExpiresAt`, an unexpired request/challenge, and still-fresh
evidence. Crossing the old deadline is irreversible even while renewal holds the
lock: the helper rejects renewal and advances the activation fence into recovery
under that lock. Otherwise it atomically fsyncs the new deadline, evidence
digest, consumed/next challenge, and next revision before replying. The watchdog
acquires that lock before evaluating expiry or advancing the fence. Exactly one
result exists: a still-timely renewal commits first, or expiry/takeover fences
first and renewal cannot extend the deadline.

Boot, suspend/resume, or a clock-domain discontinuity invalidates every
prepared plan and active lease. After acquiring the exclusive mutation lock,
the helper durably advances the fence and performs full resource and baseline
reconciliation before any mutation or `Active` publication. v0.2 rolls the old
session back; it does not silently resume or reactivate it.

That control-plane rule is insufficient unless the data plane also has a fail-
closed `ResumeBarrier` ordered before the first packet after cold boot, suspend,
or hibernate. An OS/kernel gate installed before activation MUST automatically
close on epoch change and helper/watchdog/gate-channel death independently of
later scheduling. A pre-suspend inhibitor/removal path qualifies only with proof
that holder death or forced suspend atomically closes that gate or removes
steering before suspend completes. An ordinary inhibitor released by helper
crash, userspace resume callback, runtime heartbeat, or eventual helper
scheduling is not such a barrier. The old barrier remains closed while
reconciliation rolls the session back. Any combination lacking this proof is
`Unsupported` with bounded reason `ResumeGateMissing` before mutation.

Lease expiry, runtime loss that makes the data path unsafe, or a mandatory
postcondition loss MUST cause the helper domain to fence the controller and
begin bounded rollback. A service manager restart policy is availability
support; it is not a substitute for this lease or recovery protocol.

## Stop and rollback

Stop is idempotent for the current generation. Concurrent repeated stops join
the same operation and return its final result. Stop with a stale generation,
lease, or fence fails without side effects.

The state-by-command rules are:

| Observed state | `start` | `stop` |
| --- | --- | --- |
| `Inactive` | Begin one new generation | Idempotent `Inactive` result |
| `Preflighting` | `Busy` | Cancel discovery, durably invalidate the preparation ticket, release read-only state, then `Inactive` |
| `Prepared` | `Busy` | Fence/tombstone the unused plan and run its zero-or-more cleanup graph, then `Inactive` or `RecoveryRequired` |
| `Applying` or `Verifying` | `Busy` | Fence new steps and join reverse rollback of all possibly applied nodes |
| `Active` | `Busy` | Enter `Stopping`, keep mandatory data-plane actors available, then reverse rollback |
| `Stopping` or `RollingBack` | `Busy` | Join the existing operation and return its eventual terminal result |
| `Recovering` | `Busy` | Join recovery; it cannot be interrupted or converted to a new policy |
| `RecoveryRequired` | Refuse with `RecoveryRequired` | Run only the already authorized safe reconciliation; never force-delete or overwrite drift, and otherwise remain `RecoveryRequired` |

Authority is state-specific: `Preflighting` uses only its non-mutating
preparation ticket; `Prepared` through a normal `RollingBack` use the live
activation lease/fence; `Recovering` and recovery work in `RecoveryRequired`
use the helper-owned recovery epoch/base/plan internally, while external work
also requires a live delegate lease/fence for the current `ControllerId` and
connection-binding epoch; `Inactive` has no lease. The preparation ticket, plan,
activation authority, and every recovery delegation are bound to their exact
controller binding. Generation and state revision apply wherever a transaction
exists. A stop naming an older session or another controller cannot affect the
current one.

Rollback runs in reverse topological order. For each resource it MUST:

1. rediscover by stable identity and owner marker;
2. compare only normalized FlowProbe-managed fields with the durably observed
   after image;
3. if they match and the backend can consume an atomic condition/revision token
   or proves exclusive ownership of that exact resource instance, journal and
   execute the compensation, then verify the before image or verified absence;
   for whole-object deletion, the condition or ownership proof MUST cover the
   entire normalized object plus every transitively deleted dependent, and that
   current closure MUST exactly match the recorded owned after-image graph;
4. if the resource already matches the before image, record idempotent success;
5. if managed fields differ, any passthrough/foreign dependent was added, or
   identity/ownership is ambiguous, preserve the current state, record
   `ExternalDrift`, and enter `RecoveryRequired`; and
6. persist the rollback result before proceeding to a dependent cleanup.

Rollback MUST NOT restore a whole interface, route table, DNS configuration,
firewall, or trust store from an old snapshot. It restores or removes only the
fields proven to be owned by the fenced FlowProbe generation. Best-effort
process cleanup, object destruction, application exit, `Drop`, and UI closure
are not rollback evidence.

The helper MAY continue independent compensations after one conflict so that it
reduces risk, but it MUST retain all unresolved records and report the complete
bounded conflict set. The journal cannot be deleted until no owned resource
remains, all compensations are durably verified, internal services are stopped,
and `BaselineEquivalent` is proven.

A successful read immediately before an unconditional setter/deleter is not a
safe comparison because an external write can race it. If the platform cannot
make the compensation conditional or operate on an exact exclusively owned
instance, FlowProbe preserves the object and enters `RecoveryRequired`.

On a normal stop, the Supervisor first refuses new product operations but keeps
all mandatory actors in the sealed mode's data path available. Because system-network
resources depend on that data path during activation, reverse rollback removes
traffic steering, DNS/rules/routes, and TUN ownership before stopping the
mode-specific runtime/Capture actors. `BaselineEquivalent` is verified after
system traffic no longer depends on the FlowProbe data path; internal services
are then stopped and their absence is verified. Quiescing or killing the data
plane while an owned route can still direct traffic to it is forbidden.

If a mandatory data-plane actor has already crashed, the helper cannot preserve
that ordering; it MUST fence immediately and remove proven owned steering
resources without waiting for the failed data plane. Failure to complete that
bounded emergency rollback is `RecoveryRequired`, never a reason to restart the
old session implicitly.

## Crash, restart, and boot recovery

The helper/watchdog MUST start before accepting new session requests. It first
locks and validates the journal, fences expired owners, and reconciles every
non-terminal generation. A corrupt, unauthenticated, unknown-version, or
partially durable journal fails closed as `JournalCorrupt` or
`BackendProtocolMismatch`; it is never discarded automatically.

For an intent with no durable after image, recovery MUST query stable identity,
owner marker, and intended postcondition:

- if the intended state and ownership are proven, persist the observed after
  image and treat the step as applied;
- if the before image is still proven and no owned resource exists, persist an
  unapplied result;
- otherwise classify the mutation as ambiguous, preserve the OS state, and
  enter `RecoveryRequired`.

For an applied step, a matching after image is eligible for compensation. An
already-restored before image is idempotently complete. Any other change is
external drift and MUST NOT be overwritten.

Recovery after helper crash, Supervisor crash, Network Runtime crash, Capture
Core crash, UI exit, logout, sleep/resume, or reboot follows the same journal
algorithm. A boot-local name or handle MUST be rediscovered through the stable
platform identity. If rediscovery is not unambiguous, the backend cannot claim
support.

The helper may reach its own durable `NetworkRestoredAwaitingController` phase
after all privileged/session-network resources are safely compensated and the
terminal connectivity predicate is proven. It MUST NOT publish the whole
session as `Inactive`: only the Supervisor owns session publication and the
helper does not terminate arbitrary unprivileged processes.

A newly authenticated Supervisor must resume `Recovering`, rediscover each
sealed `RuntimeInstanceId` through the protected Network Runtime/Capture control
identity, and first obtain a helper response containing the helper-owned recovery
epoch/fence, immutable base root, sealed recovery plan, current journal head,
and a separate delegate lease/epoch/fence bound to its `ControllerId`, connection
binding, allowed node subset, revision, and expiry. The helper never shares its
internal recovery authority. A proven-close reconnect may rebind the same
controller-key during a sealed grace while all requests/permits are paused;
delegate expiry or an unrecovered disconnect is revoked under the mutation lock,
advances the delegate fence, and invalidates every old permit. Internal recovery
continues and a later controller may claim a new delegate with a new idempotency
key.

The Supervisor uses `Direction=Compensate` online gates for exact delegated
nodes: the helper fsyncs `ExternalCompensationIntentDurable` before stop/prove-
absent, rejects all old-controller/delegate control, and fsyncs the typed absence
observation afterward. PID/name/executable similarity is insufficient. Appended
records advance the expected journal head/revision but not the immutable base
root; changing the recovery node set requires a new helper recovery epoch/fence,
base root, and plan.

The Supervisor then sends idempotent `AcknowledgeRecovery` with the live helper
recovery and delegate bindings, exact current pre-finalization journal head/
revision, complete
runtime-absence observation-set digest, and `BaselineEquivalent` evidence. Under
the mutation lock the helper revalidates delegate lifetime, every resource and
runtime absence, terminal evidence, and unchanged head/revision immediately
before fsync. The response separately echoes the acknowledged pre-finalization
tip and returns the resulting post-finalization tip. Only a durable
`RecoveryFinalized` response (or its exact replay) lets the owning Supervisor
publish `Inactive`; expired authority, a concurrent journal append, ambiguity,
or failed predicate rejects finalization.

The helper also retains the latest non-authorizing finalization receipt in its
protected installation index, independent of transaction-journal pruning and
the original controller key. If the owning Supervisor is permanently lost after
the terminal fsync, any new authenticated Supervisor may obtain that receipt
through `InactiveStatus` and publish `Inactive`; the receipt grants no mutation
authority, has no time-based expiry while it is the current terminal generation,
and is retired as publication proof only when a later generation is durably
allocated. If an instance cannot be identified or safely terminated, the result
is `RecoveryRequired` even when the OS network is already restored.

## Typed commands and errors

The renderer-facing surface MAY expose only typed commands equivalent to:

- `preview_start(requested_mode)`;
- `start(requested_mode, optional_preview_digest)`;
- `stop(session_id, generation)`;
- `status()`; and
- `request_recovery(session_id)`.

`preview_start` is an advisory read-only query. It allocates no generation,
preparation ticket, plan, lease, reservation, or state transition. Its bounded
snapshot expires and cannot authorize mutation; `start` repeats authoritative
preflight. If the current state is not `Inactive`, preview reports that state
rather than pretending the mode can start.

`start` owns the complete transaction from `Inactive` through internal
`Prepared` and `Applying`; renderer code does not issue a second activate
command. `Prepared -> Applying` is the continuation of that same fenced start.
Any additional external `start` observed in `Prepared` receives `Busy`.

`request_recovery` asks the Supervisor to run the accepted recovery protocol;
it does not authorize force deletion or baseline overwrite. Renderer payloads
MUST NOT contain helper operation kinds, executable names, paths, environment
variables, raw network configuration, or fencing credentials.

The shared session errors are:

```text
Unsupported
NotReady
PolicyProhibited
Degraded
Unauthenticated
Unauthorized
PermissionMissing
PermissionDenied
InteractionRequired
InvalidRequest
InvalidTransition
Busy
StaleGeneration
StaleLease
StaleFence
StaleStateRevision
PlanExpired
PreflightFailed
JournalUnavailable
JournalCorrupt
HelperUnavailable
BackendProtocolMismatch
MutationFailed
MutationAmbiguous
PostconditionFailed
HealthCheckFailed
ExternalDrift
RollbackFailed
RecoveryRequired
TimedOut
IntegrityFailure
```

An error response MUST contain operation, phase, safe observed state, resource
kind when applicable, retryability, and a bounded stable reason code. It MUST
NOT return raw commands, arbitrary helper stderr, secrets, captured data, or
unbounded platform messages.

## Downstream extension registry

ARCH-001 reserves only these namespace envelopes:

| Namespace | Owner | ARCH-001 guarantee |
| --- | --- | --- |
| `core.session.*`, `core.resource.*`, `core.helper.*` | ARCH-001 | Common envelope, journal, fencing, and rollback rules |
| `egress.*` | ARCH-002 | May register typed resources and validation predicates |
| `trust.ca.*` | ARCH-003 | May reuse helper safety primitives only through an independent persistent trust transaction; it is never compensated by network stop/lease loss |
| `transport.udp.*`, `dns.*` | ARCH-004 | May register typed transport/DNS resources and predicates |

An extension MUST provide a schema version, stable identity rules, ownership
proof, normalized image schemas, success predicate, idempotency rule,
compensation, capability mapping, and deterministic plus real-host tests. The
helper operation remains a compile-time allowlist. Dynamic privileged plugins
are forbidden.

An extension that is session-scoped inherits this state machine. A persistent
extension does not: its owner must define a separate transaction class,
generation, commit/retention semantics, and interaction with network-session
start/stop. ARCH-003 therefore decides whether and how trust survives network
sessions; ARCH-001 does not assume uninstall-on-stop.

This contract does not define HTTP/HTTPS/SOCKS5 behavior, local-proxy identity,
loop-exclusion mechanisms, CA states or fingerprints, trust-store scope, UDP
flow keys, DNS metadata, encrypted-DNS visibility, or domain support claims.

## Verification contract

Deterministic tests MUST include:

- model-based testing of every state transition and invalid transition;
- every state-by-command cell; two-controller start; repeated/concurrent stop;
  stale generation, lease, fence, and state revision; plan expiry/cancel; and
  substitution of plan, step, operation, observation, or runtime-instance
  identity; include two helper-assigned `ControllerId` values under the same OS
  service identity, same-ID/key theft attempts, live duplicate connection,
  proven-close reconnect/epoch rotation, and replay of preparation, activation,
  and recovery delegation;
- failure injection immediately before a journal intent, after durable intent
  but before mutation, after backend/OS API return but before the
  direction-specific terminal-result fsync, after that fsync but before the
  helper IPC response, and helper-response loss followed by an idempotent retry;
- crash replay from every journal phase and dependency edge;
- helper, Supervisor, runtime, Capture Core, renderer, and watchdog loss;
- corrupted, truncated, stale, unknown-version, and replayed journal/request
  records;
- external drift before apply, between apply steps, while active, and during
  rollback, including the compare-to-unconditional-write race and a foreign
  address/route/attachment added under a FlowProbe-created object before whole-
  object deletion;
- external apply and recovery-compensation gate races: issue then fence then
  late redeem, pause issue after validation and race takeover, pause in
  `Redeeming`, helper/executor crash, gate-channel loss, permit replay, stop
  followed by crash before absence observation, and lost response; no stale
  action may launch, attach, stop, append an orphan intent, or repeat; cover
  parent `H0` -> issued `H1` -> redeem, plus issued `H1` -> renewal `H2` ->
  stale redeem returning `H2` -> new-key redeem, unrelated head advancement,
  supersession, and stale-current-head retry without authority resubmission;
- pause renewal after validation and race expiry/takeover in both lock orders,
  including crossing the old deadline while renewal holds the lock, proving
  exactly one durable deadline-or-fence result and one-use challenge rotation;
- lose `PlanPrepared` and `RecoveryGranted` responses after fsync and retry on
  the same/proven-reconnected controller, proving the same idempotent grants;
- recovery-delegate expiry/disconnect/replacement and stale request/permit
  races, proving helper-internal recovery remains authoritative and re-planning
  advances recovery base/plan/fence;
- `AcknowledgeRecovery` with exact pre-finalization head/revision and terminal
  evidence, response loss/replay, delegate expiry before final fsync, and
  concurrent internal append; prove acknowledgement `H0/R0` produces distinct
  result `H1/R1`, and permanently lose the original Supervisor/key both before
  response and before publication so a new `ControllerId` must recover the
  read-only terminal receipt; no other operation may finalize or authorize
  `Inactive`;
- closed `MutationPhase` behavior and response loss for apply
  `AppliedDurable`, compensate `CompensatedDurable`, and
  `RecoveryFinalizedDurable`;
- separate requested-mode actor sets proving that an unused Capture Core or
  optional actor does not control `Active`;
- online, partially reachable, IPv4-only, IPv6-only, and offline baselines plus
  an external outage during rollback;
- suspend immediately before durable intent, after OS mutation, while active,
  and during rollback, plus helper/watchdog crash immediately followed by
  suspend/hibernate and cold boot, injecting traffic at first availability and
  proving the `ResumeBarrier` permits zero packets through the old generation
  before reconciliation;
- secret injection proving logs, errors, plans, and journals remain redacted;
  and
- fake backend proof that no operation occurs after a failed durable barrier.

Fake tests are not platform support evidence. Every claimed supported
platform/mode MUST run privileged tests on real release-packaged hosts covering
start, stop, every mutation-boundary crash, stale journal, owner loss, logout or
equivalent, sleep/resume, and boot recovery.

The real-host suite MUST define bounded ordinary-connectivity oracles for IPv4,
IPv6 where the host has IPv6 baseline, DNS, and a direct non-FlowProbe control
path:

- before start, to establish the baseline;
- while active, alongside the requested end-to-end FlowProbe data path;
- after ordinary stop;
- after injected engine, helper, Supervisor, and UI crashes; and
- after reboot recovery.

A platform cannot be marked supported if any test leaves an owned TUN, route,
rule, firewall, DNS, or session process resource, cannot distinguish external
drift, or cannot prove `BaselineEquivalent`. A persistent `trust.ca.*` resource
is judged only by its future ARCH-003 lifecycle, not by network-session stop.

FlowProbe is unreleased at this decision point. Implementations replace the v0
scaffolding directly; compatibility shims and migration code are forbidden
unless a later task is explicitly authorized to introduce production
compatibility or migration.
