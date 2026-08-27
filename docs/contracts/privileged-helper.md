# Contract: Privileged Network Helper v0.2

Status: Normative for v0.2

This contract defines the only process boundary allowed to perform privileged
FlowProbe system-network mutations. It implements the mutation, journal,
fencing, and recovery rules in the Transactional Network Session Lifecycle
contract. It is not a general privilege broker and it is not a Network Runtime.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## Purpose and threat model

The helper exists so the desktop host, renderer, Capture Core, analyzers, and
independent sing-box process do not run with ambient administrator/root
privilege. It assumes that all unprivileged callers, renderer content, user
profiles, captured traffic, analyzer output, proxy metadata, file paths, and
network input may be hostile.

The helper MUST resist:

- an untrusted local process connecting to its IPC endpoint;
- a compromised renderer replaying or fabricating a mutation request;
- stale Supervisor instances racing a newer generation;
- arbitrary command, argument, environment, path, or configuration injection;
- duplicate delivery and response loss;
- helper, controller, runtime, UI, and machine crashes at every mutation
  boundary;
- journal truncation, in-store record replay/tampering, downgrade, and unknown
  schema; and
- accidental deletion or overwrite of administrator, VPN, DHCP, resolver, or
  other application state.

The helper MUST NOT receive captured payloads, Authorization/Cookie values,
proxy credentials, CA private keys, full user configuration, or analyzer data.

An administrator/root actor or offline disk/VM snapshot rollback is outside the
helper's integrity threat model because that actor can already replace the
helper and mutate the network directly. The helper still uses a protected
`InstallationEpoch`, durable generation high-water mark, monotonic record
sequence, and hash-chain root to detect record/request replay, truncation, and
partial index rollback within the current protected store. It MUST NOT claim
protection against replay of an entire valid privileged-storage snapshot.

## Process and writer model

There is exactly one helper authority per FlowProbe installation and platform
network namespace. It owns:

- per-transaction-class durable generation and lease counters;
- the authoritative privileged network journal;
- the exclusive mutation lock;
- backend protocol/version selection;
- OS mutation and read-back verification; and
- startup, boot, and expired-owner reconciliation.

The Supervisor remains the only unprivileged session orchestrator. The helper
does not choose proxy policy, compile sing-box configuration, inspect captured
traffic, or interpret renderer intent.

A watchdog MAY run as a separately supervised process only if it uses the same
authenticated journal and kernel-enforced cross-process mutation lock. It MUST
first acquire that lock, reread the durable state rather than a cache, and only
then durably advance the lease epoch/fence before takeover. A current mutation
holds the same lock through fence recheck, intent fsync, OS call, read-back, and
direction-specific durable-result fsync, so takeover cannot fence between
validation and side effect.
Two processes MUST never mutate under the same live fence. A service restart,
watchdog restart, process ID, or current IPC connection is not fencing proof.
If a platform call cannot be bounded/cancelled and can retain the lock
indefinitely, that operation is unsupported; a second writer cannot proceed in
parallel to “recover” it.

On every service start, including boot, the helper MUST reconcile all
non-terminal `core.session` journal records before it reports the network class
ready or accepts a new network session. Other future transaction classes are
isolated: an unresolved persistent trust transaction blocks networking only
when its declared resource-conflict set overlaps the requested plan, its owning
contract requires that interaction, or the shared helper/journal integrity is
unsafe. It MUST NOT automatically reactivate the last user session.

## Transport and peer authentication

The transport MUST be local, typed, length-bounded, versioned, and deny by
default. The endpoint MUST be inaccessible from the network and from sandboxed
web content.

Every connection MUST authenticate both:

1. the expected FlowProbe installation and unprivileged Supervisor identity;
   and
2. the expected signed/installed helper identity from the Supervisor side.

OS peer credentials alone are insufficient when another process under the same
interactive user could connect. On Windows and Linux the selected candidate
therefore places the orchestration owner in a dedicated non-administrator OS
service identity; the interactive desktop/renderer reaches it only through a
separate typed product IPC surface. Installation setup provisions the helper
endpoint and channel binding only to that identity. On macOS the candidate uses
the signed XPC peer requirement. Authentication failure occurs before protocol
parsing beyond the fixed handshake header.

The platform transports are:

| Platform | Transport and peer boundary |
| --- | --- |
| Windows | A local named pipe owned by the privileged service, with a DACL granting only SYSTEM and the dedicated non-admin FlowProbe Supervisor service SID; verify that service token and installation binding before accepting requests |
| macOS 26+ candidate | A fixed signed XPC service/LaunchDaemon installed through `SMAppService`; enforce an XPC peer code-signing requirement and installation binding; older macOS needs a separately sourced peer-authentication design |
| Linux | A root-owned `AF_UNIX` socket under the helper runtime directory, accessible only to the dedicated non-root FlowProbe Supervisor service UID; verify `SO_PEERCRED` and installation binding; use polkit only for explicit product authorization, never as the mutation transport |

The helper MUST close a connection after malformed framing, oversize fields,
authentication failure, replay, or protocol downgrade. Errors returned before
authentication contain no installation or journal information.

## Handshake and request envelope

The Supervisor instance generates an ephemeral signing key in protected service
memory and proves possession over the helper challenge. After authenticating the
dedicated OS service identity and installation, the helper assigns a random
256-bit `ControllerId`; callers never choose or reuse it. The live controller
registry binds that ID to the instance public key and a `ConnectionBindingEpoch`.
Two live connections cannot register the same key or ID. Rebinding is allowed
only after the prior transport is proven closed, or after an explicit rotation
authorized by the old connection; the helper atomically advances the connection
epoch and invalidates every old nonce/frame. A proven-close reconnect with the
same key may atomically rebind the controller's still-live authorities during a
short sealed reconnect grace; no request or external permit can execute during
that gap. If proof does not arrive before the grace/authority deadline, the
helper fences those authorities normally. A new Supervisor process without the
private key always receives a different ID even under the same OS identity.

Public-key possession is necessary but not sufficient. The helper also binds
registration to the kernel-reported live peer process object/audit token and the
service manager's current signed Supervisor instance, retaining a live handle or
equivalent while the controller exists; PID is only a locator. The Ed25519
private key is generated after process start, never persisted, exported, or
inherited, excluded from logs, swap, and core/crash dumps, held in locked no-dump
memory, and zeroized on exit. The Supervisor process must be non-debuggable by
peer processes under the same service UID/SID; process-handle/task-port access
and dump creation are denied except to the already-out-of-scope administrator/
root authority. A platform that cannot prove peer-process binding and memory/
handle isolation reports `PeerBindingImplementationMissing` and remains
unsupported.

The handshake therefore binds:

- protocol major/minor version;
- helper build and backend IDs;
- supported compile-time operation/schema versions;
- `InstallationId`;
- authenticated client and helper identities;
- helper-assigned `ControllerId`, instance-public-key proof, and
  `ConnectionBindingEpoch`;
- a fresh connection nonce; and
- current safe session phase, generation, lease epoch, and state revision.

The authenticated server hello returns the assigned `ControllerId`, current
`ConnectionBindingEpoch`, fresh connection nonce, and controller-registry
binding digest. None of those fields is accepted from an unauthenticated client.

An unsupported major version or unknown backend fails closed. Minor-version
negotiation MUST NOT silently omit a requested safety field or operation.

Every framed request contains one canonical common header:

```text
ProtocolVersion
HelperBuildId
BackendId + BackendProtocolVersion
ConnectionNonce + ConnectionBindingEpoch + MessageSequence
RequestId
CanonicalRequestDigest
AuthenticatedClientIdentity
InstallationId
ControllerId + ControllerBindingProof
TransactionClass
RevisionExpectation = NoRevision | Exact(ExpectedStateRevision)
Deadline
```

`ExpectedStateRevision` occurs only inside `RevisionExpectation`; duplicate
header/body fields, unknown fields, non-canonical encodings, and conflicting
values are rejected before dispatch. A state-changing operation requires
`Exact`; an installation status query may use `NoRevision`.

`CanonicalRequestDigest` is the stable idempotency-content digest over protocol/
backend, installation, `ControllerId`, transaction class, revision expectation,
deadline, operation tag, and canonical body. It deliberately excludes transport-
rotating `RequestId`, connection nonce/epoch, message sequence, and proof bytes;
the authenticated frame MAC/signature covers those separately. Thus a proven
reconnect can replay the same operation digest without making an old frame valid
on the new connection.

### Canonical wire profile

Protocol v0.2 uses deterministic CBOR as defined by
[RFC 8949 section 4.2](https://www.rfc-editor.org/rfc/rfc8949.html), narrowed as
follows:

- the common header and every variant are fixed-length arrays; elements appear
  exactly in the order listed by this contract, so maps and duplicate/extra
  fields are not accepted;
- request tags are `0 BeginSession`, `1 PreparePlan`, `2 ActivationStep`,
  `3 RenewActivationLease`, `4 ClaimRecovery`, `5 RecoveryStep`,
  `6 IssueExternalPermit`, `7 RedeemExternalPermit`,
  `8 AcknowledgeRecovery`, and `9 Status`;
- response tags are `0 PreparationGranted`, `1 PlanPrepared`,
  `2 ExternalPermitIssued`, `3 ExternalGateResult`, `4 LeaseRenewed`,
  `5 RecoveryGranted`, `6 RecoveryFinalized`, `7 StepResult`,
  `8 StatusSnapshot`, and `9 ErrorResult`; every nested union has an unsigned
  numeric tag fixed by the same versioned schema;
- core nested tags are: first-listed alternative `0`, then monotonically in the
  exact displayed order for `RevisionExpectation`, `Direction`, `Authority`,
  `JournalExpectation`, `Scope`, `StatusSnapshot`, `LastFinalizationReceipt`,
  `PreparationSummary`, `PlanSummary`, `AuthoritySummary`, and
  `DelegateSummary`; session state, `MutationPhase`, and helper error codes
  likewise use zero-based order from their closed lists in these two contracts;
- integers and lengths use the shortest CBOR encoding; counters, revisions,
  epochs, and continuous-clock ticks are unsigned 64-bit values; a deadline is
  `[BootOrSuspendEpoch, ContinuousNanoseconds]`; floating point, negative zero,
  indefinite-length items, generic CBOR tags, and untyped maps are forbidden;
- `InstallationId`, `SessionId`, `AttemptId`, and `RequestId` are 16-byte byte
  strings; helper/controller/plan/lease/permit/runtime opaque IDs, nonces, keys,
  and SHA-256 digests are 32-byte byte strings; the controller instance key is
  Ed25519 and `ControllerBindingProof` is its 64-byte signature as specified by
  [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html); booleans use CBOR
  simple values;
- typed registry graphs and operation payloads are recursively fixed-length
  arrays in the numeric field order declared by their compile-time schema;
  any permitted text is length-bounded, valid UTF-8 in Unicode NFC, and rejected
  if normalization would change the received bytes; and
- `CanonicalRequestDigest = SHA-256("FlowProbe.Helper.Request.v0.2\0" ||
  CanonicalContentCBOR)`, where `CanonicalContentCBOR` is the fixed array of the
  stable fields named above. Frame authentication separately uses the domain
  `FlowProbe.Helper.Frame.v0.2\0` over the full canonical frame with the proof
  field omitted.

The compile-time schema package MUST contain byte-exact encoding and digest
golden vectors for every request/response variant, nested union, boundary value,
and registered operation version. Two independent encoder/decoder
implementations MUST accept those vectors and reject non-minimal integers,
wrong array lengths/order, invalid UTF-8/NFC, unknown tags, and trailing bytes
before a backend/version may be supported.

The request body is this closed tagged union; braces list every field in the
variant in addition to the common header:

```text
BeginSession {
  IdempotencyKey, SessionId, AttemptId
}
PreparePlan {
  IdempotencyKey, SessionId, AttemptId, Generation, PreparationTicketId,
  CandidateResourceGraph, CandidatePlanDigest,
  CapabilitySnapshotDigest, BaselineDigest,
  AuthorizationGrant = None | Grant(AuthorizationGrantId,
                                    AuthorizationGrantDigest)
}
ActivationStep {
  IdempotencyKey, SessionId, AttemptId, Generation,
  PreparedPlanId, PlanDigest,
  ActivationLeaseId, LeaseEpoch, FenceToken,
  StepId, OperationDigest, RegisteredOperationKind, OperationSchemaVersion
}
RenewActivationLease {
  IdempotencyKey, SessionId, AttemptId, Generation,
  PreparedPlanId, PlanDigest,
  ActivationLeaseId, LeaseEpoch, FenceToken,
  RenewalChallengeNonce,
  MandatoryActorObservationDigests,
  ResourcePostconditionObservationDigests,
  ModeConnectivityObservationDigests
}
ClaimRecovery {
  IdempotencyKey, SessionId, AttemptId, Generation
}
RecoveryStep {
  IdempotencyKey, SessionId, AttemptId, Generation,
  RecoveryEpoch, RecoveryFenceToken,
  RecoveryBaseRootDigest, RecoveryPlanId, RecoveryPlanDigest,
  RecoveryDelegateLeaseId, RecoveryDelegateEpoch,
  RecoveryDelegateFenceToken, DelegatedNodeSetDigest,
  ExpectedJournalHeadDigest,
  StepId, OperationDigest, RegisteredOperationKind, OperationSchemaVersion
}
IssueExternalPermit {
  IdempotencyKey, SessionId, AttemptId, Generation,
  Direction = Apply | Compensate,
  Authority = ActivationAuthority(PreparedPlanId, PlanDigest,
                                  ActivationLeaseId, LeaseEpoch, FenceToken)
            | RecoveryDelegateAuthority(RecoveryEpoch, RecoveryFenceToken,
                                        RecoveryBaseRootDigest,
                                        RecoveryPlanId, RecoveryPlanDigest,
                                        RecoveryDelegateLeaseId,
                                        RecoveryDelegateEpoch,
                                        RecoveryDelegateFenceToken,
                                        DelegatedNodeSetDigest),
  JournalExpectation = NotApplicable | Exact(ExpectedJournalHeadDigest),
  StepId, OperationDigest, RegisteredOperationKind, OperationSchemaVersion,
  RuntimeInstanceId, ExecutorIdentityDigest
}
RedeemExternalPermit {
  IdempotencyKey, SessionId, AttemptId, Generation,
  PermitId, Direction, ExpectedCurrentJournalHeadDigest,
  RuntimeInstanceId, GateChannelId, GateChannelNonce,
  GateChannelBindingDigest
}
AcknowledgeRecovery {
  IdempotencyKey, SessionId, AttemptId, Generation,
  RecoveryEpoch, RecoveryFenceToken,
  RecoveryBaseRootDigest, RecoveryPlanId, RecoveryPlanDigest,
  RecoveryDelegateLeaseId, RecoveryDelegateEpoch,
  RecoveryDelegateFenceToken, DelegatedNodeSetDigest,
  ExpectedCurrentJournalHeadDigest,
  RuntimeAbsenceObservationSetDigest,
  BaselineEquivalentEvidenceDigest
}
Status {
  Scope = Installation | Transaction(SessionId, AttemptId, Generation)
}
```

While holding the mutation lock, `BeginSession` verifies `Inactive`, allocates
the next durable generation, binds the preparation authority to the controller
and connection binding, and returns `PreparationGranted`. The authorization
grant in `PreparePlan` is a fixed typed handle bound to installation, requested
mode, allowed operation namespaces, platform approval result, and expiry. It
cannot contain an opaque privileged payload or expand the compile-time registry.

The challenge and every renewal observation are bound to the controller,
connection binding, plan, generation, activation authority, verifier identity,
and sealed freshness window. A renewal carries no operation payload.

Helper takeover owns `RecoveryEpoch + RecoveryFenceToken`, an immutable
`RecoveryBaseRootDigest`, and a helper-sealed `RecoveryPlanId +
RecoveryPlanDigest`; this internal authority is never lent to a Supervisor.
`ClaimRecovery` is the sole recovery request with no delegate authority. Under
the mutation lock it verifies the activation authority is invalid and issues a
separate `RecoveryDelegateLeaseId + RecoveryDelegateEpoch +
RecoveryDelegateFenceToken`, bound to one controller, connection binding,
helper-selected remaining external recovery-plan node subset and its
`DelegatedNodeSetDigest`, state revision, and continuous expiry. The caller
cannot widen or substitute that subset.
Delegate expiry or disconnect not recovered by the same controller-key proof
within the sealed reconnect grace causes the helper/watchdog to take the same
lock, durably revoke it, advance the delegate epoch/fence, and invalidate every
derived permit before another claim; helper-internal recovery continues.
There is no implicit delegate renewal. Long recovery reacquires a new delegation
with a new idempotency key after the prior one is revoked or expired.

`RecoveryBaseRootDigest` never changes during one recovery plan. Appended
records advance `ExpectedJournalHeadDigest` and the state revision. Any change
to the recovery node set requires the helper to advance recovery epoch/fence and
seal a new base root and plan before delegation. Delegate requests authorize
only observe and compensation nodes already sealed in that plan; they cannot
apply, replace, commit, or introduce payloads.

The stable identity recipe, expected-before digest, exact typed payload,
expected postcondition, observation schema, authorization-grant digest, and
deadline are loaded from the durably sealed step. They are never caller-
selectable in an apply/compensate request.

The helper validates canonical framing, controller proof, live connection
binding, generation, applicable activation-or-recovery-delegate authority,
fences, revision/head expectation, deadlines, schema, ownership, and
precondition before any side effect. Every state-changing variant has an
idempotency key. The helper atomically persists its canonical request digest,
state transition, authority grant if any, and complete response variant.
The same installation/controller/key/digest returns that durable result after
response loss, including after a proven reconnect; the same key with different
content is `IntegrityFailure`. Stale requests fail without mutation.

## Sealed-plan binding

`prepare_plan` is the only request that may introduce a typed resource graph or
operation payload. The helper independently validates that:

- every node is a compile-time registered operation and schema;
- every node belongs to the declared transaction class and its resource-
  conflict set does not overlap an unresolved transaction;
- all resource targets are inside that operation's fixed FlowProbe-owned scope;
- no operation can address an arbitrary system object even if the Supervisor is
  compromised;
- the graph is acyclic and has explicit dependency/compensation ordering;
- the helper's own read-only discovery agrees with the normalized baseline and
  expected-before digests;
- capability, permission/authorization grant, backend, generation, preparation
  ticket, and expiry constraints hold; and
- the plan digest binds every node, payload, identity recipe, postcondition,
  deadline, and downstream contract/schema version.

The helper then durably stores the exact transaction-class graph, including its
`ControllerId`, and atomically issues `PreparedPlanId + PlanDigest +
ActivationLeaseId + LeaseEpoch + FenceToken`. The preparation ticket, plan,
lease, and fence all remain bound to the same controller and authenticated
connection until an explicit recovery delegation. No mutation lease or fence is
issued before sealing. Preparation is invalidated by expiry, fence or generation
change, baseline conflict, backend/version change, boot/suspend epoch change, or
unresolved journal state.

`apply_step` MUST name the prepared plan, exact `StepId`, and
`OperationDigest`. It carries no mutable operation payload. The helper loads the
durably sealed payload, verifies all dependencies and the expected state
revision, and executes only that node. A mismatch, out-of-order node, omitted
node, substituted payload, or step not in the graph fails without mutation.
The same binding applies to observe, compensate, commit, and recovery records;
recovery never asks a new Supervisor to recreate an old payload.

For a sealed non-helper node, external execution is a helper-authoritative,
two-stage online gate rather than an offline bearer permit:

1. `issue_external_permit` fsyncs `ExternalIntentDurable` for `Direction=Apply`
   or `ExternalCompensationIntentDurable` for `Direction=Compensate`, then moves
   one `PermitId` to `Issued`. It MUST acquire the same cross-process mutation
   lock as takeover before validation, reread authority/fences/revision and the
   journal head, then atomically fsync the intent, full permit, idempotency
   result, and next revision before releasing the lock. The permit record seals
   its immutable authority, `ParentJournalHeadDigest`, resulting
   `IssuedJournalHeadDigest`, and `IssuedStateRevision`; the response returns
   both heads, while its common `StateRevisionAtResult` is the issued revision
   and its common `JournalHeadDigestAtResult` equals the issued head. Thus
   takeover observes a complete issued permit in its sealed recovery base/plan,
   or takeover wins and issue returns `StaleFence` without appending an intent.
   An apply permit binds
   activation authority. A normal-stop compensation permit also binds activation
   authority; a takeover compensation permit binds the helper recovery epoch/
   plan/base root plus its controller delegate authority. Every permit also
   binds `ControllerId`, connection binding, plan/step/operation digests,
   generation, exact `RuntimeInstanceId`, executor identity, nonce, and suspend-
   aware expiry. The returned permit is only a redeem ticket; possessing it does
   not authorize launch, attach, control, or stop.
2. The executor must call `redeem_external_permit` over a live authenticated gate
   channel. The helper acquires the same cross-process mutation lock used by
   takeover and loads authority only from the sealed permit record; redemption
   never resubmits or rewrites it. The request supplies the permit ID, live gate
   binding, and exact current journal-head/revision expectations. The helper
   proves the issued head is an ancestor of the current authenticated hash chain
   and that no later record superseded/revoked the permit, changed its authority/
   delegate fences, consumed it, or conflicted with its resource. Unrelated
   journal advancement does not invalidate the immutable permit, but a stale
   current-head/revision expectation fails before action and may be retried with
   a new idempotency key. The fresh error, any intervening operation response,
   and `Status` all expose their linearized tip in the common response header;
   the caller never guesses or reads the journal directly. The helper then
   fsyncs `Redeeming` before it sends any executor instruction. It retains the
   lock through the bounded launch/attach
   or exact-instance compensation, protected instance handshake, read-back,
   typed observation, and `AppliedDurable` or `CompensatedDurable` fsync. Only
   then may it mark the permit `Consumed`, release the lock, and reply.

For `Apply`, a process may be created only in an inert state after the online
gate opens; it cannot attach to a TUN, accept product work, or send/receive
session traffic before a helper gate command. The protected actor echoes the
permit and exact `RuntimeInstanceId`; after any staged attach, it remains fail-
closed until the helper fsyncs `AppliedDurable` and sends a durable-result
acknowledgement while still holding the lock. Gate-channel/helper loss before
that acknowledgement forces immediate detach/quiescence and self-termination.
For `Compensate`, the executor may control only that exact protected instance
and the helper must fsync a typed absence observation. A backend/executor that
cannot provide these bounded fail-closed stages is unsupported. A fence after
issuance rejects redemption without launch; a fence cannot occur during
redemption because the same lock is held; after lock release takeover observes
either the durable applied or compensated result. Duplicate, expired,
stale-controller/delegate, stale-fence, lost-response, and already-consumed
redemption never repeat the external action.

After a successful authenticated handshake, `Response` is a closed tagged union
consisting of a common header plus exactly one operation-specific variant.
Pre-handshake rejection is a bounded transport failure mapped locally to
`Unauthenticated`; it cannot expose a controller or journal field. The common
header is:

```text
ProtocolVersion
RequestId
ControllerId
ConnectionBindingEpoch
OutcomeKind
SafeSessionPhase
StateRevisionAtResult
JournalHeadDigestAtResult
```

`StateRevisionAtResult` and `JournalHeadDigestAtResult` are the authenticated
state-index and hash-chain tip at the response's linearization point. Every
success, typed error, and status response carries both. A state-changing
operation durably stores the complete response with its idempotency result, so
an exact replay returns the original result tip rather than pretending it is a
fresh snapshot. A caller that needs the newest tip issues `Status` or a new
request; a newly evaluated stale-head/revision error reports the tip observed
under the mutation lock. Thus every authenticated controller has a protocol
path to form its next exact expectation without reading helper storage. For
`JournalFailure` or `JournalCorrupt`, the fields are only the last protected-
index tip available for diagnosis; all mutations remain blocked and that tip
cannot authorize a retry until reconciliation establishes a valid chain.

The operation-specific variants are:

```text
PreparationGranted {
  SessionId, AttemptId, Generation, PreparationTicketId,
  PreparedAtBootEpoch, ContinuousExpiresAt
}
PlanPrepared {
  PreparedPlanId, PlanDigest,
  ActivationLeaseId, LeaseEpoch, FenceToken, ContinuousExpiresAt,
  RenewalChallengeNonce, RenewalChallengeExpiresAt
}
ExternalPermitIssued {
  PermitId, Direction, SealedAuthorityDigest, RuntimeInstanceId,
  ParentJournalHeadDigest, IssuedJournalHeadDigest,
  PermitState=Issued, ContinuousExpiresAt
}
ExternalGateResult {
  PermitId, Direction, StepId, OperationDigest, RuntimeInstanceId,
  ObservedResourceIdentity, ObservedStateDigest, OwnershipProof, MutationPhase
}
LeaseRenewed {
  ActivationLeaseId, LeaseEpoch, FenceToken,
  ContinuousExpiresAt, RenewalEvidenceDigest,
  NextRenewalChallengeNonce, NextChallengeExpiresAt
}
RecoveryGranted {
  RecoveryEpoch, RecoveryFenceToken, RecoveryBaseRootDigest,
  RecoveryPlanId, RecoveryPlanDigest,
  RecoveryDelegateLeaseId, RecoveryDelegateEpoch,
  RecoveryDelegateFenceToken, DelegatedNodeSetDigest,
  DelegateContinuousExpiresAt
}
RecoveryFinalized {
  SessionId, AttemptId, Generation,
  AcknowledgedJournalHeadDigest, AcknowledgedStateRevision,
  RuntimeAbsenceObservationSetDigest, BaselineEquivalentEvidenceDigest
}
StepResult {
  StepId, OperationDigest, ObservedResourceIdentity,
  ObservedStateDigest, OwnershipProof, MutationPhase
}
StatusSnapshot =
  InactiveStatus {
    GenerationHighWater, CapabilitySummaryDigest,
    LastFinalizationReceipt = None
                            | Receipt(SessionId, AttemptId, Generation,
                                      AcknowledgedJournalHeadDigest,
                                      AcknowledgedStateRevision,
                                      ResultingJournalHeadDigest,
                                      ResultingStateRevision,
                                      RuntimeAbsenceObservationSetDigest,
                                      BaselineEquivalentEvidenceDigest)
  }
| PreflightingStatus {
    SessionId, AttemptId, Generation,
    PreparationSummary = None | OwnedPreparation(PreparationTicketId,
                                                  ContinuousExpiresAt)
  }
| TransactionStatus {
    SessionId, AttemptId, Generation, MutationPhase,
    PlanSummary = NoPlan | Prepared(PreparedPlanId, PlanDigest),
    AuthoritySummary = NoAuthority
                     | OwnedActivation(ActivationLeaseId, LeaseEpoch,
                                       FenceToken, ContinuousExpiresAt)
                     | HelperRecovery(RecoveryEpoch, RecoveryFenceToken,
                                      RecoveryBaseRootDigest,
                                      RecoveryPlanId, RecoveryPlanDigest,
                                      DelegateSummary = NoDelegate
                                                      | OwnedDelegate(
                                                          RecoveryDelegateLeaseId,
                                                          RecoveryDelegateEpoch,
                                                          RecoveryDelegateFenceToken,
                                                          DelegatedNodeSetDigest,
                                                          DelegateContinuousExpiresAt))
  }
ErrorResult { Retryability, BoundedError }
```

Every authority-bearing variant is bound to the common-header `ControllerId`
and current connection-binding epoch. Status returns `Owned*` only to that
owner; another controller receives `NoAuthority`/`NoDelegate` while still seeing
the safe non-secret phase. A response cannot mix variants or omit a field
required by its operation. `OutcomeKind` selects the variant; arbitrary
extension fields are rejected during the negotiated protocol version.

Arbitrary OS error strings are diagnostic input, not protocol output. Backends
map them to a bounded code and keep only redacted local diagnostics.

## Compile-time operation registry

The helper accepts only operations compiled into the selected backend and
registered by an accepted architecture contract. Each operation version MUST
declare:

- exact typed fields and size limits;
- authorization and platform preconditions;
- stable identity discovery and owner proof;
- normalized managed, identity, and passthrough fields;
- before/postcondition read-back functions;
- idempotency and conflict rules;
- a bounded mutation deadline;
- compensation and recovery behavior; and
- deterministic and real-host acceptance cases.

`core.session` session/journal/lease operations are owned by ARCH-001. TUN resource
operations may be registered by the platform backend selected by ADR-0004.
`egress.*`, `trust.ca.*`, `transport.udp.*`, and `dns.*` operations cannot be
enabled until their owning architecture contracts are accepted.

`trust.ca.*` is reserved for an ARCH-003-defined persistent transaction class.
It may reuse the helper's authentication, journal, fencing, and conditional-
restore primitives, but it MUST NOT use a network-session generation or be
compensated merely because a TUN session stops or loses its lease.

The registry MUST NOT contain a generic shell runner, executable launcher,
arbitrary file writer, arbitrary path operation, environment override, raw
netlink/route-socket/WFP request, arbitrary JSON mutation, dynamic native
plugin, or renderer-defined operation. A user-provided sing-box configuration
or command line is never a helper payload.

## Journal authority and durability

The helper journal is an authenticated, checksummed, schema-versioned,
hash-chained append log plus an atomically published state index. The protected
index binds `InstallationEpoch`, generation high-water, record sequence,
previous-root digest, and current root digest. It is the authoritative recovery
record; the UI database and Supervisor memory are only mirrors.

`MutationPhase` is this closed protocol enum:

```text
Planned
IntentDurable
ExternalIntentDurable
ExternalCompensationIntentDurable
PermitIssued
Redeeming
ObservedDurable
AppliedDurable
CompensatedDurable
UnappliedDurable
CommittedDurable
RecoveryFinalizedDurable
AmbiguousDurable
```

An operation direction determines its successful terminal phase: apply requires
`AppliedDurable`, compensate requires `CompensatedDurable`, pure observe requires
`ObservedDurable`, session commit requires `CommittedDurable`, and recovery
finalization requires `RecoveryFinalizedDurable`. `AmbiguousDurable` is never a
success. Response variants cannot carry a phase outside this enum.

Journal storage MUST be local, non-roaming, persistent across service restart
and boot, inaccessible to interactive users and the renderer, and protected
against symlink/path substitution. Approved locations are:

| Platform | Storage requirement |
| --- | --- |
| Windows | A fixed service-SID-restricted directory under `%ProgramData%`; use tested file flush and atomic publication primitives |
| macOS | A fixed root-owned directory under `/Library/Application Support/FlowProbe`; use tested durable file and directory barriers |
| Linux | A root-owned systemd `StateDirectory=` under `/var/lib`; never `RuntimeDirectory=`, `/run`, `/tmp`, or the interactive user's home |

Before every mutation, the helper MUST durably append the prepared plan/step
digests, transaction class, generation, applicable activation authority or
helper-recovery plus external-delegate authority, fences, state revision,
backend,
step/dependencies, resource owner and stable identity, normalized before image
and provenance, managed-field mask, intended postcondition, compensation,
idempotency key, and `IntentDurable` phase. The durability barrier MUST complete
before the OS call.

Before a sealed non-helper process/service node executes, the helper similarly
appends `ExternalIntentDurable` or `ExternalCompensationIntentDurable` with its
pre-sealed `RuntimeInstanceId`, direction, controller, and activation or helper-
recovery/delegate authority. Issuance alone grants no execution authority. The live
executor and protected runtime control handshake MUST complete the online gate
protocol while the helper holds the mutation lock; the helper records the
resulting typed presence or absence observation durably. An executor that
cannot start inert, validate the gate, bind exact instance identity, or fail
closed on a pre-result channel loss is unsupported.

After the call, the helper MUST rediscover the OS object, verify ownership and
the direction-specific success predicate, and durably append the observed
after/before image, tombstone, or absence proof plus the applicable successful
terminal phase before allowing a dependent mutation or commit. It MUST withhold
helper IPC success until `AppliedDurable` for apply or `CompensatedDurable` for
compensation. If that response is lost, the same idempotency key returns the
durable result without another OS call. Return status or command exit code alone
is not evidence.

Journal records MUST include the boot/suspend/network-namespace observation
needed to detect an ephemeral locator change, but those values do not become
stable identity. Each registered transaction class MUST define its own sealed
terminal and retention predicate; a journal cannot be pruned while that
predicate is false or any resource is unresolved. For `core.session` only, the
predicate is baseline-relative `BaselineEquivalent` plus acknowledgement by the
Supervisor of the final revision after every exact internal instance is proven
stopped. It is not unconditional Internet reachability. The helper may publish
only its own `NetworkRestoredAwaitingController` phase before that
acknowledgement. A future persistent class such as `trust.ca.*` uses the
terminal/retention semantics defined by its owning contract, not the network-
session predicate.

Unknown versions, invalid checksums, missing durable ancestors, inconsistent
state revisions, or authentication failures yield `JournalCorrupt` or
`ProtocolMismatch` and `RecoveryRequired`. The helper does not guess, reset, or
delete such state.

## Mutation and compare-before-restore

For each mutation the helper performs:

```text
acquire cross-process mutation lock
  -> reread durable fence/state revision
  -> authenticate sealed plan and step
  -> discover stable resource
  -> compare expected managed fields
  -> durable intent
  -> one typed OS mutation
  -> OS read-back
  -> verify postcondition and owner
  -> durable direction-specific observed result and terminal phase
  -> release mutation lock
```

The lock is held continuously from the durable fence reread through
`AppliedDurable` or `CompensatedDurable` result fsync. Takeover cannot advance
the fence until it obtains that same lock. A newly acquired lock always forces a
durable reread; cached fence state is never used.

A backend MUST also prove that a submitted OS operation cannot complete after
the executing process dies and releases the lock, or expose a durable OS
operation identity that takeover can settle/cancel before another mutation.
Otherwise process death could create a late stale write after fencing and the
operation is unsupported.

Updating or deleting an externally mutable object is supported only when the OS
mutation consumes an atomic condition/revision token, or when the exact object
instance is proven exclusively FlowProbe-owned. For an operation that deletes a
whole object, `exclusive ownership` covers the complete deletion domain and the
normalized closure of every address, route, rule, attachment, child object, or
other dependency the OS would remove transitively. The backend must either
prevent foreign additions to that closure or prove immediately before deletion,
under an OS condition covering the deletion, that the whole current object and
dependent closure exactly match the recorded owned after-image graph. A managed-
field match alone is not exclusive ownership. Read/compare followed by an
unconditional setter does not detect a write in between and is forbidden. If
the platform lacks a safe primitive, preflight reports `Unsupported`; recovery
preserves the object and reports `RecoveryRequired`.

Rollback applies only when the current managed fields still equal the recorded
after image. A created object is removed only when its stable identity and owner
proof match and an atomic condition covers the exact whole-object/dependent-
closure after image, or exclusive ownership of that entire deletion domain is
still proven. Any added passthrough field or foreign dependent/attachment is
external drift and blocks deletion, even if every FlowProbe-managed field still
matches. An updated object restores only its managed fields and preserves
passthrough fields through an OS conditional/revisioned mutation. If an OS
setter necessarily replaces a whole object, it is supported only with an
enforceable version/lock covering the whole replaceable normalized object;
read-back after an unconditional replace is insufficient.

An object already equal to its before image or a safely absent created object
is idempotently restored. Any other difference is external drift: preserve it,
record a bounded non-secret diff, and enter `RecoveryRequired`.

Destructive replace-on-conflict, deletion by interface name/index, PID, rule
priority alone, or whole-store baseline restoration is forbidden.

## Lease, owner loss, and startup reconciliation

After verifying there is no unresolved earlier `core.session` journal or
declared conflicting resource transaction, the helper may issue a short-lived
`PreparationTicketId` bound to the new generation, `ControllerId`, and
connection-binding epoch for read-only discovery. It authorizes no mutation.
Only successful durable `prepare_plan` sealing atomically issues an
`ActivationLeaseId`, durable monotonic `LeaseEpoch`, and ordered fence bound to
the exact plan digest, generation, `ControllerId`, connection-binding epoch,
boot/suspend epoch, and nonce.

Renewals use a platform clock that advances through suspend plus durable
boot/suspend epoch. Wall-clock time is informational only. Boot,
suspend/resume, or clock-domain discontinuity invalidates prepared plans and
active leases; after acquiring the mutation lock the helper advances the fence
and reconciles. v0.2 never silently reactivates the old session.

A renewal is accepted only with a fresh helper nonce and plan/generation/fence-
bound observation digests for every mandatory actor, resource postcondition,
and mode-specific connectivity predicate inside its sealed freshness window.
The helper re-queries safety-critical OS state on the sealed cadence. A simple
controller heartbeat, cached boolean, stale evidence, or optional-actor success
cannot extend the lease.

Renewal and watchdog takeover are one conditional state transition domain. For
`renew_activation_lease`, the helper acquires the same cross-process mutation
lock, durably rereads generation, plan, `ControllerId`, connection binding,
activation lease/epoch/fence, state revision, expiry, challenge, and observation
digests and performs required fresh OS queries. Immediately before the renewal
fsync it rereads the suspend-aware clock and boot/suspend epoch and revalidates
that `now < old ContinuousExpiresAt`, the request deadline has not passed, and
the one-use challenge plus every observation remains inside its freshness
window. Crossing the old lease deadline is irreversible even while this lock
blocks the watchdog: the helper rejects renewal and, under the same lock,
advances the activation fence and enters recovery. Otherwise it atomically
appends and fsyncs the new deadline, evidence digest, consumed challenge, next
challenge/expiry, and next state revision before replying `LeaseRenewed`. The
idempotency key returns that exact durable result. The watchdog obtains the same
lock before evaluating expiry or advancing the fence. Therefore exactly one
ordering is possible: a still-timely renewal commits first and takeover observes
the later deadline, or expiry/takeover wins and renewal cannot extend the lease.

A supported active data path also requires a fail-closed `ResumeBarrier` whose
ordering is enforced before user-space scheduling can forward the first packet
after cold boot, suspend, or hibernate. An OS/kernel gate installed before
activation MUST automatically close on boot/suspend/hibernate epoch change and
on helper/watchdog/gate-channel death, independently of later helper scheduling.
A pre-suspend inhibitor/removal sequence qualifies only if the platform proves
that inhibitor-holder death or forced suspend atomically closes the same gate or
removes steering before suspend can complete. A normal inhibitor that vanishes
with a crashed helper, post-resume callback, runtime heartbeat, timer, or
eventual reconciliation is not a barrier. The old generation's barrier is never
reopened: reconciliation rolls it back. A platform/mode without this proof
reports `Unsupported` with reason `ResumeGateMissing` before mutation.

When the controller disconnects, misses its deadline, or presents stale state,
the helper/watchdog MUST:

1. acquire the exclusive journal/mutation lock;
2. reread the durable state and durably advance the lease epoch/fence;
3. snapshot immutable `RecoveryBaseRootDigest`, derive and seal
   `RecoveryPlanId + RecoveryPlanDigest` from its uncompensated observe/reverse-
   compensation nodes, and advance the helper-owned monotonic `RecoveryEpoch +
   RecoveryFenceToken`; internal recovery uses only that authority and never a
   controller delegate lease;
4. reject all commands from the old controller;
5. classify every durable intent using stable discovery and postconditions;
6. compensate proven owned resources in reverse dependency order; and
7. publish helper phase `NetworkRestoredAwaitingController` only after no
   privileged session resource remains and `BaselineEquivalent` is proven;
   otherwise publish helper phase `RecoveryRequired`.

The helper MUST NOT publish session `Inactive` or kill a process selected by
PID/name. `claim_recovery` returns `RecoveryGranted` only after it atomically
persists the idempotency result and a separate `RecoveryDelegateLeaseId +
RecoveryDelegateEpoch + RecoveryDelegateFenceToken`, bounded node subset,
`ControllerId`, connection binding, state revision, and expiry. The immutable
base root and current journal head are distinct response fields. A newly
authenticated Supervisor then resumes `Recovering`, rediscovers each pre-sealed
`RuntimeInstanceId` through the protected Network Runtime/Capture control
identity, and stops or proves absent every internal node through a delegate-
bound `Direction=Compensate` external gate. The helper fsyncs
`ExternalCompensationIntentDurable` before the stop/prove-absent instruction and
a typed exact-instance absence observation afterward. Delegate expiry or loss
fences its requests and permits without interrupting helper-internal recovery;
a later controller must claim a new delegate lease. Only after the Supervisor
acknowledges the exact current pre-finalization journal head/revision may the
helper finalize the `core.session` journal and the Supervisor publish
`Inactive`. Ambiguous process identity keeps the session `RecoveryRequired`
even if ordinary networking is restored.

That acknowledgement is the explicit idempotent `AcknowledgeRecovery` variant,
not a recovery step or commit alias. Under the mutation lock the helper reloads
the helper recovery epoch/fence/base/plan, live delegate binding and expiry,
request's `ExpectedCurrentJournalHeadDigest` and common
`Exact(ExpectedStateRevision)`, every privileged compensation result, the
complete typed exact-runtime absence observation set, and `BaselineEquivalent`
evidence. Immediately before finalization it rechecks delegate time/fence and
that exact pre-finalization head/revision. Any expiry, new record, unresolved
resource, ambiguous instance, or failed terminal predicate rejects without
finalization; an expired delegate is fenced and a new controller must reclaim
and revalidate.

On success the helper atomically fsyncs the acknowledgement idempotency mapping,
terminal evidence, and `RecoveryFinalizedDurable`, then returns
`RecoveryFinalized`. Its variant echoes the acknowledged pre-finalization head/
revision; the common `JournalHeadDigestAtResult` and `StateRevisionAtResult` are
the new post-finalization tip. The durable idempotency result and installation
receipt retain both pairs.

The helper still does not publish the product session as `Inactive`. The owning
Supervisor may publish it from that response or its exact idempotent replay. If
that process and its ephemeral key are permanently lost after finalization, any
new authenticated Supervisor may instead publish `Inactive` from
`InactiveStatus.LastFinalizationReceipt`; the receipt is read-only terminal
proof and grants no mutation, recovery, permit, lease, or controller authority.
The latest receipt remains in the protected installation index independently of
transaction-journal pruning and without a time-based expiry. `InactiveStatus`
returns it only while its session/attempt/generation is the installation's
current terminal generation; durable allocation of a later generation retires
it as publication proof. It is not limited to the original controller's
protocol retry window.

For an intent without a durable after image:

- a proven unchanged before image or absent create target is unapplied;
- a proven intended state with matching owner is first completed with a
  durable observed after image and then compensated;
- partial state, multiple candidates, missing owner proof, or ambiguous
  identity is preserved and becomes `RecoveryRequired`.

An `ExternalIntentDurable` or `ExternalCompensationIntentDurable` record without
an observation is resolved by the same rule using the exact
`RuntimeInstanceId`, permit state, helper recovery epoch/plan, delegate authority
when external, and protected executor control. A new controller can act only
after `RecoveryGranted` and online redemption of a new delegate-fenced
compensation permit; an expired/old-controller permit or direct runtime-control
call is rejected. It compensates a proven instance, records a proven absence,
and otherwise refuses to kill a candidate and enters `RecoveryRequired`.

SCM failure actions, systemd `Restart=`, systemd watchdogs, launchd restart,
Network Extension restart, process cleanup, or closure of a non-persistent TUN
descriptor may reduce exposure but cannot replace reconciliation.

## Platform authority and packaging

### Windows candidate backend

- Install a signed per-machine `SERVICE_WIN32_OWN_PROCESS` service with ordinary
  automatic start. UI/renderer processes remain unelevated.
- Install the orchestration owner as a separate non-administrator service with
  its own service SID. Only that identity can open the helper pipe; the desktop
  host uses a narrower product IPC surface and never receives helper channel
  credentials.
- Bind each controller key to the named-pipe peer's live process object, the
  SCM-reported current service instance, and signed executable identity. The
  release integration must deny peer-SID process-handle duplication/debug/dump
  access and exclude the key from Windows crash dumps; SID equality alone is not
  controller proof.
- Restrict the service object, pipe, and `%ProgramData%` journal with a service
  SID and explicit DACLs. Service failure actions are availability only.
- Treat the official pre-signed Wintun DLL as a fixed audited backend dependency,
  not a plugin. Install it at one administrator-owned, non-user-writable path;
  load only that absolute path with DLL-search hardening; verify its Authenticode
  publisher, allowed version, and signed-manifest hash before load. Never search
  the working directory, `PATH`, renderer input, or a profile path. A mismatch
  is `BackendVersionMismatch`/`Unsafe` before mutation. Record the observed OS
  `InterfaceGuid`, tunnel type, installation owner marker, and other device
  identity; `IfIndex` and a requested GUID, including any higher-layer
  name-derived requested value, are locators or creation inputs, not sufficient
  recovery identity.
- Candidate route discovery/create/read-back uses typed IP Helper rows and full
  normalized tuples bound to the owned adapter identity, but those APIs alone
  do not prove atomic CAS; update/delete remains unsupported without an exact
  conditional or exclusive-owned resource proof. DNS operations target
  `InterfaceGuid` through the
  supported per-interface API only when the backend proves an exact
  exclusively owned adapter/object or a conditional mutation; shared-interface
  unconditional DNS replacement is unsupported. WFP objects use generation-
  derived provider, sublayer, and filter GUIDs; a dynamic WFP session is cleanup
  assistance only.
- Durable process ownership is the sealed `RuntimeInstanceId` plus protected
  runtime handshake and package/launch evidence. A retained process handle and
  creation/file identity corroborate only the live instance; PID is only a
  locator and cannot recover ownership after handle loss.
- The initial candidate floor is Windows 10 build 19041 or later on x86_64,
  because the selected per-interface DNS API starts there. Windows Server and
  other architectures remain unverified until separately exercised. Until the
  isolated Supervisor identity, runtime attachment, fail-closed resume gate, and
  real-host suite are implemented and tested, the result remains
  `UnsupportedPendingArchitecture`/`Unsafe`/`DesignOnly` with reasons
  `PeerBindingImplementationMissing`, `ExternalRuntimeAttachmentMissing`,
  `ResumeGateMissing`, and `RealHostUnverified`.

Primary references: Microsoft documents [service security and access
rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights),
[service SID configuration](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info),
[named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[interface GUID versus volatile interface
index](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter),
[IP Helper route
creation](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2),
[IP Helper route
read-back](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardentry2),
[per-interface DNS
settings](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings),
and [WFP dynamic-session
lifetime](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0),
plus the GUID-key fields for
[`FWPM_PROVIDER0`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0),
[`FWPM_SUBLAYER0`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0), and
[`FWPM_FILTER0`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0).
Wintun publishes its [signed DLL and supported
API](https://www.wintun.net/).

### Linux candidate backend

- Install a fixed system service, typed Unix IPC endpoint, and explicit polkit
  product action through a release-tuple-specific distribution/repository-
  authenticated package and service integration. The authenticity mechanism is
  currently unselected; no `.deb` or `.rpm` packaging is supported until the
  release tuple and its package/repository authentication contract are selected.
  The service holds only justified capabilities, initially `CAP_NET_ADMIN`; add
  `CAP_NET_RAW` only when an accepted operation proves it necessary.
- Run the orchestration owner as a separate fixed non-root service UID. The
  helper socket grants access only to that UID; the interactive desktop uses a
  different typed product endpoint and never receives helper channel material.
- Bind the controller key to the Unix peer credentials plus the live service
  process object/instance evidence. The release service must deny same-UID
  ptrace/process-memory/core-dump access, prevent key inheritance, and keep the
  key in locked no-dump memory; UID equality alone is not controller proof.
- Apply `CapabilityBoundingSet`, `NoNewPrivileges`, filesystem/device/address-
  family restrictions, `Type=notify`, `WatchdogSec`, and
  `Restart=on-failure`. Send `READY=1` only after boot reconciliation.
- The candidate operation uses non-persistent `/dev/net/tun` and would persist an
  installation/generation owner marker in `IFLA_IFALIAS` and rediscover it with
  network-namespace and device-kind evidence. Interface name and ifindex are
  current locators only.
- Route/rule backends use typed rtnetlink operations, exclusive creation, full
  normalized tuples, and explicit FlowProbe table/protocol/mark ownership. The
  full tuple is identity evidence, not automatically atomic CAS; update/delete
  remains unsupported unless the operation targets an exact exclusive-owned
  instance or gains a platform conditional token. A priority or table number
  alone is never deletion authority.
- systemd-resolved uses its per-link D-Bus API after rediscovering the current
  link. It MUST NOT blindly call whole-link `RevertLink`. Because the per-link
  setter has no shared-object CAS in this contract, it is usable only for an
  exact exclusively FlowProbe-owned link whose lifecycle is safely conditional;
  otherwise it is unsupported. A NetworkManager backend is separate and uses
  connection UUID plus applied-connection version as its CAS input. Direct
  edits to `/etc/resolv.conf` and mixed/unknown resolver ownership are
  unsupported.
- Durable process ownership is the sealed `RuntimeInstanceId` plus protected
  runtime handshake/package/launch evidence. pidfd and boot/process-start/file
  observations corroborate only a live instance; PID, unit name, cgroup, or
  service restart alone is not durable identity.
- Candidate prerequisites are x86_64, systemd, a kernel floor selected as part
  of the release tuple, authenticated package/service and polkit/D-Bus
  integration, and exactly one selected resolver backend. No release
  distribution/kernel/systemd/resolver/NetworkManager tuple is selected by
  ARCH-001, so every Linux host remains
  `StaticSupport=UnsupportedPendingArchitecture`/`Readiness=Unsafe`/
  `Evidence=DesignOnly` with reasons `ReleaseTupleUnselected`,
  `ExternalRuntimeAttachmentMissing`, `PeerBindingImplementationMissing`,
  `ResumeGateMissing`, and `RealHostUnverified`. “Linux” by itself is never a
  support claim.

Primary references: the Linux kernel documents
[TUN/TAP](https://docs.kernel.org/networking/tuntap.html),
[link attributes including interface alias](https://docs.kernel.org/netlink/specs/rt-link.html),
[route netlink](https://docs.kernel.org/netlink/specs/rt-route.html), and
[rule netlink](https://docs.kernel.org/netlink/specs/rt-rule.html). systemd
documents persistent [`StateDirectory=` and service
sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
and [service watchdog/restart
semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).
The resolver contract is the
[`org.freedesktop.resolve1`](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html)
D-Bus API. polkit warns that PID-only subject identity is racy in
[`PolkitUnixProcess`](https://polkit.pages.freedesktop.org/polkit/PolkitUnixProcess.html).
Linux documents local Unix-socket peer credentials through
[`SO_PEERCRED`](https://man7.org/linux/man-pages/man7/unix.7.html); that peer
UID/PID evidence is combined with, and never replaces, the separate
installation-bound authenticated handshake.

### macOS 26+ candidate backend

- The only authority direction compatible with an independent sing-box process
  is a fixed signed Developer ID LaunchDaemon registered with `SMAppService`
  and a narrow authenticated XPC contract. Apple sources reviewed here do not
  establish a supported native TUN creation API, cross-process handoff, or
  stable native TUN identity; those remain unselected.
- The helper, host, and independent runtime must be correctly signed, hardened,
  and notarized. Denied or pending administrator approval yields typed
  `PermissionMissing`/`InteractionRequired` without mutation.
- Bind the controller key to the XPC audit-token/code-signing peer and current
  launchd service instance. The release must deny peer task-port/debug/dump
  access, key inheritance/export, and crash-dump inclusion; matching code
  signature alone is not controller proof.
- For System Configuration preferences, a candidate identity uses the
  identifier returned by `SCNetworkServiceGetServiceID()` plus protocol type,
  while holding `SCPreferencesLock` across synchronize/reread, change, and
  `SCPreferencesCommitChanges`. The backend would then request
  `SCPreferencesApplyChanges` and independently read back the effective active
  configuration. The lock protects preferences access only;
  `SCPreferencesGetSignature` is saved-preferences change detection, not an
  atomic CAS token or proof that active-state application completed. A revision-
  token/conditional design remains separately unproven. TUN identity has no
  accepted source-backed design. A `utun` name and PID are locators only.
- This remains `UnsupportedPendingArchitecture`/`Unsafe`/`DesignOnly`: the
  current independent sing-box CLI has no stable public external-TUN descriptor/
  configuration contract, Apple native TUN authority/identity is unproven, no
  fail-closed resume gate is selected, real-host evidence is absent, and letting
  sing-box own routes/DNS prevents helper-level before/after journaling and
  compare-before-restore. Reasons include `NativeTunAuthorityUnproven`,
  `ExternalRuntimeAttachmentMissing`, `ResumeGateMissing`, and
  `RealHostUnverified`.

Primary references: Apple documents
[`SMAppService.register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29),
[XPC peer code-signing
requirements](https://developer.apple.com/documentation/xpc/xpc_connection_set_peer_requirement),
[`SCPreferencesLock`](https://developer.apple.com/documentation/systemconfiguration/scpreferenceslock%28_%3A_%3A%29),
[`SCPreferencesSynchronize`](https://developer.apple.com/documentation/systemconfiguration/scpreferencessynchronize%28_%3A%29),
[`SCPreferencesGetSignature`](https://developer.apple.com/documentation/systemconfiguration/scpreferencesgetsignature%28_%3A%29),
[`SCPreferencesCommitChanges`](https://developer.apple.com/documentation/systemconfiguration/scpreferencescommitchanges%28_%3A%29),
[`SCPreferencesApplyChanges`](https://developer.apple.com/documentation/systemconfiguration/scpreferencesapplychanges%28_%3A%29),
[`SCNetworkServiceGetServiceID()`](https://developer.apple.com/documentation/systemconfiguration/scnetworkservicegetserviceid%28_%3A%29),
[`SCNetworkServiceCopyProtocol()`](https://developer.apple.com/documentation/systemconfiguration/scnetworkservicecopyprotocol%28_%3A_%3A%29),
and [notarization for outside-App-Store
distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

`SMAppService.register()` is available from macOS 13, while the selected
`xpc_connection_set_peer_requirement` peer requirement is available from macOS
26. The combined candidate floor is therefore macOS 26. Older releases remain
unsupported until a separate primary-sourced peer-authentication architecture
is accepted.

No candidate above becomes supported until its versioned independent-process
TUN attachment/mutation ownership contract and real privileged acceptance
matrix pass. Current sing-box `auto_route`, `auto_redirect`, or DNS management
MUST NOT run alongside helper ownership.

## Permission, update, and uninstall behavior

Permission or user approval is established before preparation. The background
helper MUST NOT display its own UI or continue into partial mutation after a
permission failure. It returns `PermissionDenied`, `PermissionMissing`, or
`InteractionRequired`; the Supervisor may then initiate the platform-approved
user flow.

Only the signed installer/update mechanism may replace or reconfigure the
helper. Update and uninstall MUST refuse new sessions and first reconcile the
current journal. Uninstall MUST NOT remove the helper, journal, or recovery
authority while an owned resource or `RecoveryRequired` record remains.

FlowProbe is unreleased at this decision point. Current internal formats may be
replaced directly, and no compatibility shim or journal migration is added by
this architecture. A future production upgrade/migration policy requires an
explicitly authorized task.

## Error contract

The helper error kinds are:

```text
Unauthenticated
Unauthorized
ProtocolMismatch
UnknownOperation
InvalidPayload
ReplayDetected
StaleGeneration
StaleLease
StaleFence
StaleStateRevision
PlanExpired
Conflict
ResourceNotOwned
PreconditionFailed
ExternalDrift
PolicyProhibited
PermissionDenied
PermissionMissing
InteractionRequired
Unsupported
TimedOut
BackendUnavailable
MutationFailed
MutationAmbiguous
PostconditionFailed
JournalFailure
JournalCorrupt
RecoveryRequired
IntegrityFailure
```

Every failure reports the safe observed phase, operation kind, resource kind
when authenticated, retryability, and bounded stable code. A retryable label
never permits automatic retry of `MutationAmbiguous` without reconciliation.

The normative helper-to-session mapping is:

| Helper error | Session error |
| --- | --- |
| `Unauthenticated`, `Unauthorized` | same named session error; do not reveal protected details |
| `ProtocolMismatch` | `BackendProtocolMismatch` |
| `UnknownOperation`, `InvalidPayload` | `InvalidRequest` unless the installed helper lacks a plan-required version, then `BackendProtocolMismatch` |
| `ReplayDetected`, `IntegrityFailure` | `IntegrityFailure` |
| `StaleGeneration`, `StaleLease`, `StaleFence`, `StaleStateRevision`, `PlanExpired` | same named session error |
| `PolicyProhibited`, `PermissionDenied`, `PermissionMissing`, `InteractionRequired`, `Unsupported`, `TimedOut` | same named session error |
| `BackendUnavailable` | `HelperUnavailable` |
| `JournalFailure`, `JournalCorrupt` | `JournalUnavailable`, `JournalCorrupt` respectively |
| `MutationFailed`, `MutationAmbiguous`, `PostconditionFailed`, `ExternalDrift`, `RecoveryRequired` | same named session error |
| `Conflict`, `ResourceNotOwned`, `PreconditionFailed` | `PreflightFailed` before apply; `ExternalDrift` during compensation/recovery; otherwise `MutationFailed` |

## Verification

The helper conformance suite MUST cover:

- unauthenticated, wrong-installation, same-user impostor, stale/replayed,
  malformed, oversized, downgrade, and unknown-operation requests, including
  proof that an interactive same-UID process cannot obtain the dedicated
  Supervisor identity, endpoint, or channel binding;
- byte-exact deterministic-CBOR and SHA-256 domain-separated golden vectors for
  every request/response/nested variant and registered operation, plus rejection
  of non-minimal integers, wrong array length/order, invalid UTF-8/NFC, unknown
  tags, trailing bytes, and a digest reused across a different domain/version;
- two controllers and watchdog takeover proving the cross-process lock spans
  durable fence reread through applied-result fsync; pause the old writer after
  validation and prove takeover cannot advance or mutate concurrently; include
  two helper-assigned `ControllerId` values under the same OS service identity,
  concurrent attempts to register the same ID/key, wrong-key proof, live-
  connection rebind refusal, proven-close reconnect/epoch rotation, and replay
  against controller-bound preparation, activation, and recovery delegation;
- same-UID/SID peer attempts to read/duplicate the controller process/key/handle,
  ptrace or debug it, create/read a core or crash dump, inherit the key, or reuse
  a copied public/private-key blob from a different live process; real-host
  release tests must prove all fail before helper authority is granted;
- pause `renew_activation_lease` after evidence validation and race watchdog
  expiry/takeover, including a pause that crosses the old deadline while holding
  the lock, proving that only a still-timely renewal can commit and an expired
  lease is fenced without extension; verify initial/next challenge rotation;
- idempotency-key replay with equal and unequal payloads, including response loss
  after `PreparePlan` and `ClaimRecovery` fsync on the same connection and after
  a proven reconnect; the grant and full response must not be regenerated;
- plan/step/operation/authorization/observation substitution and replay of
  apply and recovery-compensation external permits; pause issue after validation
  and race takeover, cover issue then fence then late redeem, crash in
  `Redeeming`, gate-channel loss, response loss, and prove launch cannot precede
  `ExternalIntentDurable`, occur after fencing, or escape inert state before the
  helper-held gate completes; explicitly prove parent `H0` -> issue/issued `H1`
  -> redeem at `H1`, issue `H1` -> lease renewal `H2` -> stale redeem returning
  `H2` -> new-key redeem at `H2`, unrelated internal-recovery head advancement,
  superseding fence/revocation, and stale-current-head retry without authority
  resubmission;
- recovery delegate expiry, disconnect, replacement, and stale permit/request
  races, proving delegate fencing never transfers or stalls helper-internal
  recovery and a changing node set requires a new recovery base/plan/fence;
- `AcknowledgeRecovery` success, lost response/idempotent receipt replay,
  delegate expiry immediately before final fsync, and concurrent internal
  recovery append, proving only an unchanged exact pre-finalization head/
  revision plus complete resource/runtime/terminal evidence can produce
  `RecoveryFinalizedDurable`; prove `H0/R0` acknowledgement yields a distinct
  resulting `H1/R1`, then permanently kill the owning Supervisor/key before
  response or publication and require a new `ControllerId` to recover the
  read-only receipt through `InactiveStatus` and publish `Inactive`;
- durable-write failure before every OS call and crash after each mutation but
  before read-back or after-image persistence; distinguish backend/OS API return
  from helper IPC response, which MUST occur only after direction-specific
  `AppliedDurable` or `CompensatedDurable`;
- lost helper responses after `AppliedDurable`, `CompensatedDurable`, and
  `RecoveryFinalizedDurable`, followed by the same idempotency key returning the
  durable result without another OS/external action;
- stable-identity rediscovery across process restart and boot, including name,
  index, and PID reuse;
- external changes to managed and passthrough fields and a write precisely
  between compare and an unconditional setter, proving such a backend is
  unsupported rather than overwriting drift; add a foreign address, route, or
  attachment beneath a FlowProbe-created interface and prove whole-object
  deletion is refused without removing that dependent state;
- journal truncation, checksum failure, incompatible schema, read-only/full
  storage, record/request replay against the current installation epoch, and
  path/symlink substitution; whole privileged-store snapshot rollback is
  explicitly outside the stated threat model;
- bounded OS/API hangs and lost helper responses;
- proof that logs, errors, and journals never contain injected credentials,
  captured data, full configuration, or private keys; and
- install approval denial, helper update, uninstall, and boot with active,
  pre-commit, rollback-interrupted, and stale journals; and
- Wintun missing/wrong signer, hash, version, ACL, absolute path, and DLL-search
  hijack cases, proving no library loads and no mutation occurs; and
- suspend/resume before intent, after OS return, while active, and during
  rollback, plus helper/watchdog crash immediately followed by suspend/hibernate
  and cold boot, proving the OS-enforced `ResumeBarrier` blocks every old-
  generation packet from the first packet, then old plan/lease invalidation and
  reconciliation occur before any later mutation.

Each claimed platform also requires release-packaged privileged tests on real
hosts. Tests run with an out-of-band management path and directly enumerate OS
TUN, route/rule, firewall, DNS, process, and journal state. They verify IPv4,
IPv6 when baselined, resolver behavior, route selection, intended data-path
egress, ordinary connectivity before/during/after the session, and recovery
after UI, Supervisor, runtime, helper, watchdog, and machine crashes.

Service-manager “running”, process exit, TUN descriptor closure, or a passing
fake backend is never sufficient support or rollback evidence.
