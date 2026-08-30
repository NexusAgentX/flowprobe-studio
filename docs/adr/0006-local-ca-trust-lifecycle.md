# ADR-0006: Local CA trust lifecycle

Status: Accepted

Task: ARCH-003

## Decision scope

FlowProbe will manage a local interception certificate authority as persistent,
consented product state through a generation-fenced transaction independent of
temporary network sessions. A separate CA key authority owns the protected
private key. The generic privileged helper owns the authenticated trust journal
and daemon-safe privileged trust mutations but never receives the key.
Current-user trust is performed only by a live authenticated user-context agent
under a one-use helper gate. macOS Admin Trust Settings require a separate
foreground GUI agent and native administrator authentication under the same
journaled gate; the LaunchDaemon cannot substitute for it.

Trust installation, verification, removal, drift, rotation, and crash recovery
operate on an exact platform-tagged target and complete certificate DER
identity. TLS interception is allowed only by a fresh dual proof that the
installed certificate, effective target trust, and signing key all refer to the
same current CA generation. A failed or unsupported trust path transparently
passes traffic or refuses interception according to an explicit policy; it
never presents an unverified FlowProbe certificate.

The normative types, state, protocols, platform target semantics, support
truth, and evidence obligations are in
[local-ca-lifecycle.md](../contracts/local-ca-lifecycle.md).

This decision defines architecture only. It changes no accepted helper wire
schema, implements no trust mutation or key storage, and claims no currently
supported platform or browser.

## Preserved architecture

This ADR preserves the frozen decomposition:

- sing-box remains an independent managed Network Runtime process;
- Capture Core remains protocol-oriented and independent from sing-box
  internals;
- the Config Compiler continues to own protected system/runtime overlays;
- third-party analyzers remain in the versioned WASM sandbox;
- raw and normalized capture data remains source material while semantic output
  remains derived and rebuildable; and
- the ARCH-001 helper remains a typed mutation/journal authority, not a generic
  shell, key vault, signing service, TLS endpoint, or captured-data consumer.

Persistent CA state is not a core.session resource. Stopping or rolling back a
TUN session, losing a runtime lease, exiting the application, or rebooting does
not remove trust or imply removal consent. Conversely, trust failure does not
silently uninstall or roll back a separately requested network session.

## Observed baseline

The current Capture Core uses an in-memory P-256 CertificateAuthority for
ephemeral leaf issuance. It has no protected persistent key provider, explicit
persistent-consent receipt, trust-store ownership, platform mutation, durable
journal, exact uninstall, rotation transaction, restart reconciliation, or
real-host/browser evidence. It must not be promoted or imported as v0.2 trust
state.

The accepted ARCH-001 helper protocol v0.2 is a closed deterministic-CBOR union
for core.session preparation, activation, lease, external permit, recovery, and
status operations. It has no persistent trust generation, transaction, proof,
key-authority gate, or ARCH-002 CA identity-set query. ARCH-003 cannot add
hidden request tags or reinterpret Status without changing that accepted
architecture.

Therefore the design below is accepted while no platform row is supported.
Mutable rows are UnsupportedPendingArchitecture unless a stricter product-
policy restriction applies; the macOS System domain is immutable. A later
architecture task must version the helper protocol explicitly before
implementation tasks can claim trust support.

## Actors and authority

| Actor | Decision |
| --- | --- |
| Renderer | Expresses bounded typed product intent and displays non-authorizing status; has no helper/key channel, raw DER mutation, private key, arbitrary path/store, or consent-signing authority |
| Consent broker | Authenticates explicit generate/install/repair/remove/destroy actions and the separate rotate-prepare/rotate-commit actions, then signs the exact operation, known CA or generation profile, target set, scope, fallback policy, privilege outcome, and expiry |
| CA trust coordinator | One unprivileged Supervisor-owned orchestrator sequences a persistent trust transaction; it is not a journal writer or key holder |
| CA key authority | Generates and persists the protected key, builds the exact public CA certificate, proves key possession, signs bounded leaves after admission, destroys the key, and uses a separate attestation identity only for the closed key-ledger-receipt, purpose-specific provider-absence, destroy-negative-possession, rotation-ready-projection, identity-set, quiescent-stable-receipt, and Absent-residual-receipt domains |
| Privileged helper | Sole writer for the authenticated trust journal/state index and executor of registered privileged public-certificate mutations that permit daemon execution |
| Authenticated user trust agent | Executes one exact current-user mutation in the named login identity through a live one-use helper gate |
| Authenticated administrator trust agent | Executes one exact macOS Admin-domain/System.keychain mutation in a foreground GUI session after native administrator authentication through a live one-use helper gate |
| Platform trust verifier | Independently normalizes exact store/domain, certificate, trust precedence, derived outputs, and effective TLS evidence |
| Capture Core signer client | Requests one bounded leaf for an exact admitted connection without receiving the CA key |
| ARCH-002 trust-material broker | Reads the authenticated complete interception-CA SPKI set; unavailable is never encoded as empty |

The release-global vendor-signed manifest signs only a closed attestation
policy: algorithms, domain/role registry, key-generation requirements, bounds,
and verifier rules. It does not ship an installation attestation private key.
For each fresh InstallationId, one protected root-owned selector atomically
generates and pins exactly two different non-exportable Ed25519 identities:
HelperAttestation and KeyAuthorityAttestation. Bootstrap is not self-signed.
The selected installation state, both protected ledgers, and every signed proof
bind the two public keys, key IDs, InstallationId, selected manifest history,
and closed role/domain. V1 never rotates or replaces either key within an
InstallationId. Loss, mismatch, suspected compromise, aliasing, or unexpected
replacement permanently selects Invalidated, closes the gate, and enters
RecoveryRequired. Invalidated is a fail-closed sink inside this protocol: it
cannot refresh, resume, reopen, rekey, or select another protocol operation.
Only an external installer/uninstaller may complete exact trust/key/provider
cleanup and retire the installation. Returning to service then requires a fresh
InstallationId. An old anchor remains available solely to verify retained
historical evidence and grants no current signing, mutation, recovery, cleanup,
or admission authority.

A protected root-owned machine InstallationNamespaceSelector, separate from
each installation's lifecycle selector, names at most one current installation
and an immutable set of RetiredInstallationSeal commitments. Current and
retired InstallationId, epoch, anchor, and nonce identities are globally unique;
a retired entry is never deleted, reactivated, or accepted as current authority.
Each compact seal binds the old complete anchor, terminal exact-cleanup evidence,
and content-addressed retained history without copying that history into the new
installation journal.
The namespace also retains a bounded append-only bootstrap-attempt event vector:
per-role provider markers/results precede calls, lost-CAS cleanup is replayable,
failed attempts remain historical, and attestation public keys, provider
objects/secrets, and nonexportable identities are never reused. Current pins a
fixed protected per-installation selector locator and bootstrap anchor, not the
selector's changing current-state-slot digest.
Retirement first selects a gate-closed namespace preparation, then destroys the
two current role keys through their preallocated marker-bound operations, and
only after both terminal absence results selects the retired seal and
Current=None; crashes resume by exact operation ID and the old anchor thereafter
verifies history only.

The helper and key authority keep separate protected ledgers. Durable challenge
and compact pre-signer-switch abort records use distinct domains under
HelperAttestation. Recovery/key facts and registered provider/key evidence use
KeyAuthorityAttestation. Identity-set and stable-state proofs retain both
signatures. A signature authenticates a closed fact only after its signer has
verified the exact current CAS predecessor and typed evidence; it never replaces
that CAS, current target observation, key possession, or platform authorization.
Unknown domains, arbitrary messages, helper-only claims offered as key facts,
and stale/mismatched projections are rejected. Cross-store atomicity is not
assumed. Neither ledger's state tag, provider lookup, service liveness, or cached
boolean authorizes the other. Every leaf requires fresh helper-signed trust
evidence and key-authority-signed possession evidence bound to one challenge,
state revision, gate epoch, CA identity, Capture Core instance, and request.

## Persistent identity and state

The trust class is trust.ca.v1 and has nonwrapping CaGeneration,
TrustStateRevision, TrustFenceToken, KeyStateRevision, KeyAuthorityEpoch,
ResidualScanUniverseRevision, authenticated KeyJournalHeadDigest, and
InterceptionGateEpoch domains
independent from core.session. Network-session
generation, lease, fence, plan, or recovery values are invalid in trust
positions.

One CA instance is identified by complete canonical certificate DER,
SHA-256(DER), SHA-256(canonical SubjectPublicKeyInfo DER), installation,
generation, and a random CaInstanceId. Subject, label, friendly name, nickname,
filename, issuer/serial, OpenSSL subject hash, and SPKI alone are only locators
or diagnostics and never deletion authority.

The accepted top-level states are:

    Absent
    GeneratePending
    Generated
    InstallPending
    InstalledAndVerified
    RemovePending
    Drifted
    RecoveryRequired

Every state and retained pending snapshot uses only closed canonical containers.
Consent digests, phase recovery entries, destroy continuations, current and
terminal target steps, key steps, candidate/current/retiring identities, drift
findings, and installed verification facts each have an explicit count, order,
encoded-byte bound, and state/phase cardinality. There is no digest-only or
legacy uncounted vector encoding of the same field. The signed product manifest
contains every persistent count, byte, lifetime, recovery, journal-retention,
provider-reservation, and proof-selection bound consumed by this decision;
local defaults and bounds hidden in an open manifest remainder are invalid.

The monotonic envelope carries one closed interception-gate disposition:
Closed, ClosedDuringRotation, or AdmissionEligible bound to the exact installed
identity and business postcondition. Absent, Generated, ordinary pending,
Drifted, and RecoveryRequired are Closed; the post-switch rotation suffix is
ClosedDuringRotation; only InstalledAndVerified may be AdmissionEligible.
Moving from either closed tag to AdmissionEligible strictly advances the gate
epoch and still authorizes no connection without a fresh dual-signed admission
proof. Unknown tags, a state/tag mismatch, or restoration of an old eligible
epoch fail closed.

GeneratePending retains the candidate generation commitment before key
creation and reaches Generated only with exact public-identity/key proof.
Pending states retain every target/key step, before image, intended
postcondition, durable phase, observed result, and compensation. Multi-target
partial success is never collapsed into installed or removed. Drifted and
RecoveryRequired close the signing gate. InstalledAndVerified is authorizing
only through the fresh admission protocol, not by its stored tag. A pending
operation cannot transition to ordinary Drifted or be replaced by a new
consent; unresolved recovery retains its complete operation/plan/consent/step
snapshot in RecoveryRequired. Drifted itself moves to RecoveryRequired without
new consent when later fail-closed reconciliation can no longer prove bounded
identity, ownership, or journal/key ancestry. RecoveryRequired always retains
the last quiescent snapshot. With no pending operation it can leave only by one
registered RecoveryNoneReproofExit helper-journal record carrying a fresh
state-tagged residual/key/target reproof of that exact CA/target/key business
postcondition, except that an Absent snapshot may reconcile a fully proven
change to its preserved-external residual projection into a new Absent business
postcondition. Generated and Installed reproof require the current LiveReady
projection and fresh purpose-specific key possession; Installed additionally
reproves every required target, while Drifted requires ClosedDrifted and keeps
the gate closed. The record appends first, then the helper derives the successor
journal head and monotonic envelope, issues the matching domain-specific stable
receipt, and selects the quiescent state; the record contains none of those
resulting digests. A Drifted exit also issues a new RetainedClosed gate receipt
over that successor head/envelope; it never reuses the predecessor Recovery
receipt. Journal identity is a closed union: an initial operation selection
binds its pending TrustOperationId to the complete receipt/intent/plan, later
ordinary work binds it to the selected or retained pending snapshot, and a
RecoveryRequired episode with no pending operation allocates one installation-
lifetime-unique, non-authorizing RecoverySelectionId. That recovery identity is
stored in the selected state and repeated by its entry, reproof context,
possession proof, exit record, and gate evidence; it is never usable as consent
or mutation authority. Identity and authority are related by one closed
delta-tag compatibility table rather than a false one-to-one encoding:
receipt/retained-pending, recovery-entry-with/without-pending, recovery reproof,
and consent-authority selection accept only their exact listed pairs.

Pending failure disposition is also closed and non-authorizing. Every failure
key includes its exact phase and operation/target/key step, the first retry is
one and later retries increment by exactly one without changing that key, and
compensation names only one outcome from that same phase plan. No failure value
can supply mutation or recovery authority by itself.

Every first transition to RecoveryRequired is one typed
EnterRecoveryRequired journal delta. A quiescent/Drifted predecessor inlines the
last-quiescent snapshot and selects RecoveryWithoutPending; a pending
predecessor retains the exact complete pending snapshot and its TrustOperationId.
It carries no caller-selected phase digest merely to fail closed. Both forms
carry a closed bounded reason/fact set and gate-close intent. Every reason has a
deterministic variant-specific unique key, including its scope or phase where
needed. Every target-mutation reason appears exactly once in its matching
unresolved-target row; operation/scope/key reasons cannot be attached to a
target row. The gate reason is the deterministic priority projection of the
complete reason vector. Recovery payloads inline a complete authenticated trust
head, complete key-ledger projection/tip, and a counted, sorted vector of every
known complete CA public identity whose direct sorted-SPKI projection is the
ARCH-002 identity-set digest. Normal versus quarantined trust/key tip relations
are closed tags; no opaque digest or caller-added identity can substitute. The
record is followed one-way by the resulting journal head, closed monotonic
envelope, complete helper-signed GateClosedReceiptV1, and Recovery state. A crash
selects the complete predecessor or complete recovery successor; a refresh
record cannot synthesize first entry. With a pending snapshot it can leave only
by restoring the byte-identical sealed operation authority/core, except for the
typed reason-resolving step refinements below, and following its sealed phase-
scoped recovery-disposition vector.
Its recovery-resume ancestry inlines the complete native-record/link/resulting-
head suffix from the retained pending tip through the selected Recovery state,
including any residual refresh; an operation-record-only list or detached
record without its link/head chain is insufficient.
Every RecoveryRequired state also carries a complete current key projection.
Quiescent projections remain closed to their quiescent uses, while a distinct
recovery-only projection represents an authenticated Creating, DestroyPending,
or Ambiguous current tip without treating it as Ready, absent, or admissible.
The projection, reason vector, known identities, key head, and complete retained
generation chain agree byte-for-byte.

Fresh recovery observation has two non-interchangeable residual-query purposes.
RecoveryNoneReproof binds the unique RecoveryWithoutPending identity and exact
last-quiescent snapshot. RecoveryPendingResolution instead binds the selected
RecoveryRequired state, retained pending snapshot and TrustOperationId, complete
reason/unresolved-target roots, and one helper-generated challenge. Its complete
context and same-scan result may resolve only matching target-mutation or
incomplete-residual reasons; selector, head, envelope, snapshot, or reason-root
change discards the scan. Neither purpose can substitute for identity-set,
admission, or signer-switch evidence or grant mutation/provider authority.

Recovery exit is reason-bijective rather than a generic evidence switch. Trust-
journal, key-ledger, target mutation, incomplete residual observation, provider
outcome, and selector/ancestry reasons each accept only their listed complete
resolution conjunction with the same reason key, target, scope, phase, key
step, and evidence digest. RecoveryPathExhausted has no ordinary automatic
resolution. Both pending and no-pending exits carry the complete predecessor
reason vector and exactly one compatible resolution for every member. A
provider-ambiguous pending key step may change only inside that typed recovery
record, atomically from its exact Ambiguous record to the matching native
terminal receipt and terminal helper step; every unrelated step and sealed
authority remains byte-identical. Thus a valid ancestry proof cannot falsely
clear a provider reason, and a fresh business scan cannot hide an unresolved
journal failure. SelectorOrAncestryFailure has separate closed resolutions:
the pending form binds the retained complete pending snapshot, while the no-
pending form binds RecoverySelectionId, last-quiescent snapshot, and a complete
authenticated native journal/head suffix from the last verified tip through the
selected recovery state. A pending snapshot can never appear in the latter, and
fresh business reproof never replaces either ancestry proof.
RotatePrepare and RotateCommit append separate entries, so preparation never
contains later install/switch/retire authority and commit does not broaden the
preparation entry. RotatePrepare creates the operation's sole initial pending
snapshot; consuming RotateCommit is one typed SubsequentRotationPhaseSelection
whose complete helper record is the exact AuthorizedOperationSuccessor of that
snapshot. Every phase retains its complete plan, signed manifest, capability,
privilege/interaction, target graph, exact outcomes, provider deadlines, and
bounded ForwardOnly commitments.

RotateCommit has one ForwardOnly commitment. Before signer switch it may select
the distinctly tagged old-base abort outcome; signer switch selects the intended
new Installed outcome from the same exact predecessor. The two selections are
mutually exclusive CAS successors. Selecting abort changes the retained
RotatePrepare entry to CleanupLockedByRotationAbort, a terminal non-authorizing
tag that prevents ordinary Prepare cleanup from racing or reusing the cleanup
operation ID. It does not create a second ForwardOnly entry or transfer broad
RotateCommit authority into RotatePrepare.

The RotateCommit snapshot contains a closed CandidateAbortCompensationVector
bijective with the complete CandidateInstallSet. It is separate from the
original candidate-install step vector, whose terminal anchors remain immutable.
Each abort row repeats the exact target, original terminal anchor/current fresh
observation, executor, permission/interaction requirement, ownership and
after-image evidence, and one closed compensation disposition: exact owned
removal, derived reverse-dependency reconciliation, preserved external, or
never-attempted/verified absent. Owned rows alone may be removed. Derived rows
are recomputed only through the sealed reverse dependency order; external and
pre-existing rows are observed and preserved. The abort follows every target's
original authenticated user/helper/foreground-admin executor and native
authorization boundary; it never falls back between user, admin, machine, NSS,
or browser-private scopes.

One compact domain-separated HelperAttestation-signed abort authority binds the
exact current predecessor, both phase plans/receipts, candidate/Ready binding,
old-base snapshot, complete compensation vector, retained Prepare cleanup
continuation/ID, and AbortCapacityAdmission. The signature never substitutes for
the current journal/state CAS. The abort selector and SignerSwitchSelection
compete for the same predecessor. After abort selection, the fixed suffix is
candidate-owned removal and derived reconciliation, a fresh complete candidate-
absence vector/root, candidate-key cleanup under the already reserved ID, then
the exact old-base outcome. Candidate key destruction is forbidden until every
owned candidate row is freshly absent and every derived/preserved row is
settled. Recovery continues only this suffix; it never re-adds trust or recreates
a destroyed key. Until cleanup completes, the candidate SPKI remains in the
conservative ARCH-002 exclusion set.

AbortCapacityAdmission is durably selected in the RotateCommit snapshot before
the first candidate-target mutation. It checks the Cartesian worst case for the
full CandidateAbortCompensationVector, fresh observation and absence vectors,
all target/journal/replay/recovery terminal results, and the already reserved
candidate-key cleanup provider path against the existing vendor-signed count and
canonical-byte maxima. It creates no new reservation ledger. The current signed
manifest may raise a future bound but cannot lower any live floor below retained
state plus the admitted abort suffix. Failure to admit abort capacity prevents
the first candidate mutation rather than stranding a partially installed CA.

The ordinary outcome vector is also an exact phase matrix, not a bag of any
well-formed outcome tags. Generate, install, repair, remove, direct destroy,
and RotatePrepare each carry only their named terminal, exact-base, or awaiting-
later-consent members, with the DirectDestroyOnly exception removing the
reversible base choice. RotateCommit carries exactly the intended new Installed
outcome plus its distinctly tagged pre-signer-switch old-base abort outcome;
the latter is not a generic ExactBase and cannot be selected after signer
switch. Extra, missing, cross-phase, or wrong-business outcomes invalidate the
plan before consent.

Each complete per-target step uses one closed state/evidence variant rather than
independent cross-product fields. Pre-attempt, in-flight, ambiguous, terminal,
and failed/drifted variants constrain the exact selected fact, native
observation, retryability, bounded reason, and allowed predecessor-to-successor
edges. A terminal observation can first enter only through the existing timed
terminal-selection record; an ambiguous step cannot be relabeled terminal
without its typed recovery evidence.
Returning to the same business postcondition keeps authenticated descendant
journal/replay/time/gate metadata, issues a new stable receipt, and never rolls
back an old generation high-water, trust fence, key-authority epoch/revision,
replay root/time, state revision, journal tip, or AdmissionEligible gate epoch.
The contract
uses separate canonical QuiescentBusinessPostconditionBodyV1 and
MonotonicSafetyEnvelopeBodyV1 domains, plus a digest-free pending-operation
snapshot body, so a post-dispatch CreateUnapplied or no-dispatch
CreateUnappliedNeverStarted generation, or a cleaned rotation candidate,
can restore the exact old business facts while all allocated counters and
fences remain consumed.

A quiescent lifecycle payload is not a second source of truth beside its
StateEvidence. Its business digest and complete stable-receipt reference are
byte-identical to the inline business object and receipt; state, business,
envelope, receipt, and public identity use one InstallationId and journal/key/
gate coordinates. Generated repeats the exact current identity from
GeneratedBusiness, InstalledAndVerified repeats the active identity and required
target set, Absent repeats generation high-water and the direct residual
identity set, and Drifted resolves LastStableStateDigest to the unique retained
stable business while repeating the same GateClosedReceipt. Receipt domain,
business variant, key evidence, identity-set digest, and payload tag form one
closed matrix; a duplicate but unequal wrapper is invalid even when each object
independently verifies.

Quiescent target state is split into three non-interchangeable layers. A
context-free TargetBusinessFact and every source-business fact commit only pure
target/source identity, scope, certificate, ownership, trust, consumer, and
result semantics. They contain no plan role, current/terminal step, historical
ordinal, operation/query context, time, expiry, deadline, boundary token,
journal/state wrapper, receipt/signature, observation, scan, result, or digest
whose preimage contains one of those values. Owner receipts, owned after images,
external before/current observations, and their proof digests stay in evidence;
they verify to separate closed semantic ownership/source projections rather than
being hashed into business facts. The quiescent per-target business root is the
canonical sorted TargetId-to-TargetBusinessFactDigest projection. An operation-
bound terminal target observation separately retains the complete evidence that
produced that fact. Its durable-evidence deadline is checked only before that
terminal evidence is first selected; once timely committed, the terminal
observation is an immutable historical anchor whose later age neither invalidates
it nor supplies current freshness.
Terminal status is a closed plan-role-specific union, not an arbitrary
PerTargetStep. Its first selection is one TerminalEvidenceFirstSelection variant
of the registered TrustOperationJournalRecordV1; that record inlines the
complete observation/fact and mechanically proves its effective selection time
is no later than must_select_by. The successor pending snapshot inlines the same
complete helper record/digest in AuthorizedOperationSuccessor lineage. A late or
digest-only terminal row is invalid.

Pending residual refresh uses the parallel ResidualObservationSuccessor lineage
variant, but it inlines the complete ResidualIdentityObservationRecordV1 and its
recomputed digest rather than storing an external digest-only pointer. The
snapshot therefore remains independently verifiable after journal compaction;
the record still cannot refer to its resulting snapshot, envelope, head, or
state.

Every identity query, drift/recovery recheck, and interception admission instead
creates a purpose-specific ephemeral verification context bound only to the
already selected predecessor state/business/envelope, its exact consumer and
release, a fresh challenge/nonce, the applicable universe, and one bounded time
window. Fresh direct target observations bind that context, the immutable
terminal anchor, and the current business fact. A fixed-regenerator query receipt
binds the complete current authority inputs and native output before the derived
query observation binds that receipt. Every derived wrapper repeats and requires
byte-for-byte equality of target, primary lineage, source-set, regenerator,
consumer, release, hostname, challenge/request, time, and output fields rather
than accepting digest-local consistency alone.

RecoveryRequired(None) uses the third closed context purpose
RecoveryNoneReproof. Its selected-state anchor repeats the exact
RecoverySelectionId and proves that no pending snapshot exists. The complete
scan, context digest, fresh helper challenge, observation time, expiry,
key-ledger projection, and resulting state tag are repeated byte-for-byte by the
purpose-specific CA-key possession proof when required. Identity-read or
admission contexts, caller-chosen challenges, cross-episode proofs, and expired
evidence cannot substitute. Drifted reproof carries the complete selected gate-
closed receipt as predecessor evidence and intentionally has no possession
proof; after its journal append, the resulting Drifted state carries a newly
signed RetainedClosed receipt bound to the successor head/envelope.

A byte-identical query is read-only: it validates ReplayTimeHighWater and expiry
without advancing replay time, journal, selector, state revision, or terminal
evidence. Replay/time maintenance may be folded only into a state transition that
already must be committed for an independent semantic change; a query never
manufactures a maintenance-only write. When a scan discovers changed facts, that
scan may authorize only the existing state-appropriate observation successor.
After the successor is durably selected, the caller creates a new nonce/context
against the new selected predecessor, repeats the complete all-scope scan, and
signs only that second byte-consistent result. The change-discovering scan is
never also the freshness proof returned from the successor state.

The digest order is therefore one-way: business fact to terminal observation
and quiescent business, selected business/envelope to fresh context, direct
query observations to regenerator receipt, then derived observation/member and
scan result, followed only when needed by a successor envelope/receipt. A
terminal observation cannot reference quiescent state, a fresh context cannot
reference its resulting successor, and no business fact can reference an
observation wrapper. This removes fixed-point construction while retaining the
exact evidence ancestry.

All consent/phase selection, candidate refinement, target/key step, terminal
evidence, recovery-disposition/ForwardOnly refinement, recovery resume or
None-reproof exit, signer switch, phase outcome, and failure refinement use one
registered closed TrustOperationJournalRecordV1 union. Each body binds the exact
predecessor state and optional snapshot, revision/head/envelope, replay
revision/root/high-water, complete typed delta, effective selection time, and
complete replay successor. The record contains no resulting state, snapshot,
journal-head, envelope, stable-receipt, or signer-switch-receipt digest. Pending
lineage and immutable receipt/phase anchors inline the complete record plus its
native digest rather than accepting an untyped digest.

LifecycleStateDigest is the domain-separated digest of one closed lifecycle-state
union; unknown tags, cross-tag fields, partial projections, and a digest computed
from a status/display shape are invalid. Complete pending and last-quiescent
snapshot commitments separately bind their complete closed state body,
then-current safety-envelope digest, and stable receipt reference.
LastQuiescentStateSnapshot retains every current context-free target/source/key
fact plus each corresponding immutable terminal anchor; it is not merely a
business-root pointer. A PendingOperationSnapshot additionally binds that exact
complete last-quiescent base snapshot before adding its sealed operation facts,
plans, consents, steps, and recovery dispositions. Recovery cannot reconstruct
either snapshot from current observations or a summary digest. Every quiescent
selection emits one closed state/domain-compatible dual-signed receipt over the
exact business digest, then-current envelope, nonrecursive transition head, and
a complete context-free key-ledger state projection; recovery issues a new
receipt for the successor envelope.
Generated and InstalledAndVerified accept only a LiveReady projection plus a
fresh CA-key StableStateSelection possession proof bound to that exact business,
envelope, trust head/revision, and key projection. Drifted accepts only a
ClosedDrifted attestation projection and requires the gate closed; possession is
not required and cannot authorize admission. Absent, including an Absent
residual-observation receipt, accepts only a complete NoLiveOrAmbiguous
projection and explicitly forbids a possession proof. Ready, DestroyPending, or
Ambiguous key state cannot be hidden inside an Absent projection. The
attestation signature authenticates the projection but never impersonates the
destroyed or unavailable CA key. Current state/index/proof fields equal the
selected envelope; key ancestors, snapshots, old results, and receipts keep
their then-selected roots and prove a unique typed successor lineage to current
authority.
The generation commitment is the one staged exception: it permanently binds
selected H0 and pure unselected U1, while the U0-to-U1 successor plus the H1
intent prove that H1/U1 was the first selected pair. It never falsely claims
H0/U1 was selected. Historical objects are never rewritten merely to match a
later universe or time-maintenance successor.

Every identity-set query uses one manifest-bounded ResidualScanUniverseV1 under
the global mutation lock. The installation-lifetime catalog retains every
historical CA public identity, every ever-used exact physical/user/consumer
scope, append-only observer-release history for each stable scope, and any
pending pre-key identity-capacity reservation; its revision/root is in the
monotonic envelope and compaction cannot discard it. Canonical body sizes are
computed from the final encoding, never stored inside their own bodies. The
manifest fixes identity/scope/body limits, caps every historical/answerable
identity count at the ARCH-002 uint32 limit, and every admission proves the
Cartesian worst case of maximum identities across maximum per-scope result rows
still fits. Generation uses the acyclic order H0 selected tip, pure staged U1
containing the reservation plus every plan-exact first-use scope for that phase,
commitment(H0,U1), journal H1, then one selector; Ready, post-dispatch
CreateUnapplied, or CreateUnappliedNeverStarted refines/releases that exact reservation through pending cross-ledger
recovery. First use of a scope registers its plan-exact stable projection with
consent before side effects. Count/byte failure rejects before consent or
mutation and never evicts history.

Each scope keeps a stable ResidualScopeId separate from its append-only current
observer-release binding. Each binding revision carries its signed release
tuple, canonical observer schema, and per-scope enumeration limits, so a
supported backend update appends a complete new binding without editing
historical provenance; rollback appends another authorized binding rather than
selecting an old universe. A complete scan first
reads every scope's monotonic no-ABA before token, then enumerates every scope,
then reads every after token. All pairs must match, so moving a certificate from
a not-yet-scanned scope to an already-scanned scope cannot create a false
negative. Canonical enumeration roots retain every bounded item, including
foreign and duplicate certificate items; result ordinals are valid only for the
exact universe revision. The binding's signed observer-schema digest fixes
native item normalization. Item bodies carry closed certificate/object, trust,
ownership-evidence, member-authority provenance, and consumer-outcome unions
inline. A derived target retains exactly one primary DerivedBy edge to a direct
authority target; that edge controls only plan execution order, consent-set
membership, and inherited permission/interaction. It is not the complete
provenance assertion. The signed target template also fixes the complete
read-only regenerator input-scope set. Each fresh derived member separately
commits a complete, sorted, bounded current direct-source set from those scopes,
including the primary source when it is still present and every additional
owned or external source that accounts for the native output. An active primary
lineage binds the current primary/derived terminal anchors; a retained primary
lineage may bind an already absent or externally removed primary during removal,
rotation retirement, or residual observation. Neither lineage nor an additional
source grants deletion authority.

Direct source observations are constructed first, followed by the complete
source-set digest, one fixed-regenerator receipt, and then the derived query
observation/member proof. Every additional source is observation-only, must be
direct rather than another derived output, and cannot enter the mutation target
set, privilege aggregate, or executor fallback. A missing source, unregistered
input scope, cross-context observer failure, unknown hook, mixed release,
changed token, omitted contribution, or unbounded derivation is
DerivedProvenanceUnknown. A derived member is controlled-owned only when every
current source is exactly FlowProbe-owned, is preserved-external when any
current source is external, and is ambiguous otherwise. Classification uses the
current source set rather than the historical primary owner, so deleting the
owned primary cannot hide an external source that still regenerates the same
output. The artifact itself never acquires InstallerOwner, delete, rewrite, or
whole-output restore authority.

Terminal derived verification follows the same completeness rule: its immutable
operation-time evidence carries the full direct-source set actually consumed by
the fixed regenerator, not merely the primary edge or a context-free source
root. The terminal source evidence projects to the pure source-business facts
above; later queries reconstruct a complete current set and require every
repeated primary, source, regenerator, output, consumer, and release field to
equal its enclosing target/member evidence byte-for-byte. A terminal/current
difference is a changed fact or provenance result, never an unverified merge.

An exact external certificate or source first observed after installation uses
ExternalCurrentObserved with a complete same-scan NoFlowProbeOwnershipProof over
the authenticated owner/target ledgers and exact current item/member identity.
This evidence proves only that the current item must be preserved and that its
historical FlowProbe SPKI remains in the ARCH-002 exclusion set. It cannot become
ExternalPreExisting target evidence, satisfy Installed/admission/support, enter
a consent or mutation set, select an executor, inherit privilege, establish
owner or delete authority, or authorize adoption, rewrite, or restore. Missing
owner ancestry or an item that could still be FlowProbe-owned remains Unknown.
After the matching historical key is provably destroyed, conservative
probe-unavailable truth may use either a direct ExternalCurrentObserved item or
a derived item whose complete current source set includes an
ExternalCurrentObserved source, but only with that exact source's complete
same-query ownership proof and the exact historical destroyed-key terminal
evidence. This retains the SPKI conservatively; it never establishes Installed,
admission, mutation, ownership, or deletion authority.

Per-identity ownership/trust aggregates use registered exact preimages, require
unknown/ambiguous evidence to select Ambiguous rather than OwnedOnly, and may
not join ownership from one item with trust success from another. Consumer TLS
result preimages bind the exact item, member, historical identity,
consumer/release, hostname, validation profile, and freshness. Ordinals are
zero-based uint32; container/member identities preserve duplicate entries
without emitting partial duplicate item views; and scope, identity, and
RequiredTarget bitmaps have one fixed high-bit-first encoding with zero padding.

Every lifecycle state that can answer binds that query's fresh context, target
observations, scan digest, challenge, and effective time into the dual-signed
proof. A byte-identical current business-fact projection signs from the existing
selected state without rewriting its immutable terminal observations or
advancing replay time, journal, or revision. A changed projection first commits a
non-authorizing state-appropriate observation successor: stable Generated or
Installed enters Drifted; pending retains its sealed operation core, phase
plans, consents, recovery dispositions, intended postconditions, immutable
anchors, and exact planned-target steps byte-identically, while selecting a new
successor snapshot wrapper with updated current facts/root/count, monotonic
envelope, and explicit predecessor lineage for an off-plan residual change;
planned-target or derived-source drift first uses the sealed operation's typed
step reconciliation and keeps the query unavailable; Drifted/RecoveryRequired
refresh only their bounded observation evidence, and Absent uses its sole
ResidualObservationReconciled self-edge. That Absent edge proves every owned
target absent and key destroyed, then atomically publishes the new Absent
business body, direct ARCH-002 identity-set digest, monotonic envelope, and
dual-signed stable receipt carrying the NoLiveOrAmbiguous key projection. The
successor record binds the fresh predecessor context/result, but the resulting
business root is reconstructed only from context-free facts. It consumes no
consent or replay capacity, creates no operation, performs no trust/key mutation,
and cannot open the gate. Replay/time maintenance is included only because this
successor already commits. The successor-producing scan is discarded after
selection; a new nonce and complete scan against the selected successor are
mandatory before any proof is signed. Crash recovery selects the complete old
or new state; incomplete or expired query evidence is discarded and rescanned
rather than invalidating the historical terminal anchor.
RecoveryRequired(None) retaining Absent may select the updated Absent projection
rather than being trapped reproducing stale external state.

## CA key and certificate decision

The CA key is generated inside a separate platform key authority and becomes
non-exportable or equivalently protected after creation. The authority exposes
only typed self-sign, fresh possession, bounded leaf-sign, and destroy
operations. It exposes no raw private bytes, generic arbitrary-message signing,
provider handle, PIN, wrapping secret, or renderer/helper interface.

The key is bound to installation, generation, CaInstanceId, algorithm, and
certificate SPKI. Every newly created SPKI is unique across the installation's
complete generation history, including Destroyed, post-dispatch
CreateUnapplied, and CreateUnappliedNeverStarted audit history, and the provider
proves that the candidate key object/secret is not an
alias of any live, pending, ambiguous, or historical FlowProbe CA key. A repeated
SPKI, shared handle/object, provider-identity ABA, or destroy operation that can
affect another generation fails before Ready, signer switch, or automatic
candidate cleanup. Unavoidable transient private bytes use locked no-dump memory
and are zeroized on every path. Ordinary status, logs, diagnostics, crash dumps,
analyzer input, capture data, and the helper journal never contain key material.

The key authority also owns one append-only installation-lifetime provider-
operation reservation ledger shared by create and destroy purposes. A canonical
reservation record binds one random 256-bit operation ID to the exact operation,
signed consent digest, phase/step/purpose, generation/instance, provider/profile,
deadline, helper predecessor, and closed create/direct-destroy/candidate-cleanup/
old-key target. Records form a nonwrapping predecessor-root chain and a complete
canonical vector/root. Raw IDs are unique across both purpose tags and every
current, terminal, ambiguous, staged, or compacted history. The signed manifest
bounds vector count and canonical bytes; capacity is charged before consent
consumption and exhaustion has no side effect.

The helper stages the full next record and deterministically computed resulting
root in GenerationCommitment or DestroyContinuationAuthority. Only after that
helper pending selection does the key authority append-select the byte-identical
record in its own checksummed copy-on-write ledger, and it must do so before any
bootstrap, marker, or provider-authorizing intent. RotatePrepare stages and
later selects candidate-create then candidate-cleanup-destroy records in that
fixed consecutive order. Selection of a staged record is non-dispatching and may
be recovered after a provider deadline, but cannot create a late marker. Every
record and preimage remains after cancellation, success, ambiguity, unused
cleanup, and compaction; an opaque root or operation-ID summary is insufficient.
The helper-side provider CompleteKeyStep is initialized as
OperationReservationSelected with that complete proposed record; this denotes
only helper selection of the staged reservation evidence, not provider dispatch
or prior key-authority append. A phase with no provider operation has an empty
CompleteKeyStepVector; every present provider step begins at that selected
reservation, so there is no NotAttempted/NoProvider placeholder member.

The remaining helper key-step algebra contains only externally durable facts.
ProviderMarkerDurable inlines the complete selected Creating or DestroyPending
record and marker; issuing the idempotent call is not a separate durable helper
state. The four terminal dispositions map bijectively to their complete native
receipts, ProviderOutcomeAmbiguous maps only to a complete Ambiguous record, and
CreateNeverStarted may advance directly from the reserved step. Intent-only and
provider-issued booleans are omitted because they cannot be independently
reconstructed after a crash. Every KeyStepAdvance carries the same complete
native record/receipt as its resulting step evidence and cannot skip, reverse,
or rewrite a terminal state.

Provider call absence is represented by three complete, non-interchangeable,
attestation-signed proofs rather than one opaque digest. CreatePreCall proves,
under the exact generation commitment, provider profile, operation identity,
helper/key predecessor, purpose-specific challenge, and stable no-ABA
before/after token, that neither a prior operation nor a matching key exists.
CreatePostCall additionally binds the exact Creating record and proves the one
provider call terminally created no object. DestroyPostCall binds the exact
Ready and DestroyPending ancestry, destroy operation/intent, historical CA
identity, and negative-possession challenge, and proves destruction applied and
the key is absent. Each proof carries a closed bounded normalized provider-
evidence root. CreatePreCall requires zero matching provider operations and zero
matching keys; CreatePostCall and DestroyPostCall each require exactly one
terminal result for the bound operation and zero matching keys. Each post-call
proof also carries the complete ProviderCallInvocationMarkerV1 selected in the exact
Creating or DestroyPending ancestor, and the provider must echo its exact digest.
ProviderOperationFirstInvokedAt remains immutable audit metadata but is never
deadline authority; a provider-controlled/backdated clock cannot turn a late or
unselected mutation into an authorized one. The proof
contains no raw handle, internal key identity, PIN, provider secret, or arbitrary
provider bytes. A proof from another purpose/domain, operation,
provider release, key head, helper tip, challenge, or time window is invalid.

The complete signed product manifest carries one closed freshness policy per
KeyProviderProfileDigest. Its
MaximumProviderKeyUniquenessWindow, MaximumCreationPossessionWindow, and
MaximumCreateNeverStartedObservationWindow, plus the two post-call create and
destroy observation windows, are finite, strictly positive
canonical uint64 values and never `UINT64_MAX`. Uniqueness evidence expires at
exactly `checked_add(observed_at, MaximumProviderKeyUniquenessWindow)`; creation
possession expires at the canonical minimum of its checked observed-at sum and
the uniqueness-evidence deadline; never-started proof expires at exactly the
checked sum of EffectiveObservedAt and its window; CreatePostCall and
DestroyPostCall proofs use the corresponding exact checked observed-at sum, and
the destroy negative-possession result repeats the latter deadline. Each object repeats the exact
manifest digest, profile digest, and window. Overflow, expiry, a caller/provider
shortening or extension, manifest/profile substitution, or reuse after an ABA
requires rejection and a new complete observation rather than deadline repair.

Creation that never reaches a marker uses a fourth, distinct attestation domain
rather than pretending it is CreatePreCall or CreatePostCall. That signed proof
binds the complete generation commitment, selected create-reservation record and
root, operation ID, unchanged NoRecord key predecessor/root, current helper
GenerationCommitted snapshot/journal/envelope/replay authority, and two exact
NeverInvoked/StoredMarker=None bootstrap observations with one stable no-ABA
token and zero matching operations/objects. Label guessing, missing history, or
an incomplete provider inventory is Ambiguous.

The key ledger exposes one closed key-generation projection whose variants and
required evidence are exhaustive: marker-bearing Creating, live Ready, post-
dispatch CreateUnapplied, direct marker-free CreateUnappliedNeverStarted, and
Ambiguous. Destruction is a separate closed refinement from
Ready through a complete durable destroy intent to DestroyPending, then either
Ambiguous or Destroyed. The destroy intent appends from the current global key-
ledger predecessor and binds its exact pre-destroy complete-generation root.
Within that root, LastReadyRecordDigest selects the historical target Ready
entry and its public/internal identity; during rotation the same root also
retains the non-target Ready generation. The target Ready head is ancestry,
never the global predecessor, so an intervening candidate record cannot be
skipped or rewound. The intent also binds the operation, consent, challenge,
helper tip, and intended absence. Negative possession is accepted only for that exact intent
after the provider call; Destroyed terminal evidence includes the complete
DestroyPostCall absence proof, negative-possession result, and immutable
DestroyPending ancestry. No lookup result, status enum, or digest-only reference
can substitute for one of those complete objects.

Destroy authority is a closed union. Direct RemoveAndDestroy binds its exact
receipt/phase/pending state. Pre-commit candidate cleanup instead binds the
already-selected rotation Ready-projection attestation and its helper selection
record and targets only CandidateReadyRecordDigest; it neither needs nor accepts
a later CandidateKeyBinding. Post-commit old-key destruction separately binds
CandidateKeyBindingDigest, RotationTargetBindingDigest, and the old-retire phase
graph and targets only ActiveReadyRecordDigest. Swapping those variants, Ready
roles, receipts, roots, or helper ancestry is invalid. Each variant also binds
its exact consumed phase-plan digest and the common already-selected
ForwardOnly helper authorization. Each provider phase seals a
KeyProviderSelectionDeadlineBinding keyed by operation, phase, provider step,
purpose, and generation. The matching recovery-disposition entry and complete
key step repeat it byte-for-byte. The selected deadline is exactly the canonical
minimum of the consumed receipt expiry and the checked sum of that receipt's
issued time plus the exact step-role window in the signed product manifest.
Create uses that value as the Creating marker's first-selection deadline.
Destroy instead uses it as the first-selection deadline for a non-dispatching
DestroyContinuationAuthority and authenticated helper selection record.

RemoveAndDestroy, RotatePrepare, and RotateCommit each allocate an installation-
lifetime-unique destroy operation ID, stage its complete reservation record in
the continuation, and atomically select that continuation
with receipt/tombstone consumption, phase plan, recovery disposition, key-step
initialization, replay-time successor, and pending state before any side effect.
It binds the exact receipt/plan/phase/step/generation, role-specific target
commitment, the complete allowed ForwardOnlySelectionCommitment matrix copied
from the phase plan, deadline,
predecessor state/snapshot/journal/envelope/replay authority, and effective
selection time. It grants no provider dispatch. The plan never refers back to
the continuation, and neither continuation object refers to its resulting
state/head, preserving the one-way plan -> provider-operation reservation ->
continuation selection -> typed receipt/phase helper journal record -> pending
state -> ForwardOnly -> ForwardOnlyDestroyAuthorization -> destroy intent ->
bootstrap -> marker -> DestroyPending
graph. Intent, marker, and record reuse the same continuation and preallocated
ID. Before intent construction, the key authority append-selects that exact
reservation record; its resulting root may only be an authenticated prefix of
the current complete reservation vector. A destroy marker may first be selected after the original deadline because
the continuation was selected on time; after that deadline the continuation
remains authority only for later selecting one complete byte-identical matrix
member, never for dispatch or a different target/ID/outcome/path. The selected
ForwardOnly helper record, disposition, authorization, intent, and descendants
all retain that same member byte-for-byte. Create retains its marker deadline.
Missing, late, duplicate, cross-phase, shortened, or extended bindings fail
closed.

Key creation has disjoint dispatch and no-dispatch protected-ledger paths.
Before the dispatch path can call the provider, the key authority selects the
staged create reservation and obtains the complete CreatePreCall proof. The only
marker-free provider operation is a read-only bootstrap query over the operation
ID, exact selected reservation-record digest, and create-commitment or destroy-
intent/purpose binding. It cannot
dispatch or bind an operation and returns only NeverInvoked, no stored marker,
and a stable observation token; any prior operation, different binding, or token
instability fails closed. The bootstrap query/result has no standalone signing
or dispatch authority. One result may appear only inside the resulting marker;
two byte-identical results may instead appear only in the complete signed
CreateNeverStarted proof. The authority then constructs
ProviderCallInvocationMarkerV1 from that result and fsyncs Creating
with that proof and marker, the exact signature-free generation
commitment, helper tip, consent, provider profile, random
ProviderCreateOperationId, and CreateIntentDurable. The marker binds the selected
replay revision, root, and high-water, which must equal the complete replay body
and monotonic envelope at its helper journal tip. Its effective committed time,
derived from that authenticated replay-time high-water, must meet
the generation deadline; that timely selected record, not a provider timestamp,
is the sole dispatch authority. At that point certificate
DER, SPKI, and internal key identity do not yet exist and are forbidden from the
Creating payload. After one exclusive provider call, the authority either builds
and verifies the certificate and obtains a creation-purpose CA-key possession
proof over the exact Creating revision/head, provider operation, and generation
challenge, or obtains a complete CreatePostCall proof tied to that Creating
record. The first path append-only refines to Ready with the complete public DER,
exact CA identity, internal non-exportable key identity, and creation receipt;
the second refines to terminal non-signing CreateUnapplied, allowing both
ledgers to return to the exact base without pretending a key was Destroyed. A
separate post-Ready possession proof binds the committed Ready revision/head and
a fresh helper challenge; that later proof is not embedded in Ready.

If no marker or provider operation ever existed, the key authority may first-
consume a fresh CreateNeverStarted proof in a distinct attestation-signed
KeyCreateNeverStartedReceipt and append directly from NoRecord to terminal
CreateUnappliedNeverStarted. This route is available after the marker deadline,
or for a still-authorized exact-base compensation before it, and never grants
dispatch. The helper cross-binds that receipt, releases only the staged identity
reservation, records the terminal replay result, and returns Generate to Absent
or RotatePrepare to its freshly proven old InstalledAndVerified base. The
generation, create ID, and selected reservation then remain permanent tombstones
and can never later acquire Creating, a marker, or a provider call. A crash after
helper pending selection but before key reservation selection recovers only the
byte-identical staged record before taking this route.

A provider that cannot atomically invoke-if-NeverInvoked for the exact operation
ID and marker, echo the marker on every invocation and post-selection query,
distinguish NeverInvoked, definitive no-object
creation, and applied destruction, or prove after a crash that the operation
identity produced exactly zero or one recoverable result, remains unsupported.
Incomplete enumeration, changed tokens, multiple candidates, missing operation
history, or an unknown/unqueryable/marker-mismatched result is Ambiguous and
RecoveryRequired. A current Creating record must have selected its marker on
time. A current DestroyPending record instead must carry the exact timely
continuation, later ForwardOnly retaining descendant, intent, and marker. With
the exact provider state NeverInvoked, recovery may make the one first call with
the same operation ID and marker even after the applicable selection deadline.
In-flight or terminal state is query-only; recovery never guesses by
label, chooses another marker/ID, or creates/destroys again.

Every key-ledger record has a canonical digest-free body and an external
domain-separated RecordDigest. Ready and post-dispatch CreateUnapplied link the
exact CreatingRecordDigest; CreateUnappliedNeverStarted instead links the exact
NoRecord predecessor, selected reservation, signed proof, and signed receipt.
DestroyPending links the exact Ready record; Destroyed
and destroy ambiguity link the exact DestroyPending record, operation, consent,
intent, and complete DestroyPostCall proof. Key-created, post-dispatch create-
unapplied, create-never-started, and key-destroyed receipts sign explicit bodies
that exclude their signature,
resulting record digest, and resulting journal head. KeyCreatedReceipt contains
the complete creation-purpose CA-key possession proof inline, not only its
digest; the inline proof binds the exact Creating ancestor and is independently
recomputed before Ready is accepted. The proof order is
commitment/predecessor to CreatePreCall to invocation marker to Creating, then either possession to
Ready or CreatePostCall to CreateUnapplied; destruction is Ready to
destroy intent to invocation marker to DestroyPending to DestroyPostCall to
Destroyed. A provider proof cannot name
its resulting receipt/record, and the key-created receipt contains only the
pre-Ready Creating-bound possession proof, so neither ancestry is directly or
indirectly self-referential.

The separate no-dispatch order is prior reservation root to proposed record to
GenerationCommitment to selected helper pending state to selected reservation
vector to the two bootstrap observations to CreateNeverStarted proof to its
receipt to CreateUnappliedNeverStarted and only then the exact-base helper
successor. No earlier node contains a later receipt, record/head, projection, or
helper successor.

LocalInterceptionCaCertificateV1 is one self-signed X.509 v3 ECDSA P-256 CA,
uses SHA-256, has critical CA=true/pathLen=0 and keyCertSign-only usage, matching
subject/authority key identifiers, no EKU extension, a random non-reused
positive minimally encoded 20-octet serial beginning with 0x01 through 0x7f,
no unknown critical extension, and at most a 365-day validity. Leaves are
CA=false, serverAuth/digitalSignature only, exact normalized SANs, fresh leaf
keys, and at most seven days or the remaining CA/admission deadline.

No concrete protected key provider is selected here. All provider rows remain
unsupported until non-exportability, peer binding, crash recovery, key
destruction, zeroization, exact release identity, and real-host evidence pass.

## Consent and transaction decision

Read-only preview enumerates exact targets, current state, permissions,
interaction, exclusions, support truth, and connectivity policy. It allocates
no key, generation, plan, permission, or mutation authority.

Generate, Install, Repair, RemoveTrust, and RemoveAndDestroy each need a new
bounded one-use consent receipt signed outside the renderer. Rotation needs a
RotatePrepare receipt binding the active CA and candidate generation profile,
then a second user action and RotateCommit receipt binding both exact CA
identities before any trust install or old-state mutation. RotatePrepare binds
a canonical target-scope/permission template because generation-scoped
TargetIds do not exist yet; RotateCommit binds a phase-tagged rotation body
whose candidate-install set is a bijective refinement proving every stable
scope, executor,
per-target permission/interaction requirement, release, dependency edge, and
required bit still matches that template. Template-local entry keys represent
derived-authority dependencies before AuthorityTargetId exists. RotateCommit
separately binds the old generation's exact active-retire set and an acyclic
phase graph through old-key destruction, so new install and old retirement are
never collapsed into one impossible scope-only bijection. Each retire row is
sealed as owned-remove, external-preserve, derived-reconcile, or optional-
omitted; only owned-remove can delete. A phase-tagged privilege/preauthorization
aggregate covers the candidate and retire sets in fixed order. The
Generate no-target variant has count zero and an empty bitmap. Template and
exact-set variants have canonical order and exact-length required bitmaps;
malformed length/order, duplicates, missing mappings, or scope/required
broadening fail before consent consumption. Both rotation receipts bind one
coordinator-chosen TrustOperationId, user/admin scope, fallback policy, native
interaction requirements, helper nonce, and expiry. A platform prompt inside a
later mutation is recorded as that journaled step's result, not predicted by a
receipt. Current-user and machine targets never fall back to each other.

CaConsentReceiptV1 is a closed canonical signed object, not an opaque broker
blob. Its signature-free body fixes version/domain, strict Ed25519 algorithm,
manifest-pinned keyset epoch/digest and key ID, signed product manifest digest,
current manifest-selection revision/root, receipt/installation/operation/base/
principal bindings, the closed operation and candidate/target unions,
`RequestedInterceptionFallbackPolicy = InterceptionPolicyV1`, privilege
aggregate, helper nonce, issuance/not-before/expiry, and 256-bit one-use nonce.
The policy is byte-identical in the plan, receipt, and runtime admission input;
unknown tags are rejected. CanonicalConsentReceiptBodyDigest hashes the
domain, `body` field tag, and exact body. The broker signature covers the same
body under a distinct `broker-signature` field tag. ConsentReceiptDigest hashes
the complete `{Body, body digest, signature}` wrapper under `signed-receipt`;
neither digest nor signature appears in an earlier preimage.

The v1 broker signature is only strict RFC 8032 Ed25519 with canonical 32-byte
public key and 64-byte signature; there is no alternate algorithm, prehash, or
context. ConsentBrokerKeyId is the consent domain plus `broker-key-id` field-tag
hash of that public key. `CompleteSignedProductManifestV1` retains the exact
canonical `SignedProductManifestBodyV1`, pinned Ed25519 verification key/ID, and
signature. SignedProductManifestDigest is the single domain-separated
`manifest-body` digest of that body, while the manifest signature uses the
distinct `manifest-signature` preimage; no wrapper-hash alternative exists. The
signed body directly contains ConsentAuthorityManifestProjectionV1, including
the complete ConsentBrokerKeysetV1, every key-provider freshness policy, and the
finite TrustCaManifestBoundsV1 used by plan, capability, replay, and provider
deadlines. Its remaining payload is release/profile/capability catalog data
only; operation, plan, receipt, selection, replay, journal, state, envelope, or
proof objects and their derived digests are forbidden, so the manifest cannot
refer back to a consumer constructed from it.

Current manifest/keyset authority is selected only through an append-only
installation ledger. Each ConsentBrokerKeysetSelectionRecordV1 binds a fresh
non-authorizing ConsentAuthoritySelectionId, nonwrapping revision, exact
predecessor revision/root and current manifest/keyset tuple, the full signed
manifest and projection, and effective selection time. The complete selection
state retains the ordered full record vector and recomputable root. Its current
signed manifest carries finite nonzero
MaximumConsentBrokerKeysetSelectionCount and
MaximumConsentBrokerKeysetSelectionEncodedBytes. Before bootstrap or append,
the helper constructs the entire candidate state and requires its exact count
and canonical encoded size to fit the candidate manifest's two bounds. A
successor may raise capacity but cannot lower either bound below retained
history plus its own new record; overflow or max-plus-one leaves the previous
manifest current with no journal, replay, envelope, receipt, or selector write.
Manifest
sequence strictly increases; keyset epoch never decreases; a same-epoch keyset
is byte-identical and a higher epoch is only an allowed append/retire/revoke
successor. Each key entry retains immutable not-before/not-after bounds and is
Active, Retired with a last-valid issuance cutoff, or terminal Revoked; keys
cannot be removed, replaced, reactivated, or un-revoked. Bootstrap selects the
first record with the initial Absent state. Later selection is a global-lock,
non-authorizing quiescent-state transaction whose journal delta, state index,
MonotonicSafetyEnvelopeV1, replay-time successor, and same-business stable
receipt all carry the same resulting selection revision/root, manifest
sequence/digest, and keyset epoch/digest. The selection record contains none of
those resulting objects, preserving a one-way manifest -> selection record ->
journal/head -> envelope/state graph.

Fresh-install selection does not pretend that an ordinary operation journal
predecessor already exists. After exact cleanup, the machine namespace selector
first uses a crash-safe CAS to retire the old installation seal and select no
current installation. Namespace CAS then selects one durable preparation before
either distinct non-exportable HelperAttestation or KeyAuthorityAttestation
provider call. After both marker-bound results verify, a final crash-safe CAS pins them, verifies
the release-global signed attestation policy, and selects their public keys and
IDs with a globally fresh InstallationId. The intermediate no-current state is
gate-closed and non-authorizing. The dedicated
InstallationBootstrapSelectionRecordV1 is not
self-signed. It is authenticated by that protected selector and binds the
verified manifest history, both role keys, the first complete selection state,
canonical empty replay/residual/provider/history roots, key-journal genesis, and
context-free initial Absent facts. The record is followed by the installation-
genesis trust-journal link/head, MonotonicSafetyEnvelopeV1, dual-signed Absent
stable receipt, last-quiescent snapshot, state, and selector in one acyclic
uninitialized-to-complete per-installation transaction. A crash exposes the old
current installation, the complete retired seal with no current installation,
one complete cleanup-capable preparation, or the retired seal plus the complete
new installation graph; it never exposes
two current installations or loses retired history. A second bootstrap or
either key replacement for the same InstallationId is invalid.

Every durable challenge and compact rotation-abort authority has an explicit
signature-free body, the HelperAttestation key ID, strict Ed25519 algorithm,
registered NUL-terminated role/domain and unique body field tag, plus a distinct
signed-wrapper digest tag. Recovery/key projections use the parallel
KeyAuthorityAttestation role. Identity-set and stable proofs contain both
signatures over the same canonical fact. The CA key, provider key, journal key,
gate key, manifest vendor key, old installation key, or caller-supplied key
cannot substitute. No signed body contains its signature/digest or a resulting
journal head, envelope, receipt, snapshot, or state. Any missing/mismatched role
key selects Invalidated and cleanup-only RecoveryRequired, never a replacement
key under the existing InstallationId.

Before first consumption, TrustPlanV1 and CaConsentReceiptV1 bind the exact
current manifest-selection revision/root as well as its manifest/keyset tuple.
The receipt must satisfy `not_before <= issued_at < not_after` for the selected
broker key. First consumption verifies the body-named signed manifest as that
exact current selection member, its complete keyset, key
ID/algorithm/public key, both receipt digests, signature, finite manifest-bound
lifetime, and the current selected revocation state before any side effect. Its
canonical ConsentReceiptVerificationResultV1 retains the complete receipt,
receipt-named manifest/projection, current complete selection state, evaluated
Active/Retired disposition, and effective replay time. Validation is repeated
under the same global lock immediately before the journal/tombstone selector;
the nested current state is re-encoded and checked against its current
manifest's selection count/byte bounds before the result is accepted;
any manifest-selection change aborts rather than consuming against a stale
decision. A currently revoked key is rejected even if an older keyset showed it
active. After atomic valid consumption, the exact receipt, verification result,
and full historical/current selection ancestry are immutable authority only for
that operation's already sealed recovery/safety-reduction path. Compaction
retains every referenced manifest, keyset, selection-record, and verification-
result preimage and cannot reset the logical selection count/encoded-size
accounting or discard a vector row; later retirement/revocation cannot replay
or broaden it.

Verification results live in a separate bounded append-only
ConsentVerificationHistoryStateV1, empty at bootstrap and retaining complete
canonical result preimages with a nonwrapping revision, count, ordered vector,
recomputable root, and encoded-byte total. First consumption reserves capacity
under the current signed manifest and appends exactly one result before the
receipt can be selected; deterministic replay of the same consumption appends
nothing. The current history revision/root is carried by the state index,
MonotonicSafetyEnvelopeV1, receipt intent, ordinary trust-journal predecessor,
and ReceiptAndPhaseSelection result. A successor manifest cannot lower the
history count/byte/result bounds below retained history, and tombstone or
journal compaction never frees or rewrites that logical history.

Each consumed consent appends its own phase-scoped recovery disposition before
that phase's first side effect. RotatePrepare's entry reaches only candidate
preparation/awaiting-commit or exact-base cleanup; RotateCommit consumes an
operation-bound capacity reservation and appends a separate entry for install,
switch, retire, and old-key destruction. Privilege aggregate references are
closed tagged template-versus-exact values and inherited authority references
must resolve within the same phase and set from the current dependent target to
the named authority endpoint; an unrelated edge in that set is not sufficient.
Authority endpoints are direct helper/user/administrator targets. Derived-to-
derived chains are rejected because their intermediate terminal proof would not
satisfy the direct VerifiedOwned/VerifiedPreExistingExact authority contract.
RotatePrepare capability rows use template-only subjects keyed by
TemplateEntryKey, including a distinct derived-template subject with its exact
authority key, fixed regenerator, stable scope, executor class, and read-only
input-scope commitment. They never invent a generation-scoped TargetId before
candidate allocation. Exact materialization later proves a bijection from each
template subject to its one exact target/derived-output capability row.

The helper journal is a canonical authenticated chain rather than an opaque
implementation tip. Genesis and every Append head use the registered
TrustJournalHead domain; one state-selector transition commits one registered
TrustJournalRecordLink over an exact counted native-record union, predecessor
head/revision, and nonwrapping resulting revision. A combined universe plus
state transition orders the universe record first and exactly one operation or
observation state-selection record second. The link never contains its resulting
head, so the DAG is native records to link to head to envelope/receipt/state.
Ordinary links inline and verify their complete predecessor head. If the
selected head itself is the detected integrity failure, only
EnterRecoveryRequired may use the quarantine predecessor variant, which commits
both that selected unverifiable digest and the latest complete authenticated
ancestor; it can grant no mutation and subsequent verified history extends the
new recovery head rather than blessing the corrupt tip.
Compaction uses a helper-signed canonical checkpoint containing a contiguous
recomputable verification suffix plus every detached historical record still
referenced by a state, snapshot, receipt, recovery proof, or replay result.
Ordinary links remain revision-adjacent; a quarantine link alone may bridge its
explicit selected-unverifiable interval from the complete last-authenticated
head, without claiming that the corrupt head verified. Detached rows have one
closed canonical sort key and retain their complete native preimages. Compaction
changes neither logical head nor authority and cannot replace ancestry required
for mutation.

The helper journal is the authoritative replay registry. It consumes a receipt
only in the same fsynced transition that records the first immutable phase
intent and an authenticated replay tombstone. Every receipt also binds its
exact expected lifecycle digest, revision, and journal tip. The replay index
has a digest-free canonical body and stores each tombstone's complete bounded
typed replay result inline; its root is external to its preimage. Journal
compaction retains those bodies. Each tombstone stores and verifies
CanonicalConsentReceiptBodyDigest, the complete signed ConsentReceiptDigest,
ConsentReceiptVerificationResultDigest, and the one-use nonce digest. The
selecting journal record retains the complete verification result and exact
predecessor keyset-selection revision/root, manifest sequence/digest, and keyset
epoch/digest; its resulting envelope/index must repeat that tuple byte-for-byte.
A different signature/keyset under
the same receipt ID or nonce is replay/integrity failure, not an equivalent
encoding. Byte-identical retry resumes or returns the old
result without another side effect, while reuse of either a receipt ID or nonce
with different content fails closed. All receipts for a compound rotation are
updated atomically. Terminal results use one bounded closed evidence-reference
union whose allowed receipt/plan/key/target/identity/absence domains cannot
refer to replay, tombstone, selector, lifecycle-state, or response objects.
TrustOperationId is separately unique across retained
operations; only the exact matching Prepare/Commit pair may share it, so a
phase update cannot contaminate another operation's replay result. Rollback-
safe time high-water rules retain tombstones until the receipt cannot be
accepted at any future valid clock. Preview and byte-identical query paths are
strictly read-only: they validate time and simulate pruning/capacity while
conservatively counting every tombstone not already pruned. Replay-time
maintenance and actual pruning may be folded only into an otherwise-authorized
selector transition; no preview, readiness, query, or maintenance-only path
writes a replay root, revision, envelope, or selector. Thus an authorized later
transition can reclaim safely expired entries without letting a read mutate
authority; live entries are never evicted. Capacity charges each entry at its maximum terminal-result size and
authenticates non-borrowable safety-reduction headroom: two entries while
installed permit RemoveTrust then RemoveAndDestroy, one while generated permits
destruction, and RotatePrepare reserves its exact future RotateCommit entry.
Drifted inherits its last stable FullChoice or DirectDestroyOnly mode exactly;
external drift never releases or downgrades the destruction reserve.
Ordinary work may be refused when full, but a matching commit or safety-
reduction operation consumes its reserve; after a consumed safety attempt only
the direct-destroy reserve may remain. If RemoveAndDestroy consumes that last
reserve, receipt consumption atomically creates an initially ForwardOnly
SafetyReservationConsumed disposition toward Absent; its same receipt/pending
snapshot remains the recovery authority until Absent instead of claiming it
can return to a key-owning base or terminally demand another receipt. Later
owned-removal and key-destroy intents verify that already selected outcome/path
and do not append a second ForwardOnly refinement. New key/
trust state cannot be created unless its future reserve fits. A crash cannot
leave a broker-only consumed bit without a recoverable TrustOperationId.
Generate enters
GeneratePending in that transition before the key call. RotatePrepare enters InstallPending with a generation commitment
before its candidate-key call, retains the template only in its preparation
phase, and has an empty per-target step vector. It authorizes candidate creation
and safe cleanup only. RotateCommit materializes the bijective candidate-install
set, seals the exact active-retire set and complete phase graph, initializes the
candidate steps, and is required for install, signer switch, retirement, and
old-key destruction.

Before every key or trust side effect, the owning ledger fsyncs exact intent,
before image, plan, fence/revision, consent, deadline, expected platform
conditional token or explicit absence, postcondition, and compensation. Trust,
Ready, and destruction operations require the exact CA identity and bounded
public DER. The sole pre-identity create call instead requires the exact
generation commitment, complete CreatePreCall proof, and
ProviderCreateOperationId in Creating before the call. A definitive post-
dispatch no-create or a successful destroy result requires the matching complete
CreatePostCall or DestroyPostCall proof before its terminal receipt/record. A
creation proven never started uses the distinct complete CreateNeverStarted
proof and receipt and has no Creating or provider-call intent. The executor performs
one registered operation, independently reads the exact result, and fsyncs
Applied, Compensated, Observed, Ready, post-dispatch CreateUnapplied,
CreateUnappliedNeverStarted, Destroyed, or Ambiguous
before returning success.

Idempotent retry requires the byte-identical operation. A changed request under
the same identity is rejected. An operation return code, process exit, mtime,
notification, chain result, or response without a durable result is not
transaction proof.

## Exact install, removal, and ownership

TrustTargetV1 is a closed platform-tagged union. Every row binds the full
certificate identity, exact store/domain/path/database scope, installer
executor, per-target privilege/interaction requirement, operation role,
installer owner, pre-existing classification, before image, backend release
tuple, intended postcondition, per-target step, and independent verification.

Installation uses exclusive add-if-absent where the platform target permits
it. An exact pre-existing external certificate/trust item can be verified and
used when policy permits, but ownership remains external. A collision,
different trust semantic, duplicate ambiguity, target mismatch, or unsupported
conditional primitive fails before or preserves the partial state.

Removal can affect only an item proven created by the same FlowProbe
installation/generation and still byte-for-byte equal to the recorded owned
after image. It requires an atomic expected revision/condition or an exact
exclusively owned object whose full deletion closure is unchanged. A broad
subject, label, nickname, issuer/serial, filename, hash, SPKI, logical store,
keychain, aggregate bundle, or database deletion is forbidden.

External deletion, replacement, trust changes, scope copies, duplicates, and
administrator writes close the gate and are preserved as Drifted or
RecoveryRequired. FlowProbe does not automatically reinstall or overwrite
them. During a later explicit remove, an exact previously owned item already
absent becomes an ExternallyRemoved terminal step carrying its prior owner
receipt, owned after image, current absence, and complete owned-copy scan; it
satisfies absence without authorizing a delete. Journal loss or corruption
never permits appearance-based cleanup.

Key destruction occurs only after every known owned target is proven absent,
all external pre-existing state is preserved, no signer/connection can use the
key, and the complete identity set is known. A FullChoice direct-destroy path
first commits its sole intended-Absent ForwardOnly refinement unless owned
removal already selected the identical path; a DirectDestroyOnly path verifies
the initially ForwardOnly SafetyReservationConsumed path and never refines it
again. Rotation cleanup/retirement likewise selects or retains its exact
phase-specific ForwardOnly direction. In all four direct-mode/rotation paths,
the phase's timely non-dispatching continuation and preallocated destroy ID
already exist before this later ForwardOnly selection. The selected helper state and complete
pending snapshot produce one common ForwardOnlyDestroyAuthorization before the
destroy intent exists. The key authority then fsyncs
the complete destroy intent and ProviderCallInvocationMarkerV1 in DestroyPending
before its one provider call. The marker may first be selected after the
continuation deadline; it reuses the same ID and proves the earlier continuation
selection rather than manufacturing new time authority. The provider operation
is keyed by that ID plus marker digest. Intent, marker, and DestroyPending inline
the same continuation, forward-only authorization, and deadline binding. Exact recovery may first-dispatch only a
NeverInvoked operation with that selected marker and a current helper state that
is the bound ForwardOnly state or a byte-preserving authenticated descendant;
in-flight/terminal operations are query-only. The
authority then requires the purpose-specific DestroyPostCall proof and negative-
possession result before Destroyed. Ambiguous
destruction remains RecoveryRequired; Absent cannot be published while a key may
survive and cannot substitute an attestation signature for destroyed-key
possession.

## Rotation and identity-set decision

Rotation is one compound TrustOperationId with at most one active and one
candidate/retiring CA. RotatePrepare is consumed together with a durable
InstallPending generation commitment before key creation. Until the exact
candidate key/certificate is bound, the identity-set read is unavailable rather
than publishing an active-only partial result. If no create marker was ever
selected, the complete never-started proof/receipt may terminalize that reserved
candidate generation, release only its residual identity reservation, retain
both provider-operation reservations (including the unused cleanup ID), and
return to the freshly proven old InstalledAndVerified base; no candidate SPKI
ever enters the set. Otherwise the candidate SPKI is then
appended to the ARCH-002 set, and RotateCommit
binds both exact identities, the template-refined candidate-install set, the
exact old-generation active-retire set, and the complete phase/dependency graph
before any trust mutation. Candidate Ready refinement also selects a key-
authority-signed
RotationReadyKeyProjectionAttestationV1 over the exact rotation operation,
post-Ready key epoch/revision/head, complete generation-state root, both active
and candidate Ready record digests, candidate commitment, uniqueness evidence,
and creation receipt. A separate, acyclic
RotationReadyProjectionSelectionRecordV1 binds that attestation to the exact
predecessor lifecycle state/revision/journal head, safety envelope, replay
revision/root/high-water, the exact predecessor complete pending snapshot,
effective committed time, and resulting replay-time high-water. The successor
snapshot uses AuthorizedOperationSuccessor with that same predecessor snapshot
digest and a complete CandidateDescriptorRefinement
TrustOperationJournalRecordV1 that inlines the native selection record/digest.
The helper record digest is distinct from the native evidence digest. The selector atomically commits the record and pending descriptor
refinement no later than the attestation deadline. The digest direction is
projection to attestation to selection record to pending refinement; neither the
attestation nor record names a resulting state/head/envelope digest. RotateCommit
and the old-key-destroy phase graph bind the complete attestation/record pair and
CandidateKeyBindingDigest; they are rotation-only historical selection evidence
and cannot substitute for a quiescent key projection or possession proof. The two sets may name the same logical scope but
carry distinct operation roles, generations, locators, and TargetIds. Both
SPKIs remain excluded through verified old-target removal and old-key
destruction. Every owned item locator is generation-scoped and
active/candidate platform items are disjoint; in-place path, nickname, item, or
trust replacement is forbidden. The new signer is selected only after all new
target and key proofs pass. The sealed retire set is carried unchanged into
RemovePending. Owned rows are removed exactly, external rows are preserved,
derived rows are reconciled through their mapped authorities, and omitted rows
prove no owned mutation before old-key destruction. A failure after signer
switch never silently reverts, drops the old identity, or reports completed
rotation. Signer switch has an acyclic context-free SignerSwitchPlanV1 built
from the candidate/active Ready and target-business commitments before the
rotation target binding, consent, and phase plan. Its digest is the phase-graph
node. Execution first creates a fresh SignerSwitchSelectionChallengeV1 binding
the operation, plan, RotateCommit consent/verification result, exact predecessor
state/snapshot/head/envelope/replay coordinates, candidate public identity and
complete key-generation root, helper nonce, observation time, and a finite
manifest-bounded selection deadline. Candidate possession and active-target
reverification are both challenge-specific. Signer-switch is a closed residual-
query purpose: every satisfaction row carries the complete query context, scan
result, ordered observations, and its own deadline rather than a digest-only or
ordinary admission observation. The SignerSwitchSelection helper-journal record
inlines the same complete challenge, candidate possession proof, and all target
query evidence, selects the complete SignerSwitchCommitted ForwardOnly
commitment, atomically narrows the RotateCommit recovery entry, changes the
internal signer, and
issues a helper-signed SignerSwitchReceiptV1 over that record's resulting
head/envelope/replay successor while the gate remains closed. The plan contains
no later binding/receipt; the challenge, proofs, and journal record contain no
resulting receipt/head. EffectiveSelectedAt is no later than the receipt,
challenge, possession-proof, query-context, scan-result, and observation
deadlines; an old challenge, cross-predecessor proof, incomplete scan, or mixed
query context is rejected. Thus the complete evidence is authenticated by the
journal delta without introducing a result-to-predecessor cycle.
The signer-switch journal selection and receipt carry the same candidate
identity, challenge, predecessor coordinates, and resulting journal coordinates;
one following RotationRetirePhaseAdvance record then moves the receipt-bearing
InstallPending snapshot to RemovePending and initializes the exact sealed
ActiveRetire step vector. A crash at that boundary selects a complete old or
new pending snapshot and never repeats signer switch.
The receipt contains no resulting state/snapshot, so the DAG is one-way. The
successor pending snapshot then carries the complete plan/receipt in its
SelectedSignerSwitch evidence beside the same journal lineage, and every later
retirement descendant retains it byte-for-byte. The
signer-switch selection reaches only the new installed terminal. Candidate
cleanup before RotateCommit uses the ordinary retained RotatePrepare path. Once
RotateCommit has begun candidate-target mutation, only its compact abort
authority can select the independent CandidateAbortCompensationVector and mark
RotatePrepare CleanupLockedByRotationAbort. The abort selector then owns the
fixed cleanup suffix without creating another ForwardOnly entry or editing any
original terminal target anchor. Each owned removal follows its original
executor/permission, derived output follows reverse dependency order, and
preserved/never-attempted rows remain non-mutating. The fresh complete absence
root must precede candidate-key destroy under the already selected continuation
and preallocated operation ID. A missing AbortCapacityAdmission, changed
compensation vector, stale predecessor, lost interaction gate, or selected signer
switch leaves the operation pending/RecoveryRequired and grants no cleanup call.
Old-key
destruction uses the distinct RotateCommitOldKeyDestroy variant, revalidates the
attested post-Ready root/head, CandidateKeyBinding/RotationTargetBinding, and
candidate Ready entry, and inlines the same complete SignerSwitchPlanV1 and
SignerSwitchReceiptV1/digests. A missing, stale, or substituted receipt forbids
old-key destruction. It then appends from the current global key tip while
selecting only ActiveReadyRecordDigest as the historical destroy target.

The authoritative ARCH-002 identity-set read is a linearizable dual-signed
helper/key-authority proof over one explicit signature-free canonical body. It
contains every generated, candidate, current,
retiring, residual, drifted, externally removed, partially installed, or
key-destroy-pending known FlowProbe CA SPKI. Only a fully reconciled Absent
state may return an authoritative empty set. An incomplete/corrupt ledger or
generation commitment whose exact public identity is not yet bound returns
IdentitySetUnavailable; ARCH-002 maps that to DependencyContractUnavailable and
never assumes empty.
The proof also binds the selected machine namespace. Its returned SPKI vector is
the sorted unique union of the current installation's fresh complete projection
and every retired seal's immutable conservative SPKI vector, so a fresh
InstallationId cannot erase an externally preserved old CA from loop exclusion.

Absent means no FlowProbe-owned trust item and no live/ambiguous CA key; it may
still carry a nonempty known-residual identity set and preserved-external
business root when an exact historical FlowProbe certificate remains in an
external scope FlowProbe did not own. A residual with a fresh exact-anchor TLS
success is PreservedExternalLive. After that historical CA key is terminally
Destroyed, a fresh leaf can no longer be produced, so the narrower
ConservativeExternalTrustPotential disposition is allowed only when the exact
destroy receipt and unique key-ledger ancestry verify, a fresh complete scan
still finds an exact external member with ServerAuthTrusted semantics, and the
only missing consumer fact is the fresh probe made impossible by that key
destruction. Its sole authority is to retain the historical SPKI in ARCH-002
filtering. It is not a live trust success, consumer-support claim,
Installed/admission proof, signing authority, ownership, or permission to
delete, rewrite, or restore the external item; no current or replacement key may
probe on behalf of the destroyed identity.

There is no time- or leaf-expiry-based removal of that conservative SPKI. It is
removed only when a later complete scan proves the exact external residual gone
or unambiguously without server-auth trust. Any other missing, unknown, or
ambiguous provenance/trust evidence makes the identity-set read unavailable
rather than empty. Only complete proof that neither live nor conservative
external residual exists makes the Absent identity set canonical-empty. Known
residual/current identity-set fields in the quiescent business body directly
equal the ARCH-002 sorted-SPKI digest and are not double-hashed under the
quiescent-business domain.

Every read, regardless of lifecycle state, validates ReplayTimeHighWater without
writing it, then creates a fresh ephemeral query context against the single
selected predecessor and performs a complete same-lock universe scan. The
response binds that context, fresh target observations, scan result, challenge,
and effective time. A byte-identical business-fact projection may sign the fresh
proof without rewriting terminal observations or advancing replay time,
journal, or state revision. A changed projection must atomically select the
state-appropriate observation successor first, optionally folding necessary
replay/time maintenance into that already-required commit; it then uses a new
nonce to repeat the full scan before signing. Incomplete, expired,
clock-rollback, unknown-identity, or selector-crash state returns
IdentitySetUnavailable. A historical terminal observation, prior scan, watch
result, or receipt is never reused as current freshness evidence.

## Interception admission and connectivity

Interception policy is one of PassThroughOnly,
PreferInterceptionWithTransparentPassThrough, or RequireInterception. The
first never contacts the key. PreferInterception passes through transparently
when trust proof is unavailable. RequireInterception returns a typed refusal
before presenting a FlowProbe leaf.

Every new intercepted TLS connection consumes one fresh proof binding:

- installation, CA generation/instance, complete certificate identity, and
  installed receipt;
- complete required target verification root and effective TLS success;
- helper journal tip/revision, key-ledger tip/epoch/revision, and gate epoch;
- exact Capture Core instance, connection, normalized leaf request, challenge,
  observation time, and expiry; and
- matching helper trust and key-possession signatures.

The admission challenge, exact Capture Core instance/connection, and normalized
leaf request deterministically derive the query nonce/context for one complete
ResidualScanUniverse scan. Admission reuses that exact challenge/request-bound
scan body and all of its direct/derived observations; it cannot substitute a
status read, a target-only rescan, the identity-set result from another
challenge, or independently assembled per-target roots. If the admission scan
discovers a changed fact, it follows the successor-then-new-nonce full-rescan
rule above before either admission signature or leaf signing.

The LiveReady possession proof selected into a Generated or
InstalledAndVerified stable receipt proves that exact stable-state selection;
it is not reusable as the per-connection possession proof above. Conversely,
the ClosedDrifted and NoLiveOrAmbiguous attestation projections, an immutable
terminal observation, and ConservativeExternalTrustPotential can never satisfy
admission or authorize leaf signing.

Pending, drift, ambiguity, missing target, stale proof, key mismatch, residual
rotation, helper/key loss, or identity-set failure refuses signing. Established
connections may drain only under a bounded sealed lease that cannot create a
new connection or leaf. CA failure alone does not claim loss of ordinary
connectivity or mutate the persistent network session.

## Platform target decision

### Windows

Only the exact physical `Root\.Default` store is a candidate, separately for
CurrentUser with an authenticated interactive User SID and LocalMachine with an
administrator helper. The logical Root collection, maximum-allowed fallback,
Group Policy stores, other users, and browser-private stores are not mutation
targets. Add uses CERT_STORE_ADD_NEW and exact DER reread; replace/use-existing
dispositions are forbidden. Raw inventory explicitly selects CurrentUser or
LocalMachine, includes archived items, bypasses CurrentUser protected-root
cache filtering for observation, and remains distinct from effective chain
trust. The only bounded add candidate sets exactly the serverAuth EKU property
on a detached context before one ADD_NEW call; changing a context already
visible in Root is forbidden. Its extension-only view is absent/all-uses, while
the query reports FALSE with CRYPT_E_NOT_FOUND. Its property-only and combined
queries return TRUE with exactly serverAuth. Pre-existing external contexts are
never changed, and every claimed consumer must prove it preserves that purpose
restriction. SSL proof fixes serverAuth, server
authentication, exact hostname, zero flags in both policy structures, exact
root DER, and a zero policy-status error; API BOOL success alone is
insufficient.

CryptoAPI provides neither store revision nor conditional delete. Context
duplication, store notification/resync/commit, certificate properties, and
issuer/serial comparison are not CAS or ownership. Both shared Root candidates
therefore remain unsupported pending exact conditional deletion. Microsoft
documents copying ordinary properties into the new stored context, but not
atomic externally visible or crash-durable certificate-plus-property install;
that gap and per-consumer propagation both require exact-release real-host
proof.

### macOS

User Trust Settings plus the resolved user file keychain and Admin Trust
Settings plus the exact System.keychain are separate candidates. The Apple
System Trust Settings domain is observation-only even for root. User mutation
requires the exact logged-in GUI identity; Admin is a separate administrator
choice that must execute in a foreground GUI agent after native administrator
authentication under a one-use helper gate. The LaunchDaemon keeps the journal
and lock but cannot perform or replace that GUI-authenticated Admin call.

The only accepted semantic is SSL-server policy
(SecPolicyCreateSSL(server=true, hostname=null), persisted
kSecPolicyAppleSSL plus policy name sslServer) and TrustRoot with no
application, hostname, allowed-error, or key-usage constraint. Client, missing,
or unknown policy names fail closed. Removal uses the exact certificate/domain
RemoveTrustSettings operation and verifies trust absence before deleting only
a proven FlowProbe-owned Keychain item; null Set is never removal. Public
Security.framework has no stable revision, expected-state CAS, or transaction
spanning Keychain and Trust Settings. Apple implementation evidence shows
whole-domain and multi-store writes can be partial. User/Admin remain
unsupported pending conditional mutation, a stable monotonic/no-ABA observation
revision, and crash durability; Admin
additionally awaits the exact foreground administrator agent/interaction. Both
require real-host proof; System is immutable.

### Linux

There is no generic Linux or browser-trust target. Debian/Ubuntu
generation-scoped source anchors, Fedora/RHEL generation-scoped p11-kit policy
sources directly below the parent trust-source directory, each derived system
output, and each explicit NSS SQL database are separate rows bound to an exact
release tuple. NSS nicknames are generation-scoped too. Caller paths, commands,
environments, HOME discovery, wildcard browser profiles, DBM databases, and
direct aggregate-bundle writes are forbidden.

Debian/Ubuntu implicit anchors carry no purpose constraint and are
UnsupportedByProductPolicy as overbroad. A Fedora/RHEL candidate must normalize
to a p11-kit positive anchor only for TLS server authentication and preserve
that purpose through every claimed derived consumer. NSS is fixed to the exact
C,, SSL-CA flags. A plain all-purpose Fedora/RHEL anchors-directory file or a
consumer that drops purpose constraints is not the selected semantic.

Debian/Ubuntu /usr/local trust-source parents are administrator-managed rather
than package-owned. Their complete path identity, writer set, input tree, and
hooks are observed; a group-writable or otherwise non-exclusive ancestor is
Unsafe and cannot be repaired by final-component no-follow checks.

Shared regenerators rewrite global outputs and may run hooks without a stable
cross-output transaction or revision. NSS certutil deletion is nickname-based
without expected DER/revision. These candidates remain unsupported pending
safe conditional source/database lifecycle, a release-bound monotonic/no-ABA
snapshot token, bounded regenerator recovery, complete release tuples, and real-
host proof. CurrentUser and SystemService NSS databases are separate capability
rows: the former additionally carries AuthenticatedUserAgentUnavailable until
its exact owner-context agent exists, and neither row may fall back to the
other's executor.

Each derived output reaches its own VerifiedDerivedExact state without
acquiring ownership. Its one primary DerivedBy edge controls only plan order,
executor, consent-set membership, and inherited permission/interaction; it is
not a complete source claim. Fresh provenance instead binds the registered
read-only input scopes, the complete current set of direct owned and external
authority sources, and one same-query fixed-regenerator result before observing
the derived member. Additional sources grant no mutation target, privilege,
executor fallback, ownership, or deletion authority. After the primary is
removed, retained primary lineage preserves execution history while the current
source set may still prove that an identical external source legitimately keeps
derived bytes and TLS trust present. Such state is reported and preserved,
never deleted or rewritten as though the primary edge owned the aggregate.

Browser and application coverage is always separate consumer evidence. OS
trust does not imply browser-private store, profile policy, enterprise-roots
setting, pinning, embedded TLS stack, or already-running consumer coverage.

## Helper protocol consequence

A new explicit ARCH-001 task must add versioned deterministic schemas for the
trust transaction, per-target operations, user/admin/key online gates, recovery,
state/proof reads, gate challenge, and identity-set query, including numeric
tags, golden vectors, peer bindings, deadlines, errors, and receipts. It must
preserve global mutation-lock serialization while keeping trust and network
generation/fence domains distinct.

Until that task is accepted and implemented, every mutable target carries
TrustTransactionProtocolUnavailable and TrustReadProofUnavailable. Direct
journal reads, a generic helper operation, an in-process key call, or a Status
boolean are forbidden substitutes.

## Support and evidence decision

Capability is reported per exact key provider, trust target, derived output,
and consumer. StaticSupport, current DynamicReadiness, and independent evidence
bits are all required; a runtime success never promotes static support. A row
becomes usable only when it is statically Supported, dynamically Ready, has no
bounded reasons, and has deterministic, real install, crash-recovery, exact-
uninstall, and per-consumer TLS proof for the exact signed release tuple.

At this ADR snapshot every key provider, mutable Windows/macOS/Linux target,
derived output, NSS database, and browser consumer remains DesignReviewed only
and cannot authorize interception. The complete normative matrix and reasons
are in the contract.

## Crash, drift, update, and uninstall

Startup and every admission revalidate both ledgers, all exact targets, derived
outputs, effective TLS trust, key possession, identity-set completeness, and
gate epoch. Platform notifications and modification dates only trigger a fresh
observation; they are not ordered authority.

Crash recovery settles each intent as applied, unapplied, or ambiguous from
exact durable identity and current observation. It may finish observation,
compensate a proven partial addition, or complete destruction already covered
by exact consent. It cannot install, repair, broaden scope, rotate, or re-add
trust from implied startup consent.

Compaction retains the pinned two-key installation anchor, Invalidated state,
every historical signature needed for audit verification, the complete admitted
abort capacity floor, CandidateAbortCompensationVector, fresh absence evidence,
cleanup operation identity, and selected abort/signer-switch CAS edge. It cannot
turn an old role key into current authority, discard CleanupLockedByRotationAbort,
reclaim abort capacity before terminal cleanup, or summarize away which
candidate rows were owned, derived, preserved, or never attempted.
After external exact cleanup, the immutable RetiredInstallationSeal and machine
namespace selector keep the old per-installation checkpoint discoverable for
historical verification. Compaction cannot prune or relabel that seal, reuse its
global identities, or let its old role keys authenticate current state.

Updater and uninstaller close the gate and reconcile first. They cannot remove
the helper, key authority, journal, owner record, or provider while any owned
target/key, pending mutation, drift, or RecoveryRequired state remains. Foreign
or ambiguous state is preserved and reported rather than deleted.

## Rejected alternatives

- Reuse the current in-memory CA as persistent state: it has no protected key,
  consent, ownership, restart, or trust-store evidence.
- Store the CA private key in the renderer, Supervisor database, helper journal,
  configuration, profile, or ordinary OS file: this violates least privilege
  and expands compromise and diagnostic leakage.
- Let the generic helper generate or sign leaves: this turns mutation authority
  into a high-value signing oracle and mixes unrelated trust boundaries.
- Treat a certificate fingerprint, subject, label, nickname, filename, or SPKI
  alone as ownership: none proves the exact certificate instance, target, or
  creator and each can delete foreign state.
- Save and restore a whole trust store, keychain, aggregate bundle, or NSS
  database: this overwrites concurrent administrator and package-manager state.
- Consider install API success or chain validation alone sufficient: neither
  proves durable transaction state, exact ownership, key match, all outputs,
  consumer coverage, or safe removal.
- Automatically reinstall after external deletion or repair changed trust:
  external change is drift and requires new explicit intent.
- Remove trust whenever the network runtime stops: persistent trust consent and
  temporary network-session lifecycle are intentionally independent.
- Encode unavailable ARCH-002 CA identities as an empty exclusion set: this can
  route interception traffic through a proxy trusting the same local CA.
- Advertise generic Windows/macOS/Linux/browser trust: authority, scope,
  release, consumer, permission, and evidence differ materially.
- Hash terminal/query observation wrappers into TargetBusinessFact or the
  quiescent business root, or let a fresh context reference its own resulting
  state: either creates a digest fixed point or turns historical evidence into
  false freshness.
- Treat the single primary DerivedBy edge as the complete provenance of a
  derived aggregate: this loses additional external sources and can authorize
  deletion of state FlowProbe never owned.
- Retain, recreate, or substitute another signing key merely to probe a
  preserved external copy after destruction: this violates key destruction and
  can turn observation into a signing oracle; conservative SPKI inclusion is the
  fail-safe alternative.
- Use one generic provider-absence attestation across creation and destruction:
  it permits cross-purpose evidence substitution and hides whether a provider
  call was never made, created nothing, or completed destruction.
- Put installation attestation private keys in the release manifest, self-sign
  bootstrap, or rotate a role key inside one InstallationId: each confuses
  release policy with installation authority and makes compromise/replacement
  recovery indistinguishable from rollback. V1 invalidates and reinstalls under
  a fresh InstallationId instead.
- Reuse the candidate-install terminal step vector as abort mutation state, or
  model abort as two ForwardOnly entries joined by a giant handoff: terminal
  anchors are immutable, while split authority can race, partially select, or
  consume cleanup twice. A separate bijective abort vector and one compact CAS
  keep observation history immutable and authority singular.
- Discover abort capacity after the first candidate mutation or add a second
  reservation ledger: the former can strand trust and the latter adds another
  recovery authority. AbortCapacityAdmission uses the existing signed maxima and
  is selected before mutation.
- Extend the accepted helper protocol implicitly inside this task: its wire
  union is closed and changing it requires a separately scoped architecture
  task.

## Consequences

Positive consequences:

- private-key material stays outside renderer and generic privileged mutation
  authority;
- persistent trust has explicit consent, ownership, exact identity, durable
  partial state, crash recovery, drift closure, and bounded uninstall;
- context-free business facts, immutable terminal evidence, and fresh query
  observations have an acyclic construction order without sacrificing current
  proof freshness;
- release policy is separated from installation authority; two pinned,
  non-exportable role keys provide domain separation without in-installation key
  rotation or bootstrap self-trust;
- rotation abort preserves original terminal anchors while a separately bounded
  compensation vector gives one crash-recoverable cleanup suffix;
- administrator and pre-existing trust state is preserved rather than restored
  from stale baselines;
- interception readiness is cryptographically cross-bound to effective trust
  and the actual signing key for each new connection;
- ARCH-002 receives one authoritative conservative identity set through
  rotation and recovery; and
- product capability truth cannot outrun platform, release, or browser proof.

Costs and constraints:

- a new helper protocol version, separate key authority, user-context and
  foreground administrator agents, platform backends, deterministic conformance
  suites, and disposable real-host labs are required before any support claim;
- shared platform trust stores without conditional mutation may remain
  unsupported unless an exclusive-owned architecture can be proven;
- multi-target state, rotations, and partial outputs stay visible until exact
  reconciliation, increasing implementation and evidence complexity;
- loss or suspected compromise of either installation attestation key is
  intentionally terminal for that InstallationId and may require a cleanup-only
  recovery followed by fresh installation;
- a destroyed-key external residual can conservatively over-include an SPKI and
  force pass-through or reduced interception observability until a complete
  later scan proves it gone; this false positive is preferred to an exclusion
  false negative; and
- browser/app compatibility is tested and reported separately rather than
  inferred from OS trust.

## Verification obligations

These closure decisions require explicit byte-exact positive and negative
conformance coverage:

- require exact equality between the contract and this ADR's release-global
  closed attestation policy and two-key domain registry. Exercise distinct
  non-exportable HelperAttestation and KeyAuthorityAttestation identities,
  domain/role substitution, equal-key aliasing, manifest-policy downgrade, key
  loss/mismatch/suspected compromise, permanent Invalidated cleanup-only state,
  historical-only old-anchor verification, and rejection of any replacement or
  self-signed bootstrap under the same InstallationId;
- exercise complete TrustPlan body/wrapper/ID/digest,
  CompleteSignedProductManifestV1 body/digest/signature with no alternate
  wrapper digest, explicit ConsentAuthorityManifestProjectionV1 and
  TrustCaManifestBoundsV1,
  capability-snapshot body/wrapper/digest, immutable-target-plan body/wrapper/
  digest, provider-deadline vector, and pending candidate/current/retiring
  identity-or-commitment vector golden encodings. Reject wrong counts, order,
  bounds, graph membership, dependency edges, phase/manifest/capability
  substitution, digest-only target records, missing or extra capability rows,
  and state-incompatible identity-vector variants;
- exercise the root-owned installation selector, two fresh pinned role keys,
  non-self-signed installation-bootstrap native record, installation-genesis
  trust-journal head, revision-zero key-journal genesis, canonical empty roots,
  initial Absent receipt/state, and final selector as one acyclic golden graph.
  Crash at every durable boundary must expose either an uninitialized
  installation or that complete graph. Reject bootstrap through an ordinary
  operation predecessor, a record that names a resulting object, cross-
  installation/key-authority substitution, unequal nested installation/epoch/
  counter/root fields, a nonempty genesis root, and any second-bootstrap
  attempt. Exercise recovery-key-projection, durable challenge, and compact abort
  signature-free bodies, the correct installation-pinned role key, unique
  signature field tags, and signed-wrapper digest field tags; reject manifest-
  embedded installation keys, signer-role, old-installation, or wrapper/preimage
  substitution and prove every signature still requires the current CAS;
- exercise every closed lifecycle payload and pending-snapshot container with
  exact count, order, encoded-byte bound, state/phase cardinality, and complete
  step type. Exercise the unique AuthorizedPhaseOutcome and per-target
  step/fact/evidence/retry/reason matrices for all phases, and reject every
  unknown tag, missing/extra row, cross-phase outcome, impossible evidence
  combination, and unregistered transition. Exercise the closed interception-
  gate matrix and epoch changes, proving that only InstalledAndVerified can
  select AdmissionEligible and that the post-signer-switch rotation suffix is
  ClosedDuringRotation; receipt, envelope, runtime admission, policy, identity,
  and business postcondition must be byte-identical. For each quiescent payload,
  reject a different inline business/receipt wrapper, identity, required-target
  set, identity-set digest, gate receipt, or retained stable ancestor even when
  each duplicate object verifies independently;
- exercise RecoveryRequired with complete Creating, DestroyPending, and
  Ambiguous key-tip projections and every closed reason-to-resolution mapping.
  Some and None exits must account bijectively for the original reason vector;
  only the matching provider resolution may atomically refine the exact
  ProviderOutcomeAmbiguous helper step to its native terminal step, unrelated
  fields remain unchanged, and RecoveryPathExhausted never exits through an
  ordinary automatic resolution. Reject cross-reason evidence, an omitted
  reason, retained ambiguity declared resolved, and recovery-only key
  projections used as signing or admission authority. Exercise separate
  RecoveryPendingResolution and RecoveryNoneReproof query anchors, one same-scan
  context across compatible pending resolutions, selector/ancestry resolution
  with and without a retained pending snapshot, stale reason roots, mixed
  contexts, and a business reproof offered in place of journal repair;
- exercise current-selection-bound plans and receipts, broker-key not-before/
  issuance/not-after boundaries, and bounded consent-verification history.
  First consumption appends exactly one complete result before selection and
  deterministic replay appends none. Check history result/count/encoded bytes,
  every signed residual/pending/provider/journal/recovery capacity, and checked
  arithmetic at max-minus-one, max, max-plus-one, zero, UINT64_MAX, and overflow.
  Reject first consumption after any selection change, a successor manifest
  below retained history, history reclamation through compaction, and any
  mismatch among state index, envelope, receipt intent, journal predecessor,
  and selection result history coordinates;
- construct pure target/source facts, immutable terminal observations, selected
  closed lifecycle state/envelope, fresh contexts, direct observations, fixed-
  regenerator receipts, derived observations/results, and any successor in the
  accepted one-way order. Reject plan role/step, receipt, observation, ordinal,
  context/time/token, wrapper-in-business-root, reverse edge, stale terminal-as-
  current proof, or context-to-resulting-successor reference. Two evidence sets
  with the same semantics must project to the same fact; terminal evidence must
  pass its deadline only before first durable selection and remain valid
  afterward. Exercise complete LastQuiescent current facts plus terminal anchors,
  Pending-to-exact-base-snapshot binding, unknown/cross-tag lifecycle variants,
  and reconstruction-from-summary rejection;
- keep exactly one primary DerivedBy edge while testing complete current source
  sets at terminal operation time and at query time containing primary-only,
  additional owned, additional external, mixed, removed-primary retained-lineage,
  omitted-source, nested-derived, and changed-regenerator cases. Require every
  repeated primary/source/regenerator/output/consumer/release/context field to be
  byte-identical. Exercise ExternalCurrentObserved with complete
  NoFlowProbeOwnershipProof after install and after destroy; it may preserve and
  retain an SPKI only, and must never change support, admission, mutation,
  privilege, interaction, executor, ownership, adoption, or delete sets;
- prove that a byte-identical query performs no replay-time, journal, selector,
  or state write; maintenance appears only inside an independently required
  semantic transition. A changed scan must commit the correct successor, discard
  that scan for response purposes, create a new nonce/context, repeat the complete
  all-scope scan, and sign only the second result. Admission must use the exact
  challenge/request-derived complete residual scan and reject a cached identity
  query, target-only scan, independently assembled roots, or any field mismatch;
- exercise the stable-state key projection matrix: Generated and
  InstalledAndVerified require matching LiveReady plus fresh stable-selection
  CA-key possession; Drifted requires gate-closed ClosedDrifted and no
  possession; Absent, including residual reconciliation, requires
  NoLiveOrAmbiguous and rejects possession. An attestation must not substitute
  for LiveReady possession, possession must not substitute for a closed
  attestation projection, and a per-connection admission proof must not
  substitute for any stable-state selection proof;
- prove the three provider-call absence domains, the separate signed never-
  started domain, and the closed generation/destruction projections separately
  across pre-call crashes, definitive post-dispatch no-create, direct NoRecord-
  to-CreateUnappliedNeverStarted cancellation,
  durable
  destroy intent, negative possession, applied destroy, token/operation/provider/
  key/helper/challenge/time mismatch, incomplete enumeration, multiple
  candidates, and cross-purpose replay. KeyCreatedReceipt must carry and verify
  the complete inline creation-possession proof. Reject installation-lifetime
  SPKI reuse, same provider object under two generations, distinct handles that
  alias one key, provider-identity ABA, and old-key destruction that can affect a
  candidate; only matching complete evidence may select Ready, post-dispatch
  CreateUnapplied, CreateUnappliedNeverStarted, DestroyPending, or Destroyed.
  Exercise cross-purpose/reused provider-operation IDs, staged reservation crash
  recovery, unused cleanup-ID retention, and compact-then-recompute of the full
  reservation vector. Exercise the rotation-ready attestation body,
  signature, digest, first-selection deadline, operation/root/head bindings, and
  active/candidate Ready substitution. Candidate cleanup and old-key destroy
  must use the current global predecessor plus the exact attested pre-destroy
  root, rejecting historical-Ready-head rewind, intervening-record skip, and
  target/non-target Ready swap. Recompute all five profile freshness windows,
  checked sums, and the creation canonical minimum at before/equal/after
  boundaries; reject zero, `UINT64_MAX`, overflow, shortening, extension,
  wrong manifest/profile/window, expiry, and provider-object ABA reuse;
- exercise SignerSwitchSelectionChallengeV1 with the complete predecessor,
  candidate identity/root, plan, consent result, nonce, and finite selection
  window; its candidate possession proof and every signer-switch residual query
  context/scan/observation must inline and bind that exact challenge. The
  journal delta and receipt must agree on all predecessor/result coordinates,
  and EffectiveSelectedAt must meet every consent, challenge, proof, context,
  scan, and observation deadline. Reject cached ordinary-admission evidence,
  digest-only rows, mixed contexts, omitted active targets, stale challenges,
  cross-predecessor/candidate substitution, and any result-to-predecessor
  reference cycle;
- exercise pre-signer-switch rotation abort after zero, one, or several
  candidate target mutations. CandidateAbortCompensationVector must be a full
  bijection with CandidateInstallSet while original terminal anchors remain
  immutable; cover owned removal, derived reverse-dependency reconciliation,
  external preservation, and never-attempted/verified-absent rows under their
  original executor/permission. The compact abort selector must atomically select
  the sole RotateCommit ForwardOnly direction and mark Prepare
  CleanupLockedByRotationAbort, then require a fresh complete absence root before
  the retained candidate-key cleanup. Reject missing/undersized
  AbortCapacityAdmission, manifest lowering below its live floor, a new
  reservation ledger, changed target/after-image/cleanup ID/deadline/Ready
  evidence, key-first ordering, user/admin/helper fallback, external or browser-
  private deletion, duplicate cleanup consumption, abort after signer switch,
  or old-base selection from a post-switch descendant;
- exercise keyset-selection genesis and append golden vectors with complete
  signed-manifest/keyset preimages, nonwrapping revision, predecessor/root,
  effective selection time, envelope/index/journal equality, same-epoch exact
  bytes, higher-epoch append/retire/revoke, receipt-named historical membership,
  current revocation, and compaction retention. Exercise selection count and
  canonical-state bytes at max-minus-one, exact max, and max-plus-one, a
  candidate lowering either bound below retained history, a candidate raising
  capacity for a fitting append, overflow, receipt verification against an
  oversized current state, and proof that compaction cannot reclaim selection
  rows. Reject manifest-sequence and
  keyset-epoch rollback, forked predecessor, same-sequence/different-digest,
  same-epoch/different-keyset, missing history, stale current projection, and
  validation-to-selector TOCTOU before any tombstone or side effect;
- after key destruction and after every pre-destruction test leaf has expired,
  verify that an exact current external server-auth member with only a destroyed-
  key probe gap selects ConservativeExternalTrustPotential and retains only its
  SPKI. It must not authorize signing, admission, deletion, ownership, or a live
  support claim; complete absence/no-server-auth removes it, while any other
  uncertainty makes the identity-set query unavailable; and
- inject crashes before and after fresh-context creation, the first changed scan,
  successor selection, the mandatory new-nonce rescan, unchanged proof signing,
  stable receipt selection, and provider calls. Recovery must keep terminal
  observations immutable, discard expired or incomplete query evidence, preserve
  foreign state, and converge to one complete predecessor or successor without
  reusing stale freshness or repeating a key/platform side effect.

Implementation tasks must provide byte-exact state/receipt/proof golden vectors,
malformed/fuzz coverage, exhaustive transitions, consent and replay negatives,
crash injection around every durable/key/platform boundary, exact-identity and
concurrent-admin races, partial multi-target recovery, key match/destruction,
post-dispatch CreateUnapplied, CreateUnappliedNeverStarted, and ambiguous
provider outcomes; digest-free key-record and receipt bodies with exact
create/destroy ancestry and distinct pre-Ready versus
post-Ready possession proofs, compact-then-replay of the complete inline typed
result with closed nonrecursive evidence references, operation-ID collision
checks, maximum-result capacity accounting, reserved commit/safety-reduction
progress including initially ForwardOnly consumption of the final destroy
reserve without later duplicate refinement and exact Drifted-mode inheritance,
replay-index time maintenance and
clock-rollback cases, byte-exact quiescent-business/pending-snapshot/monotonic-
envelope projections with failed-generation and candidate-cleanup high-water
successors, template dependency/refinement and dual-set rotation
graphs, all active-retire dispositions and closed phase/set-tagged privilege
aggregates with derived-to-derived rejection, ObservationOnly exact-set
rejection, empty and preserved-external-residual Absent identity sets,
direct ARCH-002 Known*IdentitySetDigest vectors with double-hash negatives,
Absent residual empty-to-nonempty/nonempty-to-empty/scope-change observation
transactions, byte-identical no-op, incomplete-scan fail-closed behavior,
old/new selector crash convergence, and RecoveryRequired(None)-from-Absent
reconciliation without consent, mutation, operation, gate, or replay authority,
manifest-bounded residual-universe identity/scope/byte capacity at max-minus-
one/max/overflow, ARCH-002 uint32 count/+1, and every canonical integer-width
boundary, H0/combined-U1/commitment/H1 ordering, full-body and Cartesian result
reservation, identity refinement, multi-scope first-use registration,
observer-release update/rollback/crash, unique current-versus-historical
universe ancestry and compaction retention including the staged H0/U1-to-H1/U1
generation exception, complete pending/last-quiescent snapshot commitments and
every closed quiescent stable-receipt domain, zero-based uint32 container
ordinals, exact scope/identity/RequiredTarget bitmap packing, closed
enumeration/consumer-TLS/derived-provenance/ownership/trust aggregate preimages
with no cross-item join, no ambiguous OwnedOnly, sort, and duplicate cases,
all-scopes-before/enumerate/all-scopes-after
barriers including cross-scope moves, complete presence/negative bitmaps,
omitted or substituted scope/identity/token negatives, mandatory fresh scan and
state-appropriate observation successor for every answerable lifecycle state,
off-plan pending refresh versus planned-target step reconciliation,
observation expiry, and ReplayTimeHighWater clock rollback,
quiescent observation-only recovery with monotonic safety metadata,
  phase-scoped RotatePrepare/RotateCommit dispositions, the sole RotateCommit
  ForwardOnly choice, CleanupLockedByRotationAbort, complete independent abort
  compensation rows and AbortCapacityAdmission Cartesian count/byte floors,
zeroization/redaction, admission/fallback behavior, and complete ARCH-002
identity-set cases.

Each supported release row additionally requires disposable real-host install,
effective TLS validation, restart, hard-crash recovery, drift, concurrency,
exact uninstall, unrelated-state preservation, and separately versioned real
consumer/browser tests. Fake backends prove deterministic logic only and never
platform support.

FlowProbe is unreleased at this decision point. Current internal formats may be
replaced directly, and this ADR adds no compatibility shim or migration path.
Future production upgrade/migration behavior requires a separate authorized
architecture task.
