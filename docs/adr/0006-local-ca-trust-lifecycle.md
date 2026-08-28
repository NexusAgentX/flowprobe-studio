# ADR-0006: Local CA trust lifecycle

Status: Accepted

Task: ARCH-003

## Decision scope

FlowProbe will manage a local interception certificate authority as persistent,
consented product state through a generation-fenced transaction independent of
temporary network sessions. A separate CA key authority owns the protected
private key. The generic privileged helper owns the authenticated trust journal
and machine/admin trust mutations but never receives the key. Current-user
trust is performed only by a live authenticated user-context agent under a
one-use helper gate.

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
| Consent broker | Authenticates one explicit generate/install/repair/remove/destroy/rotate action and signs the exact CA, target set, scope, fallback policy, privilege outcome, and expiry |
| CA trust coordinator | One unprivileged Supervisor-owned orchestrator sequences a persistent trust transaction; it is not a journal writer or key holder |
| CA key authority | Generates and persists the protected key, builds the exact public CA certificate, proves key possession, signs bounded leaves after admission, and destroys the key |
| Privileged helper | Sole writer for the authenticated trust journal/state index and executor of registered machine/admin public-certificate mutations |
| Authenticated user trust agent | Executes one exact current-user mutation in the named login identity through a live one-use helper gate |
| Platform trust verifier | Independently normalizes exact store/domain, certificate, trust precedence, derived outputs, and effective TLS evidence |
| Capture Core signer client | Requests one bounded leaf for an exact admitted connection without receiving the CA key |
| ARCH-002 trust-material broker | Reads the authenticated complete interception-CA SPKI set; unavailable is never encoded as empty |

The helper and key authority keep separate protected ledgers. The key authority
also has a distinct installation-bound attestation key for key-ledger and
identity-set receipts; it never uses that key for CA or leaf signatures.
Cross-store atomicity is not assumed. Neither ledger's state tag, provider lookup, service
liveness, or cached boolean authorizes the other. Every leaf requires fresh
helper-signed trust evidence and key-authority-signed possession evidence bound
to one challenge, state revision, gate epoch, CA identity, Capture Core
instance, and request.

## Persistent identity and state

The trust class is trust.ca.v1 and has nonwrapping CaGeneration,
TrustStateRevision, TrustFenceToken, KeyStateRevision, KeyAuthorityEpoch,
authenticated KeyJournalHeadDigest, and InterceptionGateEpoch domains
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
    Generated
    InstallPending
    InstalledAndVerified
    RemovePending
    Drifted
    RecoveryRequired

Pending states retain every target/key step, before image, intended
postcondition, durable phase, observed result, and compensation. Multi-target
partial success is never collapsed into installed or removed. Drifted and
RecoveryRequired close the signing gate. InstalledAndVerified is authorizing
only through the fresh admission protocol, not by its stored tag.

## CA key and certificate decision

The CA key is generated inside a separate platform key authority and becomes
non-exportable or equivalently protected after creation. The authority exposes
only typed self-sign, fresh possession, bounded leaf-sign, and destroy
operations. It exposes no raw private bytes, generic arbitrary-message signing,
provider handle, PIN, wrapping secret, or renderer/helper interface.

The key is bound to installation, generation, CaInstanceId, algorithm, and
certificate SPKI. Unavoidable transient private bytes use locked no-dump memory
and are zeroized on every path. Ordinary status, logs, diagnostics, crash dumps,
analyzer input, capture data, and the helper journal never contain key material.

LocalInterceptionCaCertificateV1 is one self-signed X.509 v3 ECDSA P-256 CA,
uses SHA-256, has critical CA=true/pathLen=0 and keyCertSign-only usage, matching
subject/authority key identifiers, no EKU extension, a random non-reused
serial, no unknown critical extension, and at most a 365-day validity. Leaves
are CA=false, serverAuth/digitalSignature only, exact normalized SANs, fresh
leaf keys, and at most seven days or the remaining CA/admission deadline.

No concrete protected key provider is selected here. All provider rows remain
unsupported until non-exportability, peer binding, crash recovery, key
destruction, zeroization, exact release identity, and real-host evidence pass.

## Consent and transaction decision

Read-only preview enumerates exact targets, current state, permissions,
interaction, exclusions, support truth, and connectivity policy. It allocates
no key, generation, plan, permission, or mutation authority.

Generate, Install, Repair, RemoveTrust, RemoveAndDestroy, and Rotate each need a
new bounded one-use consent receipt signed outside the renderer. It binds the
exact operation, current/candidate CA, ordered target set, required bitmap,
user/admin scope, fallback policy, requested native authorization/interaction
requirement and any completed preauthorization result, helper nonce, and
expiry. A platform prompt that occurs inside the later mutation is recorded as
that journaled step's result, not predicted by the consent receipt. Current-user
and machine targets never fall back to each other.

Before every key or trust side effect, the owning ledger fsyncs exact intent,
identity, before image, plan, fence/revision, consent, deadline, expected
platform conditional token or explicit absence, postcondition, and
compensation. The executor performs one registered operation, independently
reads the exact result, and fsyncs Applied, Compensated, Observed, or Ambiguous
before returning success.

Idempotent retry requires the byte-identical operation. A changed request under
the same identity is rejected. An operation return code, process exit, mtime,
notification, chain result, or response without a durable result is not
transaction proof.

## Exact install, removal, and ownership

TrustTargetV1 is a closed platform-tagged union. Every row binds the full
certificate identity, exact store/domain/path/database scope, installer
executor, installer owner, pre-existing classification, before image, backend
release tuple, intended postcondition, per-target step, and independent
verification.

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
them. Journal loss or corruption never permits appearance-based cleanup.

Key destruction occurs only after every known owned target is proven absent,
all external pre-existing state is preserved, no signer/connection can use the
key, and the complete identity set is known. Ambiguous destruction remains
RecoveryRequired; Absent cannot be published while a key may survive.

## Rotation and identity-set decision

Rotation is one explicit compound transaction with at most one active and one
candidate/retiring CA. Both SPKI identities remain in the ARCH-002 exclusion
set from new-key generation through verified removal and old-key destruction.
Every owned item locator is generation-scoped and active/candidate platform
items are disjoint; an in-place path, nickname, item, or trust replacement is
forbidden. The new signer is selected only after all new target and key proofs
pass. A failure after signer switch never silently reverts, drops the old
identity, or reports completed rotation.

The authoritative ARCH-002 identity-set read is a linearizable dual-signed
helper/key-authority proof. It contains every generated, candidate, current,
retiring, residual, drifted, externally removed, partially installed, or
key-destroy-pending known FlowProbe CA SPKI. Only a fully reconciled Absent
state may return an authoritative empty set. An incomplete/corrupt ledger or
unresolved identity returns IdentitySetUnavailable; ARCH-002 maps that to
DependencyContractUnavailable and never assumes empty.

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
choice.

The only accepted semantic is SSL policy plus TrustRoot with no application,
hostname, allowed-error, or key-usage constraint. Removal uses the exact
certificate/domain RemoveTrustSettings operation and verifies trust absence
before deleting only a proven FlowProbe-owned Keychain item; null Set is never
removal. Public Security.framework has no stable
revision, expected-state CAS, or transaction spanning Keychain and Trust
Settings. Apple implementation evidence shows whole-domain and multi-store
writes can be partial. User/Admin remain unsupported pending conditional
mutation, crash durability, and real-host proof; System is immutable.

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
safe conditional source/database lifecycle, bounded regenerator recovery,
complete release tuples, and real-host proof.

Each derived output reaches its own VerifiedDerivedExact state bound to the
current authority and regenerator result without acquiring ownership. Exact
uninstall proves the FlowProbe authority source absent; an identical preserved
external source may legitimately keep derived bytes and TLS trust present, and
is reported rather than deleted.

Browser and application coverage is always separate consumer evidence. OS
trust does not imply browser-private store, profile policy, enterprise-roots
setting, pinning, embedded TLS stack, or already-running consumer coverage.

## Helper protocol consequence

A new explicit ARCH-001 task must add versioned deterministic schemas for the
trust transaction, per-target operations, user/key online gates, recovery,
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
- Extend the accepted helper protocol implicitly inside this task: its wire
  union is closed and changing it requires a separately scoped architecture
  task.

## Consequences

Positive consequences:

- private-key material stays outside renderer and generic privileged mutation
  authority;
- persistent trust has explicit consent, ownership, exact identity, durable
  partial state, crash recovery, drift closure, and bounded uninstall;
- administrator and pre-existing trust state is preserved rather than restored
  from stale baselines;
- interception readiness is cryptographically cross-bound to effective trust
  and the actual signing key for each new connection;
- ARCH-002 receives one authoritative conservative identity set through
  rotation and recovery; and
- product capability truth cannot outrun platform, release, or browser proof.

Costs and constraints:

- a new helper protocol version, separate key authority, user-context agent,
  platform backends, deterministic conformance suites, and disposable real-host
  labs are required before any support claim;
- shared platform trust stores without conditional mutation may remain
  unsupported unless an exclusive-owned architecture can be proven;
- multi-target state, rotations, and partial outputs stay visible until exact
  reconciliation, increasing implementation and evidence complexity; and
- browser/app compatibility is tested and reported separately rather than
  inferred from OS trust.

## Verification obligations

Implementation tasks must provide byte-exact state/receipt/proof golden vectors,
malformed/fuzz coverage, exhaustive transitions, consent and replay negatives,
crash injection around every durable/key/platform boundary, exact-identity and
concurrent-admin races, partial multi-target recovery, key match/destruction,
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
