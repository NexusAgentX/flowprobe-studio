# Contract: Local CA Trust Lifecycle v0.2

Status: Normative for v0.2

Task: ARCH-003

This contract defines the persistent local certificate-authority and operating-
system trust lifecycle used by FlowProbe TLS interception. It is independent
from a temporary network session. It defines architecture and verification
obligations; it does not claim that a current release implements or supports a
platform target.

The key words MUST, MUST NOT, SHOULD, and MAY are normative.

## Scope and preserved boundaries

This contract owns:

- local interception-CA generation, protected key ownership, rotation, and
  destruction;
- explicit user consent for persistent key creation and trust mutation;
- exact, per-target trust installation, verification, removal, drift, and
  recovery;
- the readiness proof consumed before TLS interception may sign a leaf;
- the authoritative FlowProbe interception-CA identity set consumed by
  ARCH-002; and
- deterministic and real-host evidence required for a support claim.

The following accepted boundaries remain unchanged:

- sing-box remains an independent managed Network Runtime;
- Capture Core owns protocol-oriented TLS interception and does not gain
  sing-box internals;
- the renderer has neither helper transport nor private-key access;
- the ARCH-001 helper remains a typed mutation and journal authority, not a
  generic shell, key vault, TLS endpoint, or signing service;
- the CA private key MUST NOT enter the generic privileged helper, its journal,
  the renderer, ordinary diagnostics, user profiles, analyzer data, or captured
  traffic;
- external HTTPS proxy trust remains independent from this local interception
  CA and MUST exclude every identity returned by this contract; and
- network-session stop, rollback, lease loss, boot recovery, or application exit
  MUST NOT imply removal of persistent CA trust.

The current v0.1 in-memory CertificateAuthority proves only ephemeral leaf
issuance. It provides no protected persistent key, consent, system-store
ownership, crash recovery, exact uninstall, or platform support evidence and
MUST NOT be imported or promoted as v0.2 trust state.

## Threat model and non-authorities

This lifecycle assumes renderer input, captured traffic, profile data,
certificate subjects, labels, filenames, nicknames, store contents, and
ordinary platform messages may be hostile or stale.

It MUST resist:

- a renderer or unrelated local process asking the helper to install arbitrary
  certificates or operate on arbitrary stores or paths;
- private-key extraction through helper payloads, status, logs, dumps, swap,
  inheritance, diagnostics, or renderer IPC;
- replay or substitution of consent, certificate, target, generation, store,
  key, signer, or verification evidence;
- helper, key authority, Supervisor, user trust agent, Capture Core, UI, and
  machine crashes at every durable or platform boundary;
- duplicate request delivery and response loss;
- partial success across certificate storage, trust settings, derived bundles,
  consumers, or multiple targets;
- external deletion, replacement, duplicate insertion, trust-setting changes,
  target-scope changes, and package or policy drift;
- subject, issuer/serial, label, nickname, filename, hash-link, or SPKI-only
  deletion that could affect a foreign certificate; and
- read-compare-write or read-compare-delete races that overwrite an
  administrator or another application.

Administrator/root replacement of the FlowProbe package or rollback of the
entire protected machine snapshot remains outside the helper integrity threat
model inherited from ARCH-001. Ordinary administrator changes are nevertheless
external drift: FlowProbe MUST preserve them rather than silently reinstall,
overwrite, or delete them.

## Actors and authority

| Actor | Authority | Explicitly lacks authority |
| --- | --- | --- |
| Renderer | Request a bounded preview and express typed product intent through desktop IPC | Helper/key channels, raw DER mutation, private keys, arbitrary store/path, consent signing |
| Consent broker | Authenticate the product user action and produce one bounded operation/CA/target-set consent receipt | Trust mutation, key generation, leaf signing, policy expansion |
| CA trust coordinator | Supervisor-owned single unprivileged orchestrator for one persistent CA transaction | Direct privileged mutation, raw private key, arbitrary platform command |
| CA key authority | Generate and retain the non-exportable or protected CA key, create the exact public certificate, prove key possession, and sign bounded leaf certificates | Trust-store mutation, network policy, renderer access |
| Capture Core interception signer client | Request a bounded leaf from the exact admitted CA generation | Raw CA key, trust mutation, admission policy |
| Privileged helper | Journal and execute compile-time registered machine/admin trust operations over public certificate material only | CA private key, leaf signing, arbitrary shell/path/store, product consent |
| Authenticated user trust agent | Execute a sealed current-user trust operation in the exact logged-in user context through an online helper gate | Machine/admin targets, private key, arbitrary profile discovery or path |
| Platform trust verifier | Independently enumerate and normalize exact target/effective TLS trust evidence | Mutation, consent, optimistic boolean |
| ARCH-002 trust-material broker | Query the authenticated interception-CA identity set for upstream-proxy filtering | Installing/removing local CA, reading key material, treating unavailable as empty |

One CA trust coordinator owns a transaction generation. The installation's
ARCH-001 helper authority remains the single writer for the protected trust
journal and state index. User-context execution is an externally gated step,
not a second journal writer. The key authority maintains a separate protected
key ledger because the helper MUST NOT receive the key. No single stored
boolean from either ledger authorizes interception.

## Identifiers, counters, and domains

The persistent class is named trust.ca.v1. It MUST use counters and fences
separate from core.session:

- InstallationId: the existing installation identity;
- CaGeneration: a nonzero, monotonically increasing, nonwrapping durable
  counter scoped to trust.ca.v1 and never reused;
- CaInstanceId: a helper-coordinated random 256-bit identity for one CA
  certificate/key pair;
- TrustOperationId: a random 256-bit identity for one generate, install, repair,
  remove, destroy, or rotate operation;
- TrustPlanId and TrustPlanDigest: the immutable target/resource graph;
- TrustFenceToken: a monotonically ordered trust-class fence;
- TrustStateRevision: a nonwrapping durable revision;
- TrustJournalHeadDigest: the authenticated current journal tip;
- KeyAuthorityEpoch and KeyStateRevision: nonwrapping key-ledger counters;
- KeyJournalHeadDigest: the authenticated current protected key-ledger tip;
- InterceptionGateEpoch: a nonwrapping local signer admission epoch;
- ConsentReceiptId: a random 256-bit one-operation receipt identity; and
- TargetId: the digest of one exact normalized trust target.

A core.session Generation, ActivationLeaseId, LeaseEpoch, FenceToken,
PreparedPlanId, or recovery authority MUST NOT be accepted in any of those
positions. Network and trust classes share only helper authentication, the
global mutation lock, journal integrity primitives, and declared conflict-set
serialization.

All digests are SHA-256 over canonical deterministic encodings and a
NUL-terminated domain string. At minimum the schema registers these domains:

| Value | Domain |
| --- | --- |
| TrustPlanDigest | FlowProbe.TrustCa.Plan.v1 |
| TargetId | FlowProbe.TrustCa.Target.v1 |
| certificate public identity | FlowProbe.TrustCa.CertificateIdentity.v1 |
| target before/after observation | FlowProbe.TrustCa.TargetObservation.v1 |
| key creation receipt | FlowProbe.TrustCa.KeyCreatedReceipt.v1 |
| key possession proof | FlowProbe.TrustCa.KeyPossession.v1 |
| consent receipt | FlowProbe.TrustCa.ConsentReceipt.v1 |
| installed-state receipt | FlowProbe.TrustCa.InstalledReceipt.v1 |
| interception admission proof | FlowProbe.TrustCa.InterceptionAdmission.v1 |
| identity-set query response | FlowProbe.TrustCa.IdentitySetProof.v1 |

Unknown variants, fields, domains, versions, algorithms, target kinds, trust
semantics, or operation kinds fail closed.

## Certificate and key profile

LocalInterceptionCaCertificateV1 is one immutable DER certificate with:

- X.509 v3, self-issued and self-signed;
- ECDSA P-256 SubjectPublicKeyInfo and ECDSA-with-SHA-256 self-signature;
- a random nonzero 20-octet serial whose high bit is clear and which is not
  reused by the installation;
- a normalized display subject identifying FlowProbe Studio and a bounded
  non-authorizing CaInstanceId suffix;
- critical BasicConstraints CA=true with pathLenConstraint=0;
- critical KeyUsage containing keyCertSign and no leaf/server key usage;
- no ExtendedKeyUsage certificate extension;
- matching SubjectKeyIdentifier and AuthorityKeyIdentifier;
- notBefore between the recorded generation wall clock minus five minutes and
  that generation wall clock;
- notAfter later than notBefore and no later than 365 days after the recorded
  generation wall clock; and
- no unknown critical extension.

The subject, serial, label, friendly name, nickname, filename, and key
identifier are locators or operator display only. The authoritative certificate
identity is the complete canonical DER plus:

    CertificateDerSha256 = SHA-256(exact DER)
    CertificateSpkiSha256 = SHA-256(canonical SubjectPublicKeyInfo DER)

Both digests, the complete DER length, algorithm profile, validity, serial, and
CaInstanceId are carried by CaPublicIdentityV1. SPKI alone is not certificate
identity because multiple certificates can use the same public key.

The CA key is generated inside the CA key authority. A supported provider MUST:

- prevent raw private-key export after generation;
- bind the key to InstallationId, CaGeneration, CaInstanceId, algorithm, and
  certificate SPKI;
- persist it under a fixed package-owned identity inaccessible to the renderer,
  helper, ordinary user processes, and analyzers;
- exclude key pages/handles from inheritance, diagnostics, core/crash dumps, and
  swap where the platform permits;
- hold unavoidable transient private bytes only in locked no-dump memory and
  zeroize every copy on all success and error paths;
- offer only self-sign, key-possession, bounded leaf-sign, and destroy
  operations through its authenticated typed channel; and
- expose no generic sign-arbitrary-bytes or provider-handle API.

The key authority also owns a distinct installation-bound attestation identity
whose public key is pinned by the signed installation manifest and helper
handshake. That attestation key signs key-ledger receipts and identity-set
proofs, including absence after a CA key is destroyed; it MUST NOT sign a CA
certificate or leaf. A CA key itself signs KeyPossessionProofV1. The two
purposes, keys, domains, and verifiers are not interchangeable.

KeyPossessionProofV1 signs:

    domain
    InstallationId
    CaGeneration
    CaInstanceId
    CertificateDerSha256
    CertificateSpkiSha256
    KeyAuthorityEpoch
    KeyStateRevision
    KeyJournalHeadDigest
    InterceptionGateEpoch
    caller challenge
    purpose
    observed_at
    expires_at

The verifier checks the signature with the certificate public key and requires
the public key used by the key authority to equal the certificate SPKI. A
provider lookup success, key label, handle, or public-key digest without the
fresh signature is insufficient.

Leaf signing is allowed only after a valid InterceptionAdmissionProofV1. A leaf
is CA=false, contains only the exact normalized target SANs allowed by Capture
Core, carries serverAuth and digitalSignature, has a freshly generated leaf key,
and expires no later than seven days or the CA/admission deadline, whichever is
earlier. This contract does not broaden Capture Core protocol semantics.

## Normative lifecycle state

The top-level state is this closed union:

| State | Meaning |
| --- | --- |
| Absent | No FlowProbe-owned CA key remains and every known owned trust target is verified absent; only a non-authorizing terminal receipt and generation high-water may remain |
| Generated | One current CA key/certificate pair is durably verified, no trust mutation is pending, and no required target is currently claimed installed |
| InstallPending | A consented immutable install, repair, or new-CA rotation plan exists and one or more per-target or key steps are not terminal |
| InstalledAndVerified | One active CA pair has fresh key-match proof and every required target has a fresh exact effective-trust verification under the same committed receipt |
| RemovePending | A consented remove, destroy, or old-CA rotation cleanup plan exists and one or more exact target/key steps are not terminal |
| Drifted | A previously generated/installed fact changed externally but all observed identities remain bounded and no ambiguous mutation is outstanding; the signing gate is closed |
| RecoveryRequired | Journal/key/store integrity, ownership, mutation outcome, identity-set completeness, or safe compensation cannot be proved; the signing gate is closed |

The durable payloads are:

    Absent {
      CaGenerationHighWater,
      LastTerminalReceipt
    }

    Generated {
      CurrentCaPublicIdentity,
      KeyCreatedReceiptDigest,
      KnownIdentitySet,
      LastTargetDispositionVector
    }

    InstallPending {
      TrustOperationId,
      OperationKind = InitialInstall | Repair | RotateInstall,
      BaseStableStateDigest,
      CandidateCaPublicIdentity,
      OptionalRetainedActiveCaPublicIdentity,
      ConsentReceiptDigest,
      TrustPlanId,
      TrustPlanDigest,
      TrustFenceToken,
      PerTargetStepVector,
      KeyStepVector,
      FailureDisposition
    }

    InstalledAndVerified {
      ActiveCaPublicIdentity,
      RequiredTargetSetDigest,
      PerTargetInstalledVerificationVector,
      InstalledReceiptDigest,
      TrustJournalHeadDigest,
      TrustStateRevision,
      KeyAuthorityEpoch,
      KeyStateRevision,
      KeyJournalHeadDigest,
      InterceptionGateEpoch
    }

    RemovePending {
      TrustOperationId,
      OperationKind = RemoveTrust | RemoveAndDestroy | RotateRetireOld,
      ActiveAndRetiringCaPublicIdentities,
      ConsentReceiptDigest,
      TrustPlanId,
      TrustPlanDigest,
      TrustFenceToken,
      PerTargetStepVector,
      KeyStepVector,
      FailureDisposition
    }

    Drifted {
      LastStableStateDigest,
      KnownCaPublicIdentities,
      DriftFindingVector,
      TrustJournalHeadDigest,
      TrustStateRevision,
      GateClosedReceiptDigest
    }

    RecoveryRequired {
      LastAuthenticatedTrustTip,
      LastAuthenticatedKeyTip,
      KnownCaPublicIdentities,
      UnresolvedTargetVector,
      BoundedReasonVector,
      GateClosedReceiptDigest
    }

InstallPending and RemovePending are non-authorizing even when every visible
step appears successful. InstalledAndVerified is authorizing only through a
fresh admission proof; the state tag alone is not.

The stable transitions are:

    Absent -> Generated
    Generated -> InstallPending -> InstalledAndVerified
    Generated -> RemovePending -> Absent
    InstalledAndVerified -> InstallPending(RotateInstall)
      -> RemovePending(RotateRetireOld)
      -> InstalledAndVerified
    InstalledAndVerified -> RemovePending(RemoveTrust) -> Generated
    InstalledAndVerified -> RemovePending(RemoveAndDestroy) -> Absent
    Generated | InstalledAndVerified -> InstallPending(Repair)
      -> InstalledAndVerified
    any non-Absent state -> Drifted | RecoveryRequired
    Drifted -> InstallPending(Repair) | RemovePending
    any pending state -> same pending recovery -> stable state | RecoveryRequired

RecoveryRequired accepts no new generate, install, repair, rotate, or ordinary
remove plan. It may leave that state only when the existing authenticated
journal/key ancestry yields one unique exact pending operation whose authorized
recovery or compensation completes and freshly proves a stable state. If that
proof cannot be obtained, automated mutation remains disabled and bounded
manual remediation is reported; a new consent cannot override an integrity or
ownership ambiguity.

A failed operation may return to its exact base stable state only after every
new owned mutation is safely compensated, all per-target results are durable,
the key ledger agrees, and the base state is freshly reverified. No operation
may skip from a pending state to a stable state by trusting an exit code or
cached boolean.

## Trust target schema

TrustTargetV1 is a closed platform-tagged union. Every variant is wrapped in:

    TrustTargetRecordV1 {
      TargetId,
      Required,
      CaGeneration,
      CaInstanceId,
      CertificateDerSha256,
      CertificateSpkiSha256,
      TargetKind,
      ExactStoreOrDomainScope,
      InstallerExecutor,
      InstallerOwner,
      BeforeImage,
      IntendedPostcondition,
      CurrentStep,
      CurrentVerification,
      BackendReleaseTupleDigest,
      BoundedDeadline
    }

InstallerExecutor is PrivilegedHelper, AuthenticatedUserTrustAgent,
DerivedBy(AuthorityTargetId), or ObservationOnly. InstallerOwner is:

    FlowProbeOwned {
      InstallationId,
      CaGeneration,
      CaInstanceId,
      TargetId,
      CreateReceiptDigest
    }
  | ExternalPreExisting {
      ExactBeforeObservationDigest
    }
  | None

ExternalPreExisting is never converted to FlowProbeOwned merely because the
DER, subject, key, or trust semantics match.

TargetBeforeImageV1 records all of:

- exact certificate DER match count and item identities;
- same-SPKI/different-DER and same-issuer/serial/different-DER collisions;
- exact normalized trust semantics and effective precedence;
- owner marker/receipt state;
- exact store/domain/backend/release tuple;
- stable platform item identity or explicit absence of one;
- platform generation/revision token when documented, otherwise
  NoConditionalRevision;
- current source/path/item metadata required by the variant; and
- a normalized target observation digest.

PreExistingState is:

    Absent
  | ExactOwnedPresent
  | ExactUnownedPresent
  | ConflictingIdentityPresent
  | ScopeOrTrustConflict
  | Ambiguous

PerTargetStep is:

    NotAttempted
  | IntentDurable
  | MutationIssued
  | MutationAmbiguous
  | AppliedObserved
  | VerifiedOwned
  | VerifiedPreExistingExact
  | VerifiedDerivedExact
  | ObservedOnly
  | CompensationIntentDurable
  | CompensatedObserved
  | VerifiedAbsent
  | PreservedExternal
  | Drifted
  | Failed

VerifiedDerivedExact is valid only when InstallerExecutor is
DerivedBy(AuthorityTargetId). It binds the current terminal proof for that exact
authority target, the fixed regenerator/result receipt after the authority
revision, the normalized derived item/content digest and release tuple, and the
required consumer verification. The authority proof is VerifiedOwned or
VerifiedPreExistingExact; the derived row never acquires InstallerOwner or
deletion authority of its own.

ObservedOnly is valid only when InstallerExecutor is ObservationOnly,
Required is false, and the row appears in preview/capability/baseline evidence
rather than an install, removal, required-target, or admission set. It grants no
mutation, ownership, trust, or interception authority.

Every target retains its own step, before image, observed result, retryability,
and bounded reason. Multi-target or multi-output state MUST NOT collapse into
one installed, removed, changed, or command-success boolean.

The target variants are:

    WindowsPhysicalRootV1 =
      CurrentUserRoot {
        UserSidDigest,
        Provider = PhysicalSystemStore,
        SystemStore = Root,
        PhysicalStore = DotDefault,
        ChainEngineScope = HCCE_CURRENT_USER,
        InstallerExecutor = AuthenticatedUserTrustAgent,
        TrustSemantic = WindowsTlsServerRootV1
      }
    | LocalMachineRoot {
        Provider = PhysicalSystemStore,
        SystemStore = Root,
        PhysicalStore = DotDefault,
        ChainEngineScope = HCCE_LOCAL_MACHINE,
        InstallerExecutor = PrivilegedHelper,
        TrustSemantic = WindowsTlsServerRootV1
      }

    MacOsTrustSettingsV1 =
      User {
        ConsoleUserIdentityDigest,
        TrustDomain = User,
        CertificateStore =
          UserDefaultFileKeychain(ResolvedKeychainIdentity),
        InstallerExecutor = AuthenticatedUserTrustAgent,
        TrustSemantic = AppleSslTrustRootV1,
        CertificatePersistentReferenceSchema
      }
    | AdminSystemWide {
        TrustDomain = Admin,
        CertificateStore = SystemKeychain,
        InstallerExecutor = PrivilegedHelper,
        TrustSemantic = AppleSslTrustRootV1,
        CertificatePersistentReferenceSchema
      }
    | SystemObservationOnly {
        TrustDomain = System,
        InstallerExecutor = ObservationOnly
      }

    DebianUbuntuSharedTrustV1 {
      DistributionId,
      VersionId,
      Architecture,
      TrustSemantic = DebianUbuntuImplicitGeneralPurposeAnchorV1,
      GenerationScopedOwnedSourceIdentity,
      IndividualCertificateDirectoryIdentity,
      AggregateBundleIdentity,
      FixedRegeneratorIdentity,
      FixedHookInventoryDigest
    }

    FedoraRhelSharedTrustV1 {
      DistributionId,
      VersionId,
      Architecture,
      TrustSemantic = P11KitTlsServerAnchorV1,
      GenerationScopedOwnedSourceIdentity,
      P11KitTrustModuleIdentity,
      EffectiveAnchorTokenIdentity,
      ExtractedOutputIdentityVector,
      FixedRegeneratorIdentity
    }

    DerivedSystemBundleV1 {
      AuthorityTargetId,
      ExactOutputIdentity,
      AuthorityTrustSemantic,
      EffectiveConsumerTrustSemantic,
      ConsumerClass
    }

    NssSqlDatabaseV1 {
      ExplicitDatabaseIdentity,
      DatabaseOwnerIdentity,
      ExecutionContext =
        CurrentUser(DatabaseOwnerIdentity, AuthenticatedUserTrustAgent)
      | SystemService(DatabaseOwnerIdentity, PrivilegedHelper),
      ConsumerIdentity,
      NssReleaseTuple =
        (OperatingSystem, Architecture, NssLibrary, Certutil, DatabaseSchema,
         ConsumerBuild),
      GenerationScopedExactNickname,
      TrustSemantic = NssTlsServerCaV1,
      ExactTrustFlags = "C,,",
      DatabaseFormat = Sql
    }

A generic Windows Root, default macOS keychain, generic Linux, generic system
bundle, browser profile search, HOME-relative NSS database, legacy NSS dbm
database, arbitrary path, arbitrary executable, arbitrary trust dictionary, or
caller-selected command/environment is not a valid target.

Every owned platform item locator is a deterministic bounded function of
InstallationId, CaGeneration, and CaInstanceId and is included in TargetId,
the plan, before/after images, and the ownership receipt. Locators and platform
item identities for an active and candidate/retiring generation MUST be
disjoint. Rotation never renames, replaces, or rewrites an old-generation item
in place to represent a new generation.

## Durable plan, journal, and state indexes

The helper owns the authenticated trust journal and a two-slot copy-on-write
trust state index selected by one checksummed atomic selector. The index binds:

- InstallationEpoch and trust-class generation high-water;
- current lifecycle tag and complete state digest;
- TrustFenceToken, TrustStateRevision, and TrustJournalHeadDigest;
- current and known residual CaPublicIdentityV1 values;
- current TrustPlanId/TrustPlanDigest when pending;
- required target-set digest and per-target terminal roots;
- current interception gate epoch and closed/open disposition;
- current identity-set digest; and
- the latest non-authorizing stable-state receipt.

Recovery accepts one complete valid old index or one complete valid new index.
It never combines slots, guesses a selector, rolls back a nonwrapping revision,
or treats an unselected staged slot as authoritative. A torn/ambiguous selector,
unknown state tag, missing journal ancestor, mismatched key receipt, or
incomplete identity set is RecoveryRequired.

The CA key authority separately owns a protected copy-on-write key index:

    CaKeyRecordV1 {
      InstallationId,
      CaGeneration,
      CaInstanceId,
      CertificateDerSha256,
      CertificateSpkiSha256,
      ProviderAndVersion,
      NonExportableKeyIdentity,
      KeyAuthorityEpoch,
      KeyStateRevision,
      KeyState = Creating | Ready | DestroyPending | Destroyed | Ambiguous,
      LastHelperTrustTipBoundByReceipt,
      RecordDigest
    }

NonExportableKeyIdentity is private to the key authority and MUST NOT appear in
helper, Supervisor, renderer, Capture Core, egress, status, or diagnostic
messages. Cross-store atomicity is not assumed. Every stable state and every
interception admission therefore requires a helper-signed public trust proof
and a key-authority-signed possession proof that bind the same CA identity,
challenge, lifecycle revision, and gate epoch.

Journal-before-mutation is mandatory for key and trust operations. Before each
external side effect the owning ledger fsyncs:

- exact operation, generation, CA, target, plan, fence, revision, and
  idempotency identities;
- consent receipt and authorization scope;
- normalized current before image;
- exact immutable public certificate identity and bounded public DER;
- intended postcondition, mutation direction, deadline, and compensation;
- the expected platform conditional token or explicit
  NoConditionalRevision; and
- IntentDurable.

The executor performs one registered typed operation, independently reads back
the exact target, then fsyncs the normalized result and AppliedDurable,
CompensatedDurable, ObservedDurable, or AmbiguousDurable before returning
success. A return code, process exit, helper response without the durable
result, derived-bundle mtime, notification, or consumer process restart is not
post-operation proof.

The complete public DER MAY be sealed in a trust plan and delivered to the
exact target executor because it is not secret. It is still bounded, validated
as the exact CaPublicIdentityV1, excluded from ordinary logs/status, and never
caller-selected independently of the plan. Private DER, a key handle, wrapping
key, password, PIN, provider secret, or raw signing operation MUST NOT enter the
plan or helper.

Installed target ownership records and their exact before/after images are
retained until the target is safely removed or reclassified as preserved
external state. A Generated record is retained until its key is destroyed. An
Absent generation journal may be compacted only after:

- every known FlowProbe-owned target is verified absent;
- every external pre-existing target is verified preserved;
- every key for the generation is Destroyed;
- the identity-set query proves the correct remaining known set;
- no pending/ambiguous platform or key operation remains; and
- the terminal receipt and generation high-water are durably published.

Time-based expiry alone never deletes a trust journal or ownership record.

## Consent and authorization

PreviewTrustOperationV1 is read-only and non-authorizing. It enumerates exact
targets, scopes, permission/interaction requirements, current pre-existing
state, excluded consumers, support dimensions, and the connectivity policy.
It allocates no generation, key, plan, permission, or mutation authority.

Generate, Install, Repair, RemoveTrust, RemoveAndDestroy, and Rotate each
require a new CaConsentReceiptV1. The consent broker signs:

    ReceiptVersion
    ConsentReceiptId
    InstallationId
    authenticated user/administrator policy identity
    exact operation kind
    existing and candidate CaPublicIdentity digests when applicable
    exact ordered target-set digest
    required/optional target bitmap
    requested interception fallback policy
    requested privilege/interaction requirement and any completed
      preauthorization outcome
    helper preparation nonce
    issued_at and expires_at
    one-use nonce

The receipt signs a receipt-free scope, is bound to one TrustOperationId during
plan sealing, and is consumed once with byte-identical idempotent replay. The
renderer cannot mint, copy to another target set, extend, or replay it.

Current-user and machine/admin targets are distinct choices. Permission failure
for one MUST NOT upgrade, downgrade, or fall back to the other. An OS
authorization prompt is additional platform evidence; it does not replace the
product consent receipt. Conversely, a product click does not prove native
authorization succeeded.

Recovery MAY finish observation, compensate a proven partial mutation, or
destroy a key already covered by the exact consumed RemoveAndDestroy/Rotate
receipt. It MUST NOT install, repair, re-add, broaden trust, select another
target, change user/machine scope, or rotate under implied startup consent.
External deletion never triggers automatic reinstall.

## Generation transaction

Generating a CA performs:

1. Verify lifecycle Absent and no unresolved known identity or target.
2. Obtain and consume an unexpired Generate consent receipt.
3. Under the trust mutation lock allocate the next CaGeneration,
   CaInstanceId, TrustOperationId, fence, and key-creation challenge; fsync
   GenerateIntentDurable before contacting the key authority.
4. Through a helper-gated authenticated key-authority operation, create the
   key in Creating state, build the exact certificate, persist the protected key
   record, and return the public DER plus KeyCreatedReceiptV1.
5. Independently parse the public DER, validate the complete v1 profile, recompute
   DER/SPKI digests, and verify a fresh key-possession signature.
6. Bind the helper and key ledger tips in both ledgers, fsync Generated, update
   the authoritative identity set, and only then return success.

A crash before key creation leaves no key. A crash after the key provider may
have created a key is reconciled by exact CaInstanceId and provider identity:
one matching Ready key completes the public receipt, a proven absent key records
unapplied, and any multiple/mismatched/unknown result is RecoveryRequired.
Recovery never guesses by label or creates a second key under the same
generation.

Generated does not mean installed, trusted, or interception-ready.

## Install and repair transaction

An install or repair plan freezes:

- one exact candidate CA public identity and fresh key-possession proof schema;
- one consent receipt and interception fallback policy;
- a sorted unique target vector and required/optional bitmap;
- each target's exact backend release tuple and installer executor;
- complete before-image and pre-existing-state schemas;
- the dependency graph for public-certificate storage, trust semantics, derived
  outputs, consumer verification, and compensation;
- per-step deadlines and crash reconciliation; and
- AllRequiredTargetsByCompensation as the v1 failure disposition.

The operation is:

1. Close the InterceptionGate for the CA generation, advance its epoch, refuse
   new leaf signing, and durably record the closed receipt.
2. Reverify the key/certificate match and every target before image under the
   trust mutation lock. Any Ambiguous target or unsupported conditional
   primitive fails before mutation.
3. Fsync the complete immutable plan and InstallPending state.
4. For each authority target in dependency order:
   - Absent may use only its registered exclusive add-if-absent operation;
   - ExactOwnedPresent is an idempotent replay only when the complete current
     item/owner/receipt matches;
   - ExactUnownedPresent receives no mutation and remains
     VerifiedPreExistingExact only if the exact effective trust semantics pass;
   - a conflict, duplicate ambiguity, different DER, different trust semantic,
     or target-scope mismatch is preserved and fails the required target; and
   - every mutation follows journal-before, one operation, exact read-back, and
     durable-result ordering.
5. Verify every derived output separately and persist VerifiedDerivedExact with
   its current authority/regenerator/result/consumer proof. A source-anchor
   success does not prove an aggregate bundle, hash directory, p11-kit token,
   Keychain trust setting, chain engine, browser, or already-running consumer.
6. Produce an actual TLS validation with a fresh bounded leaf issued by the
   candidate key, correct reference hostname, and the exact target/consumer
   scope. Wrong hostname, wrong key, wrong CA, or excluded consumer is a
   negative test, not optional evidence.
7. Under the lock, reread every required target, verify the current key proof,
   target-set digest, consent, fence, revision, journal head, and identity set,
   then fsync InstalledAndVerified and InstalledReceiptV1 in one selected state-
   index transition.
8. Keep the gate closed. It opens only for an individual connection after the
   fresh dual admission protocol defined below.

If any required target fails after another target changed, the helper
immediately runs safe reverse compensation for every newly FlowProbe-owned
addition. InstallPending remains visible with the complete partial vector until
compensation ends. It returns to the exact prior stable state only when every
new owned item/output is safely absent/restored, every pre-existing item is
preserved, and the base state is freshly proven. Otherwise the state is
RecoveryRequired or Drifted; it MUST NOT report installed or erase the partial
history.

An optional target failure remains explicit and prevents a claim that that
consumer/store is covered. It may coexist with InstalledAndVerified only when
the user requested it as optional, no required target depends on it, and the
installed receipt enumerates the omission. A product mode requiring that
consumer still refuses or passes through.

## Removal and key destruction

RemoveTrust and RemoveAndDestroy require a new exact consent receipt. Before the
first target mutation the coordinator:

- closes the InterceptionGate and advances its epoch;
- prevents new leaf issuance;
- stops or boundedly drains every outstanding leaf-sign request;
- records the exact set of already established interception connections and
  their bounded disposition; and
- fsyncs RemovePending with every target before image.

Removal is conditional and exact:

    ResidualEffectiveTrustDispositionV1 =
      Rejected {
        ConsumerObservationDigest,
        NegativeTlsResultDigest
      }
    | PreservedExternal {
        ExternalSourceOrScopeObservationDigest,
        ConsumerObservationDigest,
        SuccessfulTlsResultDigest
      }
    | Ambiguous {
        BoundedObservationDigest,
        BoundedReason
      }

Every disposition also binds InstallationId, CaGeneration, TargetId, exact
consumer/release identity, certificate identity, reference hostname,
post-removal authority observation digest, observed_at, and expires_at. The TLS
result uses a fresh otherwise-valid leaf so an unrelated hostname, expiry, or
key error cannot masquerade as removal evidence.

1. The target must equal the recorded store/domain, platform item identity,
   complete DER, DER SHA-256, normalized trust semantic, owner marker, and
   observed owned after image.
2. PreExistingState MUST prove FlowProbe ownership. ExactUnownedPresent and
   every preserved external target are never deleted.
3. The platform operation MUST consume an atomic expected revision/condition or
   target an exact exclusively owned item whose complete deletion domain and
   attachments are proven unchanged.
4. Subject, issuer, serial, label, friendly name, nickname, filename,
   OpenSSL subject hash, SPKI, or a previous query result alone is forbidden
   deletion authority.
5. A different DER, changed trust semantic, extra duplicate, replaced path/item,
   foreign attachment, or scope change is ExternalDrift. Preserve it and enter
   Drifted/RecoveryRequired.
6. A previously owned item already absent is recorded as ExternallyRemoved. It
   satisfies the removal postcondition only after the explicit remove plan
   verifies no other owned copy; the drift remains in the terminal audit
   receipt.
7. After each authority operation, independently verify that the exact owned
   authority item is absent. Re-run only the selected fixed regenerator and
   verify that each derived row no longer depends on the removed owned source.
   If an identical external anchor or another scope still provides the same DER,
   the derived bytes and effective TLS may legitimately remain; record
   ResidualEffectiveTrustDispositionV1.PreservedExternal and never chase or
   delete that source.
8. Require effective TLS rejection only when the exact consumer observation
   proves no preserved external trust path remains, recording Rejected.
   Otherwise record the external residual separately. An unattributable
   residual records Ambiguous and enters RecoveryRequired, not authority to
   broaden removal.

Shared aggregate bundles, logical store collections, whole trust-setting
domains, browser profiles, keychains, NSS databases, or baseline backups MUST
NOT be restored or deleted wholesale.

RemoveTrust reaches Generated after all FlowProbe-owned trust is absent and all
external pre-existing state is preserved, regardless of a separately reported
external residual trust path. RemoveAndDestroy then:

1. proves every known owned target is absent, the identity set is complete, no
   signer request/connection can use the key, and no rotation needs it;
2. fsyncs key DestroyPending and helper KeyDestroyIntentDurable;
3. invokes the exact key-authority destroy operation;
4. independently proves the key cannot sign the challenge and the provider
   identity is absent;
5. fsyncs Destroyed in the key ledger; and
6. fsyncs Absent plus the terminal receipt and correct identity-set update in
   the helper state index.

Failure or ambiguity destroying the key is RecoveryRequired. FlowProbe MUST NOT
report Absent while key material may remain or report Generated after deleting
a still-required key.

## Rotation

Rotation is one explicit consented compound operation with at most one active
and one candidate/retiring CA.

Before any RotateInstall mutation, the plan proves that every controlled item
locator for the candidate generation is generation-scoped and disjoint from
the active generation, and the before image proves no candidate locator aliases
an active item. After exclusive creation, read-back MUST prove the assigned
platform item identities are also disjoint before any signer-switch or stable
commit. A collision fails closed; it cannot authorize replacement or reuse.

1. Close the signing gate and include both known SPKI identities in the
   authoritative identity set.
2. Generate and verify the new key/certificate under a new CaGeneration.
3. Enter InstallPending(RotateInstall) and install/verify the new CA on the
   exact target set while preserving the old CA.
4. Commit an internal signer-switch receipt only after the new CA independently
   satisfies every InstalledAndVerified predicate and the old CA is freshly
   reverified.
5. Enter RemovePending(RotateRetireOld); remove only old FlowProbe-owned exact
   target items and then destroy the old key.
6. Commit InstalledAndVerified for the new CA and an identity set containing
   only identities still generated, installed, residual, drifted, or ambiguous.

No leaf is signed while either pending state is authoritative. A failure before
the signer switch safely compensates the new target/key and may return to the
freshly reverified old InstalledAndVerified state. A failure after the switch
keeps both identities known, the gate closed, and the operation pending or
RecoveryRequired until the old residual is settled. It never silently switches
back, drops an identity from ARCH-002 filtering, or calls partial rotation
complete.

## Crash and recovery

On key-authority, helper, user-agent, Supervisor, Capture Core, login, or machine
start, trust.ca.v1 reconciliation runs before trust readiness or identity-set
availability is reported. An unresolved trust transaction blocks a network
session only when the requested mode needs interception/identity filtering, a
declared resource conflict overlaps, or shared helper/journal integrity is
unsafe. It never automatically reactivates a previous network session.

For an intent without a durable result:

- exact intended state plus proven FlowProbe owner is observed durably, then
  the sealed operation either completes verification or compensates;
- exact before state and proven absence of an owned item is UnappliedDurable;
- a proven external pre-existing item is preserved;
- partial state, multiple candidates, missing owner proof, unknown conditional
  token, late operation, mismatched key/certificate, or ambiguous target is
  AmbiguousDurable and RecoveryRequired.

The trust fence and global mutation lock serialize owner loss and every OS/key
call. A stale controller, user-agent gate, consent, generation, plan, target,
revision, fence, or key epoch has no side effect. An OS operation that may
complete after process death without a durable platform operation identity that
recovery can settle is unsupported.

A user trust agent receives only a one-use online permit sealed by the helper.
It cannot act from an offline ticket. The helper holds the mutation lock from
authority reread through intent fsync, live user-context action, exact
read-back, durable result, and permit consumption. Helper/gate loss before
durable-result acknowledgement forces the agent to stop; any platform UI that
can continue and mutate after that loss is unsupported.

Unknown journal/key versions, corrupt/truncated records, missing ancestors,
state/key revision disagreement, selector ambiguity, or an incomplete known CA
set fail closed. The helper never reconstructs an old plan from renderer input,
deletes a certificate by appearance, resets the journal, or assumes an empty
identity set.

## Drift and continuous verification

InstalledAndVerified is not permanent truth. Startup, helper/key-authority
restart, every interception admission, every status transition, and a bounded
watch cadence reobserve:

- exact certificate presence/count and DER;
- normalized trust semantics and effective precedence;
- target store/domain/release tuple and owner evidence;
- derived outputs and selected effective consumer validation;
- CA key possession and certificate SPKI match;
- known current/candidate/retiring/residual identity-set completeness; and
- helper/key journal revisions and gate epoch.

Platform notifications and modification dates are wake-up hints only. They are
not durable order, a complete change log, ownership, freshness, or a conditional
mutation token. Missed events during downtime are covered by startup rescan.

DriftFindingV1 is a closed union including:

    CertificateMissing
    CertificateCollision
    CertificateReplaced
    CertificateOrPathMetadataChanged
    TrustMissing
    TrustModified
    ScopeChanged
    OwnerEvidenceChanged
    ExternalExactCopyObserved
    UserPolicyOverridesAdminTrust
    EffectiveTlsTrustRejected
    KeyUnavailable
    KeyCertificateMismatch
    BackendReleaseTupleChanged
    DerivedOutputPartial
    ConsumerReloadRequired
    BrowserPrivateStoreExcluded
    ObservationAmbiguous

When any finding invalidates the installed receipt, the local gate closes
before another leaf can be issued, the state becomes Drifted or
RecoveryRequired, and all future interception follows the connectivity policy.
FlowProbe never automatically re-adds a deleted anchor, rewrites changed trust,
removes a foreign replacement, or restarts a consumer and calls that proof.

## Interception admission and connectivity-first behavior

InterceptionPolicyV1 is:

    PassThroughOnly
  | PreferInterceptionWithTransparentPassThrough
  | RequireInterception

PassThroughOnly never queries a signing key. PreferInterception uses transparent
pass-through whenever a fresh proof cannot be obtained. RequireInterception
returns a typed refusal before presenting a FlowProbe-issued leaf; it MUST NOT
silently pass through and report interception.

For every new intercepted TLS connection, the coordinator obtains one fresh
helper challenge. The helper trust verifier and CA key authority independently
produce matching proofs over:

    InstallationId
    CaGeneration
    CaInstanceId
    CertificateDerSha256
    CertificateSpkiSha256
    InstalledReceiptDigest
    RequiredTargetSetDigest
    complete per-target verification-root vector
    TrustJournalHeadDigest
    TrustStateRevision
    KeyAuthorityEpoch
    KeyStateRevision
    KeyJournalHeadDigest
    InterceptionGateEpoch
    exact connection and Capture Core instance binding
    exact normalized leaf-sign request digest
    helper challenge
    observed_at
    expires_at

InterceptionAdmissionProofV1 is valid only when:

- the authoritative lifecycle state is InstalledAndVerified;
- both signatures and all cross-bound fields match;
- the gate epoch is current and open for this one request;
- the key-possession public key equals the installed certificate SPKI;
- every required authority target is freshly VerifiedOwned or
  VerifiedPreExistingExact and every required derived target is freshly
  VerifiedDerivedExact, all with effective TLS validation;
- no pending, drift, ambiguity, residual rotation, or identity-set error exists;
- the request and evidence are unexpired immediately before signing; and
- the proof is consumed once by the exact Capture Core instance and leaf
  request.

A cached state tag, helper Status summary, old chain success, previous leaf,
service liveness, renderer boolean, direct journal read, or copied database is
not admission proof. The key authority signs no leaf after gate/challenge loss.

Already established intercepted connections do not authorize new leaf signing.
On gate closure they may drain only under a sealed bounded connection lease that
cannot mint a new TLS connection or leaf; otherwise they are closed. Ordinary
network traffic remains available through transparent pass-through when the
chosen policy permits it. CA failure alone MUST NOT roll back or uninstall a
separate network session.

## ARCH-002 interception-CA identity-set interface

AuthenticatedInterceptionCaIdentitySetReadV1 is a versioned, linearizable,
read-only query. It returns:

    IdentitySetProofV1 {
      InstallationId,
      CaGenerationHighWater,
      TrustLifecycleStateTag,
      TrustJournalHeadDigest,
      TrustStateRevision,
      KeyAuthorityEpoch,
      KeyStateRevision,
      KeyJournalHeadDigest,
      InterceptionGateEpoch,
      SortedUniqueInterceptionCaSpkiSha256,
      FlowprobeCaExclusionSetDigest,
      observed_at,
      expires_at,
      HelperSignature,
      KeyAuthoritySignature
    }

HelperSignature uses the installation-bound helper attestation identity.
KeyAuthoritySignature uses the separate key-authority attestation identity, not
any current or historical CA key. The key authority signature attests the
protected key-ledger projection and can therefore prove a destroyed or absent
CA record without retaining its signing key. Both signatures bind the same
canonical complete response and helper challenge.

The digest is exactly the ARCH-002 formula:

    SHA-256(
      "FlowProbe.Egress.FlowProbeCaExclusionSet.v1\0" ||
      uint32_be(count) ||
      sorted_unique_interception_ca_spki_sha256...
    )

The sorted set contains every known FlowProbe CA identity that is:

- Generated, InstallPending, InstalledAndVerified, RemovePending, or Drifted;
- a current, candidate, retiring, partially installed, externally removed,
  residual, or key-destroy-pending identity; or
- named by an authenticated unresolved record whose target/key absence is not
  yet proven.

Absent may return the authoritative empty set only when the helper and key
ledgers are valid, every historical owned target is proven absent, every key is
destroyed, and no unresolved identity record exists. RecoveryRequired returns
the complete known set only when completeness itself is proven; otherwise the
query fails with IdentitySetUnavailable.

The query exposes no raw certificate, key, provider handle, target path,
journal storage, or mutation authority. Direct helper-journal reading,
Supervisor-memory authority, a sidecar cache, a copied SQLite row, or a second
selector is forbidden. ARCH-002 MUST map an unavailable/expired/incomplete
query to DependencyContractUnavailable and MUST NOT encode it as an empty set.

## Privileged-helper protocol integration

The accepted ARCH-001 helper protocol v0.2 is a closed deterministic-CBOR
schema. Its request tags are 0 through 9 for BeginSession, PreparePlan,
ActivationStep, RenewActivationLease, ClaimRecovery, RecoveryStep,
IssueExternalPermit, RedeemExternalPermit, AcknowledgeRecovery, and Status. Its
response tags are likewise closed. Those messages and the registered
core.session operation graph do not provide a persistent trust transaction, a
CA-key gate, a trust-proof read, or an identity-set read.

ARCH-003 does not assign hidden tags, overload Status, place trust operations
inside a core.session plan, or reinterpret an external permit as durable trust
authority. The current helper therefore cannot execute or attest this contract.
A later explicit ARCH-001 architecture task MUST register a new protocol
version and byte-exact schemas for at least:

- beginning and sealing a trust.ca.v1 transaction under its own generation,
  plan, revision, fence, consent, and idempotency domains;
- prepare, apply, compensate, commit, and recovery steps with per-target
  before/after observations and durable phases;
- one-use online permits for an exact authenticated user trust agent and an
  exact CA key authority operation;
- current trust-state, installed-proof, gate-challenge, and identity-set
  linearizable reads;
- key-created, key-possession, key-destroyed, target-installed, target-removed,
  gate-closed, and terminal receipts; and
- fixed numeric tags, array layouts, bounds, domains, error mappings, golden
  vectors, peer bindings, deadlines, and restart semantics.

That task MUST also define how trust.ca.v1 and core.session contend for the
global mutation lock without sharing generation numbers or allowing either
class to authorize the other. It MUST preserve the current helper guarantee
that external executors act only through a live, one-use, online gate whose
loss stops the operation before any unjournaled side effect.

Until that protocol is accepted and implemented, no mutable platform target can
be Supported. A row not already more restrictive has StaticSupport
UnsupportedPendingArchitecture, and every mutable row carries at least reasons
TrustTransactionProtocolUnavailable and TrustReadProofUnavailable. A direct
journal query, an in-process key call, a generic registered operation, or a
boolean added to Status does not close either gap.

## Windows exact target and backend candidate

WindowsPhysicalRootV1 has exactly two scope variants:

    CurrentUserRoot {
      UserSidDigest,
      Provider = CERT_STORE_PROV_PHYSICAL_W,
      ExactPhysicalStore = Root\.Default,
      StoreLocationFlag = CERT_SYSTEM_STORE_CURRENT_USER,
      RawInventoryAdditionalFlag = CERT_SYSTEM_STORE_UNPROTECTED_FLAG,
      Executor = AuthenticatedUserTrustAgent,
      ChainEngine = HCCE_CURRENT_USER,
      TrustSemantic = WindowsTlsServerRootV1
    }

    LocalMachineRoot {
      Provider = CERT_STORE_PROV_PHYSICAL_W,
      ExactPhysicalStore = Root\.Default,
      StoreLocationFlag = CERT_SYSTEM_STORE_LOCAL_MACHINE,
      RawInventoryAdditionalFlag = None,
      Executor = PrivilegedHelper,
      ChainEngine = HCCE_LOCAL_MACHINE,
      TrustSemantic = WindowsTlsServerRootV1
    }

The backend opens the existing physical store named `Root\.Default` with
CERT_STORE_PROV_PHYSICAL_W and the exact scope's CERT_SYSTEM_STORE_CURRENT_USER
or CERT_SYSTEM_STORE_LOCAL_MACHINE high-word location flag. HCCE_CURRENT_USER
and HCCE_LOCAL_MACHINE select a chain engine only; they never select the
mutation store. A raw read-only inventory handle also uses
CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_READONLY_FLAG, and
CERT_STORE_ENUM_ARCHIVED_FLAG. CurrentUser raw inventory additionally uses
CERT_SYSTEM_STORE_UNPROTECTED_FLAG so protected-root filtering cannot hide a
SystemRegistry item. The scoped mutation handle uses OPEN_EXISTING and
ENUM_ARCHIVED and the same CurrentUser UNPROTECTED behavior, but not READONLY.

The raw inventory, the ordinary protected/effective CurrentUser view, and the
selected chain-engine result are separate observations. A difference is
recorded rather than normalized away. The backend MUST NOT use the logical Root
collection for mutation or deletion and MUST NOT request
CERT_STORE_MAXIMUM_ALLOWED_FLAG, which can silently fall back to read-only.
CurrentUser is bound to the explicitly authenticated interactive User SID and
executes in that user's context; a service's HKEY_CURRENT_USER is not that
identity. LocalMachine is a separate explicit administrator choice and cannot
be an automatic fallback from CurrentUser.

WindowsTlsServerRootV1 uses three deliberately different
CertGetEnhancedKeyUsage observations because LocalInterceptionCaCertificateV1
has no EKU extension:

- CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG MUST return FALSE with the immediately
  captured GetLastError equal to CRYPT_E_NOT_FOUND; no output structure is
  consumed, and the missing DER extension alone denotes all uses;
- CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG MUST return TRUE with exactly OID
  1.3.6.1.5.5.7.3.1 server-auth; and
- flags zero MUST return TRUE with exactly that one server-auth OID as the
  intersection of the extension and property views.

An absent property, an extension-only result other than the specified absence,
an empty no-uses result, any additional OID, or a consumer that ignores the
property restriction is not this semantic.

No conforming Windows add path is selected in this snapshot. A future backend
may research only this bounded candidate shape:

1. Enumerate the exact physical store and classify exact-DER count,
   same-SPKI/different-DER, same-issuer-and-serial/different-DER, and other
   collisions.
2. Create an off-store context from the exact DER and set exactly one
   server-auth EKU property on that detached context. Verify its three views as
   specified above before opening a mutation handle.
3. Persist the complete before image and one add intent binding both the DER
   and exact EKU property after-image.
4. For Absent only, make the sole persistent side effect by passing that
   detached context to CertAddCertificateContextToStore with
   CERT_STORE_ADD_NEW. CertSetEnhancedKeyUsage on a context already visible in
   the physical Root store is forbidden.
5. Reopen and resynchronize the exact store, recompute SHA-256 over the returned
   encoded bytes, and require exactly one byte-equal DER.
   Re-read the three EKU views and require their distinct expected results
   exactly.
6. Resynchronize the selected chain engine and build a chain for a fresh leaf
   with CERT_CHAIN_PARA.RequestedUsage using AND match for exactly
   szOID_PKIX_KP_SERVER_AUTH. Require the chain root DER to equal the CA.
7. Evaluate CERT_CHAIN_POLICY_SSL with
   CERT_CHAIN_POLICY_PARA.dwFlags equal to zero and
   SSL_EXTRA_CERT_CHAIN_POLICY_PARA.fdwChecks equal to zero; set dwAuthType to
   AUTHTYPE_SERVER and pwszServerName to the exact normalized reference
   hostname. Require both a TRUE CertVerifyCertificateChainPolicy return and
   CERT_CHAIN_POLICY_STATUS.dwError equal to ERROR_SUCCESS. A TRUE return alone
   means only that Windows completed the policy check and is not trust success.

CERT_STORE_ADD_ALWAYS, CERT_STORE_ADD_REPLACE_EXISTING,
CERT_STORE_ADD_NEWER, and CERT_STORE_ADD_USE_EXISTING are forbidden. They can
create duplicates, replace administrator state, or attach properties to a
pre-existing item. CRYPT_E_EXISTS triggers a complete reobservation; it never
authorizes an update. CertCompareCertificate is not identity proof because it
compares only issuer and serial. CERT_SHA256_HASH_PROP_ID is corroboration only;
FlowProbe independently hashes and compares the complete DER.

CertDeleteCertificateFromStore consumes its context and has no expected
revision, compare-and-delete condition, or transaction identity.
CertDuplicateCertificateContext only retains a context reference and is not a
snapshot or CAS token. CertControlStore notifications, resynchronization, and
commit controls provide neither a complete ordered history nor a stable store
revision. Certificate properties are externally mutable and are not an
exclusive owner marker.

Microsoft documents that CertAddCertificateContextToStore creates a new copy
and copies ordinary context properties, but does not specify that the
certificate and its EKU property become externally visible as one atomic,
crash-durable unit. Until exact supported-release fault tests prove there is no
observable or recoverable all-uses interval, the candidate carries
AtomicPurposeConstraintInstallUnproven. An add followed by a stored-context EKU
write is always nonconforming: those are two persistent side effects, each
would need its own durable intent, and a crash between them could leave an
all-uses root that cannot be conditionally removed.

Consequently the shared Windows Root physical store does not satisfy the
normative exact conditional-removal rule. CurrentUserRoot and
LocalMachineRoot both remain unsupported with reasons
ConditionalExactDeleteUnavailable, StableStoreRevisionUnavailable, and
AtomicPurposeConstraintInstallUnproven, plus
PurposeConstraintPropagationUnproven even if add and TLS validation succeeds.
A future installation-unique registered
physical Root member with helper-only access may be researched separately, but
it is not selected here and would still require store-registration rollback,
chain-engine visibility, policy, and real-host proof.

Group Policy and enterprise physical stores are observed external authorities
and never modified. Other users, the other CurrentUser/LocalMachine scope,
Windows Server, ARM64, browser profile policies, and application-private trust
stores are outside a target unless a future contract names them. Microsoft
Edge may consume the OS root through its own verifier, but its separate
per-profile certificate policy and private state are not controlled; Edge
coverage requires an explicit real-browser consumer proof.

Primary platform references are Microsoft documentation for
[CertOpenStore](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore),
[logical and physical stores](https://learn.microsoft.com/en-us/windows/win32/seccrypto/logical-and-physical-stores),
[system store locations](https://learn.microsoft.com/en-us/windows/win32/seccrypto/system-store-locations),
[CurrentUser and LocalMachine stores](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores),
[certificate addition](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddcertificatecontexttostore),
[certificate deletion](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certdeletecertificatefromstore),
[context duplication](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certduplicatecertificatecontext),
[certificate comparison](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certcomparecertificate),
[enhanced-key-usage reads](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetenhancedkeyusage),
[enhanced-key-usage writes](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsetenhancedkeyusage),
[store controls](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certcontrolstore),
[chain building](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain),
[SSL chain policy](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifycertificatechainpolicy),
[SSL policy parameters](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-httpspolicycallbackdata),
[chain request parameters](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_para),
[service registry identity](https://learn.microsoft.com/en-us/windows/win32/services/services-and-the-registry),
and [Edge certificate verification](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-cert-verification).

## macOS exact target and backend candidate

MacOsTrustSettingsV1 separates the Trust Settings domain from the certificate
keychain. Its only variants are:

    User {
      ConsoleUserIdentityDigest,
      TrustDomain = kSecTrustSettingsDomainUser,
      CertificateStore = UserDefaultFileKeychain(ResolvedKeychainIdentity),
      Executor = AuthenticatedUserTrustAgent
    }

    AdminSystemWide {
      TrustDomain = kSecTrustSettingsDomainAdmin,
      CertificateStore = SystemKeychain(
        exact identity /Library/Keychains/System.keychain),
      Executor = PrivilegedHelper
    }

    SystemObservationOnly {
      TrustDomain = kSecTrustSettingsDomainSystem,
      Executor = ObservationOnly
    }

UID zero is not a fourth trust domain. The System domain contains Apple system
roots and is immutable even to root. The Admin domain and System.keychain are
not the System domain. A root helper's default keychain/search list is not a
valid substitute for the explicit target. User mutation occurs only in the
authenticated logged-in user's GUI/session context; Admin mutation is a
separate explicit administrator action.

AppleSslTrustRootV1 normalizes exactly one trust dictionary:

    Policy = kSecPolicyAppleSSL
    Result = kSecTrustSettingsResultTrustRoot
    ApplicationConstraint = Absent
    PolicyString = Absent
    AllowedError = Absent
    KeyUsage = Absent

An empty or null all-purpose Always Trust setting, TrustAsRoot for this
self-signed certificate, application constraints, hostname strings, and
allowed-error exceptions are forbidden. SecPolicyRef pointer identity and raw
property-list byte order are not semantic identity; verification normalizes the
closed fields above.

The candidate install path uses SecItemAdd into the exact file keychain, then
SecTrustSettingsSetTrustSettings for the exact certificate/domain, then exact
DER and normalized-trust rereads. A duplicate result requires enumeration and
byte-exact classification. The certificate/keychain item identity may include a
persistent reference as a locator, but deletion re-reads complete DER and trust
first. Removal calls SecTrustSettingsRemoveTrustSettings for the exact
certificate and exact User/Admin domain, reads back that the exact trust setting
is absent, and only then uses SecItemDelete for a certificate item proven
FlowProbe-owned through an exact item reference/match list. Calling
SecTrustSettingsSetTrustSettings with null is forbidden because null means
all-purpose Always Trust rather than removal. A broad SecItemDelete attribute
query is forbidden. Label, subject, issuer/serial, legacy SHA-1 trust dictionary
key, and persistent reference alone are not owner or revision proof.

Public Security.framework does not provide an expected-state CAS token, a
stable trust-domain revision, or an atomic transaction spanning certificate
storage and Trust Settings. SecTrustSettingsCopyModificationDate is a wall-clock
observation, not a monotonic revision. SecKeychain callbacks are deprecated,
unordered wake-up hints that can miss changes during downtime.

The reviewed Apple Security implementation reads and rewrites an entire trust
domain, writes the legacy Trust Settings file with truncation rather than an
atomic rename/fsync protocol, and then writes a per-certificate trust store in a
separate step. A crash or concurrent administrator can therefore leave partial
or overwritten state. The security command-line tool composes the same
non-atomic primitives and provides no structured durable phase; it is allowed
only as a disposable real-host oracle, never as the production backend.

User and Admin targets consequently remain unsupported with reasons
ConditionalExactMutationUnavailable and CrashDurabilityUnproven. The System
target is UnsupportedImmutablePlatformDomain. A successful
SecTrustEvaluateWithError result is effective-trust evidence, not a substitute
for those missing mutation guarantees.

Safari, Chrome, and Firefox are distinct consumer rows. System-trust use must
be verified with a fresh real TLS connection and correct hostname. Firefox OS
enterprise-root integration may be disabled and its NSS database is never
modified. Chrome/Firefox private stores, profile policy, pinning, embedded TLS
stacks, and applications with private CA sets are excluded.

Primary references are Apple's
[Trust Settings interface](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/trust/headers/SecTrustSettings.h),
[TN3137 on macOS keychains](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains),
[DER certificate storage](https://developer.apple.com/documentation/security/storing-a-der-encoded-x-509-certificate),
[SecItemDelete](https://developer.apple.com/documentation/security/secitemdelete%28_%3A%29),
and the open-source implementations of
[SecTrustSettings](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_keychain/lib/SecTrustSettings.cpp),
[TrustSettings flush](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_keychain/lib/TrustSettings.cpp),
and [trustd persistence](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/trust/trustd/SecTrustSettingsServer.c).

## Linux exact targets and backend candidates

Linux has no generic system trust target. The release manifest selects one
authority target and enumerates each derived output and consumer separately.
No caller-supplied path, command, environment, HOME, nickname, hook, or package
binary is accepted.

### Linux trust-purpose semantics

LinuxTrustSemanticV1 is a closed union:

    DebianUbuntuImplicitGeneralPurposeAnchorV1
    P11KitTlsServerAnchorV1
    NssTlsServerCaV1

DebianUbuntuImplicitGeneralPurposeAnchorV1 records that a PEM certificate below
/usr/local/share/ca-certificates is implicitly trusted by the shared generated
store without a purpose constraint carried by that source format. A successful
TLS test cannot prove that every consumer will refuse client-auth, email,
code-signing, timestamping, or an unknown purpose. This semantic is deliberately
StaticSupport UnsupportedByProductPolicy with reason TrustPurposeOverbroad; an
extra consent warning does not promote it. A future purpose-limited Debian/
Ubuntu target requires a separate architecture decision and consumer evidence.

P11KitTlsServerAnchorV1 uses one release-selected canonical trust-policy
representation that normalizes to a positive anchor assertion only for OID
1.3.6.1.5.5.7.3.1 server-auth, explicit rejection for the selected release's
known client-auth, email, code-signing, and timestamping purposes, and no
positive any-purpose or unknown-purpose assertion. A plain PEM/DER file in the
anchors directory does not satisfy this type because p11-kit treats it as an
unconstrained anchor. The exact representation must pass trust check-format,
normalize through the p11-kit trust module to that assertion set, appear for
trust list/extract server-auth, remain absent for other-purpose extracts, and
pass positive server TLS plus negative non-server consumer tests. A derived
format or consumer that discards these constraints is excluded with
PurposeConstraintPropagationUnproven rather than reported trusted.

NssTlsServerCaV1 fixes the exact NSS trust string to C,,: trusted CA for SSL,
with empty email and object-signing fields. Any other flag, reordered semantic,
pre-existing broader trust, or consumer-private interpretation is a target
conflict. A nickname or successful server TLS check cannot prove the flags.

### Debian and Ubuntu shared trust

DebianUbuntuSharedTrustV1 owns one generation-scoped deterministic basename
below /usr/local/share/ca-certificates ending in .crt. Active and candidate
generations use disjoint source paths. The privileged helper creates that
source using no-follow resolution and exclusive creation, with root
ownership/group and fixed mode 0644. The parent is administrator-managed
/usr/local state, not package-owned state. Before every observation or mutation,
the backend records every path component's file identity, owner, group, mode,
mount identity, and effective writer set while holding stable directory handles.
Any non-accepted writer able to rename or replace the source or an ancestor is
Unsafe with reason TrustSourceParentNotExclusive; no-follow on the final file is
insufficient. The file is canonical PEM with exactly one CERTIFICATE block
whose decoded bytes equal the authoritative DER; source-file digest and decoded
DER digest are both recorded. It then invokes the exact release-manifest
update-ca-certificates executable with a fixed environment.

The source anchor is the authority item. Each generated individual certificate
or hash-link under /etc/ssl/certs and the aggregate ca-certificates.crt bundle
is a separate DerivedSystemBundleV1 observation. They are never directly
edited, deleted, or restored from a baseline copy. Removal deletes only the
exact owned source after a current conditional ownership check, invokes the
same fixed regenerator, and verifies every derived output and fresh TLS result.

update-ca-certificates scans inputs, may clear many links in fresh mode, rewrites
shared outputs, and runs hooks. It exposes no stable release-independent store
revision, conditional source deletion, cross-output transaction, or crash
receipt. The complete input tree, path writers, hooks, and package changes are
external authorities and drift. The candidate therefore
remains unsupported until exact source-object conditional deletion, bounded
regenerator/hook execution, partial-output recovery, and real-host durability
are proved.

### Fedora and RHEL shared trust

FedoraRhelSharedTrustV1 owns one generation-scoped deterministic purpose-policy
identity directly below /etc/pki/ca-trust/source, outside the anchors
subdirectory that implicitly promotes policy-free files. Active and candidate
generations use disjoint source identities. The source is created and
conditionally removed with the same no-follow, exclusive, root-owned mode-0644
rules. Its
release-selected trust-policy representation decodes byte-for-byte to the
authoritative DER and normalizes to P11KitTlsServerAnchorV1; representation,
DER, and assertion-set digests are all recorded. The release manifest binds
exact ca-certificates, update-ca-trust, p11-kit, trust module, distribution,
version, and architecture identities.

The source assertion, effective purpose-bound p11-kit anchor token, and every
extracted PEM/Java or compatibility output are distinct authority/derived
observations.
update-ca-trust extraction globally regenerates outputs and has no documented
cross-output transaction, stable revision, or compare-and-delete input. A
source write or command exit cannot prove the effective token and all bundles.
The target remains unsupported until an exact release tuple, safe conditional
source lifecycle, global-regenerator recovery, and real-host proof exist.

### NSS SQL databases and derived bundles

NssSqlDatabaseV1 names one explicit absolute sql database directory, database
owner, owner-context executor, exact NSS/certutil/database-schema/consumer/OS
release tuple, consumer, generation-scoped exact nickname, and trust flags in
the release plan. Active and candidate generations use disjoint nicknames;
rename, overwrite, and in-place trust-flag replacement are forbidden.
User-owned databases execute only through the exact authenticated user trust
agent; system/service-owned databases execute only through the privileged
helper bound to that DatabaseOwnerIdentity. Permission failure never switches
contexts. Browser
profile discovery, wildcard profile mutation, HOME-relative paths, DBM
databases, shared unknown-owner databases, and automatic browser shutdown are
forbidden.

The backend must read the exact DER and exact C,, trust flags behind a nickname
before any operation.
NSS certutil deletion is nickname-addressed and has no expected DER/revision
condition, so an externally mutable database is unsupported. Nickname, subject,
and database path are not deletion authority. An application-owned exclusive
database could become a candidate only under a separately accepted database
transaction/locking and crash-recovery contract.

DerivedSystemBundleV1 is never an independent write target. Its authority is
the exact source target and fixed regenerator; it records content digest,
ownership/metadata, generation relationship, release tuple, and consumer TLS
result. A bundle, symlink forest, p11-kit projection, or compatibility file
must not be restored wholesale because doing so could erase administrator or
package-manager changes.

The initially researched release rows are Debian 13 amd64 with
ca-certificates 20250419, Ubuntu 24.04 LTS amd64 with the selected release
ca-certificates package, and candidate Fedora 44 x86_64. RHEL and the complete
Fedora p11-kit tuples are not selected by this contract. These identifiers are
research anchors, not support claims; the immutable signed release manifest
must bind exact installed package hashes/versions before a row can advance.

Primary references are the Debian
[update-ca-certificates manual](https://manpages.debian.org/trixie/ca-certificates/update-ca-certificates.8.en.html)
and [source package](https://sources.debian.org/src/ca-certificates/20250419/sbin/update-ca-certificates/),
Ubuntu's [root CA installation guidance](https://ubuntu.com/server/docs/how-to/security/install-a-root-ca-certificate-in-the-trust-store/),
Red Hat's [shared system certificate guidance](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/securing_networks/index#using-shared-system-certificates_securing-networks),
Fedora's [ca-certificates package](https://packages.fedoraproject.org/pkgs/ca-certificates/ca-certificates/fedora-44-updates.html),
p11-kit's [trust module](https://p11-glue.github.io/p11-glue/p11-kit/manual/trust-module.html)
and [NSS compatibility](https://p11-glue.github.io/p11-glue/p11-kit/manual/trust-nss.html),
and the NSS [certutil reference](https://nss-crypto.org/reference/security/nss/legacy/reference/nss_tools__colon__certutil/index.html).

## Capability, readiness, and evidence

TrustCapabilitySnapshotV1 is computed before consent or mutation and is bound
into every plan. It contains one row per exact target, derived output, key
provider, and claimed consumer. A row has:

    TargetOrConsumerId
    TargetKind and exact scope
    BackendReleaseTupleDigest
    StaticSupport
    DynamicReadiness
    EvidenceVector
    SortedUniqueReasonVector
    RequiredPermission
    RequiredInteraction
    ExcludedScopeVector
    observed_at and expires_at

StaticSupport is a closed union:

    Supported
  | UnsupportedPendingArchitecture
  | UnsupportedImmutablePlatformDomain
  | UnsupportedByProductPolicy

DynamicReadiness is a closed union:

    Ready
  | Unsafe
  | PermissionMissing
  | InteractionRequired
  | BackendUnavailable
  | ReleaseTupleMismatch
  | Drifted
  | RecoveryRequired

EvidenceVector independently records DesignReviewed,
DeterministicConformancePassed, RealHostInstallPassed,
RealHostCrashRecoveryPassed, RealHostExactUninstallPassed, and a separate
RealConsumerTlsPassed value for each claimed consumer and release tuple. Missing
evidence is explicit; these values are not collapsed into a maximum level.

A row may be used only when StaticSupport is Supported, DynamicReadiness is
Ready at preparation and immediately before every mutation/admission, every
required evidence bit is present for the exact signed release tuple, and the
complete reason vector is empty. Runtime success cannot promote a statically
unsupported row. A release-manifest change, OS/package update, helper/key
provider change, store-scope change, or consumer update invalidates the matching
evidence until the declared compatibility rule and required real-host gates
pass again.

The reason registry includes:

    TrustTransactionProtocolUnavailable
    TrustReadProofUnavailable
    KeyAuthorityProtocolUnavailable
    KeyProviderUnselected
    NonExportabilityUnproven
    KeyDestroyProofUnavailable
    AuthenticatedUserAgentUnavailable
    ConditionalExactDeleteUnavailable
    ConditionalExactMutationUnavailable
    StableStoreRevisionUnavailable
    CrashDurabilityUnproven
    ReleaseTupleUnselected
    GlobalRegeneratorRecoveryUnproven
    HookInventoryUnbounded
    NssConditionalDeleteUnavailable
    NssDatabaseTransactionUnproven
    TrustSourceParentNotExclusive
    TrustPurposeOverbroad
    PurposeConstraintEncodingUnproven
    AtomicPurposeConstraintInstallUnproven
    PurposeConstraintPropagationUnproven
    ImmutablePlatformDomain
    RealHostUnverified
    RealBrowserUnverified
    BrowserPrivateStoreExcluded

Unknown reasons fail closed. The vector is sorted, unique, bounded, and exposed
without platform free-form error text.

## Current support matrix

This matrix is normative for the architecture snapshot. It intentionally makes
no supported trust or browser claim.

| Row | Exact scope / permission | StaticSupport / readiness / evidence | Additional bounded reasons and exclusions |
| --- | --- | --- | --- |
| CA key authority on every platform | Separate protected signer authority; explicit product consent | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | KeyAuthorityProtocolUnavailable, KeyProviderUnselected, NonExportabilityUnproven, KeyDestroyProofUnavailable, RealHostUnverified |
| Windows CurrentUser Root | Exact interactive User SID, physical `Root\.Default`, authenticated user agent | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | AuthenticatedUserAgentUnavailable, ConditionalExactDeleteUnavailable, StableStoreRevisionUnavailable, AtomicPurposeConstraintInstallUnproven, PurposeConstraintPropagationUnproven, RealHostUnverified; other users and browser-private stores excluded |
| Windows LocalMachine Root | Exact physical `Root\.Default`, administrator and privileged helper | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | ConditionalExactDeleteUnavailable, StableStoreRevisionUnavailable, AtomicPurposeConstraintInstallUnproven, PurposeConstraintPropagationUnproven, RealHostUnverified; Group Policy and Edge profile CA policy excluded |
| macOS User | Exact console user, User Trust Settings plus resolved user file keychain, GUI authentication | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | AuthenticatedUserAgentUnavailable, ConditionalExactMutationUnavailable, CrashDurabilityUnproven, RealHostUnverified |
| macOS Admin | Admin Trust Settings plus exact System.keychain, administrator/helper | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | ConditionalExactMutationUnavailable, CrashDurabilityUnproven, RealHostUnverified |
| macOS System | Apple System Trust Settings, observe only | UnsupportedImmutablePlatformDomain / Unsafe / DesignReviewed | ImmutablePlatformDomain; no mutation is permitted |
| Debian 13 amd64, ca-certificates 20250419 research row | Fixed source below administrator-managed /usr/local/share/ca-certificates, root helper; outputs separate | UnsupportedByProductPolicy / Unsafe / DesignReviewed | TrustPurposeOverbroad, TrustSourceParentNotExclusive, ConditionalExactDeleteUnavailable, GlobalRegeneratorRecoveryUnproven, HookInventoryUnbounded, RealHostUnverified |
| Ubuntu 24.04 LTS amd64, ca-certificates 20260601~24.04.1 research row | Fixed source below administrator-managed /usr/local/share/ca-certificates, root helper; outputs separate | UnsupportedByProductPolicy / Unsafe / DesignReviewed | TrustPurposeOverbroad, TrustSourceParentNotExclusive, ConditionalExactDeleteUnavailable, GlobalRegeneratorRecoveryUnproven, HookInventoryUnbounded, RealHostUnverified |
| Fedora 44 x86_64, ca-certificates 2025.2.80_v9.0.304-7.fc44 research row | Purpose-policy source directly below /etc/pki/ca-trust/source, root helper; p11-kit and outputs separate | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | ReleaseTupleUnselected, PurposeConstraintEncodingUnproven, PurposeConstraintPropagationUnproven, ConditionalExactDeleteUnavailable, GlobalRegeneratorRecoveryUnproven, RealHostUnverified |
| RHEL 9.8 x86_64 research row | Purpose-policy source directly below /etc/pki/ca-trust/source, root helper | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | ReleaseTupleUnselected, PurposeConstraintEncodingUnproven, PurposeConstraintPropagationUnproven, ConditionalExactDeleteUnavailable, GlobalRegeneratorRecoveryUnproven, RealHostUnverified |
| Explicit NSS SQL database | One absolute selected database, exact owner-context user agent or helper, and exact NSS/certutil/schema/consumer/OS tuple; never profile discovery | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | ReleaseTupleUnselected, NssConditionalDeleteUnavailable, NssDatabaseTransactionUnproven, CrashDurabilityUnproven, RealHostUnverified; shared/browser-private stores excluded |
| Any derived Linux bundle or p11-kit projection | Read-only result of one exact authority target and fixed regenerator | Inherits the authority's equal-or-more-restrictive StaticSupport / Unsafe / DesignReviewed | Inherits authority reasons plus PurposeConstraintPropagationUnproven and GlobalRegeneratorRecoveryUnproven; never directly mutated |

Every mutable row also carries TrustTransactionProtocolUnavailable and
TrustReadProofUnavailable until the helper integration section is satisfied.
Every mutable row depends on a supported CA key authority. These common reasons
are stated once here rather than repeated in each table cell.

Safari, Chrome, Edge, Firefox, command-line TLS libraries, and application
clients are consumer evidence rows, not trust targets. Each is
RealBrowserUnverified or RealHostUnverified until tested against the exact OS,
browser/application build, policy, running/restarted state, and trust target.
Firefox enterprise-root-disabled mode, browser-private stores, profile-managed
roots, pinning, and embedded private TLS stacks remain excluded even if an OS
target later becomes supported.

## Error and result contract

TrustLifecycleErrorV1 is a closed union:

    Unauthenticated
    Unauthorized
    ProtocolMismatch
    InvalidRequest
    InvalidCertificateProfile
    CertificateKeyMismatch
    ConsentMissing
    ConsentExpired
    ConsentScopeMismatch
    ReplayDetected
    StaleGeneration
    StaleFence
    StaleStateRevision
    PlanExpired
    Unsupported
    PermissionDenied
    PermissionMissing
    InteractionRequired
    BackendUnavailable
    BackendReleaseMismatch
    TargetConflict
    ResourceNotOwned
    ExternalDrift
    MutationFailed
    MutationAmbiguous
    PostconditionFailed
    KeyUnavailable
    KeyDestroyAmbiguous
    IdentitySetUnavailable
    JournalFailure
    JournalCorrupt
    RecoveryRequired
    IntegrityFailure
    TimedOut

Every result reports only a stable bounded reason, safe observed phase,
TrustOperationId, generation, target identifier when authenticated,
retryability, and current non-authorizing state/revision. Platform error strings
are sanitized diagnostics and never wire enums. Retryability never authorizes
automatic reinstall, scope fallback, another consent, or retry of an ambiguous
mutation before reconciliation.

Unsupported, permission rejection, drift, key mismatch, stale proof,
identity-set failure, and recovery failure close the signing gate. Capture Core
then applies the exact InterceptionPolicyV1: transparent pass-through for
PreferInterceptionWithTransparentPassThrough, or a typed refusal for
RequireInterception. It never presents an unverified FlowProbe leaf.

## Deterministic conformance gates

Before any target can advance from DesignReviewed, deterministic tests MUST
cover at least:

- byte-exact golden vectors and independent encode/decode/hash validation for
  every lifecycle state, target, plan, receipt, proof, error, and identity-set
  variant, including unknown tags, fields, versions, domains, algorithms,
  noncanonical order, and boundary sizes;
- exhaustive allowed/forbidden state transitions, nonwrapping generation,
  fence/revision monotonicity, stale controller rejection, idempotent identical
  replay, conflicting replay, and terminal receipt retention;
- crash injection before and after every journal fsync, index selector update,
  key-provider call, platform mutation, read-back, derived-output update,
  compensation, gate transition, and response delivery;
- all multi-target partial-success permutations, deterministic reverse
  compensation, preservation of pre-existing state, ambiguous outcome, and
  restart convergence without an installed boolean shortcut;
- exact DER positive cases and same-subject, same-SPKI/different-DER,
  same-issuer-and-serial/different-DER, same-label/nickname, duplicate,
  replacement, missing, cross-scope, and foreign-owner negative cases;
- consent cancellation, expiry, replay, operation/CA/target/policy substitution,
  user-to-machine escalation, interaction loss, and recovery actions outside
  the consumed consent;
- CA profile parsing, normalized trust-purpose matching, positive server-auth
  and negative client-auth/email/code-signing/timestamping purpose cases,
  derived-purpose preservation, non-exportability adapter behavior, public-key/
  SPKI match, fresh possession challenge, stale/chosen-message proof rejection,
  leaf SAN and lifetime bounds, key destruction ambiguity, and zeroization/error
  paths;
- signing admission at every state and drift condition, dual-proof field
  mismatch, stale epoch, one-use consumption, key/service loss, and exact
  pass-through/refusal behavior;
- complete ARCH-002 identity sets for generation, install, rotation, partial
  removal, external deletion, residual key, drift, recovery ambiguity, valid
  Absent, and unavailable/incomplete ledgers;
- platform fake backends that model external mutation between observe/apply,
  apply/read-back, observe/delete, and delete/read-back, plus missed notification
  and restart rescan; and
- redaction snapshots proving no private key, key handle, public DER, captured
  credential, arbitrary platform string, or unbounded path appears in ordinary
  status, logs, errors, telemetry, or diagnostics.

Critical DER, target-observation, journal, and wire parsers require malformed-
input and fuzz coverage. A fake backend proves deterministic logic only; it
cannot provide platform support, trust, crash durability, or browser evidence.

## Real-host and consumer acceptance

Real-host gates run in disposable signed-release VMs on both the selected
minimum and latest supported tuple. They preserve a cryptographic before image
of every unrelated target and prove that the final state is identical. Common
gates are:

1. Generate, install, effective TLS verify, app/helper/key-authority restart,
   drift detection, exact remove, key destruction, and reinstall with new
   generation/identity.
2. Process kill and VM hard-stop at every externally observable durable and
   platform boundary; restart must converge to a bounded state without guessing
   ownership or silently reapplying trust.
3. User cancellation, privilege denial, UI/session loss, backend/package/policy
   change, full disk, read-only target, timeout, response loss, and concurrent
   duplicate requests.
4. Every exact-identity collision and pre-existing-state case from the
   deterministic suite, with all foreign certificates and settings preserved.
5. External deletion, replacement, trust modification, same-DER copy in another
   scope, consumer reload requirement, notification loss, and application
   restart; the gate must close before the next new leaf.
6. Concurrent administrator writes to the same and unrelated trust entries. If
   the backend can overwrite or delete a competing current state, the target
   remains unsupported.
7. Positive TLS with a fresh correctly named leaf and negative TLS for wrong
   hostname, wrong CA, wrong signing key, expiration, and excluded store/policy.
   After removal, require negative TLS only when no preserved external path
   remains; otherwise prove the owned authority absent and bind the successful
   residual to ResidualEffectiveTrustDispositionV1.PreservedExternal. The
   validated chain anchor must be the exact DER.
8. Exact uninstall proving every FlowProbe-owned certificate/trust/key is gone,
   every external/pre-existing item is preserved, and no aggregate store,
   bundle, keychain, NSS database, or browser profile was restored wholesale.

Windows additionally covers Windows 10 22H2 x86_64 and Windows 11 24H2 x86_64,
two interactive users, CurrentUser versus LocalMachine inheritance, non-elevated
and elevated flows, domain Group Policy refresh, protected-root behavior,
CryptoAPI/Schannel or WinHTTP, and the exact Edge builds claimed. Physical-store
absence and effective trust through another scope/policy are reported
separately.

macOS additionally covers the selected minimum and latest release on every
claimed architecture, User/Admin/System precedence, GUI and headless contexts,
user authentication cancellation, administrator flow, Keychain Access external
edits, trustd/helper/app restart, hard power loss, SecTrustEvaluateWithError,
Safari, exact Chrome builds, and Firefox with OS enterprise roots both enabled
and disabled. Tests prove Firefox NSS databases remain unchanged.

Each supported Linux tuple additionally covers package/repository identity,
file no-follow/owner/mode checks, concurrent package-manager activity, every
regenerator/hook output, partial bundle/hash/p11-kit generation, hard power
loss, package upgrade, exact source removal, and actual selected command-line
and browser consumers. Debian/Ubuntu, Fedora/RHEL, p11-kit, each system bundle,
and each NSS SQL database retain separate results; passing one never promotes
the others or a generic Linux claim.

Evidence records the signed release artifact hashes, helper/key authority and
backend versions, exact OS/package/browser tuples, target and before/after
digests, crash points, consumer result roots, and test-harness version. It
contains no private key or captured secrets. A support manifest is published
only after all required deterministic and real-host rows pass.

## Security, diagnostics, update, and uninstall

Ordinary status and diagnostics may expose bounded lifecycle tags, target kinds,
truncated display fingerprints, support/reason enums, and receipt digests. They
MUST NOT expose the CA private key, provider identity/handle, wrapping material,
full public DER, arbitrary target path, user profile path, complete store
inventory, consent credential, helper/key channel material, or captured
Authorization/Cookie content. A separately consented support export may include
the public certificate only through a dedicated redacted schema.

The helper, key authority, and user trust agent reject inherited descriptors,
debug/task/ptrace access, dumps, unsigned replacement, wrong package identity,
wrong peer, and downgrade before any secret or mutation. Test fixtures use only
ephemeral generated certificates and keys and never real user or production
material.

An updater or uninstaller first closes the gate and reconciles trust.ca.v1. It
MUST NOT remove the helper, key authority, journal, target owner records, or key
provider while an owned target/key, pending operation, drift, or
RecoveryRequired state remains. Product uninstall does not broaden removal:
foreign or ambiguous state is preserved and reported for bounded manual
recovery.

FlowProbe is unreleased at this decision point. Existing in-memory CA behavior
and future internal trust formats may be replaced directly; this contract adds
no compatibility shim or migration path. Production upgrade or migration
semantics require a separately authorized architecture task.
