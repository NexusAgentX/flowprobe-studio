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
- helper, key authority, Supervisor, user/admin trust agents, Capture Core, UI,
  and machine crashes at every durable or platform boundary;
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
| CA key authority | Generate and retain the protected CA key, create the exact public certificate, prove key possession, sign bounded leaves, and attest only the closed key-ledger, identity-set, and quiescent-stable receipt domains after typed verification | Trust-store mutation, network policy, renderer access, generic attestation or arbitrary-message signing |
| Capture Core interception signer client | Request a bounded leaf from the exact admitted CA generation | Raw CA key, trust mutation, admission policy |
| Privileged helper | Journal and execute compile-time registered privileged public-certificate mutations whose backend permits daemon execution | CA private key, leaf signing, arbitrary shell/path/store, product consent, macOS GUI-authenticated Admin Trust Settings calls |
| Authenticated user trust agent | Execute a sealed current-user trust operation in the exact logged-in user context through an online helper gate | Machine/admin targets, private key, arbitrary profile discovery or path |
| Authenticated administrator trust agent | Execute one sealed macOS Admin-domain and System.keychain operation in a foreground GUI session after native administrator authentication through an online helper gate | User-domain fallback, other machine targets, private key, arbitrary trust/keychain operation, offline authority |
| Platform trust verifier | Independently enumerate and normalize exact target/effective TLS trust evidence | Mutation, consent, optimistic boolean |
| ARCH-002 trust-material broker | Query the authenticated interception-CA identity set for upstream-proxy filtering | Installing/removing local CA, reading key material, treating unavailable as empty |

One CA trust coordinator owns a transaction generation. The installation's
ARCH-001 helper authority remains the single writer for the protected trust
journal and state index. User- or foreground-admin-context execution is an
externally gated step, not a second journal writer. The key authority maintains
a separate protected key ledger because the helper MUST NOT receive the key. No
single stored boolean from either ledger authorizes interception.

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
- RecoverySelectionId: a random 256-bit identity for one non-authorizing
  RecoveryRequired episode that has no pending operation, installation-lifetime
  unique and never accepted as a consent, plan, target/key mutation, provider
  operation, or TrustOperationId;
- TrustPlanId and TrustPlanDigest: the immutable target/resource graph;
- TrustFenceToken: a monotonically ordered trust-class fence;
- TrustStateRevision: a nonwrapping durable revision;
- TrustJournalHeadDigest: the authenticated current journal tip;
- ResidualScanUniverseRevision: a nonwrapping installation-lifetime catalog
  revision;
- KeyAuthorityEpoch and KeyStateRevision: nonwrapping key-ledger counters;
- KeyJournalHeadDigest: the authenticated current protected key-ledger tip;
- InterceptionGateEpoch: a nonwrapping local signer admission epoch;
- ConsentReceiptId: a random 256-bit one-operation receipt identity; and
- ConsentAuthoritySelectionId: a random 256-bit, installation-lifetime-unique
  identity for one non-authorizing signed-manifest/keyset selection; it is not a
  TrustOperationId and is never reused after selection, recovery, or compaction;
  and
- InstallationBootstrapAttemptId: a random 256-bit machine-namespace-lifetime-
  unique identity for one attestation-key bootstrap attempt, retained after
  success, abandonment, cleanup, retirement, and compaction; and
- AttestationProviderOperationId: a random 256-bit machine-namespace-lifetime-
  unique idempotency identity for exactly one role-key Create or CleanupDestroy
  provider operation; role and operation-kind are part of its typed identity,
  and it is never reused after any result or ambiguity; and
- ProviderCreateOperationId: a random 256-bit non-secret idempotency identity
  for the single provider create attempt, unique for the complete installation
  lifetime and never reused after cancellation, success, ambiguity, recovery, or
  compaction;
- KeyDestroyOperationId: a random 256-bit non-secret idempotency identity for
  one provider destroy attempt, unique for the complete installation lifetime
  and never reused after success, ambiguity, recovery, or compaction; and
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
| phase plan | FlowProbe.TrustCa.PhasePlan.v1 |
| trust capability snapshot | FlowProbe.TrustCa.TrustCapabilitySnapshot.v1 |
| trust-operation journal record | FlowProbe.TrustCa.TrustOperationJournalRecord.v1 |
| trust-journal record link | FlowProbe.TrustCa.TrustJournalRecordLink.v1 |
| trust-journal head | FlowProbe.TrustCa.TrustJournalHead.v1 |
| trust-journal compaction checkpoint | FlowProbe.TrustCa.TrustJournalCompaction.v1 |
| signer-switch plan | FlowProbe.TrustCa.SignerSwitchPlan.v1 |
| signer-switch selection challenge | FlowProbe.TrustCa.SignerSwitchSelectionChallenge.v1 |
| signer-switch receipt | FlowProbe.TrustCa.SignerSwitchReceipt.v1 |
| helper purpose-separated attestation | FlowProbe.TrustCa.HelperAttestation.v1 |
| installation attestation anchor | FlowProbe.TrustCa.InstallationAttestationAnchor.v1 |
| installation attestation signature | FlowProbe.TrustCa.InstallationAttestationSignature.v1 |
| installation attestation policy | FlowProbe.TrustCa.InstallationAttestationPolicy.v1 |
| installation retirement cleanup evidence | FlowProbe.TrustCa.InstallationRetirementCleanup.v1 |
| retired installation seal | FlowProbe.TrustCa.RetiredInstallationSeal.v1 |
| machine installation namespace | FlowProbe.TrustCa.InstallationNamespace.v1 |
| recovery key-ledger state projection | FlowProbe.TrustCa.RecoveryKeyLedgerStateProjection.v1 |
| installation bootstrap selection | FlowProbe.TrustCa.InstallationBootstrap.v1 |
| TargetId | FlowProbe.TrustCa.Target.v1 |
| immutable trust-target plan record | FlowProbe.TrustCa.TargetPlanRecord.v1 |
| certificate public identity | FlowProbe.TrustCa.CertificateIdentity.v1 |
| candidate generation commitment | FlowProbe.TrustCa.GenerationCommitment.v1 |
| quiescent business postcondition | FlowProbe.TrustCa.QuiescentBusinessPostcondition.v1 |
| residual scan universe | FlowProbe.TrustCa.ResidualScanUniverse.v1 |
| residual universe successor | FlowProbe.TrustCa.ResidualUniverseSuccessor.v1 |
| residual scope enumeration | FlowProbe.TrustCa.ResidualScopeEnumeration.v1 |
| residual scan result | FlowProbe.TrustCa.ResidualScanResult.v1 |
| residual identity observation | FlowProbe.TrustCa.ResidualIdentityObservation.v1 |
| absent residual observation record | FlowProbe.TrustCa.AbsentResidualObservationRecord.v1 |
| absent residual observation receipt | FlowProbe.TrustCa.AbsentResidualObservationReceipt.v1 |
| pending operation snapshot body | FlowProbe.TrustCa.PendingOperationSnapshot.v1 |
| complete pending operation snapshot | FlowProbe.TrustCa.CompletePendingOperationSnapshot.v1 |
| last-quiescent state snapshot | FlowProbe.TrustCa.LastQuiescentStateSnapshot.v1 |
| monotonic safety envelope | FlowProbe.TrustCa.MonotonicSafetyEnvelope.v1 |
| residual consumer observation | FlowProbe.TrustCa.ResidualConsumerObservation.v1 |
| successful consumer TLS result | FlowProbe.TrustCa.ConsumerTlsSuccess.v1 |
| negative consumer TLS result | FlowProbe.TrustCa.ConsumerTlsNegative.v1 |
| ambiguous consumer observation | FlowProbe.TrustCa.ConsumerObservationAmbiguous.v1 |
| destroyed-key conservative consumer result | FlowProbe.TrustCa.ConsumerProbeUnavailable.v1 |
| residual ownership aggregate | FlowProbe.TrustCa.ResidualOwnershipAggregate.v1 |
| residual scan trust disposition | FlowProbe.TrustCa.ResidualScanTrustDisposition.v1 |
| current derived-authority source set | FlowProbe.TrustCa.DerivedAuthoritySourceSet.v1 |
| target-scope template entry | FlowProbe.TrustCa.TargetScopeTemplateEntry.v1 |
| requested target-scope template | FlowProbe.TrustCa.TargetScopeTemplate.v1 |
| exact ordered target set | FlowProbe.TrustCa.ExactTargetSet.v1 |
| target-template refinement | FlowProbe.TrustCa.TargetTemplateRefinement.v1 |
| rotation target binding | FlowProbe.TrustCa.RotationTargetBinding.v1 |
| rotation phase graph | FlowProbe.TrustCa.RotationPhaseGraph.v1 |
| consumed-consent tombstone | FlowProbe.TrustCa.ConsentReplayTombstone.v1 |
| consumed-consent replay index | FlowProbe.TrustCa.ConsentReplayIndex.v1 |
| operation replay result | FlowProbe.TrustCa.OperationReplayResult.v1 |
| privilege/interaction aggregate | FlowProbe.TrustCa.PrivilegeAggregate.v1 |
| complete trust lifecycle state | FlowProbe.TrustCa.TrustLifecycleState.v1 |
| context-free target business fact | FlowProbe.TrustCa.TargetBusinessFact.v1 |
| operation target observation | FlowProbe.TrustCa.OperationTargetObservation.v1 |
| terminal target observation | FlowProbe.TrustCa.TerminalTargetObservation.v1 |
| terminal fixed-regenerator result | FlowProbe.TrustCa.TerminalFixedRegeneratorResult.v1 |
| terminal derived-authority source set | FlowProbe.TrustCa.TerminalDerivedAuthoritySourceSet.v1 |
| no-FlowProbe-ownership proof | FlowProbe.TrustCa.NoFlowProbeOwnershipProof.v1 |
| residual-query context | FlowProbe.TrustCa.ResidualQueryContext.v1 |
| residual-query target observation | FlowProbe.TrustCa.ResidualQueryTargetObservation.v1 |
| residual-query fixed-regenerator result | FlowProbe.TrustCa.ResidualQueryFixedRegeneratorResult.v1 |
| residual-query derived-member proof | FlowProbe.TrustCa.ResidualQueryDerivedMemberProof.v1 |
| create pre-call provider absence proof | FlowProbe.TrustCa.ProviderCreatePreCallAbsence.v1 |
| create post-call provider absence proof | FlowProbe.TrustCa.ProviderCreatePostCallAbsence.v1 |
| create never-started provider absence proof | FlowProbe.TrustCa.ProviderCreateNeverStartedAbsence.v1 |
| destroy post-call provider absence proof | FlowProbe.TrustCa.ProviderDestroyPostCallAbsence.v1 |
| provider operation reservation | FlowProbe.TrustCa.ProviderOperationReservation.v1 |
| destroy continuation authority | FlowProbe.TrustCa.DestroyContinuationAuthority.v1 |
| destroy continuation selection record | FlowProbe.TrustCa.DestroyContinuationSelection.v1 |
| key destroy intent | FlowProbe.TrustCa.KeyDestroyIntent.v1 |
| negative key-possession result | FlowProbe.TrustCa.NegativeKeyPossessionResult.v1 |
| provider key-uniqueness evidence | FlowProbe.TrustCa.ProviderKeyUniqueness.v1 |
| key-journal head | FlowProbe.TrustCa.KeyJournalHead.v1 |
| complete key-ledger record chain | FlowProbe.TrustCa.KeyLedgerRecordChain.v1 |
| complete key-generation state root | FlowProbe.TrustCa.KeyGenerationStateRoot.v1 |
| destroyed terminal key evidence | FlowProbe.TrustCa.DestroyedTerminalKeyEvidence.v1 |
| key-ledger state projection | FlowProbe.TrustCa.KeyLedgerStateProjection.v1 |
| rotation dual-Ready key projection attestation | FlowProbe.TrustCa.RotationReadyKeyProjection.v1 |
| rotation Ready-projection selection record | FlowProbe.TrustCa.RotationReadyProjectionSelection.v1 |
| provider-call invocation marker | FlowProbe.TrustCa.ProviderCallInvocationMarker.v1 |
| key creation receipt | FlowProbe.TrustCa.KeyCreatedReceipt.v1 |
| key creation-unapplied receipt | FlowProbe.TrustCa.KeyCreateUnappliedReceipt.v1 |
| key creation never-started receipt | FlowProbe.TrustCa.KeyCreateNeverStartedReceipt.v1 |
| key ledger record | FlowProbe.TrustCa.KeyRecord.v1 |
| key destroyed receipt | FlowProbe.TrustCa.KeyDestroyedReceipt.v1 |
| key possession proof | FlowProbe.TrustCa.KeyPossession.v1 |
| consent receipt | FlowProbe.TrustCa.ConsentReceipt.v1 |
| signed consent-authority manifest | FlowProbe.TrustCa.ConsentAuthorityManifest.v1 |
| consent broker keyset selection ledger | FlowProbe.TrustCa.ConsentBrokerKeysetSelection.v1 |
| consent receipt verification history | FlowProbe.TrustCa.ConsentVerificationHistory.v1 |
| generated-state receipt | FlowProbe.TrustCa.GeneratedReceipt.v1 |
| installed-state receipt | FlowProbe.TrustCa.InstalledReceipt.v1 |
| drifted-state receipt | FlowProbe.TrustCa.DriftedReceipt.v1 |
| absent-state receipt | FlowProbe.TrustCa.AbsentReceipt.v1 |
| gate-closed receipt | FlowProbe.TrustCa.GateClosedReceipt.v1 |
| interception admission proof | FlowProbe.TrustCa.InterceptionAdmission.v1 |
| identity-set query response | FlowProbe.TrustCa.IdentitySetProof.v1 |

Unknown variants, fields, domains, versions, algorithms, target kinds, trust
semantics, or operation kinds fail closed.

## Certificate and key profile

LocalInterceptionCaCertificateV1 is one immutable DER certificate with:

- X.509 v3, self-issued and self-signed;
- ECDSA P-256 SubjectPublicKeyInfo and ECDSA-with-SHA-256 self-signature;
- a random, positive, minimally encoded 20-octet serial whose first octet is in
  0x01 through 0x7f and which is not reused by the installation;
- a normalized display subject identifying FlowProbe Studio and a bounded
  non-authorizing CaInstanceId suffix;
- critical BasicConstraints CA=true with pathLenConstraint=0;
- critical KeyUsage whose bit set is exactly keyCertSign;
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
identity because multiple certificates can use the same public key. That
general X.509 distinction does not authorize FlowProbe to reuse a CA key: the
installation-lifetime uniqueness rule below rejects same-SPKI/different-DER
across its own generations.

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

Every successful provider create MUST allocate a provider object, underlying
private secret, and NonExportableKeyIdentity that are pairwise non-aliasing with
every current or historical generation of the installation. A
CertificateSpkiSha256 is installation-lifetime unique: it MUST NOT equal the
SPKI of any prior Ready or Destroyed generation, including a certificate with a
different DER, serial, subject, CaInstanceId, provider label, or object wrapper.
The registered provider profile MUST expose package-internal stable object and
secret non-aliasing tags without exposing a handle or deriving a tag from raw
private bytes. Equal, missing, unstable, or incompletely enumerable tags are
not uniqueness evidence.

    InstallationLifetimeKeyUniquenessPolicyV1 {
      SchemaVersion = 1,
      Scope = InstallationLifetime,
      CertificateSpkiUnique = true,
      ProviderObjectNonAliasingRequired = true,
      ProviderSecretNonAliasingRequired = true,
      NonExportableKeyIdentityNonAliasingRequired = true,
      CompleteHistoricalGenerationCheckRequired = true
    }

InstallationLifetimeKeyUniquenessPolicyDigest is SHA-256 over the registered
provider-key-uniqueness domain, the field tag `"policy\0"`, and the canonical
policy body above. No provider-specific weakening or unknown field is accepted.

The signed product manifest also carries one closed
`KeyProviderFreshnessWindowPolicyV1` entry for every registered
KeyProviderProfileDigest:

    KeyProviderFreshnessWindowPolicyV1 {
      SchemaVersion = 1,
      KeyProviderProfileDigest,
      MaximumProviderKeyUniquenessWindow,
      MaximumCreationPossessionWindow,
      MaximumCreateNeverStartedObservationWindow,
      MaximumCreatePostCallObservationWindow,
      MaximumDestroyPostCallObservationWindow
    }

Each window is a finite, strictly positive canonical uint64 duration. The
profile digest occurs exactly once in the manifest's sorted profile vector;
zero, `UINT64_MAX`, duplicate profiles, unknown fields, or a window whose
checked addition to an applicable observation time overflows are invalid. A
proof or evidence object binds the complete manifest by
SignedProductManifestDigest, repeats its profile digest and exact window, and
uses only the formula specified for that object below. Neither a caller,
provider, key authority, nor proof signer may shorten, extend, or reinterpret
one of these first-consumption windows.

The key authority normalizes that check before the creation-possession proof:

    ProviderKeyUniquenessEvidenceV1 {
      Body = ProviderKeyUniquenessEvidenceBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.ProviderKeyUniqueness.v1,
        InstallationId,
        CaGeneration,
        CaInstanceId,
        ProviderAndVersion,
        KeyProviderProfileDigest,
        SignedProductManifestDigest,
        MaximumProviderKeyUniquenessWindow,
        KeyAuthorityEpoch,
        GenerationCommitmentDigest,
        ProviderCreateOperationId,
        ProviderCallInvocationMarkerV1,
        ProviderCallInvocationMarkerDigest,
        ProviderEchoedInvocationMarkerDigest,
        ProviderOperationFirstInvokedAt,
        CertificateSpkiSha256,
        NonExportableKeyIdentityDigest,
        ProviderObjectNonAliasingTagDigest,
        ProviderSecretNonAliasingTagDigest,
        PreCreateCompleteKeyGenerationStateRoot,
        CheckedPriorGenerationCount,
        Result = DistinctSpkiObjectSecretAndIdentityFromEveryPriorGeneration,
        observed_at,
        must_commit_by
      },
      ProviderKeyUniquenessEvidenceDigest
    }

ProviderKeyUniquenessEvidenceDigest is exactly SHA-256 over the NUL-terminated
registered provider-key-uniqueness domain, the field tag `"evidence\0"`, and
the canonical Body. The policy and evidence field tags are distinct and neither
object can be decoded in the other's preimage. The complete evidence is carried
by KeyCreatedReceiptV1 and its digest is also
bound by KeyCreationPossessionProofV1. The pre-create root and prior-generation
count MUST equal the exact selected key-ledger projection named by the
GenerationCommitmentBodyV1; every prior Ready/Destroyed SPKI and every retained
internal object/secret/NonExportableKeyIdentity tag participates in the check.
The complete marker recomputes to ProviderCallInvocationMarkerDigest, its Create
payload binds that commitment, operation, and root, and
ProviderEchoedInvocationMarkerDigest MUST equal it byte-for-byte. The provider's
first-invocation time is corroborating metadata only. Evidence observed_at and
must_commit_by form a fresh post-result first-consumption window.
SignedProductManifestDigest and KeyProviderProfileDigest MUST equal the
GenerationCommitmentBodyV1 values. The verifier resolves that complete signed
manifest from the phase plan and current keyset-selection state, requires its
digest to equal the selected envelope/state-index current manifest digest,
selects the unique matching KeyProviderFreshnessWindowPolicyV1, and
requires the repeated MaximumProviderKeyUniquenessWindow to equal it
byte-for-byte. `must_commit_by` is exactly the checked, nonwrapping sum of
observed_at and MaximumProviderKeyUniquenessWindow. It MAY be later than
GenerationCommitmentBodyV1.KeyProviderMarkerSelectionDeadline because the
timely durable marker, not this evidence or the provider timestamp, authorized
dispatch. Overflow, zero/`UINT64_MAX` window, manifest/profile substitution, a
shorter or longer deadline, or first consumption after the deadline is invalid.
The raw tags remain inside the key authority. Their domain-separated digests may
appear only in the protected key ledger, KeyCreatedReceiptV1,
KeyDestroyedReceiptV1, the typed attested KeyLedgerStateProjectionV1, and
DestroyedTerminalKeyEvidenceV1 when that complete evidence is nested in an
authenticated internal key/identity proof. They are excluded from status, log,
diagnostic, user-visible/public result, untrusted helper input, and provider-
facing objects, and an internal verifier MUST NOT re-export them.
A tag digest is exactly SHA-256 over the NUL-terminated provider-uniqueness
domain, the distinct canonical field tag `"nonexportable-identity\0"`,
`"provider-object\0"`, or `"provider-secret\0"`, and the provider profile's
canonical package-internal opaque tag bytes. The secret tag is a provider-
assigned non-secret equality handle, never a hash or encoding of private key
material. Cross-field and cross-provider tag substitution is invalid.
A collision or inability to prove completeness selects CreateAmbiguous with
KeyUniquenessCollision or KeyUniquenessEvidenceUnavailable, closes the gate,
forbids Ready, and forbids destroying either possibly aliased object until a
provider-native proof establishes which exact object and secret would be
affected. It is never normalized as an already-owned candidate or successful
rotation.

The key authority also owns one append-only installation-lifetime provider-
operation reservation ledger. It covers create and destroy IDs in one namespace
before either ID may enter a provider bootstrap query:

    ProviderOperationReservationRecordV1 {
      Body = ProviderOperationReservationRecordBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.ProviderOperationReservation.v1,
        InstallationId,
        ReservationRevision,
        ExpectedPredecessorReservationRevision,
        ExpectedPredecessorProviderOperationReservationRoot,
        TrustOperationId,
        ConsentReceiptDigest,
        PhaseRole = Generate | RemoveAndDestroy | RotatePrepare | RotateCommit,
        KeyProviderStepRole = GenerateCreate
          | RotatePrepareCandidateCreate
          | DirectRemoveAndDestroyKeyDestroy
          | RotatePrepareCandidateCleanupDestroy
          | RotateCommitOldKeyDestroy,
        ProviderOperationPurpose = Create | Destroy,
        ProviderOperationId =
            Create { ProviderCreateOperationId }
          | Destroy { KeyDestroyOperationId },
        CaGeneration,
        CaInstanceId,
        ProviderAndVersion,
        KeyProviderProfileDigest,
        ReservationSubject =
            CreateGeneration {
              CertificateProfileDigest
            }
          | DirectReadyDestroy {
              CurrentCaPublicIdentityDigest,
              LastReadyRecordDigest
            }
          | CandidateCleanupDestroy {
              CandidateCertificateProfileDigest,
              CandidateKeyProviderProfileDigest
            }
          | OldReadyDestroy {
              ActiveCaPublicIdentityDigest,
              CandidateCaPublicIdentityDigest,
              ActiveReadyRecordDigest,
              CandidateReadyRecordDigest,
              CandidateKeyBindingDigest,
              RotationTargetBindingDigest
            },
        KeyProviderSelectionDeadlineBindingV1,
        ExpectedHelperPredecessorTrustLifecycleStateDigest,
        ExpectedHelperPredecessorTrustStateRevision,
        ExpectedHelperPredecessorTrustJournalHeadDigest,
        ExpectedHelperPredecessorReplayIndexRevision,
        ExpectedHelperPredecessorConsentReplayIndexRoot,
        ExpectedHelperPredecessorReplayTimeHighWater
      },
      ProviderOperationReservationRecordDigest
    }

The record digest is exactly SHA-256 over the NUL-terminated registered
reservation domain, the field tag `"reservation-record\0"`, and the canonical
body:

    ProviderOperationReservationRecordDigest = SHA-256(
      "FlowProbe.TrustCa.ProviderOperationReservation.v1\0" ||
      "reservation-record\0" ||
      canonical(ProviderOperationReservationRecordBodyV1)
    )

ReservationRevision is the nonwrapping predecessor revision plus one. The
complete state is:

    ProviderOperationReservationStateV1 {
      ProviderOperationReservationRevision,
      CompleteProviderOperationReservationCount,
      CompleteProviderOperationReservationVector = [
        ProviderOperationReservationRecordV1
      ],
      ProviderOperationReservationRoot
    }

    ProviderOperationReservationRoot = SHA-256(
      "FlowProbe.TrustCa.ProviderOperationReservation.v1\0" ||
      "complete-vector\0" ||
      uint64_be(CompleteProviderOperationReservationCount) ||
      canonical(CompleteProviderOperationReservationVector)
    )

The vector is strictly ordered by ReservationRevision, starts at the manifest-
bound empty genesis root, contains every revision exactly once, and each record
names the immediately preceding revision/root. It is also unique by
`{TrustOperationId, PhaseRole, KeyProviderStepRole}` and, across both purpose
tags, by the raw 256-bit ProviderOperationId. The phase/step/purpose mapping is
the same closed bijection as KeyProviderSelectionDeadlineBindingV1. The
reservation subject must match its role: create roles use CreateGeneration;
direct destroy, candidate cleanup, and old-key destroy use only their
corresponding subject. All common receipt, operation, generation, instance,
provider, profile, helper-predecessor, replay, and deadline fields are byte-
identical to the verified receipt and proposed phase input.
CompleteProviderOperationReservationCount is the exact uint64 vector length.
For a nonempty vector, ProviderOperationReservationRevision equals that count
and the last record's ReservationRevision; the empty genesis uses revision zero.
Every inline record digest is independently recomputed before the complete root.

The signed manifest fixes nonzero uint64
MaximumProviderOperationReservationCount and
MaximumProviderOperationReservationEncodedBytes. Before consent consumption,
capacity accounting reserves every record the phase can stage: Generate one,
RemoveAndDestroy one, RotatePrepare two in the fixed order below, RotateCommit
one, and Install/Repair/RemoveTrust zero. The complete resulting exact uint64
count is no greater than MaximumProviderOperationReservationCount and
`len(canonical(ProviderOperationReservationStateV1))` is no greater than
MaximumProviderOperationReservationEncodedBytes. Count or canonical encoded-byte
exhaustion fails without receipt consumption or side effect; no record is
pruned, summarized, or evicted to make space.

Under the global mutation lock, allocation checks the complete current vector
plus every exact helper-staged reservation record in a selected pending
commitment/continuation that has not yet reached the key ledger. A retry of the
same receipt and `{TrustOperationId, PhaseRole, KeyProviderStepRole}` returns
only the byte-identical record and ID. A different ID for that key, the same raw
ID under another key or purpose, a missing predecessor vector, or an ID found in
any current, terminal, ambiguous, compacted, or helper-staged history is
OperationIdCollision. Random generation is not a substitute for this check.

The helper first embeds the complete proposed reservation record/digest and its
deterministically computed resulting reservation root in the GenerationCommitment
or DestroyContinuationAuthority selected with receipt consumption. That object
does not claim the reservation root was already selected. Before any provider
bootstrap, marker, provider call, or terminal phase completion, the key
authority verifies the selected helper commitment/continuation and append-
selects exactly that record. RotatePrepare proposes two consecutive records in
fixed step-role order: candidate create first and candidate-cleanup destroy
second. Its commitment binds the first record/root and its cleanup continuation
binds the second; the key authority selects both records before candidate create
bootstrap. A crash may leave only the helper-selected staged records; exact
recovery appends those same records and no allocator may bypass them. A record
grants no bootstrap, marker, create, destroy, signing, or target authority.
The reservation state uses its own checksummed copy-on-write slots and atomic
selector under the key-authority side of the global mutation lock. Recovery
accepts one complete old vector or one complete appended vector, never a partial
record, reconstructed root, or merged selector. Selection of an already staged
record has no wall-clock deadline because it is non-dispatching; after a create
marker deadline it can lead only to the never-started terminal route, never to a
late marker. An unstaged or byte-different record can never be selected merely
because its ID is unused.

Once selected, every reservation record remains forever in the complete vector,
including a create that is cancelled before marker selection and an unused
RotatePrepare candidate-cleanup destroy ID after successful RotateCommit. A
terminal/compacted ledger retains the complete canonical vector and every record
preimage, not only its root. The construction is prior reservation root ->
reservation record -> commitment/continuation -> helper pending selection ->
selection of that already-committed record in the key authority -> later
bootstrap/marker/key record; no reservation record contains a commitment,
continuation, pending-state, marker, provider result, complete consent receipt,
key-authority/provider receipt, or resulting key-journal digest. Its
ConsentReceiptDigest is only the earlier signed-consent commitment already
shown in the record body.

Every installation creates exactly two distinct nonexportable Ed25519
attestation identities before its one bootstrap selector transition:

    InstallationAttestationSignerRoleV1 =
        HelperAttestation
      | KeyAuthorityAttestation

    InstallationAttestationAnchorBodyV1 {
      SchemaVersion = 1,
      InstallationId,
      InstallationEpoch,
      InitialSignedProductManifestDigest,
      TrustCaAttestationPolicyDigest,
      HelperAttestationAlgorithm = Ed25519,
      HelperAttestationPublicKey32,
      HelperAttestationKeyId,
      HelperNonExportableKeyProviderProfileDigest,
      HelperAttestationProviderBinding =
        InstallationAttestationProviderCreatedBindingV1 {
          SignerRole = HelperAttestation
        },
      KeyAuthorityAttestationAlgorithm = Ed25519,
      KeyAuthorityAttestationPublicKey32,
      KeyAuthorityAttestationKeyId,
      KeyAuthorityNonExportableKeyProviderProfileDigest,
      KeyAuthorityAttestationProviderBinding =
        InstallationAttestationProviderCreatedBindingV1 {
          SignerRole = KeyAuthorityAttestation
        },
      AnchorCreationNonce: bytes32,
      DispositionAtGenesis = Active
    }

    InstallationAttestationAnchorDigest = SHA-256(
      "FlowProbe.TrustCa.InstallationAttestationAnchor.v1\0" ||
      "anchor-body\0" || canonical(InstallationAttestationAnchorBodyV1)
    )

    InstallationAttestationAnchorV1 {
      Body = InstallationAttestationAnchorBodyV1,
      InstallationAttestationAnchorDigest
    }

Each key ID is SHA-256 over the anchor domain, field tag `"key-id\0"`, the
canonical signer-role tag, InstallationId, uint64_be(InstallationEpoch), literal
`"Ed25519\0"`, and the canonical 32-byte public key. The two public keys and key
IDs MUST differ. Their private keys remain nonexportable and are accessible only
to their respective authenticated helper or key-authority process.
Both provider-profile digests resolve to complete manifest-policy allowed
nonexportable-key profiles for their exact roles. Each complete provider binding,
including its public key, key ID, profile, provider create operation and marker,
provider object and secret non-aliasing identities, nonexportable-key identity,
and creation receipt, equals the terminal Created event in the machine-selected
bootstrap attempt byte-for-byte. AnchorCreationNonce is a cryptographically random
256-bit value unique across every retained installation anchor; reuse is
integrity failure.

The anchor is intentionally unsigned. Its authority is the root-owned machine
InstallationNamespaceSelectorV1 Current entry, its fixed protected per-
installation selector locator, and that selector's atomic uninitialized-to-
revision-one bootstrap, not a self-signature or a
caller-supplied handshake. The selected per-installation copy-on-write slot
directly contains the complete anchor and digest and its exact slot digest
equals Current.InitialPerInstallationSelectedStateSlotDigest at bootstrap;
later selected slots are authenticated descendants through the same fixed
locator and never require a machine-namespace rewrite. Checksums detect torn writes only; security
depends on root-owned, no-follow, owner/mode/device/inode-validated protected
storage and authenticated peer identity. A cross-process verifier accepts an
anchor returned over authenticated IPC only when it is byte-identical to both
selected protected slots. An orphan anchor/bootstrap file, a checksum
recomputed after key substitution, a retired entry, or a second genesis has no
current authority.

All helper/key-authority attestations use one closed wrapper:

    InstallationAttestationSignatureContextV1 {
      SchemaVersion = 1,
      InstallationId,
      InstallationEpoch,
      InstallationAttestationAnchorDigest,
      SignedProductManifestDigest,
      TrustCaAttestationPolicyDigest,
      SignerRole = InstallationAttestationSignerRoleV1,
      Algorithm = Ed25519,
      SignerKeyId,
      TypedSignatureDomain,
      TypedBodyFieldTag,
      CanonicalTypedBodyDigest
    }

    CanonicalTypedBodyDigest = SHA-256(
      TypedSignatureDomain || TypedBodyFieldTag ||
      canonical(TypedSignatureFreeBody)
    )

    InstallationAttestationSignatureV1 {
      Context = InstallationAttestationSignatureContextV1,
      Signature = Ed25519.Sign(
        selected_role_private_key,
        "FlowProbe.TrustCa.InstallationAttestationSignature.v1\0" ||
        "signature-context\0" || canonical(Context)
      )
    }

TypedSignatureDomain is a registered NUL-terminated object domain and
TypedBodyFieldTag is the one closed tag assigned to that object/purpose. The
typed verifier recomputes the body digest, requires body/context InstallationId
equality, and requires epoch, anchor digest, manifest/policy digests, role,
algorithm, key ID, and public key to equal the current selected Active anchor
and current manifest policy. The context SignedProductManifestDigest may advance
through an authenticated compatible manifest selection while the anchor's
InitialSignedProductManifestDigest remains immutable; the policy digest and
role/profile rules must remain byte-identical. Unknown domain/tag/purpose or cross-role substitution is
invalid. When an object defines a signed-wrapper digest, it covers its
signature-free body and complete InstallationAttestationSignatureV1 under that
object's distinct signed-wrapper tag. A dual-signed receipt whose existing
semantic digest is explicitly body-only retains both complete wrappers beside
that digest. The context never contains the object digest or a
resulting journal/state object, so the graph remains acyclic.

Current authority verification requires the selected current anchor, Active
disposition, and machine namespace ActiveCurrentRetirement=None. Historical audit instead resolves the exact retained anchor,
manifest/policy, context, and object that were current at first selection; a
later Invalidated disposition does not make that old signature malformed, but
the old context can never satisfy a current-authority check.

`TypedSignedWrapperFieldTagV1` is the closed union
`NoneBodyOnly | Some { FieldTag }`. `NoneBodyOnly` means that the object has the
explicitly specified body-only semantic digest and retains the complete
attestation wrapper beside it; it is a canonical enum value, not a missing or
caller-selected tag. `Some` names the exact field tag used by the digest that
covers the signature-free body and attestation wrapper.

The one closed generic-attestation purpose registry is:

| Typed object/purpose | Signer role | TypedSignatureDomain | TypedBodyFieldTag | TypedSignedWrapperFieldTagV1 |
| --- | --- | --- | --- | --- |
| RotationPreSwitchAbortAuthorizationV1 | HelperAttestation | FlowProbe.TrustCa.HelperAttestation.v1 | `rotation-pre-switch-abort-authorization-body\0` | Some(`signed-rotation-pre-switch-abort-authorization\0`) |
| TrustJournalCompactionCheckpointV1 | HelperAttestation | FlowProbe.TrustCa.TrustJournalCompaction.v1 | `checkpoint-body\0` | Some(`signed-checkpoint\0`) |
| GateClosedReceiptV1 | HelperAttestation | FlowProbe.TrustCa.GateClosedReceipt.v1 | `receipt-body\0` | Some(`signed-receipt\0`) |
| SignerSwitchSelectionChallengeV1 | HelperAttestation | FlowProbe.TrustCa.SignerSwitchSelectionChallenge.v1 | `challenge-body\0` | Some(`signed-challenge\0`) |
| SignerSwitchReceiptV1 | HelperAttestation | FlowProbe.TrustCa.SignerSwitchReceipt.v1 | `receipt-body\0` | Some(`signed-receipt\0`) |
| GeneratedReceiptV1 | Both | FlowProbe.TrustCa.GeneratedReceipt.v1 | `receipt-body\0` | NoneBodyOnly |
| InstalledReceiptV1 | Both | FlowProbe.TrustCa.InstalledReceipt.v1 | `receipt-body\0` | NoneBodyOnly |
| DriftedReceiptV1 | Both | FlowProbe.TrustCa.DriftedReceipt.v1 | `receipt-body\0` | NoneBodyOnly |
| AbsentReceiptV1 | Both | FlowProbe.TrustCa.AbsentReceipt.v1 | `receipt-body\0` | NoneBodyOnly |
| AbsentResidualObservationReceiptV1 | Both | FlowProbe.TrustCa.AbsentResidualObservationReceipt.v1 | `receipt-body\0` | NoneBodyOnly |
| IdentitySetProofV1 | Both | FlowProbe.TrustCa.IdentitySetProof.v1 | `proof-body\0` | NoneBodyOnly |
| InterceptionAdmissionProofV1 | HelperAttestation | FlowProbe.TrustCa.InterceptionAdmission.v1 | `admission-body\0` | Some(`signed-admission-proof\0`) |
| RecoveryKeyLedgerStateProjectionV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.RecoveryKeyLedgerStateProjection.v1 | `attestation-body\0` | Some(`signed-projection\0`) |
| RotationReadyKeyProjectionAttestationV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.RotationReadyKeyProjection.v1 | `attestation-body\0` | Some(`signed-attestation\0`) |
| CreatePreCallProviderAbsenceProofV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.ProviderCreatePreCallAbsence.v1 | `attestation-body\0` | Some(`signed-proof\0`) |
| CreatePostCallProviderAbsenceProofV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.ProviderCreatePostCallAbsence.v1 | `attestation-body\0` | Some(`signed-proof\0`) |
| CreateNeverStartedProviderAbsenceProofV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.ProviderCreateNeverStartedAbsence.v1 | `attestation-body\0` | Some(`signed-proof\0`) |
| DestroyPostCallProviderAbsenceProofV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.ProviderDestroyPostCallAbsence.v1 | `attestation-body\0` | Some(`signed-proof\0`) |
| NegativeKeyPossessionResultV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.NegativeKeyPossessionResult.v1 | `attestation-body\0` | Some(`signed-result\0`) |
| KeyCreatedReceiptV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.KeyCreatedReceipt.v1 | `attestation-body\0` | Some(`signed-receipt\0`) |
| KeyCreateUnappliedReceiptV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.KeyCreateUnappliedReceipt.v1 | `attestation-body\0` | Some(`signed-receipt\0`) |
| KeyCreateNeverStartedReceiptV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.KeyCreateNeverStartedReceipt.v1 | `attestation-body\0` | Some(`signed-receipt\0`) |
| KeyDestroyedReceiptV1 | KeyAuthorityAttestation | FlowProbe.TrustCa.KeyDestroyedReceipt.v1 | `attestation-body\0` | Some(`signed-receipt\0`) |

`Both` is presentation shorthand only: the canonical policy expands that row
into one HelperAttestation entry and one KeyAuthorityAttestation entry. The v1
registry therefore has exactly 29 canonical entries. No generic attestation
wrapper exists outside this table, and an absent, extra, duplicate, or
role/domain/body-tag/wrapper-disposition substitution is invalid.

A provider-absence wrapper is available only through the typed online
provider-observation gate. Before signing a stable receipt the key authority
verifies exact helper journal ancestry, state-compatible business/envelope
preimages, and its byte-identical key-ledger projection. Unknown domains,
helper-only state, stale/mismatched projections, and arbitrary messages are
rejected. Neither attestation key may sign a CA certificate or leaf. A CA key
itself signs only the closed KeyPossessionProofV1 purposes
CreationPreReady, PostReadyGenerationVerification, StableStateSelection,
SignerSwitchCandidateSelection, and RecoveryNoneReproof, plus the admission
specialization below.
SignerSwitchCandidateSelection is accepted only through the complete
SignerSwitchKeyPossessionProofV1 defined by the rotation protocol and cannot
substitute for creation, stable-state, post-Ready, or admission possession.
RecoveryNoneReproof is accepted only through the complete
RecoveryReproofKeyPossessionProofV1 defined by RecoveryRequired(None); it binds
no resulting helper head/envelope and cannot substitute for a stable-state or
other possession proof.
The purposes, keys, domains, field tags, and verifiers are not interchangeable.
IdentitySetProofV1 and every dual-signed stable/absence receipt require one
complete wrapper from each role over the same CanonicalTypedBodyDigest. A CA-key
KeyPossessionProofV1 is not an InstallationAttestationSignatureV1 and cannot
substitute for either role.
For compactness, any later schema field still spelled `HelperSignature`,
`HelperGateClosedSignature`, `HelperSignerSwitchSignature`, or
`HelperJournalCompactionSignature` is a type alias for a complete
InstallationAttestationSignatureV1 whose role is HelperAttestation. Any later
field spelled `KeyAuthoritySignature` or `KeyAuthorityAttestationSignature` is
the corresponding KeyAuthorityAttestation wrapper. Later prose saying such a
signature “covers the body” means its generic context carries the exact typed
domain/tag and CanonicalTypedBodyDigest defined above; a raw Ed25519 signature
without the context is invalid.

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
    purpose-specific deadline = expires_at | must_commit_by | must_select_by

The verifier checks the signature with the certificate public key and requires
the public key used by the key authority to equal the certificate SPKI. A
provider lookup success, key label, handle, or public-key digest without the
fresh signature is insufficient.

InterceptionAdmissionKeyPossessionProofV1 is the one admission-purpose
specialization: the CA key signs the exact canonical signature-free
InterceptionAdmissionProofBodyV1 under
`FlowProbe.TrustCa.InterceptionAdmission.v1`, byte-identical to the body signed
by the helper. That body itself carries Purpose=InterceptionAdmission and every
identity/request/challenge/revision/deadline field. The CA signature wrapper is
not embedded or digested back into the body and grants no generic signing
surface. It is not substitutable for a KeyCreation, StableStateSelection, or
PostReadyGenerationVerification possession proof, and those proofs cannot
substitute for admission.

The creation receipt uses this explicit pre-Ready specialization rather than a
proof over the resulting Ready head:

    KeyCreationPossessionProofBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.KeyPossession.v1,
      Purpose = CreationPreReady,
      TrustOperationId,
      ConsentReceiptDigest,
      InstallationId,
      CaGeneration,
      CaInstanceId,
      CertificateDerSha256,
      CertificateSpkiSha256,
      KeyAuthorityEpoch,
      CreatingKeyStateRevision,
      CreatingKeyJournalHeadDigest,
      CreatingRecordDigest,
      GenerationCommitmentDigest,
      ProviderCreateOperationId,
      ProviderCallInvocationMarkerDigest,
      KeyCreationChallengeDigest,
      ProviderKeyUniquenessEvidenceDigest,
      PreCreateCompleteKeyGenerationStateRoot,
      SignedProductManifestDigest,
      KeyProviderProfileDigest,
      MaximumCreationPossessionWindow,
      observed_at,
      must_commit_by
    }

    KeyCreationPossessionProofV1 {
      Body = KeyCreationPossessionProofBodyV1,
      CaKeySignature
    }

CaKeySignature covers that canonical body under its SignatureDomain, and
KeyCreationPossessionProofDigest covers canonical
`{Body, CaKeySignature}` under the
registered key-possession domain. CreatingKeyStateRevision and
CreatingKeyJournalHeadDigest MUST be the exact authenticated revision/head that
contain CreatingRecordDigest. The challenge, pre-create key-generation root,
and uniqueness-policy inputs are the ones sealed in the matching
GenerationCommitmentBodyV1. ProviderCallInvocationMarkerDigest MUST equal the
timely marker embedded in the Creating ancestor and in the complete uniqueness
evidence. The complete ProviderKeyUniquenessEvidenceV1 MUST
recompute to the bound digest and name that same root, generation, provider
operation, candidate SPKI, signed manifest, and provider profile. The proof's
SignedProductManifestDigest and KeyProviderProfileDigest equal both the
GenerationCommitmentBodyV1 and complete uniqueness evidence. The verifier
selects that manifest's unique matching KeyProviderFreshnessWindowPolicyV1 and
requires MaximumCreationPossessionWindow to equal it byte-for-byte.
`must_commit_by` is exactly the canonical minimum of (a) the checked,
nonwrapping sum of observed_at and MaximumCreationPossessionWindow and (b) the
complete uniqueness evidence's recomputed must_commit_by. Overflow,
zero/`UINT64_MAX` window, a manifest/profile/window mismatch, or a caller-
selected shorter or longer value is invalid. This proof is produced after the provider result
and certificate are verified but before Ready is written, so it cannot contain
the Ready RecordDigest, Ready revision, Ready receipt, or Ready journal head. It
is first consumed only by a Ready record whose committed_at is no earlier than
observed_at and no later than must_commit_by. After that timely selection the
complete proof remains valid historical ancestry and its deadline is never
reinterpreted as current possession. A distinct fresh
KeyPossessionProofV1 with purpose PostReadyGenerationVerification binds the
committed Ready revision/head and a new helper challenge after Ready is durable;
it is never embedded in Ready or KeyCreatedReceiptV1 and retains an ordinary
per-use expires_at.

Generated and InstalledAndVerified stable selection use this other closed
purpose:

    StableStateKeyPossessionProofBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.KeyPossession.v1,
      Purpose = StableStateSelection,
      LifecycleStateTag = Generated | InstalledAndVerified,
      InstallationId,
      CaGeneration,
      CaInstanceId,
      CertificateDerSha256,
      CertificateSpkiSha256,
      QuiescentBusinessPostconditionDigest,
      MonotonicSafetyEnvelopeDigest,
      TrustStateRevision,
      TrustJournalHeadDigest,
      KeyAuthorityEpoch,
      KeyStateRevision,
      KeyJournalHeadDigest,
      KeyLedgerStateProjectionDigest,
      InterceptionGateEpoch,
      StableStateSelectionChallenge,
      SignedProductManifestDigest,
      MaximumStableStatePossessionSelectionWindow,
      observed_at,
      must_select_by
    }

    StableStateKeyPossessionProofV1 {
      Body = StableStateKeyPossessionProofBodyV1,
      CaKeySignature
    }

CaKeySignature covers that body and KeyPossessionProofDigest covers canonical
`{Body, CaKeySignature}` under the registered possession domain.
It contains no stable receipt, snapshot, selector, or resulting object digest.
The proof is constructed after the business, transition head, envelope, and
key-ledger projection are fixed and before the containing stable receipt, so its
graph is acyclic. Its observed_at is no later than the containing receipt's
committed_at. SignedProductManifestDigest equals the current selected manifest
in that envelope/state index, and
MaximumStableStatePossessionSelectionWindow equals its signed
TrustCaManifestBoundsV1 field byte-for-byte. `must_select_by` is exactly the
checked, nonwrapping sum of observed_at and that finite, nonzero window;
committed_at MUST be no later than must_select_by. Overflow, zero,
`UINT64_MAX`, a historical/current manifest substitution, or a shorter or
longer deadline is invalid. Once
that receipt/state is selected, the proof is permanently valid only as its
historical selection evidence; a later current possession check always requires
a new challenge and deadline. Drifted and Absent never use this purpose.

Leaf signing is allowed only after a valid InterceptionAdmissionProofV1. A leaf
is CA=false, contains only the exact normalized target SANs allowed by Capture
Core, carries serverAuth and digitalSignature, has a freshly generated leaf key,
and expires no later than seven days or the CA/admission deadline, whichever is
earlier. This contract does not broaden Capture Core protocol semantics.

## Normative lifecycle state

Pending failure state uses this closed non-authorizing projection:

    OperationFailedStepKeyV1 =
        OperationWide { PhaseRole }
      | TargetStep { PhaseRole, TargetId }
      | KeyStep {
          PhaseRole,
          KeyProviderStepRole,
          CaGeneration,
          CaInstanceId
        }

    FailureDispositionV1 =
        NoFailure
      | RetryScheduled {
          OperationFailedStepKeyV1,
          FailureClass = TransientPlatformFailure
            | IncompleteObservation
            | RetryableProviderStatus,
          RetryAttemptCount,
          BoundedFailureEvidenceRoot
        }
      | CompensationScheduled {
          OperationFailedStepKeyV1,
          FailureClass = ReversiblePartialFailure
            | RequiredTargetFailure
            | ProviderTerminalUnapplied,
          SelectedAuthorizedPhaseOutcome = AuthorizedPhaseOutcomeV1,
          BoundedFailureEvidenceRoot
        }

`RetryAttemptCount` is a nonzero canonical uint32 and cannot wrap. `NoFailure`
is the only initial value. A typed `FailureDispositionRefinement` may select
`NoFailure -> RetryScheduled` only with RetryAttemptCount=1, advance
RetryScheduled only by exactly one retry for the same complete phase/step key,
or select
`NoFailure | RetryScheduled -> CompensationScheduled`.
CompensationScheduled is immutable and its complete
outcome MUST be one byte-identical member of the selected phase plan. Every
RetryScheduled-to-CompensationScheduled transition retains the same complete
phase/step key. Every selected phase role and outcome resolves to the same
phase-plan entry in the pending snapshot; an operation-wide failure in one
phase cannot select another phase's compensation outcome. Every
non-NoFailure evidence root equals the complete bounded failure evidence carried
by that journal record. An ambiguous mutation, integrity/authority failure,
unknown provider outcome, or exhausted path is not encodable as ordinary retry
or compensation and instead uses the typed EnterRecoveryRequired transition.
FailureDispositionV1 grants no mutation, provider dispatch, recovery, phase, or
consent authority by itself.

Every TrustOperationJournalRecordV1 carries one closed selection identity:

    TrustJournalSelectionIdentityV1 =
        PendingOperation {
          TrustOperationId
        }
      | RecoveryWithoutPending {
          RecoverySelectionId
        }
      | ConsentAuthoritySelection {
          ConsentAuthoritySelectionId
        }

PendingOperation is valid for an InitialOperationSelection only when its
TrustOperationId equals the complete receipt, receipt-selection intent, and
phase plan byte-for-byte; every later use requires the selected predecessor or
retained pending snapshot to carry that same TrustOperationId.
RecoveryWithoutPending is valid either for the typed
EnterRecoveryWithoutPendingAuthority that first selects its fresh
RecoverySelectionId or for a later record whose selected RecoveryRequired
payload has OptionalPendingOperationSnapshot=None and carries that same ID.
It cannot appear in a consent tombstone, phase plan, provider operation,
target/key step, mutation record, or pending snapshot.
ConsentAuthoritySelection is likewise non-authorizing and is valid only for the
typed manifest/keyset selection record; it cannot substitute for either a
pending operation or recovery episode identity.

Recovery state retains complete, canonical authenticated tips and identities;
an opaque head or identity-set digest is insufficient:

    LastAuthenticatedTrustTipV1 {
      TrustStateRevision,
      TrustJournalHeadV1,
      TrustJournalHeadDigest,
      RelationToRecoveryPredecessor =
          VerifiedSelectedPredecessor
        | RetainedVerifiedAncestorOfUnverifiableSelectedTip {
            SelectedUnverifiableTrustStateRevision,
            SelectedUnverifiableTrustJournalHeadDigest
          }
    }

    LastAuthenticatedKeyTipV1 =
        VerifiedSelectedKeyTip {
          KeyAuthorityEpoch,
          KeyStateRevision,
          KeyJournalHeadDigest,
          RecoveryKeyLedgerStateProjectionV1,
          RecoveryKeyLedgerStateProjectionDigest
        }
      | RetainedVerifiedKeyAncestor {
          KeyAuthorityEpoch,
          KeyStateRevision,
          KeyJournalHeadDigest,
          KeyLedgerStateProjectionV1,
          KeyLedgerStateProjectionDigest,
          SelectedUnverifiableKeyStateRevision,
          SelectedUnverifiableKeyJournalHeadDigest,
          ObservedInvalidRecordOrProjectionDigest
        }

    KnownCaPublicIdentitySetV1 {
      KnownCaPublicIdentityCount,
      SortedUniqueKnownCaPublicIdentityVector = [
        {
          CaGeneration,
          CaInstanceId,
          CaPublicIdentityV1,
          CaPublicIdentityDigest
        }
      ],
      KnownCaIdentitySetDigest
    }

Every complete head/projection/identity and duplicated digest independently
recomputes under its registered domain. Both tip variants are closed.
VerifiedSelectedPredecessor equals the first EnterRecoveryRequired record's
selected predecessor complete trust head/revision; the retained-ancestor
variant equals the complete
RecoveryQuarantinePredecessor last-authenticated head and repeats its selected
unverifiable revision/digest. VerifiedSelectedKeyTip equals the selected
predecessor envelope and complete recovery-only key projection, including every
nonterminal or ambiguous generation. RetainedVerifiedKeyAncestor
is allowed only with a KeyLedgerIntegrity reason: its complete projection is
the latest uniquely verified ancestor, while its selected-unverifiable fields
equal the predecessor envelope and its observed-invalid digest equals that
reason. No wrapper may claim a staged or resulting recovery head as a
predecessor tip.

Both tip wrappers are retained byte-for-byte by later RecoveryRequired refresh
records; their relation is to that episode's first entry predecessor, not to a
later refresh head. KnownCaPublicIdentityCount is the exact canonical uint32 vector length and is no
greater than the signed MaximumResidualHistoricalIdentityCount. Entries are sorted uniquely by
`(CertificateSpkiSha256, CaGeneration, CaInstanceId)`; each repeated generation,
instance, DER, SPKI, and identity digest agrees with the complete
CaPublicIdentityV1. KnownCaIdentitySetDigest is the direct ARCH-002 sorted-SPKI
set digest projected from exactly this vector, never a rehash of the wrapper.
The vector is the duplicate-free union of every identity in the retained last-
quiescent/pending snapshots, the complete authenticated key tip, and complete
current recovery evidence, with no caller-added row. A same-SPKI/different-body
row, missing retained identity, count/order mismatch, digest-only entry, or
identity absent from all those complete sources is invalid.
In Drifted, KnownCaIdentitySetDigest equals the Drifted business body's direct
identity-set digest; in RecoveryRequired it equals the selected current state-
index identity set and the EnterRecoveryRequired/refresh projection.

The top-level state is this closed union:

| State | Meaning |
| --- | --- |
| Absent | No FlowProbe-owned CA key remains and every known owned trust target is verified absent; only non-authorizing terminal receipts, replay tombstones, generation high-water, and terminal no-key/key-destroyed audit records may remain |
| GeneratePending | A consented generation intent and candidate-generation commitment are durable, but key creation and exact public-identity binding are not yet terminal |
| Generated | One current CA key/certificate pair is durably verified, no trust mutation is pending, and no required target is currently claimed installed |
| InstallPending | A consented immutable install, repair, or new-CA rotation plan exists and one or more per-target or key steps are not terminal |
| InstalledAndVerified | One active CA pair and every required target have selected exact terminal business facts under the same committed receipt; each actual admission obtains separate fresh per-request key/target evidence |
| RemovePending | A consented remove, destroy, or old-CA rotation cleanup plan exists and one or more exact target/key steps are not terminal |
| Drifted | A previously stable Generated/InstalledAndVerified fact changed externally, all observed identities remain bounded, and no pending or ambiguous mutation is outstanding; the signing gate is closed |
| RecoveryRequired | Journal/key/store integrity, ownership, mutation outcome, identity-set completeness, or safe compensation cannot be proved; the signing gate is closed |

The state-index payload uses the following closed common types. No payload
contains an untyped digest vector or a second encoding of a pending operation:

    InterceptionGateDispositionV1 =
        Closed
      | ClosedDuringRotation
      | AdmissionEligible

    ConsentReceiptReferenceV1 {
      PhaseRole = Generate | Install | Repair | RemoveTrust | RemoveAndDestroy
        | RotatePrepare | RotateCommit,
      CaConsentReceiptV1,
      ConsentReceiptDigest
    }

    ConsentReceiptReferenceVectorV1 {
      ConsentReceiptReferenceCount,
      OrderedConsentReceiptReferenceVector = [ ConsentReceiptReferenceV1 ]
    }

    PendingOperationStateReferenceV1 {
      PendingLifecycleStateTag = GeneratePending | InstallPending
        | RemovePending,
      OperationKind = Generate | InitialInstall | Repair | RotateInstall
        | RemoveTrust | RemoveAndDestroy | RotateRetireOld,
      TrustOperationId,
      CompletePendingOperationSnapshotDigest
    }

The consent-reference count is the exact canonical uint32 vector length.
Entries are in phase order (the single non-rotation phase, or RotatePrepare
then RotateCommit), contain the complete signed receipt, and independently
recompute the repeated digest. Missing preimages, duplicate phases, reordered
entries, or a receipt whose operation/phase/InstallationId differs from the
enclosing pending snapshot are invalid. `PendingOperationStateReferenceV1` has
this exact tag/kind mapping: GeneratePending/Generate; InstallPending with
InitialInstall, Repair, or RotateInstall; and RemovePending with RemoveTrust,
RemoveAndDestroy, or RotateRetireOld. Its operation id and complete-snapshot
digest equal `StateEvidence.Pending.PendingOperationSnapshotV1` byte-for-byte.

The durable payloads form the closed `TrustLifecycleStatePayloadV1` union:

    Absent {
      CaGenerationHighWater,
      QuiescentBusinessPostconditionDigest,
      StableReceiptReferenceV1
    }

    GeneratePending { PendingOperationStateReferenceV1 }

    Generated {
      CurrentCaPublicIdentity = CaPublicIdentityV1,
      CurrentCaPublicIdentityDigest,
      QuiescentBusinessPostconditionDigest,
      StableReceiptReferenceV1
    }

    InstallPending { PendingOperationStateReferenceV1 }

    InstalledAndVerified {
      ActiveCaPublicIdentity = CaPublicIdentityV1,
      ActiveCaPublicIdentityDigest,
      RequiredTargetSetDigest,
      QuiescentBusinessPostconditionDigest,
      StableReceiptReferenceV1
    }

    RemovePending { PendingOperationStateReferenceV1 }

    Drifted {
      LastStableStateDigest,
      QuiescentBusinessPostconditionDigest,
      GateClosedReceiptV1,
      StableReceiptReferenceV1
    }

    RecoveryRequired {
      TrustJournalSelectionIdentityV1,
      LastAuthenticatedTrustTip = LastAuthenticatedTrustTipV1,
      LastAuthenticatedKeyTip = LastAuthenticatedKeyTipV1,
      LastQuiescentStateSnapshotV1,
      OptionalPendingOperationSnapshot = None | PendingOperationSnapshotV1,
      UnresolvedTargetVectorV1,
      BoundedReasonVectorV1,
      GateClosureEvidenceV1 =
          SignedGateClosed { GateClosedReceiptV1 }
        | AttestationAnchorInvalidated {
            AttestationAnchorInvalidationRecordV1,
            AttestationAnchorInvalidationRecordDigest
          }
    }

Every selected lifecycle state also carries one complete, canonical current
target-fact set. Its entries are:

    SelectedTargetFactStateEntryV1 {
      TargetId,
      SelectedTargetBusinessFact = TargetBusinessFactV1,
      SelectedTargetBusinessFactDigest,
      ImmutableTerminalAnchor =
          None {
            ClosedReason = NoTerminalAttempt | TargetNotYetTerminal
          }
        | Some {
            TerminalTargetBusinessFact = TargetBusinessFactV1,
            TerminalTargetBusinessFactDigest,
            TerminalTargetObservationV1,
            TerminalTargetObservationDigest
          }
    }

`SortedUniqueSelectedTargetFactStateVector` contains exactly one entry for
every TargetId represented by the selected state's target-bearing business
root, pending step vector, last-quiescent snapshot, or bounded recovery target
set, and no other entry. It is sorted strictly by TargetId. The selected fact's
complete body and digest MUST match and its TargetId MUST equal the entry key.
`Some` resolves to the unique immutable terminal fact/observation pair for that
target, with all repeated identity, target, business-fact, and observation
fields byte-identical. `None` is valid only when authenticated ancestry proves
that no terminal attempt has ever been selected for that TargetId; it cannot
erase an existing terminal anchor. Every SelectedTargetFactCount field is the
vector's exact canonical uint32 length; overflow is invalid. The vector root is
`SHA-256("FlowProbe.TrustCa.TrustLifecycleState.v1\0" ||
"selected-current-target-facts\0" || canonical_vector)`.

The selected state itself has one domain-separated, self-digest-free body:

    TrustLifecycleStateV1 {
      Body = TrustLifecycleStateBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        LifecycleStatePayload = TrustLifecycleStatePayloadV1,
        KnownCaPublicIdentities = KnownCaPublicIdentitySetV1,
        SortedUniqueSelectedTargetFactStateVector,
        SelectedTargetFactStateRoot,
        SelectedTargetFactCount,
        StateEvidence =
            Quiescent {
              QuiescentBusinessPostconditionV1,
              MonotonicSafetyEnvelopeV1,
              StableReceiptReferenceV1,
              OptionalGateClosedReceipt = None
                | Some { GateClosedReceiptV1 }
            }
          | Pending {
              PendingOperationSnapshotV1
            }
          | Recovery {
              LastQuiescentStateSnapshotV1,
              OptionalPendingOperationSnapshot = None
                | PendingOperationSnapshotV1,
              CurrentMonotonicSafetyEnvelope = MonotonicSafetyEnvelopeV1,
              GateClosureEvidenceV1
            }
      },
      TrustLifecycleStateDigest
    }

`TrustLifecycleStateDigest` is SHA-256 over the exact canonical
`TrustLifecycleStateBodyV1` under
`FlowProbe.TrustCa.TrustLifecycleState.v1`. The payload tag and StateEvidence
variant are bijective: Absent, Generated, InstalledAndVerified, and Drifted use
Quiescent; GeneratePending, InstallPending, and RemovePending use Pending; and
RecoveryRequired uses Recovery. Every complete object and duplicated digest in
StateEvidence MUST independently verify. For every quiescent state, the payload's
complete `StableReceiptReferenceV1` is byte-identical to the reference in
`StateEvidence.Quiescent`, and the payload's
`QuiescentBusinessPostconditionDigest` equals the complete inline
`QuiescentBusinessPostconditionV1` digest. The state, business, envelope, and
receipt have the same InstallationId; the receipt's state-compatible business
field equals that business digest, its envelope digest equals the complete
inline `MonotonicSafetyEnvelopeV1` digest, and its transition journal head equals
that envelope's trust-journal head. The top-level selected-target
vector/root/count is the complete current set that recomputes every
target-bearing business root.

The payload, business, receipt, key evidence, identity set, and optional gate
receipt use this exact closed compatibility matrix:

- Absent requires `AbsentBusiness`, either a standard `AbsentReceiptV1` or an
  `AbsentResidualObservationReceiptV1` with its corresponding registered domain,
  `NoLiveOrAmbiguous` key evidence, and `OptionalGateClosedReceipt=None`.
  `CaGenerationHighWater` equals the envelope field and
  `KnownCaPublicIdentities.KnownCaIdentitySetDigest` equals
  `KnownResidualCaIdentitySetDigest`. For the residual-observation receipt,
  `ResultingAbsentBusinessPostconditionDigest` is the receipt's business-binding
  field; for the standard receipt it is
  `QuiescentBusinessPostconditionDigest`.
- Generated requires `GeneratedBusiness`, `GeneratedReceiptV1`, `LiveReady`, and
  `OptionalGateClosedReceipt=None`. The payload's complete
  `CurrentCaPublicIdentityV1` independently recomputes and its digest equals both
  the payload and business `CurrentCaPublicIdentityDigest`; the state's direct
  identity-set digest equals the business `KnownCaIdentitySetDigest`.
- InstalledAndVerified requires `InstalledAndVerifiedBusiness`,
  `InstalledReceiptV1`, `LiveReady`, and `OptionalGateClosedReceipt=None`. The
  payload's complete `ActiveCaPublicIdentityV1` independently recomputes and its
  digest equals both payload and business `ActiveCaPublicIdentityDigest`;
  `RequiredTargetSetDigest` and the state's direct identity-set digest equal the
  corresponding business fields byte-for-byte.
- Drifted requires `DriftedBusiness`, `DriftedReceiptV1`, `ClosedDrifted`, and
  `OptionalGateClosedReceipt=Some`. The complete gate receipt is byte-identical
  to the payload copy, and the state's direct identity-set digest equals the
  business `KnownCaIdentitySetDigest`. `LastStableStateDigest` resolves through
  authenticated trust-journal/state-index ancestry to exactly one prior stable
  state whose quiescent business digest equals
  `LastStableBusinessPostconditionDigest`; a bare or unrelated prior state digest
  is invalid.

The standard receipt's lifecycle tag and signature domain are the exact pair for
the row above. The Absent residual receipt uses only its distinct registered
domain. A different complete receipt with the same claimed reference, a payload/
business identity or target-set mismatch, a direct identity-set mismatch, a
standard/residual Absent domain substitution, or a Drifted last-state edge that
  does not resolve to the named last-stable business is invalid. Recovery payload
  and StateEvidence carry one byte-identical `GateClosureEvidenceV1`. With
  `SignedGateClosed`, the envelope's attestation-anchor disposition is Active and
  the complete GateClosedReceiptV1 is byte-identical in both copies; its head,
  revision, envelope, and key tip equal CurrentMonotonicSafetyEnvelope. With
  `AttestationAnchorInvalidated`, the envelope disposition is Invalidated and its
  complete invalidation record/digest is byte-identical to both evidence copies
  and the selecting journal-native preimage. This second branch contains no
  current GateClosedReceiptV1; an Active/invalidation or Invalidated/signed pair,
  both branches at once, or a historical receipt substituted as current evidence
  is invalid.
RecoveryRequired's TrustJournalSelectionIdentityV1 is PendingOperation if and
only if OptionalPendingOperationSnapshot is Some, and its TrustOperationId must
equal that snapshot. It is RecoveryWithoutPending if and only if the snapshot is
None, and its RecoverySelectionId is retained unchanged through every refresh
and exit. ConsentAuthoritySelection is forbidden in a lifecycle payload.
For a pending state,
the pending snapshot's state tag, operation, envelope, and current selected
fact vector/root/count equal the state reference and this state body; the
reference's CompletePendingOperationSnapshotDigest equals the complete inline
snapshot and that snapshot's exact base resolves through authenticated ancestry
to the quiescent TrustLifecycleStateV1 whose business, envelope, receipt, and
selected fact/terminal-anchor vector are the inline
ExactBaseLastQuiescentStateSnapshot. For RecoveryRequired, the retained
LastQuiescentStateSnapshotV1 and any present PendingOperationSnapshotV1 equal
the payload copies byte-for-byte and independently verify against their own
historical vector/root/count commitments; they are not required to equal the
current top-level selected-target vector. CurrentMonotonicSafetyEnvelope is
their authenticated monotonic successor. The current top-level vector/root/
count is selected by the current recovery payload and authenticated observation/
journal successor, may differ only through an allowed recovery/residual-
observation rule, and MUST retain every historical immutable terminal anchor
from every retained snapshot byte-for-byte. `KnownCaPublicIdentities` is common
to every state tag and is the duplicate-free exact union derived from the
current business/key evidence plus all retained snapshots and terminal anchors;
no payload carries an alternate identity-set encoding. The state body contains neither its own
digest nor a receipt,
snapshot, observation, or journal object that refers to that resulting digest.
LastStableStateDigest and every other historical state digest inside a payload
are predecessor edges only. Consequently quiescent construction is
strictly context-free business facts/terminal anchors -> journal head/envelope
-> receipt/snapshot -> state body -> state digest. A pending successor instead
follows predecessor state/snapshot -> authorized journal record or residual
query/observation record -> successor head/envelope -> successor snapshot ->
state body -> state digest. No state/business/observation digest cycle is
permitted.

GeneratePending, InstallPending, and RemovePending are non-authorizing even when
every visible step appears successful. InstalledAndVerified is authorizing only
through a fresh admission proof; the state tag alone is not.

`InterceptionGateDispositionV1` is used everywhere a gate disposition is
encoded. Absent, Generated, Drifted, every pending state, and RecoveryRequired
require Closed. The RotateCommit interval after a selected signer switch and
before the resulting InstalledAndVerified receipt requires
ClosedDuringRotation. Only a fully selected InstalledAndVerified state may use
AdmissionEligible. AdmissionEligible -> Closed advances InterceptionGateEpoch
exactly once; Closed -> Closed and Closed -> ClosedDuringRotation retain the
epoch; ClosedDuringRotation -> AdmissionEligible advances it exactly once.
Every other tag/disposition or epoch delta is invalid.

The allowed transitions are:

    Absent -> Absent(ResidualObservationReconciled)
    Absent -> GeneratePending -> Generated
    Generated -> InstallPending -> InstalledAndVerified
    Generated -> RemovePending -> Absent
    InstalledAndVerified -> InstallPending(RotateInstall)
      -> RemovePending(RotateRetireOld)
      -> InstalledAndVerified
    InstalledAndVerified -> RemovePending(RemoveTrust) -> Generated
    InstalledAndVerified -> RemovePending(RemoveAndDestroy) -> Absent
    Generated | InstalledAndVerified -> InstallPending(Repair)
      -> InstalledAndVerified
    Generated | InstalledAndVerified -> Drifted
    Drifted -> InstallPending(Repair) -> InstalledAndVerified
    Drifted -> RemovePending(RemoveTrust) -> Generated
    Drifted -> RemovePending(RemoveAndDestroy) -> Absent
    GeneratePending | InstallPending | RemovePending
      -> same pending(ResidualIdentityObservationRefreshed)
    Drifted -> Drifted(ResidualIdentityObservationRefreshed)
    RecoveryRequired(SignedGateClosed)
      -> RecoveryRequired(ResidualIdentityObservationRefreshed)
    RecoveryRequired(SignedGateClosed)
      -> RecoveryRequired(AttestationAnchorInvalidated)
    Absent | Generated | InstalledAndVerified -> RecoveryRequired
    Drifted -> RecoveryRequired
    GeneratePending | InstallPending | RemovePending
      -> same pending recovery -> authorized phase outcome
        | exact base business postcondition when its recovery disposition allows
        | RecoveryRequired
    RecoveryRequired(Some pending snapshot)
      -> authorized recovery-resume pending snapshot successor
        -> sealed authorized path
        -> authorized phase outcome
          | exact base business postcondition when its recovery disposition allows
    RecoveryRequired(None pending snapshot)
      -> TrustOperationJournalRecord.RecoveryNoneReproofExit
        -> exact last-quiescent business postcondition
        under a monotonic safety-envelope successor
      | when that snapshot is Absent, residual observation reconciliation
        -> updated Absent business postcondition
          under a monotonic safety-envelope successor

Every first edge into RecoveryRequired is selected only by
TrustOperationJournalRecord.EnterRecoveryRequired. Quiescent/Drifted
predecessors use FromQuiescentOrDrifted and RecoveryWithoutPending; pending
predecessors use FromPending and retain their PendingOperation identity and
complete snapshot. An anchor-invalidation selection may also use
FromSelectedRecoveryRequired to replace only a previously signed recovery's
closure evidence and envelope disposition. RefreshRecoveryRequired is valid only
after one signed entry and can never synthesize the initial recovery state.
RecoveryRequired(AttestationAnchorInvalidated) is a fail-closed sink for this
InstallationId and has no refresh, resume, reproof, reconciliation, admission,
provider, target, key, phase, or quiescent-state successor.

A quiescent base state is Absent, Generated, InstalledAndVerified, or Drifted;
it has no pending operation. Returning to it after failure requires byte-exact
fresh proof of that same pre-operation state, including the already-closed gate
when the base was Drifted.

CandidateCaDescriptor is a closed union:

    ExistingIdentity {
      CaPublicIdentityV1,
      KeyCreatedReceiptDigest,
      RotationReadyProjection =
          NoneForGenerate
        | SelectedForRotation {
            RotationReadyKeyProjectionAttestationV1,
            RotationReadyKeyProjectionAttestationDigest,
            RotationReadyProjectionSelectionRecordV1,
            RotationReadyProjectionSelectionRecordDigest
          }
    }
  | GenerationCommitted {
      Body = GenerationCommitmentBodyV1,
      GenerationCommitmentDigest
    }

GenerationCommitmentBodyV1 is a signature-free canonical body:

    GenerationCommitmentBodyV1 {
      SchemaVersion = 1,
      DigestDomain = FlowProbe.TrustCa.GenerationCommitment.v1,
      TrustOperationId,
      InstallationId,
      CaGeneration,
      CaInstanceId,
      CertificateProfileDigest,
      KeyProviderProfileDigest,
      SignedProductManifestDigest,
      ProviderAndVersion,
      ProviderCreateOperationId,
      ProviderCreateOperationReservation = {
        ProviderOperationReservationRecordV1,
        ProviderOperationReservationRecordDigest,
        ResultingProviderOperationReservationRevision,
        ResultingProviderOperationReservationRoot
      },
      KeyCreationChallengeDigest,
      ExpectedKeyAuthorityEpoch,
      ExpectedKeyStateRevision,
      ExpectedKeyJournalHeadDigest,
      ExpectedCompleteKeyGenerationStateRoot,
      InstallationLifetimeKeyUniquenessPolicyDigest,
      ConsentReceiptDigest,
      LastHelperTrustTip,
      TrustFenceToken,
      ResidualScanUniverseRevision,
      ResidualScanUniverseDigest,
      ResidualIdentityCapacityReservationDigest,
      KeyProviderMarkerSelectionDeadline
    }

GenerationCommitmentDigest is SHA-256 over the domain-separated canonical
encoding of that body. ProviderCreateOperationId is a random non-secret
idempotency identity chosen before either ledger records an intent, unique for
the complete installation lifetime and retained as a tombstone after
compaction. It is not a
provider key handle and grants no signing authority. The selected provider MUST
be able to use it to prove after a crash that exactly zero or one key-creation
operation and exactly zero or one resulting key exist. A provider that can
only search by label, enumerate an unbounded candidate set, or create again
after an uncertain result remains unsupported.
GenerationCommitmentBodyV1.KeyProviderMarkerSelectionDeadline is the latest allowed first
selection time for the marker-bearing Creating record, not a provider-reported
invocation-time test. A marker timely selected under that deadline remains the
sole dispatch authority during exact crash recovery as defined below. It MUST
equal the deadline in the byte-identical GenerateCreate or
RotatePrepareCandidateCreate KeyProviderSelectionDeadlineBindingV1 carried by the
phase plan, recovery disposition entry, and complete key step; its receipt,
phase, generation, purpose, and step role MUST also match. A missing or
nonidentical binding invalidates the commitment before marker construction.
SignedProductManifestDigest MUST equal the complete manifest inline in that
phase's TrustPlanV1, the consent body, and the selected predecessor monotonic
envelope/state index; KeyProviderProfileDigest MUST select exactly one policy in
that manifest projection.

The complete create reservation record has purpose Create, the matching create
step role, ProviderCreateOperationId, generation/instance/provider/profile,
receipt, helper predecessor, replay fields, deadline binding, and
CreateGeneration subject byte-identical to this commitment. Its predecessor
reservation root is the selected key-authority root used to propose the record;
the resulting revision/root are recomputed from the complete predecessor vector.
For RotatePrepare, that resulting root is the predecessor of the cleanup-destroy
reservation selected in the same helper transition. The commitment permanently
binds the proposed record but does not claim it was selected before the helper
pending state; the key authority must select it under the staged-reservation rule
before CreatePreCall or bootstrap.

ExpectedKeyAuthorityEpoch/StateRevision/JournalHeadDigest and
ExpectedCompleteKeyGenerationStateRoot are the exact selected pre-create key
authority state read under the global mutation lock. The manifest-bound
InstallationLifetimeKeyUniquenessPolicyDigest fixes the SPKI, provider-object,
underlying-secret, and NonExportableKeyIdentity non-aliasing rules above. The
key authority rejects the commitment unless all five values equal its live
state and complete retained history. They are predecessor inputs only: neither
the candidate SPKI, uniqueness evidence, Creating/Ready record, nor any
resulting root is present in the commitment, preserving the order
pre-create root -> commitment -> CreatePreCall proof -> invocation marker ->
Creating -> uniqueness evidence -> creation-possession proof ->
KeyCreatedReceipt -> Ready -> successor projection.

GeneratePending and RotateInstall first persist GenerationCommitted before
contacting the key authority. InitialInstall and Repair require
ExistingIdentity. After exact certificate/profile/key-possession verification,
GeneratePending binds ExistingIdentity with RotationReadyProjection=NoneForGenerate
in its transition to Generated, while RotateInstall makes one authenticated
append-only refinement to ExistingIdentity with the complete timely selected
SelectedForRotation attestation and selection record. InitialInstall/Repair exact-identity bindings
also use NoneForGenerate. PhasePlanVectorV1 and
ConsentReceiptReferenceVectorV1 retain the immutable preparation and exact-identity
phases; an existing element is never replaced or omitted. Both vectors are
ordered and bounded: non-rotation operations have exactly one consent and one
phase plan, while rotation has exactly RotatePrepare and RotateCommit entries
after commit consent is consumed.

Generation admission has one exact acyclic preimage order. Let H0 be the
pre-transition selected TrustJournalHeadDigest; H0 MUST equal the consent
receipt/tombstone ExpectedBaseTrustJournalHeadDigest and the commitment's
LastHelperTrustTip. From selected U0, the helper purely constructs unselected
U1 by adding the capacity reservation and every plan-exact first-use residual
scope/current observer binding required by this consent phase; that scope set is
empty for no-target Generate. U1 contains no journal head, commitment, or
receipt digest and makes no other change. The helper then constructs the commitment over H0, U1's
revision/digest, and ResidualIdentityCapacityReservationDigest, the field-
tagged digest of that exact reservation entry under the residual-universe
domain. It next appends one Generate/RotatePrepare intent from H0 containing
the receipt, commitment, and U1 root, yielding H1, and stages one selector slot
containing H1, U1, the replay consumption, and the pending state. Only after
that complete slot is selected may the provider be called. No field may instead
name H1 inside the commitment. A crash selects old H0/U0 with unconsumed
consent, or new H1/U1 with the exact pending operation; it never selects a
reservation alone. A missing, different, released, or cross-operation
reservation invalidates key creation; Ready, post-dispatch CreateUnapplied, or
CreateUnappliedNeverStarted terminalization must name the same commitment and
reservation ancestry.

Every phase that can create or destroy a key seals this common deadline object
before the phase's first side effect:

    KeyProviderSelectionDeadlineBindingV1 {
      InstallationId,
      TrustOperationId,
      PhaseRole = Generate | RemoveAndDestroy | RotatePrepare | RotateCommit,
      KeyProviderStepRole =
          GenerateCreate
        | RotatePrepareCandidateCreate
        | DirectRemoveAndDestroyKeyDestroy
        | RotatePrepareCandidateCleanupDestroy
        | RotateCommitOldKeyDestroy,
      ProviderOperationPurpose = Create | Destroy,
      CaGeneration,
      CaInstanceId,
      ConsentReceiptDigest,
      ConsentReceiptIssuedAt,
      ConsentReceiptExpiresAt,
      SignedProductManifestDigest,
      ManifestKeyProviderSelectionWindow,
      SealedPhaseStepDeadline,
      SelectionDeadline =
          CreateMarkerFirstSelection {
            KeyProviderMarkerSelectionDeadline
          }
        | DestroyContinuationFirstSelection {
            DestroyContinuationSelectionDeadline
          }
    }

    KeyProviderSelectionDeadlineBindingVectorV1 {
      KeyProviderSelectionDeadlineBindingCount,
      SortedUniqueKeyProviderSelectionDeadlineBindingVector = [
        KeyProviderSelectionDeadlineBindingV1
      ]
    }

`KeyProviderSelectionDeadlineBindingCount` is the exact canonical uint32 vector
length, is no greater than
TrustCaManifestBoundsV1.MaximumProviderStepsPerPhase, and the complete canonical
phase plan is no larger than MaximumPhasePlanEncodedBytes. Entries are strictly sorted by
`(PhaseRole, KeyProviderStepRole, CaGeneration, CaInstanceId,
ProviderOperationPurpose)` and duplicate semantic keys are invalid even when
other bytes differ. Every entry repeats one InstallationId, TrustOperationId,
ConsentReceiptDigest, and SignedProductManifestDigest for its enclosing phase;
unknown roles, overflow counts, reordered entries, cross-manifest entries,
or a count/vector mismatch are malformed.
An empty vector is valid only for the exact Install, Repair, and RemoveTrust
phase matrices that contain no provider create or destroy step; Generate,
RemoveAndDestroy, RotatePrepare, and RotateCommit require their exact nonempty
role set below.

The exact signed product manifest named by SignedProductManifestDigest contains
one canonical finite strictly positive
`ManifestKeyProviderSelectionWindow` in its
TrustCaManifestBoundsV1.SortedUniqueKeyProviderSelectionWindowVector for each of
the five step roles and no other role. `SealedPhaseStepDeadline` is exactly the checked, nonwrapping
sum of the consumed receipt's `issued_at` and that role's manifest window;
overflow or a receipt/body mismatch is invalid. The timestamp carried by the
selected deadline variant is exactly the canonical minimum of
`ConsentReceiptExpiresAt` and `SealedPhaseStepDeadline`; equality at either
bound is permitted. Create roles use only CreateMarkerFirstSelection. Destroy
roles use only DestroyContinuationFirstSelection. None of these values is
supplied by the provider or caller. The
purpose and phase/step-role combinations are bijective: GenerateCreate and
RotatePrepareCandidateCreate are Create; the other three are Destroy;
GenerateCreate belongs only to Generate,
DirectRemoveAndDestroyKeyDestroy only to RemoveAndDestroy, both candidate
roles only to RotatePrepare, and RotateCommitOldKeyDestroy only to
RotateCommit.

The phase plan is this complete digest-free canonical object. No other phase,
authority, outcome, path, or step tag is decodable:

    AuthorizedPhaseOutcomeV1 =
        QuiescentTerminal {
          LifecycleStateTag = Absent | Generated
            | InstalledAndVerified | Drifted,
          BusinessPostconditionDigest
        }
      | AwaitingLaterConsent {
          LifecycleStateTag = InstallPending(RotateInstall),
          SealedPendingBusinessPostconditionDigest
        }
      | ExactBase {
          ExactBaseLifecycleStateTag = Absent | Generated
            | InstalledAndVerified | Drifted,
          ExactBaseQuiescentBusinessPostconditionDigest
        }
      | PreSignerSwitchExactOldBase {
          LifecycleStateTag = InstalledAndVerified,
          ExactOldBaseQuiescentBusinessPostconditionDigest,
          CandidateKeyDestroyedPostconditionDigest
        }

    AuthorizedPhaseOutcomeVectorV1 {
      AuthorizedPhaseOutcomeCount,
      SortedUniqueAuthorizedPhaseOutcomeVector = [ AuthorizedPhaseOutcomeV1 ]
    }

`CandidateKeyDestroyedPostconditionDigest` is the context-free key-business
projection digest over `{InstallationId, CandidateCaGeneration,
CandidateCaInstanceId, CandidateCaPublicIdentityDigest,
ExpectedTerminalKeyDisposition = DestroyedNoLiveOrAmbiguous}` under the phase-
plan domain with field tag `"candidate-key-destroyed-postcondition\0"`. It is
computable before the phase plan is sealed and contains no key record, receipt,
observation, journal, state, selector, or resulting evidence digest. At outcome
selection the complete terminal Destroyed evidence must independently verify and
project byte-for-byte to this precommitted body.

    ForwardPhaseStepV1 =
        RemoveExactOwnedTargetSet {
          ExactOrderedTargetSetDigest,
          ExpectedOwnedAbsencePostconditionRoot
        }
      | DestroyExactKey {
          KeyProviderStepRole = DirectRemoveAndDestroyKeyDestroy
            | RotatePrepareCandidateCleanupDestroy
            | RotateCommitOldKeyDestroy,
          CaGeneration,
          CaInstanceId
        }
      | RetireExactActiveTargetSet {
          ActiveRetireExactOrderedTargetSetDigest,
          ActiveRetireDispositionRoot
        }
      | SelectAuthorizedOutcome {
          AuthorizedPhaseOutcomeV1
        }
      | CompleteCandidateAbortCompensation {
          CandidateInstallExactOrderedTargetSetDigest
        }
      | DestroyRetainedCandidateKey {
          RetainedPhaseRole = RotatePrepare,
          KeyProviderStepRole = RotatePrepareCandidateCleanupDestroy
        }

    BoundedForwardPhasePathV1 {
      ForwardPhaseStepCount,
      OrderedForwardPhaseStepVector = [ ForwardPhaseStepV1 ]
    }

    ForwardOnlySelectionCommitmentV1 {
      PhaseRole = Install | Repair | RemoveTrust | RemoveAndDestroy
        | RotatePrepare | RotateCommit,
      IrreversiblePhase = SignerSwitchCommitted
        | PreSignerSwitchAbortCommitted
        | OwnedRemovalIssued
        | KeyDestroyIssued
        | SafetyReservationConsumed,
      SelectedForwardOutcome = AuthorizedPhaseOutcomeV1,
      RemainingForwardPhasePath = BoundedForwardPhasePathV1
    }

`ForwardPhaseStepCount` is the exact canonical uint32 vector length, is at most
TrustCaManifestBoundsV1.MaxForwardPhaseStepCount, and overflow is invalid. The
vector order is execution order and duplicate adjacent or non-adjacent steps
are invalid. Its last entry is exactly one `SelectAuthorizedOutcome` whose
complete outcome is byte-identical to SelectedForwardOutcome; no earlier entry
has that tag. Every `DestroyExactKey` matches the plan's one corresponding
deadline binding byte-for-byte. Target-set and disposition roots match the
phase authority binding below. Therefore a path is executable data rather than
an implementation-defined label.

    PhasePlanAuthorityBindingV1 =
        GenerateAuthority {
          CertificateProfileDigest,
          KeyProviderProfileDigest
        }
      | ExactTargetAuthority {
          PhaseRole = Install | Repair | RemoveTrust,
          CaPublicIdentityDigest,
          ExactOrderedTargetSetDigest,
          ExpectedOwnedAbsencePostconditionRoot
        }
      | DirectRemoveAndDestroyAuthority {
          SafetyReductionModeAtConsumption = FullChoice | DirectDestroyOnly,
          CurrentCaPublicIdentityDigest,
          CaGeneration,
          CaInstanceId,
          ExactOrderedTargetSetDigest,
          ExpectedOwnedAbsencePostconditionRoot,
          IntendedAbsentBusinessPostconditionDigest
        }
      | RotatePrepareAuthority {
          RequestedTargetScopeTemplateDigest,
          CandidateCertificateProfileDigest,
          CandidateKeyProviderProfileDigest,
          CandidateCaGeneration,
          CandidateCaInstanceId,
          ExactOldBaseQuiescentBusinessPostconditionDigest
        }
      | RotateCommitAuthority {
          RotationTargetBindingDigest,
          RotationPhaseGraphDigest,
          SignerSwitchPlanDigest,
          CandidateInstallExactOrderedTargetSetDigest,
          ActiveRetireExactOrderedTargetSetDigest,
          ActiveRetireDispositionRoot,
          ActiveCaGeneration,
          ActiveCaInstanceId,
          CandidateCaGeneration,
          CandidateCaInstanceId,
          IntendedNewInstalledBusinessPostconditionDigest,
          ExactOldBaseQuiescentBusinessPostconditionDigest
        }

    TrustPlanResourceGraphV1 =
        NoTargetGenerate {
          CertificateProfileDigest,
          KeyProviderProfileDigest
        }
      | ExactTargetGraph {
          SetRole = InitialInstall | Repair | RemoveTrust | RemoveAndDestroy
            | CandidateInstall | ActiveRetire,
          ImmutableTrustTargetPlanRecordCount,
          SortedUniqueImmutableTrustTargetPlanRecordVector = [
            {
              TargetId,
              ImmutableTrustTargetPlanRecordV1,
              ImmutableTrustTargetPlanRecordDigest
            }
          ],
          SortedUniqueExactDependencyEdgeVector,
          RequiredTargetBitmap,
          ExactOrderedTargetSetV1,
          ExactOrderedTargetSetDigest
        }
      | RotatePrepareTemplateGraph {
          RequestedTargetScopeTemplateV1,
          RequestedTargetScopeTemplateDigest
        }
      | RotateCommitGraph {
          CandidateInstallGraph = ExactTargetGraph(SetRole = CandidateInstall),
          ActiveRetireGraph = ExactTargetGraph(SetRole = ActiveRetire),
          RotationTargetBindingV1,
          RotationTargetBindingDigest,
          RotationPhaseGraphV1,
          RotationPhaseGraphDigest
        }

`CompleteSignedProductManifestV1` is the complete, closed, canonical signed release
manifest artifact resolved by this contract's existing product-manifest trust
root, including its body, signer identity/algorithm, and signature. Its
`SignedProductManifestDigest` is the one independently recomputed
`"manifest-body\0"` digest of its complete `SignedProductManifestBodyV1` under
the consent-authority-manifest domain. There is no alternate wrapper digest; a
locally reconstructed policy subset, digest-only reference, unsigned body, or
unknown-field extension is not this type and is invalid in a TrustPlan.

    InterceptionPolicyV1 =
        PassThroughOnly
      | PreferInterceptionWithTransparentPassThrough
      | RequireInterception

    RequestedInterceptionFallbackPolicy = InterceptionPolicyV1

    TrustPlanBodyV1 {
      SchemaVersion = 1,
      DigestDomain = FlowProbe.TrustCa.Plan.v1,
      InstallationId,
      TrustOperationId,
      PhaseRole = Generate | Install | Repair | RemoveTrust | RemoveAndDestroy
        | RotatePrepare | RotateCommit,
      IssuanceConsentBrokerKeysetSelectionRevision,
      IssuanceConsentBrokerKeysetSelectionRoot,
      IssuanceProductManifestSequence,
      IssuanceConsentBrokerKeysetEpoch,
      IssuanceConsentBrokerKeysetDigest,
      CompleteSignedProductManifestV1,
      SignedProductManifestDigest,
      TrustCapabilitySnapshotV1,
      TrustCapabilitySnapshotDigest,
      TrustPlanResourceGraphV1,
      PrivilegeAndInteractionAggregateV1,
      PrivilegeAndInteractionAggregateDigest,
      RequestedInterceptionFallbackPolicy,
      PlanExpiresAt
    }

    TrustPlanV1 {
      Body = TrustPlanBodyV1,
      TrustPlanId,
      TrustPlanDigest
    }

    TrustPlanId = SHA-256(
      "FlowProbe.TrustCa.Plan.v1\0" || "plan-id\0" ||
      canonical(TrustPlanBodyV1)
    )

    TrustPlanDigest = SHA-256(
      "FlowProbe.TrustCa.Plan.v1\0" || "plan-body\0" ||
      canonical(TrustPlanBodyV1)
    )

The resource graph is closed and complete. ExactTargetGraph vectors are strictly
sorted by TargetId, their count is the exact canonical uint32 length, and every
inline immutable record/digest equals the corresponding ExactOrderedTargetSetV1
entry byte-for-byte. Its dependency vector and required bitmap are also
byte-identical to that exact set. RotateCommitGraph contains both complete exact
graphs and the complete binding/phase graph; RotatePrepareTemplateGraph contains
the complete template rather than only its digest.
ImmutableTrustTargetPlanRecordCount and every exact target vector are no greater
than TrustCaManifestBoundsV1.MaximumTrustPlanTargetCount; the complete dependency
edge vector is no greater than MaximumTrustPlanDependencyEdgeCount; and
`len(canonical(TrustPlanBodyV1))` is no greater than
MaximumTrustPlanEncodedBytes. The signed manifest and
capability snapshot wrappers independently verify and their digests equal the
repeated fields. Unknown graph tags, digest-only target rows, omitted preimages,
duplicate targets/edges, cross-phase roles, or manifest/capability substitution
are invalid. TrustPlanId and TrustPlanDigest use distinct field tags and neither
is present in TrustPlanBodyV1.

The five Issuance fields and SignedProductManifestDigest are byte-identical to
the CaConsentReceiptV1 issuance-selection tuple for this phase. The complete
manifest is the last record of that exact selection revision/root and its
sequence, digest, keyset epoch, and keyset digest equal those repeated fields.
A plan made from a merely historical manifest, a newer selection root, or a
receipt/plan tuple mismatch is invalid even when both manifests independently
verify.

    PhasePlanBodyV1 {
      SchemaVersion = 1,
      InstallationId,
      TrustOperationId,
      PhaseRole = Generate | Install | Repair | RemoveTrust | RemoveAndDestroy
        | RotatePrepare | RotateCommit,
      TrustPlanV1,
      TrustPlanId,
      TrustPlanDigest,
      ConsentReceiptDigest,
      ExpectedBaseTrustLifecycleStateDigest,
      ExpectedBaseTrustStateRevision,
      ExpectedBaseTrustJournalHeadDigest,
      PhasePlanAuthorityBindingV1,
      AuthorizedPhaseOutcomeVectorV1,
      KeyProviderSelectionDeadlineBindingVectorV1,
      AllowedForwardOnlySelectionCommitmentCount,
      AllowedForwardOnlySelectionCommitmentVectorV1 = [
        ForwardOnlySelectionCommitmentV1
      ]
    }

    PhasePlanV1 {
      Body = PhasePlanBodyV1,
      PhasePlanDigest
    }

    PhasePlanDigest = SHA-256(
      "FlowProbe.TrustCa.PhasePlan.v1\0" || canonical(PhasePlanBodyV1)
    )

Every count is the exact canonical uint32 length of its adjacent vector and is
no greater than TrustCaManifestBoundsV1.MaximumPhasePlanCount; the complete
canonical PhasePlanBodyV1 is no larger than MaximumPhasePlanEncodedBytes.
Outcomes are sorted uniquely by their closed variant tag followed by the
complete canonical variant payload, including every old-base,
candidate-absence, and key-destroyed-postcondition field. Forward-only commitments are sorted uniquely by
`(PhaseRole, IrreversiblePhase)` and inline their complete path; duplicate
keys, digest-only path references, unknown variants, or alternate encodings are
invalid. `PhasePlanVectorV1` is the closed append-only object
`{PhasePlanCount, OrderedPhasePlanEntryVector}`, whose entries are exactly
`{PhaseRole, TrustPlanId, PhasePlanV1, PhasePlanDigest}`. PhasePlanCount is the
exact canonical uint32 vector length. Entries are ordered Generate or the single
non-rotation role, then RotatePrepare, then RotateCommit. Every repeated
body/digest/role/plan field is byte-identical; overflow, a gap, duplicate phase,
or a digest-only entry is invalid.

The authorized-outcome vector is not caller-selected. Its exact phase matrix is:

- Generate has exactly QuiescentTerminal(Generated) and ExactBase(Absent);
- Install has exactly QuiescentTerminal(InstalledAndVerified) and
  ExactBase(Generated);
- Repair has exactly QuiescentTerminal(InstalledAndVerified) and ExactBase whose
  tag and complete business digest equal the selected repair base;
- RemoveTrust has exactly QuiescentTerminal(Generated) and ExactBase whose tag
  and business digest equal the selected pre-removal base;
- RemoveAndDestroy has exactly QuiescentTerminal(Absent) and ExactBase whose tag
  and business digest equal the selected pre-removal base;
- RotatePrepare has exactly AwaitingLaterConsent(InstallPending(RotateInstall))
  and ExactBase(InstalledAndVerified) for the old active business; and
- RotateCommit has exactly QuiescentTerminal(InstalledAndVerified) for the new
  active identity and materialized target set plus one distinctly tagged
  PreSignerSwitchExactOldBase for the byte-identical old active business,
  together with the context-free candidate-key-destroyed postcondition
  commitment. The
  latter is selectable only before signer switch through the compact
  authorization below;
  generic ExactBase is forbidden for RotateCommit. Candidate key cleanup remains
  authorized only by the retained RotatePrepare entry.

Every outcome body carries the exact complete business or sealed-pending digest
from the same authority binding. Missing, extra, duplicate, cross-phase, or
same-tag/different-digest outcomes are invalid even if an implementation would
never choose them.
The inline TrustPlanV1 independently recomputes to TrustPlanId and
TrustPlanDigest; its installation, operation, phase role, authority/resource
graph, manifest, capability snapshot, privilege aggregate, fallback policy, and
expiry equal the PhasePlanBodyV1, consumed consent, and phase authority binding.
Every PhasePlanVectorV1 entry retains that same complete plan wrapper; a plan ID
or digest without its canonical body grants no authority.

Generate has exactly GenerateCreate; RemoveAndDestroy has exactly
DirectRemoveAndDestroyKeyDestroy; RotatePrepare has exactly
RotatePrepareCandidateCreate and RotatePrepareCandidateCleanupDestroy; and
RotateCommit has exactly RotateCommitOldKeyDestroy. The pre-switch abort authorization
consumes the retained RotatePrepareCandidateCleanupDestroy binding and does not
add that role to the RotateCommit deadline vector. Install, Repair, and
RemoveTrust have an empty deadline vector. A missing, duplicate, extra,
cross-phase, cross-generation, or cross-manifest member invalidates the phase
plan.

The allowed forward-only matrix is exact. Generate has an empty commitment
vector. Install and Repair each have exactly one `OwnedRemovalIssued` entry,
select ExactBase, and have path `[RemoveExactOwnedTargetSet,
SelectAuthorizedOutcome(ExactBase)]`; this is the complete reverse-
compensation path for newly owned additions and treats already absent or
pre-existing rows only through their sealed no-mutation verification. RemoveTrust
has exactly one `OwnedRemovalIssued` entry, selects Generated, and has path
`[RemoveExactOwnedTargetSet, SelectAuthorizedOutcome(Generated)]`. Direct
RemoveAndDestroy in FullChoice has exactly two entries: `OwnedRemovalIssued` with path
`[RemoveExactOwnedTargetSet, DestroyExactKey(
DirectRemoveAndDestroyKeyDestroy), SelectAuthorizedOutcome(Absent)]`, and
`KeyDestroyIssued` with path `[DestroyExactKey(
DirectRemoveAndDestroyKeyDestroy), SelectAuthorizedOutcome(Absent)]`.
DirectDestroyOnly has exactly `SafetyReservationConsumed` with path
`[RemoveExactOwnedTargetSet, DestroyExactKey(
DirectRemoveAndDestroyKeyDestroy), SelectAuthorizedOutcome(Absent)]`; receipt
consumption selects the path before any owned-removal intent, including when a
prior safety operation safely compensated back to an installed base. The
removal step is an exact bounded verification/no-op for an empty or already
absent owned set, never permission to touch external rows. RotatePrepare has
exactly `KeyDestroyIssued`, selects ExactBase,
and has path `[DestroyExactKey(RotatePrepareCandidateCleanupDestroy),
  SelectAuthorizedOutcome(ExactBase)]`. RotateCommit has exactly two mutually
  exclusive commitments. `PreSignerSwitchAbortCommitted` selects
  PreSignerSwitchExactOldBase and has path
  `[CompleteCandidateAbortCompensation(
  CandidateInstallExactOrderedTargetSetDigest),
  DestroyRetainedCandidateKey(RotatePrepare,
  RotatePrepareCandidateCleanupDestroy),
  SelectAuthorizedOutcome(PreSignerSwitchExactOldBase)]`.
  `SignerSwitchCommitted` selects the intended new InstalledAndVerified
postcondition, and has path `[RetireExactActiveTargetSet,
DestroyExactKey(RotateCommitOldKeyDestroy),
SelectAuthorizedOutcome(InstalledAndVerified)]`. The signer switch itself is
selected atomically with its receipt before that remaining path begins. Each
symbolic path above expands to the complete typed values from the same
PhasePlanBodyV1; it is not a second encoding. A phase plan contains no destroy
continuation, journal record, signer-switch receipt, resulting state, resulting
  journal head, or resulting envelope. The abort path commits only the exact
candidate set and retained cleanup role. Its runtime authorization, complete
compensation vector, exact-base facts, retained continuation/operation ID, and
resulting evidence are selected later and never appear in a phase-plan digest.

The pre-switch abort uses one compact predecessor-only authorization, one
complete coverage vector, and an independent compensation progress vector. It
does not rewrite the candidate-install terminal anchors.

    AbortCapacityChargeEntryV1 {
      ManifestBoundFieldTag,
      CheckedWorstCaseLiveValue: uint64,
      AppliedManifestMaximumValue: uint64
    }

    AbortCapacityChargeVectorV1 {
      AbortCapacityChargeCount,
      OrderedAbortCapacityChargeVector = [ AbortCapacityChargeEntryV1 ]
    }

    AbortCapacityAdmissionV1 =
        NotApplicable
      | RotateCommitAbortAdmitted {
          InitialSignedProductManifestDigest,
          CandidateTargetCount,
          CandidateScopeCount,
          AbortCapacityChargeVectorV1
        }

`RotateCommitAbortAdmitted` is selected with the RotateCommit receipt/phase and
is retained byte-for-byte by every RotateCommit pending descendant. The charge
vector contains exactly one row, in `TrustCaManifestBoundsV1` declaration order,
for every scalar count or canonical-encoded-byte maximum in that closed manifest
schema, including the replay, provider reservation, key ledger/generation,
residual scan, pending target/key/snapshot, trust-journal/compaction, recovery,
retained-attestation-history, plan, and capability dimensions. It also contains
the `MaxForwardPhaseStepCount` dimension. `ManifestBoundFieldTag` is the closed
canonical field tag from that schema; the count is exact uint32, duplicate,
missing, extra, reordered, time-window, or unknown tags are invalid. Each
AppliedManifestMaximumValue is the exact current signed-manifest value widened
without loss to uint64.

For every row, CheckedWorstCaseLiveValue is the deterministic checked Cartesian
maximum of the currently selected live data plus every legal descendant of the
pre-switch abort suffix that consumes that dimension, and is no greater than
AppliedManifestMaximumValue. The calculation includes the complete candidate
TargetId-by-scope set; largest legal source/progress/evidence rows; full fresh
exact-base query/result; compact authorization; every compensation, ambiguity,
RecoveryRequired and RecoveryResume form; replay successor; pending target and
key vectors; provider reservation, destroy intent/marker/terminal key records;
helper journal native records/links; successor snapshots; final old-base
outcome/receipt; and the retained-link/detached-record compaction projection.
A dimension not otherwise consumed by that suffix charges its exact current
selected live use, never a caller-selected zero. All counts, canonical lengths,
additions, and multiplications are checked and nonwrapping.

While the pending rotation or any abort-authorized cleanup/audit projection is
live, a successor manifest may raise a charged maximum but may not lower it
below the admission's AppliedManifestMaximumValue or the recomputed current live
floor. Actual legal descendants are checked against both the admitted worst case
and their same-named current manifest maximum before selection. Failure selects
no RotateCommit phase, target intent, journal link, or partial capacity state.
This is an admission charge against existing signed maxima, not a separate
reservation ledger, ID, digest, replay object, or mutation authority.

    CandidateAbortOwnedProgressV1 =
        RemovalNotStarted
      | RemovalIntentDurable {
          OperationTargetObservationV1,
          OperationTargetObservationDigest
        }
      | RemovalIssued {
          OperationTargetObservationV1,
          OperationTargetObservationDigest
        }
      | ExactBaseVerified {
          ResultingExactAbsentTargetBusinessFact = TargetBusinessFactV1 {
            Body.InstallerOwnershipBusinessFact = None,
            Body.BusinessDisposition = ExactAbsent
          },
          ResultingExactAbsentTargetBusinessFactDigest,
          TerminalTargetObservationV1 {
            Body.TerminalTargetStepV1 = RemovalVerifiedAbsent
          },
          TerminalTargetObservationDigest
        }
      | RemovalAmbiguous {
          BoundedTargetAmbiguityBodyV1,
          CompleteBoundedObservationDigest
        }

    CandidateAbortDerivedProgressV1 =
        WaitingForPrimaryExactBase
      | RegeneratorIntentDurable {
          OperationTargetObservationV1,
          OperationTargetObservationDigest
        }
      | RegeneratorIssued {
          OperationTargetObservationV1,
          OperationTargetObservationDigest
        }
      | ExactBaseVerified {
          ResultingExactBaseTargetBusinessFact = TargetBusinessFactV1,
          ResultingExactBaseTargetBusinessFactDigest,
          TerminalFixedRegeneratorResultReceiptV1,
          TerminalFixedRegeneratorResultReceiptDigest,
          TerminalTargetObservationV1,
          TerminalTargetObservationDigest
        }
      | RegeneratorAmbiguous {
          BoundedTargetAmbiguityBodyV1,
          CompleteBoundedObservationDigest
        }

    CandidateAbortCompensationEntryV1 =
        OwnedCompensation {
          TargetId,
          ImmutableTrustTargetPlanRecordV1,
          ImmutableTrustTargetPlanRecordDigest,
          SourceCompletePerTargetStep = CompletePerTargetStepV1 {
            PerTargetStep = VerifiedOwned,
            SelectedTargetBusinessFact = Some {
              TargetBusinessFactV1 {
                Body.InstallerOwnershipBusinessFact = FlowProbeOwnedBusiness,
                Body.BusinessDisposition = ExactPresent
              },
              TargetBusinessFactDigest
            },
            StepEvidence = TerminalObservation,
            Retryability = TerminalNoRetry
          },
          SourceCompletePerTargetStepDigest,
          OwnedPlatformItemIdentityDigest,
          CandidateAbortOwnedProgressV1
        }
      | DerivedCompensation {
          TargetId,
          ImmutableTrustTargetPlanRecordV1 {
            InstallerExecutor = DerivedBy(PrimaryAuthorityTargetId)
          },
          ImmutableTrustTargetPlanRecordDigest,
          SourceCompletePerTargetStep = CompletePerTargetStepV1 {
            PerTargetStep = VerifiedDerivedExact,
            StepEvidence = TerminalObservation,
            Retryability = TerminalNoRetry
          },
          SourceCompletePerTargetStepDigest,
          PrimaryAuthorityTargetId,
          PrimaryAuthoritySourceCompletePerTargetStepDigest,
          RequiredReverseDependencyEdge,
          CandidateAbortDerivedProgressV1
        }
      | PreservedExactBase {
          TargetId,
          ImmutableTrustTargetPlanRecordV1,
          ImmutableTrustTargetPlanRecordDigest,
          SourceCompletePerTargetStep = CompletePerTargetStepV1 {
            PerTargetStep = InstallVerifiedUnapplied,
            SelectedTargetBusinessFact = Some {
              TargetBusinessFactV1 {
                Body.InstallerOwnershipBusinessFact = None,
                Body.BusinessDisposition = ExactAbsent
              },
              TargetBusinessFactDigest
            },
            StepEvidence = TerminalObservation,
            Retryability = TerminalNoRetry
          },
          SourceCompletePerTargetStepDigest,
          ExactBaseTargetBusinessFact = TargetBusinessFactV1,
          ExactBaseTargetBusinessFactDigest,
          RequiredResult = ByteIdenticalNoMutation
        }
      | Preserved {
          TargetId,
          ImmutableTrustTargetPlanRecordV1,
          ImmutableTrustTargetPlanRecordDigest,
          SourceCompletePerTargetStep = CompletePerTargetStepV1,
          SourceCompletePerTargetStepDigest,
          PreservedTargetBusinessFact = TargetBusinessFactV1,
          PreservedTargetBusinessFactDigest,
          RequiredResult = ByteIdenticalNoMutation
        }
      | NeverAttempted {
          TargetId,
          ImmutableTrustTargetPlanRecordV1,
          ImmutableTrustTargetPlanRecordDigest,
          SourceCompletePerTargetStep = CompletePerTargetStepV1 {
            PerTargetStep = NotAttempted,
            SelectedTargetBusinessFact = None,
            StepEvidence = NoneBeforeAttempt,
            Retryability = RetrySameSealedStep,
            OptionalBoundedReason = None
          },
          SourceCompletePerTargetStepDigest
        }

    CandidateAbortExactBaseFactVectorV1 {
      ExactBaseFactCount,
      SortedUniqueExactBaseFactVector = [
        { TargetId, TargetBusinessFactV1, TargetBusinessFactDigest }
      ],
      CandidateAbortExactBaseFactRoot
    }

    CandidateAbortCompensationVectorBodyV1 {
      SchemaVersion = 1,
      TargetVectorRole = RotationAbortCompensation,
      InstallationId,
      TrustOperationId,
      RotateCommitPhasePlanDigest,
      CandidateInstallExactOrderedTargetSetDigest,
      CandidateAbortCompensationCount,
      SortedUniqueCandidateAbortCompensationVector = [
        CandidateAbortCompensationEntryV1
      ],
      ExactBaseCompletion = Incomplete
        | Complete {
            CandidateAbortExactBaseFactVectorV1,
            ResidualQueryContextV1,
            ResidualQueryContextDigest,
            ResidualScanResultV1,
            ResidualScanResultDigest
          }
    }

    CandidateAbortCompensationVectorV1 {
      Body = CandidateAbortCompensationVectorBodyV1,
      CandidateAbortCompensationVectorDigest
    }

    CandidateAbortCompensationVectorDigest = SHA-256(
      "FlowProbe.TrustCa.HelperAttestation.v1\0" ||
      "candidate-abort-compensation-vector\0" ||
      canonical(CandidateAbortCompensationVectorBodyV1)
    )

The vector count is the exact canonical uint32 length, is no greater than the
admitted candidate target count, and the vector is strictly sorted by TargetId.
It is a bijection with CandidateInstallExactOrderedTargetSetV1 and the
predecessor's `TargetVectorRole=PrimaryPhase` candidate-install vector: every
TargetId and complete immutable plan record/source step appears exactly once.
OwnedCompensation is valid only for the exact immutable VerifiedOwned terminal
anchor. DerivedCompensation is valid only when its exact `DerivedBy` edge
reverses to one OwnedCompensation entry whose source digest equals
PrimaryAuthoritySourceCompletePerTargetStepDigest; it may advance only after
that primary entry is ExactBaseVerified. A derived row whose primary is
preserved is Preserved and remains byte-identical. PreservedExactBase accepts
only an exact terminal InstallVerifiedUnapplied source whose no-owner
ExactAbsent fact equals ExactBaseTargetBusinessFact byte-for-byte; it is a
closed no-side-effect row and never becomes NotAttempted. Preserved accepts only a
terminal pre-existing/external or preserved-derived fact. NeverAttempted
accepts only its exact no-side-effect row. An intent/issued/applied/ambiguous
source row makes authorization unavailable until typed reconciliation selects
a closed row.

Only OwnedCompensation and DerivedCompensation progress. Their source
candidate-install terminal rows and observations remain byte-identical forever.
Owned progress is strictly RemovalNotStarted -> RemovalIntentDurable ->
RemovalIssued -> ExactBaseVerified, with either nonterminal edge permitted to
enter RemovalAmbiguous. Derived progress follows reverse dependency order and
is strictly WaitingForPrimaryExactBase -> RegeneratorIntentDurable ->
RegeneratorIssued -> ExactBaseVerified, with either nonterminal edge permitted
to enter RegeneratorAmbiguous. Ambiguity requires the typed RecoveryRequired
path. Skipped, reversed, cross-target, cross-primary, ordinary-target-vector,
or post-terminal advances are invalid.

Complete requires every action entry ExactBaseVerified, every Preserved or
PreservedExactBase fact byte-identical, every NeverAttempted row still side-effect-free, and one fresh
complete scan over the exact candidate scopes. The fact vector is a TargetId
bijection with the coverage vector and hashes only context-free facts. Its root
is SHA-256 under the quiescent-business domain with field tag
`"candidate-abort-exact-base-facts\0"`, exact uint32 count, and canonical sorted
vector. Missing, extra, duplicate, reordered, derived-before-primary,
same-TargetId/different-fact, incomplete enumeration, or changed preserved fact
cannot select Complete.

    RotationPreSwitchAbortAuthorizationBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.HelperAttestation.v1,
      Purpose = RotationPreSwitchAbortAuthorization,
      SignedProductManifestDigest,
      InstallationId,
      TrustOperationId,
      RotatePreparePhasePlanDigest,
      RotatePrepareConsentReceiptDigest,
      RotateCommitPhasePlanDigest,
      RotateCommitConsentReceiptDigest,
      RotationTargetBindingDigest,
      CandidateKeyBindingDigest,
      ExpectedPredecessorTrustLifecycleStateDigest,
      ExpectedPredecessorTrustStateRevision,
      ExpectedPredecessorTrustJournalHeadDigest,
      ExpectedPredecessorMonotonicSafetyEnvelopeDigest,
      ExpectedPredecessorCompletePendingOperationSnapshotDigest,
      ExpectedPredecessorReplayIndexRevision,
      ExpectedPredecessorConsentReplayIndexRoot,
      ExpectedPredecessorReplayTimeHighWater,
      ExpectedSignerSwitchSelectionEvidence = NoneBeforeSignerSwitch,
      ExpectedInterceptionGateDisposition = Closed,
      ExpectedCandidateInstallPrimaryTargetVectorDigest =
        CompletePerTargetStepVectorDigest,
      InitialCandidateAbortCompensationVectorDigest,
      AbortCapacityAdmission = RotateCommitAbortAdmitted,
      RetainedRotatePrepareCleanupDeadlineBinding,
      RetainedRotatePrepareCleanupContinuationAuthorityDigest,
      RetainedRotatePrepareCleanupSelectionRecordDigest,
      RetainedRotatePrepareCleanupProviderOperationReservationRecordDigest,
      RetainedRotatePrepareCleanupKeyDestroyOperationId,
      ExpectedRotatePrepareRecoveryDisposition = ResumeOrCompensate,
      ExpectedRotateCommitRecoveryDisposition = ResumeOrCompensate,
      SelectedRotateCommitForwardOnlyCommitment =
        ForwardOnlySelectionCommitmentV1 {
          PhaseRole = RotateCommit,
          IrreversiblePhase = PreSignerSwitchAbortCommitted
        },
      HelperSelectionNonce,
      EffectiveSelectedAt
    }

    RotationPreSwitchAbortAuthorizationV1 {
      Body = RotationPreSwitchAbortAuthorizationBodyV1,
      HelperAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = HelperAttestation,
        Context.TypedSignatureDomain = FlowProbe.TrustCa.HelperAttestation.v1,
        Context.TypedBodyFieldTag =
          "rotation-pre-switch-abort-authorization-body\0"
      },
      RotationPreSwitchAbortAuthorizationDigest
    }

    RotationPreSwitchAbortAuthorizationDigest = SHA-256(
      "FlowProbe.TrustCa.HelperAttestation.v1\0" ||
      "signed-rotation-pre-switch-abort-authorization\0" ||
      canonical({RotationPreSwitchAbortAuthorizationBodyV1,
                 HelperAttestation})
    )

The complete generic HelperAttestation context is domain/tag separated and
cannot be substituted with bootstrap, journal, gate, signer-switch, key-
authority, CA, provider, renderer, caller, other-installation, or historical-
manifest authority.

The authorization is compact and predecessor-only. Every digest resolves from
the one selected predecessor pending snapshot, its complete phase/consent/
binding/continuation vectors, current helper state/envelope/replay slot, or the
complete initial compensation vector in the selecting journal delta. The body
contains no resulting journal record/head, envelope, snapshot, state, exact-
base scan/fact root, destroy intent/marker/receipt, or any digest of those
objects. The phase plans contain neither this authorization nor its digest.
Compaction retains the complete selected predecessor snapshot, authorization,
initial compensation-vector preimage, and retained Prepare cleanup objects
until the rotation reaches a quiescent terminal receipt.

    RotationPreSwitchAbortStateV1 {
      RotationPreSwitchAbortAuthorizationV1,
      RotationPreSwitchAbortAuthorizationDigest,
      CurrentCandidateAbortCompensationVector =
        CandidateAbortCompensationVectorV1
    }

Under the global mutation lock, one RotationPreSwitchAbortSelection native
journal CAS compares the exact predecessor state/revision/head/envelope,
pending snapshot, replay coordinates, capacity admission, both recovery
entries, and NoneBeforeSignerSwitch. It atomically selects the complete compact
authorization and initial compensation vector, changes RotatePrepare from
ResumeOrCompensate to non-authorizing CleanupLockedByRotationAbort, and changes
RotateCommit from ResumeOrCompensate to the sole
ForwardOnly(PreSignerSwitchAbortCommitted) commitment. It changes no original
candidate-install terminal row. SignerSwitchSelection and abort selection use
the same exact predecessor and are mutually exclusive CAS successors.

Later abort target advances use only the independent compensation vector. A
complete exact-base vector and its fresh full scan are selected before the
retained Prepare cleanup continuation may construct a candidate-key destroy
authorization. The continuation, selection record, reservation record,
deadline, and installation-lifetime-unique KeyDestroyOperationId are exactly
the predecessor values bound by the abort authorization; no replacement or
second ID is permitted. After terminal candidate-key destruction, the single
RotateCommit PreSignerSwitchExactOldBase outcome requires the complete
Destroyed evidence and exact old-base business. There is no RotatePrepare
ForwardOnly or second phase outcome on this path. Crash recovery resumes only
the selected compensation/destroy suffix and may neither reinstall a removed
candidate target, rerun a preserved target, recreate the candidate key, nor
reach the new-installed signer-switch outcome.

Every RecoveryDispositionEntryV1 carries the complete phase-plan
KeyProviderSelectionDeadlineBindingVectorV1 byte-for-byte. Every member of
CompleteKeyStepVector carries this closed field:

    ProviderSelectionDeadline = ExactProviderOperation {
      KeyProviderSelectionDeadlineBindingV1
    }

For every marker-bearing step, the matching recovery-entry vector member and
the one complete key step selected for the same `{InstallationId,
TrustOperationId, PhaseRole, KeyProviderStepRole, CaGeneration,
CaInstanceId}` inline the byte-identical binding from
the corresponding phase plan; that key step uses ExactProviderOperation. All
other CompleteKeyStepVector members are forbidden. The vector is sorted
uniquely by that six-field key and contains exactly one entry for every planned
provider step and no unplanned/non-provider step. A phase with no provider step
has the canonical empty vector with CompleteKeyStepCount=0. A transition may advance
the step disposition but MUST retain this binding byte-for-byte. The matching
GenerationCommitmentBodyV1.KeyProviderMarkerSelectionDeadline repeats the
create variant's deadline. A destroy continuation repeats the destroy variant's
deadline. A create marker has no later deadline authority, while a destroy
marker inherits only the already-selected continuation authority defined below.

The operation step containers are also closed canonical schemas:

    CompletePerTargetStepV1 {
      InstallationId,
      TrustOperationId,
      PhaseRole,
      PhasePlanDigest,
      TargetId,
      ImmutableTrustTargetPlanRecordDigest,
      PerTargetStep = PerTargetStepV1,
      SelectedTargetBusinessFact = None
        | Some { TargetBusinessFactV1, TargetBusinessFactDigest },
      StepEvidence = PerTargetStepEvidenceV1,
      Retryability = PerTargetStepRetryabilityV1,
      OptionalBoundedReason = None
        | Some {
            BoundedRecoveryReasonKeyV1,
            BoundedRecoveryReasonV1
          }
    }

    PerTargetStepEvidenceV1 =
        NoneBeforeAttempt
        | OperationObservation {
            OperationTargetObservationV1,
            OperationTargetObservationDigest
          }
        | TerminalObservation {
            TerminalTargetObservationV1,
            TerminalTargetObservationDigest
          }
        | BoundedAmbiguity {
            BoundedTargetAmbiguityBodyV1,
            CompleteBoundedObservationDigest
          }

    PerTargetStepRetryabilityV1 =
        RetrySameSealedStep
      | RequiresTypedRecovery
      | TerminalNoRetry

    CompletePerTargetStepDigest = SHA-256(
      "FlowProbe.TrustCa.TrustOperationJournalRecord.v1\0" ||
      "complete-target-step\0" || canonical(CompletePerTargetStepV1)
    )

    CompletePerTargetStepVector {
      TargetVectorRole = PrimaryPhase,
      CompletePerTargetStepCount,
      SortedUniqueCompletePerTargetStepVector = [
        { CompletePerTargetStepV1, CompletePerTargetStepDigest }
      ]
    }

    CompletePerTargetStepVectorDigest = SHA-256(
      "FlowProbe.TrustCa.TrustOperationJournalRecord.v1\0" ||
      "complete-primary-target-step-vector\0" ||
      canonical(CompletePerTargetStepVector)
    )

`TargetVectorRole=PrimaryPhase` is required for every ordinary planned target
vector. Rotation-abort progress exists only in
CandidateAbortCompensationVectorV1 with
`TargetVectorRole=RotationAbortCompensation`; the two encodings and transition
authorities are not interchangeable.

The per-target step/evidence/retryability mapping is exact:

- NotAttempted uses NoneBeforeAttempt, has no selected fact/reason, and uses
  RetrySameSealedStep;
- IntentDurable, MutationIssued, AppliedObserved, and
  CompensationIntentDurable use OperationObservation whose CurrentStep and
  complete plan/target/operation fields equal the row, and use
  RetrySameSealedStep unless the observation itself carries a bounded ambiguity;
- MutationAmbiguous uses BoundedAmbiguity, carries exactly one matching
  AmbiguousTargetMutation reason, and uses RequiresTypedRecovery;
- VerifiedOwned, VerifiedPreExistingExact, VerifiedDerivedExact,
  InstallVerifiedUnapplied, CompensatedObserved, VerifiedAbsent,
  ExternallyRemoved, and PreservedExternal
  use TerminalObservation whose TerminalTargetStepV1 is the bijective wrapper
  for that exact step, carry the exact selected business fact, have no bounded
  reason, and use TerminalNoRetry.

ObservedOnly is preview/capability evidence only. Drifted and Failed are state or
failure-disposition projections only. None of those three tags is encodable in
a CompletePerTargetStepVector. The only ordinary forward edges are
NotAttempted -> IntentDurable or a no-mutation terminal verification;
IntentDurable -> MutationIssued or MutationAmbiguous; MutationIssued ->
AppliedObserved or MutationAmbiguous; AppliedObserved -> a phase-compatible
terminal step, CompensationIntentDurable, or MutationAmbiguous; and
CompensationIntentDurable -> CompensatedObserved or MutationAmbiguous. A
terminal row is immutable. MutationAmbiguous advances only through the typed
recovery-resolution record defined below. For InitialInstall or CandidateInstall,
fresh exact-absence/no-side-effect proof selects terminal
InstallVerifiedUnapplied and never rewrites the row to NotAttempted. Skipped,
reversed, cross-phase, or
same-step/different-evidence successors are invalid.

    CompleteKeyStepV1 {
      InstallationId,
      TrustOperationId,
      PhaseRole,
      PhasePlanDigest,
      KeyProviderStepRole,
      CaGeneration,
      CaInstanceId,
      ProviderSelectionDeadline,
      KeyStepDisposition =
          OperationReservationSelected
        | ProviderMarkerDurable
        | ProviderOutcomeAmbiguous
        | ReadyTerminal
        | CreateUnappliedTerminal
        | CreateNeverStartedTerminal
        | DestroyedTerminal,
      KeyStepEvidence =
          ProviderReservation {
            ProviderOperationReservationRecordV1,
            ProviderOperationReservationRecordDigest
          }
        | MarkerBearingKeyRecord {
            ProviderCallInvocationMarkerV1,
            ProviderCallInvocationMarkerDigest,
            CaKeyRecordV1 {
              StatePayload = Creating | DestroyPending
            },
            RecordDigest
          }
        | NativeTerminalReceipt {
            Receipt = KeyCreatedReceiptV1
              | KeyCreateUnappliedReceiptV1
              | KeyCreateNeverStartedReceiptV1
              | KeyDestroyedReceiptV1,
            NativeTerminalReceiptDigest
          }
        | AmbiguousKeyRecord {
            CaKeyRecordV1 {
              StatePayload = Ambiguous
            },
            RecordDigest
          }
    }

    CompleteKeyStepDigest = SHA-256(
      "FlowProbe.TrustCa.TrustOperationJournalRecord.v1\0" ||
      "complete-key-step\0" || canonical(CompleteKeyStepV1)
    )

    CompleteKeyStepVector {
      CompleteKeyStepCount,
      SortedUniqueCompleteKeyStepVector = [
        { CompleteKeyStepV1, CompleteKeyStepDigest }
      ]
    }

Both counts are exact canonical uint32 lengths. CompletePerTargetStepCount is no
greater than MaximumPendingTargetStepCount and the canonical target-step vector
encoding is no greater than MaximumPendingTargetStepVectorEncodedBytes;
CompleteKeyStepCount is no greater than MaximumPendingKeyStepCount and the
canonical key-step vector encoding is no greater than
MaximumPendingKeyStepVectorEncodedBytes. Target steps are sorted uniquely
by TargetId; key steps use the six-field key above. Key evidence and disposition
are bijective:

- OperationReservationSelected uses only the complete ProviderReservation;
- ProviderMarkerDurable uses only MarkerBearingKeyRecord. Create roles require
  the complete Creating record; destroy roles require the complete
  DestroyPending record. The inline record, marker, reservation, operation,
  phase/step, generation/instance, commitment or continuation, intent when
  destroying, deadline authority, and every digest are byte-identical;
- ProviderOutcomeAmbiguous uses only the complete AmbiguousKeyRecord; and
- ReadyTerminal, CreateUnappliedTerminal, CreateNeverStartedTerminal, and
  DestroyedTerminal use only NativeTerminalReceipt with respectively
  KeyCreatedReceiptV1, KeyCreateUnappliedReceiptV1,
  KeyCreateNeverStartedReceiptV1, and KeyDestroyedReceiptV1.

Every repeated operation, plan, target/key, deadline, fact, receipt, record, and
evidence field is byte-identical. There is deliberately no helper-side
IntentDurable or ProviderOperationIssued disposition: create intent and marker
are atomically observable as Creating, destroy intent and marker as
DestroyPending, and issuing the idempotent provider call does not itself create
a distinct durable helper fact. Every provider-bearing phase initializes each
planned provider step as exactly OperationReservationSelected with its complete
byte-identical ProviderOperationReservationRecordV1/evidence; this remains pre-
bootstrap and pre-marker and grants no dispatch. There is no helper
NotAttempted/NoneBeforeAttempt/NoProviderOperation encoding: absence of a
planned provider step is represented only by an empty CompleteKeyStepVector,
while every present member begins with its already selected reservation and can
never omit it. The only provider-step transitions are
OperationReservationSelected -> ProviderMarkerDurable -> its matching terminal
disposition, OperationReservationSelected -> CreateNeverStartedTerminal for the
proven no-dispatch create path, and either nonterminal provider disposition ->
ProviderOutcomeAmbiguous when the complete selected key record is Ambiguous.
Terminal and ambiguous dispositions are immutable in the pending snapshot;
resolution proceeds only through the typed recovery path.

Each RemoveAndDestroy, RotatePrepare, and RotateCommit phase additionally
selects exactly one non-dispatching destroy continuation at receipt consumption.
Its role-specific target commitment is this closed union:

    DestroyContinuationTargetCommitmentV1 =
        DirectRemoveAndDestroyTarget {
          SafetyReductionModeAtConsumption = FullChoice | DirectDestroyOnly,
          CurrentCaPublicIdentityDigest,
          LastReadyRecordDigest
        }
      | RotatePrepareCandidateTarget {
          GenerationCommitmentDigest,
          CandidateCaGeneration,
          CandidateCaInstanceId,
          CandidateCertificateProfileDigest,
          CandidateKeyProviderProfileDigest
        }
      | RotateCommitOldKeyTarget {
          ActiveCaPublicIdentityDigest,
          CandidateCaPublicIdentityDigest,
          CandidateKeyBindingDigest,
          RotationTargetBindingDigest,
          ActiveReadyRecordDigest,
          CandidateReadyRecordDigest
        }

The complete continuation is:

    DestroyContinuationAuthorityV1 {
      Body = DestroyContinuationAuthorityBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.DestroyContinuationAuthority.v1,
        InstallationId,
        TrustOperationId,
        KeyDestroyOperationId,
        DestroyAuthorityRole = DirectRemoveAndDestroy
          | RotatePrepareCandidateCleanup
          | RotateCommitOldKeyDestroy,
        PhaseRole = RemoveAndDestroy | RotatePrepare | RotateCommit,
        KeyProviderStepRole = DirectRemoveAndDestroyKeyDestroy
          | RotatePrepareCandidateCleanupDestroy
          | RotateCommitOldKeyDestroy,
        CaGeneration,
        CaInstanceId,
        ConsentReceiptDigest,
        PhasePlanDigest,
        DestroyContinuationTargetCommitmentV1,
        ProviderDestroyOperationReservation = {
          ProviderOperationReservationRecordV1,
          ProviderOperationReservationRecordDigest,
          ResultingProviderOperationReservationRevision,
          ResultingProviderOperationReservationRoot
        },
        AllowedForwardOnlySelectionCommitmentCount,
        AllowedForwardOnlySelectionCommitmentVectorV1 = [
          ForwardOnlySelectionCommitmentV1
        ],
        KeyProviderSelectionDeadlineBindingV1,
        PredecessorStateAnchor =
            QuiescentPredecessor {
              ExpectedPredecessorTrustLifecycleStateDigest,
              ExpectedPredecessorLastQuiescentStateSnapshotDigest
            }
          | PendingPredecessor {
              ExpectedPredecessorTrustLifecycleStateDigest,
              ExpectedPredecessorCompletePendingOperationSnapshotDigest
            },
        ExpectedPredecessorTrustStateRevision,
        ExpectedPredecessorTrustJournalHeadDigest,
        ExpectedPredecessorMonotonicSafetyEnvelopeDigest,
        ExpectedPredecessorReplayIndexRevision,
        ExpectedPredecessorConsentReplayIndexRoot,
        ExpectedPredecessorReplayTimeHighWater,
        ExpectedKeyAuthorityEpoch,
        ExpectedPredecessorKeyStateRevision,
        ExpectedPredecessorKeyJournalHeadDigest,
        ExpectedPredecessorCompleteKeyGenerationStateRoot,
        CurrentObservedTime,
        EffectiveSelectedAt
      },
      DestroyContinuationAuthorityDigest
    }

    DestroyContinuationAuthorityDigest = SHA-256(
      "FlowProbe.TrustCa.DestroyContinuationAuthority.v1\0" ||
      canonical(DestroyContinuationAuthorityBodyV1)
    )

    DestroyContinuationSelectionRecordV1 {
      Body = DestroyContinuationSelectionRecordBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.DestroyContinuationSelection.v1,
        DestroyContinuationAuthorityV1,
        DestroyContinuationAuthorityDigest,
        ConsentReceiptDigest,
        PhasePlanDigest,
        ExpectedPredecessorTrustLifecycleStateDigest,
        ExpectedPredecessorTrustStateRevision,
        ExpectedPredecessorTrustJournalHeadDigest,
        ExpectedPredecessorMonotonicSafetyEnvelopeDigest,
        ExpectedPredecessorReplayIndexRevision,
        ExpectedPredecessorConsentReplayIndexRoot,
        ExpectedPredecessorReplayTimeHighWater,
        CurrentObservedTime,
        EffectiveSelectedAt
      },
      DestroyContinuationSelectionRecordDigest
    }

`DestroyContinuationSelectionRecordDigest` is
`SHA-256("FlowProbe.TrustCa.DestroyContinuationSelection.v1\0" ||
canonical(DestroyContinuationSelectionRecordBodyV1))`. Every duplicated field in the selection
record and authority is byte-identical. EffectiveSelectedAt is
`max(CurrentObservedTime, ExpectedPredecessorReplayTimeHighWater)` under the
manifest clock-rollback rule and MUST be no later than the binding's
DestroyContinuationSelectionDeadline. The selected predecessor state/snapshot,
journal head/revision, safety envelope, replay body/root/revision/high-water,
and key root/head/revision MUST all independently resolve and match. A first
RemoveAndDestroy or RotatePrepare phase uses QuiescentPredecessor; RotateCommit
uses the exact current RotatePrepare PendingPredecessor. The three authority
roles map bijectively to their phase, step role, target-commitment variant, and
allowed ForwardOnly matrix. The count/vector are byte-identical to the complete
matching PhasePlanBodyV1. Direct FullChoice therefore retains both distinct
`OwnedRemovalIssued` and `KeyDestroyIssued` commitments; DirectDestroyOnly,
RotatePrepare, and RotateCommit retain their one exact commitment. The
continuation preselects no member and grants no outcome by itself. A later
ForwardOnly journal record selects exactly one complete byte-identical vector
member; synthesizing a new phase, outcome, path, or step is invalid.
The provider reservation record independently verifies and its purpose,
phase/step role, KeyDestroyOperationId, generation/instance subject, receipt,
deadline binding, and predecessor reservation revision/root are byte-identical
to the continuation and its selected phase plan. Its resulting revision/root
equal the complete reservation wrapper. RotatePrepare candidate cleanup uses
the reservation successor selected in the same initial transition after the
candidate-create reservation, without referring back to a later generation
commitment. A missing, reused, cross-purpose, or nonidentical reservation
invalidates the continuation before selection.

    DestroyContinuationAuthorityVectorV1 {
      DestroyContinuationAuthorityCount,
      OrderedDestroyContinuationAuthorityVector = [
        {
          PhaseRole = RemoveAndDestroy | RotatePrepare | RotateCommit,
          DestroyContinuationAuthorityV1,
          DestroyContinuationAuthorityDigest,
          DestroyContinuationSelectionRecordV1,
          DestroyContinuationSelectionRecordDigest
        }
      ]
    }

The count is the exact canonical uint32 vector length. The vector has exactly
one row for each consumed destroy-bearing phase and none for other phases; it is
ordered RemoveAndDestroy or RotatePrepare then RotateCommit. Complete bodies and
digests independently verify, the selection record selects the adjacent
authority, and every repeated operation, phase, plan, receipt, deadline,
provider reservation, key subject, target commitment, allowed-forward matrix,
and reserved KeyDestroyOperationId is byte-identical. A count mismatch,
digest-only row, missing or extra phase, duplicate semantic key, or reordered
rotation row is invalid.

Under the global mutation lock, receipt/tombstone consumption, phase-plan and
recovery-entry selection, complete key-step initialization, the continuation
selection record, replay-time successor, and resulting pending state/snapshot
are one copy-on-write selector transition. The selection record is the typed
native continuation evidence nested in the typed ReceiptAndPhaseSelection
TrustOperationJournalRecordV1, and that complete helper record/digest is
retained in OperationJournalAnchorVectorV1. `KeyDestroyOperationId` is allocated before
that transition, is installation-lifetime unique against the complete retained
key/provider-operation history, and is permanently reserved by the selected
continuation even if no intent is ever constructed. A collision, late
selection, incomplete predecessor, or mismatched target/outcome/path rejects the
phase before any side effect. The continuation is not a provider marker,
bootstrap input, destroy intent, or dispatch authority. Neither its body nor its
selection record contains the resulting pending state/snapshot digest,
resulting helper journal head/envelope/replay root, ForwardOnly authorization,
destroy intent, marker, or key record. PhasePlanDigest likewise does not contain
or refer to either continuation digest. The construction is therefore
    receipt/phase plan and any role-specific predecessor commitment -> provider
    operation reservation -> continuation body/selection record -> receipt/phase
    helper journal record -> resulting pending state -> later ForwardOnly selection.
Once timely selected, the continuation remains immutable historical authority
after its deadline only to select the exact expected ForwardOnly disposition,
construct the bound destroy intent with its reserved operation ID, and continue
that sealed path. It never expires into broader authority and cannot authorize
a different target, outcome, operation ID, plan, or provider dispatch by itself.

`DestroyContinuationAuthorityVectorV1` is sorted uniquely by
`{PhaseRole, KeyProviderStepRole}` and inlines each complete authority/digest and
selection record/digest. RemoveAndDestroy and RotatePrepare pending snapshots
contain exactly their one entry. After RotateCommit consumption, rotation
snapshots retain the RotatePrepare entry byte-for-byte and append exactly the
RotateCommit entry. Generate, Install, Repair, and RemoveTrust have no entry.

OptionalPendingOperationSnapshot is None only when no operation was pending.
Otherwise it is PendingOperationSnapshotV1:

    OperationJournalAnchorVectorV1 {
      OperationJournalAnchorCount,
      OrderedOperationJournalAnchorEntryVector = [
        {
          TrustOperationJournalRecordV1 {
            RequiredDelta = ReceiptAndPhaseSelection
          },
          TrustOperationJournalRecordDigest
        }
      ]
    }

OperationJournalAnchorCount is the exact canonical uint32 vector length and is
bounded by the phase-plan maximum. Entries are ordered by phase-plan order and
then EffectiveSelectedAt; each digest recomputes from its complete body.

    CandidateCurrentRetiringIdentityOrCommitmentEntryV1 =
        CandidateGenerationCommitment {
          Role = Candidate,
          GenerationCommitmentBodyV1,
          GenerationCommitmentDigest
        }
      | CandidateExistingIdentity {
          Role = Candidate,
          CaPublicIdentityV1,
          KeyCreatedReceiptDigest,
          RotationReadyProjection = NoneForGenerate
            | SelectedForRotation {
                RotationReadyKeyProjectionAttestationV1,
                RotationReadyKeyProjectionAttestationDigest,
                RotationReadyProjectionSelectionRecordV1,
                RotationReadyProjectionSelectionRecordDigest
              }
        }
      | CurrentIdentity {
          Role = Current,
          CaPublicIdentityV1,
          ReadyRecordDigest,
          StableReceiptDigest
        }
      | RetiringIdentity {
          Role = Retiring,
          CaPublicIdentityV1,
          ReadyRecordDigest,
          ActiveInstalledReceiptDigest,
          ActiveRetireExactOrderedTargetSetDigest
        }

    CandidateCurrentRetiringIdentityOrCommitmentVectorV1 {
      CandidateCurrentRetiringIdentityOrCommitmentCount,
      SortedUniqueCandidateCurrentRetiringIdentityOrCommitmentVector = [
        CandidateCurrentRetiringIdentityOrCommitmentEntryV1
      ]
    }

The count is the exact canonical uint32 vector length, is at most two, and its
complete encoding is included in the signed
MaximumPendingOperationSnapshotEncodedBytes check. Entries are sorted
by `(Role tag, CaGeneration, CaInstanceId)` with role order Current, Candidate,
Retiring; duplicate roles or identities are invalid. GeneratePending has exactly
one Candidate entry; ordinary InstallPending has exactly one Current entry;
RotateInstall has exactly Current then Candidate; direct RemovePending has
exactly Current; RotateRetireOld has exactly Current then Retiring. A candidate
is represented by exactly one commitment or existing-identity variant, never
both. Every complete commitment, public identity, receipt, Ready record,
attestation, selection record, and target-set digest equals the corresponding
CandidateCaDescriptor, selected key-ledger projection, phase plan, and lifecycle
payload byte-for-byte. Unknown tags, count/order mismatch, digest-only identities,
or current/candidate/retiring substitution are invalid.

    PendingOperationSnapshotV1 {
      Body = PendingOperationSnapshotBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        PendingLifecycleStateTag = GeneratePending | InstallPending
          | RemovePending,
        TrustOperationId,
        OperationKind,
        BaseQuiescentBusinessPostconditionDigest,
        ExactBaseLastQuiescentStateSnapshotDigest,
        ExactBaseStableReceiptDomain,
        ExactBaseStableReceiptDigest,
        CandidateCurrentRetiringIdentityOrCommitmentVectorV1,
        ConsentReceiptReferenceVectorV1,
        PhasePlanVectorV1,
        RecoveryDispositionVectorV1,
        DestroyContinuationAuthorityVectorV1,
        AbortCapacityAdmission = AbortCapacityAdmissionV1,
        SignerSwitchSelectionEvidence =
            NoneBeforeSignerSwitch
          | SelectedSignerSwitch {
              SignerSwitchPlanV1,
              SignerSwitchPlanDigest,
              SignerSwitchReceiptV1,
              SignerSwitchReceiptDigest
            },
        OptionalRotationPreSwitchAbortState = None
          | Some { RotationPreSwitchAbortStateV1 },
        TrustFenceToken,
        CompletePerTargetStepVector,
        CompleteKeyStepVector,
        SortedUniqueSelectedTargetFactStateVector,
        SelectedTargetFactStateRoot,
        SelectedTargetFactCount,
        FailureDisposition = FailureDispositionV1,
        OperationJournalAnchorVectorV1,
        PendingSnapshotLineage =
            InitialPendingSelection
          | AuthorizedOperationSuccessor {
              PredecessorCompletePendingOperationSnapshotDigest,
              TrustOperationJournalRecordV1,
              TrustOperationJournalRecordDigest
            }
          | ResidualObservationSuccessor {
              PredecessorCompletePendingOperationSnapshotDigest,
              ResidualIdentityObservationRecordV1,
              ResidualIdentityObservationRecordDigest
            }
      },
      PendingOperationSnapshotBodyDigest,
      ExactBaseLastQuiescentStateSnapshot = LastQuiescentStateSnapshotV1,
      SnapshotSafetyEnvelope = {
        Body = MonotonicSafetyEnvelopeBodyV1,
        MonotonicSafetyEnvelopeDigest
      },
      CompletePendingOperationSnapshotDigest
    }

PendingOperationSnapshotBodyDigest covers only the canonical digest-free body
under the registered pending-snapshot-body domain.
`len(canonical(PendingOperationSnapshotV1))` is no greater than the current
signed manifest's MaximumPendingOperationSnapshotEncodedBytes. The target/key
vector limits and this whole-snapshot limit are all checked with nonwrapping
size arithmetic before selecting an initial or successor snapshot. Exceeding
any limit leaves the complete predecessor selected and creates no partial
journal, replay, envelope, or state update.
CompletePendingOperationSnapshotDigest is the registered complete-snapshot-
domain digest of exactly this signature-free canonical commitment body:

    CompletePendingOperationSnapshotCommitmentBodyV1 {
      SchemaVersion = 1,
      InstallationId,
      PendingOperationSnapshotBodyDigest,
      ExactBaseLastQuiescentStateSnapshotDigest,
      ExactBaseStableReceiptDomain,
      ExactBaseStableReceiptDigest,
      SelectedTargetFactStateRoot,
      SelectedTargetFactCount,
      SnapshotSafetyEnvelopeDigest = MonotonicSafetyEnvelopeDigest
    }

The complete snapshot wrapper carries bodies for independent verification;
every duplicated field/digest MUST match this commitment. The inline exact-base
last-quiescent snapshot MUST independently verify, its digest MUST equal
ExactBaseLastQuiescentStateSnapshotDigest, its business digest MUST equal
BaseQuiescentBusinessPostconditionDigest, and its registered receipt domain and
digest MUST equal ExactBaseStableReceiptDomain/ExactBaseStableReceiptDigest.
The selected-target vector is complete for the pending state, has the declared
count, and hashes to SelectedTargetFactStateRoot. Neither complete digest is
inside its own preimage. OperationJournalAnchorVectorV1 is ordered by matching
phase-plan order and then the helper record's
`{EffectiveSelectedAt, TrustOperationJournalRecordDigest}`, and inlines
every complete immutable ReceiptAndPhaseSelection
TrustOperationJournalRecordV1 plus its recomputed digest. It contains exactly
one entry per consumed phase, including each applicable native
DestroyContinuationSelectionRecordV1 inside that record's delta, and never
contains the changing current journal head. InitialPendingSelection is valid only for
the first selected snapshot of that pending operation. Every successor names
the immediately preceding complete snapshot in that pending operation's
authenticated snapshot lineage. Ordinarily it is the selected Pending state's
snapshot; a RecoveryRequired(Some) exit instead names the byte-identical
retained pending snapshot in that selected recovery state.
AuthorizedOperationSuccessor additionally inlines the exact complete typed
helper journal record and recomputed digest for one transition already
authorized by the sealed operation. Its TrustOperationJournalDeltaV1 MUST be
exactly one allowed subsequent-rotation ReceiptAndPhaseSelection,
candidate-descriptor refinement, target step, key step, terminal-evidence first
selection, ForwardOnly selection, pre-switch-abort selection, abort-
compensation advance or exact-base completion, recovery-resume, signer-switch,
rotation-retire phase advance, failure refinement, or phase-outcome selection;
the record's
operation, plan/consent authority, predecessor snapshot, expected revisions,
and exact changed fields MUST match. Candidate Ready selection during rotation
uses its complete authorized selection record here. The record may change only
the candidate descriptor, append/refine the exact authorized consent/phase and
its atomically selected destroy continuation, target step, key step, recovery
disposition, failure disposition, or immutable
journal-anchor entry permitted by that transition; the operation identity, base
snapshot/receipt, and every unrelated or already-terminal element are retained
byte-for-byte. A subsequent-rotation ReceiptAndPhaseSelection is valid only for
the same TrustOperationId after the byte-identical RotatePrepare anchor: its
PendingSelectionKind is SubsequentRotationPhaseSelection, its required
predecessor digest is this lineage predecessor, and it appends exactly the
RotateCommit consent, phase plan, recovery entry, candidate-install steps,
old-key continuation and immutable operation-journal anchor without replacing
or reordering any RotatePrepare field. InitialOperationSelection is valid only
with no pending predecessor and can never be reused for RotateCommit. An
unknown record kind, untyped digest, skipped predecessor,
caller-selected field change, or authority broadening is invalid.
TrustOperationJournalRecordDigest is that complete typed record's registered-
domain digest, not a native evidence digest or a rehash under either snapshot
domain.
The authorized successor also advances SnapshotSafetyEnvelope and
PendingSnapshotLineage. Its selected-target fact vector/root/count changes only
when the named target/derived-step record deterministically selects that exact
current fact; otherwise those fields remain byte-for-byte identical.
ResidualObservationSuccessor instead names the exact
ResidualIdentityObservationRecordV1 that caused an observation-only successor,
inlines its complete digest-free body, and repeats its recomputed registered-
domain digest. A digest-only reference, unresolved external lookup, or body/
digest mismatch is invalid even after compaction.
It retains InstallationId, pending tag, operation, base snapshot/receipt,
candidate/identity vector, consent vector, phase plans, recovery dispositions,
destroy continuations, capacity admission, optional abort state,
signer-switch selection evidence,
fence, all planned target/key steps, failure disposition, and
OperationJournalAnchorVectorV1 byte-for-byte; only the current selected-
target fact vector/root/count, SnapshotSafetyEnvelope, and forward lineage may
change. RotationPreSwitchAbortSelection additionally makes its exact atomic
two-entry recovery refinement and initializes OptionalRotationPreSwitchAbortState;
its later dedicated deltas may change only that state's independent
compensation vector and the fact selected by the same completed abort row. Each
predecessor complete snapshot and successor record digest is an
ancestor only. Neither record nor its predecessor contains the resulting
snapshot body/digest, envelope digest, state digest, or journal head.
Construction is therefore predecessor snapshot -> authorized operation record
or query context/scan/residual-observation record -> successor journal
head/envelope -> successor snapshot -> successor state, with no reverse edge.
All duplicated fence, revision, receipt, plan, identity, and ancestor fields
must agree.
RecoveryRequired cannot lose, replace, or broaden the retained operation core;
a later safety envelope may only be an authenticated successor of
SnapshotSafetyEnvelope.

AbortCapacityAdmission is NotApplicable before RotateCommit and for every
non-rotation operation. The SubsequentRotationPhaseSelection that appends
RotateCommit MUST select RotateCommitAbortAdmitted before initializing the
CandidateInstall PrimaryPhase vector or any target intent. It remains
byte-identical until the rotation reaches a quiescent terminal, including after
signer switch. OptionalRotationPreSwitchAbortState is None before the abort CAS
and remains None after signer switch; only RotationPreSwitchAbortSelection may first change it
to Some. Every abort successor retains the complete authorization byte-for-byte
and may change only the independent current compensation vector through its
typed journal delta.

RecoveryDispositionVectorV1 is ordered exactly like PhasePlanVectorV1 and has one
entry for each consumed consent phase:

    RecoveryDispositionVectorV1 {
      RecoveryDispositionCount,
      OrderedRecoveryDispositionVector = [ RecoveryDispositionEntryV1 ]
    }

    RecoveryDispositionEntryV1 {
      PhaseRole = Generate | Install | Repair | RemoveTrust | RemoveAndDestroy
        | RotatePrepare | RotateCommit,
      PhasePlanDigest,
      ConsentReceiptDigest,
      KeyProviderSelectionDeadlineBindingVectorV1,
      InitialDisposition = RecoveryDispositionV1,
      OptionalDispositionRefinement = None
        | ForwardOnly
        | CleanupLockedByRotationAbort
    }

RecoveryDispositionCount is the exact canonical uint32 vector length and equals
the matching PhasePlanVectorV1.PhasePlanCount. Each entry's phase/plan/receipt
equals the same-position complete phase plan and consent reference. Missing,
extra, duplicate, reordered, digest-only, or cross-operation rows are invalid.

A non-rotation operation has exactly one entry. Rotation has exactly one after
RotatePrepare; consuming RotateCommit atomically appends its second entry before
the first RotateCommit-authorized side effect through the exact
SubsequentRotationPhaseSelection/AuthorizedOperationSuccessor lineage defined
above. The RotatePrepare entry is never
broadened to contain install, signer-switch, active-retire, or old-key-destroy
authority. InitialDisposition is ResumeOrCompensate except when a
RemoveAndDestroy receipt atomically consumes the final DirectDestroyOnly
reserve; that one entry starts as ForwardOnly with
SelectedForwardOnlySelectionCommitment byte-identical to the phase plan's sole
SafetyReservationConsumed/intended-Absent commitment. The deadline vector is byte-identical to the matching phase plan
vector and to the collection of ExactProviderOperation bindings in that phase's
complete key steps. Each entry is sealed before its own phase's first side
effect and is never replaced, reordered, or broadened. An initially ForwardOnly
entry forbids a refinement. Otherwise, immediately before an irreversible
boundary, at most one disposition refinement per entry is append-committed.
RotationPreSwitchAbortSelection is one indivisible two-entry CAS: the retained
RotatePrepare entry becomes CleanupLockedByRotationAbort and the current
RotateCommit entry becomes the sole ForwardOnly abort direction. It cannot be
decomposed into two selections. The current RecoveryDispositionV1 is the
refinement when present and otherwise the initial value.

RecoveryDispositionV1 is this closed union:

    ResumeOrCompensate {
      ExactBaseQuiescentBusinessPostconditionDigest,
      DefaultAuthorizedPhaseOutcome = AuthorizedPhaseOutcomeV1,
      AllowedForwardOnlySelectionCommitmentCount,
      AllowedForwardOnlySelectionCommitmentVectorV1 = [
        ForwardOnlySelectionCommitmentV1
      ]
    }
  | ForwardOnly {
      SelectedForwardOnlySelectionCommitment =
        ForwardOnlySelectionCommitmentV1
    }
  | CleanupLockedByRotationAbort {
      ConsumingPhaseRole = RotateCommit,
      RotationPreSwitchAbortAuthorizationDigest,
      RetainedCleanupContinuationAuthorityDigest,
      RetainedCleanupKeyDestroyOperationId,
      GrantsMutationOrOutcomeAuthority = false
    }

Generate may resume to Generated after an ambiguous create resolves Ready, or
return to Absent only after post-dispatch CreateUnapplied or the direct
CreateUnappliedNeverStarted terminal. Install/repair may finish the
sealed installed postcondition or compensate to the exact base while every
mutation remains safely reversible. RotatePrepare authorizes only candidate
creation, an AwaitingLaterConsent phase outcome, and safe candidate cleanup to
the exact old base. RotateCommit separately authorizes candidate installation,
pre-switch removal of its exact owned candidate additions, signer switch,
active retirement, and old-key destruction. Before an
irreversible call, the journal selects its one forward outcome: signer switch
selects the intended new installed postcondition; explicit removal/key destroy
selects its intended removal terminal; compensation that deletes a newly owned
anchor or destroys an uninstalled candidate selects the exact base. A
RotateCommit pre-switch abort instead selects its distinctly tagged old-base
outcome and atomically locks candidate-key cleanup to the retained RotatePrepare
entry; it is forbidden after signer switch. CleanupLockedByRotationAbort cannot
select a RotatePrepare outcome, authorize a target/provider call, allocate or
replace an operation ID, or be used without the matching current RotateCommit
ForwardOnly abort state. After a ForwardOnly selection, the complete
SelectedForwardOnlySelectionCommitment MUST be one
byte-identical member of the initial disposition and PhasePlanBodyV1 and, for a
destroy-bearing phase, the destroy-continuation allowed vector. ForwardOnly can
reach only its selected outcome because recovery
cannot re-add deleted trust or recreate a destroyed key. No recovery entry
authorizes a state, target, or phase absent from its own consumed phase plan.

QuiescentBusinessPostconditionV1 is the canonical security-relevant business
projection of a quiescent state:

    QuiescentBusinessPostconditionV1 {
      Body = QuiescentBusinessPostconditionBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        StatePayload =
            AbsentBusiness {
              ExactOwnedTargetAbsenceRoot,
              ExactNoLiveOrAmbiguousKeyPostconditionDigest,
              KnownResidualCaIdentitySetDigest,
              PreservedExternalBusinessRoot
            }
          | GeneratedBusiness {
              CurrentCaPublicIdentityDigest,
              ReadyKeyBusinessPostconditionDigest,
              KnownCaIdentitySetDigest,
              CurrentTargetBusinessDispositionRoot,
              RequiredTrustClaim = None
            }
          | InstalledAndVerifiedBusiness {
              ActiveCaPublicIdentityDigest,
              ReadyKeyBusinessPostconditionDigest,
              RequiredTargetSetDigest,
              PerTargetBusinessPostconditionRoot,
              KnownCaIdentitySetDigest
            }
          | DriftedBusiness {
              LastStableBusinessPostconditionDigest,
              KnownCaIdentitySetDigest,
              DriftFindingBusinessRoot,
              ExactObservedIdentityOwnershipTargetKeyRoot,
              GateRequiredClosed = true
            }
      },
      QuiescentBusinessPostconditionDigest
    }

The digest covers only that body under the registered quiescent-business
domain. It excludes generation/fence high-water, authority epochs, current
journal/replay/gate wrappers, receipt identities, observation contexts,
freshness windows, and boundary tokens, but it excludes no CA identity, key
existence/match, target, ownership, trust, drift, residual, or identity-set
business fact. Post-dispatch CreateUnapplied,
CreateUnappliedNeverStarted, and Destroyed audit records, historical target
receipts, and terminal attempt history are envelope/journal evidence and do not
change an otherwise identical current business postcondition.

Every target-bearing business root is constructed only from this closed,
context-free fact:

    TargetBusinessFactV1 {
      Body = TargetBusinessFactBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        TargetId,
        Required,
        CaGeneration,
        CaInstanceId,
        CertificateDerSha256,
        CertificateSpkiSha256,
        TargetKind,
        ExactStoreOrDomainScopeDigest,
        InstallerExecutor,
        PrivilegeAndInteractionRequirement,
        InstallerOwnershipBusinessFact = FlowProbeOwnedBusiness {
            OwnedPlatformItemIdentityDigest
          }
        | ExternalBusiness {
            ExternalPlatformItemIdentityDigest
          }
        | None,
        BusinessDisposition =
            ExactAbsent {
              ExpectedOwnedPlatformItemIdentityDigestOrNone,
              ExactAbsenceBusinessFactDigest
            }
          | ExactPresent {
              PlatformItemIdentityDigest,
              CaPublicIdentityDigest,
              NormalizedTrustSemantic,
              EffectiveConsumerBusinessFactRoot
            }
          | ExactDerivedPresent {
              PlatformItemIdentityDigest,
              CaPublicIdentityDigest,
              PrimaryAuthorityTargetId,
              PrimaryAuthorityTargetBusinessFactDigest,
              AuthoritySourceBusinessFactRoot,
              CanonicalNativeDerivedOutputDigest,
              NormalizedTrustSemantic,
              EffectiveConsumerBusinessFactRoot
            }
          | Omitted {
              ClosedOmissionReason
            }
          | Drifted {
              ClosedDriftBusinessRoot
            },
        BackendReleaseTupleDigest
      },
      TargetBusinessFactDigest
    }

TargetBusinessFactDigest is SHA-256 over the exact canonical body under
`FlowProbe.TrustCa.TargetBusinessFact.v1`. ExactAbsenceBusinessFactDigest covers
the exact expected locator, zero owned-match count, and complete collision
business projection, but no observation wrapper. EffectiveConsumerBusinessFactRoot
is the sorted root of closed entries
`{ConsumerIdentityDigest, ConsumerReleaseTupleDigest,
ReferenceHostnameDigest, ConsumerValidationProfileDigest,
BusinessOutcome = ExactAnchorAccepted {AnchorCertificateDerSha256}
| ExactAnchorRejected {NegativeResult}
| ExcludedByDeclaredPolicy {BoundedReason}
| Ambiguous {BoundedReason}}`; it deliberately excludes observation time,
expiry, boundary tokens, scan/query identity, and evidence-wrapper digests.
Unknown semantic fields or an evidence result that cannot be projected to
exactly one such entry invalidate the fact.

`InstallerOwnershipBusinessFact` is the complete context-free ownership
projection. `FlowProbeOwnedBusiness` contains only the stable exact native item
identity selected by this target; the enclosing InstallationId, generation,
instance, and TargetId supply its product ownership identity.
`ExternalBusiness` contains only the stable exact native item identity that is
currently outside FlowProbe ownership. `None` is valid only for a derived,
omitted, or exact-absence disposition that has no directly owned native item.
The projection contains no owner receipt, before/after observation, proof,
signature, operation, or time. A terminal or query evidence object may project
to `FlowProbeOwnedBusiness` only after independently verifying its exact owner
receipt and owned after-image, and may project to `ExternalBusiness` only after
independently verifying either its retained pre-existing evidence or the fresh
`NoFlowProbeOwnershipProofV1` defined below. In either case the evidence's exact
platform item identity MUST equal the business projection byte-for-byte.

`SourceDispositionBusinessFactV1` is the corresponding closed source
projection:

    SourceDispositionBusinessFactV1 =
        FlowProbeOwnedSourceBusiness {
          SourcePlatformItemIdentityDigest
        }
      | ExternalSourceBusiness {
          SourcePlatformItemIdentityDigest
        }

It carries no receipt or observation digest. A complete terminal/query source
evidence entry projects to exactly one variant after verifying the evidence
wrapper separately; unknown ownership has no business projection and makes the
derived fact unavailable.

TargetBusinessFactBodyV1 MUST NOT contain a plan-operation role, mutable target
step, intended-operation postcondition, operation/query context,
observation time or expiry, before/after token, journal/state/envelope/selector
value, receipt/signature, scan/result, terminal/query observation digest, or any
digest whose preimage contains one of those values. The complete fact body is
carried in the selected lifecycle payload or its retained snapshot. Each
target-bearing root is

    SHA-256(
      "FlowProbe.TrustCa.QuiescentBusinessPostcondition.v1\0" ||
      canonical_root_field_tag ||
      canonical(SortedUniqueTargetBusinessFactEntryVector)
    )

where each entry is exactly `{TargetId, TargetBusinessFactV1}` and the vector is
strictly sorted by TargetId. `PerTargetBusinessPostconditionRoot`,
`CurrentTargetBusinessDispositionRoot`, and target-bearing portions of
`ExactOwnedTargetAbsenceRoot`, `DriftFindingBusinessRoot`, and
`ExactObservedIdentityOwnershipTargetKeyRoot` use distinct closed field tags
and explicitly this entry shape. Non-target entries in those roots have their
own closed typed projections. No root hashes a TrustTargetRecordV1,
TerminalTargetObservationV1, ResidualQueryTargetObservationV1, receipt, or
evidence wrapper. Consequently a quiescent business digest can be computed from
facts before any terminal observation binds that digest; there is no fixed
point.

Except for KnownResidualCaIdentitySetDigest and every
KnownCaIdentitySetDigest field, each other nested root/digest is
`SHA-256("FlowProbe.TrustCa.QuiescentBusinessPostcondition.v1\0" ||
canonical_field_tag || canonical_projection_body)`; field tags are closed and
distinct. ReadyKeyBusinessPostconditionDigest includes the exact CA public
identity, live Ready/nonambiguous key fact, and current key-match fact but no
ledger revision/receipt wrapper. The identity-set exceptions directly equal
the exact ARCH-002 sorted-SPKI digest defined below, using domain
`FlowProbe.Egress.FlowProbeCaExclusionSet.v1`; they MUST NOT be wrapped or
rehash-derived under the quiescent-business domain. The enclosing business
Body.InstallationId supplies installation binding. Unknown projection fields,
tags, or variants fail closed.

AbsentBusiness means no FlowProbe-owned trust item and no live or ambiguous CA
key, not that every byte-equal external copy vanished. Its residual identity set
contains every still-observed historical FlowProbe CA SPKI required by the
ARCH-002 identity-set rule, and PreservedExternalBusinessRoot binds the exact
external scopes plus their PreservedExternalLive or
ConservativeExternalTrustPotential dispositions that FlowProbe did not own and
did not delete. Both are canonical empty only when complete proof shows no such
residual. RemoveAndDestroy may therefore reach Absent with a nonempty residual
set, but the authenticated identity-set read remains nonempty until later
observation proves that residual gone; it never misreports that case as the
authoritative empty set.

ResidualObservationReconciled is the sole Absent-to-Absent transition and is a
non-authorizing observation transaction, not a consented trust operation. Its
finite scan universe and complete scan result are:

    ResidualScanUniverseV1 {
      Body = ResidualScanUniverseBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        UniverseRevision,
        HistoricalIdentityCount,
        SortedUniqueHistoricalCaPublicIdentityVector,
        RegisteredScopeCount,
        SortedUniqueRegisteredResidualScopeVector = [
          {
            ResidualScopeId,
            TargetKind,
            StableScopeProjection,
            ObserverExecutorClass = PlatformTrustVerifier,
            AppendOnlyObserverBindingHistoryVector = [
              {
                ObserverBindingRevision,
                BackendReleaseTupleDigest,
                SignedProductManifestDigest,
                ResidualObserverSchemaDigest,
                MaximumEnumeratedItemCount,
                MaximumObservedMemberCountPerItem,
                MaximumConsumerObservationCountPerMember,
                MaximumResidualScopeEnumerationEncodedBytes
              }
            ]
          }
        ],
        SortedUniqueIdentityCapacityReservationVector = [
          {
            TrustOperationId,
            CaGeneration,
            ReservedMaximumUniverseGrowthEncodedBytes,
            ReservedMaximumScanResultGrowthEncodedBytes
          }
        ]
      },
      ResidualScanUniverseDigest
    }

Every authenticated identity-set read, interception-admission scan,
RecoveryRequired(None) reproof, RecoveryRequired(Some) resolution scan, or
signer-switch selection creates one ephemeral context after
`ValidateReplayIndexTimeReadOnlyV1` and before the all-scopes before-token pass:

    ResidualRecoveryStateAnchorV1 =
        WithoutPending {
          TrustJournalSelectionIdentityV1 =
            RecoveryWithoutPending { RecoverySelectionId },
          LastQuiescentStateSnapshotDigest,
          OptionalCompletePendingOperationSnapshotDigest = None
        }
      | WithPending {
          TrustJournalSelectionIdentityV1 =
            PendingOperation { TrustOperationId },
          LastQuiescentStateSnapshotDigest,
          CompletePendingOperationSnapshotDigest,
          BoundedReasonRoot,
          UnresolvedTargetRoot
        }

    ResidualQueryContextV1 {
      Body = ResidualQueryContextBodyV1 {
        SchemaVersion = 1,
        Purpose = AuthenticatedIdentitySetRead | InterceptionAdmission
          | RecoveryNoneReproof | RecoveryPendingResolution
          | SignerSwitchSelection,
        QueryChallenge,
        HelperScanNonce,
        InstallationId,
        ExpectedLifecycleStateTag,
        ExpectedStateDigest,
        SelectedStateAnchor =
            Quiescent {
              QuiescentBusinessPostconditionDigest
            }
          | Pending {
              CompletePendingOperationSnapshotDigest,
              PendingQueryBinding = OrdinaryPendingQuery
                | SignerSwitchPendingBinding {
                    SignerSwitchPlanDigest,
                    RotationTargetBindingDigest,
                    SignerSwitchSelectionChallengeDigest
                  }
            }
          | Recovery {
              RecoveryStateAnchor = ResidualRecoveryStateAnchorV1
            },
        ExpectedMonotonicSafetyEnvelopeDigest,
        ExpectedTrustJournalHeadDigest,
        ExpectedTrustStateRevision,
        ExpectedKeyAuthorityEpoch,
        ExpectedKeyStateRevision,
        ExpectedKeyJournalHeadDigest,
        ExpectedInterceptionGateEpoch,
        ResidualScanUniverseRevision,
        ResidualScanUniverseDigest,
        EffectiveObservationTime,
        expires_at
      },
      ResidualQueryContextDigest
    }

ResidualQueryContextDigest covers only the canonical body under
`FlowProbe.TrustCa.ResidualQueryContext.v1`. HelperScanNonce is fresh and unique
for every invocation, including retries. QueryChallenge is the caller's one-use
challenge only for a caller-driven identity-set read or admission request; the
two recovery purposes use the helper-generated challenges below, and signer
switch uses its dedicated derivation. Every Expected* field and
SelectedStateAnchor MUST equal the
single selected predecessor read under the mutation lock. The context contains
no enumeration/result, resulting business/state/envelope, receipt, or response
digest. It is not written to the state machine and grants no mutation or
signing authority by itself.

The selected predecessor envelope resolves the exact current signed manifest.
The context's `expires_at` is exactly the checked, nonwrapping sum of
EffectiveObservationTime and that manifest's
MaximumResidualObservationLifetime. A zero/`UINT64_MAX` window, overflow,
historical/staged manifest, local default, or shorter or longer substituted
expiry is invalid.

Purpose and selected predecessor are bijective. RecoveryNoneReproof requires a
selected RecoveryRequired state with OptionalPendingOperationSnapshot=None and
only `ResidualRecoveryStateAnchorV1.WithoutPending`; its identity,
RecoverySelectionId, and last-quiescent snapshot equal the selected payload
byte-for-byte. Its QueryChallenge is helper-generated, fresh for that one
recovery attempt, and is repeated by every recovery possession proof; it is
never caller-chosen or reusable as an identity-set/admission challenge.

RecoveryPendingResolution requires a selected RecoveryRequired state with
OptionalPendingOperationSnapshot=Some and only
`ResidualRecoveryStateAnchorV1.WithPending`. The PendingOperation identity and
TrustOperationId, complete retained pending-snapshot digest, last-quiescent
snapshot digest, BoundedReasonRoot, and UnresolvedTargetRoot equal the selected
payload and complete inline snapshots/vectors byte-for-byte. Its challenge is
exactly

    SHA-256(
      "FlowProbe.TrustCa.ResidualQueryContext.v1\0" ||
      "recovery-pending-resolution-challenge\0" ||
      canonical({
        InstallationId,
        TrustOperationId,
        ExpectedStateDigest,
        CompletePendingOperationSnapshotDigest,
        BoundedReasonRoot,
        UnresolvedTargetRoot,
        HelperScanNonce
      })
    )

and is helper-generated for that one selected recovery episode and scan. This
purpose is non-authorizing and cannot satisfy an identity-set proof,
interception admission, RecoveryNoneReproof possession, signer switch, target
mutation, provider dispatch, or consent consumption. If the selected state,
head, envelope, retained pending snapshot, reason root, or unresolved-target
root changes before the recovery-resume selector commits, the complete context
and scan are discarded.

SignerSwitchSelection requires a selected InstallPending(RotateInstall)
RotateCommit snapshot and only SignerSwitchPendingBinding. Its three digests
equal the complete selected plan/binding/challenge, and QueryChallenge is the
domain-separated derivation defined by that challenge. A non-recovery purpose
cannot use either Recovery anchor variant. AuthenticatedIdentitySetRead and
InterceptionAdmission use OrdinaryPendingQuery when a pending anchor is legal;
every non-signer-switch purpose forbids signer-switch fields. Cross-purpose,
cross-episode, cross-snapshot, or digest-only pending/recovery bindings are
invalid.

`ValidateReplayIndexTimeReadOnlyV1` runs under the global mutation lock. It
reads the selected replay-index body and current clock, applies the same bounded
rollback rejection rule as maintenance, and computes
`EffectiveObservationTime = max(CurrentObservedTime,
selected ReplayTimeHighWater)`. It does not prune a tombstone, advance
ReplayTimeHighWater, build or select a replay body, change any revision/root,
or write a selector slot. The context's EffectiveObservationTime and expiry are
validated against that read-only result immediately before each signature. A
clock rollback beyond the allowed skew or an already-expired context returns
the applicable unavailable error without state change. Replay-time maintenance
may be folded atomically into a selector transition already required for a
business, observation, consent, or operation commit; a byte-identical query is
never allowed to create a maintenance-only predecessor or successor.

    ResidualScopeEnumerationV1 {
      Body = ResidualScopeEnumerationBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        ResidualScanUniverseRevision,
        ResidualScanUniverseDigest,
        ResidualQueryContextDigest,
        ResidualScopeId,
        ObserverBindingRevision,
        BackendReleaseTupleDigest,
        ResidualObserverSchemaDigest,
        BeforeObservationBoundaryToken,
        AfterObservationBoundaryToken,
        ResidualQueryDerivedAuthoritySourceSetCount,
        SortedUniqueResidualQueryDerivedAuthoritySourceSetVector,
        ResidualQueryTargetObservationCount,
        SortedUniqueResidualQueryTargetObservationVector,
        ResidualQueryFixedRegeneratorResultCount,
        SortedUniqueResidualQueryFixedRegeneratorResultVector,
        ResidualQueryDerivedMemberProofCount,
        SortedUniqueResidualQueryDerivedMemberProofVector,
        EnumeratedItemCount,
        SortedUniqueEnumeratedItemVector = [
          {
            ItemObservationKey,
            Body = NormalizedResidualPlatformItemBodyV1 {
              PlatformItemIdentityDigest,
              ExactPlatformItemIdentity = {
                ItemIdentityKind = WindowsCertificateStoreObject
                  | MacCertificateItem
                  | MacTrustSettingsRecord
                  | LinuxAuthoritySource
                  | LinuxDerivedArtifact
                  | NssSqlCertificateEntry
                  | ConsumerPolicyObject,
                ResidualObserverSchemaDigest,
                CanonicalNativeItemIdentityBytes
              },
              OwnershipClassification =
                  FlowProbeOwned {
                    OwnerReceiptDigest,
                    OwnedAfterImageDigest
                  }
                | ExternalPreExisting {
                    ExactBeforeObservationDigest
                  }
                | ExternalCurrentObserved {
                    NoFlowProbeOwnershipProofV1,
                    NoFlowProbeOwnershipProofDigest
                  }
                | ExternalObservedUnknown {
                    BoundedOwnershipObservationDigest
                  },
              ObservedMemberCount,
              SortedUniqueObservedMemberVector = [
                {
                  ItemMemberObservationKey,
                  Body = NormalizedResidualItemMemberObservationBodyV1 {
                    PlatformItemIdentityDigest,
                    MemberIdentityDigest,
                    ExactMemberIdentity =
                        NativeSubobject {
                          CanonicalNativeMemberIdentityBytes
                        }
                      | ContainerOrdinal {
                          Ordinal
                        },
                    MemberAuthorityProvenance =
                        DirectPlatformItem
                      | DerivedFromPrimaryAuthority {
                          DerivedTargetId,
                          PrimaryExecutionLineage =
                              ActivePrimary {
                                PrimaryAuthorityTargetId,
                                PrimaryAuthorityTargetBusinessFactDigest,
                                PrimaryAuthorityTerminalTargetObservationDigest,
                                PrimaryAuthorityResidualQueryTargetObservationDigest
                              }
                            | RetainedPrimary {
                                PrimaryAuthorityTargetId,
                                PrimaryTerminalDispositionDigest,
                                LastPrimaryAuthorityTerminalTargetObservationDigest
                              },
                          DerivedTargetBusinessFactDigest,
                          DerivedTerminalTargetObservationDigest,
                          DerivedResidualQueryTargetObservationDigest,
                          CurrentDerivedAuthoritySourceSetV1,
                          CurrentAuthoritySourceSetDigest,
                          AuthoritySourceBusinessFactRoot,
                          ResidualQueryFixedRegeneratorResultReceiptDigest,
                          ResidualQueryDerivedMemberProofDigest
                        }
                      | DerivedProvenanceUnknown {
                          Body = BoundedDerivedProvenanceBodyV1 {
                            PlatformItemIdentityDigest,
                            MemberIdentityDigest,
                            OptionalDerivedTargetId,
                            SortedUniqueBoundedReasonVector
                          },
                          BoundedDerivedProvenanceDigest
                        },
                    CertificateObservation =
                        HistoricalIdentityMatch {
                          HistoricalIdentityOrdinal
                        }
                      | OtherCertificate {
                          CertificateDerSha256,
                          CertificateSpkiSha256,
                          CompleteDerLength
                        }
                      | NonCertificateTrustObject {
                          ObjectKind = CertificateTrustProperty
                            | TrustSettingsEntry
                            | PurposePolicyEntry
                            | DerivedTrustMetadata
                            | ConsumerPolicyEntry,
                          CanonicalNormalizedObjectBytes
                        },
                    NormalizedTrustSemantic = ServerAuthTrusted
                      | ExplicitlyDistrusted
                      | NoServerAuthTrust
                      | OtherPurposeOnly {
                          SortedUniquePurposeOidVector
                        }
                      | ConsumerPrivateOrPolicyExcluded
                      | UnknownTrustSemantic,
                    SortedUniqueConsumerObservationVector = [
                      {
                        ConsumerObservationKey,
                        Body = ResidualConsumerObservationBodyV1 {
                          ResidualQueryContextDigest,
                          PlatformItemIdentityDigest,
                          MemberIdentityDigest,
                          HistoricalIdentityOrdinal,
                          ConsumerIdentityDigest,
                          ConsumerReleaseTupleDigest,
                          ReferenceHostnameDigest,
                          ConsumerValidationProfileDigest,
                          observed_at,
                          expires_at,
                          Outcome = ExactAnchorAccepted {
                              Body = ConsumerTlsSuccessBodyV1,
                              ValidatedChainAnchorCertificateDerSha256,
                              SuccessfulTlsResultDigest
                            }
                          | ExactAnchorRejected {
                              Body = ConsumerTlsNegativeBodyV1,
                              NegativeTlsResultDigest
                            }
                          | ExcludedByDeclaredPolicy {
                              BoundedReason
                            }
                          | ProbeUnavailableAfterKeyDestruction {
                              Body = ConsumerProbeUnavailableBodyV1,
                              ConservativeConsumerResultDigest
                            }
                          | Ambiguous {
                              Body = AmbiguousConsumerObservationBodyV1,
                              BoundedConsumerObservationDigest
                            }
                        }
                      }
                    ]
                  }
                }
              ]
            }
          }
        ]
      },
      CompleteEnumerationRoot
    }

An item first observed after the corresponding target operation is not forced
to pretend that it had a retained before image. It may use this query-scoped,
non-authorizing proof:

    NoFlowProbeOwnershipProofV1 {
      Body = NoFlowProbeOwnershipProofBodyV1 {
        SchemaVersion = 1,
        ResidualQueryContextDigest,
        InstallationId,
        ExpectedTrustStateRevision,
        ExpectedTrustJournalHeadDigest,
        ResidualScanUniverseRevision,
        ResidualScanUniverseDigest,
        ResidualScopeId,
        ObserverBindingRevision,
        PlatformItemIdentityDigest,
        ExactPlatformItemIdentity,
        BeforeOwnershipObservationBoundaryToken,
        AfterOwnershipObservationBoundaryToken,
        OwnershipLedgerEntryCount,
        CompleteFlowProbeOwnershipLedgerProjection = [
          {
            TargetId,
            CaGeneration,
            CaInstanceId,
            TargetLocatorDigest,
            OwnedPlatformItemIdentityDigestOrNone,
            OwnershipRecordDisposition = CurrentOwned {
                OwnerReceiptDigest,
                OwnedAfterImageDigest
              }
              | RemovedOrExternallyRemoved {
                OwnerReceiptDigest,
                OwnedAfterImageDigest,
                TerminalOwnershipDispositionDigest
              }
              | Unresolved {
                BoundedUnresolvedOwnershipRecordDigest
              }
          }
        ],
        CompleteFlowProbeOwnershipLedgerRoot,
        MatchingOwnedPlatformItemIdentityCount = 0,
        MatchingUnresolvedOwnedLocatorCount = 0,
        observed_at,
        expires_at
      },
      NoFlowProbeOwnershipProofDigest
    }

The proof digest covers the exact digest-free body under
`FlowProbe.TrustCa.NoFlowProbeOwnershipProof.v1`. The ownership-ledger vector is
complete for every current and retained target-owner record under the selected
trust journal head, is strictly sorted by `(TargetId, CaGeneration,
CaInstanceId, TargetLocatorDigest)`, and rejects duplicate semantic keys.
CurrentOwned requires a present owned item identity; a removed record retains
its last exact identity and terminal disposition; Unresolved may carry None but
must retain its complete bounded locator evidence. Its root
uses the same domain with field tag `"ownership-ledger\0"` over the complete
vector, and OwnershipLedgerEntryCount is its canonical uint32 length. Every
receipt/after-image/terminal/unresolved digest resolves to the retained exact record;
an unavailable, forked, compacted-away, or unresolved record invalidates the
proof. The two boundary tokens are equal under the same no-ABA ownership
observer used by the scope enumeration, and all context, state, universe,
scope, item, time, and token fields equal the enclosing fresh query evidence.
OwnershipLedgerEntryCount is no greater than the current signed
MaximumResidualOwnershipLedgerEntryCount and the complete canonical ledger
projection is no greater than MaximumResidualOwnershipLedgerEncodedBytes;
checked max-plus-one or byte overflow invalidates the proof.

`ExternalCurrentObserved` is valid only when this proof names the exact
enclosing platform item and both matching counts are zero. It projects only to
`ExternalBusiness`/`ExternalSourceBusiness`; it creates no target, consent,
executor, inherited privilege, mutation, adoption, owner receipt, or deletion
authority. A missing owner ledger, possible alias to an owned locator, or
ambiguous target history remains `ExternalObservedUnknown` and fails closed.

Consumer result digests have closed, independently recomputable preimages:

    ConsumerTlsSuccessBodyV1 {
      SchemaVersion = 1,
      ResidualQueryContextDigest,
      InstallationId,
      ResidualScanUniverseRevision,
      ResidualScanUniverseDigest,
      ResidualScopeId,
      PlatformItemIdentityDigest,
      MemberIdentityDigest,
      HistoricalIdentityOrdinal,
      HistoricalCertificatePublicIdentityDigest,
      ConsumerIdentityDigest,
      ConsumerReleaseTupleDigest,
      ReferenceHostnameDigest,
      ConsumerValidationProfileDigest,
      ValidatedChainAnchorCertificateDerSha256,
      observed_at,
      expires_at
    }

    ConsumerTlsNegativeBodyV1 {
      SchemaVersion = 1,
      ResidualQueryContextDigest,
      InstallationId,
      ResidualScanUniverseRevision,
      ResidualScanUniverseDigest,
      ResidualScopeId,
      PlatformItemIdentityDigest,
      MemberIdentityDigest,
      HistoricalIdentityOrdinal,
      HistoricalCertificatePublicIdentityDigest,
      ConsumerIdentityDigest,
      ConsumerReleaseTupleDigest,
      ReferenceHostnameDigest,
      ConsumerValidationProfileDigest,
      ExpectedAnchorCertificateDerSha256,
      NegativeResult = ExactAnchorNotAccepted
        | ExactPurposeRejected,
      observed_at,
      expires_at
    }

    AmbiguousConsumerObservationBodyV1 {
      SchemaVersion = 1,
      ResidualQueryContextDigest,
      InstallationId,
      ResidualScanUniverseRevision,
      ResidualScanUniverseDigest,
      ResidualScopeId,
      PlatformItemIdentityDigest,
      MemberIdentityDigest,
      HistoricalIdentityOrdinal,
      HistoricalCertificatePublicIdentityDigest,
      ConsumerIdentityDigest,
      ConsumerReleaseTupleDigest,
      ReferenceHostnameDigest,
      ConsumerValidationProfileDigest,
      SortedUniqueBoundedEvidenceDigestVector,
      BoundedReason,
      observed_at,
      expires_at
    }

    ConsumerProbeUnavailableBodyV1 {
      SchemaVersion = 1,
      ResidualQueryContextDigest,
      InstallationId,
      ResidualScanUniverseRevision,
      ResidualScanUniverseDigest,
      ResidualScopeId,
      PlatformItemIdentityDigest,
      MemberIdentityDigest,
      HistoricalIdentityOrdinal,
      HistoricalCaPublicIdentityDigest,
      ConsumerIdentityDigest,
      ConsumerReleaseTupleDigest,
      ReferenceHostnameDigest,
      ConsumerValidationProfileDigest,
      DestroyedTerminalKeyEvidenceV1,
      DestroyedTerminalKeyEvidenceDigest,
      Reason = HistoricalPrivateKeyDestroyed,
      ProbeDisposition = NotAttempted,
      ConservativeRetentionRequired = true,
      observed_at,
      expires_at
    }

SuccessfulTlsResultDigest, NegativeTlsResultDigest,
BoundedConsumerObservationDigest, and ConservativeConsumerResultDigest are
SHA-256 over the canonical body above under, respectively,
`FlowProbe.TrustCa.ConsumerTlsSuccess.v1`,
`FlowProbe.TrustCa.ConsumerTlsNegative.v1`,
`FlowProbe.TrustCa.ConsumerObservationAmbiguous.v1`, and
`FlowProbe.TrustCa.ConsumerProbeUnavailable.v1`. Each complete preimage body is
carried inline with its digest and independently recomputed. The signed release manifest
binds ConsumerValidationProfileDigest to an exact server-auth policy, reference-
hostname treatment, otherwise-valid bounded test leaf, trust-engine call,
flags, and result normalizer. A member consumer vector MUST be empty unless its
CertificateObservation is HistoricalIdentityMatch. For a nonempty vector, the
ordinal and complete historical certificate identity resolved through the
exact universe MUST match every result body. Every platform/member/consumer/
release/hostname/profile/time field duplicated between the enclosing consumer
body and result body MUST be byte-identical. InstallationId, universe
revision/digest, and ResidualScopeId in every result body MUST equal the
enclosing complete enumeration. ResidualQueryContextDigest in the enclosing
consumer body and complete result body MUST equal that enumeration's fresh
context byte-for-byte; an otherwise unexpired result from another nonce or
query is invalid.

An ExactAnchorAccepted outcome requires the success body and its anchor hash to
equal the resolved historical CA DER hash. ExactAnchorRejected requires the
negative body's expected anchor to equal that same DER hash; a hostname, leaf,
time, key, or unrelated-purpose failure cannot be normalized as
ExactAnchorNotAccepted. Ambiguous requires the complete bounded ambiguous body;
its evidence vector is nonempty, sorted, unique, and complete. observed_at is
no earlier than the scan's EffectiveObservationTime, expires_at is later than
observed_at and no later than the enclosing scan expiry, and stale/overflowing
times invalidate the enumeration. Digest substitution across consumers,
hostnames, releases, members, identities, or result variants is invalid.

ProbeUnavailableAfterKeyDestruction is not a TLS success, negative result, or
consumer-support claim. It is valid only when the member is an exact historical
identity, the authenticated key ledger retains the complete matching
DestroyedTerminalKeyEvidenceV1, that evidence proves the same historical public
identity and a unique ordered ancestry to the current key tip, and no live,
destroy-pending, or ambiguous key for that identity exists. Its surrounding
member MUST be either (a) a direct ExternalPreExisting member, (b) a direct
ExternalCurrentObserved member carrying the complete same-query
NoFlowProbeOwnershipProofV1 for that exact platform item, or (c) a derived
member with complete current provenance containing at least one
ExternalPreExistingAuthority or ExternalCurrentObservedAuthority source. Every
ExternalCurrentObservedAuthority source in case (c) MUST carry the complete
same-query NoFlowProbeOwnershipProofV1 for its exact source item; an ownership
proof from another query, item, member, scope, or state is invalid. The member's
freshly normalized trust semantic MUST be exactly ServerAuthTrusted. It waives
only the impossible act of minting a new otherwise-valid leaf with a destroyed
historical key; ownership, trust semantic, source provenance, scope, release,
boundary-token, enumeration, and freshness checks remain mandatory. A Ready,
DestroyPending, Ambiguous, wrong-identity, forked, missing, or compacted-away
key record makes the outcome invalid. The conservative result preserves the
historical SPKI in the ARCH-002 exclusion set, but it never authorizes
InstalledAndVerified, interception admission, leaf signing, target
verification, support promotion, mutation, adoption, or deletion.

    ResidualScanResultV1 {
      Body = ResidualScanResultBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        ResidualScanUniverseRevision,
        ResidualScanUniverseDigest,
        ResidualQueryContextV1,
        ResidualQueryContextDigest,
        EffectiveObservationTime,
        expires_at,
        ScanConsistencyProof = AllScopesBeforeEnumerateAfterV1 {
          AllScopeBeforeTokenVector,
          AllScopeAfterTokenVector
        },
        CompleteScopeBitmap,
        PerScopeObservationVector = [
          {
            ResidualScopeId,
            CompleteEnumeration = ResidualScopeEnumerationV1,
            CompleteEnumerationRoot,
            HistoricalIdentityPresenceBitmap,
            SortedUniquePresentIdentityObservationVector = [
              {
                HistoricalIdentityOrdinal,
                SortedUniqueMatchingItemMemberObservationKeyVector,
                ExactOwnershipAggregateDigest,
                EffectiveTrustDispositionDigest,
                CompleteConsumerObservationRoot
              }
            ],
            EnumeratedItemCount
          }
        ]
      },
      ResidualScanResultDigest
    }

The universe, enumeration, and result digests cover only their digest-free
bodies under their registered domains. No body contains its own digest or its
encoded byte length. Verifiers compute byte counts from the final canonical
encoding. HistoricalIdentityCount and RegisteredScopeCount exactly equal their
vector lengths; both are canonical uint32 values. Historical identities are complete CaPublicIdentityV1 values
sorted by their certificate-public-identity digest; scopes are sorted by
ResidualScopeId; reservations are sorted by the canonical
(TrustOperationId, CaGeneration) pair. Historical and scope membership is
append-only, but each new universe revision canonically re-sorts those vectors;
HistoricalIdentityOrdinal and every vector position are valid only with the
exact bound UniverseRevision/ResidualScanUniverseDigest. No proof may carry an
ordinal across revisions.

The complete ResidualQueryContextV1 and duplicate digest in a result MUST match
byte-for-byte, and every enumeration's ResidualQueryContextDigest equals it.
Each PerScopeObservationVector entry carries exactly one complete
ResidualScopeEnumerationV1. Its duplicate CompleteEnumerationRoot MUST be
independently recomputed from that inline body's canonical encoding and equal
the wrapper root byte-for-byte. Its InstallationId, universe revision/digest,
scope, current observer binding/release/schema, before/after boundary tokens,
and EnumeratedItemCount MUST equal the result, universe, global token vectors,
and enclosing per-scope entry. The inline enumerations are in exact universe
scope-vector order; a missing, extra, reordered, root-only, or externally
resolved enumeration is invalid.
Each of the four query-evidence counts exactly equals its inline vector length;
current derived-authority source sets are strictly sorted and unique by
`(DerivedResidualScopeId, DerivedTargetId)`; target observations by
`(TargetId, HistoricalIdentityOrdinalOrNone)`; regenerator results by
`(DerivedResidualScopeId, DerivedTargetId)`; and member proofs by
`(PlatformItemIdentityDigest, ExactMemberIdentity, DerivedTargetId)`. A second
body with the same semantic key is invalid even when its digest differs. The
four vectors are respectively no greater than
MaximumResidualQueryDerivedAuthoritySourceSetCount,
MaximumResidualQueryTargetObservationCount,
MaximumResidualQueryFixedRegeneratorResultCount, and
MaximumResidualQueryDerivedMemberProofCount from the context's current signed
manifest; the whole result remains within MaximumResidualScanResultEncodedBytes.
Every referenced query evidence digest resolves
exactly once in this result. A missing, extra, cross-context, cross-scope, or
unreferenced security-relevant entry invalidates the complete scan rather than
being ignored.

ResidualScopeId is the field-tagged digest, under the universe domain, of
TargetKind, StableScopeProjection, and ObserverExecutorClass only. It excludes
the observer-binding history, limits, and ResidualScopeId itself, so the stable
physical/user/consumer scope survives a backend release update. Each scope's
observer history is ordered by contiguous nonzero ObserverBindingRevision; its
last entry, including that entry's four per-scope capacity limits, is the only
current binding and older entries remain immutable provenance.
Duplicate identities, scopes, reservation pairs, observer revisions, or
noncanonical order are invalid.

CompleteObserverBindingEntryDigest is
`SHA-256("FlowProbe.TrustCa.ResidualScanUniverse.v1\0" ||
"observer-binding-entry\0" || canonical(complete binding entry))`.
CompleteResidualScopeEntryDigest uses the same domain and tag
`"residual-scope-entry\0"` over the complete scope entry including its history.
ResidualIdentityCapacityReservationDigest uses tag
`"identity-capacity-reservation\0"` over the exact complete reservation entry.
None of these entry bodies includes its own digest, and every duplicate digest
field is recomputed rather than trusted.

ResidualObserverSchemaDigest is
`SHA-256("FlowProbe.TrustCa.ResidualScopeEnumeration.v1\0" || "schema\0" ||
canonical(ResidualObserverSchemaBodyV1))`, where the complete bounded schema
body is carried by the signed product manifest for this release binding. It
identifies the exact canonical normalizer and boundary-token schema. That
schema selects a supported subset of the contract's closed
ItemIdentityKind/ObjectKind values and fixes the
complete field layout and maximum length of CanonicalNativeItemIdentityBytes,
CanonicalNativeMemberIdentityBytes, CanonicalNormalizedObjectBytes, every
derived-authority evidence body, and the mapping from the exact registered
TrustTargetV1 scope to those bytes. The renderer cannot choose any of them.
Canonical native identity includes the exact physical store/domain/database or
registered artifact scope and the release-defined native object identity; two
distinct platform items MUST have different canonical identities. Unknown,
noncanonical, empty, over-bound, or cross-schema bytes invalidate the complete
enumeration.

PlatformItemIdentityDigest is
`SHA-256("FlowProbe.TrustCa.ResidualScopeEnumeration.v1\0" ||
"platform-item-identity\0" || canonical(ExactPlatformItemIdentity))` and MUST
equal the inline identity. ObservedMemberCount exactly equals the member-vector
length, is a canonical uint32, and is at most
MaximumObservedMemberCountPerItem; every member's consumer vector is at most
MaximumConsumerObservationCountPerMember. The enumeration item count is at
most MaximumEnumeratedItemCount. MemberIdentityDigest is
`SHA-256("FlowProbe.TrustCa.ResidualScopeEnumeration.v1\0" ||
"member-identity\0" || PlatformItemIdentityDigest ||
canonical(ExactMemberIdentity))`. It and the parent digest in every consumer
body MUST equal the enclosing member. ItemMemberObservationKey is
`SHA-256("FlowProbe.TrustCa.ResidualScopeEnumeration.v1\0" || "member\0" ||
canonical(NormalizedResidualItemMemberObservationBodyV1))`. The member body
binds its parent identity digest, so byte-equal member content in two different
platform items remains distinct. NativeSubobject bytes are nonempty and unique
within the parent. ContainerOrdinal.Ordinal is an explicitly carried canonical
uint32, is less than ObservedMemberCount, and is the zero-based index in the
release-defined complete parser order. A schema that selects ContainerOrdinal
requires no ordinal for an empty member vector and otherwise exactly the
contiguous range `0..ObservedMemberCount - 1`, so duplicate certificate/object
occurrences remain separate without allowing a uint64 or `UINT32_MAX + 1`
member. Member vectors are sorted by member key and a duplicate
key is a duplicate view of the same exact member and is invalid. A certificate
store object normally has one member;
an aggregate bundle, database, trust-settings record, or policy container has
one member for every bounded normalized certificate/object entry. The platform
item appears exactly once even when several historical identities occur inside
it; emitting multiple partial views of one native item is invalid.

DirectPlatformItem is valid only for a non-derived native member and inherits
its exact parent OwnershipClassification. A LinuxDerivedArtifact or any target
whose executor is DerivedBy MUST instead use DerivedFromPrimaryAuthority or
DerivedProvenanceUnknown. The unique `DerivedBy` plan edge is the primary
execution/permission lineage only; it is not a claim that the derived bytes
have exactly one current source.

The operation-bound complete source set used to select a terminal derived fact
is:

    TerminalDerivedAuthoritySourceSetV1 {
      Body = TerminalDerivedAuthoritySourceSetBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        TrustOperationId,
        PhasePlanDigest,
        DerivedTargetId,
        CompleteReadOnlyRegeneratorInputScopeSetDigest,
        SortedUniqueTerminalDirectAuthoritySourceVector = [
          {
            SourceKind = PrimaryTargetAuthority {
                PrimaryAuthorityTargetId,
                PrimaryAuthorityTargetBusinessFact = TargetBusinessFactV1,
                PrimaryAuthorityTargetBusinessFactDigest,
                PrimaryAuthorityTerminalTargetObservation =
                  TerminalTargetObservationV1,
                PrimaryAuthorityTerminalTargetObservationDigest
              }
            | AdditionalTargetAuthority {
                SourceTargetId,
                SourceTargetBusinessFact = TargetBusinessFactV1,
                SourceTargetBusinessFactDigest,
                SourceTerminalTargetObservation = TerminalTargetObservationV1,
                SourceTerminalTargetObservationDigest
              }
            | AdditionalExternalAuthority,
            SourceResidualScopeId,
            SourcePlatformItemIdentityDigest,
            SourceMemberIdentityDigest,
            HistoricalCaPublicIdentityDigest,
            CanonicalNativeAuthorityInputDigest,
            SourceDispositionEvidence = FlowProbeOwnedAuthority {
                OwnerReceiptDigest,
                OwnedAfterImageDigest
              }
            | ExternalPreExistingAuthority {
                ExactBeforeObservationDigest
              },
            SourceDispositionBusinessFactV1
          }
        ],
        AuthoritySourceBusinessFactRoot
      },
      TerminalDerivedAuthoritySourceSetDigest
    }

TerminalDerivedAuthoritySourceSetDigest covers the exact digest-free body under
`FlowProbe.TrustCa.TerminalDerivedAuthoritySourceSet.v1`. Its vector is
nonempty, strictly sorted by `(SourceResidualScopeId,
SourcePlatformItemIdentityDigest, SourceMemberIdentityDigest)`, and rejects a
duplicate semantic key even when the remaining bytes differ. It contains every
direct input source in the manifest-bound read-only regenerator input scopes at
the operation's equal before/after boundary tokens. Every target-bound source
is direct, carries its complete already-selected fact/terminal observation, and
matches the immutable phase plan. The SourceKind and evidence variants form a
closed matrix: PrimaryTargetAuthority and AdditionalTargetAuthority require
FlowProbeOwnedAuthority or ExternalPreExistingAuthority as established by their
complete target fact and terminal anchor; AdditionalExternalAuthority is valid
if and only if SourceDispositionEvidence is ExternalPreExistingAuthority.
Conversely, any additional FlowProbeOwned source MUST be encoded as
AdditionalTargetAuthority and carry its complete SourceTargetId,
SourceTargetBusinessFactV1/digest, and SourceTerminalTargetObservationV1/digest;
it cannot be represented as AdditionalExternalAuthority.
AdditionalExternalAuthority carries no target or execution authority. The
evidence variant projects byte-for-byte to the
shown `SourceDispositionBusinessFactV1`. The source business root is recomputed
from this vector by the context-free projection below. The object contains no
derived target business fact, derived terminal observation, regenerator result,
quiescent state, stable receipt, or resulting object digest, so the terminal
order remains direct terminal sources -> complete terminal source set ->
derived business fact/regenerator result -> derived terminal observation.

The complete current source set used by a residual query is:

    CurrentDerivedAuthoritySourceSetV1 {
      Body = CurrentDerivedAuthoritySourceSetBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        ResidualQueryContextDigest,
        ResidualScanUniverseRevision,
        ResidualScanUniverseDigest,
        DerivedResidualScopeId,
        DerivedTargetId,
        ObserverBindingRevision,
        BackendReleaseTupleDigest,
        PrimaryExecutionLineageDigest,
        SortedUniqueCurrentDirectAuthoritySourceVector = [
          {
            SourceKind = PrimaryTargetAuthority {
                PrimaryAuthorityTargetId,
                PrimaryAuthorityTargetBusinessFactDigest,
                PrimaryAuthorityTerminalTargetObservationDigest,
                PrimaryAuthorityResidualQueryTargetObservationDigest
              }
            | AdditionalObservedAuthority {
                OptionalSourceTargetAnchor = NoneForExternal
                  | Some {
                      SourceTargetId,
                      SourceTargetBusinessFactDigest,
                      SourceTerminalTargetObservationDigest,
                      SourceResidualQueryTargetObservationDigest
                    }
              },
            SourceResidualScopeId,
            SourcePlatformItemIdentityDigest,
            SourceItemMemberObservationKey,
            SourceMemberIdentityDigest,
            HistoricalIdentityOrdinal,
            HistoricalCaPublicIdentityDigest,
            CanonicalNativeAuthorityInputDigest,
            SourceDisposition = FlowProbeOwnedAuthority {
                OwnerReceiptDigest,
                OwnedAfterImageDigest
              }
            | ExternalPreExistingAuthority {
                ExactBeforeObservationDigest
              }
            | ExternalCurrentObservedAuthority {
                NoFlowProbeOwnershipProofV1,
                NoFlowProbeOwnershipProofDigest
              },
            SourceDispositionBusinessFactV1
          }
        ],
        AuthoritySourceBusinessFactRoot
      },
      CurrentAuthoritySourceSetDigest
    }

CurrentAuthoritySourceSetDigest covers the exact canonical body under
`FlowProbe.TrustCa.DerivedAuthoritySourceSet.v1`. The vector is nonempty,
strictly sorted by `(SourceResidualScopeId, SourcePlatformItemIdentityDigest,
SourceMemberIdentityDigest)`, unique, bounded, and complete for every direct
source that contributes this member under the registered regenerator input
scope set. Each source key resolves exactly once to a DirectPlatformItem member
in this same ResidualScanResultV1 and has the byte-identical ownership evidence,
historical ordinal, and normalized input digest. An additional source is
observation only: it creates no target edge, consent scope, inherited privilege,
ownership, or deletion authority. An additional FlowProbeOwnedAuthority must
carry Some and resolve to its own exact direct selected target/fresh query pair;
an external source uses NoneForExternal or a byte-identical pre-existing target
anchor. `ExternalCurrentObservedAuthority` additionally requires
NoneForExternal and the exact fresh ownership proof carried by its direct item;
it grants no target or operation authority. Every evidence variant projects to
the explicitly carried SourceDispositionBusinessFactV1 and the native identity
in that projection MUST equal SourcePlatformItemIdentityDigest byte-for-byte.
The signed release manifest fixes
CompleteReadOnlyRegeneratorInputScopeSetDigest in the target template/exact
target refinement and the observer mapping that proves completeness. An
unregistered input, hook, source scope, nested derived source, incomplete
enumeration, or second FlowProbe-owned source without its own exact target/owner
proof makes provenance unknown.

AuthoritySourceBusinessFactRoot is the context-free projection of that vector:

    SHA-256(
      "FlowProbe.TrustCa.TargetBusinessFact.v1\0" ||
      "authority-source-business-facts\0" ||
      canonical(sorted_unique[
        {
          SourceResidualScopeId,
          SourcePlatformItemIdentityDigest,
          SourceMemberIdentityDigest,
          HistoricalCaPublicIdentityDigest,
          CanonicalNativeAuthorityInputDigest,
          SourceDispositionBusinessFactV1
        }
      ])
    )

HistoricalCaPublicIdentityDigest is the stable digest of the complete
CaPublicIdentityV1 matched by the source. HistoricalIdentityOrdinal remains only
query-local evidence and MUST NOT enter this projection. It excludes query
context, terminal/query observation, item-member key,
receipt/proof, boundary token, and time. A current source set's carried
AuthoritySourceBusinessFactRoot MUST equal this projection byte-for-byte; a
terminal derived TargetBusinessFactV1 stores the same root
computed from its operation-time complete sources. Thus source semantics can
change a business fact without making that fact depend on a freshness wrapper.

ActivePrimary is valid only while the primary target's selected terminal fact
is present and its fresh query observation is definite; exactly one
PrimaryTargetAuthority entry then matches its target/fact/terminal/query
digests. RetainedPrimary is valid only after removal/rotation history proves the
same primary edge reached VerifiedAbsent or ExternallyRemoved; it binds that
terminal disposition and last terminal observation but grants no current
authority, and the current source vector contains only sources still observed.
It allows a preserved external source to keep a derived aggregate present after
the owned primary is gone without inventing a second plan edge.
PrimaryExecutionLineageDigest is
`SHA-256("FlowProbe.TrustCa.DerivedAuthoritySourceSet.v1\0" ||
"primary-execution-lineage\0" || canonical(the complete inline ActivePrimary or
RetainedPrimary body))`. It is absent from that body and every duplicate digest
in the source set and regenerator receipt must recompute to the member's exact
inline lineage.
PrimaryTerminalDispositionDigest uses the TargetBusinessFact domain with field
tag `"primary-terminal-disposition\0"` over exactly
`{PrimaryAuthorityTargetId, PrimaryTargetBusinessFactDigest,
TerminalStep = VerifiedAbsent | ExternallyRemoved,
LastPrimaryAuthorityTerminalTargetObservationDigest}`. The complete preimage is
retained beside the lineage and contains no current source, query, or derived
output.

The same enumeration carries these complete result objects:

    ResidualQueryFixedRegeneratorResultReceiptV1 {
      Body = ResidualQueryFixedRegeneratorResultReceiptBodyV1 {
        SchemaVersion = 1,
        ResidualQueryContextDigest,
        InstallationId,
        ResidualScanUniverseRevision,
        ResidualScanUniverseDigest,
        DerivedResidualScopeId,
        ObserverBindingRevision,
        DerivedTargetId,
        DerivedTargetBusinessFactDigest,
        DerivedTerminalTargetObservationDigest,
        PrimaryExecutionLineageDigest,
        CurrentDerivedAuthoritySourceSetV1,
        CurrentAuthoritySourceSetDigest,
        AuthoritySourceBusinessFactRoot,
        BackendReleaseTupleDigest,
        FixedRegeneratorIdentity,
        BeforeOutputBoundaryToken,
        AfterOutputBoundaryToken,
        CanonicalNativeDerivedOutputDigest,
        NormalizedTerminalResult = ExactSuccess,
        observed_at,
        expires_at
      },
      ResidualQueryFixedRegeneratorResultReceiptDigest
    }

    ResidualQueryDerivedMemberProofV1 {
      Body = ResidualQueryDerivedMemberProofBodyV1 {
        SchemaVersion = 1,
        ResidualQueryContextDigest,
        InstallationId,
        ResidualScanUniverseRevision,
        ResidualScanUniverseDigest,
        DerivedResidualScopeId,
        ObserverBindingRevision,
        BackendReleaseTupleDigest,
        PlatformItemIdentityDigest,
        MemberIdentityDigest,
        ExactMemberIdentity,
        CertificateObservation,
        NormalizedTrustSemantic,
        DerivedTargetId,
        DerivedTargetBusinessFactDigest,
        DerivedTerminalTargetObservationDigest,
        DerivedResidualQueryTargetObservationDigest,
        CurrentDerivedAuthoritySourceSetV1,
        CurrentAuthoritySourceSetDigest,
        AuthoritySourceBusinessFactRoot,
        ResidualQueryFixedRegeneratorResultReceiptV1,
        ResidualQueryFixedRegeneratorResultReceiptDigest,
        BeforeOutputBoundaryToken,
        AfterOutputBoundaryToken,
        CanonicalNativeDerivedOutputDigest,
        observed_at,
        expires_at
      },
      ResidualQueryDerivedMemberProofDigest
    }

Their digests cover only the canonical bodies under their registered domains.
Every vector count exactly equals its vector length and each vector obeys the
semantic-key sorting and uniqueness rule above, in addition to the signed
manifest count/byte limits. Every
digest reference in a source set or member resolves to exactly one complete
object in the same query context and scan. The regenerator receipt contains no
derived query observation, member proof, enumeration/result, resulting state,
complete quiescent business body, stable receipt, or response digest. The member proof contains no enclosing
member key/body or consumer result. The construction order is direct source
members and fresh source observations, source-set digest, regenerator receipt,
fresh derived observation, derived-member proof, then enclosing member and scan
result; reverse references are invalid.

Resolution alone is insufficient. The following duplicated fields MUST be
byte-identical:

- a source set and the enclosing derived provenance use the same query context,
  installation, universe revision/digest, derived scope/target, complete primary
  lineage, observer binding, backend release, complete direct-source vector,
  source-set digest, and AuthoritySourceBusinessFactRoot;
- its regenerator result uses that same context, installation, universe,
  derived scope/target, lineage, complete inline source set/digest/business root,
  and its
  observer binding, backend release, fixed regenerator, output boundary-token
  pair, native output, and freshness equal the derived target observation and
  enclosing enumeration;
- the derived target observation's context, installation, universe, scope,
  observer binding, backend release, selected terminal anchor, current fact,
  primary target, complete inline source set/result, their digests, the
  authority-source business root, boundary
  tokens, output, and freshness equal the corresponding fields in that result,
  source set, enclosing enumeration, and selected target records;
- a member proof's platform item, exact member identity, certificate
  observation, trust semantic, context, installation, universe, derived scope,
  observer binding, backend release, derived target/fact/terminal/query
  observation, complete inline source set and regenerator result, the
  authority-source business root, output
  boundary-token pair, native output, and freshness equal the enclosing member,
  target observation, enumeration, and provenance byte-for-byte; and
- every repeated digest is independently recomputed from the complete inline
  object before those equality checks.

A cross-member, cross-target, cross-scope, cross-observer-binding,
cross-release, cross-output, cross-time, or same-key/different-body substitution
invalidates the complete scan rather than selecting a locally convenient
object.

BoundedDerivedProvenanceDigest uses the scope-enumeration domain with tag
`"derived-provenance-unknown\0"` over the exact complete inline
BoundedDerivedProvenanceBodyV1; its reason vector is closed, bounded, sorted,
and unique. A missing source, unbounded hook, mixed release, stale result,
digest mismatch, incomplete source vector, target/query-anchor mismatch, or
unresolvable complete object is DerivedProvenanceUnknown. Derived evidence
grants no InstallerOwner, delete, rewrite, or whole-output authority.

HistoricalIdentityOrdinal is a canonical uint32, zero-based index into the
exact bound universe's sorted historical-identity vector. A
HistoricalIdentityMatch is valid only after the observer parses the complete
certificate bytes and proves byte equality to the exact CaPublicIdentityV1 at
that ordinal. OtherCertificate is valid only after the complete parsed DER was
compared against every historical identity and matched none; its two hashes and
length are recomputed from those bytes. NonCertificateTrustObject uses the
closed ObjectKind and exact canonical object bytes fixed by the observer
schema. Purpose OIDs are canonical DER object identifiers sorted by DER bytes;
duplicates and nonminimal encodings are invalid. The trust-semantic, ownership,
and consumer-outcome unions above are closed. The parent platform item's
FlowProbeOwned evidence must verify its exact owner receipt and owned after
image; ExternalPreExisting must verify the retained exact before image; and
ExternalCurrentObserved must verify the complete same-context
NoFlowProbeOwnershipProofV1.
ExternalObservedUnknown, DerivedProvenanceUnknown, UnknownTrustSemantic, or
Ambiguous is diagnostic only and cannot authorize a matching historical
identity. A platform item whose
members are all foreign/nonmatching remains complete enumeration evidence and
does not by itself block the query; it blocks only if it participates in, or
makes ambiguous, a historical-identity trust/consumer projection.

ConsumerObservationKey is
`SHA-256("FlowProbe.TrustCa.ResidualConsumerObservation.v1\0" || "entry\0" ||
canonical(ResidualConsumerObservationBodyV1))`. An ExactAnchorAccepted body is
valid only when the fresh chain's exact anchor DER hash equals the historical
identity being aggregated and its platform/member identity digests equal the
enclosing member; rejected, excluded, and ambiguous outcomes are not
positive trust evidence. Each per-member consumer vector is sorted by key and
duplicate keys or duplicate consumer/release/hostname tuples are invalid.

ItemObservationKey is
`SHA-256("FlowProbe.TrustCa.ResidualScopeEnumeration.v1\0" || "item\0" ||
canonical(NormalizedResidualPlatformItemBodyV1))`. Enumeration items are
sorted by that key and duplicate keys are rejected. CompleteEnumerationRoot is
the registered-domain digest of the complete
ResidualScopeEnumerationBodyV1; it therefore binds the exact universe/scope,
current observer release/schema, two boundary tokens, all four query-evidence
counts/vectors, item count, and every bounded normalized platform-item body and
all of its members. Two byte-equal
certificates in distinct platform items remain separate members because their
PlatformItemIdentityDigest values differ; two views of the same exact platform
item are a duplicate error, never collapsed.

For each present historical identity, the verifier derives exactly:

    ResidualOwnershipAggregateBodyV1 {
      SchemaVersion = 1,
      ResidualScanUniverseRevision,
      ResidualScanUniverseDigest,
      ResidualScopeId,
      HistoricalIdentityOrdinal,
      SortedUniqueControlledOwnedItemMemberObservationKeyVector,
      SortedUniquePreservedExternalItemMemberObservationKeyVector,
      SortedUniqueUnknownAuthorityItemMemberObservationKeyVector
    }

Those three vectors are disjoint, sorted, and their ordered union is exactly
SortedUniqueMatchingItemMemberObservationKeyVector. A DirectPlatformItem member
is controlled-owned, preserved-external, or unknown according to its exact
parent ownership. A DerivedFromPrimaryAuthority member is controlled-owned only
when its complete current source vector is nonempty and every source is
FlowProbeOwnedAuthority; it is preserved-external when at least one complete
source is ExternalPreExistingAuthority or ExternalCurrentObservedAuthority; an
incomplete/unknown source set is
unknown. Historical primary ownership does not override the current source
set. The explicit derived-authority link
may classify provenance only: it cannot import trust semantic or consumer
success from the authority item, grant ownership of the derived item, or grant
mutation authority. ExactOwnershipAggregateDigest is the registered ownership-
aggregate-domain digest of that complete body.
CompleteConsumerObservationRoot is
`SHA-256("FlowProbe.TrustCa.ResidualConsumerObservation.v1\0" || "root\0" ||
canonical(SortedUniqueMatchingConsumerObservationEntryVector))`, where the
vector is the sorted unique union of every `{ConsumerObservationKey, Body}`
carried by exactly those matching member bodies. A duplicate key with different
bytes is integrity failure.

EffectiveTrustDispositionDigest is the registered scan-trust-disposition-
domain digest of:

    ResidualScanTrustDispositionBodyV1 {
      SchemaVersion = 1,
      ResidualScanUniverseRevision,
      ResidualScanUniverseDigest,
      ResidualScopeId,
      HistoricalIdentityOrdinal,
      SortedUniqueMatchingItemMemberObservationKeyVector,
      CompleteConsumerObservationRoot,
      Disposition = PreservedExternalLive {
          SortedUniqueQualifyingExternalItemMemberObservationKeyVector,
          SortedUniqueExactAnchorAcceptedConsumerObservationKeyVector
        }
      | ConservativeExternalTrustPotential {
          SortedUniqueQualifyingExternalItemMemberObservationKeyVector,
          SortedUniqueProbeUnavailableAfterKeyDestructionConsumerObservationKeyVector,
          SortedUniqueHistoricalKeyTerminalEvidenceVector = [
            {
              CaGeneration,
              HistoricalCaPublicIdentityDigest,
              DestroyedTerminalKeyEvidenceV1,
              DestroyedTerminalKeyEvidenceDigest
            }
          ]
        }
      | OwnedOnly {
          SortedUniqueQualifyingOwnedItemMemberObservationKeyVector
        }
      | NotTrusted
      | Ambiguous {
          SortedUniqueAmbiguousEvidenceKeyVector
        }
    }

A qualifying external member key MUST name one member classified preserved-
external by the exact ownership aggregate and whose own body simultaneously has
ServerAuthTrusted semantic. PreservedExternalLive additionally requires an
ExactAnchorAccepted consumer observation anchored at this historical identity;
its two vectors are exactly all such member keys and all accepted consumer keys
contained by those same members. ConservativeExternalTrustPotential instead
requires, in each listed member, a
ProbeUnavailableAfterKeyDestruction observation whose complete body resolves to
the exact matching Destroyed record/receipt/ancestry. Its three vectors contain
exactly all such member keys, consumer keys, and unique historical-key terminal
evidence entries. A conservative member is not a live trust success; it is the
fail-safe statement that current exact external serverAuth trust still exists
but a fresh leaf for that exact historical key can no longer be created.
The historical-key vector is strictly sorted by
`(CaGeneration, HistoricalCaPublicIdentityDigest)`, rejects duplicate semantic
keys, and contains exactly one independently verified terminal-evidence object
for every probe-unavailable result; every duplicated generation, public
identity, and evidence digest is byte-identical to that consumer result.

Ownership from one item may never be joined with trust semantic or consumer
evidence from another; the derived-source provenance link above does not relax
that rule. Either external variant is valid iff its member vector is nonempty
and the complete matching set contains no unknown/ambiguous evidence.
PreservedExternalLive takes precedence when every required live probe exists;
the conservative variant is selected only for qualifying members whose sole
missing fact is the destroyed-key live probe. OwnedOnly is valid iff no
qualifying external member exists, the complete matching set contains no
unknown/ambiguous ownership, derivation, trust, or consumer evidence, at least
one controlled-owned member carries both ServerAuthTrusted and exact-anchor
acceptance in that same member, and its vector lists exactly all such member
keys. NotTrusted is valid iff neither qualifying path exists and every
member/consumer outcome is unambiguous negative or excluded. A destroyed-key
probe-unavailable result is never negative and therefore cannot select
NotTrusted. Any other complete matching set selects Ambiguous, and Ambiguous
makes the public identity-set query unavailable. The known-residual projection
includes exactly the historical identities with at least one per-scope
PreservedExternalLive or ConservativeExternalTrustPotential disposition.

SortedUniqueAmbiguousEvidenceKeyVector is not caller-chosen. It equals the
complete sorted unique union of: every unknown-authority member key; every
member key carrying UnknownTrustSemantic; and every ConsumerObservationKey
whose outcome is Ambiguous. Each entry is the closed tagged pair
`{EvidenceKind = AuthorityProvenance | TrustSemantic | Consumer, Digest}` sorted
by `(EvidenceKind, Digest)`. An omitted, extra, duplicate, differently tagged,
or cross-domain digest invalidates the disposition; an otherwise malformed
ownership/provenance/result body invalidates the scan rather than being hidden
inside Ambiguous.

CompleteScopeBitmap and HistoricalIdentityPresenceBitmap are canonical byte
strings. For a vector of N entries they contain exactly `ceil(N / 8)` bytes;
entry i uses the bit `0x80 >> (i mod 8)` in byte `floor(i / 8)`, and unused low
bits of the final byte are zero. The empty vector uses an empty byte string.
CompleteScopeBitmap has every in-range bit set. A historical-presence bit is one
iff exactly one present-identity row with that zero-based ordinal exists; a zero
bit forbids such a row. Alternate bit order, padding, integer ordinal width, or
bitmap length is noncanonical.

Every RequiredTargetBitmap uses the same canonical byte-string rule with N
equal to the exact template-entry or target-record vector length. Bit i is one
iff entry i is Required, unused low bits are zero, and an empty vector uses an
empty byte string. Boolean-vector, low-bit-first, integer, overlong, short, or
nonzero-padding encodings are noncanonical.

The signed product manifest fixes
MaximumCanonicalCaPublicIdentityEncodedBytes,
MaximumResidualHistoricalIdentityCount, MaximumResidualScopeCount,
MaximumResidualUniverseEncodedBytes, MaximumResidualScanResultEncodedBytes,
MaximumResidualObservationLifetime,
MaximumResidualEnumeratedItemCountPerScope,
MaximumResidualObservedMemberCountPerItem,
MaximumResidualConsumerObservationCountPerMember, and
MaximumResidualScopeEnumerationBodyEncodedBytes. Each is a finite, strictly positive uint64 semantic value encoded in canonical
shortest form in the signed manifest and cannot equal `UINT64_MAX`. Manifest validation additionally requires
MaximumResidualHistoricalIdentityCount, MaximumResidualScopeCount,
MaximumResidualEnumeratedItemCountPerScope,
MaximumResidualObservedMemberCountPerItem, and
MaximumResidualConsumerObservationCountPerMember to be no greater than
`UINT32_MAX`;
the ARCH-002 set count, all vector counts used by these schemas, and every
bitmap/container ordinal use that bound.
Each selected ResidualScopeObserverBindingV1 per-scope
MaximumEnumeratedItemCount, MaximumObservedMemberCountPerItem,
MaximumConsumerObservationCountPerMember, and
MaximumResidualScopeEnumerationEncodedBytes is respectively no greater than
those four signed global fields. A scope may select a smaller exact supported
limit but never a larger or caller-defaulted one.
Every selected canonical ResidualScanUniverseBodyV1 MUST be no larger than its
universe maximum; every complete ResidualScanResultBodyV1 MUST be no larger
than its result maximum; and each canonical enumeration body MUST be within its
scope maximum. Length is always `len(canonical_encode(body))`, with no stored
self-length field.

The catalog maintains a Cartesian worst-case invariant: replacing every
identity reservation by one maximum-size CaPublicIdentityV1, setting every
historical-presence bit, emitting every maximum-size matching row in every
scope, enumerating each scope to its item/member/consumer/body maxima, and crossing every
canonical map/vector/count integer-width boundary still fits both complete
universe and result maxima. A selected universe that cannot prove this
invariant is integrity failure.

Before Generate or RotatePrepare consumes consent or calls a key provider, the
helper starts from the exact selected universe U0, constructs pure staged U1
with one operation/generation reservation plus the phase's sorted set of
plan-exact first-use scopes/current observer bindings, and proves both U1 and the
hypothetical Umax obtained by replacing that reservation with a
MaximumCanonicalCaPublicIdentityEncodedBytes identity satisfy the complete-body
and Cartesian result bounds. ReservedMaximumUniverseGrowthEncodedBytes and
ReservedMaximumScanResultGrowthEncodedBytes are authenticated uint64 semantic
values encoded in canonical shortest form and are upper bounds for those exact
worst-case deltas, including the reservation
entry, replacement, all headers/framing/count widths, every existing scope
bitmap, and matching-row growth. The reservation is selected with consent and
the pending generation commitment before the provider call.

After the key ledger is durably Ready and cross-bound to the pending helper
operation, the helper replaces only that reservation with the exact
CaPublicIdentityV1 before Generated; after terminal cross-bound
post-dispatch CreateUnapplied or CreateUnappliedNeverStarted, it releases only
that reservation using the matching closed receipt variant. The selected successor is
re-encoded and rechecked against both maxima. Because helper and key ledgers
are not cross-store atomic, the identity-set read remains unavailable between
either key-ledger terminal commit and its helper-universe refinement.
HistoricalIdentityCount plus reservation count never exceeds the identity
maximum or `UINT32_MAX`. Every answerable sorted identity-set union is also at
most `UINT32_MAX`; an addition or reservation replacement that could exceed the
bound is rejected before consent consumption or any provider/platform side
effect.

Before a consented plan may first use a scope, the helper proves the exact
manifest-registered scope entry is byte-for-byte the stable projection and
observer binding of one target in that plan, then proves the complete successor
universe and its Cartesian worst-case scan result fit. It appends that scope in
the same state-index selection that consumes consent and publishes the pending
plan, before any key/trust side effect. For Generate/RotatePrepare this is the
same combined U1 that also adds the identity reservation; there is no
intermediate reservation-only or scope-only selected universe. For every other
phase it is that phase's single pending-state selector. Extra/substituted scopes and unknown
renderer scopes are rejected and cannot consume capacity. Any count/byte
failure rejects before consent or side effect. A full lifetime catalog makes
further generation or first use of a new scope UnsupportedByProductPolicy
until a separately authorized architecture changes the bound; it never evicts
evidence to make room.

Every universe selection carries this immutable journal record:

    ResidualUniverseSuccessorRecordV1 {
      Body = ResidualUniverseSuccessorRecordBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        PriorUniverse = Genesis
          | SelectedPredecessor {
              PriorUniverseRevision,
              PriorResidualScanUniverseDigest
            },
        ResultingUniverseRevision,
        ResultingResidualScanUniverseDigest,
        SortedUniqueMutationVector = [
          AddResidualScope {
            ResidualScopeId,
            CompleteResidualScopeEntryDigest
          }
        | AddIdentityCapacityReservation {
            TrustOperationId,
            CaGeneration,
            ResidualIdentityCapacityReservationDigest
          }
        | RefineReservationToIdentity {
            TrustOperationId,
            CaGeneration,
            ResidualIdentityCapacityReservationDigest,
            CertificatePublicIdentityDigest,
            CaPublicIdentityV1,
            KeyCreatedReceiptDigest
          }
        | ReleaseCreateUnappliedReservation {
            TrustOperationId,
            CaGeneration,
            ResidualIdentityCapacityReservationDigest,
            TerminalCreateReservationReleaseEvidence =
                PostDispatchCreateUnapplied {
                  KeyCreateUnappliedReceiptV1,
                  KeyCreateUnappliedReceiptDigest
                }
              | NoDispatchCreateNeverStarted {
                  KeyCreateNeverStartedReceiptV1,
                  KeyCreateNeverStartedReceiptDigest
                }
          }
        | AppendObserverBinding {
            ResidualScopeId,
            PriorObserverBindingRevision,
            ResultingObserverBindingRevision,
            CompleteObserverBindingEntryDigest
          }
        ]
      },
      ResidualUniverseSuccessorRecordDigest
    }

The successor-record digest covers only its digest-free body under the
registered successor domain. Mutation entries are sorted by closed variant tag
and then their shown primary identity; duplicates conflict. Genesis is valid
only for the installation's first empty catalog. Every later revision is the
nonwrapping predecessor revision plus one and has exactly one selected
predecessor. The verifier applies the complete mutation vector to the exact
prior body, canonically re-sorts it, recomputes the complete resulting body and
digest, and rejects any unlisted edit. One vector may contain the admission-
required reservation plus multiple first-use scopes; reservation refinement or
release is the only way to add/resolve a historical identity and cannot delete
a historical identity/scope. A direct unreserved identity insertion is invalid. The trust-
journal hash chain and state selector admit only one successor record for the
selected lineage; a fork is integrity failure.
ReleaseCreateUnappliedReservation accepts exactly the terminal receipt variant
matching the selected key-generation terminal tag: post-dispatch
CreateUnapplied requires PostDispatchCreateUnapplied, while no-dispatch
CreateUnappliedNeverStarted requires NoDispatchCreateNeverStarted. The complete
receipt and digest independently verify and repeat operation, generation,
reservation, key terminal record, and result byte-for-byte. Cross-variant or
digest-only release evidence is invalid.

UniverseRevision is nonwrapping. Every universe change is journaled and
copy-on-write selected with the state index, and its revision/digest form an
authenticated member-addition, observer-binding append, or
reservation-add/refine/release successor of the prior pair.
Every pending snapshot retains the exact reservation and universe root that
preceded its side effect. Journal compaction MUST retain the complete current
universe body and all pending reservations, so later Absent reconciliation
never depends on discarded generation or scope records.

An OS/package/backend update never edits an old scope or makes its historical
release tuple the current observer forever. Under the global lock,
RefineResidualObserverBindingV1 verifies a signed product manifest that names
the exact existing ResidualScopeId, stable scope, new backend release tuple,
observer class, and per-scope limits within the installation manifest's hard
maxima, plus the exact ResidualObserverSchemaDigest; proves the successor universe
and Cartesian result bounds; and appends the next observer-binding revision
containing that release tuple, manifest/schema digests, and those limits. It never
edits an earlier binding entry or any stable-scope field.
It then journals and copy-on-write selects the new universe/envelope. This is a
non-authorizing metadata refinement: it consumes no user consent, performs no
key/trust mutation, and cannot select AdmissionEligible. If Generated or
InstalledAndVerified relied on the old release evidence, the gate closes and
the same selection enters Drifted before that new binding can support a proof.
Pending operations defer refinement until their sealed operation resolves;
RecoveryRequired(None) may refine only to enable observation recovery. A crash
selects the complete old or new binding. Rollback appends a newly manifest-
authorized binding for the older release; it never selects an old universe
revision. Until a compatible current binding is selected, every identity-set
query is unavailable. Historical binding entries remain provenance but only
the last binding is used for enumeration.

The scan protocol is globally ordered, not one independent local scan at a
time. Under the same global lock, it first reads
AllScopeBeforeTokenVector for every universe scope in scope-vector order,
then completes every enumeration, and only then reads
AllScopeAfterTokenVector for every scope in that same order. Each token-vector
entry is exactly `{ResidualScopeId, ObserverBindingRevision,
ObservationBoundaryToken}` and both vectors have exactly one entry per current
scope. A backend token must be monotonic, no-ABA, and guaranteed to advance for
every relevant certificate, trust, ownership, consumer, or release change;
moving an item across scopes must advance the source and destination tokens.
Every before token must equal its after token. A documented cross-scope atomic
snapshot may implement those semantics internally, but it still emits the two
equal vectors. A platform lacking this guarantee is incomplete and cannot
produce an identity-set proof.

PerScopeObservationVector has exactly one entry per universe scope in the same
order, and CompleteScopeBitmap has exactly one all-one bit per entry. Its
inline CompleteEnumeration independently verifies and its duplicate
CompleteEnumerationRoot equals that wrapper's root; the enumeration body's
scope, current observer binding, and boundary tokens match both global vectors.
EnumeratedItemCount equals the enumeration vector length. Every
HistoricalIdentityPresenceBitmap has exactly one bit per historical identity
in the bound universe order. A one bit has exactly one present-observation row,
rows are strictly ordered by HistoricalIdentityOrdinal, and its matching-item
member-key vector contains every exact matching enumeration member in
ItemMemberObservationKey order. The ownership aggregate, effective-trust
disposition, and consumer root are deterministic projections of exactly those
member bodies plus their exact parent ownership bodies. A zero bit is
authoritative negative evidence only after the complete enumeration and global
barrier both pass.

Complete enumeration includes foreign items that do not match a historical
identity; their protected bodies remain verifier evidence and are not exposed
by the public query. Truncation, count/body/result overflow, missing/extra or
reordered scope/identity/item rows, a duplicate key, token change, unknown
current observer release, or a scope without stable complete enumeration makes
the result invalid and every identity-set query unavailable.

FreshOwnedTargetAbsenceRoot, FreshKnownResidualCaIdentitySetDigest, and
FreshPreservedExternalBusinessRoot below are deterministic projections of the
exact universe/result plus retained ownership records. The known residual
digest includes exactly the historical identity ordinals whose complete
per-scope evidence proves either a live preserved external path or a conservative
destroyed-key trust potential. A conservative entry is never pruned merely by
time, CA/leaf expiry, or inability to probe; only a later complete fresh scan
proving the external item gone or definitively non-serverAuth removes it. The no-live-or-
ambiguous-key digest is independently projected from the authenticated key
ledger. The resulting AbsentBusiness fields MUST equal those four fresh
projections byte-for-byte.

For every non-Absent state, a changed fresh residual projection is committed
through this non-authorizing journal record before an identity-set proof can be
signed:

    ResidualIdentityObservationRecordV1 {
      Body = ResidualIdentityObservationRecordBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        ExpectedLifecycleStateTag,
        ExpectedStateDigest,
        ExpectedMonotonicSafetyEnvelopeDigest,
        ResidualScanUniverseRevision,
        ResidualScanUniverseDigest,
        ResidualQueryContextDigest,
        ResidualScanResultDigest,
        ExactPriorIdentitySetDigest,
        ExactResultingIdentitySetDigest,
        ExactResultingSelectedTargetFactStateRoot,
        ExactResultingSelectedTargetFactCount,
        StateObservationUpdate =
            EnterDrifted {
              ExactLastStableBusinessPostconditionDigest,
              UpdatedKnownCaIdentitySetDigest,
              ResidualDriftFindingBusinessRoot,
              ExactObservedIdentityOwnershipTargetKeyRoot
            }
          | RefreshPending {
              ExactPredecessorCompletePendingOperationSnapshotDigest
            }
          | RefreshDrifted {
              ExactPriorDriftedBusinessPostconditionDigest,
              UpdatedKnownCaIdentitySetDigest,
              AppendedDriftFindingBusinessRoot,
              UpdatedExactObservedIdentityOwnershipTargetKeyRoot
            }
          | RefreshRecoveryRequired {
              ExactLastQuiescentStateSnapshotDigest,
              ExactOptionalCompletePendingOperationSnapshotDigestOrNone,
              UpdatedKnownCaIdentitySetDigest,
              UpdatedUnresolvedObservationRoot,
              AppendedBoundedReasonRoot
            }
      },
      ResidualIdentityObservationRecordDigest
    }

The digest covers only the digest-free body under the registered residual-
identity-observation domain. It contains no resulting journal head, envelope,
state digest, receipt digest, or signature, so the commit graph is acyclic.
Every Expected* value and prior digest MUST equal the selected state/envelope;
the context/universe/result triple must be the exact scan performed for the current
query. The update union is closed and cannot change a CA/key/target, operation
plan, consent, recovery disposition, ownership record, or gate from closed to
AdmissionEligible. ExactPriorIdentitySetDigest, ExactResultingIdentitySetDigest, and every
UpdatedKnownCaIdentitySetDigest directly equal the applicable ARCH-002 sorted-
SPKI digest under `FlowProbe.Egress.FlowProbeCaExclusionSet.v1`; none is wrapped
or rehashed under the residual-observation domain.

EnterDrifted, RefreshDrifted, and RefreshRecoveryRequired append this complete
native record through one TrustJournalRecordLinkV1, derive the resulting head
and closed envelope, and only then construct a new GateClosedReceiptV1 over that
exact head/envelope. EnterDrifted uses ClosedNow unless the selected predecessor
was already closed; refresh variants use RetainedClosed. The resulting payload,
StateEvidence, envelope, and receipt repeat the same gate epoch, key tip,
revision, and head. The observation record contains no receipt or resulting
head/envelope digest. RefreshRecoveryRequired is valid only when the selected
recovery has GateClosureEvidenceV1=SignedGateClosed and an Active attestation
anchor. AttestationAnchorInvalidated rejects this record before append and
retains the selected recovery state byte-for-byte.

The resulting selected-target vector is deterministically reconstructed from
the predecessor vector and this exact scan: all definite observations carrying
one TargetId MUST project to one byte-identical complete
CurrentTargetBusinessFact (a historical-identity row cannot select a competing
fact), that entry is replaced once, every untouched entry is
retained byte-for-byte, every immutable terminal anchor is retained byte-for-
byte, and no entry may be inserted or removed except when the authenticated
state-specific transition itself introduces or retires that exact target. Its
canonical uint32 count and root MUST equal
ExactResultingSelectedTargetFactCount and
ExactResultingSelectedTargetFactStateRoot, respectively, and the selected successor
TrustLifecycleStateBodyV1. Ambiguous or incomplete facts cannot construct a
root and therefore cannot select this record.

EnterDrifted is valid only from Generated or InstalledAndVerified; it closes
the gate before publication and constructs the exact Drifted business body
with the old stable digest plus the new complete identity/residual projection
and issues the matching DriftedReceiptV1 in the same selected transition.
RefreshPending's ExactPredecessorCompletePendingOperationSnapshotDigest equals
the complete snapshot selected by ExpectedStateDigest. The successor snapshot
uses PendingSnapshotLineage=ResidualObservationSuccessor with that
predecessor digest and this record's independently recomputed digest. It retains
the sealed operation core, exact base snapshot/receipt, phase plans, consents,
recovery dispositions, steps, intended postconditions, failure disposition,
and immutable operation anchors byte-for-byte, but carries the newly
reconstructed selected-target vector/root/count and the successor monotonic
envelope. The fresh scan is bound by this journal record's
ResidualQueryContextDigest and ResidualScanResultDigest, while the same selector
updates the state-index identity-set digest and selects that new snapshot and
envelope. The record does not contain the resulting snapshot body/digest,
envelope digest, state digest, or journal head. This variant is valid only when
the changed residual projection is off-plan and leaves every exact planned
target/key observation and CompletePerTargetStepVector fact byte-identical. A
change to a planned target is not representable by RefreshPending.
RefreshDrifted retains
LastStableBusinessPostconditionDigest and only
updates the bounded current observations/findings. RefreshRecoveryRequired
retains both snapshots byte-for-byte and updates only the top-level known set,
unresolved observation, and bounded reason evidence; it cannot remove or replace
an AttestationAnchorInvalidated reason. Each permitted update fsyncs this
record, advances TrustStateRevision/journal head once, stages the resulting
same-state or Drifted state, identity-set digest, and monotonic envelope in one
copy-on-write slot, and selects it before proof signing. A crash chooses the
complete old or new state; retry always rescans.

The canonical journal body and stable receipt are:

    AbsentResidualObservationRecordBodyV1 {
      SchemaVersion = 1,
      InstallationId,
      ExpectedAbsentBusinessPostconditionDigest,
      ExpectedMonotonicSafetyEnvelopeDigest,
      ExpectedTrustStateRevision,
      ExpectedTrustJournalHeadDigest,
      ExpectedKeyAuthorityEpoch,
      ExpectedKeyStateRevision,
      ExpectedKeyJournalHeadDigest,
      ResidualScanUniverseRevision,
      ResidualScanUniverseDigest,
      ResidualQueryContextDigest,
      ResidualScanResultDigest,
      FreshOwnedTargetAbsenceRoot,
      FreshNoLiveOrAmbiguousKeyPostconditionDigest,
      FreshKnownResidualCaIdentitySetDigest,
      FreshPreservedExternalBusinessRoot,
      ResultingAbsentBusinessPostconditionDigest,
      ResultingSelectedTargetFactStateRoot,
      ResultingSelectedTargetFactCount,
      observed_at,
      expires_at
    }

    AbsentResidualObservationRecordV1 {
      Body = AbsentResidualObservationRecordBodyV1,
      AbsentResidualObservationRecordDigest
    }

The stable receipt key evidence is built from this complete non-signature
projection of the authenticated key ledger. First, every retained append is
represented by one closed link:

    KeyLedgerRecordLinkV1 {
      KeyAuthorityEpoch,
      KeyStateRevision,
      ExpectedPredecessorKeyStateRevision,
      ExpectedPredecessorKeyJournalHeadDigest,
      CaGeneration,
      CaInstanceId,
      ProviderAndVersion,
      RecordDigest,
      RecordStateProjection =
          Creating {
            GenerationCommitmentDigest,
            ProviderCreateOperationId,
            CreatePreCallProviderAbsenceProofDigest,
            ProviderCallInvocationMarkerDigest
          }
        | Ready {
            CaPublicIdentityDigest,
            CertificateSpkiSha256,
            NonExportableKeyIdentityDigest,
            ProviderObjectNonAliasingTagDigest,
            ProviderSecretNonAliasingTagDigest,
            ProviderKeyUniquenessEvidenceDigest,
            ProviderCallInvocationMarkerDigest,
            KeyCreatedReceiptDigest
          }
        | CreateUnapplied {
            GenerationCommitmentDigest,
            ProviderCreateOperationId,
            ProviderCallInvocationMarkerDigest,
            KeyCreateUnappliedReceiptDigest
          }
        | CreateUnappliedNeverStarted {
            GenerationCommitmentDigest,
            ProviderCreateOperationId,
            ProviderOperationReservationRecordDigest,
            CreateNeverStartedProviderAbsenceProofDigest,
            KeyCreateNeverStartedReceiptDigest
          }
        | DestroyPending {
            LastReadyRecordDigest,
            LastCaPublicIdentityDigest,
            CertificateSpkiSha256,
            KeyDestroyOperationId,
            KeyDestroyIntentDigest,
            ProviderCallInvocationMarkerDigest,
            ExpectedPreDestroyCompleteKeyGenerationStateRoot
          }
        | Destroyed {
            LastCaPublicIdentityDigest,
            CertificateSpkiSha256,
            NonExportableKeyIdentityDigest,
            ProviderObjectNonAliasingTagDigest,
            ProviderSecretNonAliasingTagDigest,
            ProviderCallInvocationMarkerDigest,
            KeyDestroyedReceiptDigest
          }
        | Ambiguous {
            AmbiguityKind,
            ProviderCallInvocationMarkerDigest,
            DestroyForbiddenWhenAliasingUnresolved
          },
      ResultingKeyJournalHeadDigest
    }

RecordStateProjection is the exact privacy-preserving projection recomputed by
the key authority from the internal CaKeyRecordV1 before it signs any enclosing
receipt/proof. It contains only public identities and domain-separated internal
identity/tag commitments, never NonExportableKeyIdentity, a provider handle, or
private material. All duplicated epoch/revision/generation/instance/provider/predecessor and
state-specific digest fields, including every ProviderCallInvocationMarkerDigest,
MUST match the internal record; the attestation
signature on the consuming stable/query receipt authenticates that equality.
The retained key-journal head has one closed canonical body and wrapper:

    KeyJournalHeadBodyV1 =
        Genesis {
          SchemaVersion = 1,
          InstallationId,
          KeyAuthorityEpoch,
          InstallationAttestationAnchorDigest,
          KeyAuthorityAttestationKeyId,
          SignedProductManifestDigest,
          TrustCaAttestationPolicyDigest,
          KeyStateRevision = 0,
          EmptyCompleteKeyLedgerRecordRoot,
          EmptyCompleteKeyGenerationStateRoot,
          EmptyProviderOperationReservationRoot
        }
      | Append {
          SchemaVersion = 1,
          InstallationId,
          KeyAuthorityEpoch,
          KeyStateRevision,
          ExpectedPredecessorKeyStateRevision,
          ExpectedPredecessorKeyJournalHeadDigest,
          RecordDigest
        }

    KeyJournalHeadV1 {
      Body = KeyJournalHeadBodyV1,
      KeyJournalHeadDigest
    }

    KeyJournalHeadDigest = SHA-256(
      "FlowProbe.TrustCa.KeyJournalHead.v1\0" ||
      ("genesis\0" | "append\0") ||
      canonical(KeyJournalHeadBodyV1)
    )

The selected variant chooses exactly one of the two literal field tags in the
digest preimage. Genesis is selected exactly once by the key authority during
installation bootstrap. Its InstallationId and KeyAuthorityEpoch equal
the installation-pinned key-authority identity, and its three empty roots are
the independently recomputed roots of the canonical empty vectors defined by
this contract. It contains no RecordDigest, predecessor head, provider
operation, key record, receipt, helper journal, envelope, or resulting state.
A second genesis, a genesis for another InstallationId or authority epoch, a
nonempty root, or use of Genesis as an append predecessor body without the
complete selected wrapper is integrity failure. Key-authority epoch rollover is
not a v1 operation; an Append therefore requires KeyAuthorityEpoch and the
selected predecessor wrapper's KeyAuthorityEpoch to equal the genesis epoch
byte-for-byte.
Every Append inherits the Genesis InstallationAttestationAnchorDigest,
KeyAuthorityAttestationKeyId, InitialSignedProductManifestDigest, and
TrustCaAttestationPolicyDigest through the selected predecessor chain. Any
in-place key, anchor, policy, or installation-epoch change is integrity failure;
v1 has no attestation-key rotation or reinitialization transition.

For Append, KeyStateRevision and the corresponding link's
KeyStateRevision are the checked, nonwrapping
ExpectedPredecessorKeyStateRevision plus one. InstallationId, epoch, both
revisions, predecessor digest, and RecordDigest equal the complete
KeyLedgerRecordLinkV1 and its selected predecessor head. The link's
ResultingKeyJournalHeadDigest is exactly the recomputed digest of this Append
wrapper. A digest made with the other variant tag, a skipped revision, a cross-
installation predecessor, an epoch substitution, or a digest-only predecessor
is invalid.

The first link starts at that complete selected revision-zero key-ledger genesis
head. CompleteKeyLedgerRecordVector is strictly sorted by KeyStateRevision,
contains every revision exactly once, and each link's predecessor revision/head
equals the preceding link's resulting revision/head. Its count and canonical
vector are committed as:

    CompleteKeyLedgerRecordRoot = SHA-256(
      "FlowProbe.TrustCa.KeyLedgerRecordChain.v1\0" ||
      uint64_be(CompleteKeyLedgerRecordCount) ||
      canonical(CompleteKeyLedgerRecordVector)
    )

Before any key-record append, the key authority constructs the complete
resulting vector. Its exact uint64 count MUST be no greater than the current
signed manifest's MaximumKeyLedgerRecordCount and
`len(canonical(CompleteKeyLedgerRecordVector))` MUST be no greater than
MaximumKeyLedgerRecordVectorEncodedBytes. Checked count/size exhaustion rejects
the append before a provider call, receipt, helper journal record, envelope, or
selector is made durable; no historical link is removed to create capacity.

`DestroyedRecordProjectionV1` is exactly the closed
`RecordStateProjection.Destroyed {LastCaPublicIdentityDigest,
CertificateSpkiSha256, NonExportableKeyIdentityDigest,
ProviderObjectNonAliasingTagDigest, ProviderSecretNonAliasingTagDigest,
ProviderCallInvocationMarkerDigest, KeyDestroyedReceiptDigest}` variant above,
including its
tag. One terminal destroyed generation also has this independently reusable
current-tip evidence:

    DestroyedTerminalKeyEvidenceV1 {
      Body = DestroyedTerminalKeyEvidenceBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        CaGeneration,
        CaInstanceId,
        LastCaPublicIdentityDigest,
        CertificateSpkiSha256,
        DestroyedRecordProjectionV1,
        DestroyedRecordDigest,
        KeyDestroyIntentBodyV1,
        KeyDestroyIntentDigest,
        KeyDestroyOperationId,
        ProviderCallInvocationMarkerV1,
        ProviderCallInvocationMarkerDigest,
        KeyDestroyedReceiptV1,
        KeyDestroyedReceiptDigest,
        DestroyedKeyStateRevision,
        DestroyedKeyJournalHeadDigest,
        CurrentKeyAuthorityEpoch,
        CurrentKeyStateRevision,
        CurrentKeyJournalHeadDigest,
        SuccessorRecordLinkCount,
        OrderedSuccessorRecordLinkVector = [KeyLedgerRecordLinkV1]
      },
      DestroyedTerminalKeyEvidenceDigest
    }

The destroyed digest covers only the canonical body under
`FlowProbe.TrustCa.DestroyedTerminalKeyEvidence.v1`. The complete receipt is
independently verified, and DestroyedRecordProjectionV1 equals the matching
Destroyed RecordStateProjection in the enclosing complete record vector; both
must name the same public identity, SPKI, three internal identity/non-alias tag
digests, record, and receipt. Those tag digests also equal the generation's
unique historical Ready link. The complete intent recomputes to
KeyDestroyIntentDigest; the complete invocation marker recomputes to its digest
and equals the DestroyPending record, receipt, and DestroyPostCall proof byte-
for-byte. The intent's operation/authority fields equal the receipt's
DestroyPostCall proof, and its tag fields equal the receipt's direct tag fields
and its DestroyPending ancestor. Its ExpectedPreDestroyCompleteKeyGenerationStateRoot
equals the receipt and proves that ancestor targeted the named Ready entry while
appending from the then-current global key head.
OrderedSuccessorRecordLinkVector is exactly
the suffix after DestroyedKeyStateRevision through CurrentKeyStateRevision; it
is empty iff the destroyed head is current, otherwise every adjacent link
recomputes by the key-journal-head formula above. Omitting, duplicating,
reordering, forking, or compacting away an edge invalidates the evidence. A
compactor therefore retains this canonical suffix (or byte-identical links in
the complete retained record vector), not an opaque ancestry digest.

The complete current state of one generation is:

    KeyGenerationStateEntryV1 {
      CaGeneration,
      CaInstanceId,
      ProviderAndVersion,
      GenerationRecordDigestCount,
      OrderedGenerationRecordDigestVector,
      CurrentRecordDigest,
      CurrentState =
          Creating {
            GenerationCommitmentDigest,
            ProviderCreateOperationId,
            ProviderCallInvocationMarkerDigest
          }
        | Ready {
            CaPublicIdentityDigest,
            CertificateSpkiSha256,
            NonExportableKeyIdentityDigest,
            ProviderObjectNonAliasingTagDigest,
            ProviderSecretNonAliasingTagDigest,
            ProviderKeyUniquenessEvidenceDigest,
            ProviderCallInvocationMarkerDigest,
            KeyCreatedReceiptDigest
          }
        | CreateUnapplied {
            GenerationCommitmentDigest,
            ProviderCreateOperationId,
            ProviderCallInvocationMarkerDigest,
            KeyCreateUnappliedReceiptDigest
          }
        | CreateUnappliedNeverStarted {
            GenerationCommitmentDigest,
            ProviderCreateOperationId,
            ProviderOperationReservationRecordDigest,
            CreateNeverStartedProviderAbsenceProofDigest,
            KeyCreateNeverStartedReceiptDigest
          }
        | DestroyPending {
            LastReadyRecordDigest,
            LastCaPublicIdentityDigest,
            CertificateSpkiSha256,
            KeyDestroyOperationId,
            KeyDestroyIntentDigest,
            ProviderCallInvocationMarkerDigest,
            ExpectedPreDestroyCompleteKeyGenerationStateRoot
          }
        | Destroyed {
            LastCaPublicIdentityDigest,
            CertificateSpkiSha256,
            NonExportableKeyIdentityDigest,
            ProviderObjectNonAliasingTagDigest,
            ProviderSecretNonAliasingTagDigest,
            ProviderCallInvocationMarkerDigest,
            KeyDestroyedReceiptDigest,
            DestroyedTerminalKeyEvidenceV1,
            DestroyedTerminalKeyEvidenceDigest
          }
        | Ambiguous {
            AmbiguousRecordDigest,
            ProviderCallInvocationMarkerDigest,
            AmbiguityKind = CreateOutcome | DestroyOutcome
              | KeyUniquenessCollision | KeyUniquenessEvidenceUnavailable,
            DestroyForbiddenWhenAliasingUnresolved
          }
    }

Entries are strictly sorted by CaGeneration, with exactly one entry for every
generation from one through CaGenerationHighWater. Each ordered record-digest
vector is nonempty, strictly increasing by the resolved KeyStateRevision, and
is exactly all record links for that generation; CurrentRecordDigest
is its last element. The CurrentState tag and every common projected field equal
that link's RecordStateProjection; Destroyed additionally carries the complete
terminal evidence and its digest, while Ambiguous additionally repeats the
current AmbiguousRecordDigest.
Every projected marker digest resolves through the complete record vector to
one full purpose-compatible marker: Creating/Ready/post-dispatch CreateUnapplied
and CreateAmbiguous use their unique Creating ancestor's Create marker;
DestroyPending/Destroyed and DestroyAmbiguous use their unique DestroyPending
ancestor's Destroy marker. Ready-to-DestroyPending therefore deliberately
changes from the historical create marker to a new destroy marker; a projection
cannot omit that edge, copy one purpose into the other, or synthesize a digest
without the full retained marker.
CreateUnappliedNeverStarted is the sole marker-free terminal generation entry.
It instead resolves its complete selected create reservation, signed
CreateNeverStartedProviderAbsenceProofV1, and
KeyCreateNeverStartedReceiptV1; any marker or Creating ancestor for that
generation is an integrity failure.
The union of all generation record vectors is a duplicate-free exact partition
of CompleteKeyLedgerRecordVector. Every Destroyed entry retains the exact three
non-alias tag digests from its unique historical Ready link. Those fields MUST
also equal the intervening DestroyPending intent, the Destroyed record/receipt,
and DestroyedTerminalKeyEvidenceV1; none may be regenerated, omitted, or
relabelled after destruction. Thus CompleteKeyGenerationStateRoot alone commits
the complete installation-lifetime SPKI/object/secret/identity comparison set
used by the next ProviderKeyUniquenessEvidenceV1. Every Ready/Destroyed
uniqueness/tag/receipt field resolves byte-for-byte from the authenticated
internal record and any complete receipt carried by the applicable evidence.
Raw internal identities never enter this projection.

    CompleteKeyGenerationStateRoot = SHA-256(
      "FlowProbe.TrustCa.KeyGenerationStateRoot.v1\0" ||
      uint64_be(CompleteKeyGenerationStateCount) ||
      canonical(CompleteKeyGenerationStateVector)
    )

CompleteKeyGenerationStateCount is an exact uint64 count no greater than the
current signed manifest's MaximumKeyGenerationCount, and the canonical vector
encoding is no greater than MaximumKeyGenerationStateEncodedBytes. These limits
are checked together with the key-record and provider-reservation limits before
allocating a new generation. Max-plus-one, encoding overflow, or a manifest
that cannot cover the complete retained vectors fails before consent
consumption or provider bootstrap.

The complete projection is:

    KeyLedgerStateProjectionV1 {
      Body = KeyLedgerStateProjectionBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        KeyAuthorityEpoch,
        KeyStateRevision,
        KeyJournalHeadDigest,
        ProviderOperationReservationStateV1,
        CaGenerationHighWater,
        CompleteKeyLedgerRecordCount,
        CompleteKeyLedgerRecordVector = [KeyLedgerRecordLinkV1],
        CompleteKeyLedgerRecordRoot,
        CompleteKeyGenerationStateCount,
        CompleteKeyGenerationStateVector = [KeyGenerationStateEntryV1],
        CompleteKeyGenerationStateRoot,
        Projection =
            LiveReady {
              CaGeneration,
              CaInstanceId,
              CaPublicIdentityDigest,
              CertificateSpkiSha256,
              ReadyRecordDigest,
              LiveReadyCount = 1,
              CreatingCount = 0,
              DestroyPendingCount = 0,
              AmbiguousCount = 0,
              TerminalGenerationCount
            }
          | ClosedDrifted {
              KnownCaIdentitySetDigest,
              CurrentReadyGeneration,
              CurrentReadyRecordDigest,
              LiveReadyCount = 1,
              CreatingCount = 0,
              DestroyPendingCount = 0,
              AmbiguousCount = 0,
              TerminalGenerationCount,
              GateRequiredClosed = true
            }
          | NoLiveOrAmbiguous {
              LiveReadyCount = 0,
              CreatingCount = 0,
              DestroyPendingCount = 0,
              AmbiguousCount = 0,
              CreateUnappliedCount,
              DestroyedCount,
              TerminalGenerationCount
            }
          | RotationDualReady {
              TrustOperationId,
              KnownCaIdentitySetDigest,
              ActiveCaGeneration,
              ActiveCaInstanceId,
              ActiveCaPublicIdentityDigest,
              ActiveCertificateSpkiSha256,
              ActiveReadyRecordDigest,
              CandidateCaGeneration,
              CandidateCaInstanceId,
              CandidateCaPublicIdentityDigest,
              CandidateCertificateSpkiSha256,
              CandidateReadyRecordDigest,
              CandidateGenerationCommitmentDigest,
              CandidateProviderKeyUniquenessEvidenceDigest,
              CandidateKeyCreatedReceiptDigest,
              LiveReadyCount = 2,
              CreatingCount = 0,
              DestroyPendingCount = 0,
              AmbiguousCount = 0,
              TerminalGenerationCount,
              GateRequiredClosed = true
            }
      },
      KeyLedgerStateProjectionDigest
    }

KeyLedgerStateProjectionDigest covers only the complete canonical body under
`FlowProbe.TrustCa.KeyLedgerStateProjection.v1`; the projection obtains no
standalone signing domain. The top-level revision/head equal the final record
link and the live key ledger. The complete provider-operation reservation state
is the key authority's current selected append-only vector; its revision/count/
root and every record preimage are recomputed, and every provider operation ID
in a key-record ancestor resolves to exactly one purpose-compatible reservation.
An older commitment/continuation reservation root must be an exact prefix of
this vector, while a current reservation duplicate equals the selected state
byte-for-byte. A missing, forked, compacted-away, cross-purpose, or duplicate-ID
reservation invalidates every projection variant. CompleteKeyGenerationStateCount equals
CaGenerationHighWater; every variant count is the exact projection of the
complete vector and all counts sum to it without overflow. LiveReady and
ClosedDrifted require exactly one Ready entry matching their named fields and
every other entry terminal post-dispatch CreateUnapplied,
CreateUnappliedNeverStarted, or Destroyed. NoLiveOrAmbiguous requires every
entry in one of those terminal variants and
CreateUnappliedCount is the sum of post-dispatch CreateUnapplied and no-dispatch
CreateUnappliedNeverStarted entries. `TerminalGenerationCount =
CreateUnappliedCount + DestroyedCount =
CompleteKeyGenerationStateCount`. Missing/gapped generations, a duplicate SPKI
or internal uniqueness tag, an unresolved collision, or any Creating, Ready,
DestroyPending, Ambiguous, record-chain fork, receipt mismatch, or incomplete
destroyed-terminal evidence invalidates NoLiveOrAmbiguous.
RotationDualReady is the one non-quiescent projection. It is valid only for the
exact selected RotateInstall/RotateCommit pending operation with the signing
gate closed; exactly two Ready entries match every named active/candidate field,
candidate generation is newer, every other entry is terminal CreateUnapplied or
CreateUnappliedNeverStarted or Destroyed, and the candidate commitment/evidence/receipt resolve through its
Ready record. Its KnownCaIdentitySetDigest is the direct ARCH-002 digest
containing both distinct SPKIs. The candidate evidence's pre-create root contains
the active Ready entry and excludes the candidate generation. No ordinary
Generate/Install/Remove or quiescent receipt may select this variant.

Recovery uses a separate complete projection that may faithfully encode the
very nonterminal rows that caused recovery:

    RecoveryCurrentKeyRowV1 {
      CaGeneration,
      CaInstanceId,
      CurrentState = Creating | DestroyPending | Ambiguous,
      CaKeyRecordV1,
      RecordDigest
    }

    RecoveryCurrentKeySummaryV1 {
      ReadyCount: uint64,
      CreatingCount: uint64,
      CreateUnappliedCount: uint64,
      CreateUnappliedNeverStartedCount: uint64,
      DestroyPendingCount: uint64,
      DestroyedCount: uint64,
      AmbiguousCount: uint64,
      NonterminalKeyRowCount: uint64,
      SortedUniqueNonterminalKeyRowVector = [ RecoveryCurrentKeyRowV1 ]
    }

    RecoveryKeyLedgerStateProjectionV1 {
      Body = RecoveryKeyLedgerStateProjectionBodyV1 {
        SchemaVersion = 1,
        SignatureDomain = FlowProbe.TrustCa.RecoveryKeyLedgerStateProjection.v1,
        SignedProductManifestDigest,
        InstallationId,
        KeyAuthorityEpoch,
        KeyStateRevision,
        KeyJournalHeadV1,
        KeyJournalHeadDigest,
        ProviderOperationReservationStateV1,
        CaGenerationHighWater,
        CompleteKeyLedgerRecordCount,
        CompleteKeyLedgerRecordVector = [ KeyLedgerRecordLinkV1 ],
        CompleteKeyLedgerRecordRoot,
        CompleteKeyGenerationStateCount,
        CompleteKeyGenerationStateVector = [ KeyGenerationStateEntryV1 ],
        CompleteKeyGenerationStateRoot,
        RecoveryCurrentKeySummaryV1,
        observed_at,
        must_select_by
      },
      KeyAuthorityAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = KeyAuthorityAttestation,
        Context.TypedSignatureDomain =
          FlowProbe.TrustCa.RecoveryKeyLedgerStateProjection.v1,
        Context.TypedBodyFieldTag = "attestation-body\0"
      },
      RecoveryKeyLedgerStateProjectionDigest
    }

    RecoveryKeyLedgerStateProjectionDigest = SHA-256(
      "FlowProbe.TrustCa.RecoveryKeyLedgerStateProjection.v1\0" ||
      "signed-projection\0" || canonical({
        RecoveryKeyLedgerStateProjectionBodyV1,
        KeyAuthorityAttestation
      })
    )

Neither signature wrapper nor digest is in the body. The complete generic
context selects the current Active KeyAuthorityAttestation identity; a CA key,
helper key, provider key, another installation/manifest, or another purpose is
invalid.

All eight summary counts are canonical uint64 values. The seven state counts
use checked, nonwrapping addition and their sum equals
CompleteKeyGenerationStateCount. NonterminalKeyRowCount equals the checked sum
of CreatingCount, DestroyPendingCount, and AmbiguousCount and equals the exact
uint64 vector length. Every count is no greater than the current signed
manifest's MaximumKeyGenerationCount. Rows are strictly sorted uniquely by
`(uint64_be(CaGeneration), CaInstanceId)` and each row contains the exact current
complete key record from the corresponding generation entry. The canonical
encoding of RecoveryCurrentKeySummaryV1 is no greater than the current signed
manifest's MaximumRecoveryCurrentKeySummaryEncodedBytes and the complete
projection must also fit MaximumRecoveryStateEncodedBytes. Missing/extra rows,
state/record substitution, a digest-only row, forked head/root/reservation
state, count or encoded-size overflow, a wrong manifest/key identity, or
observed_at > must_select_by is invalid. This object is non-authorizing recovery
evidence; it cannot satisfy a stable receipt, interception admission, provider
dispatch, or rotation dual-Ready gate. Its body contains no recovery journal
record, resulting state/head/envelope, receipt, signature, or projection digest,
so the authenticated key vectors precede the signed projection in the digest
DAG.

The key authority authenticates that pending-only projection without creating a
reverse edge to the later rotation plan:

    RotationReadyKeyProjectionAttestationV1 {
      Body = RotationReadyKeyProjectionAttestationBodyV1 {
        SchemaVersion = 1,
        SignatureDomain = FlowProbe.TrustCa.RotationReadyKeyProjection.v1,
        InstallationId,
        TrustOperationId,
        SelectedHelperTrustJournalHeadDigest,
        KeyLedgerStateProjectionV1 {
          Projection = RotationDualReady
        },
        KeyLedgerStateProjectionDigest,
        ActiveReadyRecordDigest,
        CandidateReadyRecordDigest,
        CandidateGenerationCommitmentDigest,
        CandidateProviderKeyUniquenessEvidenceDigest,
        CandidateKeyCreatedReceiptDigest,
        SignedProductManifestDigest,
        MaximumRotationReadyProjectionSelectionWindow,
        observed_at,
        must_select_by
      },
      KeyAuthorityAttestationSignature,
      RotationReadyKeyProjectionAttestationDigest
    }

The key-authority attestation signature covers the registered domain, field tag
`"attestation-body\0"`, and canonical body. The attestation digest covers that
domain, distinct field tag `"signed-attestation\0"`, and canonical
`{Body, KeyAuthorityAttestationSignature}`. Every duplicated field is
byte-identical to the complete inline projection and its recomputed digest. The
body contains no CandidateKeyBinding, RotationTargetBinding, phase graph,
RotateCommit consent/receipt, selection record, selector, or resulting helper
journal head. The helper proves the attestation's one timely first selection
with this separate digest-free record:

    RotationReadyProjectionSelectionRecordV1 {
      Body = RotationReadyProjectionSelectionRecordBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.RotationReadyProjectionSelection.v1,
        InstallationId,
        TrustOperationId,
        CandidateCaGeneration,
        CandidateCaInstanceId,
        CandidateCaPublicIdentityDigest,
        CandidateGenerationCommitmentDigest,
        CandidateKeyCreatedReceiptDigest,
        RotationReadyKeyProjectionAttestationDigest,
        ExpectedPredecessorLifecycleStateTag = InstallPending(RotateInstall),
        ExpectedPredecessorCandidateGenerationCommitmentDigest,
        ExpectedPredecessorTrustLifecycleStateDigest,
        ExpectedPredecessorCompletePendingOperationSnapshotDigest,
        ExpectedPredecessorTrustStateRevision,
        ExpectedPredecessorTrustJournalHeadDigest,
        ExpectedPredecessorMonotonicSafetyEnvelopeDigest,
        ExpectedPredecessorReplayIndexRevision,
        ExpectedPredecessorConsentReplayIndexRoot,
        ExpectedPredecessorReplayTimeHighWater,
        CurrentObservedTime,
        EffectiveCommittedAt,
        ResultingReplayIndexRevision,
        ResultingConsentReplayIndexBody = ConsentReplayIndexBodyV1,
        ResultingConsentReplayIndexRoot,
        ResultingReplayTimeHighWater,
        IntendedResultingTrustStateRevision,
        IntendedCandidateDescriptorVariant = ExistingIdentity.SelectedForRotation
      },
      RotationReadyProjectionSelectionRecordDigest
    }

RotationReadyProjectionSelectionRecordDigest is SHA-256 over the registered
NUL-terminated selection domain, the field tag `"selection-record\0"`, and the
canonical body. The expected state digest, complete pending-operation snapshot
digest, revision, journal head, envelope digest, replay revision/root/high-water,
pending operation, and generation
commitment MUST all equal the one selected predecessor slot. The attestation's
SelectedHelperTrustJournalHeadDigest equals
ExpectedPredecessorTrustJournalHeadDigest, and every duplicated operation,
candidate identity, commitment, receipt, and attestation field is byte-identical.
ExpectedPredecessorCompletePendingOperationSnapshotDigest equals that selected
state's complete Pending StateEvidence snapshot. The successor snapshot uses
PendingSnapshotLineage=AuthorizedOperationSuccessor with the same predecessor
snapshot digest and a complete TrustOperationJournalRecordV1 whose delta is
CandidateDescriptorRefinement and inlines this selection record/digest. The
helper record digest is distinct from the native selection-record digest. The
predecessor descriptor is GenerationCommitted with
ExpectedPredecessorCandidateGenerationCommitmentDigest; no already-refined
ExistingIdentity predecessor is accepted.

EffectiveCommittedAt is exactly
`max(CurrentObservedTime, ExpectedPredecessorReplayTimeHighWater)` after applying
the manifest clock-rollback rule and MUST be no later than the attestation's
must_select_by. The attestation's SignedProductManifestDigest equals the current
selected manifest in that same predecessor envelope/state index, and its
MaximumRotationReadyProjectionSelectionWindow equals the manifest's signed
TrustCaManifestBoundsV1 field byte-for-byte. `must_select_by` is exactly the
checked, nonwrapping sum of observed_at and that finite, nonzero window.
Overflow, zero, `UINT64_MAX`, use of a historical or staged manifest, or any
shorter or longer deadline is invalid. ResultingReplayIndexRevision is the nonwrapping predecessor plus
one. ResultingConsentReplayIndexBody and its recomputed root are the exact
MaintainReplayIndexTimeV1 successor selected by this same transition, including
the operation's updated pending replay result and all retained tombstones and
capacity reservations; ResultingReplayTimeHighWater equals both its body field
and EffectiveCommittedAt. IntendedResultingTrustStateRevision is the nonwrapping
predecessor plus one. The same atomic state-index selection appends this record,
selects the resulting replay body, constructs the successor monotonic envelope
from the attested key tip and resulting replay fields, and refines
CandidateCaDescriptor to ExistingIdentity.SelectedForRotation containing the
complete attestation and this complete record. A crash selects the complete old
GenerationCommitted predecessor or the complete new refinement, never a staged
record or a mixture.

The selection record contains no resulting lifecycle-state digest, journal head,
monotonic-envelope digest, pending snapshot digest, selector, CandidateKeyBinding,
RotationTargetBinding, or RotateCommit object. The attestation contains no
selection record. Therefore the construction order is RotationDualReady
projection -> attestation -> selection record -> pending refinement and is
acyclic. The record obtains authenticity only through that authenticated helper
journal/state selection; it has no standalone signing key or mutation authority.
After timely selection the attestation/record pair remains valid only as that
immutable pending/rotation ancestor. An unselected expired object, a record
first selected after must_select_by, or a predecessor/root/head substitution is
invalid. Only the key-authority attestation key may sign the attestation domain;
a CA-key possession proof, helper signature, selection record, or stable receipt
cannot substitute for it.

    QuiescentKeyEvidenceV1 =
        LiveReady {
          KeyLedgerStateProjectionV1,
          StableStateKeyPossessionProofV1,
          KeyPossessionProofDigest
        }
      | ClosedDrifted {
          KeyLedgerStateProjectionV1
        }
      | NoLiveOrAmbiguous {
          KeyLedgerStateProjectionV1
        }

    AbsentResidualObservationReceiptBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.AbsentResidualObservationReceipt.v1,
      InstallationId,
      LifecycleStateTag = Absent,
      AbsentResidualObservationRecordDigest,
      ResultingAbsentBusinessPostconditionDigest,
      ResultingMonotonicSafetyEnvelopeDigest,
      ResultingTrustJournalHeadDigest,
      QuiescentKeyEvidenceV1 = NoLiveOrAmbiguous,
      observed_at,
      expires_at
    }

    AbsentResidualObservationReceiptV1 {
      Body = AbsentResidualObservationReceiptBodyV1,
      AbsentResidualObservationReceiptDigest,
      HelperAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = HelperAttestation,
        Context.TypedSignatureDomain =
          FlowProbe.TrustCa.AbsentResidualObservationReceipt.v1,
        Context.TypedBodyFieldTag = "receipt-body\0"
      },
      KeyAuthorityAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = KeyAuthorityAttestation,
        Context.TypedSignatureDomain =
          FlowProbe.TrustCa.AbsentResidualObservationReceipt.v1,
        Context.TypedBodyFieldTag = "receipt-body\0"
      }
    }

The record digest covers only its digest-free body under the registered record
domain. AbsentResidualObservationReceiptDigest covers only the canonical
signature-free receipt body under its SignatureDomain. Both receipt signatures
independently cover that same body; neither the receipt digest nor either
signature is in its own or the other signer's preimage. InstallationId and the
resulting journal head MUST equal the selected resulting business/envelope
state. ResultingSelectedTargetFactStateRoot and
ResultingSelectedTargetFactCount in the named record MUST equal
the complete vector selected in the resulting Absent TrustLifecycleStateBodyV1;
the vector is reconstructed and retains immutable terminal anchors by the same
rule as ResidualIdentityObservationRecordV1. The receipt is the latest
non-authorizing stable-state receipt, while the prior remove/destroy terminal
receipt remains immutable audit evidence.

The coordinator may run this transition only while holding the global mutation
lock and while the selected state is Absent, or RecoveryRequired with no
pending snapshot whose last-quiescent snapshot is Absent. It blocks concurrent
identity-set reads, requires complete authenticated helper and key-ledger
ancestry, proves no pending or ambiguous key/trust mutation, freshly proves
every historical owned target absent and every CA key destroyed, selects the
exact current ResidualScanUniverseV1, and produces one complete
ResidualScanResultV1. Every observation must be exact, current, release-bound,
and stable across its final reread; an unknown scope, changed observation
token, incomplete scan, ambiguous identity/ownership, or stale deadline cannot
commit the transition and makes the identity-set query unavailable.

For an already-selected Absent predecessor, the complete context uses
Purpose=AuthenticatedIdentitySetRead and its exact Quiescent selected-state
anchor. For a RecoveryRequired(None) predecessor, it instead uses
Purpose=RecoveryNoneReproof and the exact RecoveryWithoutPending
RecoverySelectionId, last-quiescent Absent snapshot digest, current state
digest/head/envelope, fresh helper-generated QueryChallenge, and absence of a
pending snapshot. The complete result and this observation record repeat that
one context digest. Identity-read/admission context substitution, a caller-
chosen recovery challenge, or a context from another recovery episode is
invalid. This Absent path requires no CA-key possession proof because its
NoLiveOrAmbiguous projection proves that no live key exists.

ExpectedAbsentBusinessPostconditionDigest is the selected Absent business
digest, or the retained last-quiescent Absent digest when recovering.
ExpectedMonotonicSafetyEnvelopeDigest always names the current selected
envelope, including while RecoveryRequired; every duplicated expected
revision/tip/epoch field MUST equal that envelope and the authenticated live
ledgers. ResidualScanUniverseRevision/Digest MUST equal both that envelope and
the complete result body. The resulting envelope is an authenticated successor
of that current selected envelope. Immediately before the scan and under the
same lock, ValidateReplayIndexTimeReadOnlyV1 applies its rollback rule without
selecting a replay-index successor. EffectiveObservationTime and both
observed_at fields equal
`max(CurrentObservedTime, ReplayTimeHighWater)` from that selected predecessor;
the result, record, and receipt expires_at fields are byte-identical,
nonoverflowing, later than that effective time, and no later than the
manifest's maximum residual-observation
lifetime. Clock rollback beyond MaximumAcceptedClockSkew or expiry before
state selection makes the query unavailable. When this transaction already
must select a changed business/observation successor, its one selector commit
may also advance ReplayTimeHighWater and prune eligible tombstones; there is no
separate time-maintenance selection before the scan.

The transition performs no trust/key mutation, consumes no consent or replay
capacity, creates no TrustOperationId, and cannot select AdmissionEligible or authorize
leaf signing. If the selected state is already Absent and the recomputed
AbsentBusiness body is byte-identical, it returns the current stable receipt
without advancing state. A changed Absent body, or any exit from
RecoveryRequired, fsyncs the record as the next trust-journal entry, advances
TrustStateRevision once, constructs the resulting monotonic envelope with that
descendant journal head
and unchanged authenticated key-ledger tip, stages the updated Absent business
body, direct ARCH-002 identity-set digest, envelope, and dual-signed receipt in
one copy-on-write state-index slot, then atomically selects that slot. The
record never contains the resulting envelope or receipt digest, so no digest
preimage is recursive. A crash selects either the complete old selected state
(Absent, or RecoveryRequired(None) retaining its Absent snapshot) or the
complete new Absent snapshot and never mixes their business body, residual
roots, universe/result, revision, journal head, envelope, or receipt. An
unselected record or staged slot is not current proof; the next identity query
still performs a new complete scan.

If fresh proof shows that the prior Absent business body is no longer exact but
cannot yet prove a complete successor, the helper enters RecoveryRequired with
no pending operation, retains that last-quiescent Absent snapshot, and returns
IdentitySetUnavailable. Once completeness is restored, the same observation
transaction may select an updated Absent body rather than being forced to
reproduce the stale residual set. This path covers residual empty-to-nonempty,
nonempty-to-empty, and exact external scope/trust/certificate changes without
granting deletion, installation, or key authority.

    AttestationAnchorDispositionV1 =
        Active
      | Invalidated {
          Reason = KeyLoss | KeyMismatch | SuspectedCompromise,
          InvalidatedAt,
          AttestationAnchorInvalidationRecordV1,
          AttestationAnchorInvalidationRecordDigest
        }

    AttestationAnchorInvalidationRecordBodyV1 {
      SchemaVersion = 1,
      InstallationId,
      InstallationEpoch,
      InstallationAttestationAnchorDigest,
      ExpectedPredecessorLifecycleStateTag,
      ExpectedPredecessorTrustLifecycleStateDigest,
      ExpectedPredecessorTrustStateRevision,
      ExpectedPredecessorTrustJournalHeadDigest,
      ExpectedPredecessorMonotonicSafetyEnvelopeDigest,
      Reason = KeyLoss | KeyMismatch | SuspectedCompromise,
      BoundedDetectionEvidenceDigest,
      InvalidatedAt,
      IntendedResultingTrustStateRevision,
      IntendedResultingGateDisposition = Closed,
      IntendedResultingLifecycleState = RecoveryRequired
    }

    AttestationAnchorInvalidationRecordDigest = SHA-256(
      "FlowProbe.TrustCa.InstallationAttestationAnchor.v1\0" ||
      "invalidation-record\0" ||
      canonical(AttestationAnchorInvalidationRecordBodyV1)
    )

    AttestationAnchorInvalidationRecordV1 {
      Body = AttestationAnchorInvalidationRecordBodyV1,
      AttestationAnchorInvalidationRecordDigest
    }

This root-owned, signature-free record is non-authorizing and is selectable only
as the native evidence of the one global-lock CAS from the exact predecessor to
Invalidated + Closed + RecoveryRequired. When the helper key is unavailable,
the resulting RecoveryRequired StateEvidence uses this complete invalidation
record instead of claiming a GateClosedReceiptV1 signature. Any earlier valid
gate receipt remains historical ancestry only and is never retained beside the
record as current GateClosureEvidenceV1. The record's complete predecessor
state/revision/head/envelope and intended revision equal its paired operation
record and journal link byte-for-byte. It contains no resulting envelope, state,
receipt, or journal-head digest, so the envelope may commit its digest without a
cycle. It permits only the fail-closed RecoveryRequired selection and never
admission, refresh, recovery resume/exit, provider calls, target/key mutation,
rekey, or reinitialization.

MonotonicSafetyEnvelopeV1 is separate and explicit:

    MonotonicSafetyEnvelopeV1 {
      Body = MonotonicSafetyEnvelopeBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        InstallationEpoch,
        InstallationAttestationAnchorDigest,
        HelperAttestationKeyId,
        KeyAuthorityAttestationKeyId,
        TrustCaAttestationPolicyDigest,
        AttestationAnchorDisposition = AttestationAnchorDispositionV1,
        CaGenerationHighWater,
        TrustFenceToken,
        TrustStateRevision,
        TrustJournalHeadDigest,
        ResidualScanUniverseRevision,
        ResidualScanUniverseDigest,
        KeyAuthorityEpoch,
        KeyStateRevision,
        KeyJournalHeadDigest,
        ReplayIndexRevision,
        ConsentReplayIndexRoot,
        ReplayTimeHighWater,
        ConsentBrokerKeysetSelectionRevision,
        ConsentBrokerKeysetSelectionRoot,
        CurrentProductManifestSequence,
        CurrentSignedProductManifestDigest,
        CurrentConsentBrokerKeysetEpoch,
        CurrentConsentBrokerKeysetDigest,
        ConsentVerificationHistoryRevision,
        ConsentVerificationHistoryRoot,
        InterceptionGateEpoch,
        InterceptionGateDisposition = InterceptionGateDispositionV1
      },
      MonotonicSafetyEnvelopeDigest
    }

That digest covers only its body under the registered safety-envelope domain.
InstallationEpoch is fixed; every counter/high-water/fence is nondecreasing and
nonwrapping; trust and key tips must extend their named old ancestors; replay
revision/root/time must be a valid selected successor that preserves every live
tombstone and required capacity reservation; residual-universe revision/root
must be the same value or a valid member-addition, observer-binding, or
reservation successor under
the universe rules above; consent-broker selection revision/root must be the
same complete state or an authenticated append-only manifest-selection
successor, ProductManifestSequence and keyset epoch never decrease, and a
same-sequence manifest or same-epoch keyset has the exact same digest; and a
consent-verification-history revision/root is the same complete state or its
unique append-only successor and never decreases, forks, or loses a full result
preimage; and a
gate epoch never decreases.
The installation anchor digest, both key IDs, and policy digest are immutable
for the lifetime of InstallationId. AttestationAnchorDisposition remains Active
or transitions once to terminal Invalidated. Invalidation is selected atomically
with gate Closed and RecoveryRequired; it never returns to Active and forbids
new attestation selection, consent consumption, provider dispatch, admission,
or mutation. Retained signatures remain historical audit evidence only.
V1 defines no in-place attestation-key rotation, rekey, automatic
reinitialization, or epoch-changing recovery. Key loss, mismatch, or suspected
compromise must take the Invalidated transition. A new anchor is permitted only
after InstallationRetirementCleanupEvidenceV1 proves every old owned
target/key/provider object terminal, the machine namespace atomically selects
the immutable RetiredInstallationSealV1 with Current=None, and the old SPKI
remains conservatively excluded as required. The next CAS uses a fresh random
256-bit InstallationId and nonce absent from the complete Current/retired
namespace. The old complete anchor and signatures remain audit-only and can
never authorize the fresh InstallationId or its cleanup.
A recovery successor is Closed. A later AdmissionEligible disposition requires a strictly
new admission-authorized epoch and cannot restore a snapshot's former
AdmissionEligible disposition or gate epoch. A field in the current state-index slot, current lifecycle payload,
current replay/universe body, current scan/result, or in-flight current proof
MUST equal the selected envelope projection byte-for-byte. Immutable historical
key-record ancestors, retained snapshots, old scan/results, and old receipts
instead equal their exact then-selected envelope/universe pair and prove through
the retained authenticated journal that the pair is the unique legal ancestor
of the current selected pair.

A generation commitment is the sole staged-authority exception. It permanently
binds H0 and the purely derived, not-yet-selected U1. Verification MUST prove
the selected baseline was H0/U0, the unique complete successor record derives
U1 from U0 with only the admission-authorized reservation/scope mutations, and
the unique next journal head H1 contains that exact commitment and selects U1
atomically with the pending state. Thus `(H0,U1)` is never misrepresented as a
selected pair; the first selected pair carrying the commitment is `(H1,U1)`,
and later ancestry begins there. A commitment naming H1, a U1 without the exact
U0 successor proof, or a different H1 intent is integrity failure. Historical
objects are never rewritten merely to equal current authority. Mixing current
and historical duplicate classes, accepting a fork, or failing the applicable
equality/staged-admission/ancestry rule is integrity failure.

Every selected Drifted state and every RecoveryRequired state whose
GateClosureEvidenceV1 is SignedGateClosed carries this complete gate-closure
receipt:

    GateClosedReceiptBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.GateClosedReceipt.v1,
      InstallationId,
      GateCloseReason = DriftDetected
        | RecoveryIntegrityFailure
        | RecoveryAmbiguousMutation
        | RecoveryIncompleteObservation
        | RecoverySelectorOrAncestryFailure,
      GateClosureTransition =
          ClosedNow {
            ExpectedPredecessorInterceptionGateEpoch,
            ResultingInterceptionGateEpoch
          }
        | RetainedClosed {
            ExpectedPredecessorInterceptionGateEpoch,
            ResultingInterceptionGateEpoch
          },
      ResultingInterceptionGateDisposition = Closed,
      ResultingTrustStateRevision,
      ResultingTrustJournalHeadDigest,
      ResultingMonotonicSafetyEnvelopeDigest,
      KeyAuthorityEpoch,
      KeyStateRevision,
      KeyJournalHeadDigest,
      committed_at
    }

    GateClosedReceiptV1 {
      Body = GateClosedReceiptBodyV1,
      HelperAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = HelperAttestation,
        Context.TypedSignatureDomain = FlowProbe.TrustCa.GateClosedReceipt.v1,
        Context.TypedBodyFieldTag = "receipt-body\0"
      },
      GateClosedReceiptDigest
    }

    GateClosedReceiptDigest = SHA-256(
      "FlowProbe.TrustCa.GateClosedReceipt.v1\0" ||
      "signed-receipt\0" ||
      canonical({GateClosedReceiptBodyV1, HelperAttestation})
    )

The generic HelperAttestation context covers the registered domain, distinct field tag
`"receipt-body\0"`, and the exact canonical body using the current selected
Active anchor's HelperAttestation key. ClosedNow requires the
nonwrapping resulting gate epoch to equal the predecessor plus one;
RetainedClosed requires byte-identical epochs and a predecessor whose selected
envelope was already Closed. The resulting revision/head/envelope and key tip
equal the selected Drifted or RecoveryRequired state and its current envelope;
for a TrustOperationJournalRecord-backed transition, committed_at equals that
record's EffectiveSelectedAt. For an EnterDrifted/RefreshDrifted/
RefreshRecoveryRequired residual-observation transition it is a fresh helper
commit time no earlier than the selected query context's
EffectiveObservationTime and no later than that context's expires_at, and it is
the time repeated by any stable receipt selected in the same transition.
Drifted receipts use DriftDetected. Signed recovery receipts use the deterministic
reason-vector projection defined below, including after a refresh changes that
vector. An invalidated recovery carries only the complete matching invalidation
record and cannot construct or select this receipt. The receipt
contains no lifecycle-state digest, state/snapshot body, stable receipt,
resulting selector, or its own digest. In the SignedGateClosed branch, the lifecycle payload's
GateClosedReceiptDigest always equals the complete inline receipt digest in
StateEvidence; a digest-only receipt, reason/epoch substitution, unsigned gate
claim, stale key tip, helper-purpose signature substitution, or any current
receipt under an Invalidated envelope is invalid.

Every quiescent state selection carries exactly one complete, non-authorizing
stable receipt. The ordinary receipt shape is:

    StandardQuiescentStableReceiptV1 {
      Body = StandardQuiescentStableReceiptBodyV1 {
        SchemaVersion = 1,
        SignatureDomain = FlowProbe.TrustCa.GeneratedReceipt.v1
          | FlowProbe.TrustCa.InstalledReceipt.v1
          | FlowProbe.TrustCa.DriftedReceipt.v1
          | FlowProbe.TrustCa.AbsentReceipt.v1,
        InstallationId,
        LifecycleStateTag = Generated | InstalledAndVerified | Drifted
          | Absent,
        QuiescentBusinessPostconditionDigest,
        MonotonicSafetyEnvelopeDigest,
        TransitionJournalHeadDigest,
        QuiescentKeyEvidenceV1,
        committed_at
      },
      StableReceiptDigest,
      HelperAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = HelperAttestation,
        Context.TypedSignatureDomain = Body.SignatureDomain,
        Context.TypedBodyFieldTag = "receipt-body\0"
      },
      KeyAuthorityAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = KeyAuthorityAttestation,
        Context.TypedSignatureDomain = Body.SignatureDomain,
        Context.TypedBodyFieldTag = "receipt-body\0"
      }
    }

GeneratedReceiptV1, InstalledReceiptV1, DriftedReceiptV1, and AbsentReceiptV1
are the four tag/domain-constrained instances of that standard shape. The
domain/tag mapping is bijective: Generated uses GeneratedReceipt,
InstalledAndVerified uses InstalledReceipt, Drifted uses DriftedReceipt, and a
terminal remove/destroy Absent transition uses AbsentReceipt. A recovery that
returns to the same business state uses that state's same domain with its new
monotonic envelope and transition head; it never reuses the old receipt.
GeneratedReceiptDigest, InstalledReceiptDigest, DriftedReceiptDigest, and
AbsentReceiptDigest in lifecycle payloads are exactly their standard variant's
StableReceiptDigest without another wrapper or rehash.
StableReceiptDigest is SHA-256 over the registered NUL-terminated
SignatureDomain and the exact canonical signature-free body. Both generic
wrappers bind the same CanonicalTypedBodyDigest under their distinct roles. The
digest and both wrappers are excluded from the body/digest preimage.

The state/key-evidence mapping is bijective. Generated and
InstalledAndVerified require LiveReady with a CA-key-signed
StableStateKeyPossessionProofV1 bound to the same business, envelope, trust/key
tips, gate epoch, identity, and selection challenge and first selected by the
containing receipt's committed_at no later than must_select_by. After that
selection it remains valid only as historical receipt ancestry; it never
satisfies a later current possession or admission check. Drifted requires
ClosedDrifted, no possession proof, and a closed gate. Absent, including every
AbsentResidualObservationReceiptV1, requires NoLiveOrAmbiguous and forbids a
possession proof. An attestation signature over the complete no-key projection
is proof of ledger absence; it is not a CA-key possession signature. A variant
substitution, omitted inline projection, stale/forked key tip, or CA-key/
attestation-key signature swap is invalid.

InstallationId, lifecycle tag, business digest, envelope digest, journal head,
and committed_at MUST equal the resulting selected state/transition.
committed_at is the terminal journal entry's canonical commit time computed as
`max(CurrentObservedTime, ReplayTimeHighWater)` under the selected replay-time
successor; it is audit evidence, not an expiry or authorization window. The
terminal journal entry named by TransitionJournalHeadDigest binds the intended business digest
and every resulting envelope-body input except its own resulting head. That
entry contains no stable-receipt, snapshot, or resulting-envelope digest, so
the receipt graph is acyclic. Unknown domains, tag/domain substitutions,
single-signer receipts, and receipt bodies referring directly or indirectly to
their own digest are invalid.

QuiescentStableReceiptV1 is the closed union of
StandardQuiescentStableReceiptV1 and
AbsentResidualObservationReceiptV1. The latter is used only by the
ResidualObservationReconciled Absent transition and its
AbsentResidualObservationReceiptDigest is the union's StableReceiptDigest.
StableReceiptReferenceV1 is:

    StableReceiptReferenceV1 {
      RegisteredReceiptDomain,
      CompleteStableReceipt = StandardQuiescentStableReceiptV1
        | AbsentResidualObservationReceiptV1,
      StableReceiptDigest
    }

RegisteredReceiptDomain, the complete receipt's SignatureDomain, and its
digest MUST match byte-for-byte. The complete receipt MUST independently
verify, have the state-compatible closed variant, and bind the exact business
and envelope digests carried by the enclosing snapshot. When the enclosing
selected lifecycle state is quiescent, this complete reference is also
byte-identical to the payload's `StableReceiptReferenceV1`, and its variant,
business field, key evidence, identity fields, target-set fields, and optional
gate receipt satisfy the closed four-row state matrix above.

LastQuiescentStateSnapshotV1 is explicit:

    LastQuiescentStateSnapshotV1 {
      QuiescentBusinessPostconditionV1,
      SortedUniqueSelectedTargetFactStateVector,
      SelectedTargetFactStateRoot,
      SnapshotSafetyEnvelope = MonotonicSafetyEnvelopeV1,
      StableReceiptReferenceV1,
      LastQuiescentStateSnapshotDigest
    }

LastQuiescentStateSnapshotDigest is the registered last-quiescent-snapshot-
domain digest of exactly this signature-free canonical commitment body:

    LastQuiescentStateSnapshotCommitmentBodyV1 {
      SchemaVersion = 1,
      InstallationId,
      QuiescentBusinessPostconditionDigest,
      SelectedTargetFactStateRoot,
      SelectedTargetFactCount,
      SnapshotSafetyEnvelopeDigest = MonotonicSafetyEnvelopeDigest,
      RegisteredReceiptDomain,
      StableReceiptDigest
    }

RegisteredReceiptDomain is the exact closed receipt variant valid for that
quiescent transition; unknown or state-incompatible domains fail closed. The
selected-target vector is sorted, unique, and complete for every TargetId in
the carried quiescent business body's target-bearing roots. Each entry carries
the complete then-current selected TargetBusinessFactV1 and the complete
immutable terminal fact/TerminalTargetObservationV1 anchor, when one exists,
under the rules above; its count and root MUST equal the commitment. The
current fact may be a later Drifted or residual-reconciled descendant, but the
terminal anchor is never replaced by it. The carried complete business body,
selected facts/anchors, envelope, receipt, and transition journal anchor MUST
independently verify and match every commitment field. The
commitment contains neither its own digest nor a resulting current envelope,
so it is acyclic.

The last-quiescent snapshot stores the complete then-current business facts,
the selected current fact for every target, every immutable terminal anchor,
safety envelope, and stable receipt that signs the business/envelope digests.
The snapshot commitment binds the complete fact/anchor vector root and count.
It is
retained whether OptionalPendingOperationSnapshot is None or Some. A
RecoveryRequired entered from a quiescent rescan has
OptionalPendingOperationSnapshot=None and cannot invent an operation.
Its ordinary observation-only exit reproduces the exact last-quiescent business
body. The sole exception is an Absent last-quiescent snapshot whose complete
fresh proof changes only the known preserved-external residual projection; it
uses ResidualObservationReconciled above to commit the new Absent business body
without acquiring operation, consent, key, or trust-mutation authority.

Returning to a last-quiescent or exact-base business postcondition reproduces
the same canonical business body/digest and commits an authenticated monotonic
safety-envelope successor. Allocating a failed/CreateUnapplied generation or a
cleaned-up rotation candidate therefore advances CaGenerationHighWater,
TrustFenceToken, revisions, tips, replay metadata, and gate epoch as applicable;
none is part of the old business digest and none is rolled back or reused. The
recovery commit issues a new stable receipt over the identical business digest
and successor envelope. It never restores an old AdmissionEligible gate disposition, high-water, fence,
authority epoch, replay root/time, revision, journal tip, or receipt.

A pending state never transitions directly to Drifted. Bounded external drift
that changes a planned target is retained by the existing typed operation-step
reconciliation in its step vector while the same operation compensates or
reconciles. An identity-set query that discovers such a change returns
IdentitySetUnavailable before signing, runs no RefreshPending shortcut, and may
answer only after that operation-specific reconciliation commits and a new
complete scan succeeds. Off-plan residual changes use RefreshPending and never
alter a step. If the operation cannot reach its freshly proven base state, it enters
RecoveryRequired with OptionalPendingOperationSnapshot; a new Repair or Remove
operation cannot replace the pending transaction.

Drifted transitions to RecoveryRequired, without a new plan or consent, when a
fresh fail-closed reconciliation can no longer prove its bounded identity set,
ownership, journal/key ancestry, or absence of an ambiguous mutation. That edge
does not authorize recovery-side mutation; it only preserves the last bounded
facts and closes the state under newly discovered ambiguity.

RecoveryRequired accepts no new generate, install, repair, rotate, or ordinary
remove plan. With OptionalPendingOperationSnapshot=Some, it may leave only when
the existing authenticated journal/key ancestry yields that one unique exact
pending operation. It constructs one new PendingOperationSnapshotV1 with
PendingSnapshotLineage=AuthorizedOperationSuccessor: its predecessor digest is
the exact retained complete pending snapshot, its recovery-resume journal
record expects the selected RecoveryRequired state and refers only to that
retained snapshot, and the new wrapper carries the authenticated successor of
the retained SnapshotSafetyEnvelope. The sealed operation identity, exact base,
plans/consents, steps, recovery dispositions, and immutable anchors remain
byte-identical; the current selected-target vector/root/count matches the
recovery-exit proof and top-level successor state. It then follows only the
current entry in RecoveryDispositionVectorV1 to its freshly proved
authorized phase outcome or exact base business postcondition. Exact base is
permitted when the entry is ResumeOrCompensate or ForwardOnly already selected
ExactBase; a ForwardOnly entry selected for its authorized phase outcome cannot
return to base. With
OptionalPendingOperationSnapshot=None, it may perform observation only and
return to the snapshot's exact business postcondition under the monotonic
safety-envelope rules above when fresh complete proof shows that no key/trust
side effect occurred, the authenticated ancestry is unique, and all state
invariants hold. The sole non-byte-identical exception is a retained Absent
snapshot whose complete ResidualScanUniverseV1/ResidualScanResultV1 proof
satisfies ResidualObservationReconciled; it may select only the resulting
updated Absent business postcondition. That path cannot repair, remove, adopt,
generate, mutate trust/key state, or change a target. If either proof cannot be
obtained,
automated mutation remains disabled and bounded manual remediation is reported;
a new consent cannot override an integrity or ownership ambiguity.

A failed operation may return to its exact base business postcondition only
after every new owned mutation is safely compensated, all per-target results
are durable, the key ledger agrees, the base is freshly reverified, and the
monotonic safety envelope is committed. Crossing an owned-removal boundary for
Install or Repair first selects ForwardOnly with its exact phase-plan
OwnedRemovalIssued/ExactBase commitment; crossing a candidate key-destroy
boundary uses RotatePrepare's KeyDestroyIssued/ExactBase commitment. Neither
makes the
opposite terminal reachable. No operation may skip from a pending state to a
quiescent state by trusting an exit code or cached boolean.

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
      PlanOperationRole = Observation | InitialInstall | Repair | RemoveTrust
        | RemoveAndDestroy | CandidateInstall | ActiveRetire,
      ExactStoreOrDomainScope,
      InstallerExecutor,
      PrivilegeAndInteractionRequirement,
      InstallerOwner,
      BeforeImage,
      IntendedPostcondition,
      CurrentStep,
      LatestOperationObservation = OperationTargetObservationV1 | None,
      TerminalVerification =
          None
        | SelectedTerminal {
            TargetBusinessFactV1,
            TargetBusinessFactDigest,
            TerminalTargetObservationV1,
            TerminalTargetObservationDigest,
            SelectedCurrentFactAnchor,
            ResidualQueryTargetObservationV1,
            ResidualQueryTargetObservationDigest
          },
      BackendReleaseTupleDigest,
      CompleteReadOnlyRegeneratorInputScopeSetDigestOrNone,
      BoundedDeadline
    }

InstallerExecutor is PrivilegedHelper, AuthenticatedUserTrustAgent,
AuthenticatedAdministratorTrustAgent, DerivedBy(PrimaryAuthorityTargetId), or
ObservationOnly.

PrivilegeAndInteractionRequirement is this closed union:

    None
  | AuthenticatedCurrentUserSession
  | PrivilegedHelperAuthorization
  | ForegroundAdministratorAuthentication
  | InheritedFromAuthority
  | ObservationOnly

Direct user targets require AuthenticatedCurrentUserSession; daemon-safe
machine/root targets require PrivilegedHelperAuthorization; macOS Admin requires
ForegroundAdministratorAuthentication; a DerivedBy target requires
InheritedFromAuthority; and an ObservationOnly target requires ObservationOnly.
None is valid only for a registered executor whose fixed backend needs no
additional privilege or interaction. Any executor/requirement mismatch is a
malformed target.

InstallerOwner is:

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

Operation, terminal, and query observations are deliberately separate. An
operation row uses:

    OperationTargetObservationV1 {
      Body = OperationTargetObservationBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        OperationContext { TrustOperationId, PhasePlanDigest },
        TargetId,
        CaGeneration,
        PlanOperationRole,
        CurrentStep,
        TargetBusinessFactV1,
        TargetBusinessFactDigest,
        BackendReleaseTupleDigest,
        ExactStoreOrDomainScopeDigest,
        BeforeObservationBoundaryToken,
        AfterObservationBoundaryToken,
        ObservationEvidence,
        observed_at,
        expires_at
      },
      OperationTargetObservationDigest
    }

ObservationEvidence is the closed union:

    ExactAbsent {
      Body = ExactTargetAbsenceProofBodyV1 {
        TargetId,
        ExactStoreOrDomainScopeDigest,
        ExpectedOwnedPlatformItemIdentityDigestOrNone,
        EnumeratedOwnedLocatorMatchCount = 0,
        SortedUniqueCollisionObservationVector = [
          {
            CollisionKind = SameSpkiDifferentDer
              | SameIssuerSerialDifferentDer
              | SameLabelOrNickname
              | ForeignExactDer,
            PlatformItemIdentityDigest,
            CompletePlatformObservationDigest
          }
        ]
      },
      CompleteExactAbsenceProofDigest
    }
  | ExactPresent {
      PlatformItemIdentityDigest,
      CaPublicIdentityDigest,
      NormalizedTrustSemantic,
      Ownership = FlowProbeOwned {
          OwnerReceiptDigest,
          OwnedAfterImageDigest
        }
      | ExternalPreExisting {
          ExactBeforeObservationDigest
        },
      EffectiveConsumerObservationRoot
    }
  | ExactDerivedPresent {
      PlatformItemIdentityDigest,
      CaPublicIdentityDigest,
      PrimaryAuthorityTargetId,
      PrimaryAuthorityTargetBusinessFactDigest,
      PrimaryAuthorityTerminalTargetObservationDigest,
      AuthoritySourceBusinessFactRoot,
      TerminalFixedRegeneratorResultReceiptV1,
      TerminalFixedRegeneratorResultReceiptDigest,
      CanonicalNativeDerivedOutputDigest,
      EffectiveConsumerObservationRoot
    }
  | Ambiguous {
      Body = BoundedTargetAmbiguityBodyV1 {
        TargetId,
        ExactStoreOrDomainScopeDigest,
        SortedUniqueBoundedReasonVector,
        SortedUniqueEvidenceReferenceVector
      },
      CompleteBoundedObservationDigest
    }

An operation observation digest covers only its body under
`FlowProbe.TrustCa.OperationTargetObservation.v1`. It can advance a pending step
but is never a quiescent freshness proof. When one exact terminal step is ready
for first selection, the journal constructs:

    TerminalTargetStepV1 =
        InstalledOwned { Step = VerifiedOwned }
      | InstalledPreExistingExact { Step = VerifiedPreExistingExact }
      | InstalledDerivedExact { Step = VerifiedDerivedExact }
      | InstallVerifiedUnapplied {
          Step = InstallVerifiedUnapplied,
          SealedBeforeImageRequirement = PreExistingState.Absent,
          FreshExactAbsentObservationDigest,
          RequiredResult = ExactBaseNoMutation
        }
      | RemovalVerifiedAbsent { Step = VerifiedAbsent }
      | RemovalExternallyRemoved {
          Step = ExternallyRemoved,
          PriorFlowProbeOwnerReceiptDigest,
          PriorOwnedAfterImageDigest,
          CurrentAbsentObservationDigest,
          CompleteOwnedCopyAbsenceProofDigest,
          RemovalPlanDigest
        }
      | RemovalPreservedExternal {
          Step = PreservedExternal,
          ResidualDisposition = PreservedExternalLive
            | ConservativeExternalTrustPotential
        }
      | CompensationVerified {
          Step = CompensatedObserved,
          ExactBaseTargetBusinessFactDigest
        }

The terminal-step union is bijective with the selected plan role: install and
repair success accepts only the three Installed variants. InitialInstall and
CandidateInstall additionally accept InstallVerifiedUnapplied only as the typed
recovery result of MutationAmbiguous when the immutable before image was exact
Absent and one fresh complete exact-scope observation proves the target is still
ExactAbsent with no owner, derived output, or side effect. Its complete fact,
ExactAbsent observation, stable boundary tokens, plan/target identity, and
FreshExactAbsentObservationDigest are byte-identical to the enclosing
RecoveryResume resolution and its complete ResidualQueryTargetObservationV1;
it cannot satisfy an
installed outcome or signer-switch predicate. Remove/retire accepts only the
three Removal variants; compensation accepts only CompensationVerified. A
NotAttempted, intent, issued, ambiguous, merely applied, ObservedOnly, Drifted,
or Failed PerTargetStep is never terminal evidence.

    TerminalTargetObservationV1 {
      Body = TerminalTargetObservationBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        PlanAnchor = {
          TrustOperationId,
          PhaseRole,
          ImmutableTrustTargetPlanRecordDigest,
          ExactOrderedTargetSetDigest
        },
        TargetId,
        TargetBusinessFactV1,
        TargetBusinessFactDigest,
        TerminalTargetStepV1,
        BackendReleaseTupleDigest,
        ExactStoreOrDomainScopeDigest,
        BeforeObservationBoundaryToken,
        AfterObservationBoundaryToken,
        ObservationEvidence,
        observed_at,
        must_select_by
      },
      TerminalTargetObservationDigest
    }

TerminalTargetObservationDigest covers only the canonical body under
`FlowProbe.TrustCa.TerminalTargetObservation.v1`. The complete fact and every
duplicated semantic field MUST be byte-identical to ObservationEvidence and the
immutable plan. `must_select_by` is mechanically checked by the
TerminalEvidenceFirstSelection TrustOperationJournalRecordV1 that first selects
this complete observation into the terminal row, or by the one RecoveryResume
record that selects InstallVerifiedUnapplied from MutationAmbiguous. That record's predecessor
snapshot contains the corresponding nonterminal target step, its delta contains
the byte-identical TerminalTargetStepV1/object/digest/fact, and its
EffectiveSelectedAt MUST be no later than must_select_by. The successor snapshot
uses that record as its AuthorizedOperationSuccessor lineage. No other record
may first introduce a terminal anchor. Once selected it is an immutable historical
anchor: later wall-clock passage does not corrupt the selected state, but the
terminal object never satisfies a later freshness requirement. It contains no
quiescent business/state/envelope, stable receipt, query context, scan/result,
or response digest. The quiescent business root hashes only its context-free
TargetBusinessFactV1, so the fact and business digest are computed first and
the terminal observation is then selected beside them without a hash cycle.

A terminal derived result uses the closed object:

    TerminalFixedRegeneratorResultReceiptV1 {
      Body = TerminalFixedRegeneratorResultReceiptBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        TrustOperationId,
        PhasePlanDigest,
        DerivedTargetId,
        DerivedTargetBusinessFactDigest,
        PrimaryAuthorityTargetId,
        PrimaryAuthorityTargetBusinessFactDigest,
        PrimaryAuthorityTerminalTargetObservationDigest,
        TerminalDerivedAuthoritySourceSetV1,
        TerminalDerivedAuthoritySourceSetDigest,
        AuthoritySourceBusinessFactRoot,
        BackendReleaseTupleDigest,
        FixedRegeneratorIdentity,
        BeforeOutputBoundaryToken,
        AfterOutputBoundaryToken,
        CanonicalNativeDerivedOutputDigest,
        NormalizedTerminalResult = ExactSuccess,
        observed_at,
        must_select_by
      },
      TerminalFixedRegeneratorResultReceiptDigest
    }

Its digest uses `FlowProbe.TrustCa.TerminalFixedRegeneratorResult.v1`. The
complete source-set body/digest, its primary target/fact/terminal anchor, and its
business root MUST equal the receipt fields byte-for-byte. The derived business
fact digest MUST resolve to the exact `ExactDerivedPresent` fact whose source
root and native output equal this receipt. The receipt contains no derived
terminal observation, quiescent business postcondition, state, stable receipt,
or query object. A terminal ExactDerivedPresent evidence body carries this
complete receipt and digest inline and repeats the same primary edge, source
root, output, observed_at, and must_select_by byte-for-byte; the terminal derived observation is therefore
constructed after the complete source set, derived fact, and regenerator result.

Fresh identity-set work uses a different complete object:

    ResidualQueryTargetObservationV1 {
      Body = ResidualQueryTargetObservationBodyV1 {
        SchemaVersion = 1,
        ResidualQueryContextDigest,
        InstallationId,
        ResidualScanUniverseRevision,
        ResidualScanUniverseDigest,
        ResidualScopeId,
        ObserverBindingRevision,
        TargetId,
        HistoricalIdentityOrdinalOrNone,
        TerminalAnchor = None {
            ClosedReason = NoTerminalAttempt | TargetNotYetTerminal
          }
          | Some {
              TargetBusinessFactDigest,
              TerminalTargetObservationDigest
            },
        SelectedCurrentFactAnchor = {
          ExpectedLifecycleStateTag,
          ExpectedStateDigest,
          SelectedTargetBusinessFact = TargetBusinessFactV1,
          SelectedTargetBusinessFactDigest
        },
        CurrentBackendReleaseTupleDigest,
        ExactStoreOrDomainScopeDigest,
        BeforeObservationBoundaryToken,
        AfterObservationBoundaryToken,
        CurrentObservation =
            Definite {
              CurrentTargetBusinessFact = TargetBusinessFactV1,
              CurrentTargetBusinessFactDigest,
              Relation = MatchesSelectedFact | Changed
            }
          | Ambiguous {
              Body = BoundedTargetAmbiguityBodyV1,
              CompleteBoundedObservationDigest
            },
        QueryEvidence = DirectEvidence { ObservationEvidence }
          | DerivedEvidence {
              PrimaryAuthorityTargetId,
              CurrentDerivedAuthoritySourceSetV1,
              CurrentAuthoritySourceSetDigest,
              AuthoritySourceBusinessFactRoot,
              ResidualQueryFixedRegeneratorResultReceiptV1,
              ResidualQueryFixedRegeneratorResultReceiptDigest
            },
        observed_at,
        expires_at
      },
      ResidualQueryTargetObservationDigest
    }

ResidualQueryTargetObservationDigest covers only the body under
`FlowProbe.TrustCa.ResidualQueryTargetObservation.v1`. Every such object is
carried in exactly one enumeration evidence vector and shares that scan's exact
context, universe, current observer binding, scope boundary-token pair, and
freshness window. `Some` terminal anchor resolves to the selected immutable
`{TargetBusinessFactV1, TerminalTargetObservationV1}` pair. `None` is valid only
when the selected SelectedTargetFactStateEntryV1 has the identical None reason
and authenticated ancestry proves that no terminal row has ever been selected;
omitting or replacing a known anchor is invalid. An operation observation,
different prior terminal row, or caller-provided merge is invalid.
SelectedCurrentFactAnchor resolves to the exact complete fact for this TargetId
in the selected predecessor TrustLifecycleStateBodyV1's top-level
SortedUniqueSelectedTargetFactStateVector; a retained snapshot is ancestry, not
an alternative current row. Its state tag/digest equal the query context and it
never points to a resulting successor.
For an unchanged stable target it is byte-identical to the terminal fact; for a
previously committed Drifted, pending, RecoveryRequired, or residual Absent
projection it may be a later authenticated current fact whose journal ancestry
uniquely descends from that immutable terminal anchor. `MatchesSelectedFact`
requires the current and selected complete context-free fact bodies to be
byte-identical. Every other definite fact is `Changed`; there is no
untyped successor relation or caller-selected merge branch. A Changed observation
cannot be signed from the predecessor. The helper commits the existing
state-appropriate observation successor, discards the entire old context and
scan, and starts a new query with a new nonce; only a new
MatchesSelectedFact scan of that selected successor may be signed. Query
evidence expires and is discarded; terminal evidence does not.

Both terminal and residual-query boundary-token pairs MUST be equal under the
exact backend release's monotonic/no-ABA rule. ExactPresent at VerifiedOwned
requires FlowProbeOwned and at VerifiedPreExistingExact requires
ExternalPreExisting. ExactDerivedPresent/DerivedEvidence requires the unique
primary `DerivedBy` edge, but its complete current source set may contain
additional direct owned or external sources as defined above. Direct targets
cannot carry derived evidence, and derived targets acquire no owner/delete
authority. CompleteExactAbsenceProofDigest and
CompleteBoundedObservationDigest use the observation object's own registered
domain with, respectively, field tags `"absence-proof\0"` and
`"ambiguous-proof\0"`. Every ambiguity reference resolves to a complete
current typed object and is sorted, unique, and bounded.

CanonicalNativeDerivedOutputDigest hashes the exact release-normalized native
output bytes before query/member/provenance wrappers. The required digest order
is target facts, terminal operation evidence, selected state, query context,
fresh direct authority observations, current source set, query regenerator
result, fresh derived observation, derived-member proof, enumeration/result,
optional successor, and response. A reference in the reverse direction, a
business fact containing any observation wrapper, or a query object containing
its enclosing enumeration/result is invalid.

PreExistingState is:

    Absent
  | ExactOwnedPresent
  | ExactUnownedPresent
  | ConflictingIdentityPresent
  | ScopeOrTrustConflict
  | Ambiguous

PerTargetStepV1 is:

    NotAttempted
  | IntentDurable
  | MutationIssued
  | MutationAmbiguous
  | AppliedObserved
  | VerifiedOwned
  | VerifiedPreExistingExact
  | VerifiedDerivedExact
  | InstallVerifiedUnapplied
  | ObservedOnly
  | CompensationIntentDurable
  | CompensatedObserved
  | VerifiedAbsent
  | ExternallyRemoved {
      PriorFlowProbeOwnerReceiptDigest,
      PriorOwnedAfterImageDigest,
      CurrentAbsentObservationDigest,
      CompleteOwnedCopyAbsenceProofDigest,
      RemovalPlanDigest
    }
  | PreservedExternal {
      ResidualDisposition = PreservedExternalLive
        | ConservativeExternalTrustPotential
    }
  | Drifted
  | Failed

VerifiedDerivedExact is valid only when InstallerExecutor is
DerivedBy(PrimaryAuthorityTargetId). It binds the terminal proof for that exact
primary execution authority, the complete operation-time source business root,
the fixed regenerator/result receipt after the primary revision, the normalized
derived item/content digest and release tuple, and the required consumer
verification. The primary authority proof is VerifiedOwned or
VerifiedPreExistingExact. Fresh residual provenance may observe more direct
sources but never changes the unique plan edge; the derived row never acquires
InstallerOwner or deletion authority of its own.

ObservedOnly is valid only when InstallerExecutor is ObservationOnly,
PrivilegeAndInteractionRequirement is ObservationOnly, PlanOperationRole is
Observation,
Required is false, and the row appears in preview/capability/baseline evidence
rather than an install, removal, required-target, or admission set. It grants no
mutation, ownership, trust, or interception authority.

ExternallyRemoved is valid only during an explicit RemoveTrust,
RemoveAndDestroy, or RotateRetireOld plan when durable history proves the exact
target was FlowProbeOwned, the current exact observation is Absent, and a fresh
complete scan proves no other owned copy. It satisfies that plan's absence
postcondition without authorizing a delete call. The external drift and all
prior owner/after-image evidence remain in the terminal receipt.

The selected state's complete target disposition is represented only by its
SortedUniqueSelectedTargetFactStateVector and, while pending, the adjacent
CompletePerTargetStepVector. There is no separate legacy target-disposition vector
or generic absent/success boolean that can discard ExternallyRemoved,
PreservedExternal, ambiguity, or terminal-observation evidence.

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
        InstallerExecutor = AuthenticatedAdministratorTrustAgent,
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
      PrimaryAuthorityTargetId,
      ExactOutputIdentity,
      CompleteReadOnlyRegeneratorInputScopeSetDigest,
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

Fresh installation uses a dedicated non-operation native record; it never
pretends that an ordinary TrustOperationJournalRecordV1 already has a selected
state/head/envelope predecessor:

    InstallationBootstrapSelectionRecordV1 {
      Body = InstallationBootstrapSelectionRecordBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.InstallationBootstrap.v1,
        InstallationBootstrapAttemptId,
        ReadyForBootstrapAttemptEvent = InstallationBootstrapAttemptEventV1 {
          Body.Event = ReadyForBootstrap
        },
        ReadyForBootstrapAttemptEventDigest,
        ExpectedPredecessorInstallationNamespaceRevision,
        ExpectedPredecessorInstallationNamespaceSelectorDigest,
        InstallationId,
        InstallationEpoch,
        InstallationAttestationAnchorV1,
        InstallationAttestationAnchorDigest,
        PerInstallationSelectorLocatorV1,
        PerInstallationSelectorLocatorDigest,
        TrustCaAttestationPolicyDigest,
        InitialTrustFenceToken,
        ExpectedTrustJournalGenesisHeadV1 = TrustJournalHeadV1 {
          Body = Genesis
        },
        ExpectedTrustJournalGenesisHeadDigest,
        IntendedResultingTrustStateRevision = 1,
        InitialConsentBrokerKeysetSelectionState =
          ConsentBrokerKeysetSelectionStateV1,
        InitialConsentBrokerKeysetSelectionRevision,
        InitialConsentBrokerKeysetSelectionRoot,
        InitialSignedProductManifestDigest,
        InitialConsentReplayIndexBody = ConsentReplayIndexBodyV1,
        InitialReplayIndexRevision,
        InitialConsentReplayIndexRoot,
        InitialReplayTimeHighWater,
        InitialConsentVerificationHistoryState =
          ConsentVerificationHistoryStateV1,
        InitialConsentVerificationHistoryRevision,
        InitialConsentVerificationHistoryRoot,
        InitialResidualScanUniverse = ResidualScanUniverseV1,
        InitialResidualScanUniverseRevision,
        InitialResidualScanUniverseDigest,
        InitialKeyJournalHead = KeyJournalHeadV1 { Body = Genesis },
        InitialKeyJournalHeadDigest,
        InitialKeyLedgerStateProjection = KeyLedgerStateProjectionV1 {
          Projection = NoLiveOrAmbiguous
        },
        InitialKeyLedgerStateProjectionDigest,
        InitialAbsentBusinessPostcondition =
          QuiescentBusinessPostconditionV1 { StatePayload = AbsentBusiness },
        InitialAbsentBusinessPostconditionDigest,
        InitialKnownCaPublicIdentitySet = KnownCaPublicIdentitySetV1,
        InitialSelectedTargetFactCount = 0,
        InitialSortedUniqueSelectedTargetFactStateVector = [],
        InitialSelectedTargetFactStateRoot,
        InitialCaGenerationHighWater = 0,
        InitialInterceptionGateEpoch = 0,
        InitialInterceptionGateDisposition = Closed,
        CurrentObservedTime,
        EffectiveSelectedAt
      },
      InstallationBootstrapSelectionRecordDigest
    }

    InstallationBootstrapSelectionRecordDigest = SHA-256(
      "FlowProbe.TrustCa.InstallationBootstrap.v1\0" ||
      "bootstrap-body\0" ||
      canonical(InstallationBootstrapSelectionRecordBodyV1)
    )

The bootstrap record is intentionally signature-free. The verifier first
verifies the complete vendor-signed initial product manifest and its direct
TrustCaAttestationPolicyV1, then requires the complete anchor and digest to be
byte-identical to the protected selector slot selected by this same atomic
transaction. Its attempt ID, ReadyForBootstrap event/body/digest, namespace
predecessor, and fixed selector locator are byte-identical to the machine CAS
that appends BootstrapSelectedCurrent; both anchor provider bindings equal that
attempt's two Created results. InitialSignedProductManifestDigest equals the anchor's
InitialSignedProductManifestDigest and the nested selected manifest
digest and the selection state's current/last-record digest; the policy digest
equals the direct projection in that manifest. No key contained in the record
can authenticate or replace the selector TOFU anchor.

Every complete initial wrapper and repeated digest independently verifies under
this equality matrix:

- InstallationId, InstallationEpoch, and InitialTrustFenceToken equal every
  repeated installation/bootstrap coordinate. ExpectedTrustJournalGenesisHeadV1
  is the canonical revision-zero Genesis for them, its digest recomputes, and
  IntendedResultingTrustStateRevision is exactly one.
- InitialConsentBrokerKeysetSelectionState has revision and count one and one
  SelectionGenesis record. That record names predecessor revision zero and
  `SHA-256("FlowProbe.TrustCa.ConsentBrokerKeysetSelection.v1\0" ||
  "genesis\0" || InstallationId)`; its complete
  manifest projection and four resulting current manifest/keyset fields equal
  the state's four current fields and its sole last record byte-for-byte.
- InitialConsentReplayIndexBody is canonical empty: revision and tombstone count
  zero, no entries, and its repeated revision/root/high-water recompute exactly.
  InitialConsentVerificationHistoryState is canonical empty: revision/count
  zero, empty vector, its encoded-byte count equals `len(canonical([]))`, and its
  repeated root recomputes exactly.
- InitialResidualScanUniverse is its canonical empty/genesis form with revision
  and member count zero and an independently recomputed repeated digest.
- InitialKeyJournalHead is Genesis at key revision zero for the same
  InstallationId and pinned KeyAuthorityEpoch. Its three empty roots equal the
  independently recomputed canonical empty complete key-ledger-record,
  key-generation-state, and provider-operation-reservation roots.
  InitialKeyLedgerStateProjection is NoLiveOrAmbiguous and repeats that complete
  head/digest; generation high-water, ledger/generation/reservation revisions
  and counts are zero, all three complete vectors are empty, and all roots equal
  the corresponding key-journal Genesis roots.
  Its InstallationAttestationAnchorDigest, KeyAuthorityAttestationKeyId,
  InitialSignedProductManifestDigest, and TrustCaAttestationPolicyDigest equal the
  complete bootstrap anchor and nested selected manifest byte-for-byte.
- InitialKnownCaPublicIdentitySet and the selected-target-fact set have exact
  count zero, canonical empty vectors, and independently recomputed roots.
  InitialAbsentBusinessPostcondition and digest recompute, generation high-water
  is zero, and the interception gate is epoch zero and Closed.
- EffectiveSelectedAt is exactly `max(CurrentObservedTime,
  InitialReplayTimeHighWater)` and equals the sole manifest-selection record's
  EffectiveSelectedAt; that record's ExpectedPredecessorReplayTimeHighWater
  equals InitialReplayTimeHighWater. The complete anchor repeats the same
  InstallationId/Epoch and manifest/policy digests and its two distinct key IDs
  recompute from its two canonical public keys.

A missing, extra, noncanonical, or merely digest-equal-but-byte-different nested
field is invalid. The body contains no resulting trust-journal head, monotonic
envelope, stable receipt, snapshot, lifecycle state, selector, or any digest of
those objects, and the independently signed product manifest does not reference
bootstrap, so the signature graph is acyclic.

The helper trust journal has one closed native-record union. A native record is
never represented by an untyped digest:

    TrustJournalNativeRecordV1 =
        InstallationBootstrapSelection {
          InstallationBootstrapSelectionRecordV1,
          NativeRecordDigest = InstallationBootstrapSelectionRecordDigest
        }
      | OperationSelection {
          TrustOperationJournalRecordV1,
          NativeRecordDigest = TrustOperationJournalRecordDigest
        }
      | ResidualUniverseSelection {
          ResidualUniverseSuccessorRecordV1,
          NativeRecordDigest = ResidualUniverseSuccessorRecordDigest
        }
      | ResidualIdentitySelection {
          ResidualIdentityObservationRecordV1,
          NativeRecordDigest = ResidualIdentityObservationRecordDigest
        }
      | AbsentResidualSelection {
          AbsentResidualObservationRecordV1,
          NativeRecordDigest = AbsentResidualObservationRecordDigest
        }
      | AttestationAnchorInvalidation {
          AttestationAnchorInvalidationRecordV1,
          NativeRecordDigest = AttestationAnchorInvalidationRecordDigest
        }

One state-index selector transition appends exactly one canonical link:

    TrustJournalPredecessorAnchorV1 =
        InstallationGenesis {
          ExpectedGenesisTrustJournalHeadV1 = TrustJournalHeadV1 {
            Body = Genesis
          },
          ExpectedGenesisTrustJournalHeadDigest
        }
      | VerifiedPredecessor {
          ExpectedPredecessorTrustStateRevision,
          ExpectedPredecessorTrustJournalHeadV1,
          ExpectedPredecessorTrustJournalHeadDigest
        }
      | RecoveryQuarantinePredecessor {
          SelectedPredecessorTrustStateRevision,
          SelectedUnverifiableTrustJournalHeadDigest,
          LastAuthenticatedTrustStateRevision,
          LastAuthenticatedTrustJournalHeadV1,
          LastAuthenticatedTrustJournalHeadDigest
        }

    TrustJournalRecordLinkV1 {
      Body = TrustJournalRecordLinkBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        TrustJournalPredecessorAnchorV1,
        IntendedResultingTrustStateRevision,
        TrustJournalNativeRecordCount,
        OrderedTrustJournalNativeRecordVector = [ TrustJournalNativeRecordV1 ]
      },
      TrustJournalRecordLinkDigest
    }

    TrustJournalRecordLinkDigest = SHA-256(
      "FlowProbe.TrustCa.TrustJournalRecordLink.v1\0" ||
      canonical(TrustJournalRecordLinkBodyV1)
    )

The count is an exact canonical uint32, is never zero, and is no greater than
the signed MaximumTrustJournalNativeRecordCountPerLink.
`len(canonical(TrustJournalRecordLinkV1))` is no greater than
MaximumTrustJournalRecordLinkEncodedBytes. Ordinary checks use the predecessor's
current signed manifest; InstallationGenesis uses the complete bootstrap
record's initial selected manifest. All checks happen before link or selector
durability. An InstallationGenesis link contains exactly one
InstallationBootstrapSelection and no other native record. An ordinary selector
transition may carry one ResidualUniverseSelection first and exactly one state-
selection record second. The sole additional two-record form is
`[AttestationAnchorInvalidation, OperationSelection(EnterRecoveryRequired)]`;
it requires GateClosureSelectionV1=AttestationAnchorInvalidation and either
VerifiedPredecessor or the exact fail-closed
RecoveryQuarantinePredecessor form below, and carries the byte-identical
invalidation record/digest in the reason vector, delta, resulting payload,
StateEvidence, and envelope.
Otherwise a link carries exactly one state-selection record. The state-selection
record is exactly one OperationSelection, ResidualIdentitySelection, or
AbsentResidualSelection. An invalidation record alone, either two-record form in
reverse order, both prefix forms together, duplicate tags, two state-selection
records, a prefix after a state-selection record, or an unrecognized native
record is invalid. The selected manifest MUST admit at least two native records
and the canonical encoded size of the invalidation batch; a manifest that cannot
encode this mandatory fail-closed transition is invalid. Every complete native body and repeated digest recomputes
under its own registered domain. InstallationBootstrapSelection appears only
with InstallationGenesis and intended revision one. All ordinary native predecessor state/revision/head
fields equal the link's selected predecessor fields; all intended resulting
revisions equal the link's intended revision. The bootstrap record's expected
Genesis head/digest equals the anchor and its intended revision equals the link.
With VerifiedPredecessor, the
complete predecessor head independently verifies and is the selected current
head. RecoveryQuarantinePredecessor is valid only for exactly one
OperationSelection whose delta is EnterRecoveryRequired, or for the exact
two-record invalidation batch above. Both forms require a TrustJournalIntegrity
reason and a selected state-index slot naming the same unverifiable digest/
revision. The invalidation batch additionally requires exactly one
AttestationAnchorInvalidated reason bound to its first native record, a lost,
mismatched, or suspected-compromised current attestation anchor, and the
signature-free GateClosureSelectionV1=AttestationAnchorInvalidation branch; it
constructs no GateClosedReceiptV1 and grants no recovery, mutation, provider,
target, key, replay, or phase authority. Its complete last-authenticated head
verifies as a strict retained ancestor; neither value may be caller-selected.
No other transition may append from an unverifiable head. The intended revision is the
nonwrapping selected-predecessor revision plus one, or exactly one for
InstallationGenesis. The link contains no
resulting head, envelope, state, receipt, or snapshot digest.

The retained head body and digest are closed:

    TrustJournalHeadBodyV1 =
        Genesis {
          SchemaVersion = 1,
          InstallationId,
          InstallationEpoch,
          TrustStateRevision = 0
        }
      | Append {
          SchemaVersion = 1,
          InstallationId,
          TrustStateRevision,
          TrustJournalRecordLinkDigest
        }

    TrustJournalHeadV1 {
      Body = TrustJournalHeadBodyV1,
      TrustJournalHeadDigest
    }

    TrustJournalHeadDigest = SHA-256(
      "FlowProbe.TrustCa.TrustJournalHead.v1\0" ||
      canonical(TrustJournalHeadBodyV1)
    )

Genesis is constructed exactly once as the installation anchor but is never a
standalone lifecycle-state selector value. The installation transaction appends
the one bootstrap link and the first selected lifecycle head is Append at
revision one. Append's link MUST independently verify, its InstallationId and intended
revision equal the head body. For VerifiedPredecessor, the inline complete
predecessor head is the unique selected prior head at the immediately preceding
TrustStateRevision. For RecoveryQuarantinePredecessor, the selected immediately
preceding slot instead supplies the committed unverifiable digest/revision,
while the inline complete last-authenticated head is its required strict
ancestor; the resulting recovery head is at exactly
SelectedPredecessorTrustStateRevision+1 and does not claim that the corrupt head
body verified. Only the constrained EnterRecoveryRequired link above may bridge
that explicit quarantine gap. Thus an unexplained gap, fork, skipped verified
revision, alternate record order, digest-only verified predecessor, or
head/link/body substitution is invalid. The construction is native records ->
link body/digest -> head body/digest -> envelope/receipt/snapshot/state; no
object refers back to its resulting head. A crash before the single installation
selector leaves no installation; a crash after it exposes the complete revision-
one Absent state, replay/universe/history states, key projection, head, envelope,
receipt, and snapshot. A standalone Genesis, bootstrap record without its link,
or partially initialized state is never selected.

Storage compaction preserves that logical chain with this non-authorizing
checkpoint:

    TrustJournalCompactionCheckpointV1 {
      Body = TrustJournalCompactionCheckpointBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        CheckpointedTrustStateRevision,
        CheckpointedTrustJournalHeadV1,
        CheckpointedTrustJournalHeadDigest,
        FirstRetainedTrustStateRevision,
        RetainedPredecessorTrustJournalHeadV1,
        RetainedPredecessorTrustJournalHeadDigest,
        RetainedLinkCount,
        OrderedRetainedLinkAndHeadVector = [
          {
            TrustJournalRecordLinkV1,
            TrustJournalRecordLinkDigest,
            ResultingTrustJournalHeadV1,
            ResultingTrustJournalHeadDigest
          }
        ],
        DetachedRequiredHistoricalRecordCount,
        SortedUniqueDetachedRequiredHistoricalRecordVector = [
          {
            OriginalTrustStateRevision,
            OriginalTrustJournalRecordLinkDigest,
            TrustJournalNativeRecordV1
          }
        ]
      },
      HelperAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = HelperAttestation,
        Context.TypedSignatureDomain = FlowProbe.TrustCa.TrustJournalCompaction.v1,
        Context.TypedBodyFieldTag = "checkpoint-body\0"
      },
      TrustJournalCompactionCheckpointDigest
    }

    TrustJournalCompactionCheckpointDigest = SHA-256(
      "FlowProbe.TrustCa.TrustJournalCompaction.v1\0" ||
      "signed-checkpoint\0" ||
      canonical({
        TrustJournalCompactionCheckpointBodyV1,
        HelperAttestation
      })
    )

The complete generic HelperAttestation context covers the registered compaction
domain/tag and canonical checkpoint body. The checkpoint digest
covers canonical `{Body, HelperAttestation}` under the same
domain and distinct tag `"signed-checkpoint\0"`. Both counts are exact canonical
uint32 lengths. RetainedLinkCount is nonzero and no greater than
MaximumTrustJournalCompactionRetainedLinkCount;
DetachedRequiredHistoricalRecordCount is no greater than
MaximumTrustJournalCompactionDetachedRecordCount; and the complete checkpoint
encoding is no greater than MaximumTrustJournalCompactionCheckpointEncodedBytes.
All three signed limits are checked with nonwrapping arithmetic before
checkpoint selection. RetainedLinkCount is nonzero,
FirstRetainedTrustStateRevision equals the first resulting head's revision, and
the last resulting head equals the complete checkpointed head byte-for-byte.
The retained vector is the complete verification suffix: a
VerifiedPredecessor link is the immediate successor of the preceding inline
head, while a RecoveryQuarantinePredecessor link may advance across only its
explicit selected-unverifiable interval and its complete
LastAuthenticatedTrustJournalHeadV1 MUST equal that preceding inline head.
Every following link again verifies from the preceding resulting head under its
own closed predecessor variant. Therefore compaction cannot turn an ordinary
gap into a quarantine gap or discard either side of a quarantine anchor.
SortedUniqueDetachedRequiredHistoricalRecordVector is sorted uniquely by
`(OriginalTrustStateRevision, OriginalTrustJournalRecordLinkDigest,
NativeRecordVariantTag, NativeRecordDigest)`, and every native digest
independently recomputes. Every record preimage still
referenced by a selected state, snapshot, receipt, recovery proof, replay result,
or conformance-required audit object is present either in that suffix or in the
sorted detached vector with its original link digest. Compaction changes no
logical head, state revision, envelope, replay root/time, authority, or selector,
and a checkpoint can never stand in for a native record or ancestry needed to
authorize mutation.
Mandatory detached history includes every prior installation bootstrap,
complete InstallationAttestationAnchorV1, manifest policy, invalidation/final
cleanup evidence, and InstallationAttestationSignatureV1 context needed to
audit an old InstallationId. Its retained anchor count and canonical bytes fit
MaximumRetainedInstallationAnchorCount and
MaximumRetainedInstallationAnchorEncodedBytes; exhaustion forbids another
installation rather than pruning history or reusing an InstallationId.

That per-installation checkpoint is discoverable through one machine-wide,
root-owned namespace; a directory scan or orphan checkpoint is never authority.
The same namespace, rather than a second bootstrap ledger, retains the bounded
provider-call history needed to create its two installation attestation keys:

    InstallationAttestationProviderCreatedBindingV1 {
      SignerRole = HelperAttestation | KeyAuthorityAttestation,
      NonExportableKeyProviderProfileDigest,
      AttestationProviderCreateOperationId,
      CreateInvocationMarker =
        InstallationBootstrapProviderInvocationMarkerV1 {
          ProviderOperationKind = Create
        },
      CreateInvocationMarkerDigest,
      CanonicalProviderCreationReceipt,
      CanonicalProviderCreationReceiptDigest,
      AttestationPublicKey32,
      AttestationKeyId,
      ProviderObjectIdentityDigest,
      ProviderSecretNonAliasingTagDigest,
      NonExportableKeyIdentityDigest
    }

    InstallationBootstrapProviderInvocationMarkerV1 {
      Body = {
        SchemaVersion = 1,
        InstallationBootstrapAttemptId,
        IntendedInstallationId,
        IntendedInstallationEpoch,
        SignerRole,
        ProviderOperationKind = Create | CleanupDestroy,
        AttestationProviderOperationId,
        NonExportableKeyProviderProfileDigest,
        ExpectedPredecessorInstallationNamespaceRevision,
        ExpectedPredecessorInstallationNamespaceSelectorDigest,
        ExpectedPredecessorBootstrapAttemptEventDigest,
        EffectiveMarkerCommittedAt
      },
      InstallationBootstrapProviderInvocationMarkerDigest
    }

    InstallationBootstrapProviderResultV1 =
        Created {
          InstallationAttestationProviderCreatedBindingV1
        }
      | DefinitiveCreateUnapplied {
          CreateInvocationMarkerDigest,
          CompleteRegisteredProviderOperationQuery,
          CompleteProviderObjectSecretAndIdentityAbsenceProof
        }
      | DestroyedAndAbsent {
          InstallationAttestationProviderCreatedBindingV1,
          DestroyInvocationMarker =
            InstallationBootstrapProviderInvocationMarkerV1 {
              ProviderOperationKind = CleanupDestroy
            },
          DestroyInvocationMarkerDigest,
          CanonicalProviderDestroyReceipt,
          CanonicalProviderDestroyReceiptDigest,
          CompleteProviderObjectSecretAndIdentityAbsenceProof
        }
      | ExternallyDestroyedAndAbsentAfterInvalidation {
          InstallationAttestationProviderCreatedBindingV1,
          NativeAdministratorAuthorizationDigest,
          CompleteRegisteredRootInstallerProviderAbsenceObservation,
          CompleteProviderObjectSecretAndIdentityAbsenceProof
        }
      | ProviderOutcomeAmbiguous {
          ProviderOperationKind,
          AttestationProviderOperationId,
          InvocationMarkerDigest,
          BoundedReasonVector,
          BoundedEvidenceReferenceVector
        }

    InstallationBootstrapProviderResultDigest = SHA-256(
      "FlowProbe.TrustCa.InstallationNamespace.v1\0" ||
      "bootstrap-provider-result\0" ||
      canonical(InstallationBootstrapProviderResultV1)
    )

    InstallationBootstrapAttemptEventV1 {
      Body = {
        SchemaVersion = 1,
        InstallationBootstrapAttemptId,
        AttemptEventRevision,
        ExpectedPredecessorAttemptEventDigestOrGenesis,
        IntendedInstallationId,
        IntendedInstallationEpoch,
        AnchorCreationNonce,
        Event =
            Prepared {
              HelperProviderProfileDigest,
              HelperProviderCreateOperationId,
              HelperProviderCleanupDestroyOperationId,
              KeyAuthorityProviderProfileDigest,
              KeyAuthorityProviderCreateOperationId,
              KeyAuthorityProviderCleanupDestroyOperationId
            }
          | ProviderInvocationMarkerSelected {
              InstallationBootstrapProviderInvocationMarkerV1
            }
          | ProviderResultSelected {
              InstallationBootstrapProviderResultV1
            }
          | ReadyForBootstrap {
              HelperAttestationProviderBinding =
                InstallationAttestationProviderCreatedBindingV1 {
                  SignerRole = HelperAttestation
                },
              KeyAuthorityAttestationProviderBinding =
                InstallationAttestationProviderCreatedBindingV1 {
                  SignerRole = KeyAuthorityAttestation
                },
              InstallationAttestationAnchorV1,
              InstallationAttestationAnchorDigest
            }
          | AbandonmentSelected { BoundedReason }
          | AbandonedTerminal {
              HelperTerminalResult =
                DefinitiveCreateUnapplied | DestroyedAndAbsent,
              KeyAuthorityTerminalResult =
                DefinitiveCreateUnapplied | DestroyedAndAbsent
            }
          | BootstrapSelectedCurrent {
              InstallationAttestationAnchorDigest,
              PerInstallationSelectorLocatorDigest,
              InstallationBootstrapSelectionRecordDigest,
              InitialPerInstallationSelectedStateSlotDigest
            }
          | CurrentRetirementPrepared {
              ExpectedCurrentInstallationNamespaceRevision,
              ExpectedCurrentInstallationNamespaceSelectorDigest,
              FinalSelectedTrustLifecycleStateDigest,
              FinalMonotonicSafetyEnvelopeDigest,
              PreparedNonAttestationRetirementEvidence =
                InstallationRetirementNonAttestationProjectionV1,
              PreparedNonAttestationRetirementEvidenceDigest,
              PreparedRetainedHistoricalObjectIndexRoot,
              PreparedConservativeRetiredSpkiSetDigest
            }
          | CurrentRetirementSelected {
              InstallationRetirementCleanupEvidenceDigest,
              RetiredInstallationSealDigest
            }
      },
      InstallationBootstrapAttemptEventDigest
    }

    InstallationRetirementNonAttestationProjectionV1 =
      the complete canonical InstallationRetirementCleanupEvidenceBodyV1
      projection excluding only AttestationProviderRetirementCount,
      SortedUniqueAttestationProviderRetirementVector, and the two role-key
      terminal results that cannot exist before their destroy calls

    PreparedNonAttestationRetirementEvidenceDigest = SHA-256(
      "FlowProbe.TrustCa.InstallationNamespace.v1\0" ||
      "current-retirement-preparation\0" ||
      canonical(InstallationRetirementNonAttestationProjectionV1)
    )

The marker and event digests use the installation-namespace domain with distinct
field tags `"bootstrap-provider-marker\0"` and `"bootstrap-attempt-event\0"`.
Every adjacent marker/result/receipt digest independently recomputes from its
complete canonical preimage under the registered provider-profile schema; an
opaque receipt or digest-only result is invalid.
Prepared is selected by namespace CAS before either provider call and allocates
all four machine-lifetime-unique operation IDs. A provider call is legal only
after its exact marker event is selected; every provider-call result and
operation query must echo the operation ID and marker digest. The explicitly
non-calling invalidated external-cleanup result follows its separate rule below.
A marker's `{SignerRole, ProviderOperationKind, AttestationProviderOperationId}`
is a closed lookup into that attempt's unique Prepared event: Create equals the
role's exact `*ProviderCreateOperationId`, and CleanupDestroy equals its exact
`*ProviderCleanupDestroyOperationId`. The corresponding result, creation
binding, destroy receipt, operation query, and absence proof repeat that same ID
and marker byte-for-byte. At most one marker/result lineage exists for each
`{InstallationBootstrapAttemptId, SignerRole, ProviderOperationKind}`; a second
ID, a role/kind swap, or an ID not allocated by Prepared is invalid and can
never reach Created, ReadyForBootstrap, AbandonedTerminal, retirement, or
Current.
A crash before a marker proves no call
authority. A crash after a marker is reconciled by querying only that exact
operation. Unknown, multiple, marker-mismatched, or unenumerable outcomes select
ProviderOutcomeAmbiguous and never authorize bootstrap or speculative cleanup.

An attempt reaches ReadyForBootstrap only after both Created bindings verify and
the two roles differ in public key, provider object, provider secret,
NonExportableKeyIdentity, and provider operation. The namespace-wide uniqueness
check also compares those four identity classes against every Created event in
all retained attempts and every current or retired anchor. No attestation public
key, provider object, underlying secret, or NonExportableKeyIdentity is ever
reused, even after destruction or retirement. A collision/alias blocks selection
and automatic destroy whenever destroying the new handle could affect a retained
identity. It requires bounded external provider remediation rather than guessing.

ReadyForBootstrap and the complete revision-one per-installation graph are
staged before one namespace CAS atomically appends BootstrapSelectedCurrent,
clears the active preparation, and selects Current. Losing that CAS leaves the
attempt selected at ReadyForBootstrap. Recovery first selects
AbandonmentSelected, then selects each cleanup marker/result and reaches
AbandonedTerminal only after both exact provider object/secret/nonexportable
identities are proven absent. Retry uses a fresh attempt, InstallationId, nonce,
and four new operation IDs. Every failed or terminal attempt event remains in
the namespace vector and compaction cannot reclaim its identities or operation
IDs.

After BootstrapSelectedCurrent, the same attempt has one separate forward-only
retirement suffix. A namespace CAS may append CurrentRetirementPrepared only
after the selected lifecycle is final Absent, or the externally cleaned
Invalidated retirement case, the gate is Closed, every CA trust target and CA
key is already terminal, and the complete non-attestation cleanup evidence,
retained-history index, and conservative-SPKI vector are staged. That CAS sets
ActiveCurrentRetirement to this attempt and immediately makes every old role
signature current-authority-ineligible while retaining its historical validity.
It does not yet claim either role provider key absent.

The two preallocated CleanupDestroy operation IDs from Prepared are then used in
role order. Each provider destroy requires its own selected
ProviderInvocationMarkerSelected event and terminal DestroyedAndAbsent result;
after a crash, only the exact operation-ID/marker query may resume it. Once the
first marker is selected the suffix cannot return to Current authority or be
abandoned. Ambiguity keeps ActiveCurrentRetirement selected and blocks reinstall
and sealing. After both results are durable, a final namespace CAS appends
CurrentRetirementSelected, selects the complete cleanup evidence and retired
seal, appends its seal entry/conservative vector, sets Current=None, and clears
ActiveCurrentRetirement. Thus normal retirement never asserts role-key absence
while still depending on those keys, and destroyed old anchors are historical
verification material only.
For ExternalInstallerCleanupAfterInvalidation only, a role may instead select
ExternallyDestroyedAndAbsentAfterInvalidation after CurrentRetirementPrepared;
its administrator authorization and root-installer before/after absence proof
must equal the final cleanup evidence. It performs no provider call and cannot
be used for an Active anchor or ordinary Absent retirement.

Retirement first constructs this non-authorizing cleanup proof:

    InstallationRetirementCleanupEvidenceV1 {
      Body = InstallationRetirementCleanupEvidenceBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        InstallationEpoch,
        InstallationAttestationAnchorDigest,
        ExpectedCurrentInstallationNamespaceRevision,
        ExpectedCurrentInstallationNamespaceSelectorDigest,
        FinalSelectedTrustLifecycleState = TrustLifecycleStateV1,
        FinalSelectedTrustLifecycleStateDigest,
        FinalMonotonicSafetyEnvelope = MonotonicSafetyEnvelopeV1,
        FinalMonotonicSafetyEnvelopeDigest,
        CleanupExecutionMode =
            ConsentBoundProtocolCleanup
          | ExternalInstallerCleanupAfterInvalidation {
              NativeAdministratorAuthorizationDigest
            },
        HistoricalOwnedTargetCount,
        SortedUniqueHistoricalTargetRetirementVector = [
          {
            TargetId,
            FinalTargetBusinessFact = TargetBusinessFactV1,
            FinalTargetBusinessFactDigest,
            FreshResidualQueryTargetObservation =
              ResidualQueryTargetObservationV1,
            FreshResidualQueryTargetObservationDigest
          }
        ],
        HistoricalKeyGenerationCount,
        SortedUniqueProviderRetirementAbsenceVector = [
          {
            CaGeneration,
            CaInstanceId,
            ProviderAndVersion,
            CertificateSpkiSha256,
            NonExportableKeyIdentityDigest,
            ProviderObjectNonAliasingTagDigest,
            ProviderSecretNonAliasingTagDigest,
            KeyProviderProfileDigest,
            RegisteredProviderRetirementObserverSchemaDigest,
            CanonicalNativeProviderAbsenceEvidence,
            CanonicalNativeProviderAbsenceEvidenceDigest,
            CanonicalNativeProviderAbsenceEvidenceEncodedBytes,
            BeforeProviderObservationToken,
            AfterProviderObservationToken
          }
        ],
        AttestationProviderRetirementCount,
        SortedUniqueAttestationProviderRetirementVector = [
          {
            InstallationBootstrapAttemptId,
            SignerRole = HelperAttestation | KeyAuthorityAttestation,
            Origin = SelectedInstallation | AbandonedBootstrapAttempt,
            InstallationAttestationProviderCreatedBindingV1,
            TerminalProviderResult = DestroyedAndAbsent
              | ExternallyDestroyedAndAbsentAfterInvalidation,
            TerminalProviderResultDigest
          }
        ],
        FinalKnownCaPublicIdentitySetDigest,
        PreservedExternalIdentityCount,
        SortedUniquePreservedExternalCaSpkiSha256,
        PreservedExternalIdentitySetDigest,
        observed_at,
        expires_at
      },
      InstallationRetirementCleanupEvidenceDigest
    }

The cleanup-evidence digest is SHA-256 over the registered retirement-cleanup
domain, field tag `"cleanup-body\0"`, and canonical body. Both vectors are
strictly sorted by their semantic key, duplicate-free, and bijective with every
historical target/key generation reachable from the selected old installation.
HistoricalKeyGenerationCount is no greater than MaximumKeyGenerationCount.
HistoricalOwnedTargetCount is no greater than the checked, nonwrapping
`MaximumKeyGenerationCount * MaximumTrustPlanTargetCount` installation-lifetime
historical-target bound. Manifest validation rejects overflow. Before selecting
any new CA generation, the helper reserves that generation's complete target
quota and proves the existing historical TargetId count plus the reservation
fits this bound; every later target-bearing plan for that generation fits inside
the reserved per-generation quota. Compaction, target removal, or retirement
does not reclaim it.
The complete cleanup-evidence encoding is included in
MaximumRetainedInstallationAnchorEncodedBytes. Each target fact is ExactAbsent
or a byte-identical preserved external fact;
no row is FlowProbe-owned and present, drifted, ambiguous, omitted for an
ownership reason, or backed by an incomplete/expired observation. Each provider
row is a fresh, stable before/after-token proof from the provider profile's
registered root-installer observer that its exact object, secret, and
nonexportable identity are absent. Its native-evidence digest is SHA-256 over
the registered observer schema, field tag `"retirement-absence\0"`, and exact
canonical native evidence; its declared byte length is exact and participates
in the overall bound. A profile without complete independent
enumeration cannot retire an invalidated installation. Counts are exact uint64
lengths, times use the signed freshness/clock rules, and every duplicate state,
anchor, target, identity, key, namespace, and observation field is byte-equal.
The attestation-provider vector is sorted uniquely by
`(InstallationBootstrapAttemptId, SignerRole)`, is a bijection with the selected
installation's two Created role bindings and every Created result in an abandoned
attempt retained by this namespace epoch, and proves each exact provider object,
secret, and nonexportable identity terminally absent. An uncreated role is
accounted for only by its selected DefinitiveCreateUnapplied result in the
attempt history and does not appear as a Created retirement row. A missing,
ambiguous, aliased, live, or digest-only binding forbids retirement.
Every TerminalProviderResultDigest equals the registered
InstallationBootstrapProviderResultDigest of its complete adjacent result; both
creation/destroy receipt digests independently recompute under the bound provider
profile.
PreservedExternalIdentityCount is the exact uint32 length of the sorted unique
SPKI vector. Its digest is the direct ARCH-002 exclusion-set digest over that
vector, and it equals the preserved-external projection of the final complete
residual scan. It is never represented by a digest without this vector.

ConsentBoundProtocolCleanup requires a final selected Absent state and its
complete NoLiveOrAmbiguous key projection. ExternalInstallerCleanupAfterInvalidation
requires the final selected RecoveryRequired(AttestationAnchorInvalidated)
state, the complete invalidation record, and native administrator authorization
for cleanup already performed outside this protocol. The latter does not
revive either attestation key or authorize a journal, target, provider, or key
transition; the root installer only re-observes the terminal result. Any owned,
live, ambiguous, unenumerable, changed, or missing row leaves the old namespace
entry current and makes reinstall unavailable.

    RetiredInstallationSealV1 {
      Body = RetiredInstallationSealBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        InstallationEpoch,
        InstallationAttestationAnchorV1,
        InstallationAttestationAnchorDigest,
        AnchorCreationNonce,
        FinalAttestationAnchorDisposition = AttestationAnchorDispositionV1,
        InstallationRetirementCleanupEvidenceV1,
        InstallationRetirementCleanupEvidenceDigest,
        ConservativeRetiredSpkiCount,
        SortedUniqueConservativeRetiredCaSpkiSha256,
        ConservativeRetiredSpkiSetDigest,
        FinalTrustJournalHeadDigest,
        FinalKeyJournalHeadDigest,
        LastTrustJournalCompactionCheckpoint = None
          | Some { TrustJournalCompactionCheckpointDigest },
        RetainedHistoricalObjectCount,
        SortedUniqueRetainedHistoricalObjectIndex = [
          {
            ObjectDomain,
            ObjectFieldTag,
            CanonicalObjectDigest,
            CanonicalObjectEncodedBytes: uint64
          }
        ],
        RetainedHistoricalObjectIndexRoot,
        retired_at
      },
      RetiredInstallationSealDigest
    }

The seal digest is SHA-256 over the registered retired-seal domain, field tag
`"seal-body\0"`, and canonical body. `RetainedHistoricalObjectIndexRoot` is
SHA-256 over that domain, field tag `"historical-object-index\0"`, the exact
uint64 count, and canonical vector. The historical-object index is sorted
uniquely by `(ObjectDomain, ObjectFieldTag, CanonicalObjectDigest)`, its count is
exact, and its root commits the complete vector including each exact byte
length. Every indexed object remains content-addressable and independently
recomputable, including the old anchor/bootstrap, manifests/policy, journal and
key-ledger verification material, compaction checkpoint, invalidation, cleanup,
and signature contexts. The seal is intentionally unsigned: only its selection
by the root-owned namespace gives it historical retention authority. It grants
no current signature, cleanup, mutation, consent, provider, recovery, or
admission authority.
ConservativeRetiredSpkiCount/vector/digest are byte-identical to the cleanup
evidence's PreservedExternalIdentityCount/vector/digest. The vector remains
immutable and conservatively excluded for the lifetime of the machine namespace;
retirement or a fresh InstallationId can never turn it into an empty current-
installation set. This over-inclusion grants no trust, signing, ownership,
deletion, or admission authority.

    InstallationNamespaceCurrentV1 =
        None
      | Current {
          InstallationId,
          InstallationEpoch,
          InstallationAttestationAnchorDigest,
          AnchorCreationNonce,
          InstallationBootstrapAttemptId,
          PerInstallationSelectorLocator = PerInstallationSelectorLocatorV1,
          PerInstallationSelectorLocatorDigest,
          InstallationBootstrapSelectionRecordDigest,
          InitialPerInstallationSelectedStateSlotDigest
        }

    RetiredInstallationSealEntryV1 {
      InstallationId,
      InstallationEpoch,
      InstallationAttestationAnchorDigest,
      AnchorCreationNonce,
      RetiredInstallationSealDigest
    }

    PerInstallationSelectorLocatorV1 {
      StorageSchema = RootOwnedFlowProbeInstallationSelectorV1,
      InstallationId,
      SelectorObjectId
    }

    PerInstallationSelectorLocatorDigest = SHA-256(
      "FlowProbe.TrustCa.InstallationNamespace.v1\0" ||
      "per-installation-selector-locator\0" ||
      canonical(PerInstallationSelectorLocatorV1)
    )

    InitialPerInstallationSelectedStateSlotDigest = SHA-256(
      "FlowProbe.TrustCa.InstallationNamespace.v1\0" ||
      "initial-per-installation-state-slot\0" ||
      canonical(CompleteRevisionOneSelectedPerInstallationStateIndexSlot)
    )

    EmptyInstallationNamespaceSelectorDigest = SHA-256(
      "FlowProbe.TrustCa.InstallationNamespace.v1\0" ||
      "empty-predecessor\0"
    )

    InstallationNamespaceSelectorV1 {
      Body = InstallationNamespaceSelectorBodyV1 {
        SchemaVersion = 1,
        InstallationNamespaceRevision,
        ExpectedPredecessorInstallationNamespaceRevision,
        ExpectedPredecessorInstallationNamespaceSelectorDigest,
        CurrentInstallation = InstallationNamespaceCurrentV1,
        ActiveBootstrapPreparation = None
          | Some { InstallationBootstrapAttemptId },
        ActiveCurrentRetirement = None
          | Some {
              InstallationBootstrapAttemptId,
              CurrentRetirementPreparedEventDigest
            },
        InstallationBootstrapAttemptCount,
        InstallationBootstrapAttemptEventCount,
        OrderedInstallationBootstrapAttemptEventVector = [
          InstallationBootstrapAttemptEventV1
        ],
        InstallationBootstrapAttemptEventVectorRoot,
        RetiredInstallationSealCount,
        SortedUniqueRetiredInstallationSealEntryVector = [
          RetiredInstallationSealEntryV1
        ],
        RetiredInstallationSealVectorRoot,
        RetiredConservativeSpkiCount,
        SortedUniqueRetiredConservativeCaSpkiSha256,
        RetiredConservativeSpkiSetDigest,
        TotalRetainedOrReservedInstallationAnchorCount,
        CompleteInstallationNamespaceEncodedBytes
      },
      InstallationNamespaceSelectorDigest
    }

`RetiredInstallationSealVectorRoot` is SHA-256 over the registered
installation-namespace domain, field tag `"retired-seal-vector\0"`, the exact
uint64 count, and canonical vector. The namespace digest is SHA-256 over that
domain, field tag `"selector-body\0"`, and canonical body. The protected
copy-on-write selector reuses the anchor selector's root ownership, no-follow,
owner/mode/device/inode validation, checksummed slots, and atomic CAS. Revision
one names revision zero and EmptyInstallationNamespaceSelectorDigest; every successor is the
nonwrapping predecessor revision plus one and names that exact predecessor
digest. The retired vector is strictly sorted by `(InstallationId,
InstallationEpoch)`, complete, append-only, and byte-immutable. Current is
disjoint from it. InstallationId, `(InstallationId, InstallationEpoch)`, anchor
digest, and AnchorCreationNonce are unique across Current and every retained
entry; a retired entry is never deleted, rewritten, or reactivated.

The attempt-event vector is append-only in namespace-selection order. Attempt
count is the number of distinct attempt IDs; event count is its exact uint64
length. For each attempt, Prepared is revision one with the registered genesis
predecessor and every later event is the nonwrapping prior revision plus one and
names the immediately preceding complete event digest. Interleaved attempts,
two active bootstrap preparations, a nonterminal pre-bootstrap attempt with
ActiveBootstrapPreparation=None, or an active bootstrap preparation while
Current is Some are invalid. ActiveCurrentRetirement is Some exactly from the
CurrentRetirementPrepared CAS through the CurrentRetirementSelected CAS; it
names Current's bootstrap attempt and exact preparation event and is mutually
exclusive with ActiveBootstrapPreparation. The event vector root is
SHA-256 over the namespace domain, field tag `"bootstrap-attempt-vector\0"`, its
count, and canonical vector. Counts and complete bytes must fit
MaximumInstallationBootstrapAttemptCount,
MaximumInstallationBootstrapAttemptEventCount, and
MaximumInstallationBootstrapAttemptEncodedBytes before CAS.

PerInstallationSelectorLocatorV1 is an installation-ID-derived fixed protected
object locator, not a caller path. SelectorObjectId is the namespace-domain hash
of `"selector-object-id\0"`, InstallationId, and AnchorCreationNonce. The root
installer resolves it with no-follow owner/mode/device/inode validation. Current
pins this locator, the bootstrap attempt, anchor, bootstrap record, and initial
revision-one slot once; it does not contain the mutable current slot digest and
does not change when the per-installation lifecycle selector advances. Every
current read follows the fixed locator, validates its atomic selector, and
requires the selected state to carry the byte-identical InstallationId/anchor
and authenticated descendant of the pinned bootstrap head. A relocated,
recreated, orphan, or anchor-mismatched selector is invalid.

The retired conservative vector in the namespace is the sorted unique union of
the complete vectors in every retained seal. Its count and direct ARCH-002
digest recompute exactly; a seal digest without its content-addressed complete
vector, a missing SPKI, or a caller-assembled union is invalid. It is append-only
and may over-exclude but never grants trust or deletion authority.

Retirement first selects CurrentRetirementPrepared while retaining old Current,
then runs the two marker-bound role-key destroys above. The final retirement CAS
appends CurrentRetirementSelected, changes old Current to `None`, appends its
complete seal entry and conservative SPKI vector, and clears the active
retirement. It requires no active bootstrap preparation. Only after that state
is selected may a later CAS append Prepared
for one fresh attempt. Its InstallationId and nonce are freshly random and absent
from Current, all retained seals, and all retained attempts. After both provider
bindings reach ReadyForBootstrap, the next CAS may select its fully staged fresh
installation as Current and clear the active preparation. Its per-installation
genesis has no journal or selector predecessor in the retired installation.
Crash recovery exposes only old Current, retired-plus-None, a complete retained
preparation state, or retired-plus-one complete new Current; None/preparation
keeps the gate closed. Two Current entries, a lost retired/attempt row, direct
old-to-new replacement, filesystem reconstruction, or a staged key/anchor not
selected by this CAS is invalid.

TotalRetainedOrReservedInstallationAnchorCount is exactly
`RetiredInstallationSealCount + (Current is Some ? 1 : 0) +
(ActiveBootstrapPreparation is Some ? 1 : 0)` under checked nonwrapping
arithmetic; a selected Current attempt is not double-counted. That total and
CompleteInstallationNamespaceEncodedBytes are bounded by
MaximumRetainedInstallationAnchorCount and
MaximumRetainedInstallationAnchorEncodedBytes, including every complete seal,
current anchor, attempt event/result/receipt, and conservative-SPKI vector. A
successor manifest cannot lower any namespace/attempt bound below this live
floor. Exhaustion rejects preparation, retirement, or bootstrap before changing
the namespace, never prunes history or permits identifier/identity reuse.
Historical verification resolves namespace entry -> complete seal -> old
anchor/policy/checkpoint/object; current authority resolves only Current -> the
fixed selector locator -> byte-identical Active per-installation selector.
Cross-path substitution is invalid.

While OptionalRotationPreSwitchAbortState is Some, the complete abort-selection
native record/link, compact authorization, its predecessor pending-snapshot
preimage, initial and current compensation-vector preimages, retained Prepare
continuation/selection/reservation objects, and every terminal compensation
evidence object are required historical records. None may be dropped, reduced
to an unresolvable digest, or replaced by a checkpoint until the rotation's
quiescent terminal receipt retains the complete audit projection and no later
provider/target authorization can depend on them.

The helper owns the authenticated trust journal and a two-slot copy-on-write
trust state index selected by one checksummed atomic selector. The index binds:

- InstallationEpoch and trust-class generation high-water;
- the complete InstallationAttestationAnchorV1/digest, both attestation key IDs,
  TrustCaAttestationPolicyDigest, and terminal AttestationAnchorDispositionV1;
- current lifecycle tag and complete state digest;
- TrustFenceToken, TrustStateRevision, and TrustJournalHeadDigest;
- ResidualScanUniverseRevision and ResidualScanUniverseDigest;
- KeyAuthorityEpoch, KeyStateRevision, and KeyJournalHeadDigest;
- current and known residual CaPublicIdentityV1 values;
- the append-only PhasePlanVectorV1 of phase, TrustPlanId, complete PhasePlanV1,
  PhasePlanDigest, typed forward-only matrix, and complete
  KeyProviderSelectionDeadlineBindingVectorV1 when pending;
- the complete append-only DestroyContinuationAuthorityVectorV1 and its
  authenticated selection records when a destroy-capable phase is pending;
- the durable AbortCapacityAdmissionV1 and, when selected, the complete compact
  RotationPreSwitchAbortAuthorizationV1 plus current
  CandidateAbortCompensationVectorV1;
- required target-set digest and per-target terminal roots;
- current interception gate epoch and
  Closed/ClosedDuringRotation/AdmissionEligible disposition;
- current identity-set digest;
- ConsentReplayIndexRoot, ReplayIndexRevision, and ReplayTimeHighWater;
- the complete current ConsentBrokerKeysetSelectionStateV1 and its revision,
  root, current ProductManifestSequence/SignedProductManifestDigest, and current
  ConsentBrokerKeysetEpoch/ConsentBrokerKeysetDigest;
- the complete current ConsentVerificationHistoryStateV1 and its revision,
  count, encoded-byte count, and root;
- MonotonicSafetyEnvelopeDigest; and
- the latest non-authorizing stable-state receipt.

The checksummed selector directly selects the complete slot containing those
anchor fields; a digest-only or IPC-only key is insufficient. Selector checksum
validation never replaces the protected-storage and authenticated-peer checks
defined by InstallationAttestationAnchorV1.

Every helper operation selection is represented by this one registered closed
record. Native key-authority records and platform receipts are evidence nested
inside its delta; their digests never substitute for this helper-journal
record's digest:

    ReceiptPhaseSelectionIntentBodyV1 {
      SchemaVersion = 1,
      InstallationId,
      TrustOperationId,
      ConsentReceiptDigest,
      ConsentReceiptVerificationResultDigest,
      ConsentVerificationHistoryRecordDigest,
      PhasePlanDigest,
      ExpectedPredecessorTrustLifecycleStateDigest,
      ExpectedPredecessorTrustStateRevision,
      ExpectedPredecessorTrustJournalHeadDigest,
      ExpectedPredecessorReplayIndexRevision,
      ExpectedPredecessorConsentReplayIndexRoot,
      ExpectedPredecessorReplayTimeHighWater,
      ExpectedPredecessorConsentBrokerKeysetSelectionRevision,
      ExpectedPredecessorConsentBrokerKeysetSelectionRoot,
      ExpectedPredecessorProductManifestSequence,
      ExpectedPredecessorSignedProductManifestDigest,
      ExpectedPredecessorConsentBrokerKeysetEpoch,
      ExpectedPredecessorConsentBrokerKeysetDigest,
      ExpectedPredecessorConsentVerificationHistoryRevision,
      ExpectedPredecessorConsentVerificationHistoryRoot,
      ResultingConsentVerificationHistoryRevision,
      ResultingConsentVerificationHistoryRoot
    }

    ReceiptPhaseSelectionIntentDigest = SHA-256(
      "FlowProbe.TrustCa.TrustOperationJournalRecord.v1\0" ||
      "receipt-phase-intent\0" ||
      canonical(ReceiptPhaseSelectionIntentBodyV1)
    )

This digest-free intent is constructed after the signed receipt, complete
consent verification result, complete history record/resulting history state,
and phase plan
but before the replay successor. The new consent tombstone's
FirstConsumedIntentDigest equals ReceiptPhaseSelectionIntentDigest, never the
later TrustOperationJournalRecordDigest. The complete journal record can
therefore inline the resulting replay body without a digest cycle. The
intent's ConsentReceiptVerificationResultDigest equals the complete result in
ReceiptAndPhaseSelection and the new tombstone byte-for-byte. Its history
predecessor fields equal that result and the selected envelope/index; its
record digest and resulting revision/root equal the complete history record and
state carried by the same ReceiptAndPhaseSelection. Because the intent contains
only that already computable record digest and resulting revision/root, and the history record contains neither this intent
nor its digest, no digest edge points backward.

Recovery entry reasons and retained target state use these closed bounded
objects:

    BoundedRecoveryReasonV1 =
        TrustJournalIntegrity {
          ExpectedTrustJournalHeadDigest,
          ObservedInvalidLinkOrHeadDigest
        }
      | KeyLedgerIntegrity {
          ExpectedKeyJournalHeadDigest,
          ObservedInvalidRecordOrProjectionDigest
        }
      | AmbiguousTargetMutation {
          TargetId,
          OperationTargetObservationDigest
        }
      | IncompleteResidualObservation {
          ResidualQueryContextDigest,
          ResidualScanResultDigest,
          FailedResidualScopeId
        }
      | ProviderOutcomeAmbiguous {
          KeyProviderStepRole,
          CaGeneration,
          CaInstanceId,
          NativeKeyAuthorityEvidenceDigest
        }
      | SelectorOrAncestryFailure {
          ExpectedPredecessorTrustLifecycleStateDigest,
          ObservedConflictingSelectorOrAncestorDigest
        }
      | RecoveryPathExhausted {
          PhaseRole,
          BoundedFailureEvidenceRoot
        }
      | AttestationAnchorInvalidated {
          Reason = KeyLoss | KeyMismatch | SuspectedCompromise,
          AttestationAnchorInvalidationRecordDigest
        }

    BoundedRecoveryReasonKeyV1 = {
      ReasonVariantTag,
      OptionalTargetId,
      OptionalKeyStepKey,
      OptionalResidualScopeId,
      OptionalPhaseRole,
      PrimaryEvidenceDigest
    }

The reason key is the deterministic projection of its reason, never a
caller-selected label. ReasonVariantTag is the closed union tag above in the
listed canonical order. OptionalTargetId is Some only for
AmbiguousTargetMutation; OptionalKeyStepKey is Some only for
ProviderOutcomeAmbiguous and is exactly
`{KeyProviderStepRole, CaGeneration, CaInstanceId}`;
OptionalResidualScopeId is Some only for IncompleteResidualObservation; and
OptionalPhaseRole is Some only for RecoveryPathExhausted. Every other optional
field is None. PrimaryEvidenceDigest is respectively
ObservedInvalidLinkOrHeadDigest, ObservedInvalidRecordOrProjectionDigest,
OperationTargetObservationDigest, ResidualScanResultDigest,
NativeKeyAuthorityEvidenceDigest,
ObservedConflictingSelectorOrAncestorDigest, BoundedFailureEvidenceRoot, or
AttestationAnchorInvalidationRecordDigest in the union order above. Thus
failures in two scopes or phases cannot collapse to one key, and a key/body
mismatch is invalid.

    BoundedReasonVectorV1 {
      BoundedReasonCount,
      SortedUniqueBoundedReasonVector = [
        { BoundedRecoveryReasonKeyV1, BoundedRecoveryReasonV1 }
      ],
      BoundedReasonRoot
    }

    BoundedReasonRoot = SHA-256(
      "FlowProbe.TrustCa.TrustOperationJournalRecord.v1\0" ||
      "recovery-reasons\0" ||
      uint32_be(BoundedReasonCount) ||
      canonical(SortedUniqueBoundedReasonVector)
    )

    UnresolvedTargetVectorV1 {
      UnresolvedTargetCount,
      SortedUniqueUnresolvedTargetVector = [
        {
          TargetId,
          SelectedTargetFactStateEntryV1,
          ReasonKeyCount,
          SortedUniqueBoundedRecoveryReasonKeyVector = [
            BoundedRecoveryReasonKeyV1
          ]
        }
      ],
      UnresolvedTargetRoot
    }

    UnresolvedTargetRoot = SHA-256(
      "FlowProbe.TrustCa.TrustOperationJournalRecord.v1\0" ||
      "unresolved-targets\0" ||
      uint32_be(UnresolvedTargetCount) ||
      canonical(SortedUniqueUnresolvedTargetVector)
    )

Both outer counts and every ReasonKeyCount are exact canonical uint32 lengths.
BoundedReasonCount is no greater than MaximumRecoveryReasonCount,
UnresolvedTargetCount is no greater than MaximumRecoveryUnresolvedTargetCount,
and every ReasonKeyCount is no greater than
MaximumRecoveryReasonKeyCountPerTarget. Reasons are sorted uniquely by the
complete closed key; unresolved targets are sorted uniquely by TargetId and
every row has a nonzero ReasonKeyCount. Each row key resolves to exactly one
AmbiguousTargetMutation member of BoundedReasonVectorV1 whose TargetId equals
the row TargetId. Conversely, every AmbiguousTargetMutation reason appears
exactly once in the one row for its TargetId; UnresolvedTargetCount equals the
number of distinct such TargetIds. TrustJournalIntegrity, KeyLedgerIntegrity,
IncompleteResidualObservation, ProviderOutcomeAmbiguous,
SelectorOrAncestryFailure, RecoveryPathExhausted, and
AttestationAnchorInvalidated are operation/scope/key reasons and cannot be
attached to any target row. The invalidation reason's complete record is the
byte-identical first native preimage in the selecting journal link. At least one bounded reason is
required, while an episode with no target-scoped reason has the canonical empty
unresolved-target vector/count/root. Unknown reason tags, free-form strings,
missing/extra/cross-target/duplicate keys, a target row not equal to the
resulting selected-fact entry, or an evidence digest that does not resolve to
its complete native object is invalid.

Before selecting RecoveryRequired or a RecoveryRequired successor, the helper
constructs the complete resulting lifecycle payload, complete selected-target-
fact state, and every inline recovery vector. Their combined canonical encoding
is no greater than MaximumRecoveryStateEncodedBytes under the predecessor's
current signed manifest. Checked-size overflow or max-plus-one leaves the prior
state selected and creates no recovery journal link, gate receipt, envelope, or
selector. A selectable manifest is invalid unless these bounds also reserve the
sticky AttestationAnchorInvalidated reason, the complete invalidation-backed
RecoveryRequired state, and its mandatory two-native-record link; fail-closed
anchor invalidation cannot depend on optional residual or mutation capacity.

    GateCloseSelectionIntentV1 {
      GateCloseReason = DriftDetected
        | RecoveryIntegrityFailure
        | RecoveryAmbiguousMutation
        | RecoveryIncompleteObservation
        | RecoverySelectorOrAncestryFailure,
      ExpectedPredecessorInterceptionGateEpoch,
      ExpectedPredecessorInterceptionGateDisposition =
        InterceptionGateDispositionV1,
      ResultingInterceptionGateEpoch,
      ResultingInterceptionGateDisposition = Closed
    }

    GateClosureSelectionV1 =
        SignedAfterHead {
          GateCloseSelectionIntentV1
        }
      | AttestationAnchorInvalidation {
          GateCloseSelectionIntentV1,
          AttestationAnchorInvalidationRecordV1,
          AttestationAnchorInvalidationRecordDigest
        }

    RecoveryEntrySourceV1 =
        FromQuiescentOrDrifted {
          LastQuiescentStateSnapshotV1,
          LastQuiescentStateSnapshotDigest,
          ResultingRecoverySelectionId
        }
      | FromPending {
          LastQuiescentStateSnapshotV1,
          LastQuiescentStateSnapshotDigest,
          RetainedPendingOperationSnapshot = PendingOperationSnapshotV1,
          RetainedCompletePendingOperationSnapshotDigest
        }
      | FromSelectedRecoveryRequired {
          SelectedRecoveryRequiredState = TrustLifecycleStateV1 {
            LifecycleStatePayload = RecoveryRequired {
              GateClosureEvidenceV1 = SignedGateClosed
            }
          },
          SelectedRecoveryRequiredStateDigest
        }

ClosedNow intent advances the gate epoch by exactly one; an already-closed
predecessor uses a byte-identical epoch. SignedAfterHead encodes that as
RetainedClosed in the later GateClosedReceiptV1; AttestationAnchorInvalidation
repeats the epoch only in the resulting envelope and constructs no receipt.
ResultingRecoverySelectionId is freshly allocated
and installation-lifetime unique before constructing the record. FromPending
allocates no RecoverySelectionId and retains the pending TrustOperationId.
For EnterRecoveryRequired, GateCloseReason is a deterministic projection of the
complete reason vector: RecoveryIntegrityFailure if any TrustJournalIntegrity
or KeyLedgerIntegrity member exists, or if GateClosureSelectionV1 is
AttestationAnchorInvalidation; otherwise
RecoverySelectorOrAncestryFailure if any SelectorOrAncestryFailure or
RecoveryPathExhausted exists; otherwise RecoveryAmbiguousMutation if any
AmbiguousTargetMutation or ProviderOutcomeAmbiguous exists; otherwise
RecoveryIncompleteObservation. DriftDetected is reserved for EnterDrifted and
cannot label EnterRecoveryRequired. In SignedAfterHead, the selected
GateClosedReceiptV1 repeats that exact projected reason. In
AttestationAnchorInvalidation, exactly one sticky invalidation reason repeats
the same record digest and Reason and no receipt is constructed. A lower-
priority or caller-selected reason is invalid.

    OperationJournalAuthorityV1 =
        PendingPhaseAuthority {
          ConsentReceiptDigest,
          PhasePlanV1,
          PhasePlanDigest
        }
      | RetainedPendingAuthority {
          CompletePendingOperationSnapshotDigest,
          PhasePlanDigest
        }
      | RotationPreSwitchAbortAuthority {
          RotationPreSwitchAbortAuthorizationV1,
          RotationPreSwitchAbortAuthorizationDigest,
          ExpectedPredecessorCompletePendingOperationSnapshotDigest
        }
      | RetainedRotationPreSwitchAbortAuthority {
          RotationPreSwitchAbortAuthorizationV1,
          RotationPreSwitchAbortAuthorizationDigest,
          CurrentCompletePendingOperationSnapshotDigest
        }
      | EnterRecoveryWithoutPendingAuthority {
          LastQuiescentStateSnapshotV1,
          LastQuiescentStateSnapshotDigest,
          RecoverySelectionId
        }
      | EnterRecoveryWithPendingAuthority {
          LastQuiescentStateSnapshotV1,
          LastQuiescentStateSnapshotDigest,
          RetainedPendingOperationSnapshot = PendingOperationSnapshotV1,
          RetainedCompletePendingOperationSnapshotDigest
        }
      | RecoveryWithoutPendingAuthority {
          LastQuiescentStateSnapshotV1,
          LastQuiescentStateSnapshotDigest,
          GateClosedReceiptV1,
          GateClosedReceiptDigest
        }
      | ConsentAuthoritySelectionAuthority {
          ConsentAuthoritySelectionId
        }

    OperationJournalReplaySuccessorV1 =
        ReplayUnchanged {
          ResultingReplayIndexRevision,
          ResultingConsentReplayIndexRoot,
          ResultingReplayTimeHighWater
        }
      | ReplayIndexSelected {
          ResultingConsentReplayIndexBody = ConsentReplayIndexBodyV1,
          ResultingReplayIndexRevision,
          ResultingConsentReplayIndexRoot,
          ResultingReplayTimeHighWater
        }

    CurrentTargetReproofVectorV1 {
      CurrentTargetReproofCount,
      SortedUniqueCurrentTargetReproofVector = [
        {
          TargetId,
          SelectedTargetFactStateEntryV1,
          ResidualQueryTargetObservationV1,
          ResidualQueryTargetObservationDigest,
          RequiredRelation = MatchesSelectedFact
        }
      ],
      CurrentTargetReproofRoot
    }

    CurrentTargetReproofRoot = SHA-256(
      "FlowProbe.TrustCa.TrustOperationJournalRecord.v1\0" ||
      "current-target-reproof\0" ||
      uint32_be(CurrentTargetReproofCount) ||
      canonical(SortedUniqueCurrentTargetReproofVector)
    )

    TrustJournalResumeAncestryV1 {
      RetainedPendingPredecessorTrustJournalHeadV1,
      RetainedPendingPredecessorTrustJournalHeadDigest,
      JournalSuffixCount,
      OrderedCompleteTrustJournalResumeSuffixVector = [
        {
          TrustJournalRecordLinkV1,
          TrustJournalRecordLinkDigest,
          ResultingTrustJournalHeadV1,
          ResultingTrustJournalHeadDigest
        }
      ],
      SelectedRecoveryTrustJournalHeadV1,
      SelectedRecoveryTrustJournalHeadDigest
    }

    RecoveryWithoutPendingJournalAncestryV1 {
      StartLastAuthenticatedTrustTip = LastAuthenticatedTrustTipV1,
      RecoveryWithoutPendingJournalSuffixCount,
      OrderedCompleteRecoveryWithoutPendingJournalSuffixVector = [
        {
          TrustJournalRecordLinkV1,
          TrustJournalRecordLinkDigest,
          ResultingTrustJournalHeadV1,
          ResultingTrustJournalHeadDigest
        }
      ],
      SelectedRecoveryTrustJournalHeadV1,
      SelectedRecoveryTrustJournalHeadDigest
    }

    ResolvedRecoveryTargetStepV1 {
      TargetId,
      PreviousCompletePerTargetStep = CompletePerTargetStepV1 {
        PerTargetStep = MutationAmbiguous
      },
      PreviousCompletePerTargetStepDigest,
      ResultingCompletePerTargetStep = CompletePerTargetStepV1,
      ResultingCompletePerTargetStepDigest,
      ResidualQueryContextV1,
      ResidualQueryContextDigest,
      ResidualScanResultV1,
      ResidualScanResultDigest,
      CurrentTargetReproofVectorV1
    }

    ResolvedRecoveryAbortCompensationEntryV1 {
      TargetVectorRole = RotationAbortCompensation,
      TargetId,
      RotationPreSwitchAbortAuthorizationDigest,
      PreviousCandidateAbortCompensationVectorV1,
      PreviousCandidateAbortCompensationVectorDigest,
      PreviousCandidateAbortCompensationEntryV1 {
        Progress = RemovalAmbiguous | RegeneratorAmbiguous
      },
      ResultingCandidateAbortCompensationEntryV1,
      ResultingCandidateAbortCompensationVectorV1,
      ResultingCandidateAbortCompensationVectorDigest,
      ResidualQueryContextV1 {
        Purpose = RecoveryPendingResolution
      },
      ResidualQueryContextDigest,
      ResidualScanResultV1,
      ResidualScanResultDigest
    }

    ResolvedRecoveryKeyStepV1 {
      KeyProviderStepRole,
      PreviousCompleteKeyStep = CompleteKeyStepV1 {
        KeyStepDisposition = ProviderOutcomeAmbiguous
      },
      PreviousCompleteKeyStepDigest,
      ResultingCompleteKeyStep = CompleteKeyStepV1,
      ResultingCompleteKeyStepDigest,
      RecoveryKeyLedgerStateProjectionV1,
      RecoveryKeyLedgerStateProjectionDigest,
      NativeTerminalReceipt = KeyCreatedReceiptV1
        | KeyCreateUnappliedReceiptV1
        | KeyDestroyedReceiptV1,
      NativeTerminalReceiptDigest
    }

    RecoveryReasonResolutionV1 =
        TrustJournalIntegrityResolved {
          VerifiedSelectedTrustJournalHead = TrustJournalHeadV1,
          VerifiedSelectedTrustJournalHeadDigest
        }
      | KeyLedgerIntegrityResolved {
          RecoveryKeyLedgerStateProjectionV1,
          RecoveryKeyLedgerStateProjectionDigest
        }
      | AmbiguousTargetMutationResolved {
          Resolution = PrimaryPhase {
            ResolvedRecoveryTargetStepV1
          }
          | RotationAbortCompensation {
              ResolvedRecoveryAbortCompensationEntryV1
            }
        }
      | IncompleteResidualObservationResolved {
          FailedResidualScopeId,
          ResidualQueryContextV1,
          ResidualQueryContextDigest,
          ResidualScanResultV1,
          ResidualScanResultDigest
        }
      | ProviderOutcomeAmbiguousResolved {
          ResolvedRecoveryKeyStepV1
        }
      | SelectorOrAncestryFailureResolved {
          Resolution = SelectorOrAncestryFailureResolutionV1
        }

    SelectorOrAncestryFailureResolutionV1 =
        WithPending {
          SelectedRecoveryTrustLifecycleState = TrustLifecycleStateV1 {
            LifecycleStatePayload = RecoveryRequired {
              OptionalPendingOperationSnapshot = Some
            }
          },
          SelectedRecoveryTrustLifecycleStateDigest,
          RetainedPendingOperationSnapshot = PendingOperationSnapshotV1,
          RetainedCompletePendingOperationSnapshotDigest
        }
      | WithoutPending {
          RecoverySelectionId,
          SelectedRecoveryTrustLifecycleState = TrustLifecycleStateV1 {
            LifecycleStatePayload = RecoveryRequired {
              OptionalPendingOperationSnapshot = None
            }
          },
          SelectedRecoveryTrustLifecycleStateDigest,
          LastQuiescentStateSnapshot = LastQuiescentStateSnapshotV1,
          LastQuiescentStateSnapshotDigest,
          RecoveryWithoutPendingJournalAncestryV1
        }

    RecoveryReasonResolutionEntryV1 {
      BoundedReasonKey = BoundedRecoveryReasonKeyV1,
      PreviousBoundedReason = BoundedRecoveryReasonV1,
      Resolution = RecoveryReasonResolutionV1
    }

    RecoveryReasonResolutionVectorV1 {
      ResolutionCount,
      SortedUniqueResolutionVector = [ RecoveryReasonResolutionEntryV1 ]
    }

    RecoveryResumeEvidenceV1 {
      TrustJournalResumeAncestryV1,
      PreviousBoundedReasonVectorV1 = BoundedReasonVectorV1,
      RecoveryReasonResolutionVectorV1,
      ResultingCompletePerTargetStepVector,
      ResultingCompleteKeyStepVector,
      ResultingOptionalRotationPreSwitchAbortState = None
        | Some { RotationPreSwitchAbortStateV1 },
      ResultingRecoveryKeyLedgerStateProjection =
        RecoveryKeyLedgerStateProjectionV1,
      ResultingRecoveryKeyLedgerStateProjectionDigest,
      ResultingUnresolvedReasonCount = 0,
      ResultingUnresolvedTargetCount = 0
    }

    RecoveryResumeEvidenceDigest = SHA-256(
      "FlowProbe.TrustCa.TrustOperationJournalRecord.v1\0" ||
      "recovery-resume-evidence\0" ||
      canonical(RecoveryResumeEvidenceV1)
    )

CurrentTargetReproofCount, ResolutionCount, JournalSuffixCount, and
RecoveryWithoutPendingJournalSuffixCount are exact canonical uint32 lengths.
They are respectively no greater than MaximumRecoveryCurrentTargetReproofCount,
MaximumRecoveryResolutionCount, MaximumRecoveryJournalSuffixCount, and
MaximumRecoveryJournalSuffixCount; each canonical suffix-vector encoding is no
greater than MaximumRecoveryJournalSuffixEncodedBytes. Target rows
are sorted by TargetId; resolution rows by BoundedReasonKey. The journal suffix
is nonempty. Its complete predecessor head/digest equals the retained pending
snapshot's SnapshotSafetyEnvelope trust tip. In oldest-to-newest order, every
complete link independently verifies its inline closed
TrustJournalNativeRecordV1 vector and digest, and every resulting complete head
recomputes under the ordinary/quarantine predecessor rules above. The first
link extends that retained tip, each later link extends the preceding resulting
head, and the last head equals the complete selected RecoveryRequired
predecessor head byte-for-byte. Thus the suffix can represent operation,
residual-universe, residual-identity, Absent-residual, and other closed native
records without replacing them by operation-only digests; each native tag is
still accepted only when its state-specific transition is legal. For a pending
recovery it contains the unique EnterRecoveryRequired link and any legal
RefreshRecoveryRequired/non-authorizing successors, and cannot contain a
business/provider mutation or the recovery-resume record being constructed.
Compaction must retain these complete link/head/native preimages in this
evidence; a detached record without its compatible link/head chain is
insufficient. Every prior bounded blocking reason has
exactly one typed resolution and no new unresolved reason remains. Native
receipts/proofs independently verify under their own domains. Unknown, missing,
duplicate, digest-only, or cross-reason evidence is invalid.

`SelectorOrAncestryFailureResolutionV1` is selected by recovery shape.
`WithPending` requires a complete selected RecoveryRequired state with
`PendingOperation`, OptionalPendingOperationSnapshot=Some, and the same
TrustOperationId as the complete retained snapshot. The selected state digest
and retained complete-snapshot digest independently recompute, the snapshot is
byte-identical to the payload/StateEvidence copy, and the enclosing
`RecoveryResumeEvidenceV1.TrustJournalResumeAncestryV1` ends at that selected
state's current head. `WithoutPending` instead requires RecoveryWithoutPending,
OptionalPendingOperationSnapshot=None, and the same RecoverySelectionId,
last-quiescent snapshot, and `LastAuthenticatedTrustTipV1` as the selected state.
Its ancestry suffix is nonempty; its first complete link extends the exact start
tip under the ordinary or explicitly quarantined predecessor rule, each later
link extends the preceding resulting head, and the last complete head equals the
selected recovery envelope/head byte-for-byte. It contains the unique legal
EnterRecoveryRequired link and any later non-authorizing recovery refreshes, but
not the RecoveryNoneReproofExit record being constructed or a business/provider
mutation.

For both variants, the previous reason's
ExpectedPredecessorTrustLifecycleStateDigest and
ObservedConflictingSelectorOrAncestorDigest resolve through the complete suffix
to the unique EnterRecoveryRequired or permitted RefreshRecoveryRequired native
record that first appended that exact reason. Compaction retains every required
native/link/resulting-head preimage. A detached digest, empty/gapped/forked
suffix, different selected state, cross-episode ID, Some/None variant
substitution, or reason not present in the proved suffix is invalid. Multiple
selector/ancestry resolution entries in one vector repeat the same selected
state and applicable complete ancestry byte-for-byte.

The reason/tag mapping is exact: TrustJournalIntegrity uses only
TrustJournalIntegrityResolved; KeyLedgerIntegrity only
KeyLedgerIntegrityResolved; AmbiguousTargetMutation only
AmbiguousTargetMutationResolved for the same TargetId;
IncompleteResidualObservation only IncompleteResidualObservationResolved for
the same scope; ProviderOutcomeAmbiguous only
ProviderOutcomeAmbiguousResolved for the same provider-step semantic key; and
SelectorOrAncestryFailure only SelectorOrAncestryFailureResolved.
RecoveryPathExhausted and AttestationAnchorInvalidated have no resolution
variant and therefore cannot leave RecoveryRequired. The resolution vector is a bijection with the complete
previous reason vector: no missing, extra, duplicate, cross-key, or alternate
tag is accepted.

Every `ResolvedRecoveryTargetStepV1` context has
Purpose=RecoveryPendingResolution and its WithPending anchor equals the selected
RecoveryRequired(Some) predecessor. Its TargetId equals the reason key and the
CurrentTargetReproofVector contains exactly one row for that TargetId; every
complete observation names the same context and scan. For
IncompleteResidualObservationResolved, FailedResidualScopeId equals both the
previous reason and its key, and the new complete scan contains exactly one
stable, complete, non-ambiguous enumeration for that registered scope.

Within one `RecoveryReasonResolutionVectorV1`, all target/residual query-backed
entries use one byte-identical complete context/result pair. In
RecoveryResumeEvidenceV1 that pair has Purpose=RecoveryPendingResolution; in
RecoveryNoneReproofExit it has Purpose=RecoveryNoneReproof and equals the pair in
the complete fresh quiescent reproof evidence. The selecting journal record's
EffectiveSelectedAt is no later than the common context expiry. A mixed-purpose,
mixed-context, mixed-scan, expired, cross-state, cross-snapshot, missing-scope,
or extra target-reproof row is invalid.

For a resolved target row, the predecessor is exactly MutationAmbiguous and the
result is one phase-compatible terminal step selected by the complete fresh
query evidence. InitialInstall/CandidateInstall exact absence with the sealed
Absent before image selects only InstallVerifiedUnapplied; its observation and
fact prove exact-base no mutation, and it cannot become NotAttempted or an
installed terminal. All unrelated target rows remain byte-identical. For a resolved
key row, a create role may become only ReadyTerminal or
CreateUnappliedTerminal, and a destroy role may become only DestroyedTerminal.
CreateNeverStartedTerminal is forbidden because a ProviderOutcomeAmbiguous row
already proves a marker-bearing provider attempt. Complete native receipts,
records, projection, operation/phase/step keys, and digests are byte-identical.
The resulting step vectors apply exactly these keyed deltas and retain all
other rows. The resulting recovery projection is the selected current key tip
and must_select_by is not expired at EffectiveSelectedAt.

    RecoveryReproofKeyPossessionProofBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.KeyPossession.v1,
      Purpose = RecoveryNoneReproof,
      InstallationId,
      RecoverySelectionId,
      RecoveryRequiredStateDigest,
      LastQuiescentStateSnapshotDigest,
      ExactLastQuiescentBusinessPostconditionDigest,
      ResultingLifecycleStateTag = Generated | InstalledAndVerified,
      CaGeneration,
      CaInstanceId,
      CaPublicIdentityDigest,
      CertificateDerSha256,
      CertificateSpkiSha256,
      KeyAuthorityEpoch,
      KeyStateRevision,
      KeyJournalHeadDigest,
      KeyLedgerStateProjectionDigest,
      ResidualQueryContextDigest,
      ResidualScanResultDigest,
      QueryChallenge,
      EffectiveObservationTime,
      observed_at,
      must_select_by
    }

    RecoveryReproofKeyPossessionProofV1 {
      Body = RecoveryReproofKeyPossessionProofBodyV1,
      CaKeySignature,
      RecoveryReproofKeyPossessionProofDigest
    }

The CA key signs only that typed canonical body under the key-possession domain
and field tag `"recovery-none-reproof\0"`; the proof digest covers canonical
`{Body, CaKeySignature}` under the same domain and distinct field tag
`"recovery-none-reproof-proof\0"`. It binds only predecessor/reproof authority
and contains no resulting helper journal head, envelope, receipt, snapshot, or
state. It cannot substitute for StableStateSelection, admission, creation, or
signer-switch possession.

The proof body repeats RecoverySelectionId, ResidualQueryContextDigest,
ResidualScanResultDigest, QueryChallenge, EffectiveObservationTime, selected
state/snapshot/business identity, key-ledger projection, and resulting tag
byte-for-byte from the enclosing RecoveryNoneReproofExit evidence. The complete
context MUST have Purpose=RecoveryNoneReproof and the constrained Recovery
anchor above; the complete scan MUST name that context digest and pass every
before/after barrier. `observed_at` is not earlier than EffectiveObservationTime
and `must_select_by` is no later than the context expires_at. The journal
record's EffectiveSelectedAt MUST be no later than both must_select_by and
expires_at. A copied identity-query/admission context, different scan, different
challenge, expired context, or possession proof from another recovery episode is
invalid.

    BoundedFailureEvidenceV1 {
      FailureEvidenceCount,
      SortedUniqueFailureEvidenceVector = [ OperationEvidenceReferenceV1 ],
      BoundedFailureEvidenceRoot
    }

    BoundedFailureEvidenceRoot = SHA-256(
      "FlowProbe.TrustCa.TrustOperationJournalRecord.v1\0" ||
      "bounded-failure-evidence\0" ||
      uint32_be(FailureEvidenceCount) ||
      canonical(SortedUniqueFailureEvidenceVector)
    )

FailureEvidenceCount is the exact canonical uint32 vector length, is no greater
than MaximumRecoveryFailureEvidenceCount, and the complete canonical
BoundedFailureEvidenceV1 encoding is no greater than
MaximumRecoveryFailureEvidenceEncodedBytes. Entries use OperationEvidenceReferenceV1's
closed sort key and every reference resolves to its complete native object.

    TrustOperationJournalDeltaV1 =
        ReceiptAndPhaseSelection {
          PendingSelectionKind =
              InitialOperationSelection {
                RequiredPredecessorCompletePendingSnapshot = None
              }
            | SubsequentRotationPhaseSelection {
                RequiredPredecessorPhaseRole = RotatePrepare,
                AppendedPhaseRole = RotateCommit,
                PredecessorCompletePendingOperationSnapshotDigest
              },
          ReceiptPhaseSelectionIntentBodyV1,
          ReceiptPhaseSelectionIntentDigest,
          CaConsentReceiptV1,
          ConsentReceiptDigest,
          ConsentReceiptVerificationResultV1,
          ConsentReceiptVerificationResultDigest,
          ConsentVerificationHistoryRecordV1,
          ConsentVerificationHistoryRecordDigest,
          ResultingConsentVerificationHistoryStateV1,
          ResultingConsentVerificationHistoryRevision,
          ResultingConsentVerificationHistoryRoot,
          PhasePlanV1,
          PhasePlanDigest,
          RecoveryDispositionEntryV1,
          InitializedCompletePerTargetStepVector = CompletePerTargetStepVector,
          InitializedCompleteKeyStepVector = CompleteKeyStepVector,
          AbortCapacityAdmission = AbortCapacityAdmissionV1,
          OptionalDestroyContinuationSelection = None
            | Some {
                DestroyContinuationAuthorityV1,
                DestroyContinuationAuthorityDigest,
                DestroyContinuationSelectionRecordV1,
                DestroyContinuationSelectionRecordDigest
              }
        }
      | ConsentAuthoritySelection {
          ConsentBrokerKeysetSelectionRecordV1,
          ConsentBrokerKeysetSelectionRecordDigest,
          ResultingConsentBrokerKeysetSelectionStateV1,
          ResultingConsentBrokerKeysetSelectionRevision,
          ResultingConsentBrokerKeysetSelectionRoot,
          ResultingProductManifestSequence,
          ResultingSignedProductManifestDigest,
          ResultingConsentBrokerKeysetEpoch,
          ResultingConsentBrokerKeysetDigest
        }
      | CandidateDescriptorRefinement {
          PreviousCandidateCaDescriptor,
          ResultingCandidateCaDescriptor,
          RotationReadyProjectionSelectionRecordV1,
          RotationReadyProjectionSelectionRecordDigest
        }
      | TargetStepAdvance {
          TargetVectorRole = PrimaryPhase,
          TargetId,
          PreviousCompletePerTargetStep = CompletePerTargetStepV1,
          PreviousCompletePerTargetStepDigest,
          ResultingCompletePerTargetStep = CompletePerTargetStepV1,
          ResultingCompletePerTargetStepDigest,
          OperationTargetObservationV1,
          OperationTargetObservationDigest
        }
      | KeyStepAdvance {
          KeyProviderStepRole,
          CaGeneration,
          CaInstanceId,
          PreviousCompleteKeyStep = CompleteKeyStepV1,
          PreviousCompleteKeyStepDigest,
          ResultingCompleteKeyStep = CompleteKeyStepV1,
          ResultingCompleteKeyStepDigest,
          NativeKeyAuthorityEvidence = CaKeyRecordV1 {
              StatePayload = Creating | DestroyPending | Ambiguous
            }
            | KeyCreatedReceiptV1
            | KeyCreateUnappliedReceiptV1
            | KeyCreateNeverStartedReceiptV1
            | KeyDestroyedReceiptV1,
          NativeKeyAuthorityEvidenceDigest
        }
      | ForwardOnlySelection {
          PhaseRole,
          PreviousRecoveryDisposition = ResumeOrCompensate,
          SelectedForwardOnlySelectionCommitment =
            ForwardOnlySelectionCommitmentV1,
          ResultingRecoveryDisposition = ForwardOnly
        }
      | RotationPreSwitchAbortSelection {
          PhaseRole = RotateCommit,
          RequiredOperationJournalAuthorityVariant =
            RotationPreSwitchAbortAuthority,
          RotationPreSwitchAbortAuthorizationDigest,
          InitialCandidateAbortCompensationVector =
            CandidateAbortCompensationVectorV1 {
              Body.ExactBaseCompletion = Incomplete
            },
          InitialCandidateAbortCompensationVectorDigest,
          AbortCapacityAdmission = RotateCommitAbortAdmitted,
          PreviousRotatePrepareRecoveryDisposition = ResumeOrCompensate,
          PreviousRotateCommitRecoveryDisposition = ResumeOrCompensate,
          ResultingRotatePrepareRecoveryDisposition =
            CleanupLockedByRotationAbort {
              ConsumingPhaseRole = RotateCommit,
              RotationPreSwitchAbortAuthorizationDigest,
              RetainedCleanupContinuationAuthorityDigest,
              RetainedCleanupKeyDestroyOperationId,
              GrantsMutationOrOutcomeAuthority = false
            },
          ResultingRotateCommitRecoveryDisposition = ForwardOnly {
            SelectedForwardOnlySelectionCommitment =
              ForwardOnlySelectionCommitmentV1 {
                PhaseRole = RotateCommit,
                IrreversiblePhase = PreSignerSwitchAbortCommitted
              }
          }
        }
      | CandidateAbortCompensationAdvance {
          PhaseRole = RotateCommit,
          TargetVectorRole = RotationAbortCompensation,
          RotationPreSwitchAbortAuthorizationDigest,
          TargetId,
          PreviousCandidateAbortCompensationVectorV1,
          PreviousCandidateAbortCompensationVectorDigest,
          PreviousCandidateAbortCompensationEntryV1,
          ResultingCandidateAbortCompensationEntryV1,
          ResultingCandidateAbortCompensationVectorV1,
          ResultingCandidateAbortCompensationVectorDigest,
          NativeCompensationEvidence =
              OperationTargetObservationV1
            | TerminalTargetObservationV1
            | TerminalFixedRegeneratorResultReceiptV1
            | BoundedTargetAmbiguityBodyV1,
          NativeCompensationEvidenceDigest
        }
      | CandidateAbortExactBaseSelection {
          PhaseRole = RotateCommit,
          TargetVectorRole = RotationAbortCompensation,
          RotationPreSwitchAbortAuthorizationDigest,
          PreviousCandidateAbortCompensationVectorV1 {
            Body.ExactBaseCompletion = Incomplete
          },
          PreviousCandidateAbortCompensationVectorDigest,
          ResultingCandidateAbortCompensationVectorV1 {
            Body.ExactBaseCompletion = Complete
          },
          ResultingCandidateAbortCompensationVectorDigest,
          CandidateAbortExactBaseFactVectorV1,
          CandidateAbortExactBaseFactRoot,
          ResidualQueryContextV1,
          ResidualQueryContextDigest,
          ResidualScanResultV1,
          ResidualScanResultDigest
        }
      | RecoveryResume {
          RecoveryRequiredStateDigest,
          RetainedCompletePendingOperationSnapshotDigest,
          RecoveryResumeEvidenceV1,
          RecoveryResumeEvidenceDigest,
          ResultingCompletePerTargetStepVector,
          ResultingCompleteKeyStepVector,
          ResultingOptionalRotationPreSwitchAbortState = None
            | Some { RotationPreSwitchAbortStateV1 },
          ResultingPendingLifecycleStateTag = GeneratePending
            | InstallPending | RemovePending
        }
      | EnterRecoveryRequired {
          RecoveryEntrySourceV1,
          ResultingLastAuthenticatedTrustTip =
            LastAuthenticatedTrustTipV1,
          ResultingLastAuthenticatedKeyTip = LastAuthenticatedKeyTipV1,
          ResultingKnownCaPublicIdentities = KnownCaPublicIdentitySetV1,
          ResultingUnresolvedTargetVectorV1 = UnresolvedTargetVectorV1,
          ResultingBoundedReasonVectorV1 = BoundedReasonVectorV1,
          ResultingSortedUniqueSelectedTargetFactStateVector,
          ResultingSelectedTargetFactStateRoot,
          ResultingSelectedTargetFactCount,
          GateClosureSelectionV1,
          ResultingLifecycleStateTag = RecoveryRequired
        }
      | RecoveryNoneReproofExit {
          RecoverySelectionId,
          RecoveryRequiredStateDigest,
          LastQuiescentStateSnapshotV1,
          LastQuiescentStateSnapshotDigest,
          GateClosedReceiptV1,
          GateClosedReceiptDigest,
          PreviousBoundedReasonVectorV1 = BoundedReasonVectorV1,
          RecoveryReasonResolutionVectorV1,
          ExactLastQuiescentBusinessPostconditionDigest,
          FreshQuiescentReproofEvidenceV1 =
              GeneratedReproof {
                ResidualQueryContextV1,
                ResidualQueryContextDigest,
                ResidualScanResultV1,
                ResidualScanResultDigest,
                KeyLedgerStateProjectionV1 {
                  Projection = LiveReady
                },
                KeyLedgerStateProjectionDigest,
                RecoveryReproofKeyPossessionProofV1,
                RecoveryReproofKeyPossessionProofDigest
              }
            | InstalledReproof {
                ResidualQueryContextV1,
                ResidualQueryContextDigest,
                ResidualScanResultV1,
                ResidualScanResultDigest,
                CurrentTargetReproofVectorV1,
                KeyLedgerStateProjectionV1 {
                  Projection = LiveReady
                },
                KeyLedgerStateProjectionDigest,
                RecoveryReproofKeyPossessionProofV1,
                RecoveryReproofKeyPossessionProofDigest
              }
            | DriftedReproof {
                ResidualQueryContextV1,
                ResidualQueryContextDigest,
                ResidualScanResultV1,
                ResidualScanResultDigest,
                KeyLedgerStateProjectionV1 {
                  Projection = ClosedDrifted
                },
                KeyLedgerStateProjectionDigest
              },
          ResultingQuiescentLifecycleStateTag = Generated
            | InstalledAndVerified | Drifted,
          ResultingQuiescentBusinessPostconditionDigest,
          ResultingStableReceiptDomain = FlowProbe.TrustCa.GeneratedReceipt.v1
            | FlowProbe.TrustCa.InstalledReceipt.v1
            | FlowProbe.TrustCa.DriftedReceipt.v1
        }
      | TerminalEvidenceFirstSelection {
          TargetVectorRole = PrimaryPhase,
          TargetId,
          PreviousCompletePerTargetStep = CompletePerTargetStepV1,
          PreviousCompletePerTargetStepDigest,
          ResultingCompletePerTargetStep = CompletePerTargetStepV1,
          ResultingCompletePerTargetStepDigest,
          TerminalTargetStepV1,
          TerminalTargetObservationV1,
          TerminalTargetObservationDigest,
          ResultingTargetBusinessFact = TargetBusinessFactV1,
          ResultingTargetBusinessFactDigest
        }
      | SignerSwitchSelection {
          PhaseRole = RotateCommit,
          PreviousRecoveryDisposition = ResumeOrCompensate,
          SignerSwitchPlanV1,
          SignerSwitchPlanDigest,
          SignerSwitchFreshQueryEvidenceV1,
          SignerSwitchKeyPossessionProofV1,
          SignerSwitchKeyPossessionProofDigest,
          SelectedForwardOnlySelectionCommitment =
            ForwardOnlySelectionCommitmentV1,
          ResultingRecoveryDisposition = ForwardOnly,
          SignerSwitchSatisfactionEvidenceV1,
          SignerSwitchSatisfactionEvidenceDigest,
          CandidateInstalledTargetBusinessRoot,
          ActiveCurrentTargetBusinessRoot,
          RotationDualReadyKeyLedgerStateProjection = {
            KeyLedgerStateProjectionV1 {
              Projection = RotationDualReady
            },
            KeyLedgerStateProjectionDigest
          }
        }
      | RotationRetirePhaseAdvance {
          PreviousPendingLifecycleStateTag = InstallPending,
          PreviousOperationKind = RotateInstall,
          CompletedCandidateInstallCompletePerTargetStepVector =
            CompletePerTargetStepVector,
          SignerSwitchPlanV1,
          SignerSwitchPlanDigest,
          SignerSwitchReceiptV1,
          SignerSwitchReceiptDigest,
          SelectedForwardOnlySelectionCommitment =
            ForwardOnlySelectionCommitmentV1 {
              PhaseRole = RotateCommit,
              IrreversiblePhase = SignerSwitchCommitted
            },
          ActiveRetireExactOrderedTargetSetDigest,
          ActiveRetireDispositionRoot,
          ResultingPendingLifecycleStateTag = RemovePending,
          ResultingOperationKind = RotateRetireOld,
          InitializedActiveRetireCompletePerTargetStepVector =
            CompletePerTargetStepVector
        }
      | PhaseOutcomeSelection {
          PhaseRole,
          SelectedAuthorizedPhaseOutcome = AuthorizedPhaseOutcomeV1,
          ExactTerminalTargetBusinessRoot,
          ExactTerminalKeyBusinessPostconditionDigest,
          ResultingStableReceiptDomain = FlowProbe.TrustCa.AbsentReceipt.v1
            | FlowProbe.TrustCa.GeneratedReceipt.v1
            | FlowProbe.TrustCa.InstalledReceipt.v1
            | FlowProbe.TrustCa.DriftedReceipt.v1
        }
      | FailureDispositionRefinement {
          PreviousFailureDisposition = FailureDispositionV1,
          ResultingFailureDisposition = FailureDispositionV1,
          BoundedFailureEvidenceV1
        }

    TrustOperationJournalRecordV1 {
      Body = TrustOperationJournalRecordBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.TrustOperationJournalRecord.v1,
        InstallationId,
        TrustJournalSelectionIdentityV1,
        OperationJournalAuthorityV1,
        ExpectedPredecessorLifecycleStateTag,
        ExpectedPredecessorTrustLifecycleStateDigest,
        ExpectedPredecessorCompletePendingOperationSnapshot = None
          | Some { CompletePendingOperationSnapshotDigest },
        ExpectedPredecessorLastQuiescentStateSnapshot = None
          | Some { LastQuiescentStateSnapshotDigest },
        ExpectedPredecessorTrustStateRevision,
        ExpectedPredecessorTrustJournalHeadDigest,
        ExpectedPredecessorMonotonicSafetyEnvelopeDigest,
        ExpectedPredecessorReplayIndexRevision,
        ExpectedPredecessorConsentReplayIndexRoot,
        ExpectedPredecessorReplayTimeHighWater,
        ExpectedPredecessorConsentBrokerKeysetSelectionRevision,
        ExpectedPredecessorConsentBrokerKeysetSelectionRoot,
        ExpectedPredecessorProductManifestSequence,
        ExpectedPredecessorSignedProductManifestDigest,
        ExpectedPredecessorConsentBrokerKeysetEpoch,
        ExpectedPredecessorConsentBrokerKeysetDigest,
        ExpectedPredecessorConsentVerificationHistoryRevision,
        ExpectedPredecessorConsentVerificationHistoryRoot,
        TrustOperationJournalDeltaV1,
        CurrentObservedTime,
        EffectiveSelectedAt,
        OperationJournalReplaySuccessorV1,
        IntendedResultingTrustStateRevision
      },
      TrustOperationJournalRecordDigest
    }

    TrustOperationJournalRecordDigest = SHA-256(
      "FlowProbe.TrustCa.TrustOperationJournalRecord.v1\0" ||
      canonical(TrustOperationJournalRecordBodyV1)
    )

All ExpectedPredecessor fields resolve to one selected copy-on-write slot and
all duplicated authority, snapshot, plan, receipt, operation, target, key, and
evidence fields are byte-identical. EffectiveSelectedAt is exactly
`max(CurrentObservedTime, ExpectedPredecessorReplayTimeHighWater)` under the
clock-rollback rule. `ReplayUnchanged` repeats the predecessor replay
revision/root/high-water byte-for-byte and is valid only when CurrentObservedTime
is no greater than that high-water, so EffectiveSelectedAt equals it.
`ReplayIndexSelected` carries the
complete digest-free successor body, whose recomputed root, revision, and
high-water equal its sibling fields; revision is the nonwrapping predecessor
plus one. Consent consumption requires ReplayIndexSelected containing its exact
new tombstone. Every other variant may use ReplayIndexSelected only for the
time maintenance already authorized by that same state change.

TrustJournalSelectionIdentityV1 and OperationJournalAuthorityV1 use this closed
delta-tag compatibility mapping; they are not claimed to be a one-to-one
encoding. PendingPhaseAuthority requires PendingOperation and only
ReceiptAndPhaseSelection. RetainedPendingAuthority requires PendingOperation
and only CandidateDescriptorRefinement, TargetStepAdvance, KeyStepAdvance,
ForwardOnlySelection, RecoveryResume, TerminalEvidenceFirstSelection,
SignerSwitchSelection, RotationRetirePhaseAdvance, PhaseOutcomeSelection, or
FailureDispositionRefinement. In both cases the identity's TrustOperationId is
the exact value from the receipt/plan or selected/retained snapshot.
RecoveryResume is additionally valid only when the selected RecoveryRequired
state has GateClosureEvidenceV1=SignedGateClosed and an Active attestation
anchor; the same retained authority grants no successor from an invalidated
recovery.
RotationPreSwitchAbortAuthority requires PendingOperation and only
RotationPreSwitchAbortSelection; its complete authorization, predecessor
snapshot digest, operation, both phase/receipt digests, state/head/envelope/
replay coordinates, capacity admission, and initial compensation-vector digest
must match byte-for-byte. RetainedRotationPreSwitchAbortAuthority also requires
that PendingOperation identity and is valid only for
CandidateAbortCompensationAdvance, CandidateAbortExactBaseSelection, the exact
candidate-cleanup KeyStepAdvance, or the final
PhaseOutcomeSelection(PreSignerSwitchExactOldBase). It requires the current
snapshot to retain the same authorization, CleanupLockedByRotationAbort
Prepare entry, Commit abort ForwardOnly entry, capacity admission, and current
compensation vector. Neither abort authority is valid for ordinary primary-
phase target progress, signer switch, another phase outcome, or a fresh provider
operation ID.
EnterRecoveryWithoutPendingAuthority requires RecoveryWithoutPending and the
same fresh RecoverySelectionId in its FromQuiescentOrDrifted
EnterRecoveryRequired source, or the byte-identical retained RecoverySelectionId
in FromSelectedRecoveryRequired; it is valid for no other delta.
EnterRecoveryWithPendingAuthority requires PendingOperation and the exact
TrustOperationId, last-quiescent snapshot, and retained pending snapshot in its
FromPending EnterRecoveryRequired source, or the corresponding byte-identical
fields in FromSelectedRecoveryRequired; it is valid for no other delta. It
carries no phase/outcome authority: the complete retained
snapshot is the sole operation anchor, so a rotation with two phase plans does
not require or permit a caller-selected PhasePlanDigest merely to fail closed.
RecoveryWithoutPendingAuthority requires RecoveryWithoutPending with the exact
RecoverySelectionId from the selected RecoveryRequired payload, an exact inline
last-quiescent snapshot, and the complete selected GateClosedReceiptV1 whose
recomputed digest equals both authority and payload; it is valid only for
RecoveryNoneReproofExit and only while the envelope anchor is Active and the
payload evidence is SignedGateClosed. ConsentAuthoritySelection requires
ConsentAuthoritySelectionAuthority and is valid only with its dedicated
manifest/keyset delta. A missing,
invented, cross-episode, or variant-substituted identity is invalid; no
non-authorizing identity can appear in a target/key/provider/phase mutation
delta. Once a selected envelope is Invalidated, no OperationJournalAuthorityV1
variant or TrustOperationJournalDeltaV1 successor is valid for that
InstallationId; the invalidation record is evidence for the one fail-closed
selector only.

The delta tag determines the sole permitted snapshot/state change. Every field
not named by that variant remains byte-identical. CandidateDescriptorRefinement
changes only the candidate descriptor; TargetStepAdvance and
TerminalEvidenceFirstSelection change only their one TargetId row and its
deterministic selected fact/anchor; KeyStepAdvance changes only its unique key
step and its native evidence is exactly the complete object embedded by the
resulting KeyStepEvidence. Creating/DestroyPending records select only
ProviderMarkerDurable, Ambiguous selects only ProviderOutcomeAmbiguous, and each
terminal receipt selects only its bijective terminal disposition. A marker,
projection, intent digest, or provider-return boolean without the complete
selected key record cannot advance a helper step; skipped, reversed, or
post-terminal advances are invalid. ForwardOnlySelection changes only its one phase recovery entry;
RotationPreSwitchAbortSelection changes exactly its two named recovery entries,
initializes the independent abort state/vector, and leaves every PrimaryPhase
terminal anchor byte-identical. CandidateAbortCompensationAdvance changes one
abort entry and, only upon an exact-base terminal result, its one selected
current fact; CandidateAbortExactBaseSelection changes only Incomplete to
Complete after its exact full scan. Neither delta may change the PrimaryPhase
vector, capacity admission, authorization, cleanup ID, phase plan, or signer.
RecoveryResume changes Recovery StateEvidence to the retained pending successor
and applies exactly the keyed target/key terminal refinements carried by its
RecoveryResumeEvidenceV1. A RotationAbortCompensation resolution may instead
change exactly its one ambiguous abort entry and resulting compensation-vector
digest under the retained compact authorization; the PrimaryPhase vector and
every unrelated pending field and step row remain byte-identical.
EnterRecoveryRequired is the only operation-journal delta that first
selects RecoveryRequired. FromQuiescentOrDrifted requires
RecoveryWithoutPending with the fresh byte-identical RecoverySelectionId and
OptionalPendingOperationSnapshot=None. FromPending requires PendingOperation
with the retained snapshot's TrustOperationId and
OptionalPendingOperationSnapshot=Some containing that complete snapshot. The
two first-entry source variants inline the exact last-quiescent snapshot, retain every immutable
terminal anchor, and deterministically select the complete known-identity,
unresolved-target, reason, and selected-current-fact vectors/roots/counts shown
in the delta. At least one bounded reason must resolve to complete native
evidence. For either first-entry source under VerifiedPredecessor,
ResultingLastAuthenticatedTrustTip is that
complete predecessor head/revision with
RelationToRecoveryPredecessor=VerifiedSelectedPredecessor. Under
RecoveryQuarantinePredecessor it is the byte-identical last-authenticated
head/revision from the link anchor with the retained-ancestor tag, and its
selected-unverifiable revision/digest equals that anchor; the corrupt digest can
never be presented as authenticated ancestry. For either first-entry source,
ResultingLastAuthenticatedKeyTip uses VerifiedSelectedKeyTip for an independently verified selected projection,
or RetainedVerifiedKeyAncestor with the exact predecessor-envelope and
KeyLedgerIntegrity conflict fields. ResultingKnownCaPublicIdentities is the
complete deterministic union defined above. Both resulting tips and the known-
identity set equal the RecoveryRequired payload byte-for-byte.
FromSelectedRecoveryRequired is valid only for
GateClosureSelectionV1=AttestationAnchorInvalidation from a selected
SignedGateClosed recovery. It retains its selection identity, both snapshots,
authenticated tips, known identities, unresolved targets, and selected target-
fact vector byte-for-byte and changes only the envelope to terminal Invalidated,
the closure evidence, and the reason vector by adding exactly one matching
sticky invalidation reason. A second invalidation or any other use of this source
is invalid. The gate-close intent is derived only from the selected predecessor
gate epoch/disposition and grants no recovery-side mutation.

For SignedAfterHead, the selector appends the EnterRecoveryRequired record in
one TrustJournalRecordLinkV1, derives the resulting head and closed monotonic
envelope, constructs the byte-identical complete GateClosedReceiptV1, stages the
Recovery payload and StateEvidence with those same snapshots/facts, then selects
the complete state. For AttestationAnchorInvalidation, it instead appends the
mandatory `[AttestationAnchorInvalidation, OperationSelection]` link, derives the
Invalidated + Closed envelope, and stages payload and StateEvidence containing
the byte-identical invalidation record; it constructs no gate receipt. The
journal record contains none of the resulting head, envelope, gate-receipt, or
state digests. A crash therefore selects the complete predecessor or complete
RecoveryRequired successor; an unselected record, receipt, staged slot, mixed
snapshot, or backdated reason is not current state.
No other delta or ResidualIdentityObservationRecord refresh variant may perform
the first entry.

FailureDispositionRefinement uses only FailureDispositionV1 and the exact
allowed monotonic transition table above. PreviousFailureDisposition equals the
selected pending snapshot, ResultingFailureDisposition repeats the complete
bounded evidence root, and no target/key/phase/recovery field changes. A
CompensationScheduled value cannot be refined or cleared.

SignerSwitchSelection atomically changes exactly the RotateCommit
recovery entry from ResumeOrCompensate to the byte-identical
SignerSwitchCommitted ForwardOnly commitment and changes
SignerSwitchSelectionEvidence from NoneBeforeSignerSwitch to the complete
SelectedSignerSwitch plan/receipt; both are immutable thereafter.
RotationRetirePhaseAdvance is valid only from the complete receipt-bearing
signer-switch successor: every CandidateInstall row is terminal, its vector/root
matches the satisfaction evidence, and the new ActiveRetire vector contains one
NotAttempted row for every sealed ActiveRetire target in exact target order. It
changes only the pending tag from InstallPending to RemovePending, the operation
kind from RotateInstall to RotateRetireOld, and that phase-specific target-step
vector; it retains both receipts/plans, both identities, the ForwardOnly
direction, signer-switch evidence, complete key steps, continuations, base,
envelope ancestry, and unrelated fields byte-for-byte. ReceiptAndPhaseSelection
with InitialOperationSelection is the only initial-pending anchor; its
SubsequentRotationPhaseSelection form is instead one AuthorizedOperationSuccessor
and appends only the sealed RotateCommit phase fields described above. Unknown
deltas, multiple changed rows, skipped snapshots, or a native evidence digest
used directly as the helper record digest are invalid.

ConsentAuthoritySelection requires the matching non-authorizing selection
identity. Its complete record/digest and resulting selection state are
independently recomputed; the record's predecessor selection and replay fields
equal this journal record's ExpectedPredecessor fields, and its effective time
equals EffectiveSelectedAt. This delta changes only the manifest/keyset
selection state and the resulting replay/envelope/stable-receipt authority for
the byte-identical quiescent business; it consumes no consent and grants no
phase, target, key, provider, AdmissionEligible selection, or recovery authority. The complete
ConsentVerificationHistoryStateV1 and its revision/root remain byte-identical.

ReceiptAndPhaseSelection instead retains the predecessor manifest/keyset
selection revision/root/current digests unchanged. Its complete
ConsentReceiptVerificationResultV1 recomputes to the repeated digest, contains
the byte-identical CaConsentReceiptV1, and names a complete selected keyset
state exactly equal to those predecessor fields. ReceiptPhaseSelectionIntentBodyV1,
the journal record, predecessor monotonic envelope, state index, verification
result, and resulting envelope repeat the same selection revision/root/current
manifest/keyset values byte-for-byte. A staged/newer selection, missing full
preimage, root mismatch, or validation-to-selection TOCTOU aborts before the
tombstone, phase, or side effect is selected.

ReceiptAndPhaseSelection is the only delta that appends consent verification
history. Its complete history record contains the same verification result and
predecessor revision/root; its resulting state is the unique one-record append,
and the intent, journal delta, resulting MonotonicSafetyEnvelope, and selected
state-index slot repeat the resulting revision/root byte-for-byte. Every other
delta retains the complete history state and revision/root unchanged. A fork,
missing full result, count/byte overflow, duplicate receipt record, stale
predecessor, or result/history/journal mismatch aborts the whole selector
transition before any consent or side effect is durable.

ReceiptAndPhaseSelection carries AbortCapacityAdmission=NotApplicable for every
phase except RotateCommit. SubsequentRotationPhaseSelection for RotateCommit
requires RotateCommitAbortAdmitted, validates every applied maximum against the
same current manifest/receipt/plan tuple, and atomically stores it in the
successor pending snapshot before initializing any CandidateInstall intent.
The complete charge vector and every live/worst-case value are deterministic
checked calculations, not caller input.
A missing value, max-plus-one result, arithmetic overflow, historical manifest,
later manifest lowering, target/scope cardinality mismatch, or actual legal
abort replay/recovery/target/key/provider/journal/snapshot/outcome/compaction
object larger than its admitted worst case rejects the whole RotateCommit
selection. Every non-ReceiptAndPhaseSelection delta retains the admission
byte-identical through the terminal rotation selector and required retained
abort audit projection.

TerminalEvidenceFirstSelection requires TerminalTargetStepV1 and every repeated
fact/observation/target field to be byte-identical. The step inside
PreviousCompletePerTargetStep is one allowed nonterminal predecessor;
ResultingCompletePerTargetStep carries exactly the step wrapped by
TerminalTargetStepV1, and TargetStepAdvance is forbidden from
selecting any terminal step. The record requires
`EffectiveSelectedAt <= TerminalTargetObservationV1.Body.must_select_by`.
ReceiptAndPhaseSelection similarly requires selection no later than the signed
consent expiry and every applicable provider/continuation deadline. The
CandidateDescriptorRefinement native selection record independently proves its
own deadline. A late first selection cannot be made timely by a later wrapper.

RecoveryNoneReproofExit is valid only from selected RecoveryRequired with no
pending snapshot, GateClosureEvidenceV1=SignedGateClosed, and an Active
attestation anchor. Its record identity, delta RecoverySelectionId, selected
RecoveryRequired payload, constrained Recovery SelectedStateAnchor, and every
possession proof repeat the same RecoveryWithoutPending episode byte-for-byte.
RecoveryRequiredStateDigest equals the selected predecessor; the complete
GateClosedReceiptV1/digest equals the payload and
RecoveryWithoutPendingAuthority. That receipt is predecessor evidence; it can
never be reused as the receipt for a later resulting head/envelope. The complete
PreviousBoundedReasonVectorV1 equals the selected recovery payload and the
RecoveryReasonResolutionVectorV1 is an exact reason-key bijection under the
closed compatibility table above; RecoveryPathExhausted,
AttestationAnchorInvalidated, a missing resolution, or a cross-tag resolution
forbids exit. The complete
retained last-quiescent snapshot and business digest must verify. Its business
variant, FreshQuiescentReproofEvidenceV1 tag, resulting lifecycle tag, and
stable-receipt domain are bijective: GeneratedBusiness uses GeneratedReproof/
Generated/GeneratedReceipt, InstalledAndVerifiedBusiness uses
InstalledReproof/InstalledAndVerified/InstalledReceipt, and DriftedBusiness uses
DriftedReproof/Drifted/DriftedReceipt. Generated/Installed require
fresh LiveReady and purpose-specific possession; Installed additionally has one
complete current target reproof row per selected required target. Drifted
requires ClosedDrifted, keeps the gate closed, and forbids possession. The
complete ResidualQueryContextV1 in every variant has
Purpose=RecoveryNoneReproof; its digest, QueryChallenge,
EffectiveObservationTime, and exact complete ResidualScanResultV1/digest are
byte-identical to the RecoveryReproofKeyPossessionProofV1 when possession is
required. Every scan target observation also names that same context and scan.
Drifted cannot contain a possession proof. The
resulting business body is byte-identical to the retained last-quiescent
business body. The complete scan and key projection MUST deterministically
reproduce its known-identity set, key business projection, and the complete
selected-current-target vector/root/count from the retained snapshot. Installed
also requires CurrentTargetReproofVectorV1 to contain exactly one matching row
for every required target; Generated and Drifted do not omit verification of
their non-required or drift-finding rows merely because they have no such
required-target-only wrapper. Any changed, missing, ambiguous, or extra fact
remains RecoveryRequired and cannot use this exit. After this
record is appended, the helper derives the successor journal head and monotonic
envelope, obtains a separate fresh StableStateSelection possession proof bound
to that resulting business/head/envelope for Generated or Installed, constructs
the named stable receipt over those exact objects, and selects the quiescent
state. For Drifted, after deriving that successor head and still-closed envelope
the helper first constructs a new RetainedClosed GateClosedReceiptV1 with
GateCloseReason=DriftDetected, the same gate epoch, the resulting revision/head/
envelope and key tip, and committed_at equal to this record's
EffectiveSelectedAt; the resulting Drifted payload and StateEvidence use this
new receipt, never the predecessor recovery receipt. Absent continues to use only the dedicated
AbsentResidualObservation record/receipt path. This exit consumes no consent,
performs no trust/key mutation, and cannot select AdmissionEligible unless the
exact retained business already authorizes it.

The journal record contains no resulting lifecycle-state digest, resulting
pending/last-quiescent snapshot digest, resulting trust-journal head, resulting
monotonic-envelope digest, stable-receipt digest, or signer-switch receipt
digest. Its DAG is predecessor state/snapshot/head/envelope/replay plus native
evidence -> journal record -> resulting journal head/replay/envelope -> optional
resulting Drifted gate receipt -> snapshot or stable receipt -> resulting state.

Every current-authority duplicate in the selected index, current lifecycle
payload, current universe body, in-flight scan/result, or proof MUST equal the
selected universe/envelope projection. An immutable key ancestor,
pending/last-quiescent snapshot, prior result, or prior receipt instead MUST
equal its exact then-selected revision/root and carry a retained authenticated
successor chain to the current selected pair. That chain admits only the closed
member-addition, observer-binding append, reservation add,
reservation-to-exact-identity refinement, or terminal reservation-release edges
defined above.

The generation commitment follows the staged-authority exception above: it
remains at H0/U1 after the selected catalog advances to U2;
LastHelperTrustTip remains H0, the U0-to-U1 successor record proves the exact
pure catalog derivation, and the selected H1 proves the exact intent descendant
that first published U1. It is not required or permitted to claim that H0/U1
was ever selected. An old object is never rewritten, treated as current, or
accepted from a fork. A current duplicate mismatch or invalid, missing, or
nonunique historical/staged-admission ancestry is integrity failure, never a
merge rule.

Recovery accepts one complete valid old index or one complete valid new index.
It never combines slots, guesses a selector, rolls back a nonwrapping revision,
or treats an unselected staged slot as authoritative. A torn/ambiguous selector,
unknown state tag, missing journal ancestor, mismatched key receipt, or
missing/rolled-back residual-universe body, invalid universe successor,
incomplete scan universe, or incomplete identity set is RecoveryRequired.

The state-index ReplayIndexRevision and ReplayTimeHighWater MUST equal the
values inside the replay body selected by ConsentReplayIndexRoot; duplicate
field mismatch is integrity failure. CapacityReservationStateV1 is committed
by that same root and checked against the current lifecycle/pending state before
either selector is accepted.

The helper also maintains an authenticated copy-on-write
ConsumedConsentReplayIndexV1 independently of journal compaction:

    ConsumedConsentReplayIndexV1 {
      Body = ConsentReplayIndexBodyV1 {
        SchemaVersion = 1,
        ReplayIndexRevision,
        ReplayTimeHighWater,
        CapacityReservationStateV1 {
          SafetyReductionMode = NoProtectedState
            | FullChoice
            | DirectDestroyOnly
            | CoveredByPendingSafetyOperation(TrustOperationId),
          ReservedSafetyReductionEntryCount,
          ReservedSafetyReductionEncodedBytes,
          SortedUniqueRotationContinuationReservationVector = [
            {
              TrustOperationId,
              RotatePrepareConsentReceiptId,
              ReservedRotateCommitEntryCount = 1,
              ReservedRotateCommitEncodedBytes
            }
          ]
        },
        SortedUniqueTombstoneVector = [
          ConsentReplayTombstoneV1 {
            Body = ConsentReplayTombstoneBodyV1 {
              ConsentReceiptId,
              OneUseNonceDigest,
              TrustOperationId,
              ReceiptOperationKind,
              CanonicalConsentReceiptBodyDigest,
              ConsentReceiptDigest,
              ConsentReceiptVerificationResultDigest,
              ExpectedBaseStateDigest,
              ExpectedBaseTrustStateRevision,
              ExpectedBaseTrustJournalHeadDigest,
              FirstConsumedIntentDigest,
              ReplayResult = OperationReplayResultV1 {
                Body = OperationReplayResultBodyV1 {
                  SchemaVersion = 1,
                  TrustOperationId,
                  LogicalOperationKind = Generate | Install | Repair
                    | RemoveTrust | RemoveAndDestroy | Rotate,
                  ResultPayload =
                    Pending {
                      SafeObservedPhase,
                      ResultingTrustStateRevision,
                      Retryability,
                      BoundedReason
                    }
                  | Terminal {
                      TerminalDisposition = Succeeded | SafelyCompensated
                        | CreateUnapplied | Removed | Destroyed
                        | FailedWithoutSideEffect,
                      ResultingLifecycleStateTag,
                      ResultingTrustStateRevision,
                      OptionalCaPublicIdentityDigest,
                      BoundedTargetResultVector,
                      BoundedOperationEvidenceReferenceVector,
                      Retryability = false,
                      OptionalBoundedReason
                    }
                },
                OperationReplayResultDigest
              },
              ExpiresAt
            },
            ConsentReplayTombstoneDigest
          }
        ]
      },
      ConsentReplayIndexRoot
    }

OperationReplayResultDigest covers only the canonical
OperationReplayResultBodyV1 under the registered result domain. That body is the
complete bounded typed public result returned by an exact replay; it contains no
ReplayIndexRoot, tombstone digest, lifecycle state digest, selector digest,
private key/provider identity, public DER, or arbitrary platform text.
BoundedTargetResultVector is sorted by TargetId and carries only each public
terminal disposition, stable bounded reason, and retryability; its count and
encoding share the signed target/result limits.
BoundedOperationEvidenceReferenceVector is a canonical sorted unique closed
union:

    OperationEvidenceReferenceV1 =
        ConsentEvidence {
          ReceiptKind,
          ConsentReceiptDigest
        }
      | PhasePlanEvidence {
          PhaseRole,
          PhasePlanDigest
        }
      | KeyAuthorityEvidence {
          EvidenceKind = KeyCreated | KeyCreateUnapplied
            | KeyCreateNeverStarted | KeyDestroyed,
          KeyAuthorityReceiptDigest
        }
      | TargetObservationEvidence {
          TargetId,
          TerminalTargetStepV1,
          TerminalTargetObservationDigest
        }
      | IdentitySetBodyEvidence {
          IdentitySetProofBodyDigest
        }
      | ProviderAbsenceEvidence {
          EvidenceKind = CreatePreCall {
              RequiredSignatureDomain = FlowProbe.TrustCa.ProviderCreatePreCallAbsence.v1
            }
          | CreatePostCall {
              RequiredSignatureDomain = FlowProbe.TrustCa.ProviderCreatePostCallAbsence.v1
            }
          | DestroyPostCall {
              RequiredSignatureDomain = FlowProbe.TrustCa.ProviderDestroyPostCallAbsence.v1
            },
          ProviderAbsenceProofDigest
        }

It is sorted by `(variant tag, canonical primary identity, digest)`, rejects
duplicates, and shares the signed result count/byte limits. Each digest must
verify under exactly the domain implied by its variant. Operation replay result,
consent tombstone, replay index, selector, complete lifecycle state, stable
response/receipt, or any object whose body contains one of those values is not
an allowed evidence domain. Thus an evidence reference cannot point directly or
indirectly back to its OperationReplayResultV1, tombstone, replay root, or state
selector.
ConsentReplayTombstoneDigest similarly covers only
ConsentReplayTombstoneBodyV1, and ConsentReplayIndexRoot covers only the
canonical ConsentReplayIndexBodyV1. None of those digest fields is in its own
preimage, and the state index carries the resulting replay root as a separate
field, so there is no result/tombstone/root/state digest cycle.

Every tombstone's CanonicalConsentReceiptBodyDigest, ConsentReceiptDigest, and
ConsentReceiptVerificationResultDigest
MUST equal the independently recomputed values of the one complete verified
CaConsentReceiptV1 and complete ConsentReceiptVerificationResultV1 consumed by
its receipt ID. The selecting ReceiptAndPhaseSelection journal record retains
both complete objects and the exact then-current keyset-selection state; journal
compaction must retain those preimages. Its OneUseNonceDigest is
recomputed from that receipt body. A different signature, signer key/keyset,
signed-receipt digest, or body under the same receipt ID or nonce is replay or
integrity failure, never an alternate valid encoding of the same consent.

The vector is keyed and sorted by ConsentReceiptId. That identifier is unique
across the retained vector, and OneUseNonceDigest is independently unique
across all retained entries. Exact same-id/same-nonce/same-body replay resumes
the same pending operation or returns the inline durable terminal result;
same-id/different-nonce, different-id/same-nonce, or any body/base/operation
change is ReplayDetected. It never repeats a key/platform side effect.

TrustOperationId is independently unique across every pending operation,
retained tombstone, and uncompactable operation summary. A new receipt whose
operation ID is already bound is OperationIdCollision, except that
RotateCommit must reuse the one exact RotatePrepare operation ID and must match
its receipt, phase-plan ancestry, candidate commitment/identity, and expected
pending base byte-for-byte. No other phase or logical operation may share that
ID. Consequently an update "by TrustOperationId" first proves this unique
logical-operation binding; it cannot modify tombstones from another operation.
Coordinators generate a fresh random ID and never deliberately reuse one after
compaction, even though a receipt pruned under the expiry rule can no longer be
accepted.

The root and revision are selected with the same rollback-detecting state-index
transition that consumes a receipt. Every operation phase atomically updates
the inline replay result of every retained tombstone with that
TrustOperationId; rotation therefore updates both RotatePrepare and
RotateCommit tombstones together. A crash before selection leaves the prior
pending result and exact retry reconciles it; a crash after selection returns
the new result. Journal compaction MUST preserve each live tombstone's complete
inline result body and lookup data, not merely a digest or root.

Receipt `expires_at` is no later than the checked nonwrapping sum of `issued_at`
and TrustCaManifestBoundsV1.MaximumConsentReceiptLifetime; overflow or a later
expiry invalidates the signed receipt before consumption. ReplayTimeHighWater is
the maximum authenticated wall-clock value ever accepted and never decreases.
Clock rollback beyond TrustCaManifestBoundsV1.MaximumAcceptedClockSkew blocks new
receipt validation; within that skew, receipt validation uses
max(CurrentObservedTime, ReplayTimeHighWater) as EffectiveReceiptTime. A tombstone may be pruned only after no pending operation
references it and ReplayTimeHighWater is strictly later than ExpiresAt plus
MaximumAcceptedClockSkew using checked nonwrapping addition, so a pruned receipt is necessarily expired at every
subsequently accepted time. Selector ambiguity, index rollback, missing lookup
data, or a root mismatch is RecoveryRequired.

The live tombstone vector count and complete canonical replay body are bounded
by TrustCaManifestBoundsV1.MaximumConsentReplayTombstoneCount and
MaximumConsentReplayIndexEncodedBytes. Each inline replay result is bounded by
MaximumOperationReplayResultTargetCount,
MaximumOperationReplayEvidenceCount, and
MaximumOperationReplayResultEncodedBytes. Admission
accounts each tombstone at its maximum possible terminal inline-result size,
not its smaller initial Pending encoding, so a later result update cannot
overflow the index. CapacityReservationStateV1 is part of the authenticated
replay body and maintains these non-borrowable worst-case budgets:

- an InstalledAndVerified state with full headroom (including the corresponding
  bounded Drifted state) uses FullChoice and reserves two safety-reduction
  entries/byte maxima, permitting RemoveTrust followed by RemoveAndDestroy;
- Generated, or an installed state whose earlier safety attempt consumed one
  live tombstone, uses DirectDestroyOnly and reserves one entry/byte maximum
  exclusively for RemoveAndDestroy; another RemoveTrust is refused until safe
  pruning can re-establish FullChoice;
- Drifted inherits the exact FullChoice or DirectDestroyOnly mode and byte/count
  reservation from its LastStableStateDigest: Generated-to-Drifted and
  DirectDestroyOnly-installed-to-Drifted remain DirectDestroyOnly, while a
  FullChoice-installed-to-Drifted remains FullChoice. External drift cannot
  release, shrink, upgrade, or otherwise reinterpret that reserve; reproof,
  repair, and removal use the inherited mode until an authorized transition
  changes it;
- a pending/recovery state retains at least the reserve required by every
  reachable authorized phase outcome, and an operation may not enter a state
  whose required reserve is unavailable; and
- accepting RotatePrepare additionally creates one operation-bound continuation
  reservation for its exact RotateCommit tombstone. Only that matching commit
  may consume it, and candidate cleanup uses the already consumed prepare
  receipt.

Generate, Install, and every other ordinary capacity-increasing operation are
rejected before consent consumption or side effect unless their own maximum
tombstone, every required future safety-reduction budget, and any rotation
continuation all fit. RemoveTrust and RemoveAndDestroy may consume the safety
budget; RotateCommit may consume its continuation reservation even when the
ordinary partition is full. RemoveTrust requires FullChoice, consumes one
entry, and atomically leaves DirectDestroyOnly intact whether it reaches
Generated or safely returns to its installed base. RemoveAndDestroy may consume
the last DirectDestroyOnly entry by changing the mode to
CoveredByPendingSafetyOperation. That same atomic receipt-consumption
transition creates the phase entry initially as
ForwardOnly(SafetyReservationConsumed, intended Absent), rather than
ResumeOrCompensate. In that mode the consumed exact operation and recovery
snapshot are the continuing destruction authority and MUST remain
Pending or RecoveryRequired until they reach Absent; they cannot terminally
return to a key-owning state and demand a new receipt. Its replay result remains
Pending while a protected key or owned trust may survive; FailedWithoutSideEffect
and SafelyCompensated terminal results are forbidden in that mode. A RemoveAndDestroy that
started from FullChoice may instead safely compensate to
DirectDestroyOnly. No ordinary receipt can borrow either reserve. An
Absent state need not reserve future creation capacity, so old live tombstones
may delay a new Generate but can never trap an existing owned anchor or key.
If an authenticated state is missing its required reserve, that is integrity
failure and RecoveryRequired rather than ReplayIndexCapacityExceeded.

At the ordinary cap, the consent broker issues no ordinary receipt and the
helper returns ReplayIndexCapacityExceeded before consuming one; it never
evicts a live tombstone or reserved byte to make room.

MaintainReplayIndexTimeV1 is a non-authorizing maintenance component that may
run only inside a selector transition already required to commit a consent,
operation, recovery, business, or observation change. Under the global mutation
lock it reads the current clock, applies the rollback rule, advances
ReplayTimeHighWater, prunes only strictly eligible tombstones, and places the
new digest-free ConsentReplayIndexBodyV1/root/revision in that same
copy-on-write slot. It never selects a maintenance-only slot and never supplies
a predecessor for a query whose business projection was byte-identical. It
changes no lifecycle business fact, gate, target, key, consent semantics, or
operation result, and preserves every still-required capacity reservation.
When RecoveryRequired is current, the new root is a monotonic descendant of the
snapshot root. Crash recovery selects one complete old or combined successor
slot; it never combines them. Preview, readiness, and byte-identical query paths
use ValidateReplayIndexTimeReadOnlyV1 and conservatively count any tombstone not
yet pruned. A later authorized selector transition may reclaim safely expired
tombstones before its capacity decision and commit, so a full index cannot
permanently block RemoveTrust or RemoveAndDestroy.

Every key destroy first binds one already-selected helper-side forward-only
authority object:

    ForwardOnlyDestroyAuthorizationV1 {
      InstallationId,
      TrustOperationId,
      DestroyAuthorityRole = DirectRemoveAndDestroy
        | RotatePrepareCandidateCleanup
        | RotateCommitOldKeyDestroy,
      PhaseRole = RemoveAndDestroy | RotatePrepare | RotateCommit,
      ForwardOnlyAuthorityPhaseRole = RemoveAndDestroy
        | RotatePrepare | RotateCommit,
      ConsentReceiptDigest,
      PhasePlanDigest,
      ForwardOnlyAuthorityPhasePlanDigest,
      CaGeneration,
      CaInstanceId,
      KeyDestroyOperationId,
      DestroyContinuationAuthorityV1,
      DestroyContinuationAuthorityDigest,
      DestroyContinuationSelectionRecordV1,
      DestroyContinuationSelectionRecordDigest,
      CompletePendingOperationSnapshotDigest,
      ForwardOnlySelectionAnchor =
          InitiallyForwardOnlyReceiptConsumption {
            TrustOperationJournalRecordV1 {
              RequiredDelta = ReceiptAndPhaseSelection
            },
            TrustOperationJournalRecordDigest
          }
        | ForwardOnlyRefinement {
            TrustOperationJournalRecordV1 {
              RequiredDelta = ForwardOnlySelection
            },
            TrustOperationJournalRecordDigest
          }
        | RotationPreSwitchAbortSelection {
            TrustOperationJournalRecordV1 {
              RequiredDelta = RotationPreSwitchAbortSelection
            },
            TrustOperationJournalRecordDigest,
            RotationPreSwitchAbortAuthorizationV1,
            RotationPreSwitchAbortAuthorizationDigest,
            CandidateAbortCompensationVectorV1 {
              Body.ExactBaseCompletion = Complete
            },
            CandidateAbortCompensationVectorDigest,
            CandidateAbortExactBaseFactRoot
          }
        | SignerSwitchForwardOnlySelection {
            TrustOperationJournalRecordV1 {
              RequiredDelta = SignerSwitchSelection
            },
            TrustOperationJournalRecordDigest
          },
      SelectedForwardOnlySelectionCommitment =
        ForwardOnlySelectionCommitmentV1,
      SelectedForwardOnlyPendingLifecycleStateTag = InstallPending
        | RemovePending,
      SelectedForwardOnlyTrustLifecycleStateDigest,
      SelectedForwardOnlyTrustStateRevision,
      SelectedForwardOnlyTrustJournalHeadDigest,
      SelectedForwardOnlyMonotonicSafetyEnvelopeDigest,
      KeyProviderSelectionDeadlineBindingV1
    }

The selected complete lifecycle state and pending snapshot MUST resolve from
the authenticated helper journal, equal the named digest/revision/head/envelope,
and contain the matching phase plan, consent, complete key step, deadline
binding, timely selected destroy continuation/selection record, and current
ForwardOnly disposition byte-for-byte. Its selection-time key step is exactly
OperationReservationSelected with the complete
purpose-compatible ProviderReservation evidence from that continuation; a
missing, terminal, or different provider step cannot authorize
intent construction. Its selection anchor is the receipt-consumption record
that created the initially ForwardOnly DirectDestroyOnly entry, the sole
  authenticated ForwardOnlySelection refinement from ResumeOrCompensate, the
  RotationPreSwitchAbortSelection authorization (only for
  RotatePrepareCandidateCleanup after complete candidate exact-base
  compensation), or,
only for RotateCommitOldKeyDestroy, the SignerSwitchSelection record that
atomically selected the SignerSwitchCommitted ForwardOnly entry. The initial
record MUST be the matching immutable member of OperationJournalAnchorVectorV1;
either later selection record MUST be the exact AuthorizedOperationSuccessor
journal record in the pending snapshot lineage, and the rotation-retire phase-
advance successor MUST retain it byte-for-byte.
The named state is the exact selected descendant of that
anchor at intent construction. It may be a later pending-state descendant only
when every intervening record retains the operation, phase plan, consent,
deadline binding, ForwardOnly direction, intended/exact-base outcome, and
remaining path byte-for-byte and grants no broader authority. The complete
SelectedForwardOnlySelectionCommitment MUST be one byte-identical member of the
ForwardOnlyAuthorityPhasePlanDigest plan, current ForwardOnly disposition, and
selecting journal delta. The continuation instead equals the PhasePlanDigest
plan. Those two phase-plan digests and roles are byte-identical except for the
pre-switch-abort form, whose ForwardOnly authority is RotateCommit and whose
locked retained cleanup continuation remains RotatePrepare. The exact
remaining path MUST contain this destroy step in the role named by
DestroyAuthorityRole. DirectRemoveAndDestroy selects intended Absent;
  RotatePrepareCandidateCleanup selects the exact old base, using either its
  ordinary pre-commit cleanup selection or the complete compact
  RotationPreSwitchAbortAuthorizationV1;
  and
RotateCommitOldKeyDestroy selects the intended new InstalledAndVerified
outcome. Their deadline step roles are respectively
DirectRemoveAndDestroyKeyDestroy,
RotatePrepareCandidateCleanupDestroy, and RotateCommitOldKeyDestroy; no other
role/phase/step combination is decodable. Direct FullChoice permits only
`OwnedRemovalIssued | KeyDestroyIssued`, DirectDestroyOnly only
  `SafetyReservationConsumed`, RotatePrepare only `KeyDestroyIssued`, and
  RotateCommit only `PreSignerSwitchAbortCommitted | SignerSwitchCommitted`,
  exactly as the continuation and authorization records. The pre-switch-abort
  form additionally requires the complete fresh candidate exact-base vector,
  current RotatePrepare CleanupLockedByRotationAbort entry, and the same
  authorization/continuation/operation ID before intent construction.
Role/phase/deadline mismatch, a ResumeOrCompensate current entry, a
skipped or forked helper ancestor, or any descendant that broadened or changed
the selected path invalidates the authorization.

Key destruction has one explicit pre-provider-call object:

    KeyDestroyIntentBodyV1 {
      SchemaVersion = 1,
      DigestDomain = FlowProbe.TrustCa.KeyDestroyIntent.v1,
      TrustOperationId,
      ConsentReceiptDigest,
      DestroyAuthority =
          DirectRemoveAndDestroy {
            RemoveAndDestroyConsentReceiptDigest,
            RemoveAndDestroyPhasePlanDigest
          }
        | RotatePrepareCandidateCleanup {
            RotatePrepareConsentReceiptDigest,
            RotatePreparePhasePlanDigest,
            RotationReadyKeyProjectionAttestationV1,
            RotationReadyKeyProjectionAttestationDigest,
            RotationReadyProjectionSelectionRecordV1,
            RotationReadyProjectionSelectionRecordDigest,
            SelectedRotationReadyPendingTrustLifecycleStateDigest,
            SelectedRotationReadyPendingTrustJournalHeadDigest,
            ActiveReadyRecordDigest,
            CandidateReadyRecordDigest,
            CleanupSelectionAuthority =
                OrdinaryRotatePrepareCleanup
              | RotationPreSwitchAbort {
                  RotationPreSwitchAbortAuthorizationV1,
                  RotationPreSwitchAbortAuthorizationDigest,
                  CandidateAbortCompensationVectorV1 {
                    Body.ExactBaseCompletion = Complete
                  },
                  CandidateAbortCompensationVectorDigest,
                  CandidateAbortExactBaseFactRoot
                }
          }
        | RotateCommitOldKeyDestroy {
            RotateCommitConsentReceiptDigest,
            RotateCommitPhasePlanDigest,
            SignerSwitchPlanV1,
            SignerSwitchPlanDigest,
            SignerSwitchReceiptV1,
            SignerSwitchReceiptDigest,
            CandidateKeyBindingDigest,
            RotationTargetBindingDigest,
            RotationReadyProjectionSelectionRecordDigest,
            ActiveReadyRecordDigest,
            CandidateReadyRecordDigest
          },
      DestroyContinuationAuthorityV1,
      DestroyContinuationAuthorityDigest,
      DestroyContinuationSelectionRecordV1,
      DestroyContinuationSelectionRecordDigest,
      ForwardOnlyDestroyAuthorizationV1,
      InstallationId,
      CaGeneration,
      CaInstanceId,
      ProviderAndVersion,
      KeyProviderProfileDigest,
      SignedProductManifestDigest,
      KeyAuthorityEpoch,
      LastReadyRecordDigest,
      LastCaPublicIdentityDigest,
      CertificateSpkiSha256,
      NonExportableKeyIdentityDigest,
      ProviderObjectNonAliasingTagDigest,
      ProviderSecretNonAliasingTagDigest,
      KeyDestroyOperationId,
      KeyDestructionChallengeDigest,
      ExpectedPredecessorKeyStateRevision,
      ExpectedPredecessorKeyJournalHeadDigest,
      ExpectedPreDestroyCompleteKeyGenerationStateRoot,
      LastHelperTrustTip,
      DestroyContinuationSelectionDeadline
    }

    KeyDestroyIntentDigest = SHA-256(
      "FlowProbe.TrustCa.KeyDestroyIntent.v1\0" ||
      canonical(KeyDestroyIntentBodyV1)
    )

KeyDestroyOperationId is the installation-lifetime-unique ID preallocated by
the byte-identical timely selected DestroyContinuationAuthorityV1. It is never
a provider handle and cannot be changed or newly chosen at intent construction.
The continuation's complete ProviderDestroyOperationReservation wrapper must
recompute to its record digest/resulting revision/root, have the destroy purpose
and role named by this intent, and already be selected in the key authority's
complete current reservation vector before intent construction. Its resulting
root may be a retained exact prefix of the current reservation root; omission,
fork, purpose/target substitution, or another record for the same raw operation
ID is ProviderOperationReservationMismatch and forbids bootstrap, marker, and
dispatch.
The provider profile MUST make the exact tuple
`{KeyDestroyOperationId, ProviderCallInvocationMarkerDigest}` durable at first
dispatch; the marker itself binds KeyDestroyIntentDigest. It provides
zero-or-one/idempotent semantics: the same ID and byte-identical marker invokes
at most one destroy and returns the same queryable terminal result; the same ID
with different marker or intent bytes is an integrity error; no second ID may target an object
whose first destroy outcome is unresolved. The intent contains no
ProviderCallInvocationMarker, DestroyPending record/digest, provider result,
absence/negative proof, KeyDestroyedReceipt, Destroyed record, or resulting key
head. The complete intent is hashed before its invocation marker; both are then
fsynced in the one DestroyPending record. DestroyContinuationSelectionDeadline
was consumed only by the earlier continuation selection. It imposes no later
wall-clock bound on intent, marker, or DestroyPending first selection. Provider
dispatch and crash recovery follow the marker rules below and never rely on a
provider-reported timestamp for timeliness. Thus the destroy DAG is receipt and
phase plan -> timely continuation selection -> pending helper state ->
ForwardOnly state/snapshot -> ForwardOnlyDestroyAuthorizationV1 -> intent ->
bootstrap -> marker -> DestroyPending; none of those predecessors contains a
resulting state/head or later object/digest.
ExpectedPredecessorKeyStateRevision/Head MUST equal the current global key-ledger
tip at intent construction; it is not required to be the target generation's
historical Ready head. ExpectedPreDestroyCompleteKeyGenerationStateRoot is
recomputed at that same tip and MUST contain the target generation in Ready with
CurrentRecordDigest=LastReadyRecordDigest and byte-identical public identity,
SPKI, and all three internal identity/tag digests.
The continuation's earlier expected key revision/head/root is historical
selection authority, not the intent predecessor. A unique authenticated
nonforking key-ledger successor chain MUST connect it to this current intent
predecessor/root. Every intervening record must be authorized by the same
operation/phase; RotatePrepare may add only its exact committed candidate
creation/Ready ancestry before cleanup, while DirectRemoveAndDestroy and
RotateCommit reject an unrelated intervening provider operation or target
substitution.

DestroyAuthority is a closed, non-substitutable authorization union.
ConsentReceiptDigest equals the variant-specific receipt digest. Every variant's
phase-plan digest equals the one corresponding PhasePlanVectorV1 and
RecoveryDispositionEntryV1 member in the selected pending snapshot; its consent
digest equals that entry and the matching consumed receipt/tombstone.
SignedProductManifestDigest equals the complete manifest in that phase plan,
the consumed consent body, and the CurrentSignedProductManifestDigest in the
selected pending envelope/state index. A direct
RemoveAndDestroy names its matching phase plan, targets the common forward-only
authorization state's sole Ready generation, and rejects a second Ready entry.
For all three variants, the common authorization's installation, destroy role,
generation/instance, continuation/selection record,
KeyDestroyOperationId, deadline binding, snapshot, state, and helper head MUST
match the variant and intent byte-for-byte. PhaseRole/PhasePlanDigest identify
the provider continuation phase, while ForwardOnlyAuthorityPhaseRole/
ForwardOnlyAuthorityPhasePlanDigest identify the helper ForwardOnly path. They
are byte-identical in every ordinary form. Only the pre-switch abort uses the
retained RotatePrepare continuation under the current RotateCommit ForwardOnly
authorization, and both complete plans/receipts are bound by the compact abort
authorization. The continuation target commitment
MUST match the variant-specific target fields and LastHelperTrustTip equals
SelectedForwardOnlyTrustJournalHeadDigest. RotatePrepareCandidateCleanup is
valid in exactly two forms. OrdinaryRotatePrepareCleanup is before RotateCommit:
its
complete attestation and selection record recompute to their digests, the record
proves the attestation was timely selected in the named historical pending
state/head, the common forward-only state is its authenticated descendant
without RotateCommit or trust-target mutation, and CandidateReadyRecordDigest
MUST be the unique Ready descendant of the continuation's exact candidate
GenerationCommitmentDigest/generation/instance/profile. LastReadyRecordDigest equals
CandidateReadyRecordDigest, and the exact
pre-destroy root contains the candidate and active Ready entries named by the
attested RotationDualReady projection. It does not require or permit a
CandidateKeyBinding or RotationTargetBinding. The candidate must additionally
be proven uninstalled and its SPKI/object/secret/nonexportable identity distinct
before cleanup. RotationPreSwitchAbort is after RotateCommit selection but
before signer switch: it additionally requires the current complete abort
authorization/state, a Complete compensation vector and exact-base fact root,
RotatePrepare CleanupLockedByRotationAbort, the RotateCommit abort ForwardOnly
commitment, and the exact retained Prepare continuation/operation ID. No other
post-RotateCommit candidate-cleanup form exists.

RotateCommitOldKeyDestroy is valid only after signer switch and every sealed
active-retire postcondition. CandidateKeyBindingDigest and
RotationTargetBindingDigest resolve through the retained complete
RotationTargetBindingV1, whose selection-record digest and active/candidate
Ready digests equal this variant; LastReadyRecordDigest equals
ActiveReadyRecordDigest. Its pre-destroy root contains the same still-Ready
candidate and active entries, and LastHelperTrustTip is the selected descendant
whose phase graph authorizes old-key destruction. It cannot authorize candidate
cleanup. Both Ready digests and CA identities MUST equal the continuation's
RotateCommitOldKeyTarget commitment. The complete SignerSwitchPlanV1 and
SignerSwitchReceiptV1 independently verify; their digests, operation, phase,
identities, Ready records, target roots, selected ForwardOnly commitment,
resulting signer, journal head, envelope, and replay fields are byte-identical
to the current pending ancestry. The receipt proves the candidate was selected
and the old identity became retiring before active-target removal or old-key
destroy. An unknown variant, receipt/phase/state substitution, swapped Ready
role, absent selection ancestry, intervening target-state change, or current-
versus-history substitution invalidates the intent.

DestroyContinuationSelectionDeadline and the complete
KeyProviderSelectionDeadlineBindingV1 are copied byte-for-byte from the exact
destroy-step member sealed by that phase plan, matching recovery disposition
entry and CompleteKeyStepVector member, the complete continuation/selection
record, and ForwardOnlyDestroyAuthorizationV1. The selection record, not the
later intent or marker, MUST prove EffectiveSelectedAt no later than the exact
minimum of receipt expiry and sealed phase-step deadline. The key authority
cannot accept a caller-chosen value, shorter or extended nonidentical value,
other phase/step binding, late/missing selection record, changed operation ID,
or binding inconsistent with LastHelperTrustTip; such a mismatch is
DestroyAuthorityMismatch before bootstrap or marker construction.

The sole marker-free provider operation is this read-only bootstrap query:

    ProviderPreDispatchBootstrapQueryV1 {
      SchemaVersion = 1,
      PurposeBinding =
          Create { GenerationCommitmentDigest, ProviderCreateOperationId }
        | Destroy { KeyDestroyIntentDigest, KeyDestroyOperationId },
      ProviderOperationReservationRecordDigest,
      InstallationId,
      CaGeneration,
      CaInstanceId,
      ProviderAndVersion,
      KeyProviderProfileDigest
    }

    ProviderPreDispatchBootstrapResultV1 {
      SchemaVersion = 1,
      ExactQueryEcho = ProviderPreDispatchBootstrapQueryV1,
      ProviderOperationStatus = NeverInvoked,
      StoredInvocationMarker = None,
      ProviderPreDispatchObservationToken
    }

This one registered query accepts only the operation ID plus its exact
commitment-or-intent/purpose/provider binding and the already-selected
purpose-compatible reservation-record digest. The create digest is the record
in GenerationCommitmentBodyV1; the destroy digest is the record in the complete
DestroyContinuationAuthorityV1 retained by KeyDestroyIntentBodyV1. Before the
query, the key authority proves that record is a member of its complete current
reservation vector and that the record's resulting root is an exact prefix of
the current root. It accepts no marker, grants no dispatch authority,
creates/binds no provider operation or key object, and is idempotent read-only.
Repeating the byte-identical query before selection yields the same stable no-
ABA token while the result remains NeverInvoked. An existing operation/
tombstone, a missing/unselected reservation, a different purpose/commitment/
intent/reservation under the same ID, StoredInvocationMarker other than None,
or an unstable token is collision or Ambiguous, never a bootstrap success.
The bootstrap query/result have no standalone digest or signing domain and are
accepted only as a closed nested input under the registered provider profile:
either one result is embedded in the later invocation marker, or two byte-
identical results are embedded in the signed never-started proof below. They
cannot substitute for ProviderAbsenceProofV1, authorize a call, or be referenced
by any receipt except through their complete containing marker or complete
CreateNeverStartedProviderAbsenceProofV1.

There is one non-dispatching exception used only to terminate a creation that
never reached marker-bearing Creating. The key authority may sign:

    CreateNeverStartedProviderAbsenceProofV1 {
      Body = CreateNeverStartedProviderAbsenceProofBodyV1 {
        SchemaVersion = 1,
        SignatureDomain =
          FlowProbe.TrustCa.ProviderCreateNeverStartedAbsence.v1,
        Purpose = CreateNeverStartedCancellation,
        CancellationReason = MarkerSelectionDeadlineElapsed
          | AuthorizedSafeCompensationBeforeMarker,
        InstallationId,
        TrustOperationId,
        ConsentReceiptDigest,
        CaGeneration,
        CaInstanceId,
        ProviderAndVersion,
        KeyProviderProfileDigest,
        SignedProductManifestDigest,
        MaximumCreateNeverStartedObservationWindow,
        GenerationCommitmentBodyV1,
        GenerationCommitmentDigest,
        ProviderCreateOperationId,
        ProviderOperationReservationRecordV1,
        ProviderOperationReservationRecordDigest,
        SelectedProviderOperationReservationRevision,
        SelectedProviderOperationReservationRoot,
        ExpectedPreCreateCompleteKeyGenerationStateRoot,
        KeyAuthorityEpoch,
        ExpectedPredecessorKeyStateRevision,
        ExpectedPredecessorKeyJournalHeadDigest,
        SelectedHelperPendingLifecycleStateTag = GeneratePending
          | InstallPending(RotateInstall),
        SelectedHelperPendingTrustLifecycleStateDigest,
        SelectedHelperPendingCompleteSnapshotDigest,
        SelectedHelperTrustStateRevision,
        SelectedHelperTrustJournalHeadDigest,
        SelectedHelperMonotonicSafetyEnvelopeDigest,
        SelectedReplayIndexRevision,
        SelectedConsentReplayIndexRoot,
        SelectedReplayTimeHighWater,
        BeforeBootstrapResult = ProviderPreDispatchBootstrapResultV1,
        AfterBootstrapResult = ProviderPreDispatchBootstrapResultV1,
        ProviderEvidenceSchemaDigest,
        MatchingProviderOperationCount = 0,
        MatchingKeyObjectCount = 0,
        CompleteNormalizedProviderEvidenceRoot,
        CurrentObservedTime,
        EffectiveObservedAt,
        must_commit_by
      },
      KeyAuthorityAttestationSignature,
      CreateNeverStartedProviderAbsenceProofDigest
    }

The signature covers the NUL-terminated registered never-started domain, the
field tag `"attestation-body\0"`, and the canonical body. The digest covers the
same domain, the distinct field tag `"signed-proof\0"`, and canonical
`{Body, KeyAuthorityAttestationSignature}`. Neither preimage contains the proof
digest, a cancellation receipt, key record/head, any reservation root later
than SelectedProviderOperationReservationRoot, helper successor state, or stable
receipt.

Both bootstrap results repeat the exact same Create query for the named
commitment and ProviderCreateOperationId, report NeverInvoked and
StoredInvocationMarker=None, and carry the same nonempty stable
ProviderPreDispatchObservationToken. The registered provider evidence schema
must independently enumerate zero matching operations and zero matching key
objects with equal before/after no-ABA state and recompute the bounded evidence
root. A label lookup, absent application record, timeout, changed token, unknown
operation history, marker echo, candidate object, multiple result, or incomplete
enumeration is Ambiguous and cannot produce this proof.

The selected helper state and complete pending snapshot must be current and
must carry the exact GenerationCommitted descriptor, consent, phase plan,
recovery disposition, create key step exactly OperationReservationSelected with
the complete byte-identical ProviderReservation evidence, generation commitment,
and selected reservation record. The commitment/proof
SignedProductManifestDigest MUST equal the complete manifest in that phase plan
and the CurrentSignedProductManifestDigest in the selected envelope/state index.
The selected replay revision/root/high-water
must equal its complete current monotonic envelope and replay body.
`EffectiveObservedAt` is exactly
`max(CurrentObservedTime, SelectedReplayTimeHighWater)` under the rollback rule.
MarkerSelectionDeadlineElapsed requires EffectiveObservedAt strictly later than
the commitment's KeyProviderMarkerSelectionDeadline. The safe-compensation
variant requires the selected ResumeOrCompensate entry still authorize only the
exact base and no provider/key/platform side effect to have begun. The exact
create reservation must already be selected in the key authority's complete
current reservation vector; its purpose, operation ID, role, receipt, generation,
provider/profile, deadline, and helper predecessor equal the commitment.
SelectedProviderOperationReservationRevision/Root MUST equal the commitment
wrapper's ResultingProviderOperationReservationRevision/Root and identify the
exact vector prefix ending in that record; the live reservation vector may only
be that prefix or an authenticated append-only descendant.

The key ledger must still have NoRecord for this CaGeneration, and the expected
key revision/head and pre-create generation root must equal the commitment's
unchanged key predecessor. SignedProductManifestDigest and
KeyProviderProfileDigest equal the complete GenerationCommitmentBodyV1. The
verifier resolves the complete signed manifest, selects its unique matching
KeyProviderFreshnessWindowPolicyV1, and requires the repeated
MaximumCreateNeverStartedObservationWindow to equal it byte-for-byte.
`must_commit_by` is exactly the checked, nonwrapping sum of EffectiveObservedAt
and that finite nonzero window. A zero/`UINT64_MAX` window, overflow,
manifest/profile substitution, shorter or longer deadline, or first consumption
after that deadline is invalid. The proof's fresh first-consumption window
satisfies `EffectiveObservedAt < must_commit_by`; it may be later than the create marker
deadline because it authorizes no provider action. Before must_commit_by it may
be consumed exactly once by the direct never-started terminal record and receipt
defined below. Once that record is selected, the reservation and generation are
terminal tombstones: no Creating record, invocation marker, provider bootstrap
for dispatch, or provider call may ever be selected for this operation ID.

Every provider create or destroy dispatch is authorized by one durable marker:

    ProviderCallInvocationMarkerV1 {
      Body = ProviderCallInvocationMarkerBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.ProviderCallInvocationMarker.v1,
        PurposePayload =
            Create {
              GenerationCommitmentDigest,
              ProviderCreateOperationId,
              CreatePreCallProviderAbsenceProofDigest,
              ExpectedPreCreateCompleteKeyGenerationStateRoot
            }
          | Destroy {
              KeyDestroyIntentDigest,
              KeyDestroyOperationId,
              LastReadyRecordDigest,
              ExpectedPreDestroyCompleteKeyGenerationStateRoot,
              DestroyContinuationAuthorityV1,
              DestroyContinuationAuthorityDigest,
              DestroyContinuationSelectionRecordV1,
              DestroyContinuationSelectionRecordDigest,
              ForwardOnlyDestroyAuthorizationV1
            },
        InstallationId,
        CaGeneration,
        CaInstanceId,
        ProviderAndVersion,
        KeyProviderProfileDigest,
        KeyAuthorityEpoch,
        ExpectedPredecessorKeyStateRevision,
        ExpectedPredecessorKeyJournalHeadDigest,
        SelectedHelperTrustJournalHeadDigest,
        ProviderEvidenceSchemaDigest,
        ProviderPreDispatchBootstrapResultV1,
        CurrentObservedTime,
        SelectedReplayIndexRevision,
        SelectedConsentReplayIndexRoot,
        SelectedReplayTimeHighWater,
        EffectiveMarkerCommittedAt,
        MarkerFirstSelectionAuthority =
            CreateMarkerFirstSelection {
              KeyProviderMarkerSelectionDeadline
            }
          | DestroyContinuationSelected {
              DestroyContinuationAuthorityDigest,
              DestroyContinuationSelectionRecordDigest,
              DestroyContinuationSelectionDeadline
            }
      },
      ProviderCallInvocationMarkerDigest
    }

ProviderCallInvocationMarkerDigest is SHA-256 over the registered NUL-terminated
marker domain, the field tag `"invocation-marker\0"`, and the canonical body.
For Create, every commitment/operation/root/key-predecessor field equals
GenerationCommitmentBodyV1 and the complete CreatePreCall proof. The marker's
SelectedHelperTrustJournalHeadDigest equals that proof's selected H1 descendant
which first contains the commitment; it is not rewritten to equal the
commitment's historical LastHelperTrustTip=H0, and the staged H0-to-H1 ancestry
above MUST verify. MarkerFirstSelectionAuthority is CreateMarkerFirstSelection
and its deadline equals
GenerationCommitmentBodyV1.KeyProviderMarkerSelectionDeadline. The selected H1
pending state/snapshot MUST contain the matching GenerateCreate or
RotatePrepareCandidateCreate binding byte-for-byte in its phase plan, recovery
entry, and complete key step before Creating can be selected. That key step is
OperationReservationSelected with the complete matching ProviderReservation
evidence; an omitted provider step is invalid.
For Destroy, every operation/intent/Ready/root/predecessor/helper-tip field,
the complete continuation/selection record, and the complete
ForwardOnlyDestroyAuthorizationV1 equal
KeyDestroyIntentBodyV1 byte-for-byte; SelectedHelperTrustJournalHeadDigest
equals the authorization's SelectedForwardOnlyTrustJournalHeadDigest.
MarkerFirstSelectionAuthority is DestroyContinuationSelected and its three
fields equal the same continuation/selection record. The complete bootstrap query/result is
purpose-compatible and byte-identical to the marker's duplicated fields; its
token and NeverInvoked/None result are the only unbound provider inputs. The
marker contains no containing key
record/digest, provider result or first-invocation time, receipt, resulting key
head/root, or terminal evidence.

Under the global mutation lock, the key authority constructs a marker only
after the registered marker-free bootstrap query returns the complete
NeverInvoked/None result and ProviderPreDispatchObservationToken. The marker's
SelectedReplayIndexRevision, SelectedConsentReplayIndexRoot, and
SelectedReplayTimeHighWater MUST equal byte-for-byte both the current
MonotonicSafetyEnvelopeV1 selected at SelectedHelperTrustJournalHeadDigest and
the complete ConsentReplayIndexBodyV1/root selected by that envelope. The replay
body and root are independently recomputed; a historical, downgraded, or
unrooted high-water is invalid. The key authority computes
EffectiveMarkerCommittedAt as
`max(CurrentObservedTime, SelectedReplayTimeHighWater)` under the manifest clock-
rollback rule. The complete marker is first and permanently selected in exactly
one Creating or DestroyPending record whose committed_at equals that value and
whose predecessor fields equal the marker. Creating additionally requires
committed_at no later than its KeyProviderMarkerSelectionDeadline; a late create
marker grants no dispatch. DestroyPending has no marker-time comparison with
DestroyContinuationSelectionDeadline: instead the complete historical
continuation selection record MUST have EffectiveSelectedAt no later than that
deadline. A destroy marker may first be selected later, including during crash
recovery, but only from that exact continuation and the retained ForwardOnly
descendant. A staged, forked, replayed, cross-purpose, late-create, or
late/missing-continuation marker grants no dispatch. For Destroy,
marker construction additionally resolves the exact selected forward-only
lifecycle state, pending snapshot, disposition selection anchor, and their
authenticated helper ancestry. They MUST pass the common authorization rules
above at SelectedHelperTrustJournalHeadDigest; a digest-only reference that
cannot resolve those complete objects fails closed.

After the marker-bearing key record is selected, every provider invocation and
post-selection query MUST accept and echo the complete marker; the marker-free
bootstrap form is no longer accepted for that operation. The registered provider
primitive is atomic `invoke-if-never-invoked` over the
installation-lifetime unique operation ID and exact
ProviderCallInvocationMarkerDigest. Every invocation/query accepts and echoes
the complete marker and digest; first dispatch atomically stores them with the
operation, and every in-flight/terminal query MUST echo those stored bytes. A
NeverInvoked query echoes the requested marker but grants no authority by
itself; the selected current key record does. Before provider binding, any marker
different from that selected record is rejected locally as
ProviderInvocationMarkerMismatch even if a NeverInvoked provider query echoes
it. After provider binding, the same operation ID with different marker bytes is
also provider integrity failure. On recovery, an exact current Creating record
plus an exact provider NeverInvoked result permits its one first create
dispatch. An exact current DestroyPending record permits its one first destroy
dispatch only after the complete inline continuation/selection record, intent,
marker, and ForwardOnlyDestroyAuthorizationV1 verify with the same preallocated
KeyDestroyOperationId, and the currently selected helper
state is either the exact bound forward-only state or an authenticated
pending-state descendant retaining the same operation, phase/consent/plan,
deadline binding, ForwardOnly outcome, and remaining destroy path byte-for-byte.
RecoveryRequired(Some pending snapshot) may also qualify only when its retained
snapshot is that exact bound snapshot or an authenticated retaining successor
and all the same fields and selection-anchor ancestry independently verify. A
missing, reverted, changed, broadened, forked, or ResumeOrCompensate helper
state forbids dispatch even when the provider reports NeverInvoked. With those
conditions, the same operation ID and marker may be used even after
DestroyContinuationSelectionDeadline. An in-flight or terminal
result permits query/reconciliation only. An unknown, multiple, mutable, or
marker-mismatched result is Ambiguous: recovery neither dispatches a second
operation nor chooses a new ID. ProviderOperationFirstInvokedAt is corroborating
provider audit metadata only and can never prove that selection or dispatch was
timely.

Failure to produce a CA-key signature after the call is represented only by
this closed destroy-purpose result:

    NegativeKeyPossessionResultV1 {
      Body = NegativeKeyPossessionResultBodyV1 {
        SchemaVersion = 1,
        SignatureDomain = FlowProbe.TrustCa.NegativeKeyPossessionResult.v1,
        Purpose = DestroyPostCallNegativePossession,
        InstallationId,
        CaGeneration,
        CaInstanceId,
        ProviderAndVersion,
        KeyProviderProfileDigest,
        SignedProductManifestDigest,
        MaximumDestroyPostCallObservationWindow,
        KeyAuthorityEpoch,
        LastCaPublicIdentityDigest,
        CertificateSpkiSha256,
        DestroyPendingRecordDigest,
        DestroyPendingKeyStateRevision,
        DestroyPendingKeyJournalHeadDigest,
        KeyDestroyOperationId,
        KeyDestroyIntentDigest,
        ProviderCallInvocationMarkerDigest,
        ProviderEchoedInvocationMarkerDigest,
        KeyDestructionChallengeDigest,
        ProviderOperationFirstInvokedAt,
        ProviderOperationTerminalStatus = DestroyApplied,
        PossessionCheckResult = DefinitiveKeyObjectAbsentNoSignatureProduced,
        observed_at,
        must_commit_by
      },
      KeyAuthorityAttestationSignature,
      NegativeKeyPossessionResultDigest
    }

The typed possession check accepts only the provider's registered definitive
key-absent outcome for the exact destroyed object and challenge. Timeout,
service loss, permission failure, malformed output, an invalid signature, or a
different object is Ambiguous rather than negative possession. The attestation
signature covers only the registered domain, field tag
`"attestation-body\0"`, and canonical body;
NegativeKeyPossessionResultDigest covers the same domain, the distinct field tag
`"signed-result\0"`, and canonical
`{Body, KeyAuthorityAttestationSignature}`. The result
contains no ProviderAbsenceProof, key receipt, Destroyed record, resulting key
head/projection, or its own digest, so it can precede the provider-absence proof
without a cycle.
Its SignedProductManifestDigest and KeyProviderProfileDigest equal the complete
KeyDestroyIntentBodyV1 and selected pending phase plan/envelope. The verifier
selects the unique matching KeyProviderFreshnessWindowPolicyV1, requires
MaximumDestroyPostCallObservationWindow byte-for-byte, and recomputes
must_commit_by as the checked nonwrapping sum of observed_at and that window.
Zero, `UINT64_MAX`, overflow, substitution, or a shorter/longer deadline is
invalid.

Provider absence is never an untyped lookup digest. Each proof is this closed
purpose-specific object:

    ProviderAbsenceProofV1 {
      Body = ProviderAbsenceProofBodyV1 {
        SchemaVersion = 1,
        SignatureDomain =
            FlowProbe.TrustCa.ProviderCreatePreCallAbsence.v1
          | FlowProbe.TrustCa.ProviderCreatePostCallAbsence.v1
          | FlowProbe.TrustCa.ProviderDestroyPostCallAbsence.v1,
          PurposePayload =
            CreatePreCall {
              GenerationCommitmentDigest,
              ProviderCreateOperationId,
              SignedProductManifestDigest,
              KeyProviderMarkerSelectionDeadline,
              Result = DefinitiveNoPriorOperationAndNoMatchingKey
            }
          | CreatePostCall {
              GenerationCommitmentDigest,
              ProviderCreateOperationId,
              SignedProductManifestDigest,
              MaximumCreatePostCallObservationWindow,
              CreatingRecordDigest,
              CreatingKeyStateRevision,
              CreatingKeyJournalHeadDigest,
              ProviderCallInvocationMarkerV1,
              ProviderCallInvocationMarkerDigest,
              ProviderEchoedInvocationMarkerDigest,
              ProviderOperationFirstInvokedAt,
              ProviderOperationTerminalStatus = NoObjectCreated,
              Result = DefinitiveCreateUnapplied
            }
          | DestroyPostCall {
              TrustOperationId,
              ConsentReceiptDigest,
              SignedProductManifestDigest,
              MaximumDestroyPostCallObservationWindow,
              LastReadyRecordDigest,
              DestroyPendingRecordDigest,
              DestroyPendingKeyStateRevision,
              DestroyPendingKeyJournalHeadDigest,
              KeyDestroyOperationId,
              KeyDestroyIntentDigest,
              ProviderCallInvocationMarkerV1,
              ProviderCallInvocationMarkerDigest,
              ProviderEchoedInvocationMarkerDigest,
              LastCaPublicIdentityDigest,
              KeyDestructionChallengeDigest,
              ProviderOperationFirstInvokedAt,
              NegativeKeyPossessionResultV1,
              NegativeKeyPossessionResultDigest,
              ProviderOperationTerminalStatus = DestroyApplied,
              Result = DefinitiveDestroyAppliedAndKeyAbsent
            },
        InstallationId,
        CaGeneration,
        CaInstanceId,
        ProviderAndVersion,
        KeyProviderProfileDigest,
        KeyAuthorityEpoch,
        ExpectedKeyStateRevision,
        ExpectedKeyJournalHeadDigest,
        SelectedHelperTrustJournalHeadDigest,
        ProviderAbsenceChallenge,
        ProviderEvidenceSchemaDigest,
        BeforeProviderObservationToken,
        AfterProviderObservationToken,
        MatchingProviderOperationCount,
        MatchingKeyObjectCount = 0,
        CompleteNormalizedProviderEvidenceRoot,
        observed_at,
        must_commit_by
      },
      KeyAuthorityAttestationSignature,
      ProviderAbsenceProofDigest
    }

CreatePreCallProviderAbsenceProofV1, CreatePostCallProviderAbsenceProofV1, and
DestroyPostCallProviderAbsenceProofV1 are the three domain/purpose-constrained
instances. The pre-call instance requires MatchingProviderOperationCount=0;
the post-create and post-destroy instances require exactly one terminal result
for their bound operation. DestroyPostCall carries the complete
NegativeKeyPossessionResultV1 and its recomputed digest; every duplicated
operation, intent, invocation marker/echo, identity, challenge, DestroyPending
revision/head, time, and deadline field is byte-identical. The complete marker
recomputes to its digest, has the required purpose, and is byte-identical to the
one in the selected Creating/DestroyPending ancestor. The attestation signature covers only its own
purpose domain, field tag `"attestation-body\0"`, and canonical body.
ProviderAbsenceProofDigest covers that same purpose domain, the distinct field
tag `"signed-proof\0"`, and canonical
`{Body, KeyAuthorityAttestationSignature}`;
the digest is absent from both preimages. The complete proof is retained inline
in every record/receipt that consumes it.

The ExpectedKeyStateRevision/ExpectedKeyJournalHeadDigest mapping is exact and
purpose-specific: CreatePreCall names the selected predecessor immediately
before Creating and equals the expected key fields in
GenerationCommitmentBodyV1;
CreatePostCall names the selected Creating revision/head carried in its payload;
DestroyPostCall names the selected DestroyPending revision/head carried in its
payload. A proof with another current or historical head is invalid even when
all provider evidence is otherwise identical.

`must_commit_by` is a first-consumption deadline, not a lifetime for historical
ancestry. `observed_at < must_commit_by`; before the deadline the complete proof
must be selected into exactly one allowed consuming CaKeyRecordV1 whose
committed_at is in that interval and whose predecessor is the purpose-specific
head above. CreatePreCall is consumed by Creating, CreatePostCall by
CreateUnapplied, and DestroyPostCall by Destroyed. Once timely selected, the
complete proof remains permanently valid only as that immutable record's
historical ancestor. A proof first presented after its deadline, or replayed
into another record/generation/operation, is invalid and requires a new
same-purpose observation where the state still permits one.
CreatePreCall repeats the GenerationCommitmentBodyV1
SignedProductManifestDigest and KeyProviderMarkerSelectionDeadline and has
`must_commit_by` exactly equal to that deadline because the proof is consumed in
the same Creating record as the invocation marker. CreatePostCall repeats the
same manifest digest and the matching profile policy's
MaximumCreatePostCallObservationWindow; its must_commit_by is exactly the checked
nonwrapping sum of observed_at and that window. DestroyPostCall repeats the
SignedProductManifestDigest from KeyDestroyIntentBodyV1 and the matching policy's
MaximumDestroyPostCallObservationWindow; its must_commit_by is exactly the same
checked sum using that window. Both post-call deadlines MAY be later than the
create marker deadline or destroy continuation deadline because selecting a
terminal observation performs no provider mutation. Zero, `UINT64_MAX`,
overflow, manifest/profile/window mismatch, or a shorter or longer deadline is
invalid. They are valid only when their complete
ProviderCallInvocationMarkerV1 is byte-identical to the timely create marker or
continuation-authorized destroy marker in the exact Creating/DestroyPending
ancestor and the provider echo equals its digest.
ProviderOperationFirstInvokedAt is retained as immutable audit metadata but is
not compared to GenerationCommitmentBodyV1.KeyProviderMarkerSelectionDeadline or
DestroyContinuationSelectionDeadline and cannot authorize a call. Such a later
proof MUST NOT issue another provider operation. The contained
NegativeKeyPossessionResultV1 has the same manifest/profile/window,
marker/echo, ProviderOperationFirstInvokedAt, observed_at, and must_commit_by as
its enclosing DestroyPostCall proof. A missing/mismatched durable marker, a second operation,
or a proof first consumed after its own must_commit_by is invalid.

BeforeProviderObservationToken and AfterProviderObservationToken MUST be equal
under the registered provider profile's monotonic/no-ABA rule. The signed
provider profile fixes a bounded complete ProviderEvidenceSchemaDigest that can
distinguish NeverInvoked, definitive NoObjectCreated, and DestroyApplied for the
exact durable operation identity and marker and can return the immutable marker
and first-invocation time after a crash. Missing history, missing or mutable
marker, missing or mutable first-invocation time,
unknown terminal status,
incomplete enumeration, multiple candidates, token change, timeout, label-only
lookup, or an unregistered profile/evidence schema is Ambiguous and cannot
produce a proof. Pre-call proof cannot reference Creating; post-create proof
must reference the exact selected Creating ancestor and cannot reference
CreateUnapplied; post-destroy proof must reference the exact selected
DestroyPending ancestor and cannot reference KeyDestroyedReceipt/Destroyed.
Domain, purpose, operation, generation, provider/profile, key head, helper tip,
challenge, token, time, or signer substitution is invalid. The proof carries no
raw provider handle, NonExportableKeyIdentity, PIN, private material, or
arbitrary provider bytes. Only the key-authority attestation identity may sign
these three typed domains; neither the CA key nor helper may sign them.

The CA key authority separately owns a protected copy-on-write key index.
CaKeyRecordV1 has an explicit digest-free body and closed state payload:

    CaKeyRecordV1 {
      Body = CaKeyRecordBodyV1 {
        SchemaVersion = 1,
        InstallationId,
        CaGeneration,
        CaInstanceId,
        ProviderAndVersion,
        KeyAuthorityEpoch,
        KeyStateRevision,
        ExpectedPredecessorKeyStateRevision,
        ExpectedPredecessorKeyJournalHeadDigest,
        LastHelperTrustTipBoundByReceipt,
        committed_at,
        StatePayload =
          Creating {
            GenerationCommitmentBodyV1,
            GenerationCommitmentDigest,
            ProviderCreateOperationId,
            CreatePreCallProviderAbsenceProofV1,
            CreatePreCallProviderAbsenceProofDigest,
            ProviderCallInvocationMarkerV1,
            ProviderCallInvocationMarkerDigest,
            CreateIntentDisposition = IntentDurable
          }
        | Ready {
            GenerationCommitmentDigest,
            ProviderCreateOperationId,
            CreatingRecordDigest,
            CaPublicIdentityV1,
            BoundedPublicCertificateDer,
            CertificateDerSha256,
            CertificateSpkiSha256,
            NonExportableKeyIdentity,
            NonExportableKeyIdentityDigest,
            ProviderObjectNonAliasingTagDigest,
            ProviderSecretNonAliasingTagDigest,
            ProviderKeyUniquenessEvidenceV1,
            ProviderKeyUniquenessEvidenceDigest,
            ProviderCallInvocationMarkerDigest,
            KeyCreatedReceiptV1,
            KeyCreatedReceiptDigest
          }
        | CreateUnapplied {
            GenerationCommitmentBodyV1,
            GenerationCommitmentDigest,
            ProviderCreateOperationId,
            CreatingRecordDigest,
            ProviderCallInvocationMarkerDigest,
            CreatePreCallProviderAbsenceProofV1,
            CreatePreCallProviderAbsenceProofDigest,
            CreatePostCallProviderAbsenceProofV1,
            CreatePostCallProviderAbsenceProofDigest,
            KeyCreateUnappliedReceiptV1,
            KeyCreateUnappliedReceiptDigest
          }
        | CreateUnappliedNeverStarted {
            GenerationCommitmentBodyV1,
            GenerationCommitmentDigest,
            ProviderCreateOperationId,
            ProviderOperationReservationRecordV1,
            ProviderOperationReservationRecordDigest,
            SelectedProviderOperationReservationRevision,
            SelectedProviderOperationReservationRoot,
            CreateNeverStartedProviderAbsenceProofV1,
            CreateNeverStartedProviderAbsenceProofDigest,
            KeyCreateNeverStartedReceiptV1,
            KeyCreateNeverStartedReceiptDigest
          }
        | DestroyPending {
            TrustOperationId,
            ConsentReceiptDigest,
            LastReadyRecordDigest,
            CaPublicIdentityV1,
            BoundedPublicCertificateDer,
            CertificateDerSha256,
            CertificateSpkiSha256,
            NonExportableKeyIdentity,
            NonExportableKeyIdentityDigest,
            ProviderObjectNonAliasingTagDigest,
            ProviderSecretNonAliasingTagDigest,
            KeyDestroyOperationId,
            KeyDestroyIntentBodyV1,
            KeyDestroyIntentDigest,
            DestroyContinuationAuthorityV1,
            DestroyContinuationAuthorityDigest,
            DestroyContinuationSelectionRecordV1,
            DestroyContinuationSelectionRecordDigest,
            ForwardOnlyDestroyAuthorizationV1,
            ProviderCallInvocationMarkerV1,
            ProviderCallInvocationMarkerDigest
          }
        | Destroyed {
            LastCaPublicIdentity: CaPublicIdentityV1,
            CertificateSpkiSha256,
            NonExportableKeyIdentityDigest,
            ProviderObjectNonAliasingTagDigest,
            ProviderSecretNonAliasingTagDigest,
            LastReadyRecordDigest,
            DestroyPendingRecordDigest,
            ProviderCallInvocationMarkerDigest,
            KeyDestroyedReceiptV1,
            KeyDestroyedReceiptDigest
          }
        | Ambiguous {
            Origin =
              CreateAmbiguous {
                GenerationCommitmentBodyV1,
                GenerationCommitmentDigest,
                ProviderCreateOperationId,
                CreatingRecordDigest,
                ProviderCallInvocationMarkerV1,
                ProviderCallInvocationMarkerDigest,
                OptionalExactIdentityAndPublicDer,
                BoundedProviderCandidateSetDigest,
                OptionalProviderKeyUniquenessEvidenceV1,
                OptionalProviderKeyUniquenessEvidenceDigest,
                AmbiguityKind = CreateOutcome | KeyUniquenessCollision
                  | KeyUniquenessEvidenceUnavailable,
                DestroyForbiddenWhenAliasingUnresolved
              }
            | DestroyAmbiguous {
                TrustOperationId,
                ConsentReceiptDigest,
                LastReadyRecordDigest,
                DestroyPendingRecordDigest,
                KeyDestroyOperationId,
                KeyDestroyIntentDigest,
                ProviderCallInvocationMarkerV1,
                ProviderCallInvocationMarkerDigest,
                OptionalDestroyPostCallProviderAbsenceProofV1,
                OptionalDestroyPostCallProviderAbsenceProofDigest
              },
            BoundedReasonVector
          }
      },
      RecordDigest
    }

RecordDigest is SHA-256 over the registered key-record domain and the canonical
CaKeyRecordBodyV1 only; RecordDigest is never in its own preimage. The common
installation/generation/instance/provider fields MUST equal the referenced
GenerationCommitmentBodyV1 and every ancestor record. Unknown body fields or a
duplicate field mismatch fail closed.

For DestroyPending, the complete inline continuation/selection record and
ForwardOnlyDestroyAuthorizationV1 MUST equal the objects in
KeyDestroyIntentBodyV1 and the Destroy marker byte-for-byte. The preallocated
KeyDestroyOperationId and continuation target commitment MUST equal the record,
intent, and selected Ready target.
The marker's selected helper head and deadline MUST equal that object, and all
common operation/phase/consent/generation fields MUST equal the record and the
intent. Record selection resolves and verifies the exact helper state/snapshot
and selection-anchor ancestry before this record can become current; the key
ledger cannot treat the intent digest alone as proof of ForwardOnly authority.

KeyStateRevision is exactly ExpectedPredecessorKeyStateRevision plus one, with
nonwrapping arithmetic. ExpectedPredecessorKeyJournalHeadDigest is the selected
head before this record; the resulting head is derived by the registered
key-journal-head formula above and is not in the record body. `committed_at` is
the canonical first-selected record time computed under the same
`max(CurrentObservedTime, ReplayTimeHighWater)` and clock-rollback rule as the
helper, resolved through LastHelperTrustTipBoundByReceipt. It never decreases
along the key record chain. A receipt/proof embedded in the record must name the
same helper tip and committed_at where defined.

Creating and DestroyPending are the only dispatch-authorizing variants. Each
contains one complete ProviderCallInvocationMarkerV1 and digest; committed_at
equals its EffectiveMarkerCommittedAt, the marker predecessor equals the record
predecessor, and the marker's SelectedHelperTrustJournalHeadDigest equals
LastHelperTrustTipBoundByReceipt. Ready, post-dispatch CreateUnapplied,
Destroyed, and either Ambiguous origin retain the same marker digest (and the
complete marker wherever shown) byte-for-byte. CreateUnappliedNeverStarted
contains and permits no marker. No terminal or ambiguity refinement can select a
new marker or provider operation identity.

The predecessor mapping is closed. Creating equals the CreatePreCall proof,
ProviderCallInvocationMarkerV1, and GenerationCommitment expected predecessor.
Ready and CreateUnapplied equal the selected Creating revision/head and marker.
CreateUnappliedNeverStarted instead appends directly from the exact NoRecord
pre-create key revision/head/root in GenerationCommitmentBodyV1. Its complete
reservation is already selected, its never-started proof and receipt are first
consumed in that one record, and its helper pending snapshot still has
GenerationCommitted with the create key step OperationReservationSelected and
the complete matching ProviderReservation evidence.
DestroyPending equals the current global revision/head, marker, and complete
generation-state root named by KeyDestroyIntentBodyV1; its LastReadyRecordDigest identifies the target
generation's still-current Ready entry and MAY be historical in the global
record chain when another rotation generation was appended later. Destroyed
equals the selected DestroyPending
revision/head. CreateAmbiguous uses Creating as predecessor; DestroyAmbiguous
uses DestroyPending. A later exact ambiguity refinement uses the selected
Ambiguous record as predecessor while retaining and proving the original
Creating or DestroyPending ancestry. No variant may name its own resulting
record/head or skip an intervening key record.

The key-authority receipts use explicit signature-free bodies:

    KeyCreatedReceiptBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.KeyCreatedReceipt.v1,
      TrustOperationId,
      ConsentReceiptDigest,
      InstallationId,
      CaGeneration,
      CaInstanceId,
      ProviderAndVersion,
      GenerationCommitmentDigest,
      ProviderCreateOperationId,
      ProviderCallInvocationMarkerV1,
      ProviderCallInvocationMarkerDigest,
      CreatingRecordDigest,
      CaPublicIdentityV1,
      NonExportableKeyIdentityDigest,
      ProviderObjectNonAliasingTagDigest,
      ProviderSecretNonAliasingTagDigest,
      PreCreateCompleteKeyGenerationStateRoot,
      ProviderKeyUniquenessEvidenceV1,
      ProviderKeyUniquenessEvidenceDigest,
      KeyCreationPossessionProofV1,
      KeyCreationPossessionProofDigest,
      LastHelperTrustTip,
      IntendedKeyState = Ready,
      IntendedKeyStateRevision,
      committed_at
    }

    KeyCreateUnappliedReceiptBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.KeyCreateUnappliedReceipt.v1,
      TrustOperationId,
      ConsentReceiptDigest,
      InstallationId,
      CaGeneration,
      CaInstanceId,
      ProviderAndVersion,
      GenerationCommitmentDigest,
      ProviderCreateOperationId,
      ProviderCallInvocationMarkerV1,
      ProviderCallInvocationMarkerDigest,
      CreatingRecordDigest,
      CreatePreCallProviderAbsenceProofV1,
      CreatePreCallProviderAbsenceProofDigest,
      CreatePostCallProviderAbsenceProofV1,
      CreatePostCallProviderAbsenceProofDigest,
      LastHelperTrustTip,
      IntendedKeyState = CreateUnapplied,
      IntendedKeyStateRevision,
      committed_at
    }

    KeyCreateNeverStartedReceiptBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.KeyCreateNeverStartedReceipt.v1,
      TrustOperationId,
      ConsentReceiptDigest,
      InstallationId,
      CaGeneration,
      CaInstanceId,
      ProviderAndVersion,
      GenerationCommitmentBodyV1,
      GenerationCommitmentDigest,
      ProviderCreateOperationId,
      ProviderOperationReservationRecordV1,
      ProviderOperationReservationRecordDigest,
      SelectedProviderOperationReservationRevision,
      SelectedProviderOperationReservationRoot,
      ExpectedPreCreateCompleteKeyGenerationStateRoot,
      SelectedHelperPendingTrustLifecycleStateDigest,
      SelectedHelperPendingCompleteSnapshotDigest,
      SelectedHelperTrustJournalHeadDigest,
      CreateNeverStartedProviderAbsenceProofV1,
      CreateNeverStartedProviderAbsenceProofDigest,
      IntendedKeyState = CreateUnappliedNeverStarted,
      IntendedKeyStateRevision,
      committed_at
    }

    KeyDestroyedReceiptBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.KeyDestroyedReceipt.v1,
      TrustOperationId,
      ConsentReceiptDigest,
      InstallationId,
      CaGeneration,
      CaInstanceId,
      ProviderAndVersion,
      LastCaPublicIdentity: CaPublicIdentityV1,
      NonExportableKeyIdentityDigest,
      ProviderObjectNonAliasingTagDigest,
      ProviderSecretNonAliasingTagDigest,
      LastReadyRecordDigest,
      DestroyPendingRecordDigest,
      KeyDestroyOperationId,
      KeyDestroyIntentDigest,
      ProviderCallInvocationMarkerV1,
      ProviderCallInvocationMarkerDigest,
      ExpectedPreDestroyCompleteKeyGenerationStateRoot,
      DestroyPostCallProviderAbsenceProofV1,
      DestroyPostCallProviderAbsenceProofDigest,
      NegativeKeyPossessionResultDigest,
      LastHelperTrustTip,
      IntendedKeyState = Destroyed,
      IntendedKeyStateRevision,
      committed_at
    }

KeyCreatedReceiptV1, KeyCreateUnappliedReceiptV1,
KeyCreateNeverStartedReceiptV1, and KeyDestroyedReceiptV1 are respectively
`{Body, KeyAuthorityAttestationSignature}` with the body/domain fixed above.
The attestation signature covers only the registered receipt domain, field tag
`"attestation-body\0"`, and canonical body. The receipt digest is SHA-256 over
that domain, the distinct field tag `"signed-receipt\0"`, and the canonical
complete receipt;
neither signature nor digest appears in its own signing/hash preimage. The
intended revision and committed_at are chosen before signing and equal the
containing record. No body contains the resulting record digest or resulting
key-journal head. KeyCreatedReceiptV1 carries the complete
KeyCreationPossessionProofV1 and ProviderKeyUniquenessEvidenceV1; both digests
are independently recomputed and every generation/commitment/provider/SPKI/
pre-create-root/manifest/profile/window/deadline field is byte-identical. Each marker-bearing receipt's complete
invocation marker recomputes to its digest and is byte-identical to its Creating
or DestroyPending ancestor and every contained post-call proof/evidence.
KeyCreateNeverStartedReceiptV1 is the sole marker-free key receipt; its complete
reservation and never-started proof recompute to their digests and equal its
direct-predecessor commitment, selected reservation state, and helper pending
snapshot byte-for-byte. The
creation proof binds only the exact Creating head/revision, invocation-marker
digest, and uniqueness evidence; the uniqueness evidence binds only the
pre-create root/marker and neither refers to the receipt or Ready. The post-
create/post-destroy proofs bind only Creating/DestroyPending respectively. Thus
Ready, post-dispatch CreateUnapplied, CreateUnappliedNeverStarted, and Destroyed
can embed their receipt without a direct or indirect digest cycle.
The three internal identity/non-alias tag digests in KeyDestroyedReceiptV1 and
the Destroyed record MUST equal the unique historical Ready record and the
complete KeyDestroyIntentBodyV1 retained through its DestroyPending ancestor;
ExpectedPreDestroyCompleteKeyGenerationStateRoot is also byte-identical in the
intent and receipt. The receipt cannot relabel a destroyed object, substitute a
different global predecessor/root, or discard the comparison set.

Every key receipt enforces first-consumption time. KeyCreatedReceipt.committed_at
is within both the creation-possession and provider-uniqueness
`[observed_at, must_commit_by]` intervals after both deadlines and their signed-
manifest/profile windows are independently recomputed. KeyCreateUnappliedReceipt.committed_at
is within the post-create provider proof interval and its retained pre-call
proof was already timely consumed by Creating. KeyDestroyedReceipt.committed_at
is within both DestroyPostCallProviderAbsenceProofV1 and its contained
NegativeKeyPossessionResultV1 intervals. Deadline equality at
`must_commit_by` is allowed; a later time is invalid. After the containing
record is selected, those deadlines are historical selection evidence only.
KeyCreateNeverStartedReceipt.committed_at is within its complete never-started
proof interval after its manifest/profile window and exact checked-add deadline
are recomputed, equals the direct terminal record, and is valid only while the
named generation still has NoRecord and the reservation remains current or an
exact retained ancestor of the complete reservation vector.

The key digest DAG is normative. Creation order is pre-create generation-state
root -> GenerationCommitment -> CreatePreCall proof -> invocation marker ->
Creating record/head -> ProviderKeyUniquenessEvidence ->
KeyCreationPossessionProof -> KeyCreatedReceipt -> Ready record/head -> successor
generation-state root/projection. Destruction order is pre-destroy generation-
state root -> KeyDestroyIntent -> invocation marker -> DestroyPending record/head ->
NegativeKeyPossessionResult -> DestroyPostCallProviderAbsenceProof ->
KeyDestroyedReceipt -> Destroyed record/head -> DestroyedTerminalKeyEvidence ->
successor generation-state root/projection. An object may reference only an
earlier node in its order; current projection, resulting record/head, receipt,
or terminal evidence substitution into an earlier preimage is integrity
failure.
The disjoint no-dispatch creation branch is prior reservation root -> proposed
create reservation -> GenerationCommitment -> selected helper pending snapshot
-> selected reservation vector -> two equal NeverInvoked/None bootstrap results
-> CreateNeverStartedProviderAbsenceProof -> KeyCreateNeverStartedReceipt ->
CreateUnappliedNeverStarted record/head -> successor generation-state root/
projection -> exact-base helper successor. No object in that branch contains a
later receipt, record/head, projection, or helper successor digest.
For rotation, candidate Ready -> RotationDualReady projection ->
RotationReadyKeyProjectionAttestation ->
RotationReadyProjectionSelectionRecord -> pending descriptor refinement ->
CandidateKeyBinding -> phase graph is the additional forward-only suffix; none
of those objects is referenced by the receipt, Ready record, attestation body,
or selection predecessor that precedes it.

Creating contains no certificate DER, SPKI digest, or
NonExportableKeyIdentity because none exists before the provider side effect.
The key authority MUST fsync Creating/CreateIntentDisposition with the complete
timely invocation marker before invoking the provider. It then makes the one
provider call identified by the same ProviderCreateOperationId and marker only
when the provider reports NeverInvoked; otherwise it queries/reconciles without
dispatch. Ready is an authenticated append-only refinement of
that exact Creating record; it is written only after the key authority has
built and parsed the bounded certificate, proved that its SPKI is the created
key, verified every certificate-profile field, and produced complete
ProviderKeyUniquenessEvidenceV1 against the commitment's exact pre-create root.
The Ready record's complete
public DER hashes to CertificateDerSha256 and its canonical SPKI hashes to
CertificateSpkiSha256. Its three internal identity/tag digests and complete
uniqueness evidence equal KeyCreatedReceiptV1 byte-for-byte. A different
commitment, provider operation identity, public identity, pre-create root, or
provider object/secret cannot replace or refine the record.

The only creation transitions are either `NoRecord -> Creating -> Ready |
CreateUnapplied | Ambiguous` or the disjoint
`NoRecord -> CreateUnappliedNeverStarted` terminal path. An Ambiguous record may
refine to Ready or post-dispatch CreateUnapplied only when later exact same-operation evidence definitively
settles the zero-or-one provider result under the retained pending recovery;
otherwise it remains Ambiguous. CreateUnapplied is a terminal
non-signing tombstone for a provider operation that fresh post-call evidence
proves created no key. It retains the full commitment, invocation marker, and
both absence proofs;
it is not Destroyed because no Ready key ever existed. The helper may compensate
GeneratePending back to Absent, or RotateInstall back to its exact old
InstalledAndVerified base, only after both ledgers cross-bind that
CreateUnapplied record and independently prove there is no provider result.
Ambiguous creation is RecoveryRequired and never becomes either CreateUnapplied
variant from
timeout, label search, or incomplete enumeration.

CreateUnappliedNeverStarted is a terminal non-signing tombstone for a provider
operation that was reserved but never acquired a marker or provider-side
operation. It retains the full generation commitment, complete selected
reservation, signed never-started proof, and key-attestation-signed receipt. Its
direct NoRecord predecessor, two equal NeverInvoked/None bootstrap observations,
zero operation/key counts, helper pending snapshot, replay authority, and fresh
proof deadline all verify byte-for-byte. It is not reachable from Creating or
Ambiguous and cannot later refine. The helper may compensate GeneratePending to
Absent or RotateInstall to its exact old InstalledAndVerified base after both
ledgers cross-bind either this terminal record or the post-dispatch
CreateUnapplied record, according to which mutually exclusive branch occurred.

A CreateAmbiguous record whose ambiguity kind is KeyUniquenessCollision or
KeyUniquenessEvidenceUnavailable cannot refine to Ready or be auto-cleaned by
destroy. It retains every bounded candidate identity and internal tag digest,
sets DestroyForbiddenWhenAliasingUnresolved=true, and remains RecoveryRequired
until provider-native evidence proves exact object/secret non-aliasing. If the
candidate aliases any current or historical object/secret/SPKI, the colliding
generation is permanently rejected and the already-authoritative generation is
never passed to a destroy operation on the candidate's behalf.

Every post-dispatch creation refinement carries the exact CreatingRecordDigest, and
CreateUnapplied.CreatePreCallProviderAbsenceProofV1 and digest MUST be
byte-identical to the complete proof in Creating. Its post-call proof must have
the CreatePostCall domain/purpose and bind that exact Creating ancestor,
generation commitment, ProviderCreateOperationId, and invocation marker. The
never-started terminal route instead carries no CreatingRecordDigest or marker
and validates only through its direct predecessor, selected reservation, proof,
receipt, and helper GenerationCommitted snapshot.
DestroyPending similarly binds the exact target LastReadyRecordDigest, current global predecessor, and
ExpectedPreDestroyCompleteKeyGenerationStateRoot. Destroyed and DestroyAmbiguous bind the
exact DestroyPendingRecordDigest, KeyDestroyOperationId, KeyDestroyIntentDigest,
and invocation marker;
KeyDestroyedReceiptBodyV1 additionally binds the helper consent/tip and complete
timely selected DestroyPostCallProviderAbsenceProofV1 plus its complete negative
possession result. The authenticated journal ancestry
and these links
prevent a terminal payload from being transplanted across commitments,
provider operations, or destroy attempts.

NonExportableKeyIdentity is private to the key authority and MUST NOT appear in
helper, Supervisor, renderer, Capture Core, egress, status, or diagnostic
messages. Cross-store atomicity is not assumed, so evidence requirements are
state-specific. Generated and InstalledAndVerified stable receipts, and every
interception admission, require a helper-signed public trust proof plus a
CA-key-signed possession proof bound to the same live identity, challenge,
revision, and gate epoch. Drifted uses its closed key-ledger projection with the
gate closed. Absent uses the attestation-signed NoLiveOrAmbiguous projection and
MUST NOT carry a CA-key possession proof.

Journal-before-mutation is mandatory for key and trust operations. Before each
external side effect the owning ledger fsyncs one state-appropriate intent:

- exact operation, generation, target/plan where applicable, fence, revision,
  idempotency identities, and either the known CA identity or the one exact
  pre-identity generation commitment;
- consent receipt and authorization scope;
- normalized current before image, or for pre-identity key creation the complete
  CreatePreCallProviderAbsenceProofV1 bound alongside
  GenerationCommitmentBodyV1 and ProviderCallInvocationMarkerV1 by the complete
  Creating RecordDigest;
- for every trust mutation and every Ready/DestroyPending key operation, the
  exact immutable public certificate identity and bounded public DER; for the
  one pre-identity key-creation operation, the exact GenerationCommitmentBodyV1,
  GenerationCommitmentDigest, ProviderCreateOperationId, and the complete
  invocation marker instead;
- intended postcondition, mutation direction, deadline, and compensation;
- the expected platform conditional token or explicit
  NoConditionalRevision; and
- IntentDurable.

The pre-identity exception applies only to one exclusive key-creation call. It
does not relax identity requirements for trust mutation, signing, destruction,
or stable state. A key provider is UnsupportedPendingArchitecture unless its
documented primitive makes ProviderCreateOperationId plus the exact invocation
marker durable or otherwise
allows the key authority to prove zero-or-one creation and recover the exact
single result without label guessing or a second create; makes
KeyDestroyOperationId plus the exact destroy invocation marker durable,
idempotent, and
terminally queryable; and supplies complete stable object/secret non-aliasing
tags for the installation-lifetime uniqueness check. Missing any one primitive
is not papered over by labels, certificate DER, a second provider call, or an
application-maintained boolean.

The executor performs one registered typed operation, independently reads back
the exact target, then fsyncs the normalized result and AppliedDurable,
UnappliedDurable, CompensatedDurable, ObservedDurable, or AmbiguousDurable
before returning success. A return code, process exit, helper response without the durable
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
- every key-creation record is terminal post-dispatch CreateUnapplied or
  CreateUnappliedNeverStarted, or, if it reached Ready, its key is Destroyed;
- the complete KeyLedgerRecordLinkVector, per-generation state vector, every
  timely consumed key/provider proof and receipt, internal uniqueness-tag
  digest, and DestroyedTerminalKeyEvidence suffix needed to recompute the
  current projection remain retained, together with the canonical
  KeyJournalHeadV1 Genesis preimage and every derivable Append body/wrapper;
  an opaque ancestry/root without the
  canonical preimages is insufficient;
- the complete ProviderOperationReservationStateV1 vector, every reservation
  record preimage, predecessor/resulting root edge, and every used, cancelled,
  ambiguous, or unused create/destroy operation ID remain retained, including
  an unused RotatePrepare candidate-cleanup reservation; an accumulator or
  tombstone that cannot reproduce the exact canonical vector is insufficient;
- the complete ConsentBrokerKeysetSelectionStateV1 vector, every full signed
  product-manifest/keyset preimage and predecessor/resulting root edge, and each
  consumed receipt's complete ConsentReceiptVerificationResultV1 remain
  retained; its logical count and canonical encoded size remain the values
  checked against the current signed maxima, and compaction cannot reset either
  value or make room by discarding a record; a current-only keyset, opaque manifest digest, accumulator that
  cannot reject a rollback/fork, or tombstone lacking the verification-result
  preimage is insufficient;
- the complete ConsentVerificationHistoryStateV1, every history record and full
  verification-result preimage, and every predecessor/resulting root edge remain
  independently recomputable. Compaction does not reset its revision/count/byte
  accounting, prune a record, or replace the vector with an accumulator;
- the identity-set query proves the correct remaining known set;
- no pending/ambiguous platform or key operation remains; and
- the terminal receipt, generation high-water, and current replay-index root
  are durably published, with every still-live consumed receipt retained as an
  authenticated tombstone; and
- the complete current ResidualScanUniverseBodyV1, including every historical
  identity, ever-used scope, and pending identity-capacity reservation, remains
  selected and independently readable after compaction; and
- every authenticated residual-universe successor record needed to prove each
  retained commitment, key ancestor, snapshot, result, or receipt's then-
  selected root is on the unique lineage to the current root remains readable
  after compaction. A compacted accumulator is permitted only when it proves the
  same ordered edge kinds and rejects forks, omissions, and reordered edges.

Time-based expiry alone never deletes a trust journal or ownership record.
Consent tombstone pruning follows only the stricter replay-index rule above.

## Consent and authorization

PreviewTrustOperationV1 is read-only and non-authorizing. It enumerates exact
targets, scopes, permission/interaction requirements, current pre-existing
state, excluded consumers, support dimensions, and the connectivity policy.
It allocates no generation, key, plan, permission, or mutation authority.

Generate, Install, Repair, RemoveTrust, and RemoveAndDestroy each require one
new CaConsentReceiptV1. Rotation requires two separate user actions and
receipts: RotatePrepare before candidate-key creation and RotateCommit after
the exact candidate certificate identity is known but before any trust install,
signer switch, old-target removal, or old-key destruction.

Before the consent broker signs, the coordinator chooses a random
TrustOperationId. Choosing that identifier grants no authority and allocates no
generation, key, plan, or platform state. Under a fresh authenticated helper
snapshot, the broker first requires that the ID is unbound under the uniqueness
rule and that the operation's worst-case tombstone plus every required safety
or continuation reservation and complete provider-operation reservation record
set fits both signed count/byte limits. RotateCommit instead proves the exact
existing RotatePrepare binding and its durable continuation reservation.

The broker also reads one authenticated current
ConsentBrokerKeysetSelectionStateV1 under the global mutation lock. It copies
that state's revision/root and last-record ProductManifestSequence, signed-
manifest digest, keyset epoch, and keyset digest into both
CaConsentReceiptBodyV1 and TrustPlanBodyV1 before signing or hashing either.
Those values are rechecked immediately before signature creation. If the
selection changes, issuance restarts from the new complete state; the broker
must not sign against the old prefix after its successor is current. Receipt
issuance itself does not append selection or verification history and grants no
helper/provider authority.

The v1 consent signer profile is closed. `ConsentBrokerSignatureAlgorithm` is
exactly Ed25519 with a 32-byte canonical public key, a 64-byte signature, strict
RFC 8032 verification, and no alternate encoding, prehash, context, or
algorithm. `ConsentBrokerKeyId` is:

    SHA-256(
      "FlowProbe.TrustCa.ConsentReceipt.v1\0" ||
      "broker-key-id\0" ||
      ConsentBrokerEd25519PublicKey
    )

The signed product manifest carries this canonical append-only keyset and pins
both its epoch and digest:

    ConsentBrokerKeysetBodyV1 {
      SchemaVersion = 1,
      KeysetEpoch,
      SortedUniqueConsentBrokerKeyVector = [
        {
          ConsentBrokerKeyId,
          ConsentBrokerSignatureAlgorithm = Ed25519,
          ConsentBrokerEd25519PublicKey,
          not_before,
          not_after,
          Disposition =
              Active
            | Retired { last_valid_issued_at }
            | Revoked {
                revoked_at,
                PriorRetirementCutoff = None
                  | Some(last_valid_issued_at),
                Reason = Compromise | PolicyRevocation
              }
        }
      ]
    }

    ConsentBrokerKeysetDigest = SHA-256(
      "FlowProbe.TrustCa.ConsentReceipt.v1\0" ||
      "broker-keyset\0" ||
      canonical(ConsentBrokerKeysetBodyV1)
    )

    ConsentBrokerKeysetV1 {
      Body = ConsentBrokerKeysetBodyV1,
      ConsentBrokerKeysetDigest
    }

Every plan, capability, consent-replay, and provider-selection bound consumed by
this contract is an explicit signed field, not an implementation default or an
unnamed projection of an opaque manifest payload:

    TrustCaAttestationTypedPurposeV1 {
      SignerRole = HelperAttestation | KeyAuthorityAttestation,
      TypedSignatureDomain,
      TypedBodyFieldTag,
      TypedSignedWrapperFieldTag = TypedSignedWrapperFieldTagV1
    }

    TrustCaAttestationPolicyV1 {
      SchemaVersion = 1,
      RequiredAlgorithm = Ed25519,
      NoRotationWithinInstallation = true,
      HelperAllowedNonExportableKeyProviderProfileDigest,
      KeyAuthorityAllowedNonExportableKeyProviderProfileDigest,
      TypedPurposeCount,
      SortedUniqueTypedPurposeVector = [ TrustCaAttestationTypedPurposeV1 ],
      MaximumAttestationContextEncodedBytes,
      MaximumRetainedInstallationAnchorCount,
      MaximumRetainedInstallationAnchorEncodedBytes,
      MaximumInstallationBootstrapAttemptCount,
      MaximumInstallationBootstrapAttemptEventCount,
      MaximumInstallationBootstrapAttemptEncodedBytes,
      TrustCaAttestationPolicyDigest
    }

    TrustCaAttestationPolicyDigest = SHA-256(
      "FlowProbe.TrustCa.InstallationAttestationPolicy.v1\0" ||
      "policy-body\0" || canonical(TrustCaAttestationPolicyV1 without digest)
    )

The purpose vector is exactly the 29-entry expansion of the closed generic-
attestation purpose registry above, sorted uniquely by its four canonical
fields. TypedPurposeCount is exactly 29. All six maxima are finite,
strictly positive canonical uint64 values and not `UINT64_MAX`. The policy
contains no InstallationId or public key. A manifest successor may not change
the algorithm, role assignment, or a purpose still referenced by the current or
retained historical installation. Unknown purposes and unsigned/opaque policy
subsets are invalid.
The anchor's HelperNonExportableKeyProviderProfileDigest and
KeyAuthorityNonExportableKeyProviderProfileDigest equal the policy's two
role-specific allowed profile digests byte-for-byte. The policy's six maxima
equal the same-named TrustCaManifestBoundsV1 fields; a local default or duplicate
unsigned value is invalid. A successor manifest may not lower those maxima
below any retained anchor/context/history encoding or the machine namespace's
complete Current-plus-retired-seal live floor.

    TrustCaManifestBoundsV1 {
      SchemaVersion = 1,
      MaximumAcceptedClockSkew,
      MaximumConsentReceiptLifetime,
      MaximumConsentReplayTombstoneCount,
      MaximumConsentReplayIndexEncodedBytes,
      MaximumConsentBrokerKeysetSelectionCount,
      MaximumConsentBrokerKeysetSelectionEncodedBytes,
      MaximumConsentVerificationHistoryCount,
      MaximumConsentVerificationHistoryEncodedBytes,
      MaximumConsentReceiptVerificationResultEncodedBytes,
      MaximumOperationReplayResultTargetCount,
      MaximumOperationReplayEvidenceCount,
      MaximumOperationReplayResultEncodedBytes,
      MaximumProviderOperationReservationCount,
      MaximumProviderOperationReservationEncodedBytes,
      MaximumKeyLedgerRecordCount,
      MaximumKeyLedgerRecordVectorEncodedBytes,
      MaximumKeyGenerationCount,
      MaximumKeyGenerationStateEncodedBytes,
      MaximumCanonicalCaPublicIdentityEncodedBytes,
      MaximumResidualHistoricalIdentityCount,
      MaximumResidualScopeCount,
      MaximumResidualUniverseEncodedBytes,
      MaximumResidualScanResultEncodedBytes,
      MaximumResidualObservationLifetime,
      MaximumResidualEnumeratedItemCountPerScope,
      MaximumResidualObservedMemberCountPerItem,
      MaximumResidualConsumerObservationCountPerMember,
      MaximumResidualScopeEnumerationBodyEncodedBytes,
      MaximumResidualQueryDerivedAuthoritySourceSetCount,
      MaximumResidualQueryTargetObservationCount,
      MaximumResidualQueryFixedRegeneratorResultCount,
      MaximumResidualQueryDerivedMemberProofCount,
      MaximumResidualOwnershipLedgerEntryCount,
      MaximumResidualOwnershipLedgerEncodedBytes,
      MaximumTrustPlanTargetCount,
      MaximumTrustPlanDependencyEdgeCount,
      MaximumTrustPlanEncodedBytes,
      MaxForwardPhaseStepCount,
      MaximumPhasePlanCount,
      MaximumProviderStepsPerPhase,
      MaximumPhasePlanEncodedBytes,
      MaximumPendingTargetStepCount,
      MaximumPendingTargetStepVectorEncodedBytes,
      MaximumPendingKeyStepCount,
      MaximumPendingKeyStepVectorEncodedBytes,
      MaximumPendingOperationSnapshotEncodedBytes,
      MaximumTrustJournalNativeRecordCountPerLink,
      MaximumTrustJournalRecordLinkEncodedBytes,
      MaximumTrustJournalCompactionRetainedLinkCount,
      MaximumTrustJournalCompactionDetachedRecordCount,
      MaximumTrustJournalCompactionCheckpointEncodedBytes,
      MaximumRecoveryReasonCount,
      MaximumRecoveryUnresolvedTargetCount,
      MaximumRecoveryReasonKeyCountPerTarget,
      MaximumRecoveryCurrentTargetReproofCount,
      MaximumRecoveryResolutionCount,
      MaximumRecoveryJournalSuffixCount,
      MaximumRecoveryJournalSuffixEncodedBytes,
      MaximumRecoveryFailureEvidenceCount,
      MaximumRecoveryFailureEvidenceEncodedBytes,
      MaximumRecoveryCurrentKeySummaryEncodedBytes,
      MaximumRecoveryStateEncodedBytes,
      MaximumAttestationContextEncodedBytes,
      MaximumRetainedInstallationAnchorCount,
      MaximumRetainedInstallationAnchorEncodedBytes,
      MaximumInstallationBootstrapAttemptCount,
      MaximumInstallationBootstrapAttemptEventCount,
      MaximumInstallationBootstrapAttemptEncodedBytes,
      MaximumTrustCapabilityRowCount,
      MaximumTrustCapabilityEvidenceCountPerRow,
      MaximumTrustCapabilityReasonCountPerRow,
      MaximumTrustCapabilityExcludedScopeCountPerRow,
      MaximumTrustCapabilitySnapshotEncodedBytes,
      MaximumTrustCapabilityLifetime,
      KeyProviderSelectionWindowCount = 5,
      SortedUniqueKeyProviderSelectionWindowVector = [
        {
          KeyProviderStepRole =
              GenerateCreate
            | RotatePrepareCandidateCreate
            | DirectRemoveAndDestroyKeyDestroy
            | RotatePrepareCandidateCleanupDestroy
            | RotateCommitOldKeyDestroy,
          ManifestKeyProviderSelectionWindow
        }
      ],
      ManifestSignerSwitchSelectionWindow,
      MaximumStableStatePossessionSelectionWindow,
      MaximumRotationReadyProjectionSelectionWindow
    }

All scalar maxima and windows are canonical uint64 values. Every field except
MaximumAcceptedClockSkew is finite and strictly positive; no field may equal
`UINT64_MAX`. MaximumAcceptedClockSkew is finite, may be zero, and also may not
equal `UINT64_MAX`. The provider-window count is the exact canonical uint32
vector length, the vector contains exactly the five enumerated roles sorted by
their closed numeric tag, and every window is finite and strictly positive.
Every maximum applied to a canonical uint32 count, including
MaximumConsentReplayTombstoneCount,
MaximumOperationReplayResultTargetCount, MaximumOperationReplayEvidenceCount,
MaximumResidualHistoricalIdentityCount, MaximumResidualScopeCount,
MaximumResidualEnumeratedItemCountPerScope,
MaximumResidualObservedMemberCountPerItem,
MaximumResidualConsumerObservationCountPerMember, MaximumTrustPlanTargetCount,
MaximumResidualQueryDerivedAuthoritySourceSetCount,
MaximumResidualQueryTargetObservationCount,
MaximumResidualQueryFixedRegeneratorResultCount,
MaximumResidualQueryDerivedMemberProofCount,
MaximumResidualOwnershipLedgerEntryCount,
MaximumTrustPlanDependencyEdgeCount, MaxForwardPhaseStepCount,
MaximumPhasePlanCount, MaximumProviderStepsPerPhase,
MaximumPendingTargetStepCount, MaximumPendingKeyStepCount,
MaximumTrustJournalNativeRecordCountPerLink,
MaximumTrustJournalCompactionRetainedLinkCount,
MaximumTrustJournalCompactionDetachedRecordCount,
MaximumRecoveryReasonCount, MaximumRecoveryUnresolvedTargetCount,
MaximumRecoveryReasonKeyCountPerTarget,
MaximumRecoveryCurrentTargetReproofCount, MaximumRecoveryResolutionCount,
MaximumRecoveryJournalSuffixCount, MaximumRecoveryFailureEvidenceCount,
MaximumInstallationBootstrapAttemptCount,
MaximumInstallationBootstrapAttemptEventCount,
MaximumTrustCapabilityRowCount,
MaximumTrustCapabilityEvidenceCountPerRow,
MaximumTrustCapabilityReasonCountPerRow, and
MaximumTrustCapabilityExcludedScopeCountPerRow, is no greater than
`UINT32_MAX`. Count limits used by explicit uint64 vectors remain uint64 and
are not narrowed by this rule.
Every derived deadline uses checked nonwrapping addition and the contract's
specified canonical minimum. Overflow, a missing/extra/duplicate role, a local
default, a caller-selected replacement, or any shorter or longer substituted
bound invalidates the signed manifest.

    ConsentAuthorityManifestProjectionV1 {
      ProductManifestSequence,
      ProductReleaseTupleDigest,
      ConsentBrokerKeysetV1,
      ConsentBrokerKeysetDigest,
      TrustCaManifestBoundsV1,
      TrustCaAttestationPolicyV1,
      TrustCaAttestationPolicyDigest,
      KeyProviderFreshnessWindowPolicyCount,
      SortedUniqueKeyProviderFreshnessWindowPolicyVector = [
        KeyProviderFreshnessWindowPolicyV1
      ]
    }

The product-manifest verifier retains a complete signed preimage rather than an
opaque digest:

    CompleteSignedProductManifestV1 {
      SignedBody = SignedProductManifestBodyV1 {
        ProductManifestSchemaVersion = 1,
        ProductManifestSequence,
        ProductReleaseTupleDigest,
        ConsentAuthorityManifestProjectionV1,
        CanonicalRemainingProductManifestBody
      },
      SignedProductManifestDigest,
      ProductManifestSignatureAlgorithm = Ed25519,
      ProductManifestVerificationKeyId,
      ProductManifestEd25519PublicKey,
      ProductManifestSignature
    }

    SignedProductManifestDigest = SHA-256(
      "FlowProbe.TrustCa.ConsentAuthorityManifest.v1\0" ||
      "manifest-body\0" ||
      canonical(SignedProductManifestBodyV1)
    )

    ProductManifestSignature = Ed25519.Sign(
      ProductManifestPrivateKey,
      "FlowProbe.TrustCa.ConsentAuthorityManifest.v1\0" ||
      "manifest-signature\0" ||
      canonical(SignedProductManifestBodyV1)
    )

`CanonicalRemainingProductManifestBody` is the bounded, unique canonical
encoding of every remaining release-mapping field under the body-named,
installation-pinned product-manifest schema; a byte string that does not decode
and re-encode identically is invalid. The projection and bounds above are
direct members of the signed body, never reconstructed policy subsets. The
remaining body may contain only release/profile/capability catalog data and may
not contain a TrustOperationId, TrustPlan/PhasePlan, consent receipt,
manifest-selection record/state, replay/tombstone, journal/head, lifecycle
state/snapshot, envelope, proof/receipt, or any digest derived from one of those
operation- or installation-state objects.
The
freshness-policy count is the exact canonical uint32 vector length and entries
are strictly sorted uniquely by KeyProviderProfileDigest. The projected
sequence/release MUST equal the outer signed-body sequence/release, the complete
keyset/digest MUST recompute, and every TrustCaManifestBoundsV1 field is covered
directly by the signed-body preimage. ProductManifestVerificationKeyId is
SHA-256 over the consent-authority-manifest domain, field tag
`"manifest-key-id\0"`, and the exact repeated 32-byte public key; that key and
ID must equal the installation-pinned product-manifest verification identity.
The signature is strict RFC 8032 Ed25519 over the preimage shown above. Unknown
schema, algorithm, key, field, alternate encoding, digest/signature mismatch,
or digest-only manifest reference is invalid.

Before one such manifest becomes current, the helper append-selects this closed
installation-scoped ledger:

    ConsentBrokerKeysetSelectionRecordV1 {
      Body = ConsentBrokerKeysetSelectionRecordBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.ConsentBrokerKeysetSelection.v1,
        InstallationId,
        ConsentAuthoritySelectionId,
        SelectionRevision,
        ExpectedPredecessor =
            SelectionGenesis {
              ExpectedPredecessorSelectionRevision = 0,
              ExpectedPredecessorSelectionRoot
            }
          | SelectedManifest {
              ExpectedPredecessorSelectionRevision,
              ExpectedPredecessorSelectionRoot,
              ExpectedPredecessorProductManifestSequence,
              ExpectedPredecessorSignedProductManifestDigest,
              ExpectedPredecessorConsentBrokerKeysetEpoch,
              ExpectedPredecessorConsentBrokerKeysetDigest
            },
        CompleteSignedProductManifestV1,
        ConsentAuthorityManifestProjectionV1,
        ResultingProductManifestSequence,
        ResultingSignedProductManifestDigest,
        ResultingConsentBrokerKeysetEpoch,
        ResultingConsentBrokerKeysetDigest,
        CurrentObservedTime,
        ExpectedPredecessorReplayTimeHighWater,
        EffectiveSelectedAt
      },
      ConsentBrokerKeysetSelectionRecordDigest
    }

    ConsentBrokerKeysetSelectionRecordDigest = SHA-256(
      "FlowProbe.TrustCa.ConsentBrokerKeysetSelection.v1\0" ||
      "selection-record\0" ||
      canonical(ConsentBrokerKeysetSelectionRecordBodyV1)
    )

    ConsentBrokerKeysetSelectionStateV1 {
      SelectionRevision,
      CompleteSelectionRecordCount,
      CompleteSelectionRecordVector = [
        ConsentBrokerKeysetSelectionRecordV1
      ],
      ConsentBrokerKeysetSelectionRoot,
      CurrentProductManifestSequence,
      CurrentSignedProductManifestDigest,
      CurrentConsentBrokerKeysetEpoch,
      CurrentConsentBrokerKeysetDigest
    }

    ConsentBrokerKeysetSelectionRoot = SHA-256(
      "FlowProbe.TrustCa.ConsentBrokerKeysetSelection.v1\0" ||
      "complete-vector\0" ||
      uint64_be(CompleteSelectionRecordCount) ||
      canonical(CompleteSelectionRecordVector)
    )

CompleteSelectionRecordCount is the exact canonical uint64 vector length. Before
selecting the genesis successor or any append, the helper constructs the entire
resulting ConsentBrokerKeysetSelectionStateV1 and obtains
MaximumConsentBrokerKeysetSelectionCount and
MaximumConsentBrokerKeysetSelectionEncodedBytes from the candidate record's
fully verified signed manifest projection. The resulting count MUST be no
greater than the former and
`len(canonical(ResultingConsentBrokerKeysetSelectionStateV1))` MUST be no
greater than the latter. Both maxima are finite, strictly positive, and not
`UINT64_MAX`; canonical-size arithmetic is checked and nonwrapping. Thus a
successor manifest may raise capacity but may never set either maximum below the
already retained history plus its own new record/current-state fields. A count
or byte overflow, max-plus-one result, lowered/zero/unbounded bound, or failure
to encode the complete candidate state rejects the update before any selection
record, replay successor, journal link, envelope, stable receipt, or selector is
made durable; the previous manifest remains current.

The same pre-selection transaction reads the complete current
ConsentVerificationHistoryStateV1 from the predecessor envelope/index. The
candidate manifest's MaximumConsentVerificationHistoryCount and
MaximumConsentVerificationHistoryEncodedBytes MUST be no lower than that
state's retained count and canonical encoded size, and
MaximumConsentReceiptVerificationResultEncodedBytes MUST be no lower than the
largest retained complete result encoding. Checked comparison happens before
the selection record is durable. A successor manifest may raise these three
limits but cannot strand, discard, or retroactively invalidate retained
history; any lowering, overflow, unavailable full preimage, or size mismatch
rejects the manifest selection and leaves the prior manifest current.

The same no-lowering rule applies to every complete append-only or historically
retained state whose capacity is signed here. In particular, the candidate
provider-reservation, key-ledger-record, key-generation-state, residual-
historical-identity/scope/universe, and trust-journal compaction limits must
cover the exact predecessor counts, canonical encodings, and largest retained
entry/checkpoint required by this contract. When a selected pending/recovery
state retains a RecoveryKeyLedgerStateProjectionV1, the candidate
MaximumRecoveryCurrentKeySummaryEncodedBytes and MaximumRecoveryStateEncodedBytes
must cover its complete summary and enclosing recovery state; selection cannot
make that authenticated recovery evidence unencodable. The candidate manifest-selection
journal link itself must fit both the predecessor and candidate trust-journal
batch/link limits. A lower limit is allowed only for an ephemeral future object
class for which no selected, retained, pending, or reserved preimage already
exceeds it; no selector, compaction, or current-only summary may erase history
to make a candidate manifest fit.

The installation genesis root is SHA-256 over the selection domain, field tag
`"genesis\0"`, and InstallationId. The genesis predecessor accepts no manifest
or keyset fields. Thereafter SelectionRevision is the nonwrapping predecessor
plus one, equals the exact vector count, and every record names the immediately
preceding revision/root and a fresh installation-lifetime-unique
ConsentAuthoritySelectionId. The record's repeated
ConsentAuthorityManifestProjectionV1 is byte-identical to
CompleteSignedProductManifestV1.SignedBody.ConsentAuthorityManifestProjectionV1,
and every resulting manifest/keyset field equals that complete signed preimage.
ProductManifestSequence strictly
increases; byte-identical retry returns the already selected record and does not
append. ResultingConsentBrokerKeysetEpoch never decreases. At the same epoch the
complete keyset body and digest MUST be byte-identical to the predecessor; at a
higher epoch it MUST be exactly an allowed append/retire/revoke successor under
the rules below. Skipped product releases are allowed, but a same-sequence
different digest, same-epoch different keyset, removed/re-activated key,
predecessor mismatch, fork, rollback, overflow, or reconstructed root is
integrity failure.

EffectiveSelectedAt is exactly
`max(CurrentObservedTime, ExpectedPredecessorReplayTimeHighWater)` under the
clock-rollback rule and equals the containing helper journal record's effective
selection time. CompleteSelectionRecordVector starts at the genesis successor,
is ordered by SelectionRevision, retains every full signed manifest/keyset
preimage, and independently recomputes every record digest and the root. The
four Current fields equal the last record; no selected state is accepted from a
digest-only or partial vector.

Manifest selection is a non-authorizing product-update transaction under the
global mutation lock. Installation bootstrap is permitted only when the
root-owned InstallationNamespaceSelectorV1 has Current=None and the staged
fresh ID/epoch/anchor/nonce are absent from every retained seal; selecting the
complete per-installation revision-one state and the machine Current entry is
the second crash-safe namespace CAS defined above. It selects the unique first
record from SelectionGenesis as the complete input of the dedicated
InstallationBootstrapSelectionRecordV1. The registered bootstrap native record,
InstallationGenesis link, revision-one Append head, monotonic envelope, initial
Absent receipt/snapshot/state, and state-index slot are constructed in that
order and selected in one transaction; no receipt can be issued or consumed
against an unselected genesis. A staged bootstrap that loses its namespace CAS
has no authority and must follow its selected marker-bound cleanup events to
AbandonedTerminal before retry with a fresh attempt and operation IDs. A later selection is
allowed only from a quiescent lifecycle state
with no pending or RecoveryRequired state. The helper appends a
ConsentAuthoritySelection journal delta carrying the complete record and
resulting selection state, selects the corresponding replay-time successor,
advances the trust revision/head, constructs the resulting monotonic envelope,
and selects a new state-compatible stable receipt over the byte-identical
business and key projection. Generated/Installed obtain a fresh
StableStateSelection possession proof; Drifted/Absent retain their required
closed/no-key projection. The selection record/state contains no journal,
envelope, stable-receipt, consent-receipt, replay-result, or resulting-state
digest, so the construction is acyclic. An updater encountering a pending or
RecoveryRequired state must keep the new manifest unselected, close the gate as
applicable, and use the typed recovery path; it cannot activate a keyset beside
the authenticated state. No consent is first-consumed while a product-manifest
selection is staged, forked, or newer than the current selected envelope.

KeysetEpoch is nonwrapping and the vector is sorted uniquely by
ConsentBrokerKeyId. Every key ID is recomputed from the repeated exact public
key and algorithm; duplicate IDs, duplicate public keys, or alternate encodings
are invalid. `not_before < not_after` is immutable. A keyset successor may append
a key, change Active to Retired or Revoked, or change Retired to Revoked; it
cannot remove, replace, reactivate, un-revoke, or change the public key or prior
validity bounds of an entry. Retired.last_valid_issued_at is within the entry's
immutable Active interval. A Retired-to-Revoked successor must copy that cutoff
into PriorRetirementCutoff; Active-to-Revoked uses None. Revoked.revoked_at is no
earlier than not_before, and Revoked is terminal.
The product manifest signature is verified independently with the pinned
product-manifest verification key before this keyset is trusted. A manifest is
current only through the complete selected ConsentBrokerKeysetSelectionStateV1;
its final record contains the exact current KeysetEpoch and
ConsentBrokerKeysetDigest, never a caller-supplied key or digest. Every
historical full signed manifest/keyset preimage needed by a selected record or
consumed receipt remains readable through that vector and its retained
verification result.

`CaConsentReceiptBodyV1` is this signature-free canonical body:

    CaConsentReceiptBodyV1 {
      ReceiptVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.ConsentReceipt.v1,
      ConsentBrokerSignatureAlgorithm = Ed25519,
      IssuanceConsentBrokerKeysetSelectionRevision,
      IssuanceConsentBrokerKeysetSelectionRoot,
      IssuanceProductManifestSequence,
      ConsentBrokerKeysetEpoch,
      ConsentBrokerKeysetDigest,
      ConsentBrokerKeyId,
      SignedProductManifestDigest,
      ConsentReceiptId,
      InstallationId,
      TrustOperationId,
      ExpectedBaseLifecycleStateTag,
      ExpectedBaseStateDigest,
      ExpectedBaseTrustStateRevision,
      ExpectedBaseTrustJournalHeadDigest,
      AuthenticatedPolicyPrincipalDigest,
      OperationKind = Generate | Install | Repair | RemoveTrust
        | RemoveAndDestroy | RotatePrepare | RotateCommit,
      ExistingCaPublicIdentityDigest = None | Some(CaPublicIdentityDigest),
      CandidateBinding =
          None
        | GenerationProfileCommitment {
            CertificateProfileDigest,
            KeyProviderProfileDigest
          }
        | ExactCaPublicIdentityDigest,
      TargetBinding =
          NoneForGenerate {
            TargetCount = 0,
            RequiredTargetBitmap = empty
          }
        | RequestedTargetScopeTemplate {
            Body = RequestedTargetScopeTemplateV1,
            RequestedTargetScopeTemplateDigest
          }
        | ExactOrderedTargetSet {
            Body = ExactOrderedTargetSetV1,
            ExactOrderedTargetSetDigest
          }
        | RotationTargetBinding {
            Body = RotationTargetBindingV1,
            RotationTargetBindingDigest
          },
      RequestedInterceptionFallbackPolicy,
      PrivilegeAndInteractionAggregate = PrivilegeAndInteractionAggregateV1,
      HelperPreparationNonce,
      issued_at,
      expires_at,
      OneUseNonce
    }

The exact receipt is:

    CanonicalConsentReceiptBodyDigest = SHA-256(
      "FlowProbe.TrustCa.ConsentReceipt.v1\0" ||
      "body\0" ||
      canonical(CaConsentReceiptBodyV1)
    )

    ConsentBrokerSignature = Ed25519.Sign(
      ConsentBrokerPrivateKey,
      "FlowProbe.TrustCa.ConsentReceipt.v1\0" ||
      "broker-signature\0" ||
      canonical(CaConsentReceiptBodyV1)
    )

    CaConsentReceiptV1 {
      Body = CaConsentReceiptBodyV1,
      CanonicalConsentReceiptBodyDigest,
      ConsentBrokerSignature
    }

    ConsentReceiptDigest = SHA-256(
      "FlowProbe.TrustCa.ConsentReceipt.v1\0" ||
      "signed-receipt\0" ||
      canonical(CaConsentReceiptV1)
    )

The exact accepted first-consumption decision is also canonical and retained:

    ConsentReceiptVerificationResultV1 {
      Body = ConsentReceiptVerificationResultBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.ConsentBrokerKeysetSelection.v1,
        InstallationId,
        CaConsentReceiptV1,
        CanonicalConsentReceiptBodyDigest,
        ConsentReceiptDigest,
        ReceiptNamedCompleteSignedProductManifestV1,
        ReceiptNamedConsentAuthorityManifestProjectionV1,
        SelectedConsentBrokerKeysetSelectionStateV1,
        SelectedConsentBrokerKeysetSelectionRevision,
        SelectedConsentBrokerKeysetSelectionRoot,
        CurrentProductManifestSequence,
        CurrentSignedProductManifestDigest,
        CurrentConsentBrokerKeysetEpoch,
        CurrentConsentBrokerKeysetDigest,
        ExpectedPredecessorConsentVerificationHistoryRevision,
        ExpectedPredecessorConsentVerificationHistoryRoot,
        EvaluatedSignerDisposition =
            Active
          | Retired { last_valid_issued_at },
        EffectiveReceiptTime,
        Result = AcceptedForFirstConsumption
      },
      ConsentReceiptVerificationResultDigest
    }

    ConsentReceiptVerificationResultDigest = SHA-256(
      "FlowProbe.TrustCa.ConsentBrokerKeysetSelection.v1\0" ||
      "receipt-verification\0" ||
      canonical(ConsentReceiptVerificationResultBodyV1)
    )

The helper retains every accepted first-consumption result in this independent,
installation-bound append-only state:

    ConsentVerificationHistoryRecordV1 {
      Body = ConsentVerificationHistoryRecordBodyV1 {
        SchemaVersion = 1,
        DigestDomain = FlowProbe.TrustCa.ConsentVerificationHistory.v1,
        InstallationId,
        ConsentVerificationHistoryRevision,
        ExpectedPredecessorConsentVerificationHistoryRevision,
        ExpectedPredecessorConsentVerificationHistoryRoot,
        ConsentReceiptId,
        ConsentReceiptDigest,
        ConsentReceiptVerificationResultV1,
        ConsentReceiptVerificationResultDigest,
        EffectiveReceiptTime
      },
      ConsentVerificationHistoryRecordDigest
    }

    ConsentVerificationHistoryRecordDigest = SHA-256(
      "FlowProbe.TrustCa.ConsentVerificationHistory.v1\0" ||
      "history-record\0" ||
      canonical(ConsentVerificationHistoryRecordBodyV1)
    )

    ConsentVerificationHistoryStateV1 {
      SchemaVersion = 1,
      InstallationId,
      ConsentVerificationHistoryRevision,
      CompleteConsentVerificationHistoryCount,
      CompleteConsentVerificationHistoryVectorEncodedBytes,
      CompleteConsentVerificationHistoryVector = [
        ConsentVerificationHistoryRecordV1
      ],
      ConsentVerificationHistoryRoot
    }

    ConsentVerificationHistoryRoot = SHA-256(
      "FlowProbe.TrustCa.ConsentVerificationHistory.v1\0" ||
      "complete-vector\0" ||
      InstallationId ||
      uint64_be(CompleteConsentVerificationHistoryCount) ||
      uint64_be(CompleteConsentVerificationHistoryVectorEncodedBytes) ||
      canonical(CompleteConsentVerificationHistoryVector)
    )

CompleteConsentVerificationHistoryCount is the exact canonical uint64 vector
length; CompleteConsentVerificationHistoryVectorEncodedBytes is exactly
`len(canonical(CompleteConsentVerificationHistoryVector))`. The canonical empty
state has revision/count zero, the canonical empty-vector encoded-byte length,
the empty vector, and the root recomputed by the formula above. It is initialized only by the root-owned
installation-bootstrap transaction that also establishes the initial selected
manifest and lifecycle state. This is an explicit integration hook: the empty
history grants no journal-predecessor, receipt, replay, plan, phase, provider,
or key authority, and this section does not define or relax the separate helper
journal-genesis selection semantics.

Each first consumption appends exactly one full record. Its revision is the
checked, nonwrapping predecessor revision plus one and equals the resulting
count. The record's predecessor fields equal both the selected state-index and
predecessor MonotonicSafetyEnvelope; its complete result and digest, receipt ID,
receipt digest, EffectiveReceiptTime, and InstallationId are byte-identical to
the accepted ConsentReceiptVerificationResultV1. Records are ordered by
revision, every inline result and record digest independently recomputes, and
the resulting root is computed only after the record exists. Retry of an
already consumed receipt returns its existing record and appends nothing; the
same receipt ID or digest in a different revision, a gap, fork, reordered
vector, cross-install record, digest-only result, or reconstructed summary is
integrity failure.

Before receipt consumption, the helper constructs the complete resulting state
and requires its count and canonical state encoding to be no greater than the
current signed manifest's MaximumConsentVerificationHistoryCount and
MaximumConsentVerificationHistoryEncodedBytes. It also requires
`len(canonical(ConsentReceiptVerificationResultV1))` to be no greater than
MaximumConsentReceiptVerificationResultEncodedBytes. All size/count arithmetic
is checked and nonwrapping. Exhaustion fails before a tombstone, intent, phase,
journal link, envelope, selector, or side effect is selected; history is never
pruned or summarized to make room.

Neither digest nor signature is in its own or another earlier preimage.
`OneUseNonceDigest` is SHA-256 over the same domain, the distinct field tag
`"one-use-nonce\0"`, and the exact 256-bit OneUseNonce. Before first
consumption, the broker and helper independently recompute both receipt digests,
verify the body-named signed product manifest, resolve and recompute its complete
keyset, and require the receipt's epoch/digest/key ID and algorithm to match the
receipt-named historical keyset entry. That complete manifest/keyset must be an
exact historical member of the current selected keyset-selection vector, whose
revision/root/current fields equal the authenticated predecessor envelope and
state index. Before constructing or accepting
ConsentReceiptVerificationResultV1, the verifier also recomputes the nested
selected state's exact count and canonical encoded size and requires both to fit
the MaximumConsentBrokerKeysetSelectionCount and
MaximumConsentBrokerKeysetSelectionEncodedBytes in that state's current (last
record) signed manifest. The receipt-named historical manifest cannot lower,
raise, or replace those current capacity bounds. An oversized, unencodable, or
bound-substituted state is integrity failure before a receipt tombstone or
operation journal record is selected. They obtain the sole canonical 32-byte
public key from that entry, recompute ConsentBrokerKeyId, strictly verify the
receipt signature, require `expires_at` no later than the checked nonwrapping
sum of `issued_at` and the receipt-named manifest projection's
TrustCaManifestBoundsV1.MaximumConsentReceiptLifetime, and require issued_at no
later than EffectiveReceiptTime and EffectiveReceiptTime strictly earlier than expires_at.
The receipt's issuance selection revision/root is an exact prefix state of the
complete selected vector, and its last record equals IssuanceProductManifestSequence,
SignedProductManifestDigest, ConsentBrokerKeysetEpoch, and
ConsentBrokerKeysetDigest byte-for-byte. `issued_at` is no earlier than that
record's EffectiveSelectedAt and is strictly earlier than every successor
record's EffectiveSelectedAt. Equivalently, the bound issuance record is the
greatest selected revision whose effective time is no later than issued_at;
ties fail closed against the earlier revision. A broker therefore cannot issue
against a historical manifest/keyset after a successor became current and make
that receipt valid by retaining the old preimage.

The signing key must have been Active in that exact issuance keyset and satisfy
`not_before <= issued_at < not_after`. A key now Retired is accepted for first consumption only when
issued_at is no later than its last_valid_issued_at and the receipt remains
unexpired. A key shown Revoked by the current selected signed manifest is invalid
for first consumption regardless of an older keyset body. An unknown key,
unverified manifest, keyset rollback/fork, changed public key, algorithm
substitution, malformed signature, body/digest mismatch, or unavailable
historical keyset is ConsentScopeMismatch before any side effect.

The verification result's complete receipt and both receipt digests are
byte-identical to the object being consumed. Its receipt-named complete signed
manifest verifies and deterministically decodes to the repeated projection; its
digest/keyset epoch/keyset digest equal the receipt body and exactly one record
in the complete selected keyset-selection vector. The selected state is the
current complete state, independently recomputes to the repeated
revision/root/current manifest/keyset fields, and equals the predecessor
MonotonicSafetyEnvelope and state-index fields byte-for-byte. The signer entry
is resolved in both the receipt-named historical keyset and current keyset. A
currently Revoked or missing signer cannot be encoded as an accepted result;
Active/Retired and its cutoff equal the current entry exactly. EffectiveReceiptTime
equals the authenticated receipt-validation time. Under the global mutation
lock the helper rechecks this current selection immediately before its atomic
ReceiptAndPhaseSelection; any intervening manifest selection, different root,
or changed disposition aborts and restarts validation. Thus a verification
result cannot turn a historical Active entry into current authority or survive
a keyset-selection TOCTOU.

ExpectedPredecessorConsentVerificationHistoryRevision/Root equal the current
complete history state in that same predecessor envelope and state-index slot.
They are checked again under the global mutation lock immediately before the
result is wrapped in the next ConsentVerificationHistoryRecordV1. The result
contains neither that record nor the resulting history revision/root, so the
append remains acyclic.

The result contains no tombstone, replay index/result, helper-journal record,
pending state, monotonic envelope, history record/resulting history root, or
resulting selector. Its order is complete selected manifest/keyset history ->
receipt -> verification result -> history record/resulting history root ->
receipt-phase intent -> receipt-selection journal record and tombstone ->
resulting envelope/state, with no reverse reference.

After atomic first consumption, the exact receipt, body digest, signed-receipt
digest, signer keyset body, and verification result are immutable historical
authorization ancestry. Later retirement or revocation cannot rewrite that
history, replay the receipt, or authorize a new phase. A newly discovered
compromise closes the gate and may force bounded RecoveryRequired handling, but
the already-selected operation may retain only its exact sealed recovery and
safety-reduction authority; it gains no target, key, or provider authority.

Receipt consumption atomically appends the full verification-history record,
inserts the tombstone, reserves its maximum encoded terminal result, appends the matching phase plan and
RecoveryDispositionVectorV1 entry, and records the first phase intent before
any side effect. RemoveAndDestroy and RotatePrepare also allocate and atomically
select their exact non-dispatching destroy continuation/selection record in
that transition; RotateCommit does the same when its receipt is consumed.
RotatePrepare separately persists its one future RotateCommit consent-capacity continuation
reservation in that transition. RotateCommit consumes exactly that reservation
while appending its own tombstone, phase plan, and recovery entry; it neither
edits nor broadens the RotatePrepare entry. Its ReceiptAndPhaseSelection record
uses SubsequentRotationPhaseSelection, names the exact selected RotatePrepare
complete pending snapshot as predecessor, and the successor snapshot uses
AuthorizedOperationSuccessor with that complete record/digest. It cannot reuse
InitialPendingSelection or replace the first operation-journal anchor.

PrivilegeAndInteractionAggregateBodyV1 is:

    PrivilegeAndInteractionAggregateBodyV1 {
      SchemaVersion = 1,
      PhaseOrderedEntryVector = [
        {
          PhaseRole = InitialInstall | Repair | RemoveTrust
            | RemoveAndDestroy | RotatePrepareCandidateTemplate
            | RotateCommitCandidateInstall | RotateCommitActiveRetire,
          TargetReference =
              TemplateTarget {
                TemplateRole = CandidateInstall,
                TemplateEntryKey
              }
            | ExactTarget {
                SetRole = InitialInstall | Repair | RemoveTrust
                  | RemoveAndDestroy | CandidateInstall | ActiveRetire,
                TargetId
              },
          PrivilegeAndInteractionRequirement,
          PreauthorizationOutcome = NotPerformed
            | NotRequired
            | Succeeded(PreauthorizationEvidenceDigest)
            | Failed(BoundedReason)
            | InheritedFromTemplateAuthority {
                AuthorityTemplateEntryKey
              }
            | InheritedFromExactAuthority {
                AuthoritySetRole,
                AuthorityTargetId
              }
        }
      ]
    }

    PrivilegeAndInteractionAggregateV1 {
      Body = PrivilegeAndInteractionAggregateBodyV1,
      PrivilegeAndInteractionAggregateDigest
    }

    PrivilegeAndInteractionAggregateDigest = SHA-256(
      "FlowProbe.TrustCa.PrivilegeAggregate.v1\0" ||
      canonical(PrivilegeAndInteractionAggregateBodyV1)
    )

The wrapper and digest above are the one named aggregate used byte-for-byte by
TrustPlanBodyV1 and CaConsentReceiptBodyV1; the latter's anonymous-looking
`PrivilegeAndInteractionAggregate` field is exactly this wrapper and not a
second encoding. PrivilegeAndInteractionAggregateDigest covers only that
canonical body under its registered domain. Generate has an empty vector. RotatePrepare lists
template entries in TemplateEntryKey order. A non-rotation exact operation
lists its one set in TargetId order. RotateCommit concatenates exactly
CandidateInstallSet in TargetId order and then ActiveRetireSet in TargetId
order, with the distinct phase tags above. Each requirement MUST equal the
referenced template/exact target field. RotatePrepareCandidateTemplate is the
only phase that accepts TemplateTarget and
InheritedFromTemplateAuthority; its authority key must name an edge in that
same template whose DependentTemplateEntryKey equals the current
TemplateTarget.TemplateEntryKey and whose AuthorityTemplateEntryKey equals the
referenced authority key. Every other phase accepts only ExactTarget, whose SetRole must
be the unique role implied by PhaseRole; InheritedFromExactAuthority must name
that identical closed SetRole and the edge in that same exact set whose
DependentTargetId equals the current ExactTarget.TargetId and whose
AuthorityTargetId equals the referenced authority ID. The inherited
outcome is required exactly when the target requirement is
InheritedFromAuthority; it is forbidden otherwise. Cross-phase, cross-set, and
template/exact reference substitution is malformed. No entry may be omitted or
duplicated.
This aggregate records native preauthorization already attempted, but it never
turns product consent into native OS authorization.

RequestedTargetScopeTemplateV1 is the canonical generation-independent body:

    RequestedTargetScopeTemplateV1 {
      SchemaVersion = 1,
      TemplateRole = CandidateInstall,
      CanonicallySortedUniqueEntryVector = [
        TargetScopeTemplateEntryV1 {
          TemplateEntryKey,
          TargetKind,
          StableScopeProjection,
          InstallerExecutorClass = PrivilegedHelper
            | AuthenticatedUserTrustAgent
            | AuthenticatedAdministratorTrustAgent
            | DerivedByTemplate,
          PrivilegeAndInteractionRequirement,
          BackendReleaseTupleDigest,
          CompleteReadOnlyRegeneratorInputScopeSetDigestOrNone,
          Required
        }
      ],
      SortedUniqueTemplateDependencyEdgeVector = [
        {
          DependentTemplateEntryKey,
          AuthorityTemplateEntryKey,
          EdgeKind = DerivedBy
        }
      ],
      RequiredTargetBitmap
    }

StableScopeProjection contains the exact platform tag, store/domain/database,
owner/user context, consumer class, and trust semantic from TrustTargetV1. It
excludes values that cannot exist before candidate allocation: TargetId,
CaGeneration, CaInstanceId, certificate DER/SPKI identity, generation-scoped
locator, before/current observations, and step/results. It also excludes
DerivedBy(AuthorityTargetId); template dependencies use the separate entry-key
edge vector. InstallerExecutorClass is generation-independent: its three
direct-agent/helper classes materialize byte-for-byte, while
DerivedByTemplate plus its authority edge materializes to
DerivedBy(the mapped AuthorityTargetId).

CompleteReadOnlyRegeneratorInputScopeSetDigestOrNone is None for every direct or
ObservationOnly entry and is required for every derived entry. Its complete
manifest-signed preimage is the sorted unique bounded set of all stable direct
input scopes, observer schemas, and release-defined input normalizers that the
fixed regenerator can read. It is observation scope only: it adds no target,
mutation consent, ownership, delete authority, or inherited privilege. Template
to exact refinement preserves it byte-for-byte; an input outside this set makes
derived provenance incomplete.

Entries are first sorted by the canonical keyless entry body and duplicates are
rejected, then TemplateEntryKey is assigned as the zero-based uint32 ordinal in
that order. The final entry vector is ordered by that key. An authority key in
an edge MUST name an authority entry in the same template, a dependent key MUST
name a derived entry, self/cyclic edges are rejected, and every derived entry
has exactly one authority edge. An authority entry MUST use one of the three
direct helper/user/administrator executor classes; DerivedByTemplate cannot be
an authority endpoint, so derived-to-derived chains are malformed.
RequiredTargetBitmap uses the canonical high-bit-first byte-string rule above
and has exactly one bit per entry in key order; bit i MUST equal entry
i.Required. Empty templates are
rejected for RotatePrepare. TargetScopeTemplateEntryDigest and
RequestedTargetScopeTemplateDigest use their registered domains over the exact
canonical entry and complete body respectively. Entry, edge, and bitmap counts
are bounded by the signed product manifest's trust-target maximum.

The immutable per-target plan preimage is explicit:

    ImmutableTrustTargetPlanRecordBodyV1 {
      SchemaVersion = 1,
      DigestDomain = FlowProbe.TrustCa.TargetPlanRecord.v1,
      InstallationId,
      TrustOperationId,
      PhaseRole,
      TargetId,
      Required,
      CaGeneration,
      CaInstanceId,
      CertificateDerSha256,
      CertificateSpkiSha256,
      TargetKind,
      PlanOperationRole,
      ExactStoreOrDomainScope,
      InstallerExecutor,
      PrivilegeAndInteractionRequirement,
      InstallerOwner,
      BeforeImage,
      IntendedPostcondition,
      BackendReleaseTupleDigest,
      CompleteReadOnlyRegeneratorInputScopeSetDigestOrNone,
      BoundedDeadline
    }

    ImmutableTrustTargetPlanRecordV1 {
      Body = ImmutableTrustTargetPlanRecordBodyV1,
      ImmutableTrustTargetPlanRecordDigest
    }

    ImmutableTrustTargetPlanRecordDigest = SHA-256(
      "FlowProbe.TrustCa.TargetPlanRecord.v1\0" ||
      canonical(ImmutableTrustTargetPlanRecordBodyV1)
    )

InstallationId, TrustOperationId, and PhaseRole equal the enclosing operation
and set. Every remaining body field is the complete canonical fixed plan
projection of the matching TrustTargetRecordV1. PlanOperationRole equals the enclosing set role;
TargetId recomputes from the complete normalized TrustTargetV1 identity/scope
fields. CurrentStep, LatestOperationObservation, and TerminalVerification are the
only TrustTargetRecordV1 fields excluded because they evolve in the separate
journal step vector. The body contains neither its digest nor an enclosing
TrustPlan/ExactOrderedTargetSet digest. Unknown fields, partial owner/before-image/
scope objects, or a digest without this complete body are invalid.

ExactOrderedTargetSetV1 is:

    ExactOrderedTargetSetV1 {
      SchemaVersion = 1,
      SetRole = InitialInstall | Repair | RemoveTrust | RemoveAndDestroy
        | CandidateInstall | ActiveRetire,
      SortedUniqueTargetRecordDigestVector = [
        {
          TargetId,
          ImmutableTrustTargetPlanRecordV1,
          ImmutableTrustTargetPlanRecordDigest
        }
      ],
      SortedUniqueExactDependencyEdgeVector = [
        {
          DependentTargetId,
          AuthorityTargetId,
          EdgeKind = DerivedBy
        }
      ],
      RequiredTargetBitmap,
      OptionalPreparationRefinement = None
        | TargetTemplateRefinementV1 {
            Body = TargetTemplateRefinementBodyV1 {
              RequestedTargetScopeTemplateDigest,
              SortedUniqueTemplateEntryKeyToTargetIdVector = [
                { TemplateEntryKey, TargetId }
              ]
            },
            TargetTemplateRefinementDigest
          }
    }

The exact vector is sorted by TargetId and rejects duplicate TargetIds. Every
complete immutable record independently recomputes to its adjacent digest and
its TargetId equals the outer key.
PlanOperationRole MUST equal SetRole. The digest excludes only CurrentStep,
LatestOperationObservation, and TerminalVerification, which evolve in the
separate journal vector. The bitmap uses the canonical high-bit-first byte-string rule above,
has exactly one bit per target in that same order, and MUST equal each record's
Required field. Exact dependency edges are sorted by their
canonical pair, bounded, acyclic, internal to this exact set, and every derived
target has exactly one DerivedBy edge to its authority TargetId. That authority
target's InstallerExecutor MUST be direct PrivilegedHelper,
AuthenticatedUserTrustAgent, or AuthenticatedAdministratorTrustAgent and its
requirement cannot be InheritedFromAuthority or ObservationOnly; DerivedBy and
ObservationOnly targets cannot be authority endpoints. This matches
VerifiedDerivedExact's requirement that the authority terminal proof be
VerifiedOwned or VerifiedPreExistingExact and deliberately rejects derived-to-
derived chains.
The edge is exactly the primary execution/permission lineage. Additional
current direct sources discovered within the manifest-bound read-only input
scope set do not add dependency edges and cannot appear in privilege,
preauthorization, consent, or deletion target sets.
ObservationOnly targets are invalid in every ExactOrderedTargetSetV1 role;
they remain preview/capability/baseline evidence only and never participate in
consent, mutation, removal, required-target, rotation, or admission sets.
ExactOrderedTargetSetDigest covers the complete body under its registered
domain. TargetTemplateRefinementV1 is a bijection: every TemplateEntryKey maps
to exactly one TargetId and every exact target maps back to exactly one entry.
TargetTemplateRefinementDigest covers only the signature-free
TargetTemplateRefinementBodyV1 under its registered domain; the digest field is
not in its own preimage.
Applying that mapping to every template dependency edge MUST yield the exact
dependency-edge vector byte-for-byte. Materialization may fill only the fields
excluded from StableScopeProjection; every stable scope, direct executor class,
per-target permission/interaction requirement, backend release tuple, Required
bit, and dependency topology MUST match. DerivedByTemplate materializes only
through the mapped exact dependency edge. CandidateInstall requires this refinement and
the original RotatePrepare template digest. Other SetRole values require
OptionalPreparationRefinement=None. Exact-set and refinement counts share the
same manifest bound as the template.

RotationTargetBindingV1 is a phase-tagged signed body:

    RotationTargetBindingV1 {
      SchemaVersion = 1,
      CandidateKeyBinding = CandidateKeyBindingV1 {
        CandidateCaGeneration,
        CandidateCaInstanceId,
        CandidateCaPublicIdentityDigest,
        CandidateCertificateSpkiSha256,
        CandidateGenerationCommitmentDigest,
        CandidatePreCreateCompleteKeyGenerationStateRoot,
        CandidateProviderKeyUniquenessEvidenceDigest,
        CandidateKeyCreatedReceiptDigest,
        CandidateReadyRecordDigest,
        CandidateReadyKeyAuthorityEpoch,
        CandidateReadyKeyStateRevision,
        CandidateReadyKeyJournalHeadDigest,
        CandidateReadyCompleteKeyGenerationStateRoot,
        RotationReadyKeyProjectionAttestationV1,
        RotationReadyKeyProjectionAttestationDigest,
        RotationReadyProjectionSelectionRecordV1,
        RotationReadyProjectionSelectionRecordDigest,
        ActiveCaGeneration,
        ActiveCaInstanceId,
        ActiveCaPublicIdentityDigest,
        ActiveCertificateSpkiSha256,
        ActiveReadyRecordDigest,
        SpkiObjectSecretAndIdentityDistinct = true
      },
      CandidateKeyBindingDigest,
      CandidateInstallSet {
        Body = ExactOrderedTargetSetV1(
          SetRole = CandidateInstall,
          OptionalPreparationRefinement = matching template refinement),
        ExactOrderedTargetSetDigest
      },
      ActiveRetireSet {
        Body = ExactOrderedTargetSetV1(
          SetRole = ActiveRetire,
          OptionalPreparationRefinement = None),
        ExactOrderedTargetSetDigest,
        SortedUniqueActiveRetireDispositionVector = [
          ActiveRetireDispositionV1 =
            OwnedRemove {
              TargetId,
              FlowProbeOwnerReceiptDigest,
              OwnedAfterImageDigest,
              FreshCurrentBeforeObservationDigest,
              IntendedOwnedAbsencePostconditionDigest
            }
          | ExternalPreserve {
              TargetId,
              ExternalBeforeObservationDigest,
              FreshEffectiveTrustObservationDigest,
              IntendedUnchangedPostconditionDigest
            }
          | DerivedReconcile {
              TargetId,
              PrimaryAuthorityTargetId,
              CurrentAuthoritySourceSetDigest,
              CurrentDerivedResultProofDigest,
              IntendedDerivedDispositionDigest
            }
          | OptionalOmitted {
              TargetId,
              InstalledReceiptOmissionDigest,
              FreshNoOwnedMutationObservationDigest
            }
        ]
      },
      ActiveInstalledReceiptDigest,
      ActiveRequiredTargetSetDigest,
      SignerSwitchPlanV1,
      SignerSwitchPlanDigest,
      RotationPhaseGraphV1 {
        Body = RotationPhaseGraphBodyV1 {
          OrderedPhaseNodeVector = [
            CandidateInstall(CandidateInstallSet.ExactOrderedTargetSetDigest),
            CandidateVerify(CandidateKeyBindingDigest),
            SignerSwitch(SignerSwitchPlanDigest),
            ActiveRetire(ActiveRetireSet.ExactOrderedTargetSetDigest),
            OldKeyDestroy {
              ActiveCaPublicIdentityDigest,
              CandidateCaPublicIdentityDigest,
              CandidateProviderKeyUniquenessEvidenceDigest,
              ActiveReadyRecordDigest,
              CandidateReadyRecordDigest,
              CandidateReadyCompleteKeyGenerationStateRoot,
              RotationReadyKeyProjectionAttestationDigest,
              RotationReadyProjectionSelectionRecordDigest,
              CandidateKeyBindingDigest,
              SpkiObjectSecretAndIdentityDistinct = true
            }
          ],
          SortedUniquePhaseDependencyEdgeVector
        },
        RotationPhaseGraphDigest
      }
    }

CandidateInstallSet refines exactly the RotatePrepare template. ActiveRetireSet
instead binds every exact old-generation target from the named active installed
receipt and exactly one disposition per TargetId. OwnedRemove requires current
FlowProbeOwned evidence and is the only disposition that authorizes delete.
ExternalPreserve requires ExternalPreExisting and is never mutated.
DerivedReconcile requires the exact DerivedBy authority edge, owns nothing, and
only revalidates the derived result after its authority disposition.
OptionalOmitted is allowed only for a Required=false row that the active
installed receipt already recorded as omitted and that fresh observation proves
created no owned mutation. The disposition vector is sorted by TargetId and is
bijective with ActiveRetireSet. It may contain the same logical scopes as
the candidate set because its CA identity, generation-scoped locators,
TargetIds, and SetRole are different. CandidateKeyBinding is closed.
CandidateKeyBindingDigest is SHA-256 over the NUL-terminated registered rotation-
target-binding domain, the field tag `"candidate-key-binding\0"`, and canonical
CandidateKeyBindingV1; that field tag is distinct from the complete
RotationTargetBindingV1 preimage. CandidateKeyBindingDigest is outside its
body and therefore nonrecursive. The
CandidateKeyBinding fields resolve byte-for-byte through the candidate
GenerationCommitment, complete KeyCreatedReceipt, ProviderKeyUniquenessEvidence,
candidate Ready record, and the exact post-Ready key authority
epoch/revision/head plus CompleteKeyGenerationStateRoot; its active fields and
ActiveReadyRecordDigest equal the other Ready entry in that same complete root.
The complete RotationReadyKeyProjectionAttestationV1 recomputes to its bound
digest and names that exact RotationDualReady projection, operation, root/head,
Ready records, commitment, uniqueness evidence, and creation receipt. The
complete RotationReadyProjectionSelectionRecordV1 also recomputes to its bound
digest, proves that exact attestation was timely selected, and equals the
SelectedForRotation descriptor ancestor byte-for-byte.
That pending-rotation root has exactly those two Ready entries and only terminal
post-dispatch CreateUnapplied, CreateUnappliedNeverStarted, or Destroyed entries
otherwise. It is not mislabelled as one of the
three quiescent KeyLedgerStateProjectionV1 variants. Distinctness is recomputed
inside the key authority rather than trusted as a boolean or by exposing raw
internal tags to the helper.
Any duplicate SPKI or internal object/secret/identity tag, missing pre-create
generation, or attestation/selection/receipt/root mismatch forbids both
candidate cleanup and every later phase. A CandidateKeyBinding-specific or
RotateCommit binding failure forbids commit and old-key destruction but does
not erase an otherwise valid already-selected RotatePrepare cleanup authority.
The phase graph is acyclic
and complete:
candidate verification precedes signer switch, signer switch precedes every
active-retire mutation, and every active-retire row's disposition-specific
sealed postcondition precedes old-key destruction. Before old-key destruction
every OwnedRemove is verified absent, every ExternalPreserve is unchanged,
every DerivedReconcile is settled, and every OptionalOmitted remains no-owned-
mutation. RotationPhaseGraphDigest covers only
RotationPhaseGraphBodyV1 under its registered domain and is not in its own preimage.
RotationTargetBindingDigest covers this complete body under its
registered domain. Neither exact set can be omitted, merged, or projected to a
scope-only set.
Any authorized candidate-cleanup or old-key KeyDestroyIntentBodyV1 uses the
current global key tip as its record predecessor and MUST bind
ExpectedPreDestroyCompleteKeyGenerationStateRoot to this exact post-Ready root.
RotatePrepareCandidateCleanup binds the complete attestation/selection record
without CandidateKeyBinding or RotationTargetBinding and selects only
CandidateReadyRecordDigest. RotateCommitOldKeyDestroy binds both
CandidateKeyBindingDigest and RotationTargetBindingDigest and selects only
ActiveReadyRecordDigest. Neither rewinds the global chain to that entry's
historical Ready head or substitutes the other destroy-authority variant.

Signer switch uses a context-free semantic plan constructed before the
RotateCommit target binding and consent receipt, followed by one operation-
bound receipt. This ordering avoids a plan/target-binding/consent digest cycle:

    SignerSwitchPlanBodyV1 {
      SchemaVersion = 1,
      DigestDomain = FlowProbe.TrustCa.SignerSwitchPlan.v1,
      InstallationId,
      TrustOperationId,
      ActiveCaGeneration,
      ActiveCaInstanceId,
      ActiveCaPublicIdentityDigest,
      ActiveReadyRecordDigest,
      CandidateCaGeneration,
      CandidateCaInstanceId,
      CandidateCaPublicIdentityDigest,
      CandidateReadyRecordDigest,
      CandidateKeyBindingDigest,
      CandidateReadyCompleteKeyGenerationStateRoot,
      CandidateInstallExactOrderedTargetSetDigest,
      CandidateInstallIntendedPostconditionRoot,
      ActiveRetireExactOrderedTargetSetDigest,
      ActiveRetireDispositionRoot,
      RequiredActivePreSwitchBusinessRoot,
      IntendedNewInstalledBusinessPostconditionDigest,
      SignedProductManifestDigest,
      ManifestSignerSwitchSelectionWindow
    }

    SignerSwitchPlanV1 {
      Body = SignerSwitchPlanBodyV1,
      SignerSwitchPlanDigest
    }

    SignerSwitchPlanDigest = SHA-256(
      "FlowProbe.TrustCa.SignerSwitchPlan.v1\0" ||
      canonical(SignerSwitchPlanBodyV1)
    )

The candidate-key binding, Ready records/root, exact target sets, disposition
root, candidate intended-postcondition root, required active pre-switch business
root, and intended new business
digest independently verify and repeat the same fields later enclosed by
RotationTargetBindingV1 byte-for-byte. The signed manifest supplies one finite,
strictly positive signer-switch window; the plan's
ManifestSignerSwitchSelectionWindow MUST equal
TrustCaManifestBoundsV1.ManifestSignerSwitchSelectionWindow byte-for-byte. This plan contains no
RotationTargetBindingDigest, RotationPhaseGraphDigest, consent receipt,
PhasePlanDigest, current/predecessor state or snapshot, journal record/head,
envelope, signer-switch receipt, or resulting object. RotationPhaseGraphV1's
SignerSwitch node contains this digest, after which the complete rotation target
binding, consent receipt, and PhasePlanV1 can be constructed in that order.

    SignerSwitchSelectionChallengeV1 {
      Body = SignerSwitchSelectionChallengeBodyV1 {
        SchemaVersion = 1,
        SignatureDomain = FlowProbe.TrustCa.SignerSwitchSelectionChallenge.v1,
        SignedProductManifestDigest,
        ManifestSignerSwitchSelectionWindow,
        InstallationId,
        TrustOperationId,
        RotateCommitConsentReceiptDigest,
        RotateCommitPhasePlanDigest,
        RotationTargetBindingDigest,
        SignerSwitchPlanDigest,
        ExpectedLifecycleStateTag = InstallPending(RotateInstall),
        ExpectedTrustLifecycleStateDigest,
        ExpectedCompletePendingOperationSnapshotDigest,
        ExpectedTrustStateRevision,
        ExpectedTrustJournalHeadDigest,
        ExpectedMonotonicSafetyEnvelopeDigest,
        ExpectedReplayIndexRevision,
        ExpectedConsentReplayIndexRoot,
        ExpectedReplayTimeHighWater,
        ActiveCaPublicIdentityDigest,
        ActiveReadyRecordDigest,
        CandidateCaPublicIdentityDigest,
        CandidateReadyRecordDigest,
        RotationDualReadyKeyLedgerStateProjectionDigest,
        HelperChallengeNonce,
        EffectiveChallengeTime,
        expires_at
      },
      HelperAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = HelperAttestation,
        Context.TypedSignatureDomain =
          FlowProbe.TrustCa.SignerSwitchSelectionChallenge.v1,
        Context.TypedBodyFieldTag = "challenge-body\0"
      },
      SignerSwitchSelectionChallengeDigest
    }

    SignerSwitchSelectionChallengeDigest = SHA-256(
      "FlowProbe.TrustCa.SignerSwitchSelectionChallenge.v1\0" ||
      "signed-challenge\0" || canonical({
        SignerSwitchSelectionChallengeBodyV1,
        HelperAttestation
      })
    )

    SignerSwitchResidualQueryChallenge = SHA-256(
      "FlowProbe.TrustCa.SignerSwitchSelectionChallenge.v1\0" ||
      "residual-query-challenge\0" || SignerSwitchSelectionChallengeDigest
    )

The challenge is constructed from the one selected pending predecessor under
the global mutation lock. Every plan, binding, receipt, identity, Ready record,
key projection, state/snapshot, journal/envelope, and replay field is complete
selected evidence and byte-identical to the RotateCommit authority.
The complete generic HelperAttestation context resolves only through the current
Active installation anchor. A bootstrap, journal, gate, signer-switch receipt,
key-authority, CA, provider, caller, or other-installation key is invalid.
SignedProductManifestDigest equals the
current manifest in the predecessor envelope/state and RotateCommit phase plan;
ManifestSignerSwitchSelectionWindow equals that manifest's signed bound
byte-for-byte. Its expiry is exactly the checked minimum of the RotateCommit
consent expiry and `checked_add(EffectiveChallengeTime,
ManifestSignerSwitchSelectionWindow)`; zero, `UINT64_MAX`, overflow, a historical
manifest, or a shorter/longer substituted deadline is invalid. The helper nonce
is fresh and installation-lifetime unique. The body contains no query context,
scan, possession proof, journal successor, receipt, or resulting object.

    SignerSwitchKeyPossessionProofBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.KeyPossession.v1,
      Purpose = SignerSwitchCandidateSelection,
      InstallationId,
      TrustOperationId,
      CandidateCaGeneration,
      CandidateCaInstanceId,
      CandidateCaPublicIdentityDigest,
      CandidateCertificateDerSha256,
      CandidateCertificateSpkiSha256,
      CandidateReadyRecordDigest,
      CandidateKeyAuthorityEpoch,
      CandidateKeyStateRevision,
      CandidateKeyJournalHeadDigest,
      CandidateReadyCompleteKeyGenerationStateRoot,
      SignerSwitchPlanDigest,
      SignerSwitchSelectionChallengeDigest,
      ResidualQueryContextDigest,
      ResidualScanResultDigest,
      QueryChallenge = SignerSwitchResidualQueryChallenge,
      observed_at,
      must_select_by
    }

    SignerSwitchKeyPossessionProofV1 {
      Body = SignerSwitchKeyPossessionProofBodyV1,
      CaKeySignature,
      SignerSwitchKeyPossessionProofDigest
    }

The candidate CA key signs only the canonical body under its registered
key-possession domain, field tag `"signer-switch-body\0"`, and exact purpose.
SignerSwitchKeyPossessionProofDigest covers canonical `{Body, CaKeySignature}`
under the same domain and distinct field tag `"signer-switch-proof\0"`. The
key authority accepts this typed purpose only for the current candidate Ready
entry and complete key root/head named by the body. It accepts no arbitrary
bytes and the proof cannot substitute for creation, stable-state, admission, or
post-destroy evidence.

    SignerSwitchSatisfactionEvidenceV1 {
      TargetSatisfactionCount,
      SortedUniqueTargetSatisfactionVector = [
          CandidateInstalled {
            TargetId,
            PlannedIntendedPostconditionDigest,
            TargetBusinessFactV1,
            TargetBusinessFactDigest,
            TerminalTargetObservationV1,
            TerminalTargetObservationDigest
          }
        | ActiveReverified {
            TargetId,
            RequiredActiveBusinessFactDigest,
            SelectedCurrentFactAnchor,
            ResidualQueryTargetObservationV1,
            ResidualQueryTargetObservationDigest
          }
      ],
      CandidateInstalledTargetBusinessRoot,
      ActiveCurrentTargetBusinessRoot
    }

    SignerSwitchSatisfactionEvidenceDigest = SHA-256(
      "FlowProbe.TrustCa.SignerSwitchReceipt.v1\0" ||
      "satisfaction-evidence\0" ||
      canonical(SignerSwitchSatisfactionEvidenceV1)
    )

    SignerSwitchFreshQueryEvidenceV1 {
      SignerSwitchSelectionChallengeV1,
      SignerSwitchSelectionChallengeDigest,
      ResidualQueryContextV1 {
        Purpose = SignerSwitchSelection
      },
      ResidualQueryContextDigest,
      ResidualScanResultV1,
      ResidualScanResultDigest,
      SignerSwitchSatisfactionEvidenceV1,
      SignerSwitchSatisfactionEvidenceDigest
    }

TargetSatisfactionCount is the exact canonical uint32 vector length and shares
the rotation target bound. Entries are sorted uniquely by `(variant tag,
TargetId)`. CandidateInstalled is bijective with CandidateInstallSet and each
complete fact/terminal observation satisfies its planned intended postcondition;
its fresh current query observation also matches that selected terminal fact.
ActiveReverified is bijective with ActiveRetireSet and its fresh current query
observation matches the selected current fact and required active business fact.
The two roots recompute from their respective complete rows and satisfy
SignerSwitchPlanV1's two semantic commitment roots. Missing, extra, duplicate,
expired, changed, or cross-role evidence invalidates signer switch. The fresh-
query wrapper carries one complete challenge, one context whose QueryChallenge
is SignerSwitchResidualQueryChallenge, and one complete scan. Every candidate
and active target row is a member of that exact scan, repeats its
ResidualQueryContextDigest, and has RequiredRelation=MatchesSelectedFact. The
context/snapshot/plan/binding/challenge fields and both business roots are byte-
identical throughout. A terminal-only candidate row, two scans, missing scope
enumeration, stale context, changed row, or possession proof bound to a
different challenge/context/scan is invalid.

    SignerSwitchReceiptBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.SignerSwitchReceipt.v1,
      InstallationId,
      TrustOperationId,
      RotateCommitConsentReceiptDigest,
      RotateCommitPhasePlanV1,
      RotateCommitPhasePlanDigest,
      RotationTargetBindingV1,
      RotationTargetBindingDigest,
      SignerSwitchPlanV1,
      SignerSwitchPlanDigest,
      TrustOperationJournalRecordV1 {
        RequiredDelta = SignerSwitchSelection
      },
      TrustOperationJournalRecordDigest,
      SelectedForwardOnlySelectionCommitment =
        ForwardOnlySelectionCommitmentV1 {
          PhaseRole = RotateCommit,
          IrreversiblePhase = SignerSwitchCommitted
        },
      ActiveCaPublicIdentityDigest,
      CandidateCaPublicIdentityDigest,
      ActiveReadyRecordDigest,
      CandidateReadyRecordDigest,
      SignerSwitchFreshQueryEvidenceV1,
      SignerSwitchSatisfactionEvidenceV1,
      SignerSwitchSatisfactionEvidenceDigest,
      CandidateInstalledTargetBusinessRoot,
      ActiveCurrentTargetBusinessRoot,
      KeyLedgerStateProjectionV1 {
        Projection = RotationDualReady
      },
      KeyLedgerStateProjectionDigest,
      SignerSwitchKeyPossessionProofV1,
      SignerSwitchKeyPossessionProofDigest,
      ResultingSignerCaPublicIdentityDigest,
      ResultingInterceptionGateEpoch,
      ResultingInterceptionGateDisposition = ClosedDuringRotation,
      ResultingTrustStateRevision,
      ResultingTrustJournalHeadDigest,
      ResultingMonotonicSafetyEnvelope = MonotonicSafetyEnvelopeV1,
      ResultingMonotonicSafetyEnvelopeDigest,
      ResultingReplayIndexRevision,
      ResultingConsentReplayIndexRoot,
      ResultingReplayTimeHighWater,
      committed_at
    }

    SignerSwitchReceiptV1 {
      Body = SignerSwitchReceiptBodyV1,
      HelperAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = HelperAttestation,
        Context.TypedSignatureDomain = FlowProbe.TrustCa.SignerSwitchReceipt.v1,
        Context.TypedBodyFieldTag = "receipt-body\0"
      },
      SignerSwitchReceiptDigest
    }

    SignerSwitchReceiptDigest = SHA-256(
      "FlowProbe.TrustCa.SignerSwitchReceipt.v1\0" ||
      "signed-receipt\0" ||
      canonical({SignerSwitchReceiptBodyV1, HelperAttestation})
    )

The generic HelperAttestation context covers the same registered domain, distinct field
tag `"receipt-body\0"`, and canonical SignerSwitchReceiptBodyV1. The helper
accepts only the current selected Active anchor's HelperAttestation key;
another installation, helper purpose, CA key, renderer, or caller key is invalid.
The complete TrustOperationJournalRecordV1 independently resolves the current
RotateCommit pending predecessor, phase/consent authority and its unique
SignerSwitchSelection delta. That delta and the receipt inline the same complete
challenge, fresh-query evidence, and candidate possession proof byte-for-byte.
Its EffectiveSelectedAt is no later than the canonical checked minimum of the
RotateCommit receipt expiry, `receipt.issued_at +
ManifestSignerSwitchSelectionWindow`, challenge expiry, residual-query context
expiry, scan expiry, and possession-proof must_select_by; overflow is invalid.
The selected ForwardOnly commitment is the one byte-identical
SignerSwitchCommitted member of the phase plan, continuation, recovery entry,
and journal delta. The same delta proves that the RotateCommit recovery entry
was ResumeOrCompensate in the predecessor and is exactly this ForwardOnly value
in the successor; no generic recovery-disposition delta or second encoding is
accepted.

The journal delta verifies the complete candidate Installed target root, fresh
active target root, RotationDualReady projection, and candidate possession
proof before changing the internal signer. The receipt's resulting signer is
exactly the candidate; the old identity remains retiring, both Ready entries
remain live, and the gate remains closed until final InstalledAndVerified
selection. Resulting revision is the record predecessor plus one; the resulting
journal head is the authenticated append of exactly that record. Replay fields
equal the record's complete replay successor and the monotonic envelope binds
those values, both key tips, the new signer/gate epoch, and the same business
roots. committed_at equals the journal record's EffectiveSelectedAt. The body
contains no resulting lifecycle-state or pending-snapshot digest, and the
journal record contains no receipt digest, so the graph is acyclic.
The successor pending snapshot sets SignerSwitchSelectionEvidence to
SelectedSignerSwitch with this complete plan/receipt and recomputed digests;
its AuthorizedOperationSuccessor lineage inlines the same journal record. Every
later RotateCommit/RotateRetireOld pending descendant retains that evidence
byte-for-byte, and old-key destroy resolves it from the selected current
snapshot rather than from an unselected side object.

The only valid operation/binding combinations are:

| Operation | CandidateBinding | TargetBinding |
| --- | --- | --- |
| Generate | GenerationProfileCommitment | NoneForGenerate with zero-length bitmap |
| Install | ExactCaPublicIdentityDigest | ExactOrderedTargetSet, SetRole=InitialInstall, no refinement |
| Repair | ExactCaPublicIdentityDigest | ExactOrderedTargetSet, SetRole=Repair, no refinement |
| RemoveTrust | None, with existing identity digest | ExactOrderedTargetSet, SetRole=RemoveTrust, no refinement |
| RemoveAndDestroy | None, with existing identity digest | ExactOrderedTargetSet, SetRole=RemoveAndDestroy, no refinement |
| RotatePrepare | GenerationProfileCommitment | RequestedTargetScopeTemplate |
| RotateCommit | ExactCaPublicIdentityDigest, with active identity digest | RotationTargetBinding with candidate refinement and exact active-retire set |

Any other pairing, absent or non-empty NoneForGenerate bitmap, bitmap length or
bit mismatch, noncanonical ordering, duplicate entry/TargetId, missing or
non-bijective rotation refinement, scope broadening, executor change, or
required-to-optional change is a malformed receipt and fails before
consumption. A PlanOperationRole or per-target
PrivilegeAndInteractionRequirement mismatch is equally malformed.

PrivilegeAndInteractionAggregateV1 cannot replace, infer, or override a per-
target field. Mixed user/admin targets retain distinct requirements, outcomes,
phase roles, and executors in the signed body.

Generate and RotatePrepare use GenerationProfileCommitment because no candidate
certificate exists yet. Install, Repair, and RotateCommit bind the exact
candidate identity. Generate uses NoneForGenerate; RotatePrepare binds the
canonical requested template because generation-scoped TargetId values do not
exist yet. Every non-rotation trust-mutating operation binds its exact ordered
target set; RotateCommit binds the complete RotationTargetBindingV1 containing
both exact sets and the phase graph. RotatePrepare also binds the exact active identity
and authorizes only candidate generation plus safe destruction of that still-
uninstalled candidate if RotateCommit is refused, expires, or cannot be
obtained. RotateCommit binds the same TrustOperationId, the exact active and
candidate identities, the matching candidate template refinement, the exact
active-retire set, and the complete install/retire phase graph.

Before RotateCommit, InstallPending(RotateInstall) has an empty
CompletePerTargetStepVector. Its sole RotatePrepare PhasePlan entry contains the exact
template digest and the candidate-key steps; it is not an install plan and
authorizes no target mutation. Consuming RotateCommit atomically appends the
complete RotationTargetBindingV1 and initializes one NotAttempted candidate-
install step in CandidateInstallSet target order. Its sealed ActiveRetireSet is
carried forward unchanged and initializes the later RemovePending step vector
only after signer switch. InitialInstall and Repair enter InstallPending only
with an already exact target set and a fully initialized CompletePerTargetStepVector.

Every receipt binds the exact state observed for its own phase. Generate binds
the current Absent digest/revision/tip; install, repair, removal, and destruction
bind their exact current quiescent state; RotatePrepare binds the current
InstalledAndVerified state; and RotateCommit binds the exact
InstallPending(RotateInstall) digest/revision/tip after candidate identity
binding. The helper rechecks those fields under the mutation lock in the same
transition that consumes the receipt. A receipt for an earlier Absent,
Generated, installed, or rotation-pending revision cannot authorize a later
state even if its wall-clock expiry has not elapsed.

The helper trust journal is the authoritative one-use registry. Receipt
consumption and the first immutable phase intent are appended and fsynced in
one state transition together with the corresponding replay-index tombstone
before any key or platform side effect. A crash before
that transition leaves the receipt unconsumed; a retry after it is accepted
only as the byte-identical same TrustOperationId/receipt/phase. No independent
broker-side consumed bit may create an unjournaled operation. The renderer
cannot mint, copy to another target set, extend, or replay a receipt.

Current-user and machine/admin targets are distinct choices. Permission failure
for one MUST NOT upgrade, downgrade, or fall back to the other. An OS
authorization prompt is additional platform evidence; it does not replace the
product consent receipt. Conversely, a product click does not prove native
authorization succeeded.

Recovery MAY finish observation, resume only the exact retained pending phases
allowed by the current RecoveryDispositionVectorV1 entry, compensate a proven
partial mutation, or
destroy a key already covered by the exact consumed RemoveAndDestroy,
RotatePrepare, or RotateCommit receipt. Resuming the same authenticated pending
snapshot is not implied startup consent. RotatePrepare never authorizes trust
installation or old-state mutation. Recovery MUST NOT install, repair, re-add,
broaden trust, select another target, change user/machine scope, or rotate under
implied startup consent. External deletion never triggers automatic reinstall.

## Generation transaction

Generating a CA performs:

1. Verify lifecycle Absent and no unresolved known identity or target.
2. Choose TrustOperationId and obtain an unexpired Generate receipt binding it
   and the exact generation profile; validate the signature and scope without
   consuming it.
3. Under the trust mutation lock reverify Absent, allocate the next
   CaGeneration, CaInstanceId, fence, ProviderCreateOperationId, and
   key-creation challenge; read and verify the exact pre-create
   KeyLedgerStateProjectionV1, bind its authority epoch/revision/head,
   CompleteKeyGenerationStateRoot, and the manifest uniqueness-policy digest;
   from the projection's complete provider-operation reservation vector,
   construct the next GenerateCreate ProviderOperationReservationRecordV1 and
   its resulting revision/root, rejecting any installation-lifetime ID or step
   collision;
   prove the complete universe/result capacity; compute
   U1 with the exact reservation and the Generate phase's required first-use
   scope set, which is canonically empty for the no-target Generate variant;
   construct GenerationCommitmentBodyV1 over H0/U1 and that complete proposed
   reservation wrapper in the order above; then atomically append and fsync
   GenerateIntentDurable plus the receipt-consumption record and replay-index
   tombstone, and select GeneratePending, H1, and U1 with that exact
   GenerationCommitted descriptor and a GenerateCreate key step initialized as
   OperationReservationSelected with the complete proposed reservation evidence
   before contacting the key authority.
4. Through the helper-gated authenticated operation, the key authority verifies
   the complete generation commitment, helper pending descendant, pre-create key
   root, uniqueness policy, and proposed reservation against its live ledgers.
   It append-selects exactly that reservation record (or recovers the byte-
   identical staged append) before any bootstrap query. It then produces the complete
   purpose-bound CreatePreCallProviderAbsenceProofV1, constructs the Create
   ProviderCallInvocationMarkerV1 after an exact NeverInvoked provider query,
   and fsyncs both complete objects in a matching Creating record with
   CreateIntentDisposition=IntentDurable. Creating.committed_at equals the
   marker's EffectiveMarkerCommittedAt and is no later than both the proof's
   must_commit_by and GenerationCommitmentBodyV1.KeyProviderMarkerSelectionDeadline before making
   any provider call. The helper observes that complete selected Creating record
   and advances the same key step to ProviderMarkerDurable with
   MarkerBearingKeyRecord evidence before relying on the step for a terminal
   transition; a crash may replay that byte-identical helper advance after the
   key record, but cannot construct a different marker or skip it.
5. Invoke exactly one provider create using ProviderCreateOperationId and the
   byte-identical selected marker; require every provider result/query to echo
   that marker, build and parse the exact certificate, prove the certificate SPKI is the created
   key, and construct ProviderKeyUniquenessEvidenceV1 against the committed
   pre-create generation root. Only a distinct SPKI, provider object, underlying
   secret, and NonExportableKeyIdentity may receive the CreationPreReady proof
   bound to that evidence, exact Creating revision/head, and generation
   challenge. Before both must_commit_by deadlines, append-only refine Creating
   to Ready with the bounded public DER, exact identity, internal
   NonExportableKeyIdentity and non-aliasing tags, and KeyCreatedReceiptV1
   carrying both complete proofs and the complete marker. The provider side effect never occurs while
   the key ledger is still missing Creating. A collision or incomplete check
   selects CreateAmbiguous/RecoveryRequired with destroy forbidden, never Ready.
6. Independently parse the returned public DER, validate the complete v1
   profile, recompute DER/SPKI digests, and verify a distinct fresh
   PostReadyGenerationVerification key-possession signature over the committed
   Ready revision/head and a new helper challenge.
7. Bind the exact identity and helper/key ledger tips in both ledgers, fsync the
   GeneratePending-to-Generated transition, authoritative identity-set update,
   LiveReady KeyLedgerStateProjectionV1 and stable-state possession proof, and
   GeneratedReceiptV1 in one selected state-index transition, and only then
   return success.

A crash before marker-bearing Creating selection leaves no dispatch authority.
If the helper pending state was selected but the reservation was not, recovery
may append only the byte-identical staged reservation even after the marker
deadline; that append grants no dispatch. While the key generation remains
NoRecord, two exact NeverInvoked/None bootstrap observations may instead produce
CreateNeverStartedProviderAbsenceProofV1 and, before its fresh deadline, the key
authority atomically selects KeyCreateNeverStartedReceiptV1 with the direct
CreateUnappliedNeverStarted record. The helper then cross-binds that receipt,
advances the same complete create key step from OperationReservationSelected to
CreateNeverStartedTerminal with NativeTerminalReceipt evidence,
releases only the U1 identity reservation, records the durable terminal replay
result, and returns to the exact prior Absent state. That terminal reservation,
generation, and operation ID can never later acquire a marker or provider call.
After marker-bearing Creating selection, recovery queries the exact
`{ProviderCreateOperationId, ProviderCallInvocationMarkerDigest}` operation. A
byte-identical NeverInvoked result permits the one first provider call with that
same ID and marker even after KeyProviderMarkerSelectionDeadline; an in-flight or terminal result
permits only query/reconciliation and never another call. One matching provider
result is verified, rechecked against the immutable pre-create uniqueness root,
and refined to Ready only if every uniqueness input and provider marker echo
matches; a complete same-operation
CreatePostCallProviderAbsenceProofV1 refines to CreateUnapplied and records
UnappliedDurable in both ledgers; and any multiple,
mismatched, unqueryable, unknown, or marker-mismatched result is Ambiguous and
RecoveryRequired. ProviderOperationFirstInvokedAt is audit metadata and is not
used to manufacture deadline authority. Recovery never guesses by label,
substitutes a discovered key, or issues a
second create under the same operation or generation. It never destroys an
ambiguous candidate when object/secret aliasing with another generation has not
been excluded.

Generated does not mean installed, trusted, or interception-ready.

## Install and repair transaction

An install or repair plan freezes:

- one exact candidate CA public identity and fresh key-possession proof schema;
- one consent receipt and interception fallback policy;
- one ExactOrderedTargetSetV1 with a sorted unique target vector and exact-
  length RequiredTargetBitmap;
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
addition. Immediately before the first compensation removal is issued, it
durably narrows the active recovery entry to ForwardOnly with the exact
phase-plan OwnedRemovalIssued/ExactBase commitment and seals
the exact remaining reverse path. InstallPending remains visible with the
complete partial vector until
compensation ends. It returns to the exact prior quiescent state only when every
new owned item/output is safely absent/restored, every pre-existing item is
preserved, and the base state is freshly proven. Otherwise the state is
RecoveryRequired with the pending snapshot; it MUST NOT report installed,
enter ordinary Drifted, or erase the partial history. After safe terminal
compensation reaches the freshly proven base state, a remaining bounded
external change may independently transition that stable state to Drifted.

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

Immediately before the first owned removal is issued, a
ResumeOrCompensate entry durably appends its sole ForwardOnly refinement with
the exact intended Generated or Absent terminal. If the entry was initially
ForwardOnly(SafetyReservationConsumed, intended Absent), the helper instead
byte-exactly verifies that same outcome and that the sealed remaining path
contains this removal, then records only the per-step removal intent; it does
not write a forbidden second refinement. The deletion cannot later be
reinterpreted as compensation to an earlier installed state.

Removal is conditional and exact:

    ResidualEffectiveTrustDispositionV1 =
      Rejected {
        ConsumerObservationDigest,
        NegativeTlsResultDigest
      }
    | PreservedExternalLive {
        ExternalSourceOrScopeObservationDigest,
        ConsumerObservationDigest,
        SuccessfulTlsResultDigest
      }
    | ConservativeExternalTrustPotential {
        ExternalSourceOrScopeObservationDigest,
        ConsumerObservationDigest,
        ConservativeConsumerResultDigest,
        KeyDestroyedReceiptDigest,
        Reason = FreshConsumerTlsProbeUnavailableAfterKeyDestruction
      }
    | Ambiguous {
        BoundedObservationDigest,
        BoundedReason
      }

Every disposition also binds InstallationId, CaGeneration, TargetId, exact
consumer/release identity, certificate identity, reference hostname,
post-removal authority observation digest, observed_at, and expires_at. A live
TLS result uses a fresh otherwise-valid leaf so an unrelated hostname, expiry,
or key error cannot masquerade as removal evidence. The conservative variant is
available only after the exact historical key is terminally Destroyed and obeys
the stricter non-authorizing rules above; it is not a TLS result.

1. Before issuing a delete, the current target must equal the recorded
   store/domain, platform item identity, complete DER, DER SHA-256, normalized
   trust semantic, FlowProbeOwned receipt, and owned after image.
2. The durable InstallerOwner and create receipt MUST prove FlowProbe
   ownership. ExactUnownedPresent, ExternalPreExisting, and every preserved
   external target are never deleted. A current Absent observation issues no
   mutation and can terminate only through ExternallyRemoved.
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
   ResidualEffectiveTrustDispositionV1.PreservedExternalLive while a fresh probe
   is possible, or ConservativeExternalTrustPotential after exact key
   destruction, and never chase or delete that source.
8. Require effective TLS rejection only when the exact consumer observation
   proves no preserved external trust path remains, recording Rejected.
   Otherwise record the external residual separately. An unattributable
   residual records Ambiguous and enters RecoveryRequired, not authority to
   broaden removal.

Shared aggregate bundles, logical store collections, whole trust-setting
domains, browser profiles, keychains, NSS databases, or baseline backups MUST
NOT be restored or deleted wholesale.

RemoveTrust reaches Generated with a new GeneratedReceiptV1 after all FlowProbe-
owned trust is absent and all external pre-existing state is preserved,
regardless of a separately reported external residual trust path.
RemoveAndDestroy then:

1. proves every known owned target is absent, the identity set is complete, no
   signer request/connection can use the key, and no rotation needs it;
2. under the global mutation lock, first selects and fsyncs the exact helper
   ForwardOnly descendant that authorizes the remaining intended-Absent path.
   A FullChoice operation whose entry is still ResumeOrCompensate appends its
   sole intended-Absent refinement before any destroy intent or bootstrap
   query; a FullChoice entry already refined before owned removal verifies and
   retains that same outcome/path. A DirectDestroyOnly operation verifies the
   initially ForwardOnly(SafetyReservationConsumed, intended Absent) entry and
   never appends a second refinement. In every case the selected state and
   complete pending snapshot contain the byte-identical direct-destroy deadline
   binding and the timely continuation/selection record already selected at
   receipt consumption, and produce ForwardOnlyDestroyAuthorizationV1 before
   the key ledger can construct an intent;
3. reuses the continuation's preallocated installation-lifetime-unique
   KeyDestroyOperationId, verifies and append-selects the continuation's complete
   DirectRemoveAndDestroyKeyDestroy reservation record if exact recovery has not
   already done so, and builds
   the complete KeyDestroyIntentBodyV1 against the selected Ready record and
   internal non-aliasing tags, the current global key-ledger predecessor, and
   its exact pre-destroy CompleteKeyGenerationStateRoot and
   DestroyAuthority=DirectRemoveAndDestroy, including that exact forward-only
   authorization. After an exact NeverInvoked provider
   query it constructs the Destroy ProviderCallInvocationMarkerV1 and fsyncs the
   complete intent and marker in key DestroyPending, then select helper
   ProviderMarkerDurable with the same complete DestroyPending
   MarkerBearingKeyRecord evidence. DestroyPending.committed_at equals the marker's
   EffectiveMarkerCommittedAt; it may be selected after
   DestroyContinuationSelectionDeadline because the continuation, not this
   marker, was timely selected. The inline continuation/selection record,
   authorization, intent, marker, DestroyPending record, and current helper
   descendant all verify the same operation ID, forward-only state/path, and
   historical deadline authority;
4. invokes the exact idempotent key-authority destroy operation with
   `{KeyDestroyOperationId, ProviderCallInvocationMarkerDigest}`; recovery may
   make the one first call only when the current DestroyPending marker is bound
   to the timely selected continuation,
   the exact provider result is NeverInvoked, and the current helper state is
   the bound ForwardOnly state or a valid retaining descendant, using the same
   ID/marker even after the continuation deadline. In-flight or terminal status is
   query-only, and recovery never generates another ID or marker while unresolved;
5. obtains the complete destroy-bound NegativeKeyPossessionResultV1 and then
   independently proves the provider operation is terminal and the exact key
   object is absent with the complete same-operation
   DestroyPostCallProviderAbsenceProofV1;
6. fsyncs Destroyed in the key ledger with the exact
   DestroyPendingRecordDigest and KeyDestroyedReceiptV1 before both
   must_commit_by deadlines; and
7. fsyncs Absent plus AbsentReceiptV1 carrying the complete
   NoLiveOrAmbiguous KeyLedgerStateProjectionV1 and the correct identity-set
   update in the helper state index; no CA-key possession proof is required or
   permitted after destruction.

Failure or ambiguity destroying the key is RecoveryRequired. FlowProbe MUST NOT
report Absent while key material may remain or report Generated after deleting
a still-required key. A post-call proof not selected by its deadline is not
replayed: recovery performs a new typed observation against the same durable
destroy ID/intent when possible, otherwise remains KeyDestroyAmbiguous. An
unresolved uniqueness/aliasing collision forbids issuing the destroy call at
all.

## Rotation

Rotation is one compound TrustOperationId with at most one active and one
candidate/retiring CA and the two explicit consent phases defined above.

Before any RotateInstall trust-target mutation, the RotateCommit plan proves
that every controlled item locator for the candidate generation is
generation-scoped and disjoint from
the active generation, and the before image proves no candidate locator aliases
an active item. After exclusive creation, read-back MUST prove the assigned
platform item identities are also disjoint before any signer-switch or stable
commit. A collision fails closed; it cannot authorize replacement or reuse.
Independently, candidate key creation MUST prove installation-lifetime
distinctness of CertificateSpkiSha256, provider object, underlying private
secret, and NonExportableKeyIdentity from the active and every historical
generation. Target-locator disjointness does not imply key distinctness.

1. Choose TrustOperationId and obtain RotatePrepare binding the active identity,
   generation profile, canonical RequestedTargetScopeTemplateV1, and fallback
   policy. Under the trust mutation lock close the signing gate, allocate the
   next CaGeneration, CaInstanceId, fence, ProviderCreateOperationId, candidate-
   cleanup KeyDestroyOperationId, and key challenge. From the complete current
   provider-operation reservation vector, construct two consecutive proposed
   records in fixed order: RotatePrepareCandidateCreate followed by
   RotatePrepareCandidateCleanupDestroy. Bind the first complete record/resulting
   root in GenerationCommitmentBodyV1 and the second in the cleanup continuation;
   bind the exact pre-create CompleteKeyGenerationStateRoot and
   uniqueness-policy digest in the GenerationCommitment; prove complete
   universe/result capacity; compute one combined U1
   with the exact identity reservation and every sorted plan-exact first-use
   residual scope/current observer binding from the RotatePrepare template;
   construct GenerationCommitmentBodyV1 over H0/U1;
   then atomically consume the receipt into the replay index, reserve the exact
   future RotateCommit maximum, append the RotatePrepare recovery-disposition
   entry, and timely select the non-dispatching candidate-cleanup continuation
   and its selection record while selecting H1/U1 and entering
   InstallPending(RotateInstall) with GenerationCommitted, one RotatePrepare
   PhasePlan entry, an empty CompletePerTargetStepVector, and both provider key steps
   initialized as OperationReservationSelected with their complete consecutive
   reservation evidence before contacting the key authority. Through the helper-
   gated key operation, append-select both exact
   staged reservation records in that same order before any candidate-create
   bootstrap. A crash before either append recovers only the byte-identical
   staged suffix; neither append grants dispatch. That entry reaches only AwaitingLaterConsent or exact-old-base
   candidate cleanup. At this point the internal known set still
   contains the active SPKI, but the authenticated identity-set read is
   unavailable until the candidate outcome is exactly bound; it never
   publishes a partial active-only proof or invents an unknown candidate SPKI.
2. Run the same key-ledger Creating-before-provider and Ready-refinement
   protocol as generation. If no marker was selected, the same signed never-
   started proof/receipt route may instead terminalize the candidate generation,
   advance only the candidate-create key step to CreateNeverStartedTerminal with
   the complete native receipt, release only its identity reservation, retain both operation-ID reservation
   tombstones (including the unused cleanup ID), and return to the freshly
   verified exact old InstalledAndVerified base. Otherwise independently verify the candidate
   key/certificate and complete ProviderKeyUniquenessEvidenceV1. Construct the
   exact RotationDualReady projection, obtain the complete key-attestation-signed
   RotationReadyKeyProjectionAttestationV1, then under the lock construct
   RotationReadyProjectionSelectionRecordV1 over the selected predecessor state,
   journal/envelope/replay authority. Atomically select its exact replay-time
   successor and refine CandidateCaDescriptor to ExistingIdentity containing the
   complete KeyCreatedReceipt/uniqueness-evidence binding, post-Ready key
   authority epoch/revision/head, active/candidate Ready record digests,
   CompleteKeyGenerationStateRoot, attestation, and selection record. The
   record's EffectiveCommittedAt must be no later than attestation.must_select_by;
   then publish an identity set
   containing both exact, necessarily distinct SPKIs. Ambiguous creation or any
   SPKI/object/secret/identity collision
   enters RecoveryRequired with the pending snapshot and never exposes a
   guessed identity set, switches signer, or destroys either possibly aliased
   object.
3. Obtain a fresh RotateCommit receipt binding the same TrustOperationId, both
   exact CA identities, the complete RotationTargetBindingV1, its bijective
   candidate-template refinement, candidate GenerationCommitmentDigest,
   KeyCreatedReceiptDigest, ProviderKeyUniquenessEvidenceDigest, the exact
   post-Ready key head/root and both Ready record digests, CandidateKeyBindingDigest,
   the complete timely selected RotationReadyKeyProjectionAttestationV1/digest
   and RotationReadyProjectionSelectionRecordV1/digest, exact active-
   retire set, and immutable phase graph. Under the lock, revalidate every
   stable template field and every
   active retire disposition with its owner/external/derived/omission evidence,
   allocate the old-key KeyDestroyOperationId and construct its complete
   RotateCommitOldKeyDestroy reservation record from the current reservation
   vector, bind that record/resulting root into the old-key continuation, consume the operation-bound
   capacity reservation, append its exact phase plan, independent recovery-
   disposition entry, replay-index consumption record, and timely selected old-
   key-destroy continuation/selection record, and initialize the CandidateInstallSet
   CompletePerTargetStepVector with TargetVectorRole=PrimaryPhase to
   NotAttempted durably. The same atomic selection performs the checked
   RotateCommitAbortAdmitted Cartesian charge against the current signed target-
   vector, residual-scan, journal-link, and pending-snapshot maxima. Before this
   point no trust target is mutated. A failed or overflowing charge rejects
   RotateCommit and leaves ordinary RotatePrepare cleanup available. Refusal or expiry safely destroys only a proven uninstalled and
   provider-object/secret-distinct candidate under RotatePrepare; an unresolved
   collision cannot use cleanup destroy. The key authority append-selects the
   exact old-key reservation record before constructing its later intent; a crash
   may recover only that staged record and cannot allocate a replacement ID.
   Immediately before an allowed destroy,
   the RotatePrepare recovery entry is durably narrowed to ForwardOnly with its
   exact KeyDestroyIssued/ExactBase commitment,
   the successor pending state/snapshot and its byte-identical candidate-cleanup
   deadline binding are selected, and
   ForwardOnlyDestroyAuthorizationV1 is constructed from that exact helper
   descendant using the already-selected RotatePrepare continuation and its
   preallocated KeyDestroyOperationId. Only then may a KeyDestroyIntent with
   DestroyAuthority=RotatePrepareCandidateCleanup be constructed; that intent
   binds the complete attestation, selection record, selected pending state/head,
   and CandidateReadyRecordDigest.
   Its intent, later marker-bearing DestroyPending record, and forward-only
   authorization inline the same continuation before the one provider call. In
   this refusal/expiry-before-RotateCommit form no CandidateKeyBinding or
   RotationTargetBinding exists or is required.
   It may then restore the freshly verified old InstalledAndVerified business
   postcondition with a monotonic successor gate epoch.
4. Install and verify the new CA on CandidateInstallSet while preserving every
   ActiveRetireSet item and the old key.
   If any candidate-install step cannot safely reach the signer-switch
   precondition, the helper may choose only the pre-switch abort branch. While
   the gate is Closed and SignerSwitchSelectionEvidence is still
   NoneBeforeSignerSwitch, it freshly revalidates the old base and constructs
   the full CandidateAbortCompensationVectorV1 and compact
   RotationPreSwitchAbortAuthorizationV1 from the exact current predecessor.
   One RotationPreSwitchAbortSelection CAS atomically changes RotatePrepare to
   non-authorizing CleanupLockedByRotationAbort, changes only RotateCommit to
   ForwardOnly(PreSignerSwitchAbortCommitted), and initializes the independent
   compensation vector. Every candidate-install terminal anchor remains byte-
   identical. The CAS races SignerSwitchSelection on the same predecessor, so exactly one can
   commit. The selected fixed suffix advances only the abort compensation
   vector: it removes and verifies the exact-base fact for every OwnedCompensation
   row, reconciles DerivedCompensation rows in reverse dependency order, and
   retains Preserved/NeverAttempted rows. Only after a fresh complete scan
   selects Complete and its exact-base fact root may the retained RotatePrepare
   cleanup continuation destroy the candidate key using the same preallocated
   ID and complete inline compact authorization. Complete target exact-base
   evidence plus terminal Destroyed key evidence then selects the sole
   PreSignerSwitchExactOldBase. A crash at any boundary resumes that suffix; it
   never retries candidate installation, recreates the candidate key, or reaches
   the new-installed outcome.
5. Only while OptionalRotationPreSwitchAbortState is None, and after the new CA independently satisfies every InstalledAndVerified
   predicate and the old CA is freshly reverified, atomically narrow the
   RotateCommit recovery entry to ForwardOnly with the complete byte-identical
   SignerSwitchCommitted/intended-new-installed commitment, append the
   SignerSwitchSelection TrustOperationJournalRecordV1, switch the internal
   signer, and commit the complete SignerSwitchReceiptV1 over the resulting
   head/envelope/replay successor. The old base is no longer reachable after
   that selection; a crash selects the complete pre-switch predecessor or the
   complete receipt-bearing successor.
6. Append exactly one RotationRetirePhaseAdvance record from that complete
   receipt-bearing successor. Its crash boundary selects either the complete
   InstallPending signer-switch successor or the complete
   RemovePending(RotateRetireOld) successor, so recovery can replay the same
   phase advance without repeating the signer switch. The record retains both
   consent receipts and phase plans, carries the sealed ActiveRetireSet forward
   byte-for-byte, and initializes its separate step vector. Then remove only
   those old FlowProbe-owned
   exact target items, and then destroy the old key after the phase graph allows
   it and revalidates that the candidate's uniqueness evidence is still the
   selected Ready entry descending from the attested post-Ready root/head. The old
   key's destroy intent appends from that current global head, uses
   DestroyAuthority=RotateCommitOldKeyDestroy, binds CandidateKeyBindingDigest,
   RotationTargetBindingDigest, the selection-record digest and same complete
   root, and selects ActiveReadyRecordDigest as its target. Before constructing
   that intent, the current RemovePending state MUST be an authenticated
   descendant of the signer-switch ForwardOnly selection and retain its exact
   intended-new-installed path and byte-identical old-key-destroy deadline; the
   resulting ForwardOnlyDestroyAuthorizationV1 reuses the already-selected
   RotateCommit continuation and its preallocated ID and is inlined in the
   intent, marker, and DestroyPending record. That marker-bearing
   intent also inlines the same complete SignerSwitchPlanV1 and
   SignerSwitchReceiptV1/digests; a missing or nonidentical receipt forbids old-
   key destroy. That marker-bearing
   DestroyPending may first be selected after the continuation deadline and
   authorizes the one old-key provider call; it does not
   use the historical active Ready head as the global predecessor. The old
   destroy operation can therefore never
   address the candidate object or secret.
7. Commit InstalledAndVerified for the new CA and an identity set containing
   only identities still generated, installed, residual, drifted, or ambiguous.

No leaf is signed while either pending state is authoritative. A failure before
the signer switch safely compensates the new target/key and may return to the
freshly reverified old InstalledAndVerified state. A failure after the switch
keeps both identities known, the gate closed, and the operation pending or
RecoveryRequired until the old residual is settled. It never silently switches
back, drops an identity from ARCH-002 filtering, or calls partial rotation
complete.

## Crash and recovery

On key-authority, helper, user/admin-agent, Supervisor, Capture Core, login, or
machine start, trust.ca.v1 reconciliation runs before trust readiness or
identity-set availability is reported. An unresolved trust transaction blocks a network
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
call. A stale controller, user/admin-agent gate, consent, generation, plan, target,
revision, fence, or key epoch has no side effect. An OS operation that may
complete after process death without a durable platform operation identity that
recovery can settle is unsupported.

A user or administrator trust agent receives only a one-use online permit
sealed by the helper. It cannot act from an offline ticket. The helper holds
the mutation lock from authority reread through intent fsync, live exact-
context action, exact read-back, durable result, and permit consumption.
Helper/gate loss before durable-result acknowledgement forces the agent to
stop; any platform UI that can continue and mutate after that loss is
unsupported.

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

`InterceptionPolicyV1` is the closed type defined in TrustPlanBodyV1 above;
`RequestedInterceptionFallbackPolicy` is exactly that type, not a caller string
or a separately extensible enum.

PassThroughOnly never queries a signing key. PreferInterception uses transparent
pass-through whenever a fresh proof cannot be obtained. RequireInterception
returns a typed refusal before presenting a FlowProbe-issued leaf; it MUST NOT
silently pass through and report interception.

For every new intercepted TLS connection, the coordinator obtains one fresh
helper challenge and fixes the exact Capture Core connection/instance digest
and normalized leaf-sign request digest. It derives the residual-query
challenge exactly once as:

    SHA-256(
      "FlowProbe.TrustCa.InterceptionAdmission.v1\0" ||
      "residual-query-challenge\0" ||
      HelperChallenge ||
      ExactCaptureCoreInstanceAndConnectionDigest ||
      ExactNormalizedLeafSignRequestDigest
    )

Under the global mutation lock it runs ValidateReplayIndexTimeReadOnlyV1,
constructs one fresh ResidualQueryContextV1 with
Purpose=InterceptionAdmission and that QueryChallenge, and performs one complete
ResidualScanResultV1. The lock remains held through validation and both
admission signatures. No second challenge, context, partial target-only scan,
cached identity-set result, or terminal observation is admission freshness.
If this scan detects a changed projection, it may commit the same
state-appropriate successor defined for the identity-set query, but it discards
the entire admission context/scan and returns no admission proof. In particular,
an InstalledAndVerified change first closes the gate and selects Drifted; it is
never followed by an admission signature from either the predecessor or
successor.

Each required target is resolved from that one scan by this closed entry:

    InterceptionAdmissionTargetQueryEvidenceV1 {
      TargetId,
      SelectedInstalledTargetBusinessFact = TargetBusinessFactV1,
      SelectedInstalledTargetBusinessFactDigest,
      ResidualScopeId,
      ResidualQueryTargetObservation = ResidualQueryTargetObservationV1,
      ResidualQueryTargetObservationDigest,
      EvidenceResolution =
          Direct {
            ItemObservationKey,
            PlatformItemIdentityDigest,
            SortedUniqueRequiredConsumerEvidenceKeyVector
          }
        | Derived {
            DerivedTargetId,
            CurrentDerivedAuthoritySourceSet =
              CurrentDerivedAuthoritySourceSetV1,
            CurrentAuthoritySourceSetDigest,
            ResidualQueryFixedRegeneratorResultReceipt =
              ResidualQueryFixedRegeneratorResultReceiptV1,
            ResidualQueryFixedRegeneratorResultReceiptDigest,
            SortedUniqueDerivedMemberProofSemanticKeyVector,
            SortedUniqueRequiredConsumerEvidenceKeyVector
        }
    }

    SortedUniqueDerivedMemberProofSemanticKeyVector = [
      {
        PlatformItemIdentityDigest,
        ExactMemberIdentity,
        DerivedTargetId,
        ResidualQueryDerivedMemberProofDigest
      }
    ]

    SortedUniqueRequiredConsumerEvidenceKeyVector = [
      {
        ConsumerObservationKey,
        PlatformItemIdentityDigest,
        ExactMemberIdentity,
        ConsumerIdentityDigest,
        ConsumerReleaseTupleDigest,
        ReferenceHostnameDigest,
        ConsumerValidationProfileDigest,
        OutcomeResult = ExactAnchorAccepted {
            SuccessfulTlsResultDigest
          }
          | ExactAnchorRejected {
            NegativeTlsResultDigest
          }
          | ExcludedByDeclaredPolicy {
            BoundedReason
          }
          | ProbeUnavailableAfterKeyDestruction {
            ConservativeConsumerResultDigest
          }
          | Ambiguous {
            BoundedConsumerObservationDigest
          }
      }
    ]

The target vector is sorted strictly by TargetId and contains exactly one entry
for every member of RequiredTargetSetDigest. Each complete selected fact is the
exact TargetId entry in the selected InstalledAndVerified state's
SortedUniqueSelectedTargetFactStateVector. Each complete query observation is
the unique `(TargetId, HistoricalIdentityOrdinalOrNone)` object in the named
scope enumeration, shares the admission context digest, and has
Relation=MatchesSelectedFact. Direct resolution names the unique normalized
item and all consumer wrapper/result semantic keys used to recompute
EffectiveConsumerBusinessFactRoot. Derived resolution additionally carries the
unique current source set and `(DerivedResidualScopeId, DerivedTargetId)`
regenerator receipt, and names every unique
`(PlatformItemIdentityDigest, ExactMemberIdentity, DerivedTargetId)` member
proof. Consumer evidence keys are sorted and unique by
`(ConsumerIdentityDigest, ConsumerReleaseTupleDigest, ReferenceHostnameDigest,
ConsumerValidationProfileDigest, PlatformItemIdentityDigest,
ExactMemberIdentity)`; member-proof keys use the ordering above. Every named
object and digest MUST occur byte-for-byte in the inline scan;
every repeated context, scope, target, item/member, source, authority fact,
output, consumer, release-tuple, boundary-token, and freshness field MUST agree.
The resolved current context-free target fact and consumer-business root MUST be
byte-identical to the selected installed fact. Missing, extra, duplicate-key,
same-key/different-digest, cross-scope, cross-member, cross-consumer,
cross-release, or cross-query evidence invalidates admission.

The common signature-free admission statement is closed:

    InterceptionAdmissionProofV1 {
      Body = InterceptionAdmissionProofBodyV1 {
        SchemaVersion = 1,
        SignatureDomain = FlowProbe.TrustCa.InterceptionAdmission.v1,
        Purpose = InterceptionAdmission,
        InstallationId,
        CaGeneration,
        CaInstanceId,
        CertificateDerSha256,
        CertificateSpkiSha256,
        InstalledReceiptDigest,
        InstalledQuiescentBusinessPostconditionDigest,
        RequiredTargetSetDigest,
        RequiredTargetCount,
        SortedUniqueInterceptionAdmissionTargetQueryEvidenceVector,
        RequiredTargetQueryEvidenceRoot,
        TrustLifecycleStateDigest,
        TrustJournalHeadDigest,
        TrustStateRevision,
        KeyAuthorityEpoch,
        KeyStateRevision,
        KeyJournalHeadDigest,
        InterceptionGateEpoch,
        ExactCaptureCoreInstanceAndConnectionDigest,
        ExactNormalizedLeafSignRequestDigest,
        HelperChallenge,
        QueryChallenge,
        ResidualQueryContextV1,
        ResidualQueryContextDigest,
        ResidualScanResultV1,
        ResidualScanResultDigest,
        observed_at,
        expires_at
      },
      HelperAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = HelperAttestation,
        Context.TypedSignatureDomain = FlowProbe.TrustCa.InterceptionAdmission.v1,
        Context.TypedBodyFieldTag = "admission-body\0"
      },
      InterceptionAdmissionProofDigest,
      InterceptionAdmissionKeyPossessionProofV1 {
        Purpose = InterceptionAdmission,
        CaKeySignature
      }
    }

    InterceptionAdmissionProofDigest = SHA-256(
      "FlowProbe.TrustCa.InterceptionAdmission.v1\0" ||
      "signed-admission-proof\0" ||
      canonical({InterceptionAdmissionProofBodyV1, HelperAttestation})
    )

The complete HelperAttestation context covers the admission domain, field tag
`"admission-body\0"`, and canonical signature-free Body, and resolves only
through the current selected Active anchor. The proof digest covers canonical
`{Body, HelperAttestation}` under the distinct wrapper tag
`"signed-admission-proof\0"`; the body contains neither that digest nor either
signature. RequiredTargetQueryEvidenceRoot is the same-domain digest with field
tag `"required-target-query-evidence\0"` over the exact declared-count vector.
HelperAttestation and the purpose-specific CA-key possession signature
independently sign the exact same canonical Body. The key authority's typed gate
accepts only this domain/body schema and requires its signing public key to equal
CertificateSpkiSha256; neither signer signs arbitrary bytes. An old-installation,
historical, Invalidation-marked, manifest-supplied, caller, or other helper key
is invalid. Every context
Expected* field, selected state/business/receipt field, ledger tip, gate epoch,
universe, result, target evidence, QueryChallenge, EffectiveObservationTime,
observed_at, and expires_at MUST agree byte-for-byte. The construction order is
selected business/terminal anchors -> admission context -> complete scan and
target resolutions -> signature-free admission body -> two signatures, so no
object hashes itself or a downstream proof.

InterceptionAdmissionProofV1 is valid only when:

- the authoritative lifecycle state is InstalledAndVerified;
- both signatures and all cross-bound fields match;
- the complete admission context/scan and every required target resolution pass
  the rules above with no Changed or Ambiguous observation;
- the gate disposition is AdmissionEligible and its epoch is current for this
  one request;
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

    IdentitySetProofBodyV1 {
      SchemaVersion = 1,
      SignatureDomain = FlowProbe.TrustCa.IdentitySetProof.v1,
      QueryChallenge,
      ResidualQueryContextDigest,
      InstallationNamespaceRevision,
      InstallationNamespaceSelectorDigest,
      InstallationId,
      CaGenerationHighWater,
      TrustLifecycleStateTag,
      TrustJournalHeadDigest,
      TrustStateRevision,
      ResidualScanUniverseRevision,
      ResidualScanUniverseDigest,
      KeyAuthorityEpoch,
      KeyStateRevision,
      KeyJournalHeadDigest,
      InterceptionGateEpoch,
      ResidualScanResultDigest,
      CurrentInstallationCaSpkiCount,
      SortedUniqueCurrentInstallationCaSpkiSha256,
      CurrentInstallationCaSpkiSetDigest,
      RetiredConservativeSpkiCount,
      SortedUniqueRetiredConservativeCaSpkiSha256,
      RetiredConservativeSpkiSetDigest,
      SortedUniqueInterceptionCaSpkiSha256,
      FlowprobeCaExclusionSetDigest,
      observed_at,
      expires_at
    }

    IdentitySetProofV1 {
      Body = IdentitySetProofBodyV1,
      HelperAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = HelperAttestation,
        Context.TypedSignatureDomain = FlowProbe.TrustCa.IdentitySetProof.v1,
        Context.TypedBodyFieldTag = "proof-body\0"
      },
      KeyAuthorityAttestation = InstallationAttestationSignatureV1 {
        Context.SignerRole = KeyAuthorityAttestation,
        Context.TypedSignatureDomain = FlowProbe.TrustCa.IdentitySetProof.v1,
        Context.TypedBodyFieldTag = "proof-body\0"
      }
    }

HelperAttestation uses the selected helper attestation identity.
KeyAuthorityAttestation uses the separate key-authority attestation identity, not
any current or historical CA key. The key authority signature attests the
protected key-ledger projection and can therefore prove a destroyed or absent
CA record without retaining its signing key. Both signatures independently
sign the exact same canonical deterministic encoding of
IdentitySetProofBodyV1. Neither signature field is present in that preimage;
there is no recursive or signer-specific projection. Verification rejects a
body whose version, domain, query challenge, freshness, or either ledger
projection does not match the live query.

InstallationNamespaceRevision/Digest MUST equal the one root-owned selector
held under the same global lock. Its Current entry must resolve through the
fixed selector locator to this exact InstallationId/anchor, and its complete
retired conservative vector/count/digest must equal the proof fields.
ResidualScanUniverseRevision/Digest in the proof MUST match the selected
monotonic envelope. Every lifecycle state that returns a proof requires the
exact ResidualScanResultDigest produced for this query; there is no None or
cached-result variant. Proof observed_at equals the result
EffectiveObservationTime, proof expires_at equals the result expires_at, and
both are evaluated with the ReplayTimeHighWater rule above. The selected state,
helper/key ledgers, and result's residual projection together MUST equal the
complete current-installation vector/count/digest. The final
SortedUniqueInterceptionCaSpkiSha256 is the sorted unique union of that vector
and the namespace's retired conservative vector; its count and
FlowprobeCaExclusionSetDigest recompute from that complete union. A current-only
set, retired-seal digest without its vector, namespace revision change, or
caller-composed union is invalid.
The result carries the complete ResidualQueryContextV1; its digest equals the
proof field, and its QueryChallenge, selected predecessor, ledger/envelope
fields, universe, EffectiveObservationTime, and expiry equal the proof and live
locked state byte-for-byte. A context, nonce, or challenge from another call is
never reusable even while its time window remains open.

The digest is exactly the ARCH-002 formula:

    SHA-256(
      "FlowProbe.Egress.FlowProbeCaExclusionSet.v1\0" ||
      uint32_be(count) ||
      sorted_unique_interception_ca_spki_sha256...
    )

The count is a mathematical set cardinality that MUST be at most
`UINT32_MAX` before encoding. Manifest admission, every capacity reservation,
reservation-to-identity refinement, and every answerable union independently
enforce that bound. A would-be `UINT32_MAX + 1` result is rejected before
consent/provider/platform side effects; it is never truncated, wrapped, or
encoded as unavailable-after-mutation.

The sorted set contains every known FlowProbe CA identity that is:

- Generated, InstallPending with ExistingIdentity, InstalledAndVerified,
  RemovePending, or Drifted;
- a current, candidate, retiring, partially installed, externally removed,
  residual, or key-destroy-pending identity; or
- named by an authenticated unresolved record whose target/key absence is not
  yet proven.

A GeneratePending or RotateInstall GenerationCommitted descriptor without an
exact identity makes the query IdentitySetUnavailable. The mutation lock
prevents a read from crossing key creation, and no response omits a candidate
whose provider outcome is unknown.

Post-dispatch CreateUnapplied contributes no SPKI only when the key ledger's
complete CreatePostCallProviderAbsenceProofV1 is cross-bound to the helper
pending operation, exact Creating ancestor, and complete pre-call proof.
CreateUnappliedNeverStarted contributes no SPKI only when its complete selected
reservation, two exact NeverInvoked/None bootstrap observations,
CreateNeverStartedProviderAbsenceProofV1, and KeyCreateNeverStartedReceiptV1 are
cross-bound to the same helper pending snapshot and direct NoRecord predecessor.
While the helper still carries GenerationCommitted, the query remains
unavailable; after the exact receipt-bearing compensation returns to the base
state, the replay tombstone and applicable terminal key record remain audit
evidence but add no CA identity.

Absent may return an empty current-installation component only when the helper
and key ledgers are valid, every historical owned target is proven absent, every
key is destroyed, and no unresolved identity record exists. The authoritative
machine response is empty only when that component and the namespace's complete
retired conservative component are both empty. RecoveryRequired returns
the complete known set only when completeness itself is proven; otherwise the
query fails with IdentitySetUnavailable.

Every identity-set query, in every lifecycle state and without exception,
first runs ValidateReplayIndexTimeReadOnlyV1 without selecting or writing any
state, creates a fresh ResidualQueryContextV1 with
Purpose=AuthenticatedIdentitySetRead, and performs a new complete
ResidualScanResultV1 under the same global mutation lock held through state
selection and both proof signatures. A previously selected scan/result,
selector-current slot, notification, mtime, watch-cadence result, admission
proof, or unexpired receipt is never freshness for a new query. A
GenerationCommitted descriptor whose exact public identity is not yet bound,
an ambiguous key/platform outcome, or an incomplete universe/scan remains
IdentitySetUnavailable.

Every direct or derived target fact used by the scan is proven by a complete
same-context ResidualQueryTargetObservationV1 carried in the applicable
enumeration. A derived result additionally resolves its complete current direct
source set, regenerator receipt, and member proof in that same scan. The
immutable TerminalTargetObservationV1 is only the selected historical anchor;
its elapsed must_select_by time is irrelevant after selection and it is never
mistaken for query freshness. Expired query context/evidence is discarded and a
new invocation starts with a new nonce and scan; no Generated or
InstalledAndVerified same-state journal transition is needed merely to refresh
evidence.

The helper computes the current-installation component as the sorted unique union of every
current/candidate/retiring/pending/unresolved identity proven by the selected
helper/key ledgers and every historical identity whose fresh scan proves a
PreservedExternalLive or ConservativeExternalTrustPotential path. It then unions
that component with every SPKI in the selected namespace's retired conservative
vector to form the machine response. If the current component,
every context-free TargetBusinessFactV1, and the residual projection are
byte-identical to the selected state/index, it may sign from that exact state
without changing TerminalVerification, journal head, TrustStateRevision, or
stable receipt, but only while the selected envelope's attestation anchor is
Active. RecoveryRequired(AttestationAnchorInvalidated) returns
IdentitySetUnavailable even when the facts are byte-identical. If
they changed, it must first select exactly one state-appropriate observation
successor while still holding the lock:

- Absent, or RecoveryRequired(None, SignedGateClosed) retaining Absent, uses
  ResidualObservationReconciled and the RecoveryRequired case exits to Absent;
- Generated or InstalledAndVerified uses EnterDrifted, closing the gate before
  the changed projection is published;
- GeneratePending with ExistingIdentity, InstallPending, or RemovePending uses
  RefreshPending only for an off-plan residual change that leaves every planned
  target/key step byte-identical;
- Drifted uses RefreshDrifted without changing its last stable business digest;
  and
- every other RecoveryRequired(SignedGateClosed) with a complete known set uses
  RefreshRecoveryRequired without changing either retained snapshot.

RecoveryRequired(AttestationAnchorInvalidated) always returns
IdentitySetUnavailable and performs no observation, journal, envelope, receipt,
or lifecycle-state write.

If a pending scan changes any planned target/key observation, the query returns
IdentitySetUnavailable, the sealed operation's existing typed step
reconciliation records that change, and a later query starts with a new scan;
the residual-observation record cannot edit or bypass that authority path.

The scan that detected a change is commit evidence only and MUST NOT be signed
or returned. After the applicable successor is durably selected, the helper
discards that entire context, nonce, enumeration, result, and every nested
query observation. It then creates a new context and nonce against the selected
successor and performs a new all-scopes before-token/enumeration/after-token
scan. Only when every new current fact is MatchesSelectedFact and every other
projection is byte-identical to that successor may the helper sign the new
result. If the applicable observation successor, enumeration, freshness, or
selector commit is incomplete/unstable, or the second scan changes again, the
query returns IdentitySetUnavailable rather than any previous set. A
selector-before-commit crash cannot turn an old set into a newly fresh result:
retry rescans from whichever complete state is selected, always with a new
context. External historical-identity add/remove and cross-scope movement are
therefore detected inside the query, including between periodic watches.

For a changed fact, the successor journal record separately binds the expected
ResidualQueryContextDigest, ResidualScanResultDigest, predecessor state, and the
closed fields from which the resulting context-free business projection or
pending selected-target projection is deterministically reconstructed. A
quiescent resulting business digest hashes no query context, observation, scan,
result, or receipt. RefreshPending instead binds the predecessor complete
snapshot and resulting selected-target root/count; its successor snapshot binds
the record only through PendingSnapshotLineage and is constructed after
the successor journal head/envelope. Thus the changed path has the one-way order
old state -> old query context -> changed facts/result -> residual-observation
record -> successor journal head/envelope -> successor business receipt or
pending snapshot/state -> new query context -> byte-identical fresh
facts/result -> response. The old scan is never embedded in the new context or
response. The byte-identical path performs no state or replay-time write. A
query crash leaves no target-row artifact; after any already-selected successor,
retry uses a new context and full scan.

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
- recording and atomically selecting the non-authorizing Absent residual
  scan universe/result and observation record/receipt without manufacturing a
  trust operation;
- prepare, apply, compensate, commit, and recovery steps with per-target
  before/after observations and durable phases;
- one-use online permits for an exact authenticated user or foreground
  administrator trust agent and an exact CA key authority operation;
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
      Executor = AuthenticatedAdministratorTrustAgent
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
separate foreground GUI-session action performed only after native
administrator authentication. The LaunchDaemon helper retains the journal,
lock, and one-use online gate but does not call the Admin Trust Settings API.
Cancellation, authentication failure, GUI-session loss, gate loss, or a call
that may continue after gate loss is InteractionRequired, PermissionDenied, or
unsupported as applicable; it never falls back to a root daemon call.

AppleSslTrustRootV1 normalizes exactly one trust dictionary:

    Policy = SecPolicyCreateSSL(server = true, hostname = null)
    PersistedPolicyOid = kSecPolicyAppleSSL
    PersistedPolicyName = sslServer
    Result = kSecTrustSettingsResultTrustRoot
    ApplicationConstraint = Absent
    PolicyString = Absent
    AllowedError = Absent
    KeyUsage = Absent

An absent, client, or unknown policy name, an empty or null all-purpose Always
Trust setting, TrustAsRoot for this self-signed certificate, application
constraints, hostname strings, and allowed-error exceptions are forbidden.
SecPolicyRef pointer identity and raw property-list byte order are not semantic
identity; verification normalizes the closed fields above and negative
client-auth evaluation proves the server-only distinction.

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
ConditionalExactMutationUnavailable, StableStoreRevisionUnavailable, and
CrashDurabilityUnproven. Admin also
carries AuthenticatedAdministratorAgentUnavailable and
InteractiveAdministratorAuthorizationUnavailable. The System target is
UnsupportedImmutablePlatformDomain. A successful SecTrustEvaluateWithError
result is effective-trust evidence, not a substitute for those missing
mutation guarantees.

Safari, Chrome, and Firefox are distinct consumer rows. System-trust use must
be verified with a fresh real TLS connection and correct hostname. Firefox OS
enterprise-root integration may be disabled and its NSS database is never
modified. Chrome/Firefox private stores, profile policy, pinning, embedded TLS
stacks, and applications with private CA sets are excluded.

Primary references are Apple's
[Trust Settings interface](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/trust/headers/SecTrustSettings.h),
[Trust Settings policy names](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/trust/headers/SecTrustSettingsPriv.h),
[Trust Settings administrator interaction](https://developer.apple.com/documentation/security/sectrustsettingscopytrustsettings%28_%3A_%3A_%3A%29),
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
regenerator/hook execution, a release-bound monotonic/no-ABA snapshot token,
partial-output recovery, and real-host durability are proved.

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
source lifecycle, a release-bound monotonic/no-ABA snapshot token, global-
regenerator recovery, and real-host proof exist.

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
transaction/locking, monotonic no-ABA revision, and crash-recovery contract.

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
inline into every TrustPlanV1. Its schema is closed:

    TrustCapabilitySubjectV1 =
        ExactTarget {
          TargetId,
          TargetKind,
          ExactStoreOrDomainScope,
          InstallerExecutor
        }
      | DerivedOutput {
          DerivedTargetId,
          PrimaryAuthorityTargetId,
          CompleteReadOnlyRegeneratorInputScopeSetDigest,
          FixedRegeneratorIdentity
        }
      | TemplateDirectTargetCapability {
          TemplateEntryKey,
          TargetScopeTemplateEntryV1 {
            InstallerExecutorClass = PrivilegedHelper
              | AuthenticatedUserTrustAgent
              | AuthenticatedAdministratorTrustAgent
          }
        }
      | TemplateDerivedOutputCapability {
          TemplateEntryKey,
          TargetScopeTemplateEntryV1 {
            InstallerExecutorClass = DerivedByTemplate
          },
          ExactTemplateDependencyEdge = {
            DependentTemplateEntryKey,
            AuthorityTemplateEntryKey,
            EdgeKind = DerivedBy
          }
        }
      | KeyProvider {
          KeyProviderProfileDigest,
          ProviderAndVersion
        }
      | Consumer {
          ConsumerIdentityDigest,
          ConsumerReleaseTupleDigest,
          ConsumerValidationProfileDigest
        }

    TrustCapabilityEvidenceV1 =
        DesignReviewed
      | DeterministicConformancePassed { EvidenceArtifactDigest }
      | RealHostInstallPassed { EvidenceArtifactDigest }
      | RealHostCrashRecoveryPassed { EvidenceArtifactDigest }
      | RealHostExactUninstallPassed { EvidenceArtifactDigest }
      | RealConsumerTlsPassed {
          ConsumerIdentityDigest,
          ConsumerReleaseTupleDigest,
          EvidenceArtifactDigest
        }

    TrustCapabilityRowV1 {
      Subject = TrustCapabilitySubjectV1,
      SubjectSemanticKeyDigest,
      BackendReleaseTupleDigest,
      StaticSupport,
      DynamicReadiness,
      EvidenceCount,
      SortedUniqueEvidenceVector = [ TrustCapabilityEvidenceV1 ],
      ReasonCount,
      SortedUniqueReasonVector,
      RequiredPermission,
      RequiredInteraction,
      ExcludedScopeCount,
      SortedUniqueExcludedScopeVector,
      observed_at,
      expires_at
    }

    TrustCapabilitySnapshotBodyV1 {
      SchemaVersion = 1,
      DigestDomain = FlowProbe.TrustCa.TrustCapabilitySnapshot.v1,
      InstallationId,
      TrustOperationId,
      PhaseRole = Generate | Install | Repair | RemoveTrust | RemoveAndDestroy
        | RotatePrepare | RotateCommit,
      SignedProductManifestDigest,
      CapabilityRowCount,
      SortedUniqueCapabilityRowVector = [ TrustCapabilityRowV1 ],
      observed_at,
      expires_at
    }

    TrustCapabilitySnapshotV1 {
      Body = TrustCapabilitySnapshotBodyV1,
      TrustCapabilitySnapshotDigest
    }

    TrustCapabilitySnapshotDigest = SHA-256(
      "FlowProbe.TrustCa.TrustCapabilitySnapshot.v1\0" ||
      canonical(TrustCapabilitySnapshotBodyV1)
    )

SubjectSemanticKeyDigest uses the snapshot domain and field tag
`"subject-key\0"` over the complete canonical subject. Rows are strictly sorted
by that digest and reject the same semantic key with different bytes. Every count
is the exact canonical uint32 length of its adjacent vector. Evidence is sorted
by `(variant tag, consumer identity/release when present, EvidenceArtifactDigest)`;
reasons by their closed numeric tag; excluded scopes by their canonical complete
scope bytes. CapabilityRowCount is no greater than
TrustCaManifestBoundsV1.MaximumTrustCapabilityRowCount; each adjacent per-row
vector is no greater than its exact MaximumTrustCapabilityEvidenceCountPerRow,
MaximumTrustCapabilityReasonCountPerRow, or
MaximumTrustCapabilityExcludedScopeCountPerRow field; and the complete canonical
snapshot is no larger than MaximumTrustCapabilitySnapshotEncodedBytes.
The body contains neither its digest nor a TrustPlan identifier. InstallationId,
TrustOperationId, PhaseRole, and SignedProductManifestDigest equal the enclosing
TrustPlan byte-for-byte. Unknown subjects,
evidence/reason tags, duplicates, omitted required rows, count mismatch, invalid
time interval, or a manifest mismatch fail closed.

The snapshot contains exactly one row for every exact target, derived output, key
provider, and claimed consumer in the TrustPlanResourceGraphV1 and no unrelated
row. A RotatePrepare template graph instead contains exactly one template
capability row for every TargetScopeTemplateEntryV1: a direct entry uses
TemplateDirectTargetCapability and a DerivedByTemplate entry uses
TemplateDerivedOutputCapability with the unique byte-identical dependency edge.
It contains no ExactTarget/DerivedOutput row because no TargetId exists yet.
Every other phase forbids both template subject variants. Missing, extra,
duplicate, cross-template, or direct/derived-tag-substituted rows fail closed.
Every repeated target/scope/executor, regenerator, provider profile/release,
consumer/release, backend release tuple, permission, interaction, and exclusion
field is byte-identical to the plan, target/template, privilege aggregate, and
signed manifest. Snapshot expires_at is no later than the checked nonwrapping
sum of observed_at and
TrustCaManifestBoundsV1.MaximumTrustCapabilityLifetime; overflow invalidates the
snapshot. Snapshot observed_at is no later than plan construction and
plan/consent expiry is no later than snapshot expires_at.

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

The evidence vector independently records the variants above. Missing evidence
is explicit; these values are not collapsed into a maximum level.

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
    AuthenticatedAdministratorAgentUnavailable
    InteractiveAdministratorAuthorizationUnavailable
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
| macOS User | Exact console user, User Trust Settings plus resolved user file keychain, GUI authentication | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | AuthenticatedUserAgentUnavailable, ConditionalExactMutationUnavailable, StableStoreRevisionUnavailable, CrashDurabilityUnproven, RealHostUnverified |
| macOS Admin | Admin Trust Settings plus exact System.keychain, foreground GUI administrator agent under one-use helper gate | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | AuthenticatedAdministratorAgentUnavailable, InteractiveAdministratorAuthorizationUnavailable, ConditionalExactMutationUnavailable, StableStoreRevisionUnavailable, CrashDurabilityUnproven, RealHostUnverified |
| macOS System | Apple System Trust Settings, observe only | UnsupportedImmutablePlatformDomain / Unsafe / DesignReviewed | ImmutablePlatformDomain; no mutation is permitted |
| Debian 13 amd64, ca-certificates 20250419 research row | Fixed source below administrator-managed /usr/local/share/ca-certificates, root helper; outputs separate | UnsupportedByProductPolicy / Unsafe / DesignReviewed | TrustPurposeOverbroad, TrustSourceParentNotExclusive, ConditionalExactDeleteUnavailable, StableStoreRevisionUnavailable, GlobalRegeneratorRecoveryUnproven, HookInventoryUnbounded, RealHostUnverified |
| Ubuntu 24.04 LTS amd64, ca-certificates 20260601~24.04.1 research row | Fixed source below administrator-managed /usr/local/share/ca-certificates, root helper; outputs separate | UnsupportedByProductPolicy / Unsafe / DesignReviewed | TrustPurposeOverbroad, TrustSourceParentNotExclusive, ConditionalExactDeleteUnavailable, StableStoreRevisionUnavailable, GlobalRegeneratorRecoveryUnproven, HookInventoryUnbounded, RealHostUnverified |
| Fedora 44 x86_64, ca-certificates 2025.2.80_v9.0.304-7.fc44 research row | Purpose-policy source directly below /etc/pki/ca-trust/source, root helper; p11-kit and outputs separate | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | ReleaseTupleUnselected, PurposeConstraintEncodingUnproven, PurposeConstraintPropagationUnproven, ConditionalExactDeleteUnavailable, StableStoreRevisionUnavailable, GlobalRegeneratorRecoveryUnproven, RealHostUnverified |
| RHEL 9.8 x86_64 research row | Purpose-policy source directly below /etc/pki/ca-trust/source, root helper | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | ReleaseTupleUnselected, PurposeConstraintEncodingUnproven, PurposeConstraintPropagationUnproven, ConditionalExactDeleteUnavailable, StableStoreRevisionUnavailable, GlobalRegeneratorRecoveryUnproven, RealHostUnverified |
| CurrentUser NSS SQL database | One absolute selected user-owned database, exact owner-context authenticated user trust agent, and exact NSS/certutil/schema/consumer/OS tuple; never profile discovery | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | AuthenticatedUserAgentUnavailable, ReleaseTupleUnselected, NssConditionalDeleteUnavailable, NssDatabaseTransactionUnproven, StableStoreRevisionUnavailable, CrashDurabilityUnproven, RealHostUnverified; helper fallback and shared/browser-private stores excluded |
| SystemService NSS SQL database | One absolute selected service-owned database, exact DatabaseOwnerIdentity-bound privileged helper, and exact NSS/certutil/schema/consumer/OS tuple; never profile discovery | UnsupportedPendingArchitecture / Unsafe / DesignReviewed | ReleaseTupleUnselected, NssConditionalDeleteUnavailable, NssDatabaseTransactionUnproven, StableStoreRevisionUnavailable, CrashDurabilityUnproven, RealHostUnverified; user-context fallback and shared/browser-private stores excluded |
| Any derived Linux bundle or p11-kit projection | Read-only result of one exact primary authority edge, a manifest-bounded complete direct input-source set, and one fixed regenerator | Inherits the primary authority's equal-or-more-restrictive StaticSupport / Unsafe / DesignReviewed | Inherits primary authority reasons plus PurposeConstraintPropagationUnproven and GlobalRegeneratorRecoveryUnproven; additional observed sources grant no privilege or mutation authority; output is never directly mutated |

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
    InstallationLifetimeSpkiCollision
    ProviderKeyObjectAliasingDetected
    KeyUniquenessEvidenceUnavailable
    ProviderInvocationMarkerExpiredBeforeCommit
    ProviderInvocationMarkerMismatch
    ProviderOperationReservationMismatch
    ProviderOperationStateAmbiguous
    ConsentMissing
    ConsentExpired
    ConsentScopeMismatch
    ReplayDetected
    OperationIdCollision
    ReplayIndexCapacityExceeded
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
    KeyDestroyOperationCollision
    DestroyAuthorityMismatch
    KeyDestroyProofExpiredBeforeCommit
    KeyDestroyAmbiguous
    RotationReadyProjectionSelectionInvalid
    RotationReadyProjectionSelectionExpired
    IdentitySetUnavailable
    JournalFailure
    JournalCorrupt
    RecoveryRequired
    IntegrityFailure
    TimedOut

Every pending/error result reports only a stable bounded reason, safe observed
phase, TrustOperationId, generation, target identifier when authenticated,
retryability, and current non-authorizing state/revision. A terminal operation
result additionally reports exactly the closed TerminalDisposition, resulting
lifecycle tag/revision, optional public CA-identity digest, bounded target
results, and BoundedOperationEvidenceReferenceVector defined by the replay
schema; the initial response and every exact replay use that same canonical
public-result body. Platform error strings are sanitized diagnostics and never
wire enums. Retryability never authorizes
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
  noncanonical order, and boundary sizes, with the two Known*IdentitySetDigest
  fields proven byte-equal to the direct ARCH-002 digest and rejected when
  double-hashed under the quiescent-business domain, plus canonical
  ResidualScanUniverseV1, ResidualScopeEnumerationV1,
  ResidualScanResultV1, and ResidualIdentityObservationRecordV1 vectors with
  exact domains, zero-based uint32 revision-local ordinals, high-bit-first
  scope/identity/RequiredTarget bitmap bytes/padding, canonical uint32
  ContainerOrdinal max/+1, observer-schema-bound native identities, closed
  inline item/trust/ownership/consumer variants, complete direct/
  DerivedFromPrimaryAuthority/unknown member provenance, unique active versus
  retained primary execution lineage, exact four query-evidence vector counts,
  source-set/target-observation/regenerator/member-proof semantic-key
  uniqueness, and complete current direct source sets
  for newly generated aggregate outputs, primary-owned/additional-external,
  primary-external/additional-owned, and multiple mixed sources; omitted,
  duplicate, reordered, cross-scope/release/output/member, nested-derived, and
  source-set/regenerator/member-proof substitution negatives; exact terminal
  SourceKind-by-SourceDispositionEvidence matrix proving
  AdditionalExternalAuthority if and only if ExternalPreExistingAuthority,
  every FlowProbe-owned additional source resolves as AdditionalTargetAuthority
  with its complete target/fact/terminal anchor, and every forbidden cross-
  product is rejected; proof that
  additional sources never enter target DAG, consent, privilege, ownership, or
  delete authority; ownership/trust aggregate preimages, exact complete
  Ambiguous projection, no-cross-item-join negatives, consumer TLS success/
  negative/ambiguous/destroyed-key-probe-unavailable digest preimages with
  mandatory ResidualQueryContextDigest equality and cross-query/context,
  consumer, release, hostname, member, identity, profile, destroyed
  receipt/ancestry, time, and result-tag substitution negatives;
  one complete inline ResidualScopeEnumerationV1 per result scope, independent
  recomputation of every duplicate CompleteEnumerationRoot, and root-only,
  omitted, extra, duplicated, reordered, truncated, or cross-scope inline
  enumeration rejection both when the scan result is admitted and when its
  selected observation record is reconstructed;
  TargetBusinessFactV1, OperationTargetObservationV1,
  TerminalTargetObservationV1, TerminalDerivedAuthoritySourceSetV1,
  TerminalFixedRegeneratorResultReceiptV1,
  ResidualQueryContextV1, direct/derived
  ResidualQueryTargetObservationV1, current-source-set, query-regenerator, and
  derived-member-proof golden vectors; exact selected-current state-entry
  equality, optional terminal-anchor None rules, known-anchor omission, and
  selected-terminal-anchor equality,
  prior-row/query/challenge/nonce substitution, dependency-edge mismatch,
  native-output-versus-residual-wrapper recursion negatives,
  ExternalCurrentObserved/NoFlowProbeOwnershipProofV1 complete-ledger roots,
  zero-match requirements, current-owned/unresolved/alias negatives, and proof
  that the external projection grants no target/consent/mutation/delete
  authority; item/reservation/
  present-row sort keys, duplicate rules, and the explicit topological digest
  order; rejection when a TargetBusinessFact contains plan role/current step,
  context/time/token/observation/receipt/result or an ownership/source evidence
  wrapper; exact context-free FlowProbeOwned/External/None and source-business
  projections using stable CaPublicIdentityDigest rather than a query ordinal;
  acceptance of the terminal observation's inline context-free target fact and
  forward-only terminal source/regenerator objects, but rejection when it
  contains quiescent business/state/envelope, query/scan/response, stable
  receipt, or any reverse edge; rejection when any query object points backward
	  from its enclosing enumeration/result; TrustLifecycleStateBodyV1/wrapper
	  vectors with state-tag/evidence mismatch, self/reverse-digest, selected-fact/
	  terminal-anchor substitution negatives; the exact four-row quiescent payload/
	  business/stable-receipt/key-evidence/identity-set/gate-receipt matrix,
	  including complete payload-to-StateEvidence StableReceiptReference byte
	  equality, standard-versus-residual Absent receipt domains, Generated current
	  identity, Installed active identity/required-target set, Drifted authenticated
	  last-state-to-last-business ancestry, and cross-row/business/envelope/head/
	  identity/target/gate substitution negatives; complete pending- and last-
  quiescent-snapshot commitments with exact-base last-quiescent snapshot,
  stable-receipt, selected-current-fact/immutable-terminal-anchor vector/count/
  root, body/envelope/receipt mismatch negatives; all three closed
  PendingSnapshotLineage variants, with InitialPendingSelection admitting no
  predecessor, AuthorizedOperationSuccessor naming the exact predecessor
  snapshot and operation-journal record, and ResidualObservationSuccessor
  naming the exact predecessor snapshot and inlining the complete residual-
  observation record plus recomputed digest, with digest-only lookup,
	  body/digest mismatch, compacted-away preimage, self/reverse edge, and
	  cross-snapshot substitution negatives;
	  closed TrustLifecycleStatePayloadV1 golden vectors with the common complete
	  KnownCaPublicIdentitySetV1, exact PendingOperationStateReferenceV1
	  tag/kind/id/snapshot mapping, complete ConsentReceiptReferenceVectorV1,
	  RecoveryDispositionVectorV1, and DestroyContinuationAuthorityVectorV1
	  counts/order/preimages, and rejection of every former digest-only or duplicate
	  step/identity/disposition container; exact InterceptionGateDispositionV1
	  state-tag and gate-epoch transition matrix with cross-tag, premature
	  AdmissionEligible, stale epoch, double increment, and AdmissionEligible pending/
	  recovery negatives;
  first-phase ReceiptAndPhaseSelection using InitialOperationSelection versus
  RotateCommit using SubsequentRotationPhaseSelection plus an exact
  AuthorizedOperationSuccessor, with wrong/missing predecessor, reused initial
  tag, replaced RotatePrepare anchor, non-append vector change, and cross-
  operation/phase negatives;
  predecessor/record/successor topological construction, missing, forked,
  substituted, self, reverse, or cyclic edge rejection, and crash selection of
  the complete old or complete new snapshot only; RefreshPending retention of
  the byte-identical sealed operation core and exact planned-target steps while
  selecting a new residual projection, selected-target vector/count/root,
  state/envelope/journal head, and successor snapshot rather than claiming the
  predecessor snapshot is byte-identical; complete TrustPlanBodyV1/wrapper/ID/
  digest golden vectors with the complete signed manifest,
  TrustCapabilitySnapshotBodyV1/wrapper/digest, privilege aggregate, and closed
  NoTarget/ExactTarget/RotatePrepare/RotateCommit resource graphs; complete
  ImmutableTrustTargetPlanRecordBodyV1/wrapper/digest preimages and equality to
  every exact-set/plan target; capability subject/row/evidence/reason/exclusion
  counts, sorting, bounds, time, required-row completeness, and manifest/phase/
	  target/provider/consumer substitution negatives; complete
	  RotatePrepare template-direct/template-derived capability subjects with one
	  row per template entry and exact dependency edge, plus missing/extra,
	  exact-target-before-materialization, cross-template, and template-subject-in-
	  non-prepare-phase rejection; exact AuthorizedPhaseOutcomeVectorV1 phase
	  matrix for Generate, Install, Repair, RemoveTrust, RemoveAndDestroy,
	  RotatePrepare, and RotateCommit, including the distinctly tagged
	  PreSignerSwitchExactOldBase body, missing/extra/cross-base/candidate-cleanup-
	  substitution and generic-ExactBase-for-RotateCommit negatives; complete
  KeyProviderSelectionDeadlineBindingVectorV1 element/count/order/bound and
  exact empty-versus-nonempty phase-matrix vectors, including duplicate-role,
  cross-consent, cross-manifest, and create/destroy deadline-variant negatives;
  complete
  CandidateCurrentRetiringIdentityOrCommitmentVectorV1 variant/count/order/state
  matrices and commitment/existing/current/retiring identity substitution;
  complete PhasePlanBodyV1/vector/
  count/digest golden vectors and the closed PhasePlanAuthorityBindingV1
  variants; canonical ForwardPhaseStepV1 and
  ForwardOnlySelectionCommitmentV1 encodings, exact sorted allowed-selection
  matrices for Install/Repair OwnedRemovalIssued compensation to ExactBase,
  RemoveTrust OwnedRemovalIssued to Generated, Direct FullChoice
  OwnedRemovalIssued versus KeyDestroyIssued, DirectDestroyOnly
  SafetyReservationConsumed with mandatory exact owned removal before destroy,
  RotatePrepare cleanup, RotateCommit pre-switch abort, and RotateCommit signer
  switch. Exercise complete RotationPreSwitchAbortAuthorizationBodyV1/wrapper/
  digest, strict Ed25519 generic HelperAttestation domain with
  `rotation-pre-switch-abort-authorization-body` and signed-wrapper field tags,
  HelperAttestationKeyId, wrong algorithm/key/manifest/purpose/installation
  negatives, and exact predecessor-only digest topology. Exercise
	  CandidateAbortCompensationVectorV1 full CandidateInstallSet TargetId
	  bijection, TargetVectorRole separation, OwnedCompensation source
	  VerifiedOwned anchors, DerivedCompensation reverse dependency/order,
	  Preserved byte equality, InstallVerifiedUnapplied -> PreservedExactBase
	  no-side-effect classification without a NotAttempted rewrite,
	  NeverAttempted no-side-effect rows, exact monotonic
  progress, full fresh exact-base completion, and proof that every original
  PrimaryPhase terminal anchor remains byte-identical. Reject missing/extra/
  duplicate/cross-target rows, owned-as-preserved, derived-without-primary,
  derived-before-primary, in-flight/ambiguous source classification, ordinary
  TargetStepAdvance against an abort row, mutation of a source terminal row,
  incomplete/changed scan, and exact-base root mismatch. Exercise the fixed
  compensation -> retained-Prepare-cleanup -> old-base path and byte-exact
  compact authorization/vector equality in target compensation, key intent,
  marker, DestroyPending, terminal evidence, and outcome selection,
  and missing/extra/reordered/shortened/extended/cross-phase/cross-outcome path
  rejection. Reject a phase-plan path containing the future authorization,
  vector, scan, fact-root, receipt or result digest; reject any authorization-
  to-resulting-journal/envelope/snapshot/state edge or resulting-object-to-plan
  cycle. Exercise RotatePrepare ResumeOrCompensate ->
  CleanupLockedByRotationAbort and RotateCommit ResumeOrCompensate -> sole abort
  ForwardOnly as one indivisible CAS; reject partial/split CAS, two ForwardOnly
  entries, Prepare outcome selection after lock, signer switch after abort,
  replacement cleanup continuation/ID, or cleanup before Complete. Exercise
	  RotateCommitAbortAdmitted complete declaration-ordered charge-vector and
	  checked Cartesian worst-case max-minus-one/max/max-plus-one for replay,
	  recovery, target/key vectors, provider/key-ledger cleanup, journal/link,
	  outcome and compaction dimensions; uint32/size overflow, missing/duplicate/
	  reordered charge rows, historical/lowered manifest bounds, target/scope count
	  mismatch, and any actual legal abort descendant larger than its charge,
  mutation before admission, and proof that no independent reservation ledger
  or caller-chosen capacity value exists; byte-exact TrustOperationJournalRecordV1 vectors for every closed
  delta, predecessor state/snapshot/head/envelope/replay authority, selected
  delta, replay successor, effective selection time, and intended state
  revision, with unknown delta, wrong native evidence, late selection,
  InitialOperationSelection identity equality to its receipt/intent/plan,
  later PendingOperation identity equality to its selected/retained snapshot,
  EnterRecoveryWithoutPending fresh-identity first-selection, exact closed
  delta-tag/authority/identity compatibility table and cross-authority/tag
  substitution rejection, duplicate field,
  skipped predecessor, resulting-state/head back-reference,
  and non-delta field mutation negatives; TrustJournalNativeRecordV1,
	  TrustJournalRecordLinkV1, and Genesis/Append TrustJournalHeadV1 golden vectors,
	  including InstallationBootstrapSelectionRecordV1, InstallationGenesis, the
	  sole bootstrap native/link/revision-one Append mapping, exact initial
	  manifest/keyset/replay/history/universe/key-journal/no-key/Absent/empty-
	  identity/empty-target bindings, signature-free `bootstrap-body`, complete
	  selector-pinned two-key InstallationAttestationAnchorV1,
	  every nested-genesis equality above, DAG order and no-resulting-head backedge;
	  wrong algorithm/key/manifest/purpose, digest-equal-but-byte-different
	  duplicate, malformed empty-vector byte count, and mismatched selection/replay/
	  key/universe epoch/root/time negatives;
	  second bootstrap/genesis, ordinary-operation predecessor fields forced onto
	  bootstrap, partial selected initialization, wrong empty root, and crash
	  exposure of anything other than no installation or complete revision-one
	  Absent rejection;
  InstallationAttestationAnchorV1 and generic signature-context golden vectors,
  including distinct nonexportable provider-profile-bound keys, bytes32 unique
  nonce, unified role/InstallationId/epoch KeyId, the exact 29-entry closed
  manifest policy registry with every role/domain/body-tag and
  NoneBodyOnly-versus-Some(wrapper-tag) value,
  selector/IPC byte equality, same-body dual signatures, and every current
  envelope/index/key-genesis equality; reject checksum-recomputed key
  substitution, exportable/wrong provider profile, same key in both roles,
  absent/extra/duplicate policy rows, unknown/cross-role domain or tag,
  NoneBodyOnly/Some substitution, raw context-free signature, missing half of
  a dual signature, CA-possession substitution, and validation-to-selector
  TOCTOU; key loss/mismatch/suspected compromise must atomically select terminal
  Invalidated + gate Closed + RecoveryRequired through the exact
	  `[AttestationAnchorInvalidation, OperationSelection(EnterRecoveryRequired)]`
	  batch, matching sticky reason, and record-backed GateClosureEvidenceV1 without
	  GateClosedReceiptV1. Exercise both a verified predecessor and the unique
	  corrupt-selected-head plus unavailable-attestation-key quarantine batch with
	  retained last-authenticated ancestry and both TrustJournalIntegrity and
	  AttestationAnchorInvalidated reasons; reject a missing/reversed/standalone invalidation
  record, Active/invalidation or Invalidated/signed evidence pair, both evidence
  branches, and every later current signature/refresh/resume/reproof/
  reconciliation/provider/admission/target/key/phase mutation; reject in-place rotation, rekey,
  automatic reinitialize, disposition rollback, same InstallationId reuse, old
  anchor authorization of a fresh InstallationId, cleanup-incomplete reinstall,
  detached-history pruning, omitted invalidation native preimage, and retained-
  anchor/recovery-state/two-record-link count/byte max-plus-one, while
  retaining successful historical verification under the old exact anchor;
  InstallationRetirementCleanupEvidenceV1, RetiredInstallationSealV1, and
  InstallationNamespaceSelectorV1 golden vectors, including normal Absent and
  externally cleaned Invalidated retirement, exact historical target/key
  bijections, the checked key-generation-by-plan-target lifetime bound and
  pre-generation reservation, both selected role bindings plus every abandoned
  attempt's provider absence, complete content-addressed old-object resolution,
  fixed selector locator, Prepared/marker/result/Ready/abandonment event chains,
  CurrentRetirementPrepared gate closure, two role-ordered marker/result destroys,
  crash reconciliation by exact operation ID, and final
  CurrentRetirementSelected seal-plus-None CAS,
  old-Current -> retired/None -> preparation -> retired/fresh-Current CAS order,
  and crash selection of only complete event/current states; reject missing/
  extra/duplicate/unsorted retired or attempt rows,
  Current/retired overlap, reused InstallationId/epoch/anchor/nonce, wrong or
  missing seal/checkpoint/object, role public-key/provider-object/secret/
  nonexportable-identity reuse, provider call before marker, lost-CAS retry before
  AbandonedTerminal, mutable-current-slot digest in the namespace, orphan filesystem discovery, cleanup with any
  owned/live/ambiguous/unobservable row, invalidated-key cleanup authority,
  direct old-to-new replacement, two Current entries, namespace rollback/fork,
  retired/attempt-row deletion or reactivation, total retired+Current+Preparing
  anchor-count and namespace/attempt/history-capacity max-plus-one, and old
  anchor authorization of any fresh object;
  VerifiedPredecessor and recovery-only RecoveryQuarantinePredecessor anchors,
  exact universe-first/state-selection-second and invalidation-first/
  EnterRecoveryRequired-second batch order, zero/multiple-state-
  record, gap/fork/reorder/tag/digest/head/revision substitution, and resulting-
  head back-reference negatives; quarantine without EnterRecoveryRequired and
  TrustJournalIntegrity reason, caller-selected/invalid last-authenticated head,
  lost selected-unverifiable digest, ordinary-head adjacency imposed on a valid
	  quarantine bridge, unexplained revision gap, invalidation quarantine without
	  both required reasons, or quarantine used for mutation
  negatives;
  TrustJournalCompactionCheckpointV1 signature/
  digest vectors, nonempty complete verification-suffix recomputation across
  ordinary and explicit quarantine predecessor variants, detached-record exact
  sort-key/native-digest recomputation, retention, unchanged logical head, and
  omitted historical preimage rejection;
	  RecoveryResumeEvidence TrustJournalResumeAncestryV1 golden suffixes from the
	  retained pending head through EnterRecoveryRequired and zero-or-more legal
  residual/universe/non-authorizing successors to the selected RecoveryRequired
  head, with complete native/link/resulting-head preimages and wrong order,
  operation-only truncation, omitted RefreshRecoveryRequired, detached-record-
  without-link, incompatible native tag, gap/fork, and inclusion of the resume
	  record itself rejected; SelectorOrAncestryFailureResolutionV1 WithPending/
	  WithoutPending golden vectors, including byte-exact typed retained pending
	  snapshot fields and RecoveryWithoutPendingJournalAncestryV1 suffixes from the
	  payload's LastAuthenticatedTrustTip through the exact reason-introducing
	  EnterRecoveryRequired/RefreshRecoveryRequired record to the selected recovery
	  head, with Some/None, operation/recovery ID, detached/gapped/forked/cross-
	  episode/reason-not-in-suffix negatives; RecoveryKeyLedgerStateProjectionV1 full current
	  Creating/DestroyPending/Ambiguous projections, strict Ed25519
	  `attestation-body`/`signed-projection` preimages, installation/manifest-pinned
	  key-authority key ID, canonical uint64 count partition, sorted-unique
	  `(CaGeneration,CaInstanceId)` rows, and summary encoded bytes at max-minus-one,
	  exact max, and max-plus-one; count/addition/encoding overflow,
	  wrong-algorithm/key/manifest/purpose, helper/CA/provider signer substitution,
	  and a successor manifest lowering the bound below retained recovery evidence
	  are rejected; plus exact
	  reason-tag-to-RecoveryReasonResolutionV1 bijection and
	  ResolvedRecoveryTargetStepV1/ResolvedRecoveryAbortCompensationEntryV1/
	  ResolvedRecoveryKeyStepV1 Ambiguous-to-terminal
	  matrices; Purpose=RecoveryPendingResolution/WithPending anchor vectors with
	  exact operation/snapshot/reason/unresolved roots and helper-derived challenge,
	  one byte-identical complete context/scan across every query-backed pending
	  resolution, Purpose=RecoveryNoneReproof equality for the corresponding None
	  resolution vector, FailedResidualScopeId-to-complete-stable-scope equality,
	  and mixed-purpose/context/scan, stale-state, expired, missing-scope, or extra-
	  target-reproof negatives; missing/extra/cross-reason/cross-target/cross-provider resolution,
	  CreateNeverStarted-after-ambiguous, RecoveryPathExhausted exit, unrelated-row
	  mutation, stale projection, and digest-only terminal evidence rejection;
  FailureDispositionV1 initial retry-count-one/retry-plus-one/compensation
  transition vectors, phase/step-key and evidence-root equality, forbidden
  cross-phase outcome, retry reset/step switch/terminal refinement,
  and proof that it grants no mutation/recovery authority; CompleteKeyStepV1
  canonical empty-vector golden vectors for phases with no provider operation
  and nonempty vectors beginning only at reservation, plus complete
  Creating/DestroyPending marker-bearing record, Ambiguous record, and all four
  native terminal receipts; exact allowed transition graph, direct no-dispatch
  create terminal, create/destroy role substitution, marker-only/intent-only/
  removed NotAttempted/NoneBeforeAttempt/NoProviderOperation tags,
  generation-commitment-only/projection-only/provider-issued-boolean, skipped
  marker, unplanned/non-provider member, unmapped evidence variant,
  reversed/duplicate/
  post-terminal transition, record/digest/operation/phase/generation/continuation
	  mismatch negatives; CompletePerTargetStepV1/PerTargetStepEvidenceV1/
	  retryability golden vectors and exact ordinary/recovery transition matrix,
	  with ObservedOnly/Drifted/Failed operation-row, evidence-tag substitution,
	  missing current/terminal step equality, skipped/reversed/post-terminal, and
	  ambiguous-without-typed-resolution negatives. Exercise InitialInstall and
	  CandidateInstall MutationAmbiguous plus fresh exact-absence/no-side-effect
	  recovery to terminal InstallVerifiedUnapplied, exact-base outcome/abort
	  eligibility, and reject NotAttempted rewrite, installed-outcome satisfaction,
	  non-Absent before image, or stale/changed observation; terminal target/regenerator evidence
  first-selection before/at/after-must_select_by and immutable historical
  retention; RecoveryNoneReproofExit with exact last-quiescent snapshot,
  RecoveryWithoutPending identity, selected RecoverySelectionId, complete
  predecessor GateClosedReceiptV1, exact last-quiescent business-variant/
  reproof-tag/result-tag/stable-domain matrix,
  Purpose=RecoveryNoneReproof context, exact scan/context/
  challenge/time/expiry/key-projection equality to the CA-key proof when
  required, state-compatible stable receipt, monotonic successor, and a new
  resulting-head-bound RetainedClosed GateClosedReceiptV1 for Drifted; pending-
  operation ID, identity-read/admission context, caller challenge, cross-episode
  proof, expired scan, predecessor receipt reused as the resulting Drifted
  receipt, gate-receipt digest-only/signature/reason/epoch/key-tip,
	  and recovery identity as mutation-authority negatives; SignerSwitchPlanV1,
	  SignerSwitchSelectionChallengeV1, SignerSwitchFreshQueryEvidenceV1,
	  possession/satisfaction evidence,
  SignerSwitchSelection journal record, and SignerSwitchReceiptV1 helper
	  signature/digest vectors, including generic HelperAttestation context,
	  `challenge-body`/`signed-challenge` tags, exact current anchor/policy, exact current
	  manifest/window/deadline equality, wrong-purpose helper/key/algorithm/
	  historical-manifest negatives, and the same record's exact
  ResumeOrCompensate-to-ForwardOnly recovery transition, rejection of the
	  removed generic recovery-disposition encoding, exact one-challenge/one-
	  context/one-complete-scan binding with fresh MatchesSelectedFact rows for
	  every candidate and active target, possession equality to the same challenge/
	  context/scan, and EffectiveSelectedAt before the minimum consent/manifest/
	  challenge/context/scan/proof deadline; terminal-only candidate evidence,
	  changed/expired/missing scope rows, cross-scan/challenge/proof substitution,
	  or back-reference rejection; the following
  RotationRetirePhaseAdvance InstallPending-to-RemovePending transition with
  complete initialized ActiveRetire vector, signer-switch and phase-advance
  crash old-or-new selection, SignerSwitchForwardOnlySelection old-key-destroy
  anchor, and wrong
  candidate/active/plan/path/key/head/domain/signature rejection;
  all Generated/InstalledAndVerified/Drifted/Absent standard stable-receipt
  domains plus AbsentResidualObservationReceipt, tag/domain substitution,
  transition-head mismatch, missing signer, recursive-preimage, recovery-new-
  envelope, state-incompatible receipt, key-authority domain-whitelist,
  exact equality between this contract's key-authority attestation-domain
  whitelist and the ADR-0006 actor/authority whitelist, omission of
  NegativeKeyPossessionResultV1 or RotationReadyKeyProjectionAttestationV1,
  addition of any unregistered or role-incompatible domain,
  helper-ancestry, and key-ledger-projection negatives; LiveReady,
  ClosedDrifted, NoLiveOrAmbiguous, and pending-only RotationDualReady
  KeyLedgerStateProjection golden vectors,
  complete KeyLedgerRecordLink and CaGeneration-sorted state vectors/counts/
  roots, KeyJournalHeadV1 Genesis/Append body/wrapper/domain golden vectors,
  exact empty roots, one-installation/one-epoch genesis, first append, checked
  revision increment, and cross-install/second-genesis/variant-tag/predecessor/
  epoch substitution rejection, DestroyedTerminalKeyEvidence suffixes,
  gap/duplicate/fork/reordered/current-tip/compacted-preimage negatives,
  Generated/Installed missing or cross-business/envelope possession rejection,
  StableStateSelection exact current SignedProductManifestDigest, signed
  MaximumStableStatePossessionSelectionWindow, checked-add deadline, zero/
  `UINT64_MAX`/overflow/historical-manifest/shorter/longer-window negatives,
  committed_at-before/at/after-must_select_by boundaries and a
  timely selected proof remaining valid historical ancestry after the deadline,
  legal possession-free closed Drifted, mandatory possession-free Absent and
  AbsentResidual receipts, Ready/Creating/DestroyPending/Ambiguous-in-Absent
  rejection, duplicate SPKI/object/secret/NonExportableKeyIdentity tag rejection,
  destroyed-generation tag omission/relabel/ABA and old-destroy-affects-new-key
  negatives with exact Ready -> DestroyPending -> Destroyed ancestry equality,
  RotationReadyKeyProjectionAttestation body/signature/digest vectors, key-
  attestation/helper/CA-key signer substitution, before/at/after-must_select_by,
  exact current manifest and MaximumRotationReadyProjectionSelectionWindow,
  checked-add/zero/`UINT64_MAX`/overflow/shorter/longer/window-substitution,
  timely-selected historical retention, root/head/Ready-record/operation swap,
  quiescent-use, missing-selected-ancestor, and attestation-to-binding reverse-
  edge negatives; RotationReadyProjectionSelectionRecordV1 golden vectors with
  exact predecessor lifecycle state, complete pending snapshot, journal head,
  monotonic envelope, replay revision/root/high-water, attestation, commitment,
  effective selection time, replay successor, intended state revision, and
  SelectedForRotation descriptor; before/at/after-must_select_by, stale or
  downgraded replay authority, predecessor-snapshot substitution, result-root
  mismatch, and record-first-selected-after-expiry negatives, plus crash
  selection of the complete GenerationCommitted predecessor or complete
  selected refinement only,
  and CA-key/attestation-key signature-role substitution;
- exhaustive allowed/forbidden state transitions, nonwrapping generation,
  fence/revision monotonicity, stale controller rejection, idempotent identical
  replay, conflicting replay, pending-snapshot and last-quiescent-snapshot
  retention; EnterRecoveryRequired from every allowed quiescent/Drifted/pending
  predecessor with exact RecoveryWithoutPending versus PendingOperation
  identity, None/Some snapshot mapping, complete bounded reason/unresolved-
  target/current-fact vectors, LastAuthenticatedTrustTipV1 normal/quarantine
  variants, LastAuthenticatedKeyTipV1 current/retained-ancestor variants, and
  KnownCaPublicIdentitySetV1 complete identity/digest/count/order/direct-ARCH-002
  projection, immutable terminal-anchor retention, gate-close
  reason-key exact per-variant projection and scope/phase uniqueness,
  deterministic gate-reason priority, SignedAfterHead receipt/envelope equality,
  invalidation record/envelope/evidence equality without a receipt, and
  selector crash old-or-new behavior;
  missing/empty/free-form/cross-evidence reason, missing/extra/cross-target/
  duplicate AmbiguousTargetMutation-to-unresolved-row mapping, non-target reason
  attached to a target row, opaque/digest-only tip or identity, missing retained
  identity, same-SPKI/different-body, wrong tip-relation variant,
  refresh-as-first-entry,
  invented/reused recovery ID, dropped pending snapshot, mixed staged state, and
  EnterRecoveryRequired-as-mutation-authority and invalidated-sink successor
  negatives; RecoveryRequired(None, SignedGateClosed)
  observation-only reproof through the typed journal record and matching stable
  receipt for each non-Absent quiescent state,
  Absent ResidualObservationReconciled and RecoveryRequired(None)-from-Absent
  exits for residual empty-to-nonempty, nonempty-to-empty, and exact external
  scope/trust/certificate changes, byte-identical no-op, incomplete/unstable
  observation fail-closed behavior, exact RecoveryNoneReproof episode/context/
  helper-challenge binding on the recovery path, identity/admission/cross-
  episode context rejection, and old/new selector crash convergence,
  including byte-exact digest-free observation-record and dual-signed receipt
  vectors with nonrecursive preimages and no consent, operation, mutation,
  replay-capacity, or gate authority; exact resulting selected-target fact
  vector/count/root reconstruction with immutable terminal anchors retained and
  conflicting same-TargetId current facts rejected; manifest universe/enumeration/result
  identity/scope/byte max-minus-one, max, overflow, and every canonical integer-
  width boundary; Cartesian identity-by-scope worst-case proof; exact
  H0/combined-U1/pre-create-K0-root/commitment/H1 selector ordering, with
  generation commitment key epoch/revision/head/root and uniqueness-policy
  substitution negatives, including RotatePrepare with
  multiple new template scopes and no intermediate partial universe; identity
  reservation Ready, post-dispatch CreateUnapplied, and no-dispatch
  CreateUnappliedNeverStarted refinements; plan-exact first-use scope registration;
  observer-release refinement/update/rollback/crash with historical provenance;
  all-before-token/enumerate-all/all-after-token barriers and cross-scope move
  races; omitted, duplicated, reordered, substituted, truncated, over-cap, and
  token-changing scan rows; compact-then-rescan retention; state-appropriate
  EnterDrifted/RefreshPending/RefreshDrifted/RefreshRecoveryRequired successors;
  off-plan RefreshPending versus planned-target step-reconciliation routing;
  a terminal observation selected before must_select_by remaining a valid
  immutable anchor months later; a new same-context-fresh query observation
  answering from a byte-identical fact with no journal, state revision, target
  row, selector, or stable-receipt change; expired query evidence, old nonce/
  challenge, and cross-universe/scope/release/terminal-anchor rejection; changed
  facts forbidden from claiming MatchesSelectedFact and routed to the existing
  successor; proof that the changed scan is never signed, is discarded after
  selection, and is followed by a new-context/new-nonce full scan whose facts
  must be byte-identical to the selected successor; query crashes before/after
  successor selection and retry against only the selected state; golden DAGs
  for the no-write byte-identical path and old-business -> old query -> changed
  facts/result -> new-business -> new query -> byte-identical facts/result ->
  response, proving every business digest depends only on context-free facts;
  current-authority equality versus immutable-history ancestry across
  U1-to-Ready/CreateUnapplied U2, observer-binding U3, replay/time maintenance,
  and compaction, including missing/forked/reordered successor negatives;
  the generation-commitment staged-authority exception proving selected
  H0/U0, pure successor U1, intent H1, first-selected H1/U1, and rejection of
  any claim that H0/U1 was selected;
  `UINT32_MAX` identity-count success and pre-consent `UINT32_MAX + 1` rejection;
  and RecoveryRequired old-state versus new-Absent selector crash outcomes,
  byte-exact per-state QuiescentBusinessPostconditionBodyV1 and
  MonotonicSafetyEnvelopeBodyV1 vectors, Generate/post-dispatch
  CreateUnapplied/CreateUnappliedNeverStarted and
  RotatePrepare cleanup returning the same business digest with advanced
  generation/fence/authority/journal/replay/gate envelope fields,
  phase-scoped recovery-disposition append rules, the atomic two-entry
  RotationPreSwitchAbortSelection CAS with RotatePrepare CleanupLocked and the
  sole RotateCommit abort ForwardOnly, RotatePrepare/RotateCommit
  non-broadening, ResumeOrCompensate phase/base outcomes, the selected
  ForwardOnly direction after signer switch/removal/key destroy,
  monotonic journal/replay/gate envelope successors without rollback, and
  forbidden mutation/state substitution;
- crash injection before and after every journal fsync, index selector update,
  key-provider call, platform mutation, read-back, derived-output update,
  compensation, gate transition, and response delivery, including
  Creating-before-provider, provider-result-before-Ready, exact recovery by
  ProviderCreateOperationId, and DestroyPending-before-provider with exact
  recovery by installation-lifetime-unique KeyDestroyOperationId plus
  KeyDestroyIntentDigest; byte-exact KeyDestroyIntentBodyV1,
  NegativeKeyPossessionResultV1, ProviderKeyUniquenessEvidenceV1, and signed
  CreatePreCallProviderAbsenceProofV1,
  CreatePostCallProviderAbsenceProofV1,
  CreateNeverStartedProviderAbsenceProofV1, and
  DestroyPostCallProviderAbsenceProofV1 vectors; exact two-observation
  KeyProviderFreshnessWindowPolicyV1 lookup and byte equality, checked
  observed_at/EffectiveObservedAt plus MaximumProviderKeyUniquenessWindow,
  MaximumCreationPossessionWindow, and
  MaximumCreateNeverStartedObservationWindow, plus exact CreatePostCall and
  DestroyPostCall observation-window arithmetic, creation canonical-min
  equality, and zero/`UINT64_MAX`/overflow/shortened/extended/wrong-manifest/
  wrong-profile negatives; provider object/key alias or ABA after an expired
  uniqueness/possession/never-started observation must require a new complete
  proof and can never be hidden by a stale first consumption;
  exact two-observation
  NeverInvoked/None/token equality, NoRecord predecessor, marker-free proof,
  before/at/after fresh proof deadline, KeyCreateNeverStartedReceiptV1 and
  direct CreateUnappliedNeverStarted record/receipt/journal/helper cross-
  binding, identity-reservation release, exact-base return, and permanent
  rejection of any later marker/provider call; crash before and after staged
  provider-operation reservation, GenerationCommitted, either NeverInvoked
  observation, never-started key-record selection, helper terminalization, and
  exact-base selector; pre-as-post, create-as-destroy,
  operation/generation/provider/profile/key-head/helper-tip/challenge/time/token/
  signer substitution, same-proof replay, multiple candidates, unknown terminal
  status, unbounded evidence, and reverse-reference rejection; same destroy ID/
  same intent idempotent terminal query, same ID/different intent, different ID
  while unresolved, reuse after terminal record or compaction, cross-generation
  destroy, post-call/pre-Destroyed crash, single-Ready destroy whose target is
  also the global predecessor, rotation old-key/candidate-cleanup destroy whose
  target Ready record is historical but whose predecessor is the current global
  tip, and rewind-to-target-Ready/head, wrong-target-entry, intervening-record,
  or pre-destroy-generation-root substitution negatives,
  byte-exact DirectRemoveAndDestroy, RotatePrepareCandidateCleanup, and
  RotateCommitOldKeyDestroy DestroyAuthority vectors with non-substitutable
  receipt, phase-plan, pending-state/head, deadline, Ready role, target, and
  helper-tip bindings; pre-commit candidate cleanup requiring the complete
  timely selected rotation-ready attestation/selection record while forbidding
  CandidateKeyBinding and RotationTargetBinding in the ordinary refusal path;
  the post-RotateCommit pre-switch abort variant instead requires the complete
  compact RotationPreSwitchAbortAuthorizationV1, CandidateKeyBinding/
  RotationTargetBinding, current complete CandidateAbortCompensationVectorV1
  with fresh exact-base scan/root before key destroy, the RotatePrepare
  CleanupLockedByRotationAbort entry, sole RotateCommit abort ForwardOnly, and
  the retained RotatePrepare cleanup ID;
  old-key destruction requires
  both bindings and every sealed postcondition, and cross-variant, cross-phase,
  swapped-active/candidate, wrong-plan, or caller-extended-deadline rejection;
  byte-exact KeyProviderSelectionDeadlineBindingV1 create-marker versus destroy-
  continuation variants, exact receipt-issued-at plus signed-manifest-window
  arithmetic and canonical receipt-expiry minimum, with overflow, shortened,
  extended, missing, duplicate, cross-purpose/phase/step/generation/manifest,
  recovery-entry, or complete-key-step substitution negatives;
  DirectRemoveAndDestroyTarget, RotatePrepareCandidateTarget, and
  RotateCommitOldKeyTarget continuation commitments; complete
  DestroyContinuationAuthorityV1 and DestroyContinuationSelectionRecordV1
  bodies/digests with installation-lifetime-unique reserved destroy ID, exact
  predecessor state/snapshot/journal/envelope/replay and key-ledger authority,
  ForwardOnly outcome/path, before/at/after-selection-deadline and clock-
  rollback vectors; atomic receipt/plan/continuation/replay/pending-state
  selection, append-only rotation continuation retention, quiescent-versus-
  pending predecessor, target/ID/path/outcome/root/high-water substitution,
  self/reverse-edge and resulting-state/head reference rejection, and proof
  that the continuation alone grants no bootstrap, marker, provider-dispatch,
  target-mutation, or broader recovery authority;
  timeout-or-invalid-signature-as-negative, and intent/proof/receipt reverse-edge
  rejection; definitive
  post-call absence to CreateUnapplied, ambiguous absence, and rejection of a
  second create or label-based recovery; complete proof retention through
  compaction; proof observed_at/must_commit_by/record committed_at before,
  exact-boundary, after-boundary, delayed-first-consumption, clock-rollback, and
  timely-selected-then-months-later history cases; create recovery after the
  original operation deadline only when the complete marker-bearing Creating
  record itself was selected by its authenticated replay deadline; destroy
  recovery when the non-dispatching continuation/selection record was selected
  by its deadline, while the bound ForwardOnly state, intent, bootstrap,
  marker, and DestroyPending may be selected later on the exact sealed path;
  byte-exact marker-free read-only bootstrap NeverInvoked/None/token vectors,
  marker replay-revision/root/high-water and exact commitment/intent/key-
  predecessor/helper-tip/continuation/ForwardOnly bindings; crash before and
  after continuation selection, before and after ForwardOnly selection, after
  intent, after bootstrap, after marker-bearing record selection, and after
  provider acceptance, including recovery after arbitrary deadline passage in
  all direct FullChoice, DirectDestroyOnly, RotatePrepare candidate-cleanup,
  and RotateCommit old-key-destroy paths; one first dispatch only from the exact
  current marker-bearing key record plus the exact timely continuation, same
  reserved ID, same marker, exact retaining ForwardOnly helper descendant, and
  exact NeverInvoked result; query-only reconciliation for in-flight or
  terminal results; and late/missing continuation, ResumeOrCompensate current
  state, reverted/broadened path, continuation-as-dispatch, unbound bootstrap,
  marker-before-bootstrap, different marker, different or second operation ID,
  historical or backdated replay authority, provider-reported first-invocation-
  time as authorization, and mutable/missing/multiple/unknown status negatives;
  plus digest-free
  CaKeyRecordBodyV1 ancestry,
  duplicate-field mismatch, exact DestroyPending linkage, and all four
  signature-free key receipt bodies with committed_at and without recursive
  preimages, including inline complete CreationPreReady/uniqueness proof exact
  Creating head/challenge/pre-create-root and a separate fresh
  PostReadyGenerationVerification proof;
- all multi-target partial-success permutations, deterministic reverse
  compensation, preservation of pre-existing state, ambiguous outcome, and
  restart convergence without an installed boolean shortcut;
- exact minimal 20-octet positive serial and keyCertSign-only DER cases,
  rejected leading-zero/extra-KeyUsage cases, and same-subject,
  same-SPKI/different-DER,
  same-issuer-and-serial/different-DER, same-label/nickname, duplicate,
  replacement, missing, cross-scope, and foreign-owner negative cases;
- byte-exact CaConsentReceiptBodyV1, canonical body digest, strict Ed25519
  signed wrapper, signed-receipt digest, broker key ID, signed-manifest keyset,
  and signature preimage vectors; Active/Retired/Revoked key first-consumption
  and immutable historical-recovery boundaries, exact issuance selection
  revision/root/manifest-sequence/keyset tuple equality with TrustPlan, issuance
  against the current last record, `not_before <= issued_at < not_after`, and
  rejection of an old-prefix receipt issued at or after a successor effective
  time, including equal-time fail-closed and post-successor historical-manifest
  cases; keyset append/rotation,
  unknown/revoked/wrong-purpose key, wrong domain/algorithm/manifest, omitted/
	  duplicate/reordered/unknown field, body-versus-signed-digest, exact typed
	  RequestedInterceptionFallbackPolicy = InterceptionPolicyV1 equality across
	  plan/receipt/admission and fallback-policy substitution,
  privilege-aggregate, expected-base-tip, issued/expiry, and signature
  substitution negatives; consent cancellation, expiry, replay, operation/CA/target/policy substitution,
  intent/consumption crash boundaries, both rotation consent phases, refusal
  between them, target-template-to-exact-set bijection and stable-field
  refinement, template-entry-key dependency mapping, candidate-install versus
  active-retire set separation, all OwnedRemove/ExternalPreserve/
  DerivedReconcile/OptionalOmitted cases, complete rotation phase graph,
  derived-to-derived template and exact-edge rejection,
  phase-tagged two-set privilege/preauthorization aggregates, per-target
  permission/interaction equality, rejected cross-phase/set/template authority
  references including an authority edge whose dependent is not the current
  target, Observation-role preview encoding, ObservationOnly install-set rejection,
  empty NoneForGenerate bitmap, rejected
  absent/non-empty/short/long/mismatched bitmaps, noncanonical or duplicate
  template/target order, CandidateKeyBinding candidate/active generation,
  instance, public identity, SPKI, pre-create root, post-Ready key epoch/revision/
  head/root, active/candidate Ready record, uniqueness-evidence, Ready receipt,
  rotation-ready projection attestation, internal object/secret/identity tag,
  and phase-graph substitution,
  user-to-machine escalation, interaction loss, and recovery actions outside
  the consumed consent;
- replay-index golden vectors, expected-base substitution negatives, exact
  retry returning the inline old pending/terminal body without another side
  effect, digest-free result/tombstone/index bodies and nonrecursive roots,
  tombstone equality to canonical consent body, signed-receipt, and complete
  ConsentReceiptVerificationResult digests with verified keyset ancestry;
  ConsentVerificationHistoryRecordV1/StateV1 empty and one/many-append golden
  vectors with exact full verification-result preimages, installation/revision/
  predecessor/root/count/vector-byte equality, current envelope/state-index/
  journal/intent/resulting-state equality, and old-or-new selector crash
  behavior; duplicate receipt, cross-install, gap/fork/reorder, digest-only
  result, stale predecessor, compaction loss, rollback, and result/history/
  journal substitution negatives; count/state/result bytes at max-minus-one,
  exact max, max-plus-one and uint64/canonical-size overflow, plus proof that the
  root-owned empty-history bootstrap hook grants no helper-journal predecessor
  or operation authority;
  CompleteSignedProductManifestV1 body/digest/signature vectors and strict
  Ed25519/key-id/schema/canonical-body rejection; exact
  TrustCaManifestBoundsV1 plan/capability/replay/provider/reservation/key-ledger/
  residual/pending/journal/recovery/verification-history fields, five-role
  window vector, StableState/RotationReady windows, and keyset-selection count/
  encoded-byte maxima, with every uint32/uint64 width and count/byte limit at
  max-minus-one, max, and max-plus-one, with
  zero/`UINT64_MAX`/overflow/missing/extra/duplicate-role,
  local-default, shortened, extended, wrapper-digest, and unsigned-policy-subset
  negatives; append-only
  ConsentBrokerKeysetSelectionRecord/State vector, revision, predecessor/root,
  current manifest/keyset projection, same-epoch exact-digest, higher-epoch
  append/retire/revoke, quiescent reseal, and compaction-retention vectors;
  selection count and canonical-state bytes at max-minus-one, exact maximum,
  and max-plus-one, candidate bounds lowered below retained history, candidate
  bounds raised for an otherwise fitting append, uint64/canonical-size overflow,
  receipt verification against an oversized current selected state, and proof
  that compaction cannot reset the logical count/bytes or discard vector rows;
  successor-manifest lowering below retained provider reservations, key records,
  generation state, residual history/universe, journal checkpoint, or consent-
verification history, and a manifest-selection link that exceeds either
predecessor or candidate journal bounds;
  `M5(epoch=5,K=Active) -> M6(epoch=6,K=Revoked) -> M5` rollback, same-epoch
  fork, same-sequence different manifest, missing predecessor/preimage,
  selector/root rollback, current-versus-receipt-historical keyset substitution,
  revoked-current-key with older Active receipt, and validation-to-selection
  TOCTOU negatives before any tombstone or side effect;
  receipt-id and nonce independent uniqueness, TrustOperationId collision and
  exact rotation-only reuse, atomic two-receipt rotation updates,
  compact-then-replay, selector/root rollback, expiry-boundary pruning,
  maximum-terminal-result byte accounting, ordinary-cap rejection with
  successful reserved RotateCommit and RemoveTrust-then-RemoveAndDestroy,
  Generated-to-Drifted and FullChoice/DirectDestroyOnly-installed-to-Drifted
  reserve inheritance, crash immediately after final safety-reserve consumption
  proving initially ForwardOnly Absent-only recovery with no second refinement
  at owned-removal or key-destroy intent, reservation selector
  crash points, full-cap time maintenance and pruning folded only into an
  already-required selector transition, read-only replay-time validation with
  byte-identical query/admission producing no replay root, revision, envelope,
  or selector change,
  ProviderOperationReservationStateV1 record/vector/root/revision golden
  vectors, one raw create/destroy ID namespace, staged helper-to-key-authority
  append selection, exact reservation purpose/commitment/continuation binding,
  duplicate/cross-purpose/cross-generation/reordered/root/revision rejection,
  terminal and unused RotatePrepare cleanup-ID retention across stable states,
  restart, compaction, consent pruning, and exact negative reuse after every
  terminal outcome,
  allowed evidence-reference domains/order/bounds and rejection of evidence
  pointing directly or indirectly to response/state/replay objects,
  and wall-clock rollback beyond MaximumAcceptedClockSkew;
- CA profile parsing, normalized trust-purpose matching, positive server-auth
  and negative client-auth/email/code-signing/timestamping purpose cases,
  derived-purpose preservation, non-exportability adapter behavior, public-key/
  SPKI match, fresh possession challenge, stale/chosen-message proof rejection,
  installation-lifetime SPKI uniqueness across same-SPKI/different-DER and
  current/historical generations, provider-object/secret/NonExportableKeyIdentity
  non-aliasing, missing/unstable/incomplete uniqueness tags, rotation candidate
  collision before trust mutation, collision-to-Ambiguous with destroy forbidden,
  leaf SAN and lifetime bounds, key destruction ambiguity, and zeroization/error
  paths; exact external CA copies remaining beyond every pre-destroy test-leaf
  lifetime and producing fresh ConservativeExternalTrustPotential without a CA
  key, plus a post-destruction ExternalCurrentObserved direct item or derived
  source accepted only with its complete same-query
  NoFlowProbeOwnershipProofV1 and exact DestroyedTerminalKeyEvidenceV1;
  retention of that SPKI across restart/compaction/time, removal only after
  a complete fresh negative scan, wrong identity/destroy receipt/ancestry
  rejection, rejection of missing/stale/cross-query ownership proof and
  ExternalCurrentObserved-as-owned/adopted authority, and proof that
  conservative evidence cannot satisfy support,
  Installed verification, admission, signing, mutation, or deletion;
- signing admission at every state and drift condition, exact deterministic
  QueryChallenge derivation from helper challenge/connection/request, one
  InterceptionAdmission-purpose ResidualQueryContextV1 and complete scan,
  required-target count/root completeness, direct and derived per-target
  evidence resolution, consumer-result projection, same semantic key/different
  digest, cross-context/scope/item/member/source/release/request substitution,
  Changed/Ambiguous rejection, common signature-free body, current-Active-anchor
  HelperAttestation context with `admission-body`, `signed-admission-proof`
  wrapper/digest, and CA-key dual-signature golden vectors; reject old-
  installation, historical, Invalidated, manifest-supplied, caller, raw helper,
  wrong role/domain/body-tag/wrapper-tag/key/purpose, stale epoch,
  one-use consumption, key/service loss, and exact pass-through/refusal
  behavior;
- signature-free IdentitySetProofBodyV1 dual-signature golden vectors with
  exact IdentitySetProof domain, `proof-body`, and NoneBodyOnly registry rows,
  plus
  complete ARCH-002 identity sets for generation, install, rotation before and
  after candidate identity binding, partial
  removal, external deletion, residual key, drift, recovery ambiguity, valid
  Absent with empty, PreservedExternalLive, and
  ConservativeExternalTrustPotential nonempty residual sets; bind the exact
  machine namespace revision/digest and prove the final set is the sorted union
  of the current-installation scan and every retired seal's complete conservative
  SPKI vector, rejecting current-only, digest-only, missing-retired, stale-
  namespace, duplicate, overflow, and caller-composed unions, including a
  destroyed historical key observed after seven days and a distinct active key
  forbidden from probing the historical identity, and
  unavailable/incomplete ledgers, including a mandatory new same-lock scan for
  every query in Absent, Generated, InstalledAndVerified, each exact-identity
  pending state, Drifted, and RecoveryRequired; external historical identity
  add/remove in each state; rejection of a previously selected/cached scan
  after a change or selector-before-commit crash; residual-observation expiry
  boundaries; ResidualQueryContext challenge/nonce/body equality; byte-identical
  fresh query without a state write; terminal-anchor age independent of query
  freshness; and ReplayTimeHighWater clock-rollback cases;
- platform fake backends that model external mutation between observe/apply,
  apply/read-back, observe/delete, and delete/read-back, plus
  ExternallyRemoved-without-delete, missed notification, restart rescan, and
  proof that every row may drop StableStoreRevisionUnavailable only after its
  exact release binding supplies the required monotonic/no-ABA snapshot token;
  separate CurrentUser/SystemService NSS capability rows proving that a missing
  authenticated user agent cannot be hidden by the helper row or trigger any
  cross-context fallback;
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
   remains; otherwise prove the owned authority absent and bind a currently
   successful residual to
   ResidualEffectiveTrustDispositionV1.PreservedExternalLive. After exact key
   destruction and expiry of every bounded test leaf, repeat the fresh platform,
   ownership, source, and serverAuth observations and bind only
   ConservativeExternalTrustPotential; it must keep the SPKI excluded without
   claiming live TLS success. A live validated chain anchor must be the exact DER.
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
user authentication cancellation, the foreground administrator-agent flow,
native administrator cancellation, rejected LaunchDaemon-only Admin mutation,
exact sslServer policy-name persistence, negative SSL-client evaluation,
Keychain Access external edits, trustd/helper/app restart, hard power loss,
SecTrustEvaluateWithError, Safari, exact Chrome builds, and Firefox with OS
enterprise roots both enabled and disabled. Tests prove Firefox NSS databases
remain unchanged.

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

The helper, key authority, and user/administrator trust agents reject inherited
descriptors, debug/task/ptrace access, dumps, unsigned replacement, wrong
package identity, wrong peer, and downgrade before any secret or mutation. Test
fixtures use only ephemeral generated certificates and keys and never real user
or production material.

An updater or uninstaller first closes the gate and reconciles trust.ca.v1. It
MUST NOT remove the helper, key authority, journal, target owner records, or key
provider while an owned target/key, pending operation, drift, or ordinary
RecoveryRequired state remains. The sole terminal exception is
RecoveryRequired(AttestationAnchorInvalidated): after separately authorized
external cleanup, the root installer may only re-observe complete exact absence,
select InstallationRetirementCleanupEvidenceV1 and the immutable retired seal,
and CAS the machine namespace to Current=None. It cannot use an invalidated key
or that CAS to perform cleanup. Only after the seal and all referenced history
are durable may uninstall remove the old executables/provider registration or a
fresh bootstrap begin. Product uninstall does not broaden removal: foreign or
ambiguous state is preserved and reported for bounded manual recovery.

FlowProbe is unreleased at this decision point. Existing in-memory CA behavior
and future internal trust formats may be replaced directly; this contract adds
no compatibility shim or migration path. Production upgrade or migration
semantics require a separately authorized architecture task.
