# Contract: Egress Selection and Loop Prevention v0.2

Status: Normative for v0.2

Owner: ARCH-002 / ADR-0005

## 1. Purpose and conformance

This contract defines the closed product egress model, the proof required before
activation, local external-proxy identity, the complete loop-exclusion set, and
the `egress.*` resources and health predicates registered into the ARCH-001
network-session transaction.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL are interpreted as described by
BCP 14 when they appear in uppercase.

A conforming implementation MUST also conform to:

- ADR-0004 and
  [`network-session-lifecycle.md`](network-session-lifecycle.md) for session,
  capability, lease, fence, journal, rollback, and recovery rules;
- [`privileged-helper.md`](privileged-helper.md) for authenticated helper
  transport, allowlisted mutations, durable evidence, and conditional restore;
- [`config-compiler.md`](config-compiler.md) for protected system/runtime
  overlay ownership; and
- the future ARCH-004 contract whenever a selected path uses DNS or UDP
  resources owned by `dns.*` or `transport.udp.*`.

This document does not authorize an implementation to edit those accepted
contracts, add arbitrary helper operations, move proxy behavior into Capture
Core, or claim platform support without the evidence required below.

## 2. Trust boundaries and owners

| Component | Permitted authority |
| --- | --- |
| Renderer | Selects a saved profile and requested network scope through typed desktop IPC; receives bounded status only |
| Trusted product-policy broker | Converts an authenticated user action or installed administrator policy into bounded, signed risk-acceptance and probe-target receipts; renderer data alone is never a receipt |
| Supervisor | Sole unprivileged orchestrator; resolves product intent, coordinates policy/secret brokers, capability discovery, proof, session transaction, and status publication |
| Secret broker | Resolves an opaque credential handle and performs one plan/purpose-bound delivery to the exact runtime-config materializer for a sealed `RuntimeInstanceId`; it never grants helper or renderer access |
| Trust-material broker | Resolves request-only private-anchor/pin handles, emits non-authorizing content descriptors, and performs one plan/node/slot-bound delivery to the exact sealed runtime materializer; it never grants helper or renderer access to a handle or raw material |
| Config Compiler | Compiles a typed egress selection and protected loop overlay; emits secret slots and safe digests, never logs secret values |
| Network Runtime adapter | Materializes the fixed private runtime artifact, starts the independent runtime only through the ARCH-001 gate, authenticates its control identity, and removes the artifact |
| Network Runtime | Owns direct and external-proxy protocol execution, preactivation proof, active connectors, and all runtime-created egress sockets |
| Capture Core | Owns capture/protocol processing and a versioned connector request; it receives an established connector or typed result, not sing-box internals |
| Platform discovery backend | Produces typed baseline, route, listener, process, interface, and enforcement observations |
| Privileged helper/watchdog | Verifies registered egress observations and any future compile-time-allowlisted OS resources under the ARCH-001 journal; v1 adds no privileged egress mutator and contributes predicates to the existing fail-closed gate |

The policy, secret, and trust-material brokers are not privileged helper
operations. During
`PreparePlan`, the helper may receive the bounded signed authorization receipts
needed for verification; the sealed plan/journal retain only their digests. It
receives only non-authorizing credential descriptor digests, never handles or
values. The renderer MUST NOT receive a helper channel, runtime
secret channel, raw credential handle, receipt-signing key, OS operation, or
platform discovery primitive.

## 3. Encoding and common rules

Normative structures below are algebraic data types. A wire binding MUST:

- carry a schema name and positive schema version;
- encode a tagged union with exactly one known variant;
- reject unknown variants, unknown fields, duplicate fields, invalid enum
  values, non-canonical host/address values, and non-finite or non-positive
  bounds;
- use deterministic canonical encoding for every digest-bound object;
- distinguish absent from empty where the schema does;
- normalize DNS names to a validated A-label form without a trailing dot for
  identity comparison while preserving an independently bounded display label;
- normalize IPv4 as 32 bits and IPv6 as 128 bits plus a scope identifier only
  when the address class requires one; and
- use a product/routing endpoint port in `1..=65535`; an exact protocol-wire
  observation may carry zero only in a field whose closed variant below fixes
  that value and explicitly denies using it as an `Endpoint`.

Every object embedded in an ARCH-001 plan, helper request, journal observation,
signature, or digest inherits the exact deterministic-CBOR profile in the
Privileged Network Helper contract: fixed-length arrays in displayed field
order, zero-based union tags in displayed alternative order, shortest integers,
bounded NFC text, no maps, floating point, generic CBOR tags, indefinite
lengths, trailing bytes, or unknown fields. An optional field is encoded as the
closed union `Absent | Present { value }`, with tags zero and one; an absent
value is never encoded as an empty string, zero digest, empty list, or null.

Only a root in the following registry may use the
`FlowProbe.Egress.Object.v1` domain, be independently signed, or serve as an
object/observation root named by an ARCH-001 plan or journal field. A nested
value has no independent object-root domain unless it also appears here. This
section separately permits a closed set of non-authorizing content/reference
digests with explicit preimages; those values may appear only in their named
fields, are never independently signed, and cannot substitute for a registered
root or live observation. The fixed root-schema tags are:

```text
 0 EgressSelectionV1                    16 ProbeTargetAuthorizationScopeV1
 1 SafeEgressSelectionV1                17 ProbeTargetAuthorizationReceiptV1
 2 CapabilityReportV1                   18 ProbeTargetProfileV1
 3 ResolverDependencyDescriptorV1       19 ProxyTlsPolicyDescriptorV1
 4 ResolvedEndpointSetV1                20 EffectiveProxyTrustSnapshotV1
 5 LocalProxyIdentityV1                 21 PrivateAnchorSetDescriptorV1
 6 ConnectedLocalPeerObservationV1      22 SpkiPinSetDescriptorV1
 7 EgressActorV1                        23 ProxyTrustMaterialDescriptorV1
 8 EgressActorGraphV1                   24 ProxyTrustMaterialLoadObservationV1
 9 EgressExclusionSetV1                 25 RuntimeCredentialDescriptorV1
10 EgressExclusionEntryV1               26 ExternalObservationAuthenticatorV1
11 BaselineEgressAnchorV1               27 NonceEchoChallengeResultV1
12 EgressProofSpecificationV1           28 PostactivationCanaryResultV1
13 EgressPathProofResultV1               29 SustainedHealthObservationV1
14 ActorSocketFactoryPolicyV1            30 ProxyRiskAuthorizationScopeV1
15 SocketFactoryPolicyObservationV1      31 SocketPolicyChildObservationV1
                                         32 RiskAcceptanceReceiptV1
                                         33 EndpointIdentityV1
                                         34 SocketObservationAccumulatorV1
                                         35 EgressExclusionCompletenessProofV1
                                         36 AuthorizationConsumptionRecordV1
                                         37 PhaseBoundProbeChallengeResultV1
                                         38 ProxyRiskAuthorizationSubjectV1
                                         39 ProbeTargetAuthorizationSubjectV1
                                         40 ProxyTrustMaterialDeliveryRecordV1
                                         41 ProxyTrustMaterialArtifactObservationV1
                                         42 ProxyTlsHandshakeObservationV1
                                         43 SocketIdentitySetV1
                                         44 OsSocketCensusV1
                                         45 ProbeAddressClassifierSnapshotV1
                                         46 FactorySocketCensusObservationV1
                                         47 EffectiveProxyTrustObservationV1
                                         48 NonceEchoDeliveryConsumptionRecordV1
                                         49 TlsVerifierCapabilityEvidenceV1
                                         50 Socks5UdpAssociationObservationV1
                                         51 EgressExclusionReadbackObservationV1
                                         52 EgressOrdinaryConnectivityObservationV1
                                         53 PlatformCapabilityEvidenceV1
                                         54 ActorNetworkIsolationPolicyV1
                                         55 ActorNetworkIsolationReadbackV1
                                         56 FactoryAdmissionReleaseBatchCompletionV1
```

For registered root schema tag `T`, version `V`, and its fixed-array CBOR value
`X`, every ARCH-002 root digest is exactly
`SHA-256("FlowProbe.Egress.Object.v1\0" || uint16_be(T) || uint16_be(V) || X)`.
A field that names a digest owned by another accepted contract MUST name that
contract's exact schema, version, and digest domain in the enclosing registered
root; arbitrary evidence bytes or an implementation-private hash are invalid.
A field ending in `*_sha256` is not an ARCH-002 object digest: it is permitted
only when this contract states the exact byte content hashed (for example exact
packaged binary bytes or exact DER certificate bytes), and it can assert only
content identity. It never proves a live observation, owner, route, policy
readback, or readiness. Generic names such as `evidence_digest`,
`observation_digest`, `identity_digest`, or a hash of private serialized state
are forbidden even if their producer uses SHA-256.
A digest used in a different schema, version, plan, helper request, or field
domain is invalid. Helper frame/request authentication remains the separate
helper domain; this object digest never substitutes for controller proof or a
frame/observation signature. The compile-time schema package MUST contain byte-
exact golden vectors for every registered root and nested union, including each
rejection boundary, and two independent codecs must accept/reject the same
vectors before support. Tags `0..=56` are contiguous and immutable in v1; a
codec with a missing, duplicated, or renumbered tag is nonconforming.

The schema package mechanically inventories every field whose name ends in
`_digest`, `_digests`, or `_sha256`. Each must resolve to exactly one registered
ARCH-002 root, one explicitly named accepted-contract schema/version/domain, or
one exact content-byte preimage defined by this contract. An unresolved,
multiply classified, or generic field fails schema generation and release; the
inventory is checked independently by both codecs.

The complete ARCH-002 non-root reference-domain allowlist is:
`fence_token_digest`; `runtime_package_and_build_digest`;
`runtime_config_template_digest`; every tag-selected
`AuthenticatedChannelContextV1` channel-binding digest;
`capture_generation_marker_digest`; `response_frame_digest`;
`Socks5UdpAssociateRequestEvidenceV1.associate_request_frame_digest` and
`Socks5UdpAssociateReplyEvidenceV1.associate_reply_frame_digest`;
`Socks5UdpCanaryEvidenceV1.request_datagram_digest` and
`Socks5UdpCanaryResponseEvidenceV1.response_datagram_digest`;
`ObservedUdpDatagramSourceV1.zero_port_source_identity_digest`;
`issuer_identity_digest`; `tls_verifier_implementation_and_build_digest` and
the byte-identical `ProxyTlsHandshakeObservationV1.tls_stack_and_build_digest`;
`PlatformCapabilityEvidenceV1.implementation_and_build_digest`;
`store_revision_digest`;
`flowprobe_ca_exclusion_set_digest`; the anchor-set digest fields explicitly
defined by `FlowProbe.Egress.AnchorSet.v1`; NonceEcho `commitment`, checkpoint
commitment, and SOCKS5 UDP canary `commitment`;
`trusted_release_keyset_revision_sha256`;
`public_key_identity_digest`; and socket-accumulator
`starting_chain_digest`/`final_chain_digest`; and
`FactoryAdmissionReleaseCurrentIndexV1.index_checksum_sha256`. Their sole
formulas are the domain-separated preimages stated in this contract. The
release-artifact and exact packaged-binary/DER/SPKI fields
ending `_sha256` are the separately enumerated content hashes below. No other
nested custom domain is accepted, and none of these allowlisted values by
itself proves readiness, ownership, route selection, policy readback, or a live
result.

These ARCH-001 aliases are exact and are not new ARCH-002 digest domains:

| ARCH-002 field | Exact accepted upstream field/domain |
| --- | --- |
| `candidate_plan_digest` | Privileged Helper `PreparePlan.CandidatePlanDigest` |
| `prepared_plan_digest`, `plan_digest` | Privileged Helper / Network Session Lifecycle `PlanDigest` |
| `runtime_config_node_operation_digest`, `resume_barrier_operation_digest` | Privileged Helper `OperationDigest` for the named registered node |
| `resume_barrier_observed_state_digest`, `observed_state_digest` | Privileged Helper `ObservedStateDigest` |
| `read_back_predicate_digest` | the named registered operation's sealed Privileged Helper read-back-predicate digest |
| `runtime_executor_identity_digest` | Privileged Helper `ExecutorIdentityDigest` |
| `gate_channel_binding_digest`, `runtime_gate_channel_binding_digest` | Privileged Helper `GateChannelBindingDigest` |
| `baseline_digest` | Privileged Helper `PreparePlan.BaselineDigest` |
| `commit_journal_head_digest`, `Arch001JournalTipV1.journal_head_digest_at_result` | Privileged Helper protected journal `JournalHeadDigestAtResult` domain; the latter occurs only in the six typed tip paths enumerated below |
| `renewal_evidence_digest` | Privileged Helper `LeaseRenewed.RenewalEvidenceDigest` |

`fence_token_digest` is a non-authorizing reference computed exactly as
`SHA-256("FlowProbe.Egress.FenceTokenReference.v1\0" ||
canonical_arch001_fence_token_bytes)`; a helper request still uses the actual
ARCH-001 `FenceToken`.

Release content identities use these closed preimages:

```text
ReleaseArtifactFileV1 = {
  normalized_path,
  byte_length,
  content_sha256,
}

ReleaseArtifactCorpusV1 = {
  files,
}

RuntimePackageBuildIdentityV1 = {
  package_name,
  package_version,
  source_revision_sha256,
  runtime_binary_sha256,
  dependency_lock_sha256,
}
```

`ReleaseArtifactFileV1.content_sha256` is SHA-256 of the exact file bytes and
`byte_length` is their exact unsigned 64-bit length. `normalized_path` is an NFC
UTF-8 repository-relative path of `1..=512` bytes using `/`, with no leading
slash, empty component, `.`, `..`, backslash, NUL, or platform-dependent case
folding. A corpus contains `1..=4096` unique files in ascending normalized-path
byte order and at most 256 MiB total; no ignored, generated, or environment-
selected file may enter or leave the manifest. `source_revision_sha256`,
`dependency_lock_sha256`, and `conformance_suite_and_vectors_sha256` are,
respectively, SHA-256 of
`"FlowProbe.Egress.SourceCorpus.v1\0"`,
`"FlowProbe.Egress.DependencyLockCorpus.v1\0"`, or
`"FlowProbe.Egress.ConformanceCorpus.v1\0"` followed by
`canonical_cbor(ReleaseArtifactCorpusV1)`. Every field named
`runtime_binary_sha256`, `adapter_binary_sha256`, `producer_binary_sha256`,
`checker_binary_sha256`, `factory_binary_sha256`, `backend_binary_sha256`, or
`binary_sha256` is SHA-256 of the exact single packaged executable/library bytes
selected by the surrounding identity; the manifest supplies its normalized path
and byte length. These names never mean a VCS label, directory iteration,
post-install mutable file, or implementation-private serialization.

`runtime_package_and_build_digest` is exactly
`SHA-256("FlowProbe.Egress.RuntimePackageBuild.v1\0" ||
canonical_cbor(RuntimePackageBuildIdentityV1))`. Package name and version are
NFC, control-free UTF-8 of `1..=128` bytes and every hash is 32 raw bytes.

```text
RuntimeConfigTemplateV1 = {
  template_schema_version = 1,
  pinned_runtime_revision =
    "b5ebaa1fc0f2b94256180b95468e73ef53caa27d",
  runtime_package_and_build_digest,
  egress_selection_safe_digest,
  credential_reference_descriptor_digest?,
  proxy_tls_policy_descriptor_digest?,
  trust_material_descriptor_digest?,
  protected_objects,
  material_slots,
  user_config_boundary = UserCannotDefineReferenceSelectOrDetourProtectedObjects,
  secret_policy = RegisteredDescriptorPlaceholdersOnly,
  reload_policy = DisabledForGeneration,
}

ProtectedRuntimeObjectTemplateV1 = {
  object_kind: Outbound | RouteRule | Resolver | DnsRule |
               SocketBinding | TrustPolicy,
  reserved_tag,
  canonical_jcs_object_bytes,
}

ProtectedMaterialSlotV1 =
  | ProxyCredential {
      material_delivery_slot_id,
      credential_reference_descriptor_digest,
      placeholder_token,
      consumers,
    }
  | ProxyTrust {
      material_delivery_slot_id,
      trust_material_descriptor_digest,
      placeholder_token,
      consumers,
    }

ProtectedMaterialConsumerV1 = {
  object_kind,
  reserved_tag,
  rfc6901_json_pointer,
}
```

`protected_objects` contains `1..=64` unique values ordered by
`(object_kind-tag, reserved_tag UTF-8 bytes)`. Every reserved tag begins
`__flowprobe_`, is NFC/control-free ASCII of `13..=128` bytes, and occurs once.
`canonical_jcs_object_bytes` is the exact RFC 8785 UTF-8 encoding of the complete
secret-free protected object; it contains no user object, credential, private
anchor, bearer value, or environment expansion and uses only the displayed
descriptor placeholder tokens for material. `material_slots` contains `0..=8`
unique values ordered by `(variant-tag, material_delivery_slot_id)`; descriptor
presence in the template and slots is exactly the presence required by the
selected egress variant. `egress_selection_safe_digest`,
`credential_reference_descriptor_digest`, `proxy_tls_policy_descriptor_digest`,
and `trust_material_descriptor_digest` are respectively tags 1, 25, 19, and 23.
Every protected resolver object reproduces the exact purpose and tag-3
`ResolverDependencyDescriptorV1` reference already bound by tag 1; the template
does not add a cardinality-ambiguous resolver field. The template contains no rendered
secret bytes. `runtime_config_template_digest` is exactly
`SHA-256("FlowProbe.Egress.RuntimeConfigTemplate.v1\0" ||
canonical_cbor(RuntimeConfigTemplateV1))`; no other protected-template byte
encoding is accepted.

The template's `egress_selection_safe_digest` and
`runtime_package_and_build_digest` equal the enclosing plan and proof
specification byte-for-byte. For `Direct` or any external selection whose
`safe_authentication` is `None`, the credential descriptor field and every
`ProxyCredential` slot are absent. Otherwise that field equals the exact tag-25
digest in `SafeHttpAuthenticationV1` or `SafeSocks5AuthenticationV1` and exactly
one `ProxyCredential` slot repeats it. `ExternalHttps` requires the template's
tag-19 policy equal the safe selection, its tag-23 trust descriptor equal that
policy, and exactly one matching `ProxyTrust` slot; every other egress tag
requires both fields and every `ProxyTrust` slot absent.

Every `material_delivery_slot_id` is a unique nonzero 32-byte value across both
slot variants. Its `placeholder_token` is exactly the ASCII text
`__flowprobe_slot_` followed by the 64 lowercase hexadecimal digits of that ID.
`consumers` contains `1..=8` unique locations ordered by
`(object_kind-tag, reserved_tag bytes, RFC 6901 pointer bytes)`; every location
names one protected object and a canonical JSON string whose value is exactly
that token. All and only declared consumer locations contain a slot token, every
slot has at least one consumer, and no token may appear in a key, user object,
wrong slot kind, or undeclared/dangling location. Descriptor, slot, token, or
consumer cardinality/equality failure invalidates the template before sealing.

Every X.509 field named `*_der_sha256` is SHA-256 of the exact complete DER
certificate bytes. Every field named `*_spki_sha256` is SHA-256 of the exact DER
`SubjectPublicKeyInfo` bytes, not a certificate, PEM text, raw key, or runtime-
specific pin encoding. Digest collections use 32 raw bytes and the displayed
sort/deduplication rules.

Every non-helper field named `channel_binding_digest`,
`consumer_channel_binding_digest`, or `runtime_load_channel_binding_digest` is
computed from this closed union, encoded as canonical CBOR `[variant_tag,
fixed_array_payload]` with tags `0..=4`:

```text
AuthenticatedChannelContextV1 =
  | 0 PreplanDiscovery {
      preparation_ticket_id,
      session_id,
      generation,
      helper_assigned_observation_nonce,
      boot_epoch,
      suspend_epoch,
      component_instance_id,
      platform_backend_public_key_32,
      helper_public_key_32,
      authenticated_transport_exporter_32,
    }
  | 1 PlanComponent {
      prepared_plan_digest,
      generation,
      component_instance_id,
      component_public_key_32,
      helper_public_key_32,
      authenticated_transport_exporter_32,
    }
  | 2 Watchdog {
      watchdog_identity,
      boot_epoch,
      suspend_epoch,
      prepared_plan_digest,
      generation,
      activation_lease_id,
      lease_epoch,
      fence_token_digest,
      watchdog_public_key_32,
      helper_public_key_32,
      authenticated_transport_exporter_32,
    }
  | 3 TrustDelivery {
      prepared_plan_digest,
      generation,
      trust_material_descriptor_digest,
      runtime_instance_id,
      runtime_config_node_id,
      runtime_config_node_operation_digest,
      material_delivery_slot_id,
      trust_material_broker_component_instance_id,
      runtime_adapter_component_instance_id,
      trust_material_broker_public_key_32,
      materializer_public_key_32,
      authenticated_transport_exporter_32,
    }
  | 4 RuntimeTrustLoad {
      prepared_plan_digest,
      generation,
      trust_material_descriptor_digest,
      trust_material_delivery_record_digest,
      runtime_instance_id,
      runtime_config_node_id,
      runtime_config_node_operation_digest,
      private_artifact_observed_resource_identity,
      gate_channel_binding_digest,
      runtime_adapter_component_instance_id,
      runtime_adapter_public_key_32,
      network_runtime_public_key_32,
      authenticated_transport_exporter_32,
    }
```

The digest is exactly
`SHA-256("FlowProbe.Egress.AuthenticatedChannel.v1\0" ||
canonical_cbor(AuthenticatedChannelContextV1))`. A pre-plan authority uses
variant 0; a plan-component authority uses variant 1; a watchdog authority uses
variant 2; `ProxyTrustMaterialDeliveryRecordV1.consumer_channel_binding_digest`
uses variant 3; and both runtime-load/artifact roots use the same variant-4
`runtime_load_channel_binding_digest`. Every field of the selected variant is
byte-identical to the containing root/header or referenced delivery root.
Variant 4 contains the exact ARCH-001 `GateChannelBindingDigest` from the
runtime authenticator; the domain-separated digests are deliberately unequal.
In variant 3, `trust_material_broker_component_instance_id` is the exact
component in the delivery root's `PlanComponentAuthenticatedChannel` authority,
and `runtime_adapter_component_instance_id` is the exact component in
`expected_materialization_target.exact_owner_identity`. The broker endpoint key
is the raw Ed25519 key whose role-bound digest is the delivery root's
`authenticator.header.public_key_identity_digest`; the materializer endpoint
key is the registered authenticated-channel key for that exact runtime-adapter
component and plan/node/slot. In variant 4,
`runtime_adapter_component_instance_id` repeats the delivery target owner, the
network-runtime endpoint identity is the displayed `runtime_instance_id`, and
the two endpoint keys are respectively the registered gate-authenticated keys
for that adapter component and runtime instance. The artifact root's signer
identity/key equal the adapter endpoint, and the load root's signer
identity/key equal the network-runtime endpoint. All displayed public keys and
the exporter are nonzero authenticated-channel outputs for those exact endpoint
roles. A component/key substitution, reversed role order, omitted field,
unauthenticated transport, unknown variant, or reuse across context is invalid.

`capture_generation_marker_digest` is exactly
`SHA-256("FlowProbe.Egress.CaptureGenerationMarker.v1\0" ||
prepared_plan_digest || uint64_be(generation) || capture_core_instance_id ||
resume_barrier_resource_id || uint64_be(snapshot_barrier_epoch))`. It is
created only after the barrier-protected capture generation exists and is never
an opaque capture-health claim. `response_frame_digest` is exactly
`SHA-256("FlowProbe.Egress.NonceEcho.Result.v1\0" || commitment ||
exact_40_response_frame_bytes)`; only the digest, never the raw nonce/frame, may
be durable.
The SOCKS5 UDP canary digests are exactly
`SHA-256("FlowProbe.Egress.Socks5UdpCanary.Request.v1\0" || commitment ||
canonical_cbor(destination) || exact_request_datagram_bytes)` and
`SHA-256("FlowProbe.Egress.Socks5UdpCanary.Response.v1\0" || commitment ||
canonical_cbor(observed_udp_source) || exact_received_datagram_bytes)`.
They are non-authorizing content digests, not registered roots, and only the
digests and bounded byte counts may be durable.
For an observed UDP source port of zero, `zero_port_source_identity_digest` is
exactly `SHA-256("FlowProbe.Egress.Socks5UdpCanary.ZeroPortSource.v1\0" ||
uint8(family_tag) || canonical_cbor(normalized_address_octets_and_scope) ||
uint16_be(0))`, where `family_tag` is `0` for IPv4 and `1` for IPv6, IPv4 has
exactly four address octets and no scope, and IPv6 has exactly sixteen octets
plus the canonical optional scope required by that address. It is likewise a
non-authorizing content digest; raw source address/scope bytes are not retained
in tag 50 or normal logs.
The UDP ASSOCIATE control-frame digests are exactly
`SHA-256("FlowProbe.Egress.Socks5UdpAssociate.Request.v1\0" ||
exact_request_frame_bytes)` and
`SHA-256("FlowProbe.Egress.Socks5UdpAssociate.Reply.v1\0" ||
exact_received_bounded_reply_bytes)`. The reply digest exists exactly for
`Partial` and `Observed`, and the preimage length equals that variant's
`reply_bytes_received`. `NotObserved` and `OverBound` have no reply digest; an
over-bound reply retains only its lower-bound byte count.

`EgressActorGraphV1` is a fixed-array root containing `1..=32` unique actors in
ascending `actor_id` byte order. `EgressExclusionSetV1.entries` contains
`1..=128` unique `EgressExclusionEntryV1` roots ordered by
`(actor_id, purpose-tag, family-bitset, transport-bitset, endpoint-scope)`.
Every other list is either given an exact bound and order at its definition or
is invalid. A set is deduplicated before encoding and sorted by the full
canonical element bytes. These container rules, not producer iteration order,
determine their digests.

No union has a default variant. A rejected value cannot be coerced to `Direct`,
`Ipv4Only`, local resolution, disabled UDP, no authentication, or proxy-only
scope.

All identifiers and digests are opaque fixed-size values unless stated
otherwise. Human-readable reason text is optional, UTF-8, control-character
free, and at most 256 bytes. Stable reason codes are ASCII tokens of at most 64
bytes.

Every `*_at`, `observed_at`, `reaffirmed_at`, and `expires_at` value used for a
security decision is an unsigned tick in the helper-defined suspend-aware
monotonic clock domain inherited from ARCH-001, not producer wall-clock time.
The containing plan/authority binding supplies the exact boot and suspend
epochs. Cross-signer ordering is accepted only within that same clock/epoch
domain; boot, suspend/resume, clock-domain discontinuity, or counter wrap
invalidates the observation instead of being normalized.

```text
PlatformFamilyV1 = Windows | Linux | Darwin | HermeticTestOnly
```

Every root that combines OS mechanisms carries one explicit platform family or
closed platform profile and obeys the exact aggregate mappings stated below.
`HermeticTestOnly` and every `HermeticFake*` member are codec/test fixtures and
are rejected by release builds before plan sealing.

## 4. Request model

### 4.1 Network scope

```text
NetworkScope =
  | FullTunnel
  | ProxyOnly
```

`FullTunnel` requests system traffic steering through the ARCH-001 transaction.
`ProxyOnly` requests only explicit application use of a FlowProbe listener. The
scope is bound to `RequestedMode`, `PreparedPlan`, `ActiveMode`, status, lease
evidence, and terminal receipt.

A refused `FullTunnel` request MAY offer a `ProxyOnly` choice. Accepting it MUST
create a new typed request and plan. The implementation MUST publish
`ActiveMode.scope=ProxyOnly`; it MUST NOT publish `FullTunnel`, silently edit the
old plan, or call the result the original mode. A UI acknowledgement is not a
helper mutation authority and MUST be translated into a new Supervisor request.

### 4.2 Address and destination types

```text
Host =
  | DnsName { a_label }
  | Ipv4 { octets }
  | Ipv6 { octets, scope_id? }

Endpoint = { host, port }

EndpointIdentityV1 = {
  normalized_host,
  port,
}

PathEndpointBindingV1 =
  | ProxyEndpointSet {
      resolved_endpoint_set_digest,
    }
  | ResolverPath {
      resolver_dependency_digest,
    }
  | ProbeTargetProfiles {
      probe_target_profile_digests,
    }
  | OwnedActorAllExternalEndpoints {
      actor_socket_factory_policy_digest,
    }
  | ExternalLocalProxyAllExternalEndpoints {
      local_proxy_identity_digest,
    }

IpFamilyPolicy =
  | Ipv4Only
  | Ipv6Only
  | PreferIpv4
  | PreferIpv6
  | RequireBoth

ResolverDependencyDescriptorV1 = {
  resolver_path_id,
  resolver_policy: ResolverPolicyV1,
  resolver_actor_id,
  baseline_anchor_digest,
  family_scope,
  maximum_candidates,
  expires_at,
}

ResolverPolicyV1 = {
  query_owner = ExactResolverActor,
  forward_lookup_only = true,
  search_suffix_expansion = Prohibited,
  reverse_lookup = Prohibited,
  ambient_resolver_fallback = Prohibited,
  result_source = ExactSealedResolverPathOnly,
  cache_acceptance = FreshResultWithinDescriptorExpiry,
  external_dns_path = RequiresAcceptedArch004Binding,
}

DestinationResolutionPolicy =
  | LocalAddress {
      resolver_dependency,
      destination_family_policy,
    }
  | ProxyName { family_visibility = ProxyOpaque }

ProxyEndpointPolicyV1 = {
  endpoint,
  resolver_dependency?,
  endpoint_family_policy,
}
```

Unless a field explicitly names `ResolvedEndpointSetV1`, every ARCH-002 field
named `exact_endpoint_digest`, `selected_endpoint_digest`,
`selected_proxy_endpoint_digest`, `input_endpoint_digest`, or
`endpoint_host_and_port_digest`, and every singular
`target_endpoint_digest` is
`Digest(EndpointIdentityV1)`. Endpoint collections use
`Digest(ResolvedEndpointSetV1)`. An endpoint digest never hashes an informal
display string.
For a selected proxy candidate, `selected_proxy_endpoint_digest` is exactly
`Digest(EndpointIdentityV1 { normalized_host = candidate.address plus its
required scope, port = input_endpoint.port })`, where `input_endpoint` is the
tag-33 root named by the enclosing tag-4 `input_endpoint_digest`. DNS aliases,
the configured DNS name, a target port, or a producer-default port cannot
replace that projection.

`ResolverDependencyDescriptorV1` embeds the complete v1 resolver policy; it
does not carry a hash of an implementation-owned policy object. The
`RequiresAcceptedArch004Binding` literal is a fail-closed dependency marker,
not permission to use the ambient resolver. Until ARCH-004 supplies and the
plan references its accepted typed DNS path, every DNS name whose resolution
would emit network traffic remains `UnsupportedPendingArchitecture`.

`Direct` requires `LocalAddress` for a DNS name. External proxy variants MAY use
`ProxyName` for the destination inside CONNECT or SOCKS5. The proxy endpoint is
always governed independently by `ProxyEndpointPolicyV1`: a literal has no
resolver dependency; a DNS name requires the exact sealed dependency before the
proxy connection exists.

`PreferIpv4` and `PreferIpv6` permit a bounded ordered attempt over the sealed
candidate set. They do not authorize resolution-policy change or an unbounded
Happy Eyeballs race. `RequireBoth` requires independent successful readiness,
proof, exclusion, and health evidence for both families. A link-local IPv6
address without an unambiguous scope is invalid.

An IP-family policy governs only an address selected by FlowProbe. With
`ProxyName`, the proxy's destination resolution and resulting IP family are
opaque to the client; FlowProbe reports `ProxyOpaque` and MUST NOT claim
`Ipv4Only`, `Ipv6Only`, `Prefer*`, or `RequireBoth` for that destination. A
request that requires client-enforced destination-family behavior is therefore
invalid with `ProxyName`. The independently observable outer proxy connection
still obeys `endpoint_family_policy`. Future per-flow destinations bind the
resolution policy and resolver actor, not address results that did not exist
when the activation plan was sealed.

`maximum_candidates` is in `1..=8`. Results are deduplicated and ordered by
family, address bytes, and scope; at most two candidates per requested family
may be attempted. Resolver network traffic is an actor path and cannot use an
ambient resolver or the pending FlowProbe TUN.

### 4.3 Time and size budget

```text
TimeoutBudget = {
  resolve,
  connect,
  tls?,
  authenticate,
  proxy_handshake,
  target_challenge,
  overall,
}
```

Every duration MUST be positive. Each phase MUST be no more than 30 seconds and
`overall` MUST be no more than 60 seconds. The sum of attempted work MUST be
bounded by `overall`; phase budgets are not additive extensions after the
overall deadline. V1 has exactly one target profile and serial connection
attempts (`concurrency_limit=1`), at most two address candidates per family,
and two HTTP CONNECT exchanges including an authentication retry. Multiple
targets or concurrent connection attempts are
`UnsupportedPendingArchitecture/TargetProbeAggregationUnavailable` rather than
partially observed fallback.

The compiler enumerates the complete closed serial attempt decision tree from
the tuple groups, eligible candidates, retry limit, and selected protocol. The
sum of the applicable per-phase maxima on every legal root-to-terminal path must
fit within `overall`; otherwise the specification is invalid before sealing.
Consequently an eligible fallback is never abandoned merely because a producer
spent an unmodeled share of the total budget. External cancellation remains an
explicit terminal phase/result, not an implicit continuation choice.

For `ExternalSocks5::RequireAssociate`, every legal path separately counts role
A's proxy connect/method/authentication/CONNECT/challenge and role B's second
proxy connect, method negotiation, authentication wire exchange, and UDP
ASSOCIATE exchange. Each occurrence consumes the same applicable `connect`,
`authenticate`, `proxy_handshake`, or `target_challenge` cap and the one shared
`overall` deadline; opening B does not reset any budget. Role C's one
`target_challenge` occurrence starts when the full UDP-child factory operation
begins after successful relay classification and runs through
`AssociationReady`, and on the final successful active group through the
success-side teardown checkpoint, covering queue/create/release/drain, send,
receive/validation, the final zero-network liveness gate, and that bounded
cleanup when applicable. Its deadline is the
minimum of that occurrence's remaining `target_challenge` cap and the shared
`overall` remainder and never resets between those steps.
The compiler counts the complete A+B+C path and rejects a decision tree whose
repeated occurrences cannot fit within `overall`.

The compiler independently computes the exact worst-case protocol-byte sum in
both directions for every legal root-to-terminal path, including every eligible
candidate/retry/group, the maximum conforming frame at each reached step, and
the exact bounded extra-byte or truncation observation needed to classify that
phase's over-bound terminal without retaining the remainder.
`RequireAssociate` includes role A's greeting/authentication/CONNECT and stream
challenge, role B's independent greeting/authentication/UDP-ASSOCIATE exchange,
and role C's complete request plus expected response UDP envelope for the exact
selected destination form. Each A or C NonceEcho payload is exactly 40 bytes in
each direction and must individually fit `maximum_challenge_bytes`; every
occurrence and its framing also contributes to
`maximum_total_protocol_bytes`. The maximum path sum must be no greater than
that sealed total or the specification is invalid before sealing. Thus a
conforming bounded response or deterministic local write can never discover
that the global remainder is insufficient after protocol bytes have begun.

HTTP response status plus fields are limited to 32 KiB, 100 fields, and 8 KiB
per field line. A target marker is limited to 256 bytes. Implementations MAY set
lower product or administrator limits but MUST report the effective values in
the safe plan descriptor. Peer input that exceeds one of these structural bounds
uses its phase-specific typed failure and closes the connection; a locally
selected bound too small for the compiler's maximum path is rejected before
sealing.

### 4.4 Authentication and secret references

```text
HttpAuthentication =
  | None
  | BasicUtf8V1 {
      credential_handle,
      exchange = PreemptiveOnce | ChallengeOnce,
    }

Socks5Authentication =
  | None
  | UsernamePasswordUtf8V1 { credential_handle }

CleartextCredentialPolicy =
  | Prohibit
  | ExplicitRiskAcceptance { risk_acceptance_receipt_digest }

HttpBasicCredentialV1 = {
  user_id_utf8_nfc,
  password_utf8_nfc,
}

Socks5CredentialV1 = {
  username_utf8_nfc,
  password_utf8_nfc,
}

ProxyRiskAuthorizationSubjectV1 =
  | ExternalHttpBasic {
      proxy_endpoint_policy,
      credential_descriptor_digest,
      exchange = PreemptiveOnce | ChallengeOnce,
      destination_resolution,
      timeout_budget,
    }
  | ExternalSocks5UsernamePassword {
      proxy_endpoint_policy,
      credential_descriptor_digest,
      destination_resolution,
      udp_policy,
      timeout_budget,
    }

ProxyRiskAuthorizationScopeV1 = {
  preparation_ticket_id,
  session_id,
  generation,
  policy_broker_challenge,
  exact_network_scope,
  exact_proxy_risk_subject_digest,
  policy_text_version,
}

RiskAcceptanceReceiptV1 = {
  receipt_id,
  issuer_kind,
  issuer_identity_digest,
  installation_id,
  preparation_ticket_id,
  session_id,
  generation,
  exact_proxy_risk_authorization_scope_digest,
  decision_nonce,
  boot_epoch,
  issued_at,
  continuous_expires_at,
  signature,
}

ReceiptIssuerKind =
  | AuthenticatedUserAction
  | InstalledAdministratorPolicy
  | HermeticTestOnly

AuthorizationConsumptionRecordV1 = {
  authorization_reference: AuthorizationReferenceV1,
  issuer_identity_digest,
  receipt_id,
  decision_nonce,
  preparation_ticket_id,
  session_id,
  generation,
  candidate_plan_digest,
  prepare_idempotency_key,
  prepared_plan_id,
  plan_digest,
}

AuthorizationReferenceV1 =
  | RiskAcceptance {
      risk_acceptance_receipt_digest,
      proxy_risk_authorization_scope_digest,
    }
  | ProbeTarget {
      probe_target_authorization_receipt_digest,
      probe_target_authorization_scope_digest,
    }
```

`credential_handle` is an opaque, non-displayable capability held only by the
Supervisor/secret broker boundary. Its tag-0 request encoding is exactly 32 raw
unpredictable nonzero bytes scoped to the open preparation session; it has no
text, platform-pointer, object-serialization, or variable-length form. That
encoding exists only on authenticated in-memory Supervisor/secret-broker IPC so
the request union and hermetic codec vector are canonical. The handle and tag-0
digest MUST NOT be passed to the helper or renderer and MUST NOT appear in a
durable plan, journal, runtime command line, environment, status, error, or
ordinary log. The secret broker resolves it to the tag-25 non-secret descriptor
before tag 1 or any downstream root is constructed.

The safe plan contains only:

```text
RuntimeCredentialDescriptorV1 = {
  credential_schema,
  non_secret_credential_version,
  authentication_method,
  exact_egress_tag,
  normalized_proxy_profile_identity,
  endpoint_host_and_port_digest,
  session_generation,
}

CredentialDescriptorDigest = Digest(RuntimeCredentialDescriptorV1)
```

The digest grants no ability to resolve the credential. Credential material is
bound to the exact runtime instance, plan, endpoint, protocol, and generation.
The broker-to-materializer delivery is one-use; the authenticated runtime may
retain the credential in protected process memory and reuse it for new
connections to that exact proxy for the life of that `RuntimeInstanceId`.
Rotation, reload, endpoint/tag change, runtime restart, or generation change
requires a new descriptor, sealed plan, delivery, artifact, and runtime
instance. HTTP `Proxy-Authorization` MUST be sent only to the configured proxy
before the tunnel exists and never to the origin inside the tunnel.

`HttpBasicCredentialV1` is encoded as UTF-8 bytes of `user-id ":" password`
before Base64. The user-id is non-empty, contains no colon, NUL, CR, LF, or
control character, and is at most 255 UTF-8 bytes; the password contains no NUL,
CR, or LF and is at most 1024 UTF-8 bytes. This is the product's single explicit
RFC 7617 encoding profile; no locale/default-code-page fallback is allowed.
`Socks5CredentialV1` username and password are each 1..=255 UTF-8 bytes, NFC,
and contain no NUL or control character, matching the one-octet RFC 1929
lengths. Any other credential schema is rejected before materialization.

RFC 1929 username/password and HTTP Basic do not protect credentials on a
plaintext transport. `ExternalHttp` with `BasicUtf8V1` and `ExternalSocks5` with
`UsernamePasswordUtf8V1` therefore require `ExplicitRiskAcceptance`; otherwise their
capability disposition is `PolicyProhibited`. `ExternalHttps` protects HTTP
Basic inside authenticated proxy TLS and does not require that cleartext-risk
acceptance. Userinfo in a proxy URL is invalid for every tag.

When authentication is `None`, `cleartext_credential_policy` MUST be
`Prohibit`; an unrelated receipt is invalid. `issuer_kind` uses exactly
`ReceiptIssuerKind`.
`PreemptiveOnce` sends one Basic value on the first CONNECT request and never
retries authentication. `ChallengeOnce` sends no credential on the first
request and permits exactly one retry only after one syntactically valid 407
response that offers exactly one compatible Basic challenge. The sealed value
cannot be selected by the proxy, changed on retry, or inferred from an ambient
client default.

The trusted product-policy broker signs the receipt with an installation-bound
issuer key inaccessible to the renderer. `HermeticTestOnly` is rejected by a
release build. Both the Supervisor and the compile-time ARCH-002 helper
validator verify issuer, signature, decision nonce, boot/suspend epoch,
continuous expiry, and every exact
binding. The candidate graph carries the bounded signed receipt for this check;
the helper `AuthorizationGrantDigest` and final plan bind its digest, then the
receipt body is omitted from the journal. A
renderer boolean, cached UI acknowledgement, copied digest, expired receipt, or
receipt for another proxy/protocol/credential/ticket/session/generation is
invalid. Receipt construction never encodes an absent field in
`SafeEgressSelectionV1`. Instead, the policy broker constructs the registered
`ProxyRiskAuthorizationSubjectV1` directly from the normalized candidate
request and its already resolved non-authorizing credential descriptor. The
closed subject variant itself fixes the cleartext risk kind and contains every
selection field that can affect the proxy path except the receipt. The scope
then binds `Digest(ProxyRiskAuthorizationSubjectV1)`, the exact requested
network scope, preparation ticket/session/generation, policy-text version, and
a fresh public 32-byte `policy_broker_challenge` generated after the preparation
ticket. The final `SafeEgressSelectionV1` is constructed only after the receipt
exists and MUST reproduce every subject field byte-for-byte while setting
`ExplicitRiskAcceptance.risk_acceptance_receipt_digest` to that receipt. No projection with a
missing closed-union member is defined or accepted. All duplicated ticket/
session/generation/scope fields in the receipt and scope must match. Both
receipt classes expire no later than five minutes after issue on a suspend-aware
continuous clock and are invalid after boot or suspend epoch change.

Receipt keys are Ed25519. `issuer_identity_digest` is exactly
`SHA-256("FlowProbe.Egress.ReceiptIssuerIdentity.v1\0" ||
uint16_be(issuer_kind_tag) || issuer_public_key_32 ||
canonical_cbor([installation_id, policy_broker_scope_id,
policy_broker_scope_version]))`. The public key and every scope value come from
the compile-time trusted policy-broker registry; a key-only or concatenated
unframed hash is invalid. `receipt_id` and `decision_nonce` are fresh
32-byte values. The 64-byte signature is over the fixed-array canonical receipt
without its signature, prefixed by
`FlowProbe.Egress.RiskReceipt.v1\0`. Target receipts use the distinct domain
`FlowProbe.Egress.TargetReceipt.v1\0`. A receipt is usable only by the exact
candidate plan whose `AuthorizationGrantDigest` contains it. The broker's
durable issuance key is `(policy_broker_challenge,
exact_registered_authorization_scope_digest)`:
an exact response-loss retry returns the byte-identical receipt, while reuse of
the challenge with a different scope is rejected. During
`PreparePlan`, the helper durably stores one
`AuthorizationConsumptionRecordV1` for the non-secret tuple
`(authorization_reference, issuer_identity_digest, receipt_id, decision_nonce,
preparation_ticket_id, session_id, generation)`. The closed reference selects
exactly one pair: `RiskAcceptance` carries
`Digest(RiskAcceptanceReceiptV1)` plus
`Digest(ProxyRiskAuthorizationScopeV1)`, while `ProbeTarget` carries
`Digest(ProbeTargetAuthorizationReceiptV1)` plus
`Digest(ProbeTargetAuthorizationScopeV1)`. A class sibling, generic receipt or
scope digest, cross-paired receipt/scope, or unknown reference variant has no
encoding. The record
binds that tuple to the exact ARCH-001 `CandidatePlanDigest`, prepare
idempotency key, and returned `PreparedPlanId + PlanDigest`; there is no
implementation-private prepare-result hash. Only an exact idempotent replay
returns those same identifiers. Another plan, ticket, session, generation, or
scope is rejected without consuming new authority. The consumption record is
written only after the final helper `PlanDigest` exists, in the same durable
transaction as the prepare idempotency mapping; its digest is never an input to
the candidate graph or `PlanDigest`.

`EgressCredentialConsumerId` is the sealed `RuntimeInstanceId` plus the runtime-
config node/operation digest. Delivery uses the protected runtime-adapter
boundary, is inaccessible to sibling processes and non-inheritable, and is
zeroized in the broker/materializer immediately after the private artifact is
complete. “One-use” describes that delivery, not a promise that the long-lived
runtime authenticates only once. Response-loss replay uses the descriptor
digest and a broker-side consumed-delivery record; it MUST NOT expose or require
the helper/journal to recover secret material.

### 4.5 HTTPS proxy TLS policy

```text
ProxyTlsPolicyDescriptorV1 = {
  reference_identity,
  trust_material_descriptor_digest,
  minimum_version,
  maximum_version,
  alpn_policy = Http11OrAbsent,
  algorithm_policy = UpstreamProxyAlgorithmsV1,
  revocation_policy,
  session_resumption = Disabled,
  early_data = Disabled,
  policy_version = 1,
}

TlsVerifierCapabilityEvidenceV1 = {
  source_revision_sha256,
  runtime_package_and_build_digest,
  adapter_id,
  adapter_version,
  adapter_binary_sha256,
  dependency_lock_sha256,
  tls_backend_and_version,
  tls_verifier_implementation_and_build_digest,
  os_family,
  architecture,
  exact_os_release_or_build,
  conformance_suite_and_vectors_sha256,
  required_test_case_count,
  executed_test_case_count,
  failed_test_case_count = 0,
  result = Passed,
  real_host_verified_at_utc_unix_seconds,
  validity = UntilAnyBoundTupleOrDigestChanges,
  authenticator,
}

RequestedProxyTrustModeV1 =
  | SystemRoots
  | PrivateAnchorSet { private_anchor_handle }
  | SystemRootsWithSpkiPins { spki_pin_handle }
  | PrivateAnchorSetWithSpkiPins {
      private_anchor_handle,
      spki_pin_handle,
    }

ReferenceIdentity =
  | DnsId { configured_proxy_dns_name }
  | IpId { configured_proxy_ip }

ProxyTrustModeV1 =
  | SystemRoots { effective_trust_snapshot_digest }
  | PrivateAnchorSet { private_anchor_set_descriptor_digest }
  | SystemRootsWithSpkiPins {
      effective_trust_snapshot_digest,
      spki_pin_set_descriptor_digest,
    }
  | PrivateAnchorSetWithSpkiPins {
      private_anchor_set_descriptor_digest,
      spki_pin_set_descriptor_digest,
    }

EffectiveProxyTrustSnapshotV1 = {
  platform_trust_scope,
  trust_backend_and_version,
  store_revision_digest,
  boot_epoch,
  sorted_anchor_der_sha256,
  flowprobe_ca_exclusion_set_digest,
  filtered_anchor_set_digest,
  observed_at,
  expires_at,
}

PrivateAnchorSetDescriptorV1 = {
  set_id,
  sorted_anchor_der_sha256,
  sorted_anchor_spki_sha256,
  anchor_count,
  total_der_bytes,
  flowprobe_ca_exclusion_set_digest,
  exact_material_set_digest,
}

SpkiPinSetDescriptorV1 = {
  set_id,
  sorted_unique_leaf_spki_sha256,
}

ProxyTrustMaterialDescriptorV1 = {
  preparation_ticket_id,
  session_id,
  generation,
  runtime_instance_id,
  runtime_config_node_id,
  material_delivery_slot_id,
  reference_identity,
  minimum_version,
  maximum_version,
  alpn_policy = Http11OrAbsent,
  algorithm_policy = UpstreamProxyAlgorithmsV1,
  revocation_policy,
  session_resumption = Disabled,
  early_data = Disabled,
  trust_mode,
  effective_trust_snapshot_digest?,
  private_anchor_set_descriptor_digest?,
  spki_pin_set_descriptor_digest?,
  materialization_policy = OwnerOnlyAtomicLoadThenDeleteV1,
  maximum_material_bytes,
}

ProxyTrustMaterialDeliveryRecordV1 = {
  delivery_record_id,
  prepared_plan_digest,
  generation,
  trust_material_descriptor_digest,
  runtime_instance_id,
  runtime_config_node_id,
  runtime_config_node_operation_digest,
  material_delivery_slot_id,
  delivered_anchor_set_digest,
  delivered_spki_pin_set_digest?,
  expected_materialization_target,
  consumer_channel_binding_digest,
  delivery_idempotency_key,
  delivered_at,
  consumed_at,
  authenticator,
}

PrivateArtifactMaterializationTargetV1 = {
  private_artifact_slot_id,
  derived_identity_recipe = InstallationSessionGenerationNodeSlotV1,
  exact_owner_identity: ArtifactOwnerIdentityV1,
  access_policy = OwnerOnlyExclusiveNoFollowNonInheritable,
  cleanup_policy = RemoveAfterAuthenticatedLoad,
}

ArtifactOwnerIdentityV1 = {
  installation_id,
  runtime_adapter_component_instance_id,
  runtime_instance_id,
  os_principal: WindowsSidBytes | UnixUidAndUserNamespace |
                DarwinAuditTokenIdentity,
}

ProxyEvidenceObservationContextV1 =
  | Preactivation {
      proof_specification_digest,
      helper_observation_nonce,
    }
  | Postactivation {
      proof_specification_digest,
      canary_observation_nonce,
      capture_generation_marker_digest,
    }
  | Renewal {
      activation_lease_id,
      lease_epoch,
      renewal_challenge_nonce,
      fence_token_digest,
    }

EffectiveProxyTrustObservationV1 = {
  prepared_plan_digest,
  generation,
  observation_context,
  trust_material_descriptor_digest,
  effective_trust_snapshot_digest,
  observed_at,
  expires_at,
  authenticator,
}

ProxyTrustRuntimeStateV1 =
  | InitialLoad {
      loaded_anchor_set_digest,
      loaded_spki_pin_set_digest?,
      runtime_artifact_handle_query_scope =
        ExactRuntimeProcessAndObservedResourceIdentity,
      runtime_artifact_handles_opened_during_load_count,
      load_copy_mode = BoundedCopyIntoPrivateNonFileBackedMemory,
      runtime_artifact_handle_count_after_close = 0,
      runtime_artifact_backed_mapping_count_after_load = 0,
      runtime_artifact_handles_closed_at,
      initial_loaded_at,
    }
  | CurrentStateReaffirmation {
      initial_load_observation_digest,
      loaded_anchor_set_digest,
      loaded_spki_pin_set_digest?,
      runtime_artifact_handle_query_scope =
        ExactRuntimeProcessAndObservedResourceIdentity,
      load_copy_mode = BoundedCopyIntoPrivateNonFileBackedMemory,
      runtime_artifact_handle_count_after_close = 0,
      runtime_artifact_backed_mapping_count_after_load = 0,
      reaffirmed_at,
    }

ProxyTrustMaterialLoadObservationV1 = {
  prepared_plan_digest,
  generation,
  observation_context,
  trust_material_descriptor_digest,
  trust_material_delivery_record_digest,
  runtime_instance_id,
  runtime_config_node_id,
  runtime_config_node_operation_digest,
  private_artifact_observed_resource_identity,
  runtime_load_channel_binding_digest,
  runtime_trust_state,
  material_source = ExactDeliveredMaterialOnly,
  ambient_store_reads = Disabled,
  reload_paths = Disabled,
  inherited_artifact_handle = Absent,
  expires_at,
  authenticator,
}

ProxyTrustArtifactStateV1 =
  | InitialMaterializeThenRemove {
      materialized_anchor_set_digest,
      materialized_spki_pin_set_digest?,
      materialized_owner_identity: ArtifactOwnerIdentityV1,
      owner_access = OwnerOnly,
      exclusive_create = Enforced,
      no_follow = Enforced,
      link_or_reparse_point = Absent,
      non_inheritable = Enforced,
      materialized_at,
      absence_query_scope = ExactObservedResourceIdentity,
      artifact_absent_after_load = true,
      adapter_artifact_handle_query_scope =
        ExactRuntimeAdapterProcessAndObservedResourceIdentity,
      adapter_owned_artifact_handle_count_after_remove = 0,
      adapter_artifact_backed_mapping_count_after_remove = 0,
      removed_at,
    }
  | CurrentAbsenceReaffirmation {
      initial_artifact_observation_digest,
      materialized_anchor_set_digest,
      materialized_spki_pin_set_digest?,
      absence_query_scope = ExactObservedResourceIdentity,
      artifact_absent_after_load = true,
      adapter_artifact_handle_query_scope =
        ExactRuntimeAdapterProcessAndObservedResourceIdentity,
      adapter_owned_artifact_handle_count_after_remove = 0,
      adapter_artifact_backed_mapping_count_after_remove = 0,
      reaffirmed_at,
    }

ProxyTrustMaterialArtifactObservationV1 = {
  prepared_plan_digest,
  generation,
  observation_context,
  trust_material_descriptor_digest,
  trust_material_delivery_record_digest,
  trust_material_load_observation_digest,
  runtime_instance_id,
  runtime_config_node_id,
  runtime_config_node_operation_digest,
  private_artifact_observed_resource_identity,
  runtime_load_channel_binding_digest,
  artifact_state,
  expires_at,
  authenticator,
}

ProxyTlsHandshakeObservationV1 = {
  prepared_plan_digest,
  generation,
  observation_context,
  runtime_instance_id,
  connection_binding_epoch,
  socket_policy_child_observation_digest,
  selected_proxy_endpoint_digest,
  proxy_tls_policy_descriptor_digest,
  trust_material_descriptor_digest,
  trust_material_delivery_record_digest,
  trust_material_load_observation_digest,
  trust_material_artifact_observation_digest,
  tls_stack_and_build_digest,
  attempt: ProxyTlsAttemptV1,
  started_at,
  completed_at,
  expires_at,
  authenticator,
}

ProxyTlsAttemptV1 =
  | NotStarted {
      terminal_phase: ProxyTlsPreClientHelloPhaseV1,
      tls_bytes_sent = 0,
      tls_bytes_received = 0,
      outcome: ProxyTlsTerminalOutcomeV1,
    }
  | ClientHelloStarted {
      client_hello_policy_image,
      client_hello_wire_length,
      client_hello_wire_bytes_sent,
      tls_bytes_received,
      outcome: ProxyTlsHandshakeOutcomeV1,
    }

ProxyTlsPreClientHelloPhaseV1 =
  | PrepareClientHello
  | FirstProtocolByteExpiryGuard
  | FirstClientHelloWrite

ProxyTlsTerminalOutcomeV1 =
  | Failed { error_code: ProxyTlsAuthenticateFailureCodeV1 }
  | TimedOut
  | Cancelled

ClientHelloPolicyImageV1 = {
  client_hello_count = 1,
  hello_retry_request: HelloRetryRequestObservationV1,
  legacy_version_u16 = 0x0303,
  legacy_session_id = Empty,
  legacy_compression_methods_wire_order = [0x00],
  secure_renegotiation_signaling: SecureRenegotiationSignalingV1,
  renegotiation_info_extension = Absent,
  extension_type_codepoints_wire_order,
  supported_versions_extension_wire_order,
  offered_cipher_suite_codepoints_wire_order,
  supported_groups_extension_wire_order,
  key_share_group_codepoints_wire_order,
  signature_algorithms_extension_wire_order,
  signature_algorithms_cert_extension_wire_order,
  extended_master_secret_offer: ExtendedMasterSecretOfferV1,
  offered_alpn = Absent | Http11,
  sni_observation,
  pre_shared_key_extension = Absent,
  psk_key_exchange_modes_extension = Absent,
  early_data_extension = Absent,
  session_ticket_extension = Absent,
}

HelloRetryRequestObservationV1 =
  | Absent
  | ReceivedAndRejected { requested_group_codepoint_u16? }

SecureRenegotiationSignalingV1 =
  | NotApplicableTls13Only
  | EmptyRenegotiationInfoScsv { codepoint_u16 = 0x00ff }

ExtendedMasterSecretOfferV1 =
  | NotApplicableTls13Only
  | OfferedEmptyExtension { extension_type_u16 = 0x0017 }

SniObservationV1 =
  | DnsANameEmitted { exact_a_label }
  | AbsentForIpId

TlsServerAuthenticationSchemeV1 =
  | Tls12ServerKeyExchange {
      signature_and_hash_codepoint_u16,
    }
  | Tls13ServerCertificateVerify {
      signature_scheme_codepoint_u16,
      context = ServerCertificateVerify,
    }

ReferenceIdentityValidationResultV1 =
  | DnsIdMatched { exact_reference_a_label }
  | IpIdMatched { exact_reference_ip }

TrustChainValidationResultV1 = {
  path_certificate_count,
  path_total_der_bytes,
  selected_anchor_der_sha256,
  rfc5280_path_validation = Passed,
  name_constraints_validation = Passed,
}

CertificateValidationTimeObservationV1 = {
  unix_seconds_i64,
  source = OperatingSystemUtcWallClock,
  sampled_at_helper_tick,
  boot_epoch,
  suspend_epoch,
  clock_discontinuity_observed = false,
}

CertificateTimeAndUsageResultV1 = {
  validation_time_observation: CertificateValidationTimeObservationV1,
  validity_window = Passed,
  leaf_basic_constraints = EndEntityPermitted,
  leaf_key_usage = AbsentOrDigitalSignaturePermitted,
  leaf_extended_key_usage = AbsentOrServerAuthPermitted,
}

CertificatePublicKeyObservationV1 =
  | RsaEncryption { modulus_bits }
  | Ecdsa { named_curve = P256 | P384 | P521 }
  | Ed25519

CertificateSignatureAlgorithmV1 =
  | RsaPkcs1 { hash = Sha256 | Sha384 | Sha512 }
  | RsaPssSha256 {
      mgf1_hash = Sha256,
      salt_length = 32,
      trailer_field = 1,
    }
  | RsaPssSha384 {
      mgf1_hash = Sha384,
      salt_length = 48,
      trailer_field = 1,
    }
  | RsaPssSha512 {
      mgf1_hash = Sha512,
      salt_length = 64,
      trailer_field = 1,
    }
  | EcdsaP256Sha256
  | EcdsaP384Sha384
  | EcdsaP521Sha512
  | Ed25519

CertificateAlgorithmObservationV1 = {
  validated_path_public_keys_leaf_to_anchor:
    [CertificatePublicKeyObservationV1],
  validated_certificate_signature_algorithms_child_to_parent:
    [CertificateSignatureAlgorithmV1],
}

RevocationValidationResultV1 =
  | NoOnlineCheck { status_claim = NotMade }

PinValidationResultV1 =
  | NotConfigured
  | MatchedLeafSpki {
      leaf_spki_sha256,
      spki_pin_set_descriptor_digest,
    }

SecureRenegotiationResultV1 =
  | NotApplicableTls13
  | Tls12ServerAcknowledgedEmptyRenegotiationInfo

ExtendedMasterSecretResultV1 =
  | NotApplicableTls13
  | Tls12ServerEchoedAndDerivedExtendedMasterSecret

VersionDowngradeProtectionResultV1 =
  | NotApplicableTls13Negotiated
  | NotApplicableTls12OnlyOffered
  | MixedOfferNegotiatedTls12 {
      server_random_suffix = NoDowngradeSentinel,
    }

ProxyTlsOuterPhaseV1 =
  | AuthenticateProxyTls
  | VerifyIdentityTrustPolicyAndAlpn

ProxyTlsHandshakeOutcomeV1 =
  | Passed {
      reference_identity_result: ReferenceIdentityValidationResultV1,
      trust_chain_result: TrustChainValidationResultV1,
      certificate_time_and_usage_result: CertificateTimeAndUsageResultV1,
      certificate_algorithm_observation: CertificateAlgorithmObservationV1,
      revocation_result: RevocationValidationResultV1,
      pin_result: PinValidationResultV1,
      loaded_anchor_set_digest,
      loaded_spki_pin_set_digest?,
      negotiated_version,
      version_downgrade_protection_result:
        VersionDowngradeProtectionResultV1,
      negotiated_cipher_suite_codepoint_u16,
      negotiated_group_codepoint_u16,
      server_authentication_scheme,
      secure_renegotiation_result: SecureRenegotiationResultV1,
      extended_master_secret_result: ExtendedMasterSecretResultV1,
      negotiated_alpn = Absent | Http11,
      session_resumed = false,
      early_data_sent = false,
      renegotiation_count = 0,
    }
  | Failed {
      bounded_phase = AuthenticateProxyTls,
      error_code: ProxyTlsAuthenticateFailureCodeV1,
    }
  | Failed {
      bounded_phase = VerifyIdentityTrustPolicyAndAlpn,
      error_code: ProxyTlsVerifyFailureCodeV1,
    }
  | TimedOut { bounded_phase: ProxyTlsOuterPhaseV1 }
  | Cancelled { bounded_phase: ProxyTlsOuterPhaseV1 }

ProxyTlsEvidenceReferenceV1 =
  | NotApplicable
  | ExternalHttpsPrepared {
      proxy_tls_policy_descriptor_digest,
      trust_material_descriptor_digest,
      delivery_record_digest,
      runtime_load_observation_digest,
      adapter_artifact_observation_digest,
      effective_trust_observation_digest?,
    }
  | ExternalHttpsHandshake {
      proxy_tls_policy_descriptor_digest,
      trust_material_descriptor_digest,
      delivery_record_digest,
      runtime_load_observation_digest,
      adapter_artifact_observation_digest,
      tls_handshake_observation_digest,
      effective_trust_observation_digest?,
    }

Socks5UdpAssociationEvidenceV1 =
  | NotApplicable
  | NotReached {
      udp_associate_control: Socks5UdpPreAssociationControlEvidenceV1,
    }
  | UdpControlChildReleaseAborted {
      last_completed_phase = Passed,
      next_phase_not_entered = BindOrProtectProxySocket {
        connection_role = Socks5UdpAssociationControl,
      },
      factory_terminal_transition_counter,
      factory_terminal_failure_reason: FactoryTerminalFailureReasonV1,
    }
  | UdpControlFirstByteGuardAborted {
      udp_associate_control_binding: Socks5UdpPublishedControlBindingV1,
      last_completed_phase = VerifyConnectedLocalPeerIfHostLocal {
        connection_role = Socks5UdpAssociationControl,
      },
      next_phase_not_entered = OfferExactMethods {
        connection_role = Socks5UdpAssociationControl,
      },
      method_bytes_sent = 0,
      factory_terminal_transition_counter,
      factory_terminal_failure_reason = FirstByteExpiryGuardFailed,
    }
  | Observed {
      udp_associate_control_binding: Socks5UdpPublishedControlBindingV1,
      socks5_udp_association_observation_digest,
    }

Socks5UdpPreAssociationControlEvidenceV1 =
  | NotStarted
  | UnpublishedProtocolTerminal
  | Published {
      binding: Socks5UdpPublishedControlBindingV1,
    }

Socks5UdpPublishedControlBindingV1 = {
  udp_control_connection_binding_epoch,
  udp_control_socket_child_observation_digest,
}

MinimumTlsVersion = Tls12 | Tls13
MaximumTlsVersion = Tls12 | Tls13
AlpnPolicy = Http11OrAbsent
AlgorithmPolicy = UpstreamProxyAlgorithmsV1
RevocationPolicy =
  | NoOnlineCheck
  | RequireFreshOcsp {
      maximum_age,
      maximum_response_bytes,
      maximum_responder_chain_bytes,
      responder_resolver_dependency,
    }
```

`TlsVerifierCapabilityEvidenceV1` is immutable release evidence, not a live
runtime self-assertion. `adapter_id`, `adapter_version`,
`tls_backend_and_version`, `os_family`, `architecture`, and
`exact_os_release_or_build` are ASCII `1..=128` bytes. The required and executed
test counts are equal in `1..=65535`; zero failures and `Passed` are literal.
The suite/vector hash covers the checked-in deterministic corpus plus the exact
real-host runner used for this tuple. `real_host_verified_at_utc_unix_seconds`
is in `0..=253402300799` and is attested record metadata, not a runtime
freshness clock; live freshness remains the helper-domain window on the
referencing `CapabilityReportV1`.

The implementation/build digest is recomputed exactly as
`SHA-256("FlowProbe.Egress.TlsVerifierBuild.v1\0" ||
source_revision_sha256 || runtime_package_and_build_digest ||
adapter_binary_sha256 || dependency_lock_sha256 ||
canonical_cbor([adapter_id, adapter_version, tls_backend_and_version]))`.
The root is signed by the closed `ReleaseVerifier` authority defined in section
10.3 and is valid only until any displayed tuple or digest changes. For an
`HttpsProxyTls` capability report, `release_evidence` is exactly
`TlsVerifier { tls_verifier_capability_evidence_digest =
Digest(TlsVerifierCapabilityEvidenceV1) }`; it never equals or substitutes for
the independent implementation/build digest. A report/root tuple mismatch,
unknown release authority, incomplete suite, nonzero failure count, or changed
source/package/backend/adapter/OS tuple is not `RealHostVerified`.

`RequestedProxyTrustModeV1` exists only on the Supervisor-to-trust-broker request
boundary before `PreparePlan`. Its opaque handles are non-displayable
authorizing capabilities. They never enter a registered root, compiler output,
helper request, plan, journal, runtime configuration, process environment,
status, diagnostic, log, or crash artifact. The broker resolves them to the
registered non-authorizing snapshot/anchor/pin descriptors before the candidate
plan is constructed.

`ProxyTlsPolicyDescriptorV1.trust_material_descriptor_digest` equals
`Digest(ProxyTrustMaterialDescriptorV1)`. The material descriptor repeats the
policy's identity, version, ALPN, algorithm, revocation, resumption, early-data,
and trust-mode values byte-for-byte but never contains the policy digest or any
runtime-config/template/plan digest. `runtime_config_node_id` and
`material_delivery_slot_id` are fresh non-authorizing 32-byte identifiers,
allocated within the preparation ticket before any descriptor digest; they are
not hashes and cannot resolve material. Exactly the snapshot/anchor/pin digest
fields named by its `ProxyTrustModeV1` variant are present; every other optional
trust field is absent. `maximum_material_bytes` equals the applicable anchor and
pin bounds in this section. A mismatch is `InvalidEgressSelection` before
materialization.

The digest construction is a strict DAG: allocate the node/slot IDs and resolve
content descriptors; digest `ProxyTrustMaterialDescriptorV1`; digest
`ProxyTlsPolicyDescriptorV1`; construct `SafeEgressSelectionV1`; compile the
secret-free runtime-config node and its exact ARCH-001 `OperationDigest`; then
seal `PlanDigest`. Only after `Prepared` may a delivery record bind that final
plan and node operation. A node/template digest is never an input to the
material or TLS-policy descriptor, so neither a direct nor an indirect
selection/config/material cycle exists.

The configured host, not a CNAME, reverse name, resolved address, CONNECT target,
or certificate-presented name, is the reference identity. `DnsId` is sent as SNI
and matched according to RFC 9525. `IpId` requires an exact certificate IP-ID
match and sends no SNI extension: an IP literal is never encoded as RFC 6066
`HostName`, and no reverse-DNS or configured alias is substituted.

TLS versions below 1.2, `minimum_version > maximum_version`, missing identity
verification, empty trust, insecure skip-verify, arbitrary callbacks, and
opportunistic fallback are invalid. `Http11OrAbsent` permits no negotiated ALPN
or exactly `http/1.1`; any other selected protocol is the terminal
`ProxyTlsAlpnMismatch` at `VerifyIdentityTrustPolicyAndAlpn`. TLS 1.2
renegotiation, TLS 1.3 early data, and
session resumption are disabled in v1; every connection performs a full
handshake against the same sealed trust material.

`UpstreamProxyAlgorithmsV1` is the following closed policy:

- TLS 1.3 cipher suites are exactly `TLS_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`;
- TLS 1.2 cipher suites are exactly the ECDHE-ECDSA and ECDHE-RSA variants of
  AES-128-GCM-SHA256, AES-256-GCM-SHA384, and
  CHACHA20-POLY1305-SHA256;
- named groups are exactly X25519, secp256r1, and secp384r1;
- TLS 1.2 server authentication uses the `ServerKeyExchange` signature because
  static RSA key exchange is prohibited. Its signature scheme may be ECDSA with
  SHA-256/384/512, RSA-PSS-RSAE with SHA-256/384/512, RSA-PKCS1 with
  SHA-256/384/512, or Ed25519. The ECDSA signature scheme does not encode a
  curve; the separately validated certificate public key and named group carry
  their own constraints;
- TLS 1.3 server `CertificateVerify` permits ECDSA with SHA-256/384/512,
  RSA-PSS-RSAE with SHA-256/384/512, or Ed25519, and prohibits RSA-PKCS1;
- accepted certificate public keys are `rsaEncryption` RSA 2048..=8192 bits,
  ECDSA P-256/P-384/
  P-521, or Ed25519; certificate signatures are RSA PKCS#1/PSS with
  SHA-256/384/512, exactly ECDSA P-256/SHA-256, P-384/SHA-384, or
  P-521/SHA-512, or Ed25519; and
- DSA, static RSA key exchange, CBC, RC4, 3DES, MD5, SHA-1, unknown algorithms,
  an `id-RSASSA-PSS` subject-public-key algorithm,
  a chain deeper than eight certificates, or a chain larger than 64 KiB DER is
  rejected.

An implementation that cannot configure and verify this exact suite/group/
signature policy is unsupported; it MUST NOT delegate any portion to a drifting
runtime default.

The v1 ClientHello codepoint images are byte-exact policy constants, not
implementation-selected subsets. `(minimum_version, maximum_version)` maps to
`supported_versions_extension_wire_order` as follows: `(Tls12,Tls12)` to
`[0x0303]`, `(Tls13,Tls13)` to `[0x0304]`, and `(Tls12,Tls13)` to
`[0x0304,0x0303]`. The corresponding cipher lists are:

```text
Tls12 only = [0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0x00ff]
Tls13 only = [0x1301,0x1302,0x1303]
Tls12..Tls13 =
  [0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0x00ff]
```

`supported_groups_extension_wire_order` is always
`[0x001d,0x0017,0x0018]` (X25519, P-256, P-384), and when TLS 1.3 is offered
`key_share_group_codepoints_wire_order` is exactly the same list; otherwise key
share is absent. The TLS-1.3-only signature-algorithms list is
`[0x0403,0x0804,0x0503,0x0805,0x0603,0x0806,0x0807]`; when TLS 1.2 is offered it
is exactly
`[0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0603,0x0806,0x0601,0x0807]`.
`signature_algorithms_cert_extension_wire_order` is always that latter list.
The extension-type order is exactly optional SNI `0x0000`, supported groups
`0x000a`, signature algorithms `0x000d`, signature algorithms cert `0x0032`,
optional extended master secret `0x0017`, optional ALPN `0x0010`, supported
versions `0x002b`, and optional key share `0x0033`, with absent optionals removed
and no other reordering. An invalid
minimum/maximum pair has no image.
Whenever TLS 1.2 is offered, `0x00ff` is the last cipher-list value and
`secure_renegotiation_signaling` is `EmptyRenegotiationInfoScsv`; for TLS-1.3-
only it is `NotApplicableTls13Only`. The signaling value is never a negotiable
cipher suite. A TLS 1.2 `Passed` root requires the ServerHello's
`renegotiation_info` extension with empty renegotiated-connection bytes and uses
`Tls12ServerAcknowledgedEmptyRenegotiationInfo`; TLS 1.3 uses
`NotApplicableTls13`. A missing/non-empty acknowledgement or negotiated
`0x00ff` fails the handshake.
Whenever TLS 1.2 is offered, `extended_master_secret_offer` is the empty
`0x0017` extension; for TLS-1.3-only it is `NotApplicableTls13Only`. A TLS 1.2
`Passed` root requires the server to echo the empty extension and the key
schedule to derive the extended master secret, represented only by
`Tls12ServerEchoedAndDerivedExtendedMasterSecret`. Echo without an offer,
missing/non-empty echo, a legacy master-secret derivation, or a TLS-1.3 result
other than `NotApplicableTls13` fails.

An effective system snapshot contains `1..=1024` anchors totaling at most 4 MiB
DER, sorted by DER SHA-256. It is observed for at most five minutes and binds the
platform store scope, backend/version, store revision, boot epoch, complete
FlowProbe interception-CA exclusion set, and final filtered-anchor-set digest.
Every use is carried by a registered `EffectiveProxyTrustObservationV1` signed
by exactly one `TrustMaterialBroker`. Its `observation_context` is the exact
preactivation, postactivation, or renewal context of the load/reaffirmation and
handshake roots that consume it. The initial observation names the exact
snapshot digest sealed in `ProxyTrustMaterialDescriptorV1`; a later observation
names a newly constructed snapshot whose platform scope, backend/version, store
revision, boot epoch, ordered anchor list, FlowProbe-CA exclusion set, and
filtered-set digest are byte-identical to the sealed snapshot. Only `observed_at`
and `expires_at` may differ. The observation is made after its phase challenge
exists and before the corresponding load/reaffirmation and TLS handshake; an
older phase root or an unbound content snapshot is not freshness evidence.
For preactivation, the broker revalidates the sealed snapshot after the helper
nonce exists and signs that exact digest. For postactivation and renewal, the
current snapshot's `observed_at` is no later than the wrapper's `observed_at`;
the wrapper `expires_at` is no later than the snapshot expiry, phase deadline,
or sealed maximum-observation age. The dependent handshake completes while both
are unexpired.
The filtered set is revalidated immediately before commit and every renewal; a
store revision or set change invalidates the generation. A private anchor set
contains `1..=16` exact DER anchors totaling at most 256 KiB, is sorted by DER
digest, excludes system roots and every FlowProbe interception CA, and binds
both DER and SPKI digest lists. An SPKI pin set contains `1..=8` unique raw
32-byte SHA-256 hashes of the leaf certificate's DER SubjectPublicKeyInfo.
Every `set_id` is a fresh non-authorizing 32-byte correlation identifier. It is
not a handle, path, key, hash of a handle/raw material, or broker lookup token;
knowing it, a descriptor digest, node ID, slot ID, or delivery record never
authorizes material retrieval.

`store_revision_digest` is exactly
`SHA-256("FlowProbe.Egress.PlatformTrustStoreRevision.v1\0" ||
canonical_cbor([platform_trust_scope, trust_backend_and_version,
platform_store_generation_bytes, sorted_anchor_der_sha256]))`; the backend must
obtain `platform_store_generation_bytes` from its closed capability mechanism,
and a platform with no stable complete generation remains unsupported.
`flowprobe_ca_exclusion_set_digest` is exactly
`SHA-256("FlowProbe.Egress.FlowProbeCaExclusionSet.v1\0" ||
uint32_be(count) || sorted_unique_interception_ca_spki_sha256...)`, with the
sorted list supplied by the accepted ARCH-003 interface; unavailable identity
data cannot be encoded as the empty set. Delivery, materialization, load, and
handshake `*_anchor_set_digest`/`*_spki_pin_set_digest` fields are not new
domains: each equals the applicable `filtered_anchor_set_digest`,
`exact_material_set_digest`, or `Digest(SpkiPinSetDescriptorV1)` selected by the
same descriptor.

For an ordered anchor digest list `D`, the set digest is exactly
`SHA-256("FlowProbe.Egress.AnchorSet.v1\0" || uint32_be(count(D)) || D[0] || ...
|| D[n-1])`; system/private sets use the same formula only after the applicable
FlowProbe-CA subtraction. `filtered_anchor_set_digest` and
`exact_material_set_digest` must equal that value. Pin-set ordering is ascending
raw hash bytes and its descriptor root supplies the independent pin-set digest.

Pins are an additional AND condition after chain, time, usage, reference-
identity, algorithm, and revocation-policy validation; they never replace those
checks. Rotation succeeds only when the sealed set already contains the
presented leaf pin. In particular, an adapter MUST NOT map an AND-pin mode to
the pinned sing-box `certificate_public_key_sha256` behavior because that path
enables insecure verification and implements different semantics.

`NoOnlineCheck` means exactly that chain validation makes no revocation claim;
it is not named or reported as a platform default. `RequireFreshOcsp` requires a
successful bounded OCSP response for the leaf, signed by the issuer or an
authorized responder, within the sealed age/clock bounds. Its response is at
most 32 KiB and responder chain at most 32 KiB. CRL fetching, soft-fail, and an
ambient responder resolver are unsupported. The pinned sing-box 1.13.19
outbound TLS schema exposes no revocation-status enforcement surface, so
`RequireFreshOcsp` is unconditionally `UnsupportedProtocolFeature` in contract
v1. Enabling it requires a later accepted contract version that closes stapled
versus fetched evidence and, for fetching, the responder authority, scheme,
host, port, address classes, resolver/family policy, zero redirects, actor/
socket exclusion, byte bounds, and SSRF authorization. A runtime adapter alone
cannot enable this v1 variant.

The trust resolver MUST exclude every FlowProbe-owned local interception CA
identity supplied by the future versioned ARCH-003 identity-set interface from
the effective upstream-proxy anchor set, even if that CA is present in the
system store. `flowprobe_ca_exclusion_set_digest` binds the authoritative empty
or non-empty result; an unavailable interface while such a CA may exist is
`DependencyContractUnavailable`, not an assumed empty set. A backend that
cannot construct and prove the filtered root snapshot is unsupported. ARCH-002
does not define CA identity/store semantics and never installs, removes, or
broadens system trust. Target TLS established inside CONNECT is independent
from TLS to the proxy.

During preflight the trust-material broker may inspect its private handle only
to compute the non-authorizing content descriptors and keep a private pending
association. Raw DER/pin bytes never leave that broker before `Prepared`. After
`Prepared`, the broker atomically consumes the handle association and performs
one delivery to the exact plan/runtime/node/slot. It signs one registered
`ProxyTrustMaterialDeliveryRecordV1`; that safe projection omits the handle and
raw material and is evidence, not a bearer capability. The private broker ledger
retains the handle-to-record consumption fact, while the helper/journal retain
only the registered record. Response loss returns the byte-identical record and
never redelivers material; another plan, node, slot, runtime, idempotency key, or
second consumption is refused.

`consumed_at` is the helper-clock tick at which the broker irreversibly consumes
the pending handle association, before it releases any material. `delivered_at`
is recorded only after the exact bound consumer channel has acknowledged the
complete bounded delivery and before the adapter may materialize it. Thus a
successful record requires `consumed_at <= delivered_at`; a failed or partial
delivery produces no success record and cannot restore the consumed handle. The
record's expected target is recomputed from
`InstallationSessionGenerationNodeSlotV1` and must equal the exact ARCH-001
private-artifact slot, owner, access, and cleanup predicate sealed for the node.
Neither a path string nor a consumer-supplied observed identity can replace that
derivation.

The same owner-only, no-follow, non-inheritable private-artifact rules used for
credential material apply. The adapter writes exactly the delivered anchor/pin
sets and, after the authenticated load handshake, removes the artifact. It signs
`ProxyTrustMaterialArtifactObservationV1`, including the exact ARCH-001
`ObservedResourceIdentity`, materialized/absent `ObservedState` values, delivered
anchor/pin digests, no-follow/access/inheritance results, load-root digest, and
gate-channel binding. These are typed upstream values, not implementation-
private evidence hashes. Independently, the Network Runtime loads exactly those
sets, disables every ambient store read and reload path, proves no inherited
artifact handle, and signs `ProxyTrustMaterialLoadObservationV1`. During an
initial load it scopes its handle census to the exact runtime process and exact
ARCH-001 observed resource identity, records `1..=8` handles opened during load,
copies the bounded material into private non-file-backed memory, then proves
both the remaining handle count and artifact-backed mapping/section-view count
are exactly zero and records the closure tick. A current-state reaffirmation
repeats that scope, copy mode, and both zero counts. The adapter's
artifact root independently scopes only adapter-owned handles to the exact
adapter process and resource identity and proves its post-removal handle and
artifact-backed mapping counts are zero;
it cannot make a claim about runtime-owned handles. The load root
proves runtime-internal state; the artifact root, which depends on it, proves
adapter-owned creation and deletion. The broker record binds only the expected
target/recipe/slot and consumer channel; it never claims an actual observed file
identity.

Neither signer may attest the other's facts, and both bind the same plan,
descriptor, delivery record, runtime instance, node ID, node `OperationDigest`,
actual artifact identity, and runtime load-channel binding. The load root's
`runtime_load_channel_binding_digest` is the distinct runtime-trust-load channel
domain defined above and includes its own
`authenticator.header.authority_binding.ExternalExecutorGate.gate_channel_binding_digest`
in the signed binding context; byte equality between the two different domains
is invalid. The artifact root repeats the load-channel digest from its referenced load root. It is
the domain-separated binding of the authenticated adapter-to-runtime load-ack/
control channel established by the exact sealed runtime node and external gate;
it is not `ProxyTrustMaterialDeliveryRecordV1.consumer_channel_binding_digest`,
which binds the separate broker-to-materializer delivery. A wrong channel,
another runtime/root, or a header/body/artifact substitution invalidates both
roots. Initial facts obey
`consumed_at <= delivered_at <= materialized_at <= initial_loaded_at <=
runtime_artifact_handles_closed_at <= removed_at`; every preactivation TLS
handshake starts at or after `removed_at`
and completes before all referenced observation deadlines. The load and artifact
roots' actual ARCH-001 `ObservedResourceIdentity` must be byte-identical, derive
to the delivery record's expected target, and be the identity used for both the
load channel and exact absence query. For postactivation and renewal, the runtime
and adapter issue context-bound `CurrentStateReaffirmation`/
`CurrentAbsenceReaffirmation` roots that point directly back to the initial
roots and repeat the exact material-set digests. They neither redeliver nor
reload material. Both reaffirmation ticks precede the referenced handshake's
`started_at`, and the handshake completes before every referenced expiry.

Context equality is exact, not semantic: preactivation roots repeat
`EgressPathProofResultV1.proof_specification_digest` and
`helper_assigned_observation_nonce`; postactivation roots repeat that proof
digest plus `PostactivationCanaryResultV1.helper_assigned_observation_nonce` as
`canary_observation_nonce` and its `capture_generation_marker_digest`; renewal
roots repeat `SustainedHealthObservationV1.activation_lease_id`, `lease_epoch`,
`renewal_challenge_nonce`, and `fence_token_digest`. A root from another phase or
an earlier checkpoint is invalid even if all material digests are unchanged.

The helper verifies both signatures and cross-field equality, compares safe
material values with the broker record and expected ARCH-001 operation/result
identities, and stores only registered roots/digests. It does not read raw
anchors. Missing material, slot reuse, time inversion, snapshot drift, runtime/
config substitution, ambient-root/reload fallback, inherited/runtime-owned/
adapter-owned residual handle,
single-signer evidence, or cleanup failure makes every affected HTTPS mode
unsupported and blocks commit or renewal.
An implementation unable to enumerate both handles and file-backed mappings for
the exact process/resource scope cannot emit these roots and keeps every HTTPS
mode unsupported; closing a pathname or boolean self-assertion is not evidence.

Once an HTTPS connector child has passed route/peer checks and been signed and
released, that proof/checkpoint emits exactly one registered
`ProxyTlsHandshakeObservationV1` signed by the `NetworkRuntime`. A failure
before a connector child exists uses the enclosing result's `BeforeConnector`
prefix and `ExternalHttpsPrepared`; it must not fabricate a tag-42 root. The
tag-42 observation binds the context-matched independent material observations
and delivery record and the exact released socket child/connection.
`NotStarted` is permitted only for the three displayed post-release,
pre-ClientHello phases and records zero TLS bytes plus a non-success terminal
outcome. `FirstClientHelloWrite` represents a first write that returns zero
bytes with failure, timeout, or cancellation; only a strictly positive write
transitions to `ClientHelloStarted`. `ClientHelloStarted` carries the actual
wire-order policy image. `client_hello_wire_length` is `1..=16384`,
`client_hello_wire_bytes_sent` is `1..=client_hello_wire_length`, and
`tls_bytes_received` is no greater than the proof specification's remaining
`maximum_total_protocol_bytes` and never exceeds 262144. An implementation
terminates before accepting a byte that would exceed that remaining budget; an
already-buffered over-budget read cannot produce `Passed`. A passed handshake
requires the full ClientHello length to have been sent; a failed, timed-out, or
cancelled attempt may record a strict partial prefix and never fabricates
`NotStarted`. Exactly one
logical ClientHello is prepared and no second ClientHello is sent. Its legacy version is `0x0303`,
legacy session ID is empty, and compression methods are exactly the single null
method. `supported_versions` is always present with `1..=2` unique versions;
cipher suites contain `1..=16`, supported groups `1..=8`, key shares `1..=3`,
`signature_algorithms` `1..=16`, and `signature_algorithms_cert` `1..=16`
unique codepoints. Key share is present exactly when TLS 1.3 is offered and its
groups form a non-empty ordered subset of supported groups; otherwise it is
absent. Each list is in emitted wire order and contains exactly the allowed
policy subset, with no GREASE, SHA-1, unknown, or drifting default entry.
The extension-type list contains `5..=8` unique codepoints in actual wire order
and is exactly the set represented by the present SNI, supported-groups,
signature-algorithms, signature-algorithms-cert, extended-master-secret,
supported-versions, key-share, and optional ALPN fields; no unrepresented or
duplicate extension is allowed.
SNI and ALPN follow their closed unions. `pre_shared_key`,
`psk_key_exchange_modes`, `early_data`, and `session_ticket` are absent, so a
server rejection cannot disguise a prohibited resumption or 0-RTT offer.

The three `ProxyTlsPreClientHelloPhaseV1` values are tag-42 subphases and all
project to the section 11.3 outer phase `AuthenticateProxyTls`; they are never
encoded as new `ProtocolPhaseOutcomeV1.phase` values. A `NotStarted.outcome`
class/error equals the terminal `AuthenticateProxyTls` phase outcome. For `ClientHelloStarted`, a
transport, ClientHello/ServerHello/record/transcript/key-schedule, HRR, alert,
or cryptographic handshake terminal outcome uses outer phase
`AuthenticateProxyTls`, while reference-identity, chain/time/usage,
certificate/negotiated-algorithm, revocation, pin, downgrade, renegotiation,
extended-master-secret, and ALPN predicate evaluation uses
`VerifyIdentityTrustPolicyAndAlpn`; no error belongs to both classes. Transport,
ClientHello/ServerHello, record/transcript/key-schedule, HRR, alert, and
cryptographic-handshake failures map only to `ProxyTlsFailed`; a current trust-
snapshot mismatch maps only to `ProxyTrustSnapshotChanged`; and a runtime
artifact-containment failure maps only to `RuntimeArtifactContainmentFailed`.
Reference-identity mismatch maps only to `ProxyTlsIdentityMismatch`, chain/time/
usage/pin failure only to `ProxyTlsTrustFailed`, missing required revocation
evidence only to `ProxyTlsRevocationUnavailable`, ALPN mismatch only to
`ProxyTlsAlpnMismatch`, and every other rejected negotiated-version, downgrade,
algorithm, renegotiation, extended-master-secret, resumption, or early-data
predicate only to `ProxyTlsPolicyViolation`. Its bounded phase and class/error
equal the terminal protocol-phase entry. The enclosing tag-13/tag-28/tag-29
outcome equals that protocol negative only when no higher-priority factory/
census checkpoint or,
for tag 28, traversal failure in the shared outer
projection applies; otherwise the higher-priority code wins without changing
the nested TLS fact. A passed tag-42 root requires both outer TLS phases `Passed` in that
order.
After tag-42 `Passed`, later CONNECT/challenge failure leaves the TLS root
passed. Any subphase encoded as an outer phase, coarse/fine phase mismatch, or
TLS failure followed by a later protocol phase is invalid.

The expected evidence seals one exact `CapabilityReportV1` root whose key is
`HttpsProxyTls`, its exact `TlsVerifierCapabilityEvidenceV1` root, and one exact
verifier implementation/build digest. The report
must be `SupportedByDesign`, `Ready`, `RealHostVerified`, and `Supported` for
the exact OS/architecture/release, runtime package, backend, and adapter tuple;
for this key its `release_evidence` is the `TlsVerifier` variant whose typed
root digest is exactly `tls_verifier_capability_evidence_digest`, never the
build digest. The evidence
root's `tls_verifier_implementation_and_build_digest`, the expected build
digest, the verifier entry in the manifest named by
`runtime_package_and_build_digest`, and
`ProxyTlsHandshakeObservationV1.tls_stack_and_build_digest` are byte-identical.
An unknown digest, dynamic/unmanifested verifier load, same signer with a
different stack, capability/evidence/package mismatch, or missing manifest entry
keeps `ExternalHttps` unsupported. No runtime signature can promote an
unreviewed TLS implementation into conformance.

The handshake root is also bound to the exact end-to-end proxy connection. For
preactivation its `connection_binding_epoch`,
`socket_policy_child_observation_digest`, and
`selected_proxy_endpoint_digest` equal respectively the matching
`EgressPathProofResultV1.evidence.attempts[i].terminal.ConnectorTerminal`
connection epoch and child digest plus that attempt's
`candidate_binding.ExternalProxy.selected_proxy_endpoint_digest`. A
`BeforeConnector` attempt has no tag-42 root. For
postactivation and renewal, those three fields always equal the enclosing tag-28/
tag-29 `ConnectorTerminal` attempt directly. When that attempt uses
`PhaseBoundCompleted`, they additionally equal the referenced
`PhaseBoundProbeChallengeResultV1`; when it terminates before challenge entry
and uses `NoCompletedResult`, no tag-37 root is required or fabricated. Any
present phase-bound result's attempt ordinal, tuple, candidate binding, child,
and accumulator already equal the enclosing canary/health attempt, and its
selected proxy endpoint is a current member of the exact sealed proxy endpoint set. The child socket identity and endpoint
scope are the TCP connection on which the observed ClientHello and handshake
occurred. After TLS completes, HTTP CONNECT and the target challenge continue
on that same connection and binding epoch. Any reconnect creates the next
factory child, repeats the HostLocal peer check when applicable, emits a new
TLS root, and restarts the bounded protocol state machine. A same-plan but
different child, epoch, endpoint, socket, TLS-A/CONNECT-B splice, or TLS-root
replay forbids `Passed`.
`HelloRetryRequest` is unsupported: receipt is recorded as
`ReceivedAndRejected`, no second ClientHello is emitted, and `Passed` requires
`Absent`.

Only `ProxyTlsHandshakeOutcomeV1::Passed` carries reference-identity,
chain/time/usage/algorithm/revocation/pin results and negotiated values;
failure/timeout/cancellation carries only its bounded phase and reason, so no
placeholder success facts exist. A `NotStarted` attempt never carries any
`ProxyTlsHandshakeOutcomeV1` or ClientHello/server/certificate fact.
`Tls12ServerKeyExchange` is
valid only with TLS 1.2 and records the exact 16-bit signature/hash codepoint;
`Tls13ServerCertificateVerify` is valid only with TLS 1.3 and the fixed server
context. A TLS 1.2 ECDSA codepoint does not assert a certificate curve; the
certificate key and negotiated group are independently checked. A passed root
requires every decision to pass, material/load/artifact equality,
`DnsANameEmitted` exactly for `DnsId`, `AbsentForIpId` exactly for `IpId`, no
resumption, zero early-data bytes, zero renegotiations, a policy-permitted ALPN,
and completion before `expires_at`. The root retains no raw certificate, chain,
transcript, SNI buffer, OCSP bytes, or alert text.
`TrustChainValidationResultV1.path_certificate_count` is `1..=8`, its total DER
bytes are `1..=65536`, the public-key list has exactly that count, and the
validated child-to-parent signature-algorithm list has exactly one fewer entry,
in path order. Thus every subject and every issuer key actually used by path
validation is represented; checking only the leaf is invalid.
`selected_anchor_der_sha256` is the DER hash of the actual terminal trust anchor
used by that successful path. For a system-root mode it is a member of the
context-bound `EffectiveProxyTrustSnapshotV1.sorted_anchor_der_sha256`; for a
private-anchor mode it is a member of the exact
`PrivateAnchorSetDescriptorV1.sorted_anchor_der_sha256`. It must also be a
member of the exact anchor set loaded under the matching material/load/artifact
roots. The corresponding sorted list, filtered-set digest, and loaded-anchor-set
digest are the same ones already bound by the selected trust mode; a substituted
anchor, an anchor removed by the FlowProbe-CA exclusion set, or a terminal
certificate not present in that set forbids `Passed`. A single-certificate path
is valid only when that certificate is itself a member of the selected exact
anchor set and every other leaf/reference/time/usage rule passes. RSA modulus
size is `2048..=8192`. RSA-PSS is accepted only with MGF1 using the same fixed hash,
salt length equal to that hash output, and trailer field one as encoded by the
three closed variants; every other key, signature, curve, parameter, hash,
validation-status, or result variant is rejected.
`CertificateValidationTimeObservationV1.unix_seconds_i64` is in
`0..=253402300799` and is the single OS UTC wall-clock sample used for every
certificate validity decision in the path. It is a runtime-signed observation,
not a claim that the OS clock is an independently authenticated real-time
source. `sampled_at_helper_tick` is in the same helper-defined suspend-aware
monotonic domain as the enclosing handshake and obeys
`started_at <= sampled_at_helper_tick <= completed_at < expires_at`; its
`boot_epoch` and `suspend_epoch` equal the sealed plan/handshake clock context.
The OS UTC clock is read exactly once for the path. A read failure, a different
sample, epoch mismatch, or a wall-clock discontinuity detected between
`started_at` and `completed_at` forbids `Passed`; an implementation unable to
detect such discontinuity keeps `ExternalHttps` unsupported. The
reference-identity variant exactly matches the policy identity; DNS comparison
follows RFC 9525 and IP comparison is exact binary equality. `NoOnlineCheck`
produces only `NoOnlineCheck { status_claim = NotMade }`; no successful online-
revocation claim exists in v1.
`pin_result` is `MatchedLeafSpki` exactly for a pin-bearing trust mode and
`NotConfigured` otherwise. `loaded_spki_pin_set_digest` and the corresponding
delivery/load/artifact pin fields are present exactly for a pin-bearing mode;
the matched result must name the leaf SPKI and exact delivered pin-set
descriptor. The loaded anchor and pin digests in `Passed` equal the delivery, load,
artifact, policy, and descriptor values byte-for-byte.
The negotiated version is a member of `supported_versions`; the negotiated
cipher is in the offered list and legal for that version; and the negotiated
group is in `supported_groups` and, for TLS 1.3 without HRR, in `key_share`.
`NotApplicableTls13Negotiated` is required whenever TLS 1.3 is negotiated,
`NotApplicableTls12OnlyOffered` is required only for the TLS-1.2-only policy,
and `MixedOfferNegotiatedTls12` is required only when `[Tls13,Tls12]` was
offered and TLS 1.2 was negotiated. That last result is emitted only after the
client rejects both eight-byte `DOWNGRD\x01` and `DOWNGRD\x00` ServerHello
random suffixes; the root retains only the closed `NoDowngradeSentinel` result,
not the random bytes. A sentinel, variant/version-policy mismatch, or absent
check forbids `Passed`.
The server-authentication scheme is in `signature_algorithms`, and each
validated non-anchor certificate signature is in
`signature_algorithms_cert`. Independently legal but cross-inconsistent image,
negotiation, or certificate fields invalidate `Passed`.
For TLS 1.2 the authentication family encoded by the negotiated cipher suite is
also closed. `0xc02b`, `0xc02c`, and `0xcca9` are ECDHE_ECDSA suites and require
an ECDSA or Ed25519 leaf public key plus a `ServerKeyExchange` signature made by
that exact leaf key. An ECDSA leaf requires one of
`0x0403/0x0503/0x0603`; an Ed25519 leaf requires `0x0807`.
`0xc02f`, `0xc030`, and `0xcca8` are ECDHE_RSA suites and require a
`RsaEncryption` leaf public key plus a signature made by that exact leaf key
using RSA-PSS-RSAE `0x0804/0x0805/0x0806` or RSA-PKCS1
`0x0401/0x0501/0x0601`. No ECDHE_ECDSA/RSA-leaf,
ECDHE_RSA/ECDSA-or-Ed25519-leaf, or leaf/signature-family cross-product is
accepted. TLS 1.3 cipher suites do not encode an authentication family; their
leaf-key/signature relationship remains the exact mapping below.
For a path of `N` public keys, signature entry `i` is zipped with child key `i`
and issuer key `i+1`. `EcdsaP256Sha256`, `EcdsaP384Sha384`, and
`EcdsaP521Sha512` map to `0x0403/0x0503/0x0603` only with the exact corresponding
issuer curve; Ed25519 maps to `0x0807` only with an Ed25519 issuer;
RSA-PKCS1-SHA256/384/512 map to `0x0401/0x0501/0x0601`; and the three fixed
RSA-PSS variants map to RSA-PSS-RSAE `0x0804/0x0805/0x0806`, with either RSA
mapping requiring a `RsaEncryption` issuer. No RSA-PSS-PSS codepoint or
`id-RSASSA-PSS` subject key is accepted. The same key/codepoint relationship is
enforced for RSA and Ed25519 leaf server authentication, with RSA-PKCS1
additionally prohibited for TLS 1.3. TLS 1.3 ECDSA `CertificateVerify` requires
the exact P-256/SHA-256, P-384/SHA-384, or P-521/SHA-512 pair. TLS 1.2 ECDSA
`ServerKeyExchange` retains the older semantics: `0x0403/0x0503/0x0603` binds
only SHA-256/384/512 and accepts either P-256 or P-384 independently of the hash
codepoint. Those are the only ECDSA leaf curves in the fixed TLS 1.2
`supported_groups` image; a P-521 leaf is rejected for TLS 1.2 even though
`0x0603` remains advertised and P-521/`0x0603` is valid for TLS 1.3
`CertificateVerify`. That older-semantics exception does not relax the TLS 1.2
supported-group constraint or any certificate-signature entry.

### 4.6 SOCKS5 UDP policy

```text
Socks5UdpPolicy =
  | Disable
  | RequireAssociate {
      relay_family_policy,
      probe_datagram_bytes = 40,
    }

SocksRelayFamilyPolicy =
  | RelayIpv4Only
  | RelayIpv6Only
  | RelayAnyUnicast

Socks5UdpAssociationObservationV1 = {
  prepared_plan_digest,
  generation,
  observation_context: ProxyEvidenceObservationContextV1,
  egress_selection_safe_digest,
  runtime_instance_id,
  target_profile_digest,
  attempt_ordinal,
  family_tuple_ordinal,
  family_tuple: PathFamilyTupleV1,
  candidate_binding: ConnectionAttemptCandidateBindingV1,
  target_tunnel_connection_binding_epoch,
  selected_proxy_endpoint_digest,
  target_tunnel_socket_child_observation_digest,
  udp_control_connection_binding_epoch,
  udp_control_socket_child_observation_digest,
  udp_socket_child_observation_digest?,
  following_socket_observation_accumulator_digest,
  associate_exchange_evidence: Socks5UdpAssociateExchangeEvidenceV1,
  relay_evidence: Socks5UdpRelayEvidenceV1,
  udp_canary_evidence: Socks5UdpCanaryEvidenceV1,
  observed_at,
  expires_at,
  outcome: Socks5UdpAssociationOutcomeV1,
  authenticator,
}

Socks5UdpRelayEvidenceV1 =
  | NotSelected
  | SelectedLiteral {
      relay_endpoint_digest,
      relay_endpoint_set_digest,
      relay_address_class = PublicGlobalUnicast,
      relay_locality = Remote,
    }

Socks5UdpAssociateExchangeEvidenceV1 =
  | NotStarted
  | Attempted {
      request: Socks5UdpAssociateRequestEvidenceV1,
      reply: Socks5UdpAssociateReplyEvidenceV1,
    }

Socks5UdpAssociateRequestEvidenceV1 =
  | Ipv4UnspecifiedSameFamily {
      associate_request_frame_digest,
      request_frame_bytes = 10,
      request_bytes_sent: 0..=10,
    }
  | Ipv6UnspecifiedSameFamily {
      associate_request_frame_digest,
      request_frame_bytes = 22,
      request_bytes_sent: 0..=22,
    }

Socks5UdpAssociateReplyEvidenceV1 =
  | NotObserved { reply_bytes_received = 0 }
  | Partial {
      associate_reply_frame_digest,
      reply_bytes_received: 1..=262,
      terminal: PeerClosed | TimedOut | Cancelled,
    }
  | Observed {
      associate_reply_frame_digest,
      reply_bytes_received: 1..=262,
      parse: Socks5UdpAssociateReplyParseV1,
    }
  | OverBound {
      observed_reply_bytes_at_least = 263,
    }

Socks5UdpAssociateReplyParseV1 =
  | StructurallyInvalid { reason: Socks5ReplyStructuralErrorV1 }
  | Rejected { rep: Socks5ReplyStatusV1 }
  | SuccessfulLiteral
  | SuccessfulDomainUnsupported

Socks5ReplyStructuralErrorV1 =
  | WrongVersion
  | WrongReservedByte
  | UnknownAddressType
  | InvalidDomainLength
  | TrailingBytes
  | SuccessZeroPort

Socks5ReplyStatusV1 =
  | GeneralFailure { rep = 0x01 }
  | ConnectionNotAllowed { rep = 0x02 }
  | NetworkUnreachable { rep = 0x03 }
  | HostUnreachable { rep = 0x04 }
  | ConnectionRefused { rep = 0x05 }
  | TtlExpired { rep = 0x06 }
  | CommandNotSupported { rep = 0x07 }
  | AddressTypeNotSupported { rep = 0x08 }
  | Unassigned { rep: 0x09..=0xff }

Socks5UdpCanaryDestinationV1 =
  | ProxyOpaqueDomain {
      exact_normalized_name,
      port,
    }
  | LocalLiteral {
      destination_endpoint_digest,
    }

ObservedUdpDatagramSourceV1 =
  | ValidEndpoint {
      endpoint_digest,
    }
  | ZeroSourcePortIpv4 {
      zero_port_source_identity_digest,
    }
  | ZeroSourcePortIpv6 {
      zero_port_source_identity_digest,
    }

Socks5UdpCanaryEvidenceV1 =
  | NotReached
  | PreparationFailed {
      runtime_received_delivery = false,
      request_datagrams_sent = 0,
    }
  | PreDatagramFailedAfterDurableRecord {
      commitment,
      delivery_consumption_record_digest,
      delivery_state:
        NotReceivedByRuntime | ReceivedAndZeroizedBeforeDatagramConstruction,
      request_datagram_bytes_existed = false,
    }
  | Attempted {
      destination: Socks5UdpCanaryDestinationV1,
      commitment,
      delivery_consumption_record_digest,
      request_datagram_digest,
      request_datagram_bytes: 48..=302,
      request_datagrams_sent = 0 | 1,
      response: Socks5UdpCanaryResponseEvidenceV1,
    }

Socks5UdpCanaryResponseEvidenceV1 =
  | NotReceived { response_datagram_bytes = 0 }
  | Rejected {
      observed_udp_source: ObservedUdpDatagramSourceV1,
      response_datagram_digest,
      response_datagram_bytes: 0..=302,
      reason: Socks5UdpCanaryRejectionReasonV1,
    }
  | EchoValidated {
      observed_udp_source: ObservedUdpDatagramSourceV1,
      response_destination: Socks5UdpCanaryDestinationV1,
      response_frame_digest,
      response_datagram_digest,
      response_datagram_bytes: 48..=302,
    }
  | Oversize {
      observed_udp_source: ObservedUdpDatagramSourceV1,
      observed_datagram_bytes_at_least = 303,
    }

Socks5UdpCanaryRejectionReasonV1 =
  | UnexpectedRelaySource
  | MalformedReservedField
  | Fragmented
  | InvalidDestinationEncoding
  | DestinationMismatch
  | InvalidEchoFrame

Socks5UdpAssociationOutcomeV1 =
  | Passed {
      udp_control_connection_state = Open,
      association_state = Active,
      relay_source_validation = ExactReturnedRelayOnly,
      fragmentation_policy = DropNonZeroFragBeforePayload,
    }
  | UdpChildReleaseAborted {
      last_completed_phase = ClassifyAndExcludeRelay,
      next_phase_not_entered = SendBoundedFRAG0Canary,
      factory_terminal_transition_counter,
      factory_terminal_failure_reason: FactoryTerminalFailureReasonV1,
    }
  | Failed {
      bounded_phase: ProtocolPhaseV1,
      error_code: Socks5UdpFailureCodeV1,
    }
  | TimedOut { bounded_phase: ProtocolPhaseV1 }
  | Cancelled { bounded_phase: ProtocolPhaseV1 }
```

`probe_datagram_bytes` is exactly 40 and applies only to the ARCH-002 synthetic
canary; the complete RFC 1928 envelope is bounded separately below. ARCH-004
owns application-datagram size, flow, fragmentation, and transport policy.
`Disable` means a request requiring UDP is rejected. `RequireAssociate` means
UDP MUST traverse one RFC 1928 association through the selected proxy or the
request is rejected. Neither variant authorizes direct UDP or UDP-over-TCP.
The association's destination addressing inherits the selection's single
`destination_resolution`; there is no second family/resolution choice to
conflict with it. V1 accepts only an IP-literal relay in `BND.ADDR`. A domain-
form relay is terminal `Socks5RelayDomainUnsupported` at `ValidateRelayReply`,
starts no resolver or UDP child, and cannot be promoted by an ambient or
pre-plan resolver.
`relay_family_policy` uses exactly `SocksRelayFamilyPolicy`; the proxy returns
one association endpoint, so preference and `RequireBoth` semantics are not
claimed.

`associate_exchange_evidence=NotStarted` is exact only when the terminal prefix
ends at `EstablishedAuthenticatedSOCKS5Control` before a request byte exists.
From `SendUDP_ASSOCIATEWithUnspecifiedSameFamily` onward it is `Attempted`. Its
request frame is the exact 10-byte IPv4 or 22-byte IPv6 frame defined in section
11.5 for the control socket family; the request digest covers all of those bytes
and `request_bytes_sent` is the actual prefix length in
`0..=request_frame_bytes`. A later phase requires the full exact length. A
partial write, timeout, or cancellation has `reply=NotObserved` and cannot enter
relay validation.

`Partial` retains the exact bounded prefix digest and byte count. `PeerClosed`
maps to `Socks5RelayInvalid`; its `TimedOut`/`Cancelled` member must equal the
tag-50 terminal class. `NotObserved` at relay validation may likewise pair with
`Socks5UdpAssociateFailed`, `TimedOut`, or `Cancelled` according to the exact
terminal fact. `Partial` is legal only while the received prefix is still a
prefix of at least one structurally valid complete reply. As soon as wrong
`VER`, wrong `RSV`, unknown ATYP, zero domain length, or any other earliest
structural error is decidable from bytes already consumed in that I/O result,
the phase terminates as
`Observed::StructurallyInvalid`; later EOF, timeout, or cancellation cannot
overwrite that already determined failure class. An observed complete reply retains only its bounded exact frame
digest, byte count, and closed parse result. `StructurallyInvalid` selects exactly one earliest
applicable framing reason in this order: `WrongVersion`, `WrongReservedByte`,
`UnknownAddressType`, `InvalidDomainLength`, `TrailingBytes`,
then `SuccessZeroPort`; it maps to `Socks5RelayInvalid`. Once the entire frame is
structurally valid, any nonzero REP maps one-to-one to the displayed
`Socks5ReplyStatusV1` member and `Socks5UdpAssociateFailed`; port zero is legal
for that rejected reply. A successful domain reply uses only
`SuccessfulDomainUnsupported` and `Socks5RelayDomainUnsupported`. A successful
literal reply uses only `SuccessfulLiteral`; it remains paired with
`relay_evidence=NotSelected` while `ClassifyAndExcludeRelay` runs and must match
`SelectedLiteral` before any phase after successful classification is entered.
`OverBound` records only that at least byte 263 was observed, maps to
`Socks5RelayInvalid`, and retains no attacker-controlled reply bytes. It is the
first check for every completed control-read result: cumulative received length
`>=263` selects only `OverBound`, even when an earlier prefix already formed a
short complete reply and the remainder could otherwise look like trailing
bytes. Earliest structural-reason parsing runs only while the cumulative length
is `1..=262`; `TrailingBytes` is therefore bounded to that range. A
parse/phase/result mismatch or an invented arbitrary reason
invalidates the wrapper.

The sole authorized target profile is also the sole UDP canary target. Its
`challenge` is `NonceEcho { protocol_version = 1 }` and its
`transport_authorization` is `TcpAndSocks5UdpCanary`; no TCP-only receipt or
ambient application destination authorizes this datagram. The canary
destination is derived without choice. An enclosing `ExternalProxy` candidate
whose destination is `ProxyOpaque` uses `ProxyOpaqueDomain` with the profile's
exact normalized A-label and port. An enclosing `LocalAddress` candidate uses
`LocalLiteral` with that candidate's exact tag-33 target endpoint digest, whose
literal address, family, scope, and port equal the authorized profile and
resolved target set. Cross-form, cross-candidate, changed-name/port/address, or
another target is invalid before delivery.

The inner UDP request payload is the same closed 40-byte NonceEcho v1 frame used
by the target service: `0x46 0x50 0x45 0x47 || 0x01 || 0x00 ||
uint16_be(32) || nonce`. The expected response payload is the same length and
bytes except that the message-type byte is `0x01`; it carries the identical
nonce. This wire-payload reuse does not reuse a stream commitment or tag-27/
tag-37 result. The complete request datagram is exactly RFC 1928 `RSV=0x0000,
FRAG=0x00`, followed by the ATYP/address/port encoding determined by
`Socks5UdpCanaryDestinationV1`, followed by that request payload. IPv4, IPv6,
and domain datagrams are respectively 50, 62, and `47 + name_length` bytes, with
the domain name length in `1..=255`; these are the only valid values of
`request_datagram_bytes`.

A validated response is exactly one datagram whose outer UDP source endpoint is
the selected literal relay, whose RFC 1928 `RSV` and `FRAG` are zero, whose
ATYP/address/port encoding is byte-identical to the authorized request
destination, and whose remaining payload is exactly the 40-byte expected
response frame with no trailing byte. Its total length therefore equals the
request length. The source endpoint, response destination, inner
`response_frame_digest`, and whole-datagram digest are all explicit in
`EchoValidated`. `observed_udp_source` is the kernel-reported outer UDP source.
A nonzero source port uses `ValidEndpoint` whose `endpoint_digest` is
`Digest(EndpointIdentityV1)` (tag 33). Source port zero uses exactly the IPv4 or
IPv6 zero-port variant and does not weaken the global nonzero-port rule for
`EndpointIdentityV1`: the observed zero value is committed by
`zero_port_source_identity_digest` and never constructs,
selects, or authorizes an `Endpoint`. The digest uses the exact family-specific
preimage above; a cross-family, raw-address, scope, or domain substitution is
invalid. `EchoValidated` permits only `ValidEndpoint`, byte-identical to
`SelectedLiteral.relay_endpoint_digest`. A zero-port source can be `Oversize`
because size has higher priority, and otherwise is `Rejected {
reason=UnexpectedRelaySource }`; it can never validate.
A source mismatch uses only `UnexpectedRelaySource` and
`Socks5RelayInvalid`; nonzero `FRAG` uses only `Fragmented` and
`Socks5FragmentationUnsupported`; malformed `RSV`/destination encoding,
destination mismatch, bad magic/version/type/length/nonce, truncation, or
trailing payload uses the exact remaining rejection reason and
`Socks5UdpCanaryFailed`. An over-302-byte datagram is `Oversize` and
`Socks5UdpCanaryFailed`. Control-connection or association loss remains
`Socks5UdpAssociateFailed`. No case retries, falls back direct, or uses UDP over
TCP.
If more than one defect is observable, the evidence selects exactly the first
applicable result in this closed order: more than 302 received bytes is
`Oversize`; otherwise wrong outer relay source is `UnexpectedRelaySource`;
otherwise missing, short, nonzero, or invalid two-byte RSV is
`MalformedReservedField`; otherwise nonzero FRAG is `Fragmented`; otherwise a
missing FRAG after a complete zero RSV or malformed/unknown/truncated
ATYP/address/port is
`InvalidDestinationEncoding`; otherwise a well-formed but unequal destination
is `DestinationMismatch`; otherwise any inner-frame defect is
`InvalidEchoFrame`. `EchoValidated` is the only fallthrough. The same datagram
cannot be encoded under two reasons, and later checks do not overwrite the
earlier result.
`response_datagram_digest` exists exactly for `Rejected` and `EchoValidated`;
`response_frame_digest` exists only for `EchoValidated`; `NotReceived` and
`Oversize` carry neither. Their byte-count and source-field presence follows the
displayed variants exactly. `NotReceived { response_datagram_bytes=0 }` means
that no UDP datagram was consumed and therefore has no source or digest. A
consumed zero-length UDP datagram is instead `Rejected {
response_datagram_bytes=0 }`, retains its kernel-reported source and digest, and
selects `UnexpectedRelaySource` when that source is wrong or otherwise
`MalformedReservedField`. The response digest formula hashes the exact empty
byte string in this case. At the expected source, lengths zero or one select
`MalformedReservedField`; length two with zero RSV but missing FRAG, and length
three with zero RSV and `FRAG=0` but missing ATYP, select
`InvalidDestinationEncoding`; a nonzero third byte instead selects
`Fragmented`. The two zero-byte
cases are never interchangeable.

After the target-tunnel `Passed` marker, role B is created under the same
serialized event gate but before tag 50 exists. One bounded full factory
operation covers the role-B queue/capacity checks, socket creation,
bind/protect and option/route readback, TCP connect, the independent HostLocal
peer proof when applicable, release evidence/latch checks, signing, sequence and
TCP-epoch allocation, and the final publication commit. The operation retains
normal phase attribution internally. A cancellation/deadline before the full
operation starts, a
successful route readback whose semantic anchor/route comparison is negative,
or an exact ordinary connect refusal/unreachable/timeout atomically publishes
the exact role-B terminal prefix with `NotReached {
UnpublishedProtocolTerminal }`, closes the unpublished socket,
allocates no role-B child/epoch/sequence, and leaves the enclosing attempt as
`ConnectorTerminal` with role A and its completed challenge. Even a recoverable
connect code is terminal here and cannot retry or fall back.

If a queue, create, mechanism-apply, option/route-readback, HostLocal-peer-
check, release-evidence, latch, signing, capacity, or publication invariant
fails, the atomic result instead publishes no role-B phase or child and uses
only `UdpControlChildReleaseAborted` plus the matching tag-46 `TerminalFailed`
latch. A semantic route mismatch is not a readback failure and therefore uses
the ordinary `ObserveRoute` terminal above. If the full operation succeeds, it
atomically publishes four exact completed entries: bind, route, and connect are
`Passed`; the peer phase is `Passed` for `HostLocal` and `NotApplicable` for
`Remote`. The same commit publishes the distinct role-B child/epoch and reaches
the one-shot first-byte guard. A passing guard enters role-B
`OfferExactMethods`; a failed guard uses only
`UdpControlFirstByteGuardAborted`, closes B, and sends zero method bytes. A
cancellation or deadline before the operation starts is the terminal first
role-B phase with `UnpublishedProtocolTerminal`. Once it has started, a later
terminal event is latched while the bounded operation drains. Successful drain
publishes B and makes `OfferExactMethods { connection_role =
Socks5UdpAssociationControl }` the immediate zero-method-byte terminal with
`NotReached { Published }`; a factory failure keeps the higher-priority control-
release abort. A third result is an ordinary semantic-route or connect negative
that closes the unpublished socket. If its completion ordinal precedes the
terminal event, that exact role-B phase and ordinary class/code own the terminal.
If cancellation or deadline linearized first, the active role-B route/connect
phase instead ends respectively `Cancelled` or `TimedOut`; the later ordinary
negative is retained only for bounded drain/cleanup accounting and cannot
overwrite the winning class. Both cases use `NotReached {
UnpublishedProtocolTerminal }`, publish no B child/epoch/sequence, and are
terminal without retry. A bounded connect-timeout completion and phase-deadline
crossing obey the same ordinal rule even though both select `TimedOut`.
Unprovable drain, cleanup, lifecycle accounting, or completion
evidence invalidates the wrapper. No B method/authentication byte exists before
the child publication commit.

All role-B method/authentication and tag-50 phases use that same serialized
terminal-event gate and sampler. The gate
assigns a strictly increasing internal event ordinal at the linearization point
of every operation completion, explicit-cancellation latch, phase-deadline
crossing, and control/association-liveness loss. A network-visible write/send
or datagram consumption and its completion record linearize atomically; if a
cancellation, deadline, or liveness event linearizes first, that operation is
cancelled with zero network effect and cannot later publish a successful
completion. A completion that linearized first is processed before a later
terminal event, and none of its network-visible effects or required evidence is
discarded. Processing a successful intermediate operation does not by itself
append a phase `Passed`: successful relay classification and `EchoValidated`
use the two explicit positive-finalization barriers below.

At the start of each nonblocking iteration the sampler atomically snapshots the
gate. If an operation completion has the lowest ordinal, it processes exactly
that record first, including completed pure classification, write/read bytes
and EOF, frame construction, an atomic UDP-send result, or one consumed UDP
datagram. Otherwise it selects the lowest-ordinal terminal event; events
observed in the same atomic sample use the exact tie order explicit cancellation,
deadline, then liveness loss. When neither completion nor terminal event exists,
the sampler rechecks live control/association state and may start at most one
new bounded operation; it never consumes that operation's result in the same
iteration. Even an immediate result is published through the gate and handled
on the next iteration. Only with no event, no ready operation, and no in-flight
operation may it wait.

The only terminal-first drain exceptions are the already started role-B full
factory operation after target-tunnel `Passed`, an already started helper nonce/
tag-48/delivery/cleanup operation, and the already started role-C full factory
child operation after pending positive relay classification. Their exact rules
above or below latch the terminal, forbid every new payload-producing operation,
and delay finalization only until the bounded in-flight operation is accounted
for. Role-B success publishes B and terminates its zero-byte method phase; role-
B factory failure publishes only `UdpControlChildReleaseAborted`.

Helper nonce generation, tag-48 append/fsync/delivery, and cleanup may contain
an in-flight local operation that cannot be atomically cancelled. A terminal
event may latch its winning class/code but cannot finalize tag 50 until the
runtime/helper boundedly cancels-and-drains that one operation. The actual
durable/delivery/zeroization prefix then selects exactly `PreparationFailed`,
`PreDatagramFailedAfterDurableRecord`, or `Attempted` under the rules below; it
does not overwrite the already selected terminal class/code, and no later
operation may start. If bounded drain, durable-state proof, delivery-state
proof, or cleanup cannot complete, no valid tag-50 root exists and the enclosing
transaction fails closed. Thus no durable record, delivery, consumed datagram,
or emitted byte can be hidden by cancellation, deadline, or liveness loss.

This ordering makes an I/O result containing a still-valid partial relay reply followed by EOF exactly
`Partial { terminal=PeerClosed }` and `Socks5RelayInvalid`; zero reply bytes
followed by EOF is `NotObserved` and `Socks5UdpAssociateFailed`. A consumed UDP
datagram is classified before a later-ordinal control loss.

At `ClassifyAndExcludeRelay`, a completed negative classification is terminal
and wins over a later-ordinal liveness loss. A completed positive classification
instead creates only an implementation-internal pending literal selection; it
does not yet append `ClassifyAndExcludeRelay/Passed`, publish
`SelectedLiteral`, or release a UDP child. Before the next operation starts, the
sampler rechecks the gate. If cancellation, deadline, or liveness loss wins at
that boundary, the terminal phase remains `ClassifyAndExcludeRelay`,
`relay_evidence=NotSelected`, the UDP child is absent, and the canary is
`NotReached`; liveness loss uses `Socks5UdpAssociateFailed`.

Only a still-live boundary may start one bounded, non-payload-producing
same-factory child-creation-and-release operation. That one sampler operation
counters as the start of role C's single `target_challenge` occurrence; every
factory step and later canary/finalization/conditional-teardown step uses the
minimum of that cap's remaining deadline and the shared `overall` remainder,
with no reset. The operation
covers the complete section 12.3 order from queue/capacity checks through socket
creation, mechanism and option/route readback, UDP connect, release-evidence and
latch validation, sequence/count allocation, signing, and the final local
publication/sequence/handoff commit; only that final commit is atomic. Once the
operation starts, a later cancellation, deadline, or liveness event latches its
terminal class but cannot cancel the operation or finalize tag 50. It prohibits
nonce generation and every application-protocol byte while the runtime
boundedly drains the operation. A successful completion atomically appends
`ClassifyAndExcludeRelay/Passed`, publishes `SelectedLiteral` and the UDP child
with its sequence/handoff, and enters `SendBoundedFRAG0Canary`; any latched
terminal is then the sole immediate terminal of that send phase, with
`PreparationFailed`, no tag-48 record, and zero frame/datagram bytes. A failure
at any factory step instead atomically appends the passed classification and
`SelectedLiteral` but no child, produces only the exact
`UdpChildReleaseAborted`/`TerminalFailed` evidence below, and its higher-priority
outer factory failure owns the result rather than the latched protocol terminal.
If bounded drain, unpublished-socket cleanup, lifecycle accounting, or the
success/failure completion evidence cannot be proven, no valid tag-50 wrapper
exists and the enclosing transaction fails closed. There is no interval with a
passed classification and neither an entered send phase nor that exact abort
evidence.

At `ValidateRelaySourceAndCanary`, processing a valid consumed datagram records
`EchoValidated` but leaves that phase open. Its sole next ready operation is the
zero-network-effect internal `AssociationReadyFinalization`. That operation's
completion receives one gate ordinal and has one linearization transaction: it
rechecks that cancellation and the phase deadline remain clear, samples the TCP
control connection open and the association active, appends
`ValidateRelaySourceAndCanary/Passed` and `AssociationReady/Passed`, and freezes
the tag-50 `Passed` terminal snapshot and `observed_at` as one indivisible
change. Cancellation, deadline, and liveness-loss events receive their ordinary
gate ordinals and compete with that completion. If a terminal event linearizes
first, finalization has zero state effect; the result retains `EchoValidated`
and terminates `ValidateRelaySourceAndCanary` respectively as `Cancelled`,
`TimedOut`, or `Failed { error_code=Socks5UdpAssociateFailed }`. If finalization
linearizes first, every later cancellation, deadline, or control/association
loss belongs to the next cancellation, health, or rollback observation and
cannot rewrite that immutable terminal snapshot.

The snapshot is not yet a signed tag-50 root. After it freezes, the runtime
starts no payload operation and boundedly produces the exact first-following
tag-34 checkpoint before it signs and publishes tag 50 with that digest. This
preserves the DAG order tag 34 before tag 50. In `Preactivation`, the runtime
first performs the required controlled close of B and C; A was already closed
by its successful target NonceEcho exchange. The checkpoint permanently
includes all three child roots in its creation chain and has all three absent
from factory provenance and the independent OS current-open set. In
`Postactivation` and `Renewal`, A remains chain-present/current-absent while the
runtime retains the B and C local handles, their factory provenance, and close
bookkeeping through the checkpoint. In this attempt's A/B/C projection exactly
B and C are current-present. Let `V_i` be the retained B+C pair from this and
every earlier successful group in the same verification sequence. Every A is
absent from `V_i`. In quiescent `Postactivation`, the factory-wide current-open
sets equal `V_i`. In `Renewal`, let `O_i` be the disjoint set of every other live
child of the same actor-wide factory at that checkpoint; the factory-wide sets
equal `O_i union V_i`, not merely `V_i`. Ordinary non-verification socket
lifecycle changes between checkpoints may only remove an entry while this
sequence holds Exclusive admission; no unrelated release may add one. Every
such close is serialized into the accumulator's closure list and therefore may
shrink `O_i`; both censuses must still report the same exact set and counters. The
protocol-required local close of A and the preactivation
controlled closes of B/C are not late association-loss events. A peer FIN/RST
or other uncommanded liveness loss
after the terminal snapshot is queued as the next health/rollback event; it does
not change the historical `Open`/`Active` observation, and the runtime does not
locally close a retained handle or remove its provenance before the checkpoint.
That checkpoint proves local socket-object/handle state at its own barrier, not
a second assertion of protocol liveness after tag-50 `observed_at`.

For tag 13, 28, or 29, any attempt that terminates without protocol success,
including a first-group terminal, pre-tag-50 published-control terminal, either
control abort, tag-50 negative, UDP-child abort, timeout, or cancellation,
controlled-closes every published child from that attempt and every B+C pair
retained by an earlier successful group in the same verification sequence
before the terminal attempt's first-following checkpoint. All child roots remain
in the cumulative creation chain, but an otherwise valid protocol/timeout/
cancellation terminal has an empty verification-sequence projection in both
current-open sets. In `Preactivation` and quiescent `Postactivation` this also
leaves the full actor-wide set empty. In `Renewal`, unrelated operational
children remain present or undergo only their independently serialized ordinary
lifecycle transitions; cleanup may not erase them from either census. Every
required controlled-close list is frozen from the published current-open
provenance and processed strictly by decreasing `socket_sequence`, one child to
terminal close-step outcome before the next, so each B+C pair closes C before B
and the latest pair closes before an earlier pair. After the first failed step
the runtime continues the remaining bounded closes only to minimize residual
state; no later failure may overwrite the latch's first failure. If a required
close or bookkeeping transition itself fails,
the tag-46 factory/census negative and `SocketFactoryInvariantUnproven`
supersede that ordinary terminal; its authenticated census records the actual
cleanup state and is not an alternate current-set encoding of the ordinary
terminal.

Role A, B, and C children in tags 13, 28, and 29 are verification-only; they
are never transferred to an application-flow or generic UDP data plane. A tag-
13 final attempt always performs any sequence-wide controlled close before its
first-following checkpoint and makes that checkpoint the sequence-finalization
root with admission `FinalizedHeld`, or `TerminalHeld` on a provable factory or
census failure. A tag-28/tag-29 attempt that is not protocol-successful does the
same: its first-following checkpoint has already cleaned the verification
projection and is that sequence's finalization/top-level root. In contrast, a
tag-28/tag-29 final attempt whose first-following checkpoint is protocol-
successful, complete/equal, and still `Exclusive { stage=Running }` requires a
separate finalization after the runtime freezes the exact traversal/tag-51/tag-
52 result that the outer priority rule will project, whether positive or a
structurally valid negative. It then runs exactly one
`VerificationSequenceFinalization` operation. For `RequireAssociate`, this
operation includes `VerificationAssociationTeardown` and closes every retained
B+C pair; for every other selection it creates no child and performs only the
ordinary close-ledger/census barrier. Thus an early counted traversal failure,
exclusion-readback failure/timeout, and ordinary-connectivity failure/timeout
cannot bypass finalization, verification cleanup, or leave admission Running.
A protocol-successful attempt whose first-following checkpoint instead has a
factory terminal, negative census, or complete-census mismatch cannot advance
to another group. That checkpoint must atomically carry the matching
`TerminalFailed` latch and `TerminalHeld { terminal_context=ActiveSequence }`;
it is the sequence finalization/top-level root without claiming successful
cleanup or a complete residual set. If the independent result cannot be bound
into that same authenticated checkpoint, no outer wrapper is valid.

Authentication of a successful admission root and entry into attempt 1's zero-
effect `BeforeConnector` gate are one serialized boundary, not a scheduler
window. A cancellation or overall deadline whose ordinal wins there is encoded
as attempt 1's exact `BeforeConnector` terminal; it may not use
`PostAdmissionPreAttemptTerminal`. That zero-attempt cause is reserved solely
for an independently provable factory failure that linearizes after admission
and before the first attempt operation. The same rule assigns cancellation or
deadline between attempts to the next already-determined attempt's
`BeforeConnector` boundary, while a factory terminal may end at the next fresh
`Empty` finalization root without fabricating another attempt.
`attempt_boundary_terminal` is `FactoryOrCensusTerminalBeforeNextAttempt` only
when its ordinal equals the last recorded attempt, that attempt's continuation
is one of `RetrySameCandidate`, `AdvanceNextCandidate`, or
`AdvanceNextFamilyTuple`, and no operation or child of the promised next attempt
has begun. Its `sequence_finalization_accumulator_digest` names the immediate
next `Empty` checkpoint, whose previous root is that last attempt checkpoint and
whose admission is `TerminalHeld { terminal_context=ActiveSequence }`; known
retained verification children are controlled-closed when a complete actual
state permits it. `NotApplicable` is mandatory in every other branch. A
cancellation/deadline uses the next attempt rule above, and neither branch may
rewrite the last attempt's continuation to hide the winning boundary ordinal.

Before finalization starts, the sampler drains every already assigned event.
Any uncommanded verification loss, cancellation, or deadline denies the success
path without rewriting an already protocol-successful attempt; when that event
has no valid outer encoding, no accepted outer root or post-outer release is
fabricated and fenced rollback owns the held admission. Once finalization
starts, it is the sole bounded non-payload verification operation: retained B+C
pairs become cleanup-owned, no new payload operation may start on them, and
terminal events are latched while controlled closes drain. Its completion gets
the next gate ordinal. A terminal ordinal that precedes completion prevents
success acceptance even when cleanup later succeeds; completion-first permits
finalization-root construction, but the ordinary outer-publication drain still
rejects any later queued terminal.

The fresh tag-34 finalization checkpoint is mandatory exactly for the clean
protocol-successful tag-28/tag-29 final-attempt branch above. It names the final
attempt checkpoint as `previous_accumulator_digest`, has an `Empty` sequence
delta and unchanged creation-chain digest, includes every close/bookkeeping
transition, and carries the same reservation while changing
`Exclusive { stage=Running }` to `Exclusive { stage=FinalizedHeld }`. Let
`S_before` be the exact factory-wide current-open set in the final attempt
checkpoint and `V` the disjoint retained verification B+C set, empty for a
selection that retains no verification child. The finalization processes
exactly `V` by the decreasing-sequence rule. Exclusive admission has prohibited
every unrelated new child since sequence entry. Let `D` be the exact set of
non-verification children removed after the final attempt checkpoint and before
the authenticated finalization root; each member appears once as an
`OrdinaryLocal` or `PeerOrOs` closure transition. The finalization root's two
current-open sets equal `S_before minus (V union D)`. They contain no member of
`V`, no new child, and no unexplained disappearance, but need not be empty in
`Renewal`. In quiescent `Postactivation`, `S_before = V` and `D` is empty, so
the full set is empty. Both census outcomes are `Complete`, equal, and counter-
stable for a clean finalization. A close or bookkeeping failure instead uses
the first complete/equal actual-state checkpoint with a matching
`TerminalFailed` latch, `TerminalHeld` admission, and exact closed reason as the
finalization root. An authenticated census negative/mismatch uses its canonical
`SocketCensusFailed` reason and the same terminal admission but makes no claim
about the residual set; recovery owns every possibly open child.

An `Executed` tag 28 or tag 29 always names its
`sequence_finalization_accumulator_digest` at the probe factory's position in
the top-level `socket_observation_accumulator_digests` list. An
`AdmissionAborted` tag 28/29 instead names its terminal accumulator at that
position and has no finalization field. Outer-root publication
receives its ordinal only after the checkpoint is authenticated. A provable
close, bookkeeping, or admission failure uses the dual-signed actual-state
`TerminalFailed`/`TerminalHeld` checkpoint; an authenticated census failure uses
the corresponding fail-closed terminal checkpoint without an actual-set claim.
Either projects only
`SocketFactoryInvariantUnproven`; it outranks the previously frozen traversal,
tag-51, or tag-52 result and cannot produce `Passed`/`Healthy`. Failure to
construct, dual-sign, authenticate, or register that tag-34 root, or to sign the
outer root, yields no valid wrapper and fails closed rather than fabricating a
factory-negative checkpoint.

After a valid outer root whose finalization state is clean nonterminal
`Exclusive { stage=FinalizedHeld }` is published, release follows exactly the
shared three-path rule: tag 13 `Passed` opens VerificationOnly immediately; tag
28 `Passed` completes the all-factory OrdinaryAndVerification batch only after
the durable ARCH-001 commit receipt; tag 29 `Healthy` refreshes that complete
all-factory authority only after the durable `LeaseRenewed` receipt. Every
negative outer and terminal factory outcome has no Open checkpoint or batch.
Consequently every accepted
later renewal starts with zero prior ARCH-002 verification child current-open
while every historical root remains in the cumulative chain; unrelated
operational children of the same actor-wide factory remain visible in both
exact censuses. An operational SOCKS5 UDP association is a distinct future
ARCH-004 data-plane resource and cannot reuse these verification children, but
if it belongs to the same Network Runtime it remains governed by and visible in
that actor's one factory policy and census.

For every attempt the exact time order is `tag50.observed_at <=
attempt_tag34.observed_at < tag50.expires_at`. On the clean protocol-successful
tag-28/tag-29 final-attempt branch, the final attempt checkpoint precedes the
finalization checkpoint, which is no later than the enclosing
`completed_at`/`observed_at`; every required tag-50 root remains unexpired
through outer publication. The tag-13 release checkpoint, or tag-28/tag-29
complete release batch, is strictly later than that outer publication ordinal.
For tag 13 the checkpoint precedes proof acceptance. For tag 28/29 the durable
commit/renewal disposition lies between outer publication and every staged
release root, and only the atomic batch-completion event is effective; product-
level Active/healthy acceptance and Ordinary release follow that completion.
Outer publication, the pre-mutation terminal-event drain, durable disposition
when applicable, every release-root `observed_at` and authentication, batch
completion, latest-head/status validation, and product acceptance are all
strictly earlier than the minimum of the outer root expiry, every required tag-
50 expiry, every required tag-51/tag-52 expiry, the applicable helper receipt/
lease expiry, and the parent overall deadline.
If a passed-context retention
state cannot be proved, either signer or census is unavailable, a checkpoint is
stale/negative, or tag-50, finalization, outer, and post-outer release-batch
construction/signing
miss their bounded deadline, no success root exists and the enclosing
transaction fails closed. A provable close/bookkeeping failure instead uses the
actual-state factory-negative branch above; only an unprovable actual state has
no valid outer root. Tag-50
`observed_at` remains the finalization linearization time; later checkpoint and
signature work never backdates or resamples the terminal decision. Every late
cancellation, deadline, FIN/RST, or association loss is durably queued with its
tag-50 gate ordinal and a monotonically assigned ARCH-001 commit/renewal
serialization ordinal. Every terminal transition of every factory listed by a
tag-28 or tag-29 root participates in this same acceptance queue. Ordinary child
creation may linearize only through that factory's outer-listed latest
checkpoint; that checkpoint atomically acquires and retains its creation gate
through successful batch completion or, on any outer/batch failure, until the
fence/rollback path takes ownership. A close that linearizes after that checkpoint but
before the coordinator acquires the full all-factory batch lock remains legal
and is reflected in the corresponding `Empty` release root. After that combined
lifecycle/close-bookkeeping lock is acquired, no local removal may linearize;
any external peer/OS loss or terminal event aborts the batch. An ordinary local
or peer/OS close that won before acquisition and completed its authenticated
bookkeeping is a ledgered predecessor, not a post-lock terminal; a close whose
actual removal or bookkeeping is still unresolved at acquisition aborts. A non-probe-
factory terminal cannot hide behind an earlier listed checkpoint. Outer-
root publication receives an ordinal from that same sequence after finalization
on every valid branch. The controlled teardown closes
are not uncommanded association-loss events; an earlier queued loss prevents
teardown from owning the success path. Before the tag-28 commit or tag-29 lease-
renewal fsync, the consumer drains all listed-factory events through the outer
publication/disposition ordinal. After that durable mutation and before atomic
batch completion, it drains again through the batch-completion serialization
ordinal and confirms the receipt journal head/revision is still the current
durable transaction base before any batch record is committed. A
terminal that wins the first drain refuses the mutation; after a durable
mutation, every terminal other than a pre-lock ordinary close already completed
and ledgered as just defined prevents the entire batch from becoming current
and appends a later fence/recovery record. A
discovered post-snapshot loss leaves the historical outer/receipt as audit
evidence only; a later `Passed`/`Healthy` signature or idempotent success replay
cannot erase it or authorize an Ordinary child.

Within the phase-specific operation item,
the canary datagram uses the defect priority above. Thus simultaneous cancel/
deadline, control-loss/datagram, and timeout/malformed-datagram fakes have one
outcome and a later event never overwrites the selected class/code. With no
in-flight operation, an already latched control/association loss plus nonce/
tag-48/delivery/write/frame/send readiness performs zero new operation, writes
zero new bytes/datagrams, creates no new tag-48 record, and uses
`Socks5UdpAssociateFailed`.

`udp_canary_evidence=NotReached` is exact strictly before entry to
`SendBoundedFRAG0Canary` and implies no UDP nonce, tag-48 record, frame digest,
or datagram byte. `PreparationFailed` exists only for a failed, timed-out, or
cancelled `SendBoundedFRAG0Canary` terminal before a tag-48 record became
durable. This NetworkRuntime-
signed variant asserts only its own `runtime_received_delivery=false` and zero
datagrams; it does not sign a helper-memory or journal fact. A raw nonce may have
existed only inside the helper. Under the helper mutation lock, the helper
independently verifies that no tag-48 digest is referenced, zeroizes any pending
nonce, and records the enclosing ARCH-001 typed abort/cleanup result. If that
cleanup cannot be proven, the wrapper is invalid and no tag-50/outer `Failed`
result is accepted. If tag 48
became durable but the runtime provably did not receive the one-use delivery, or
received and zeroized it before constructing any datagram,
`PreDatagramFailedAfterDurableRecord` carries that exact commitment and
`Digest(NonceEchoDeliveryConsumptionRecordV1)` plus the sole exact delivery
state. Ambiguous delivery cannot produce a valid tag-50 root and is handled by
the enclosing fail-closed transaction. `Attempted` is mandatory once the exact
request is constructed. Its request digest and byte count
name that complete datagram; `request_datagrams_sent=0` requires `NotReceived`
and can terminate only at the send phase, while value one is the sole atomic
send and is mandatory for every later association phase. `NotReceived` is valid
only before a response datagram is consumed; `Rejected` and `Oversize` are
terminal negative evidence. `EchoValidated` is valid only with the exact fields
above and is mandatory for tag-50 `Passed`. A second sent or consumed datagram,
stage/variant mismatch, or fabricated zero/partial UDP send invalidates the
wrapper.
Every `delivery_consumption_record_digest` in either durable-record canary
variant is exactly `Digest(NonceEchoDeliveryConsumptionRecordV1)` (tag 48).
That record's plan, generation, target profile, commitment, and runtime instance
are byte-identical to tag 50. Its proof specification equals the enclosing
tag-13/tag-28/tag-29 checkpoint's exact specification; its complete
`Socks5UdpCanary` phase context repeats tag 50 plus that checkpoint's exact
attempt/tuple/candidate, both TCP epochs, all three child digests, relay
endpoint/set, and destination.
Its authenticated runtime channel equals the active gate, and its delivery ID
equals the one-use delivery frame. A TCP-context, cross-target, cross-checkpoint,
cross-runtime/channel, cross-delivery, or partially matching record is invalid.

The registered association root is signed by `NetworkRuntime` and is present
only for `ExternalSocks5::RequireAssociate` after role B completed its separate
method/authentication state machine. Its selection, context, and runtime equal
the enclosing checkpoint. Its target, attempt ordinal, family-tuple
ordinal/value, candidate binding, proxy endpoint, role-A target-tunnel epoch and
child, and role-B dedicated-control epoch and child are byte-identical to the
enclosing proof/canary/health attempt and its retained
`Observed.udp_associate_control_binding`.
The A and B epochs, tag-31 roots, platform identities, and socket sequences are
distinct; both children use the same factory/runtime/proxy candidate/family,
but A uses the phase-context proof/canary/health purpose and B uses
`ProxyControl`. A's epoch/sequence precedes B's.

Its `following_socket_observation_accumulator_digest` is that attempt's first
fresh tag-34 checkpoint after terminal and contains A, B, and every released C
UDP child in the exact creation-chain/current-open state required by the
terminal prefix. `target_tunnel_socket_child_observation_digest`,
`udp_control_socket_child_observation_digest`, and every present
`udp_socket_child_observation_digest` are
`Digest(SocketPolicyChildObservationV1)` (tag 31). The target-tunnel field is
byte-identical to the enclosing attempt's
`connector_socket_child_observation_digest`; the dedicated-control field is the
one role-B child recorded by the pre-tag-50 evidence; a present UDP field is the
later role-C child in that attempt's first-following checkpoint. The optional C
child is absent exactly while the terminal prefix precedes UDP-socket release
and present from that release onward; it is mandatory for `Passed`. The sole
non-protocol boundary inside tag 50 is `UdpChildReleaseAborted`: after successful
`ClassifyAndExcludeRelay` and before entering `SendBoundedFRAG0Canary`, the
factory may fail its queue, socket creation, mechanism, option/route readback,
connect invariant, phase latch/release evidence, signing, limit check, or
atomic publication/sequence/release transaction. That variant is
legal only with `SelectedLiteral`, absent UDP child, `NotReached` canary, zero
UDP nonce/tag-48/frame/datagram/response material, and a phase trace whose last
and only final entry is `ClassifyAndExcludeRelay/Passed`. Its reason is exactly
one of `ObservationQueueUnavailable`, `ObservationQueueCapacityExceeded`,
`OpenSocketLimitExceeded`, `LeaseSocketCreationLimitExceeded`,
`SocketCreationFailed`, `SocketMechanismApplyFailed`,
`SocketOptionReadbackFailed`, `SocketRouteReadbackFailed`,
`SocketConnectInvariantFailed`, `ReleaseEvidenceInvalid`,
`ReleasePhaseLatchInvalid`, `ChildObservationSigningFailed`, or
`AtomicChildPublicationFailed`.

Its named first-fresh tag-34 checkpoint's tag-46 root must carry
`release_phase_latch_state=TerminalFailed`; that latch's counter and reason are
byte-identical to the two abort fields. Entering `TerminalFailed` itself is the
factory-invariant failure fact. Its tag-46 and tag-44 census outcomes may be
`Complete` with equal sets and counters after clean close, or may independently
be negative/mismatched; either way the unique outer projection is `Failed {
error_code=SocketFactoryInvariantUnproven }` and continuation is `Terminal`.
It carries no nested typed-non-challenge error code. A non-terminal latch,
reason/counter mismatch, present UDP child, entered send phase, retry/fallback,
or any other outer code makes that wrapper invalid; an unrelated negative
census without the exact terminal latch cannot support this variant. Once the
atomic publication/release succeeds, the child
is present and the existing send/canary outcomes are mandatory; the abort
variant is no longer legal. Thus a
negative root cannot hide a released UDP socket. `relay_evidence=NotSelected`
is exact before a valid literal relay has been classified and is mandatory for
domain/framing/reply failures and every failure in
`ClassifyAndExcludeRelay`. `SelectedLiteral` is exact from successful
`ClassifyAndExcludeRelay` onward, including a later source-validation
`Socks5RelayInvalid`, whether or not UDP-child release later
succeeds. A present UDP child therefore requires `SelectedLiteral`; the reverse
is not required before child release. For `Passed`, all three child roots belong
to the enclosing checkpoint and `SelectedLiteral` is mandatory. The relay endpoint
is `Digest(EndpointIdentityV1)`; `relay_endpoint_set_digest` always names the context-matched
`Digest(ResolvedEndpointSetV1)` with purpose `Socks5Relay` and contains that
selected relay endpoint under the sealed relay family policy. It always uses
`LiteralNoResolution`; `ResolvedDns` is invalid for this purpose. Optionality, evidence-variant, endpoint,
phase, family, route/locality, or resolver mismatch is invalid. All present
child roots belong to the same factory and exact checkpoint accumulator chain,
and their socket sequences are exactly A < B < C. For `Passed`, at tag-50
`observed_at` the dedicated B TCP control connection is open, the association
is active, and the UDP socket accepts
datagrams only from the returned relay, and nonzero `FRAG` is dropped before
payload handling; the context-specific later checkpoint state is exactly the
one defined above. `Disable` and every
non-SOCKS selection require this root absent. A structurally valid `Failed`,
`TimedOut`, or `Cancelled` tag-50 outcome has a bounded phase equal to the
enclosing attempt's terminal association phase and the same class/code as that
protocol-phase entry. It equals the enclosing outer outcome only when no higher-
priority census or, for tag 28, traversal failure applies.
`UdpChildReleaseAborted` is the sole exception to phase/outcome equality: its
last protocol phase passed, and only its referenced first-following exact
`TerminalFailed` latch supplies the higher-priority outer factory-invariant
failure; the two census outcomes may independently be complete/equal or
negative/mismatched. A stale, cross-
context, cross-runtime, cross-child, cross-relay, phase-mismatched, or unsigned
association invalidates the wrapper and produces no valid outer outcome; it
cannot be referenced as `Passed` or converted into `Failed`.

### 4.7 Closed egress selection

```text
EgressSelectionV1 =
  | Direct {
      destination_resolution,
      timeout_budget,
    }
  | ExternalHttp {
      proxy_endpoint_policy,
      authentication,
      cleartext_credential_policy,
      destination_resolution,
      timeout_budget,
    }
  | ExternalHttps {
      proxy_endpoint_policy,
      authentication,
      proxy_tls_policy_descriptor_digest,
      destination_resolution,
      timeout_budget,
    }
  | ExternalSocks5 {
      proxy_endpoint_policy,
      authentication,
      cleartext_credential_policy,
      destination_resolution,
      udp_policy,
      timeout_budget,
    }

SafeHttpAuthenticationV1 =
  | None
  | BasicUtf8V1 {
      credential_descriptor_digest,
      exchange = PreemptiveOnce | ChallengeOnce,
    }

SafeSocks5AuthenticationV1 =
  | None
  | UsernamePasswordUtf8V1 { credential_descriptor_digest }

SafeEgressSelectionV1 =
  | Direct {
      destination_resolution,
      timeout_budget,
    }
  | ExternalHttp {
      proxy_endpoint_policy,
      safe_authentication,
      cleartext_credential_policy,
      destination_resolution,
      timeout_budget,
    }
  | ExternalHttps {
      proxy_endpoint_policy,
      safe_authentication,
      proxy_tls_policy_descriptor_digest,
      destination_resolution,
      timeout_budget,
    }
  | ExternalSocks5 {
      proxy_endpoint_policy,
      safe_authentication,
      cleartext_credential_policy,
      destination_resolution,
      udp_policy,
      timeout_budget,
    }
```

`proxy_endpoint_policy.resolver_dependency` is absent only for a literal IP. A
hostname requires the complete sealed resolver descriptor. The v1 union excludes HTTP
absolute-form forwarding, HTTP/2 CONNECT, CONNECT-UDP, SOCKS4/4a, generic
selectors, custom request paths or headers, UDP-over-TCP, PAC/WPAD, environment
proxy discovery, and user-configuration outbound substitution. Encountering one
returns `UnsupportedProtocolFeature` before mutation.

## 5. Exact-mode invariants

For a request `R`, prepared plan `P`, and active status `A`:

```text
P.network_scope == R.network_scope
P.egress_selection_safe_digest == Digest(SafeEgressSelectionV1::from(R.egress_selection))
A.network_scope == P.network_scope
A.egress_tag == R.egress_selection.tag
A.plan_digest == P.plan_digest
```

`SafeEgressSelectionV1::from` is the sole permitted projection. It preserves the
variant and every field in displayed order, replaces each HTTP/SOCKS credential
handle with the exact `RuntimeCredentialDescriptorV1` digest, and changes
nothing else. TLS trust is already represented by the exact
`ProxyTlsPolicyDescriptorV1` digest. A projection that drops or rewrites an
authentication exchange, receipt, trust, resolver, UDP, family, timeout, or
policy choice is invalid.
Tag 0 `EgressSelectionV1` is confined to the authenticated Supervisor request
boundary because it may contain request-only credential handles. It never
enters a helper request, candidate/prepared plan, journal, runtime/backend
observation, exclusion root, or health result. Every such downstream object
uses and equals the exact tag-1 `SafeEgressSelectionV1` digest.
`P.plan_digest` and `A.plan_digest` are the exact ARCH-001 `PlanDigest` issued
by `PreparePlan`; ARCH-002 defines no `Digest(P)` alias or second plan domain.

The following substitutions are forbidden within a generation:

- external proxy to direct or to another proxy tag;
- HTTP/HTTPS CONNECT to forward proxying or another CONNECT protocol;
- HTTPS to HTTP, weaker TLS, different trust mode, or different identity;
- SOCKS5 authentication, resolution, or UDP policy changes;
- local to proxy resolution or proxy to local resolution;
- direct DNS/UDP when the selected policy cannot carry them;
- an outer proxy or locally resolved destination family outside its exact
  `IpFamilyPolicy`, or any family claim for a `ProxyOpaque` destination; and
- full-tunnel to proxy-only.

Retrying the same sealed address or authentication exchange within its bound is
not substitution. Any policy change requires a new request, plan, and
generation.

### 5.1 Pinned sing-box compiler mapping

The v1 protected overlay targets repository-pinned sing-box 1.13.19 revision
`b5ebaa1fc0f2b94256180b95468e73ef53caa27d`. The following is only the
structural outbound target; it is not a capability claim:

```text
Direct
  -> { type: "direct", tag: "__flowprobe_egress_direct", explicit dial policy }

ExternalHttp
  -> { type: "http", tag: "__flowprobe_egress_http", tls: disabled,
       explicit server/address policy }

ExternalHttps
  -> { type: "http", tag: "__flowprobe_egress_https", tls: enabled,
       exact identity/trust/version/ALPN/algorithm policy,
       explicit server/address policy }

ExternalSocks5
  -> { type: "socks", tag: "__flowprobe_egress_socks5", version: "5",
       network: exact requested set, udp_over_tcp: disabled,
       explicit server/address policy }
```

The Config Compiler owns these tags and every associated protected route,
resolver, mark, and binding field. User configuration cannot redefine, select,
or detour around them.

The compiler MUST reject a `detour` on a protected outbound because the pinned
dialer ignores the outbound's other dial fields when detour is enabled. It MUST
emit SOCKS version and network explicitly because upstream defaults would
otherwise enable unrequested protocol scope. It MUST NOT emit SOCKS4/4a,
UDP-over-TCP, HTTP request path/headers, generic selector, or a rolling
post-1.13.19 field.
For `ExternalSocks5`, `Socks5UdpPolicy::Disable` maps only to the singleton
network set `tcp`, while `RequireAssociate` maps only to the ordered set
`tcp,udp`. Neither an omitted/default network field, UDP under `Disable`, nor a
TCP-only or differently ordered/extended set under `RequireAssociate` is the
sealed selection. This structural mapping does not change either variant's
current `Unsupported` support-matrix disposition.

The pinned built-in HTTP client is not a conforming ARCH-002 CONNECT executor:
it accepts only status 200 rather than every complete 2xx response, fixes Basic
to preemptive emission instead of the sealed exchange choice, performs no
bounded 407 retry, and may expose an upstream status string in its error. Both
`ExternalHttp` and `ExternalHttps` are therefore
`UnsupportedProtocolFeature/PinnedHttpConnectAdapterNonconforming` until a
separately versioned, packaged adapter implements the exact state machine,
bounds, safe error projection, and fake/real-host gates in this contract. Merely
emitting `type: "http"` cannot make either capability Ready.

The pinned TLS schema exposes server name, insecure flag, ALPN, min/max
versions, cipher/curve choices, explicit certificates, and public-key pins, but
not the complete v1 algorithm verifier, FlowProbe-anchor subtraction evidence,
or OCSP enforcement. The pinned Go public connection state also does not expose
the negotiated group or server-authentication signature scheme required by the
registered handshake root, while its default groups/signatures are broader than
v1. The compiler maps only policy fields whose exact runtime
behavior is source-backed and independently tested. A requested TLS predicate
without such a mapping is `UnsupportedProtocolFeature`; it is never silently
delegated to drifting platform defaults.
The compiler MUST NOT emit the pinned runtime's public-key-pin field for either
AND-pin trust mode because that implementation enables insecure verification.
It also MUST NOT allow the runtime to reread ambient roots after materializing
the exact filtered snapshot. Until a packaged TLS adapter proves the complete
v1 verifier, wire-order ClientHello image, delivery/load/artifact tuple, and
`ProxyTlsHandshakeObservationV1`, `ExternalHttps` remains
`UnsupportedProtocolFeature/PinnedTlsVerifierNonconforming`.

The pinned built-in SOCKS UDP path does not prove a second independent TCP
control child that restarts greeting/authentication and sends only `CMD=0x03`;
nor does it provide the required literal-relay locality/source proof or drop-
before-delivery validation of RSV/FRAG. Any adapter that can emit UDP ASSOCIATE
only on the already-established CONNECT tunnel is nonconforming.
`RequireAssociate` is therefore
`UnsupportedProtocolFeature/PinnedSocksUdpAdapterNonconforming` until a
separately versioned adapter supplies those semantics. Emitting `type: "socks"`
or observing a successful UDP packet is not conformance.

For a domain proxy endpoint, the protected outbound resolver resolves only the
proxy server endpoint. Direct destination resolution and proxy-side destination
name transport remain distinct. `network_strategy` features documented for
Android/Apple graphical clients are not desktop CLI support evidence.
`auto_detect_interface`, `default_interface`, `find_process`, process/path route
matchers, and upstream claims to prevent loops are candidate primitives only;
they do not supply FlowProbe's stable listener identity, transaction, read-back,
completeness proof, fencing, or real-host evidence.

The pinned runtime consumes credentials from its configuration and exposes no
source-backed secret callback. The v1 lifecycle is therefore explicit:

1. During ARCH-001 `Preflighting`, the compiler validates a secret-free
   structural template and the broker validates the credential schema/limits.
   No runtime process or secret-bearing artifact exists.
2. The sealed graph contains a fixed runtime-config materialization node, exact
   `RuntimeInstanceId`, package/build digest, template digest, credential
   descriptor digest, derived private-directory identity recipe, and cleanup
   predicate. It contains neither the credential nor a secret-bearing config
   digest that could enable an offline guess.
3. Only after `Prepared`, the runtime adapter redeems the exact ARCH-001 external
   permit. It creates the installation/session/generation-derived directory
   with owner-only access and exclusive no-follow semantics, verifies it is not
   a link/reparse point or foreign object, and atomically writes one owner-only,
   non-inheritable runtime artifact. No renderer path, environment variable,
   standard input, or command-line secret is accepted.
4. The packaged runtime validates and loads that exact artifact under the same
   `RuntimeInstanceId`. Its protected control handshake binds the package,
   template, selection, and credential-descriptor digests. External reload and
   signal-driven config replacement are disabled; rotation requires a new
   generation.
5. After the authenticated handshake proves the runtime no longer needs the
   pathname, the adapter removes the artifact and verifies its exact file
   identity is absent. If the packaged tuple requires a persistent plaintext
   file, cannot prevent sibling access/core dumps, cannot bound inherited
   handles, or cannot prove cleanup after crash, `RuntimeCredentialDelivery` is
   unsupported for authenticated proxy modes.
6. The runtime may retain the credential only in its protected process memory
   until that instance stops. It must be excluded from core/minidumps and debug
   attachment by the selected platform policy, must not copy the value into
   logs/control replies, and zeroizes owned buffers at teardown. Swap/dump
   containment and crash-artifact absence are release-gate evidence, not
   assumptions.

The safe compiler report, plan, helper request, journal, and diagnostics contain
only the non-authorizing credential descriptor digest. Terminal `Inactive`
requires the exact runtime absent and every secret artifact/handle removed;
recovery uses only the fixed derived identity recipe and never the secret.
The current repository compiler/runtime and pinned Go HTTP/SOCKS clients retain
credential-bearing configuration in ordinary cloneable strings/files and do not
prove teardown zeroization. Authenticated modes therefore remain
`UnsupportedProtocolFeature/PinnedCredentialLifecycleNonconforming`; a compiler-
only change cannot make them Ready.

## 6. Capability contract

### 6.1 Independent capability keys

At minimum the backend reports these keys independently:

```text
ProcessAttribution
LocalListenerOwnership
LoopExclusion
PhysicalPathBinding
ActorNetworkIsolation
SocketCreationEnforcement
SocketCensus
DirectProtocol
HttpConnectProtocol
HttpsProxyTls
Socks5ConnectProtocol
Socks5UdpAssociate
Ipv4Egress
Ipv6Egress
EndpointResolution
RuntimeCredentialDelivery
SustainedEgressHealth
```

`ProcessAttribution` describes best-effort association of observed traffic with
a process. `LocalListenerOwnership` proves who owns a selected local listening
socket. `LoopExclusion` prevents a sealed actor/path from entering the captured
path. `SocketCreationEnforcement` proves that every external-network socket
creation entrypoint in one exact actor/process/cooperative scope is constrained
to the sealed factory. `SocketCensus` proves that an independent backend can
completely enumerate every external-network socket in that exact scope under
the snapshot barrier. None of these capabilities, including
`PhysicalPathBinding`, implies another.

### 6.2 Capability report

```text
PreplanDiscoveryContextV1 = {
  preparation_ticket_id,
  session_id,
  generation,
  helper_assigned_observation_nonce,
  boot_epoch,
  suspend_epoch,
}

CapabilityReportV1 = {
  discovery_context: PreplanDiscoveryContextV1,
  key,
  disposition,
  static_support,
  readiness,
  evidence,
  mechanism: CapabilityMechanismV1,
  mechanism_version,
  backend,
  backend_version,
  package_version,
  platform_scope,
  network_scopes,
  address_families,
  transports,
  actor_classes,
  endpoint_localities,
  enforcement_strength,
  observed_at,
  expires_at,
  observation_epoch,
  release_evidence: CapabilityEvidenceReferenceV1,
  reason_code,
  authenticator,
}

CapabilityEvidenceReferenceV1 =
  | NotRealHostVerified
  | TlsVerifier {
      tls_verifier_capability_evidence_digest,
    }
  | PlatformCapability {
      platform_capability_evidence_digest,
    }

CapabilityMechanismV1 =
  | None
  | WindowsOwnerTableRetainedProcessHandleV1
  | LinuxSockDiagPidfdProcV1
  | WindowsUnicastInterfaceV1
  | WindowsWfpIdentityAndRouteV1
  | LinuxBindToDeviceV1
  | LinuxBindToIfIndexV1
  | LinuxSocketMarkPolicyRouteV1
  | DarwinBoundInterfaceV1
  | CooperativeProtectV1
  | WindowsAppContainerNetworkCapabilityDenyV1
  | WindowsWfpProcessSocketDenyV1
  | LinuxSeccompSocketBrokerDenyV1
  | DarwinSandboxSocketDenyV1
  | HermeticFakeNetworkIsolationV1
  | HermeticFakePhysicalPathBindingV1
  | PreventiveSyscallBrokerV1
  | PreventiveSandboxDenyExceptFactoryV1
  | CooperativeAttestedSocketFactoryLeaseV1
  | WindowsTransportEndpointHandleCensusV1
  | LinuxSocketCookieInodeCensusV1
  | DarwinKernelSocketGenerationCensusV1
  | CooperativeUnderlyingNativeSocketCensusV1
  | HermeticFakeSocketCreationEnforcementV1
  | HermeticFakeSocketCensusV1
  | BuiltinDirectV1
  | BuiltinHttpConnectV1
  | PackagedHttpsProxyTlsV1
  | BuiltinSocks5ConnectV1
  | BuiltinSocks5UdpAssociateV1
  | RuntimeIpv4StackV1
  | RuntimeIpv6StackV1
  | PlatformEndpointResolutionV1
  | RuntimeCredentialDeliveryV1
  | PlatformSustainedHealthV1

PlatformCapabilityEvidenceV1 = {
  capability_key,
  mechanism: CapabilityMechanismV1,
  mechanism_version,
  backend,
  backend_version,
  package_version,
  platform_scope,
  network_scopes,
  address_families,
  transports,
  actor_classes,
  endpoint_localities,
  enforcement_strength,
  source_revision_sha256,
  producer_binary_sha256,
  dependency_lock_sha256,
  implementation_and_build_digest,
  conformance_suite_and_vectors_sha256,
  required_test_case_count,
  executed_test_case_count,
  failed_test_case_count = 0,
  result = Passed,
  real_host_verified_at_utc_unix_seconds,
  validity = UntilAnyBoundTupleOrDigestChanges,
  authenticator,
}

CapabilityDisposition =
  | Supported
  | Unsupported
  | PolicyProhibited
  | PermissionRequired
  | InteractionRequired
  | TemporarilyUnavailable
  | Degraded

EnforcementStrength = Preventive | Detective | None
```

`static_support`, `readiness`, and `evidence` use the exact ADR-0004 enums.
`platform_scope` includes the OS, architecture, release/build floor, package,
backend, and feature tuple. All collections are explicit; an empty collection
means no covered scope, not all scope.
`network_scopes`, `address_families`, `transports`, `actor_classes`, and
`endpoint_localities` contain respectively `0..=2`, `0..=2`, `0..=2`,
`0..=15`, and `0..=3` unique closed-tag values, each in ascending tag order.
An over-bound, duplicated, unknown, or differently ordered collection is an
invalid report, not narrower coverage.

`PreplanDiscoveryContextV1` is allocated by the helper before any candidate
plan digest exists. Its nonce is an unpredictable public 32-byte value and its
ticket/session/generation/boot/suspend tuple is repeated by the corresponding
pre-plan discovery authority binding. It cannot be replaced by a zero value,
producer nonce, prepared-plan digest, or postactivation context. The helper
accepts each discovery root only for that still-open preparation ticket and
then seals its digest into the candidate plan; this one-way edge prevents a
plan/signature digest cycle.
Every `HermeticFake*` mechanism tag in this contract exists only in the
deterministic test codec and is rejected by release builds before plan sealing;
it can never produce a release capability or platform-support claim.

`HermeticFixtureValidation` is an explicit non-serialized verifier invocation
available only to deterministic codec/contract tests. In that context a fake
mechanism's tag-2 report is exactly `disposition=Unsupported`,
`static_support=UnsupportedPendingArchitecture`, `readiness=Unsafe`,
`evidence=DesignOnly`, `release_evidence=NotRealHostVerified`, and
`reason_code=HermeticFixtureOnly`; it carries the fake mechanism and fixture
scope but no tag-53 release root. This lets tests validate the complete closed
aggregate without pretending real-host readiness. Such a root is rejected in
normal/release preflight and cannot authorize `Prepared`, protocol bytes,
commit, renewal, an active mode, or a support-matrix change. All rules that say
`Supported`/`Ready`/`RealHostVerified` below apply to real platform profiles;
the only exception is this exact fixture-validation branch.

`CapabilityReportV1.mechanism` is exactly `CapabilityMechanismV1`; a producer
string or unknown platform/API name is invalid. `None` is permitted only for a
non-`Supported` disposition. The report itself is the signed, bounded live
readiness observation; there is no generic evidence byte string or
implementation-private evidence hash.

The key/mechanism domain is closed: `ProcessAttribution` and
`LocalListenerOwnership` accept only the Windows-owner or Linux-sock-diag
variants; `LoopExclusion` and `PhysicalPathBinding` accept only the displayed
Windows/Linux/Darwin/cooperative path-enforcement variants;
`ActorNetworkIsolation` accepts only
`WindowsAppContainerNetworkCapabilityDenyV1`,
`WindowsWfpProcessSocketDenyV1`, `LinuxSeccompSocketBrokerDenyV1`, or
`DarwinSandboxSocketDenyV1` in release builds; its hermetic test vectors use
only `HermeticFakeNetworkIsolationV1`. `SocketCreationEnforcement` accepts only
`PreventiveSyscallBrokerV1`, `PreventiveSandboxDenyExceptFactoryV1`, or
`CooperativeAttestedSocketFactoryLeaseV1` in release builds, and
`SocketCensus` accepts only `WindowsTransportEndpointHandleCensusV1`,
`LinuxSocketCookieInodeCensusV1`, `DarwinKernelSocketGenerationCensusV1`, or
`CooperativeUnderlyingNativeSocketCensusV1`. `PhysicalPathBinding`,
`SocketCreationEnforcement`, and `SocketCensus` hermetic vectors use only their
correspondingly named `HermeticFake*` variant; no fake mechanism is valid in a
release build. The five protocol keys
accept only their correspondingly named built-in/packaged variant; IPv4 and
IPv6 accept only `RuntimeIpv4StackV1` and `RuntimeIpv6StackV1` respectively;
`EndpointResolution`, `RuntimeCredentialDelivery`, and
`SustainedEgressHealth` accept only their correspondingly named variants. A
cross-key mechanism is invalid rather than a differently scoped capability.

`NotRealHostVerified` is present exactly when `evidence` is not
`RealHostVerified`, and such a report cannot be `Supported`. A
`RealHostVerified` `HttpsProxyTls` report uses `TlsVerifier` and its digest is
exactly `Digest(TlsVerifierCapabilityEvidenceV1)` (tag 49). Every other
`RealHostVerified` key uses `PlatformCapability` and its digest is exactly
`Digest(PlatformCapabilityEvidenceV1)` (tag 53). The referenced release root's
key, mechanism/version, backend/version/package, platform and every covered
scope/enforcement field equal the live report byte-for-byte. A TLS root on a
non-TLS key, a platform root on `HttpsProxyTls`, a build digest substituted for
either root, or a report/root tuple mismatch is invalid.

`PlatformCapabilityEvidenceV1` is immutable release evidence, not current
readiness. Its collections use the same bounds/order as the report. The test
counts are equal in `1..=65535`, failed count is zero, and result is literal
`Passed`. Source, dependency-lock, and suite/vector identities are recomputed
from the corresponding domain-separated `ReleaseArtifactCorpusV1` manifests
defined above; `producer_binary_sha256` hashes the exact single packaged binary
bytes. They are content identities, never runtime observations. The suite
manifest includes the exact runner and every vector file. `implementation_and_build_digest` is recomputed exactly as
`SHA-256("FlowProbe.Egress.CapabilityBuild.v1\0" || source_revision_sha256 ||
producer_binary_sha256 || dependency_lock_sha256 || canonical_cbor([
capability_key, mechanism, mechanism_version, backend, backend_version,
package_version, platform_scope]))`. The root is signed by `ReleaseVerifier`
under the trusted release-keyset revision and becomes invalid when any bound
tuple, content hash, or manifest entry changes.

The release-activation disposition is computed without discarding source
dimensions:

| Condition | Disposition |
| --- | --- |
| `Readiness=PolicyProhibited` | `PolicyProhibited` |
| `Readiness=PermissionMissing` | `PermissionRequired` |
| `Readiness=UserActionRequired` | `InteractionRequired` |
| `Readiness=TemporarilyUnavailable` or retryable `NotInstalled` | `TemporarilyUnavailable` |
| `Readiness=Degraded` | `Degraded` |
| Static unsupported, unsafe, recovery-required, backend mismatch, permanent not-installed, missing scope, insufficient enforcement, or missing required real-host evidence | `Unsupported` with the preserved underlying fields |
| `SupportedByDesign` + `Ready` + required scope + required enforcement + `RealHostVerified` for the exact package tuple | `Supported` |

For `LoopExclusion` in `FullTunnel`, `Supported` requires `Preventive`.
`Detective` can support diagnostics but not activation. `Supported` for one
family, transport, actor class, endpoint locality, proxy tag, or network scope
MUST NOT be projected to another.

A service, helper, runtime, proxy, or OS API successfully starting does not
change a capability to `Supported`. Restart is availability observation only.
Recovery readiness comes only from the ARCH-001 journal/fence state and current
resource evidence.

### 6.3 Preflight mapping

Every mandatory capability must have one unexpired report. Preflight maps:

- `Supported` to continued evaluation;
- `PolicyProhibited` to `EgressPolicyProhibited`;
- `PermissionRequired` to `EgressPermissionRequired`;
- `InteractionRequired` to `EgressInteractionRequired`;
- `TemporarilyUnavailable` to `EgressTemporarilyUnavailable`;
- `Degraded` to `EgressDegradedRefused` for the requested mode; and
- `Unsupported` to `EgressUnsupported`.

The error retains safe digests and every original capability dimension. No
mapping changes the request or starts an OS mutation.

## 7. Endpoint resolution and locality

### 7.1 Resolution evidence

```text
ResolvedEndpointSetV1 = {
  observation_context: ResolvedEndpointObservationContextV1,
  platform_family: PlatformFamilyV1,
  input_endpoint_digest,
  resolution_purpose,
  resolution_evidence: EndpointResolutionEvidenceV1,
  observed_at,
  expires_at,
  route_epoch,
  authenticator,
}

EndpointResolutionEvidenceV1 =
  | LiteralNoResolution {
      exact_literal_endpoint_digest,
      normalized_candidate: ResolvedCandidate,
    }
  | ResolvedDns {
      resolver_dependency_digest,
      resolution_mechanism: EndpointResolutionMechanismV1,
      mechanism_version,
      resolver_query_scope: ResolverQueryScopeV1,
      normalized_candidates,
      canonical_name_chain,
      outcome: DnsResolutionOutcomeV1,
      resolver_epoch,
    }

DnsResolutionOutcomeV1 =
  | Positive
  | Negative { kind = NxDomain | NoData }

ResolvedEndpointObservationContextV1 =
  | Preplan {
      discovery_context: PreplanDiscoveryContextV1,
    }
  | Socks5RelayCheckpoint {
      prepared_plan_digest,
      generation,
      phase_context: ProxyEvidenceObservationContextV1,
      runtime_instance_id,
    }

ResolverQueryScopeV1 = {
  input_endpoint_digest,
  resolver_dependency_digest,
  family_scope,
  namespace_or_compartment,
  query_type_set = AddressRecordsOnly,
}

ResolvedCandidate = {
  address,
  family,
  scope?,
  route_and_locality_observation: RouteClassificationObservationV1,
}

EndpointResolutionMechanismV1 =
  | WindowsGetAddrInfoExWV1
  | LinuxGetAddrInfoV1
  | DarwinGetAddrInfoV1
  | HermeticFakeResolverV1

RouteClassificationObservationV1 = {
  mechanism: PlatformRouteQueryMechanismV1,
  mechanism_version,
  namespace_or_compartment,
  stable_interface_identity?,
  route_table_and_metric: RouteTableAndMetricV1,
  next_hop?,
  matched_host_assigned_address?,
  interface_epoch,
  route_epoch,
  outcome: RouteLocalityOutcomeV1,
}

RouteTableAndMetricV1 = {
  route_table,
  metric,
}

PlatformRouteQueryMechanismV1 =
  | WindowsGetBestRoute2AndAddressTablesV1
  | LinuxRtmGetrouteAndGetaddrV1
  | DarwinRouteSocketAndGetifaddrsV1
  | HermeticFakeRouteQueryV1

RouteLocalityOutcomeV1 =
  | HostLocal { local_class: HostLocalClass }
  | Remote { route_class = ForwardedOrExternal }
  | Ambiguous { reason_code }

ResolutionPurpose =
  | ProxyEndpoint
  | ActivationProbeTarget
  | Socks5Relay

EndpointLocality =
  | HostLocal { local_class }
  | Remote
  | Ambiguous

HostLocalClass =
  | Loopback
  | HostAssignedAddress
  | OsHostLocalRoute
```

`LiteralNoResolution` is valid only when `input_endpoint_digest` names an exact
IP-literal `EndpointIdentityV1`; its `exact_literal_endpoint_digest` repeats that
digest, it contains exactly one normalized candidate with the same address,
family, scope, and a complete inline route/locality observation, and it contains
no resolver, query, name-chain, negative, or resolver-epoch field. It is valid
for `ProxyEndpoint` and an IP-literal `Socks5Relay`; an activation-target literal
uses its tag-18/tag-39 authorization path and has no tag-4 root.
`Socks5Relay` accepts only this IP-literal variant in the checkpoint context;
`ResolvedDns` with that purpose is invalid. `ResolvedDns::Positive` contains `1..=maximum_candidates` candidates and
`ResolvedDns::Negative` contains exactly zero; `maximum_candidates` is `1..=8`.
Candidates are deduplicated and ordered by the selected purpose-specific family
policy, then normalized address bytes and scope. Proxy endpoint and
activation-target sets are discovered in ARCH-001 `Preflighting` and sealed in
the candidate plan. A SOCKS relay set is produced by the sealed observation
recipe after the runtime returns `BND.ADDR`. A future runtime-destination set is
not a tag-4 purpose in v1; its future per-flow contract must register its own
context/signer/outer reference and can never pretend the result existed in the
activation plan. Ambient re-resolution by a runtime library is forbidden
whenever `LocalAddress` is selected. The runtime receives the selected address
set. The original name is retained only for proxy-endpoint TLS SNI/certificate
identity or a target `ProxyName` authority. A target `LocalAddress` HTTP CONNECT
or SOCKS request emits only the selected literal candidate and never the
original name; `ProxyName` sends the exact normalized name to the proxy and has
no local target result set.

TTL expiry, resolver epoch change, route epoch change, or a candidate-set change
invalidates the result. A negative result cannot be replaced by an ambient
lookup. CNAME or service-discovery intermediates never replace the configured
TLS reference identity.

The registered endpoint-set root is signed only by
`PlatformDiscoveryBackend`. `ProxyEndpoint` and `ActivationProbeTarget` require
the `Preplan` context plus `PreplanDiscoveryAuthenticatedChannel`; their roots
may enter the candidate plan. `Socks5Relay` requires
`Socks5RelayCheckpoint` plus `PlanComponentAuthenticatedChannel`; its plan,
generation, phase context, runtime, selected literal/family policy, and
freshness equal the enclosing tag-50 association root, and its digest is
referenced only by that post-plan root. Any other purpose/context/binding
combination or a post-plan root fed back into `PlanDigest` is invalid. The
backend signs the complete endpoint-set result and every inline route/locality
observation; there is no separate resolution-evidence or per-candidate route
hash. `ResolvedDns.canonical_name_chain` contains `0..=8` normalized A-labels in
actual resolver chain order, with no duplicate or loop; it is empty for a
negative result or DNS result with no alias. A ninth name, truncation,
reordering, display-name substitution, or digest of a private resolver object
is invalid.
For `ResolvedDns`, the resolver query scope repeats the root's endpoint and registered resolver
descriptor digests, the descriptor's family scope, and its exact namespace/
compartment; a search, reverse, service, or unsealed record query is outside the
closed `AddressRecordsOnly` set. Supplying any of these resolver fields in
`LiteralNoResolution`, or omitting one from `ResolvedDns`, is invalid.

`ResolvedEndpointSetV1.platform_family` closes every OS member in the root.
For `Windows`, `ResolvedDns.resolution_mechanism` is
`WindowsGetAddrInfoExWV1`, every candidate route mechanism is
`WindowsGetBestRoute2AndAddressTablesV1`, every present stable interface is
`WindowsInterface`, and every query/route namespace is the same Windows
compartment. `Linux` requires `LinuxGetAddrInfoV1`,
`LinuxRtmGetrouteAndGetaddrV1`, `LinuxInterface`, and one exact Linux network-
namespace identity. `Darwin` requires `DarwinGetAddrInfoV1`,
`DarwinRouteSocketAndGetifaddrsV1`, `DarwinInterface`, and one exact Darwin
routing namespace. `HermeticTestOnly` requires the corresponding
`HermeticFakeResolverV1`, `HermeticFakeRouteQueryV1`, and every present
`HermeticFakeInterface`. `LiteralNoResolution` omits only the resolver member;
its candidate route/interface still obey this matrix. A real/fake mix, an OS
mechanism or interface from another family, or disagreement among candidates is
an invalid root, not a narrower observation.

Each candidate's route observation uses the same namespace/compartment,
`route_epoch`, clock/boot/suspend domain, and candidate address as the enclosing
root. `HostLocal::Loopback` requires the normalized loopback class;
`HostLocal::HostAssignedAddress` requires
`matched_host_assigned_address == candidate.address` from the current address
table; `HostLocal::OsHostLocalRoute` requires a platform route class whose
closed mapping denotes delivery to this host. `Remote` requires a forwarded or
external route, and `Ambiguous` cannot be selected for activation. A missing
query field, unknown mechanism, candidate/locality disagreement, stale epoch,
or producer-defined route digest invalidates the entire set.
Elsewhere in this contract, “candidate locality” is shorthand for the exact
`RouteLocalityOutcomeV1` projection (`HostLocal`, `Remote`, or `Ambiguous`) in
that candidate; there is no second locality field that may disagree.

### 7.2 Locality rules

An address is `HostLocal` only when a platform-normalized condition is true:

- it is loopback;
- it is currently assigned to the host in the relevant namespace or
  compartment;
- the OS host-local route class declares delivery to this host.

An ordinary directly connected/on-link route, private address, VPN peer, default
gateway, or same-LAN host is `Remote`, not host-local. A backend maps only its
closed, versioned equivalents of the three `HostLocalClass` variants; it cannot
add a catch-all “platform local” class. If its route API cannot distinguish
host-local delivery from on-link forwarding, locality is `Ambiguous`.

Link-local, wildcard, multicast, unspecified, metadata-service, and otherwise
special-use addresses are not automatically safe. They require an explicit
target/endpoint policy and exact scope. A proxy endpoint that cannot be
classified reliably is `Ambiguous` and full-tunnel activation is refused.

V1 accepts a `HostLocal` proxy endpoint only as a one-candidate
`LiteralNoResolution` set with exactly one matching `LocalProxyIdentityV1`.
A DNS proxy set containing any host-local candidate, or any proxy set mixing
host-local and remote candidates, is
`UnsupportedPendingArchitecture/LocalProxyCandidateIdentityMapUnavailable`
before plan sealing. Multi-candidate proxy attempt sequences are therefore
all-`Remote`. This prevents candidate failover from selecting an unregistered
local process not covered by the actor graph and exclusion proof. Activation
target candidates retain their separately authorized locality rules. A SOCKS
relay chosen later is bound to its pre-sealed observation result; a per-flow
runtime destination remains flow evidence. Revalidation immediately before
commit reproduces every commit-relevant address, locality, resolver epoch, and
route epoch. DNS rebinding from remote to local or local to remote invalidates
the plan.

## 8. Local listener identity

### 8.1 Discovery record

```text
LocalProxyIdentityV1 = {
  discovery_context: PreplanDiscoveryContextV1,
  egress_selection_safe_digest,
  platform_family: LocalProxyPlatformFamilyV1,
  selected_endpoint,
  transport,
  address_family,
  namespace_or_compartment,
  listener_identity: ListenerIdentityV1,
  listener_owner_observation: ListenerOwnerObservationV1,
  live_process_observation: LiveProcessObservationV1,
  stable_executable_or_platform_identity:
    StableExecutableOrPlatformIdentityV1,
  exclusion_policy_identity: ExclusionPolicyIdentityV1,
  provenance: LocalProxyDiscoveryProvenanceV1,
  observed_at,
  expires_at,
  boot_epoch,
  route_epoch,
  authenticator,
}

ListenerIdentityV1 =
  | WindowsTcpOwnerTableListener {
      local_endpoint,
      compartment_id,
      owner_process_id,
      state = Listen,
      wildcard_bind,
      dual_stack_mode,
      reuse_group_identity?,
      creation_observation:
        WindowsListenerCreationObservationV1,
      table_snapshot_nonce,
    }
  | LinuxSockDiagListener {
      local_endpoint,
      network_namespace_identity,
      socket_inode_u64,
      socket_cookie_u64,
      bound_interface_identity?,
      wildcard_bind,
      dual_stack_mode,
      reuse_group_identity?,
      creation_observation: LinuxListenerCreationObservationV1,
    }

WindowsListenerCreationObservationV1 = {
  owner_process_creation_filetime_u64,
  first_retained_table_snapshot_nonce,
}

LinuxListenerCreationObservationV1 = {
  owner_proc_starttime_ticks_u64,
  first_retained_fd_snapshot_tick,
  socket_cookie_u64,
}

RetainedProcessIdentityV1 =
  | WindowsRetainedProcess {
      process_id_u32,
      process_creation_filetime_u64,
      retained_process_handle_identity,
      boot_epoch,
    }
  | LinuxRetainedPidfdProcess {
      process_id_i32,
      pidfd_identity,
      proc_starttime_ticks_u64,
      pid_namespace_identity,
      boot_epoch,
    }
  | DarwinRetainedAuditTokenProcess {
      process_id_i32,
      audit_token_bytes,
      process_start_time,
      pidversion_u32,
      boot_epoch,
    }
  | HermeticFakeRetainedProcess {
      fixture_process_identity,
      boot_epoch,
    }

ListenerOwnerObservationV1 = {
  mechanism: WindowsOwnerTableAndRetainedHandleV1 |
             LinuxSockDiagProcPidfdV1,
  mechanism_version,
  query_scope = ExactNamespaceListenerTupleAndOwner,
  listener_identity: ListenerIdentityV1,
  retained_process_identity: RetainedProcessIdentityV1,
  uniqueness = UniqueOwner,
  queried_at,
}

LiveProcessObservationV1 = {
  retained_process_identity: RetainedProcessIdentityV1,
  retention = HeldOpenThroughObservationExpiry,
  alive_at,
}

StableExecutableOrPlatformIdentityV1 =
  | WindowsExecutableIdentity {
      volume_serial_number,
      file_id_128,
      executable_file_sha256,
      authenticode_leaf_certificate_sha256?,
      package_or_service_identity?,
    }
  | LinuxExecutableIdentity {
      mount_id,
      device_major,
      device_minor,
      inode_u64,
      statx_generation_u64?,
      executable_file_sha256,
      package_name_and_version?,
    }

ExclusionPolicyIdentityV1 =
  | WindowsWfpApplicationIdentity {
      ale_app_id_bytes,
      package_sid_bytes?,
      policy_namespace,
    }
  | LinuxCgroupV2Identity {
      cgroup2_mount_id,
      cgroup_inode_u64,
      cgroup_namespace_identity,
      membership_epoch,
    }
  | CooperativeSocketBindingIdentity {
      provider_public_key_bytes,
      protocol_version,
      profile_id,
      cooperative_factory_lease_identity,
    }

LocalProxyDiscoveryProvenanceV1 = {
  backend: LocalProxyDiscoveryBackendV1,
  backend_version,
  package_version,
  listener_mechanism_version,
  process_mechanism_version,
}

LocalProxyPlatformFamilyV1 = Windows | Linux

LocalProxyDiscoveryBackendV1 =
  | WindowsIpHelperOwnerBackendV1
  | LinuxSockDiagProcBackendV1

ConnectedLocalPeerObservationV1 = {
  prepared_plan_digest,
  generation,
  runtime_instance_id,
  socket_factory_epoch,
  socket_sequence,
  connected_socket_identity: PlatformSocketIdentityV1,
  connected_peer_tuple,
  sealed_local_proxy_identity_digest,
  peer_binding_evidence: KernelEstablishedConnectionOwnerV1,
  observed_before_first_proxy_byte = true,
  observed_at,
  expires_at,
  authenticator,
}

KernelEstablishedConnectionOwnerV1 = {
  platform_family: LocalProxyPlatformFamilyV1,
  mechanism: KernelEstablishedOwnerMechanismV1,
  mechanism_version,
  query_scope = ExactEstablishedConnectionAndAcceptedOwner,
  connected_socket_identity: PlatformSocketIdentityV1,
  established_connection_identity: EstablishedConnectionIdentityV1,
  connected_peer_tuple,
  listener_identity: ListenerIdentityV1,
  accepted_owner_process: RetainedProcessIdentityV1,
  stable_executable_or_platform_identity:
    StableExecutableOrPlatformIdentityV1,
  exclusion_policy_identity: ExclusionPolicyIdentityV1,
  namespace_or_compartment,
  uniqueness = UniqueAcceptedOwner,
  queried_at,
}

KernelEstablishedOwnerMechanismV1 =
  | WindowsEstablishedTcpOwnerAndRetainedHandleV1
  | LinuxSockDiagEstablishedPeerProcPidfdV1

EstablishedConnectionIdentityV1 =
  | WindowsEstablishedTcpRow {
      local_endpoint,
      remote_endpoint,
      compartment_id,
      owner_process_id,
      state = Established,
      table_snapshot_nonce,
    }
  | LinuxEstablishedSocket {
      local_endpoint,
      remote_endpoint,
      network_namespace_identity,
      socket_inode_u64,
      socket_cookie_u64,
    }
```

`listener_identity` contains the normalized local address, port, protocol,
socket/listener kernel identity when exposed, wildcard/dual-stack flags,
reuse-group membership when exposed, and creation observation. The owner record
names the official API or kernel interface, version, query scope, and ambiguity
result.

`live_process_observation` uses a retained process object such as a Windows
handle or Linux pidfd when available and binds process creation/boot evidence.
`stable_executable_or_platform_identity` uses public evidence such as file ID,
verified signer, package identity, service identity, or executable identity.
A path string is descriptive only. `exclusion_policy_identity` is the exact
identity consumed by preventive enforcement, such as a WFP application/package
identity, helper-controlled cgroup identity, or a cryptographically attested
cooperative socket-binding profile.

The entire `LocalProxyIdentityV1` root is signed only by
`PlatformDiscoveryBackend` under its exact pre-plan discovery context. Every
`egress_selection_safe_digest` is exactly the plan's
`Digest(SafeEgressSelectionV1)` for the selected external proxy tag, and every
owner/process/listener value repeated inside the root is byte-identical; an
ambiguity is a typed discovery failure and is never encoded as a successful
identity root. `executable_file_sha256` hashes the exact bytes read through the
retained executable file object, and
`authenticode_leaf_certificate_sha256` hashes exact DER certificate bytes; both
are content identities and neither substitutes for the retained object,
creation time, listener, or exclusion identity. No generic `evidence_digest`
or private listener/owner hash exists.

The platform tuple is a closed aggregate even though its nested evidence stays
visible for field-by-field comparison. `Windows` requires, together and only
together: `WindowsTcpOwnerTableListener`,
`WindowsOwnerTableAndRetainedHandleV1`, `WindowsRetainedProcess`, the same
Windows retained process in `LiveProcessObservationV1`,
`WindowsExecutableIdentity`, `WindowsIpHelperOwnerBackendV1`, a Windows
compartment identity, and either `WindowsWfpApplicationIdentity` or an exact
`CooperativeSocketBindingIdentity`. `Linux` requires, together and only
together: `LinuxSockDiagListener`, `LinuxSockDiagProcPidfdV1`,
`LinuxRetainedPidfdProcess`, the same Linux retained process in
`LiveProcessObservationV1`, `LinuxExecutableIdentity`,
`LinuxSockDiagProcBackendV1`, a Linux network/user/PID namespace tuple, and
either `LinuxCgroupV2Identity` or an exact
`CooperativeSocketBindingIdentity`. The listener nested inside the owner
observation and every retained process occurrence are byte-identical to their
outer siblings. Windows/Linux union mixing, a backend/mechanism from the other
family, a WFP identity on Linux, a cgroup identity on Windows, or an unknown
platform family is invalid rather than merely ambiguous. A platform not in this
closed union cannot produce this root in contract v1.

No field alone proves ownership. Specifically, PID, process name, path, file
hash, port, socket inode, UID, service/unit, cgroup name, package name,
application path, interface name/index, or one listener-table row is
insufficient by itself.

### 8.2 Ambiguity and unsupported cases

Discovery returns typed unsupported or ambiguous when it observes:

- multiple possible owners, `SO_REUSEPORT`, shared listener groups, or a socket
  transfer that cannot be bound to the enforcing identity;
- wildcard/dual-stack behavior without complete family coverage;
- missing process-object, creation, executable/platform, namespace, or policy
  identity required by the platform mechanism;
- an inaccessible owner whose identity cannot be proved under current
  permission or policy;
- a proxy that creates per-connection worker identities not covered by the
  sealed enforcement policy; or
- an endpoint/relay whose locality changes or is ambiguous.

Permission and user-interaction conditions use their corresponding capability
dispositions; they are not collapsed into generic unsupported.

### 8.3 Revalidation and race closure

The backend MUST perform local identity discovery before plan sealing and
revalidate it:

1. under the helper/session serialization boundary immediately before the first
   privileged `egress.*` apply;
2. after applying the exclusion policy and before applying any dependent
   traffic-steering resource;
3. immediately before commit; and
4. as mandatory lease-renewal evidence while active.

Each revalidation re-queries the exact listener tuple, retained process object,
creation/boot evidence, executable/platform identity, namespace/compartment,
policy identity, wildcard/family behavior, endpoint resolution, and route
epoch. It proves the exclusion read-back still targets the revalidated identity.

In addition, every connection and reconnection to a host-local proxy is race-
closed after `connect` succeeds and before the runtime sends any TLS, proxy-
protocol, application, or credential byte. Contract v1 accepts only the
platform backend's kernel-established-connection owner evidence. While the actor socket factory
holds that socket in a no-send state, the platform backend binds the established
kernel connection peer—not merely the current listener table row—to the sealed
listener, retained process, stable executable/platform identity, namespace/
compartment, and exclusion-policy identity. The runtime and backend produce a
fresh `ConnectedLocalPeerObservationV1` for that socket sequence. Only then may
the factory release the socket to the protocol state machine.
Its authenticator role is `PlatformDiscoveryBackend`; the corresponding
`SocketPolicyChildObservationV1` is separately signed by
`SocketFactoryExecutor` and binds this observation digest, so neither actor can
substitute the peer or release decision alone.

`KernelEstablishedConnectionOwnerV1.platform_family` must equal the sealed
`LocalProxyIdentityV1.platform_family`. Its exact legal aggregate is the same
family tuple: Windows requires
`WindowsEstablishedTcpOwnerAndRetainedHandleV1`,
`WindowsEstablishedTcpRow`, `WindowsTcpOwnerTableListener`,
`WindowsRetainedProcess`, `WindowsExecutableIdentity`, a Windows compartment,
and only Windows-WFP or the sealed cooperative exclusion identity; Linux
requires `LinuxSockDiagEstablishedPeerProcPidfdV1`,
`LinuxEstablishedSocket`, `LinuxSockDiagListener`,
`LinuxRetainedPidfdProcess`, `LinuxExecutableIdentity`, the exact Linux
namespace tuple, and only Linux-cgroup-v2 or the sealed cooperative exclusion
identity. Every listener/process/executable/exclusion identity equals the
corresponding sealed discovery field byte-for-byte. Any cross-family member,
even when its individual union tag and bytes are otherwise valid, invalidates
the connected-peer root before first-byte release.

For a child whose selected proxy candidate is `HostLocal`,
`connected_local_peer_observation_digest` is mandatory; for a `Remote`
candidate it is absent. The referenced peer root repeats the child's exact
`prepared_plan_digest`, `generation`, `factory_epoch`, `socket_sequence`, and
`socket_identity`; its `runtime_instance_id` equals the exact non-optional
runtime instance in the referenced factory policy. Its connected peer address,
port, family, transport, namespace/compartment, and kernel connection identity
equal the child's `ProxyEndpointSet` binding, selected proxy candidate, and socket without
normalization after signing. `sealed_local_proxy_identity_digest` equals the
single plan/exclusion-set `Digest(LocalProxyIdentityV1)`. The inline kernel-owner
value repeats that root's listener identity, retained process identity, stable
executable/platform identity, exclusion-policy identity, and namespace/
compartment byte-for-byte. Its connected socket and peer tuple repeat the outer
peer root, and its `queried_at` is no later than the outer `observed_at`. The
accepted owner is unique and belongs to that same established connection; no
unregistered `observation_digest` or listener-table-only proof is accepted. Another
plan, runtime, factory, sequence, socket, endpoint, listener, process,
executable/platform identity, or exclusion identity is not interchangeable.

The peer root is current when the child is released:
`peer.observed_at <= child.observed_at < peer.expires_at`, both observations are
in the same clock/boot/suspend domain, and `child.expires_at <=
peer.expires_at`. Signing/enqueue does not permanently authorize a later send.
The factory keeps a one-shot no-send latch on the socket; the first protocol or
credential write is executed through that latch, which atomically samples the
same suspend-aware continuous clock and permits the write only when the sample
is strictly earlier than both expiries. If the check or write cannot complete
under that guard, it closes the socket, emits zero protocol/credential bytes,
and terminally fails the factory epoch. For `ExternalHttps`, additionally
`child.observed_at <= ProxyTlsHandshakeObservationV1.started_at`; a
`ClientHelloStarted` root's `started_at` is the guarded first-TLS-byte attempt
and is strictly earlier than both expiries. A `NotStarted` root records zero TLS
bytes. The TLS root names that exact child, and no ClientHello byte may precede
the peer observation or guarded expiry check. An absent HostLocal root, a root
on a Remote child, field mismatch, expiry, or time inversion terminally fails
the factory and closes the socket with zero protocol/credential bytes.

The one-shot expiry recheck applies to every published child using the child's
own freshness bound; a HostLocal TCP child additionally samples the peer-root
expiry. `FirstByteExpiryGuardFailed` is always the tag-46 factory-latch reason
and therefore selects outer `SocketFactoryInvariantUnproven`. Its nested
zero-byte projection is unique by child role: a primary Direct child terminates
`Challenge` with `ProbeFailed` and zero challenge bytes; an ExternalHttp child
terminates the first `HttpConnectExchange { step=SendConnectAuthority }` with
`ProxyConnectFailed`; an ExternalHttps child terminates
`AuthenticateProxyTls` with `ProxyTlsFailed` and a tag-42 `NotStarted` root; and
a primary ExternalSocks5 child terminates
`OfferExactMethods { connection_role=TargetTunnel }` with
`ProxyConnectFailed`. These nested values describe the attempted protocol phase
only; the accepted outer outcome remains the earlier factory-priority code.
Role B instead uses the explicit pre-tag-50
`UdpControlFirstByteGuardAborted` boundary because no method phase begins. A
published role-C UDP child uses tag 50 with the child present,
`SendBoundedFRAG0Canary` failed as `Socks5UdpCanaryFailed`,
the exact already-durable tag-48 delivery, and `Attempted` with the complete
constructed request digest, `request_datagrams_sent=0`, and
`response=NotReceived`. The atomic guarded send emits zero datagram bytes. It is not
`UdpChildReleaseAborted`, and its tag-46 latch still owns the outer outcome.
Any other phase/code/evidence pairing, a missing published child, or a network
byte despite the failed guard invalidates the wrapper.

A platform that cannot prove which process accepted the established connection
MUST NOT send any bytes to that local endpoint. An HTTPS/cooperative mechanism
that needs an in-band TLS ClientHello before peer ownership is known is
`UnsupportedPendingArchitecture/ConnectedLocalPeerPreTlsAttestationUnavailable`.
Out-of-band cooperative attestation is also
`UnsupportedPendingArchitecture/CooperativeConnectedPeerAttestationUnavailable`
because v1 defines no fresh socket-bound challenge, verification key/domain, or
signed accepted-socket root. Supporting either form requires a future accepted
contract with those fields and, for in-band TLS, a two-stage pre-TLS permit and
application-byte release root; this v1 contract deliberately defines none.
Ordinary HTTPS server authentication alone is insufficient. All other missing
peer-binding cases are
`UnsupportedPendingArchitecture/ConnectedLocalPeerUnproven`.
Re-querying the port before `connect`, a PID snapshot, or comparing only the
client-side peer tuple does not close the race.

PID reuse, port reuse, listener replacement, FD transfer, executable
replacement, signer/package change, namespace move, process-object loss,
dual-stack change, policy drift, or observation expiry returns a typed identity
error. The implementation MUST NOT retarget the running plan to the replacement.
It closes or keeps closed the data-plane gate, denies commit or renewal, and
rolls back under the ARCH-001 fence.

FlowProbe observes but does not own an external proxy. Stop and recovery remove
only FlowProbe-owned exclusion resources. They MUST NOT kill, restart, suspend,
modify, or restore the external proxy process.

## 9. Egress actor graph and exclusion set

### 9.1 Actor/path declarations

```text
EgressActorV1 = {
  actor_id,
  actor_class,
  component_instance_id,
  runtime_instance_id?,
  network_path_declarations,
  actor_identity: ActorIdentityV1,
}

ActorIdentityV1 =
  | FlowProbeOwnedComponent {
      component_instance_id,
      runtime_instance_id?,
    }
  | ExternalLocalProxyIdentity {
      local_proxy_identity_digest,
    }

ActorClass =
  | Renderer
  | TrustedProductPolicyBroker
  | Supervisor
  | SecretBroker
  | TrustMaterialBroker
  | ConfigCompiler
  | NetworkRuntimeAdapter
  | NetworkRuntime
  | CaptureCoreConnector
  | PlatformDiscoveryBackend
  | PrivilegedHelper
  | WatchdogOrReconciler
  | ExternalLocalProxy
  | DnsActor
  | UdpActor

EgressActorGraphV1 = {
  actors,
}

NetworkPathDeclaration =
  | NoExternalNetworkPath {
      isolation_policy_digest,
      initialization: ActorNetworkIsolationInitializationV1,
    }
  | RequiredPath {
      purpose,
      families,
      transports,
      endpoint_binding: PathEndpointBindingV1,
    }

PathPurpose =
  | ProxyEndpointBootstrapDns
  | RuntimeDestinationDns
  | ProxyControl
  | RuntimeDestinationTcp
  | Socks5UdpRelay
  | CertificateStatus
  | PreactivationProof
  | PostactivationCanary
  | SustainedHealth
  | ExternalLocalProxyUpstreamDns
  | ExternalLocalProxyUpstreamTcp
  | ExternalLocalProxyUpstreamUdp
  | RecoveryConnectivityProbe
  | ProductTelemetry

ActorNetworkIsolationInitializationV1 =
  | ExistingPreplanReadback {
      initial_isolation_readback_digest,
    }
  | StartInertThenPreactivationReadback

ActorNetworkIsolationPolicyV1 = {
  actor_id,
  actor_class,
  component_instance_id,
  actor_identity: ActorIdentityV1,
  capability_report_digest,
  mechanism: ActorNetworkIsolationMechanismV1,
  mechanism_version,
  policy_instance_identity,
  denied_capabilities = AllExternalSocketCreationAndNetworkIpc,
  denied_address_families = AllExternalNetworkFamilies,
  denied_transports = AllExternalNetworkTransports,
  permitted_local_ipc,
  policy_epoch,
  readback_recipe = CompletePolicyAndSocketSurfaceV1,
}

ActorNetworkIsolationReadbackContextV1 =
  | Preplan {
      discovery_context: PreplanDiscoveryContextV1,
    }
  | PreactivationPlanCheckpoint {
      prepared_plan_digest,
      generation,
      proof_specification_digest,
      helper_observation_nonce,
    }
  | ActivePlanCheckpoint {
      prepared_plan_digest,
      generation,
      phase_context: ProxyEvidenceObservationContextV1,
      activation_lease_id,
      lease_epoch,
      fence_token_digest,
    }

ActorNetworkIsolationReadbackV1 = {
  isolation_policy_digest,
  actor_id,
  actor_class,
  component_instance_id,
  actor_identity: ActorIdentityV1,
  capability_report_digest,
  observation_context: ActorNetworkIsolationReadbackContextV1,
  mechanism: ActorNetworkIsolationMechanismV1,
  mechanism_version,
  policy_instance_identity,
  denied_capabilities = AllExternalSocketCreationAndNetworkIpc,
  denied_address_families = AllExternalNetworkFamilies,
  denied_transports = AllExternalNetworkTransports,
  permitted_local_ipc,
  policy_epoch,
  readback_epoch,
  unexpected_external_entrypoint_count = 0,
  unexpected_external_socket_count = 0,
  observed_at,
  expires_at,
  outcome = PreventiveComplete,
  authenticators,
}

ActorNetworkIsolationMechanismV1 =
  | WindowsAppContainerNetworkCapabilityDenyV1
  | WindowsWfpProcessSocketDenyV1
  | LinuxSeccompSocketBrokerDenyV1
  | DarwinSandboxSocketDenyV1
  | HermeticFakeNetworkIsolationV1

LocalIpcPermitV1 = {
  endpoint_identity,
  peer_actor_id,
  transport: UnixSeqpacket | WindowsNamedPipe | MachPort |
             InProcessTypedChannel,
  direction: Send | Receive | Bidirectional,
  message_schema_ids,
  maximum_frame_bytes,
}
```

The graph contains at least one instance for every component in the trust table,
even when that component is an in-process library. Every instance has either
exactly one `NoExternalNetworkPath` declaration or `1..=16` unique sorted
`RequiredPath` declarations; the two forms are mutually exclusive. Claiming an
actor is networkless while also declaring a required path is invalid.
`FlowProbeOwnedComponent` repeats the actor's component/runtime instance fields
byte-for-byte. `ExternalLocalProxyIdentity` is permitted only for
`ExternalLocalProxy`, requires the actor's `runtime_instance_id` absent, and
names exactly `Digest(LocalProxyIdentityV1)`; no other actor identity hash or
producer-defined identity domain exists. Every exclusion entry resolves its
`actor_id` through this graph and therefore inherits that exact identity rather
than carrying a second substitutable digest.
`NoExternalNetworkPath` requires a preventive sandbox, socket-creation policy,
or equivalent complete readback; source review or a convention is insufficient.
Its `isolation_policy_digest` is exactly the unsigned
`Digest(ActorNetworkIsolationPolicyV1)` (tag 54). `ExistingPreplanReadback` is
valid only for an already-live actor whose tag-55 `Preplan` root is signed once
by `PlatformDiscoveryBackend` under the same discovery context as the graph.
`StartInertThenPreactivationReadback` is valid only for a component instance
allocated in the plan but not yet executing: after `Prepared`, the helper-
controlled launcher creates it suspended/inert with the tag-54 policy attached.
No actor instruction, local IPC frame, external socket, protocol byte, or shared
OS mutation may occur until the fresh dual-signed preactivation tag-55 root has
been durably accepted. No future readback digest is placed in the graph.
Regardless of initialization branch, the preactivation proof references exactly
one fresh `PreactivationPlanCheckpoint` tag-55 root per networkless actor before
that actor may run or the proof may emit protocol bytes.

Each real-platform tag-54 policy's `capability_report_digest` names one pre-plan tag-2 report
with key `ActorNetworkIsolation`, `Supported` disposition,
`SupportedByDesign`/`Ready`/`RealHostVerified`, `Preventive` enforcement, and a
tag-53 `PlatformCapabilityEvidenceV1` root. Report, release root, policy, and
every tag-55 readback repeat the same mechanism/version, backend/package,
platform scope, actor class, covered network scopes, all external address
families/transports, and release build tuple. The mechanism-to-platform mapping
is exact: AppContainer/WFP-deny variants are Windows only, seccomp socket-broker
deny is Linux only, and sandbox socket-deny is Darwin only. The report must
cover this actor class and every network scope in which the graph is sealed;
its endpoint-locality collection is empty because the policy denies socket
creation rather than authorizing an endpoint. A missing/narrower/stale report,
cross-platform mechanism, detective strength, release-root mismatch, or
`HermeticFakeNetworkIsolationV1` in a release build makes
`NoExternalNetworkPath` invalid. A backend signature alone cannot promote an
unpackaged isolation mechanism into `PreventiveComplete`.

Under `HermeticFixtureValidation` only, a tag-54 policy using
`HermeticFakeNetworkIsolationV1` instead names the exact fake tag-2 report
defined in section 6.2, has no tag-53 root, and may be paired with fixture
tag-55 readbacks to exercise canonical encoding and equality rules. It remains
ineligible for normal plan sealing or any release success claim.

Every tag-55 root repeats the tag-54 actor, identity, capability-report digest,
mechanism, policy identity,
denied surface, local IPC permit set, and policy epoch byte-for-byte. The
readback recipe enumerates the selected policy state and the entire externally
network-capable entrypoint/socket surface, so both unexpected counts are
literally zero. Neither policy intent without a readback nor a readback without
its exact policy root is sufficient. Local typed IPC is carried only by those
typed roots and does not authorize an Internet socket. A probe is a `PathPurpose` on the actual component that opens
the socket: the preactivation, postactivation, and selected connector paths are
normally declarations of the same `NetworkRuntime` instance, not fictional
probe processes. If an implementation introduces a separate process, it adds a
distinct actor instance before sealing. Certificate-status, resolver,
telemetry, helper/watchdog, platform-backend, secret-broker, trust-material-
broker, and recovery paths are treated identically. An unknown component class
or purpose makes the graph invalid rather than implicitly networkless.
Every `RequiredPath.endpoint_binding` selects exactly this purpose matrix:

- `ProxyControl` uses `ProxyEndpointSet` with the plan's tag-4
  `ProxyEndpoint` root;
- `ProxyEndpointBootstrapDns` and `RuntimeDestinationDns`
  use `ResolverPath` with their exact tag-3 root; a DNS-purpose declaration is
  omitted when no DNS operation exists;
- `PreactivationProof`, `PostactivationCanary`, and `SustainedHealth` are
  selection-dependent: `Direct` uses `ProbeTargetProfiles` containing the proof
  specification's exact one-entry tag-18 list, while every
  external HTTP/HTTPS/SOCKS selection uses `ProxyEndpointSet` with the plan's
  tag-4 `ProxyEndpoint` root because the connector socket's actual OS peer is
  the proxy; the tag-18 target and authorization remain separately sealed in
  the proof specification and enclosing proof/checkpoint root and are never
  represented as that socket peer;
- `RuntimeDestinationTcp`, `Socks5UdpRelay`, `CertificateStatus`,
  `RecoveryConnectivityProbe`, and `ProductTelemetry` use
  `OwnedActorAllExternalEndpoints` with the same actor's exact tag-14 factory
  policy; and
- the three `ExternalLocalProxyUpstream*` purposes use
  `ExternalLocalProxyAllExternalEndpoints` with the actor's exact tag-5 identity.

`ExternalSocks5::RequireAssociate` requires three distinct child-role bindings
on that same `NetworkRuntime`: A uses the context-specific
`PreactivationProof`, `PostactivationCanary`, or `SustainedHealth` declaration
to the proxy endpoint set; B uses `ProxyControl` to that byte-identical set; C
uses `Socks5UdpRelay` to its independently selected relay. The first two are
both TCP paths to the same proxy candidate but are not one declaration, child,
socket, or connection epoch. Omitting either purpose or using A's declaration
to label B invalidates the actor graph/checkpoint; no new `PathPurpose` tag is
introduced.

No other purpose/binding/selection combination has an encoding. The two all-external variants
are loop-exclusion scopes only: they ensure every socket of the exact owned
factory or independently owned local-proxy process bypasses the captured path;
they grant no DNS, target, telemetry, certificate, destination, or protocol
authority, which remains in its separate typed policy. A future target or relay
observation never feeds back into the pre-plan graph.
The release Renderer entry is mandatory and uses `NoExternalNetworkPath` with
preventive renderer sandbox/socket-deny policy and complete readback evidence.
Its local typed IPC is separately bounded. The renderer policy identity is
sealed, re-read before commit and at renewal, and any drift closes the gate;
source review, UI intent, or omission from the graph is not evidence that it is
networkless.

`permitted_local_ipc` contains `0..=32` unique entries ordered by full canonical
bytes; each entry has `1..=16` unique message-schema IDs in ascending numeric
order and `maximum_frame_bytes` in `1..=1048576`. Any other socket API, family,
transport, endpoint, peer, direction, schema, or frame size makes
`PreventiveComplete` false. Every tag-55 root repeats its tag-54 policy and the
actor ID, class, component identity, `ActorIdentityV1`, mechanism, permit set,
and policy epoch byte-for-byte; a stale policy/readback epoch, unexpected
entrypoint/socket, extra socket path, or unsigned/private evidence hash is
invalid.
`policy_instance_identity` and each local `endpoint_identity` are fresh
helper-sealed 32-byte correlation identifiers, not hashes or evidence by
themselves; their meaning comes only from the complete policy/readback pair.

A tag-55 `PreactivationPlanCheckpoint` repeats the exact prepared plan,
generation, proof specification, and public helper observation nonce. An
`ActivePlanCheckpoint` permits only a `Postactivation` or `Renewal`
`phase_context` and repeats the exact current plan, generation, activation
lease, lease epoch, fence, and outer checkpoint context. Either plan-bound
variant has exactly two authenticators in fixed order:
`PlatformDiscoveryBackend` with `PlanComponentAuthenticatedChannel`, then
`PrivilegedHelper` with `HelperAuthority`. The platform backend reads the
complete policy and socket surface while the helper independently binds the
sealed policy resource and applicable proof/lease/fence. Plan-bound roots are
fresh for their checkpoint and do not enter or change `EgressActorGraphV1`;
they are referenced by the path proof, canary, or health root. A one-signer,
pre-plan-replayed, cross-phase, cross-proof/lease, stale, partially enumerated,
or changed-policy root cannot authorize actor release, mutation, commit, or
renewal.

When the selected proxy candidate locality is `HostLocal`, the graph contains
exactly one `ExternalLocalProxy` actor whose `actor_identity` is
`ExternalLocalProxyIdentity { local_proxy_identity_digest =
Digest(LocalProxyIdentityV1) }`. Both exclusion roots carry that same digest, and
the actor's declarations plus exclusion entries use the closed
`ExternalLocalProxyUpstream*` purposes and cover every applicable TCP, UDP, and
DNS path for the selected protocol. Deleting that actor, omitting one
applicable path/family/transport, or substituting another local identity is
`ExclusionSetIncomplete`. For `Direct` or an external `Remote` candidate, both
optional digest fields are absent and the graph contains no
`ExternalLocalProxy` actor. Locality is never inferred from omission.
The local-proxy actor's `runtime_instance_id` is absent because FlowProbe does
not own that process. Its three upstream `RequiredPath` declarations and their
exclusion entries use only `ExternalLocalProxyAllExternalEndpoints` with the
same identity digest. That
broad scope is invalid for every other actor/purpose. It requires preventive
process/cooperative-scope-wide enforcement over every external-network-capable
socket of the complete stable worker set; enumerating selected destinations is
not completeness. An extra worker, raw/other transport, unsupported family, or
unclosable worker set is
`UnsupportedPendingArchitecture/ExternalLocalProxyProcessScopeUnproven`.
No apply/compensation predicate may start, stop, kill, or mutate that process.
Every `NetworkPathDeclaration` and `EgressExclusionEntry` `families`/
`transports` field is a non-empty closed bitset in enum-tag bit order, not an
unbounded list. Unknown or zero bits and bits outside the selected actor policy
are invalid.

### 9.2 Exclusion entries

```text
EgressExclusionSetV1 = {
  network_scope,
  egress_selection_safe_digest,
  baseline_anchor_digest,
  actor_graph_digest,
  local_proxy_identity_digest?,
  entries,
  completeness_proof_digest,
}

EgressExclusionEntryV1 = {
  actor_id,
  purpose,
  families,
  transports,
  endpoint_binding: PathEndpointBindingV1,
  mechanism,
  mechanism_version,
  enforcement_strength,
  resource_ids,
  apply_predicate,
  read_back_predicate,
  health_predicate,
  compensation_predicate,
}

EgressExclusionCompletenessProofV1 = {
  network_scope,
  egress_selection_safe_digest,
  actor_graph_digest,
  local_proxy_identity_digest?,
  sorted_exclusion_entry_digests,
  covered_actor_path_family_transport_endpoint_tuples,
  required_tuple_count,
  completeness_checker_schema_and_version,
  completeness_checker_build_identity:
    CompletenessCheckerBuildIdentityV1,
  outcome = Complete,
}

CompletenessCheckerBuildIdentityV1 = {
  package_name,
  package_version,
  source_revision_sha256,
  checker_binary_sha256,
  dependency_lock_sha256,
}

EgressExclusionResourceReadbackV1 = {
  resource_id,
  observed_resource_identity,
  observed_state_digest,
  read_back_predicate_digest,
  outcome = Matched,
}

EgressExclusionEntryReadbackV1 = {
  exclusion_entry_digest,
  resource_readbacks,
}

EgressExclusionReadbackObservationV1 = {
  prepared_plan_digest,
  generation,
  observation_context: ProxyEvidenceObservationContextV1,
  activation_lease_id,
  lease_epoch,
  fence_token_digest,
  exclusion_set_digest,
  completeness_proof_digest,
  observed_at,
  expires_at,
  outcome: EgressExclusionReadbackOutcomeV1,
  authenticators,
}

EgressExclusionReadbackOutcomeV1 =
  | Complete { entry_readbacks }
  | Failed { bounded_phase, error_code = ExclusionReadBackFailed }
  | TimedOut { bounded_phase }
```

Each required path has exactly one or more entries whose union covers every
declared family, transport, endpoint binding, DNS bootstrap, proxy control
connection, SOCKS5 UDP relay, certificate-status connection, and target probe.
Every entry's `endpoint_binding` is byte-identical to its actor declaration;
`ProbeTargetProfiles` is one-to-one with the proof specification, and
`OwnedActorAllExternalEndpoints` repeats a tag-14 policy whose actor/component/
runtime identity equals the declaration. Entries must
name the sealed baseline egress anchor and prevent use of any FlowProbe capture
interface, route/table, redirect, or recursive proxy input.
`EgressExclusionSetV1.egress_selection_safe_digest` and
`EgressExclusionCompletenessProofV1.egress_selection_safe_digest` are
byte-identical to the plan's tag-1 digest; tag 0 and a producer projection are
invalid. Their network scope, actor graph, local-proxy optional, entry list, and
covered binding tuples all describe that same selection.

The completeness checker is closed over the actor graph and selected protocol.
It rejects an unrecognized actor/path/purpose. Omitting one entry, covering only
IPv4 for a dual-stack path, covering TCP but not a required UDP/DNS path, or
using only `Detective` evidence in full-tunnel is `ExclusionSetIncomplete`.
`EgressExclusionSetV1.completeness_proof_digest` is exactly
`Digest(EgressExclusionCompletenessProofV1)`. Its sorted entry digests and covered
tuples must be one-to-one with the set and graph, including every complete
`PathEndpointBindingV1` value; a producer cannot supply an
opaque checker hash or a count without the canonical tuple list.
`entries` and `sorted_exclusion_entry_digests` each contain `1..=128` unique
values and are one-to-one; the latter is ascending raw digest bytes. Covered
tuples contain `1..=512` unique values sorted by full canonical bytes, and
`required_tuple_count` equals their exact count. Every entry has `1..=8` unique
`resource_ids` sorted by raw canonical resource-ID bytes; an empty, duplicated,
truncated, or differently ordered collection is invalid.
The completeness-checker source and dependency-lock fields use the corresponding
domain-separated `ReleaseArtifactCorpusV1` manifests, while
`checker_binary_sha256` hashes the exact single packaged checker binary; the complete structure must
match the package manifest and cannot stand in for the canonical tuple proof.

The readback root is used only after activation and has exactly two
authenticators, `PlatformDiscoveryBackend` then `PrivilegedHelper`. It repeats
the exact postactivation or renewal context, current activation lease/epoch/
fence, registered exclusion-set digest, and registered completeness-proof
digest. For `Complete`, `entry_readbacks` contains exactly one item per exclusion entry in the
set's order; each item repeats that entry digest and contains exactly one item
per `resource_id` in resource-ID order. `observed_resource_identity`,
`observed_state_digest`, and `read_back_predicate_digest` use the exact ARCH-001
`ObservedResourceIdentity`, `ObservedStateDigest`, and sealed operation
read-back-predicate domains and equal that entry's planned values. Unknown,
missing, extra, reordered, stale, mismatched, non-`Matched`, or single-signer
readback data cannot produce `Complete`.

### 9.3 Baseline egress anchor

```text
BaselineEgressAnchorV1 = {
  discovery_context: PreplanDiscoveryContextV1,
  platform_family: PlatformFamilyV1,
  platform_stable_interface_identity: PlatformStableInterfaceIdentityV1,
  namespace_or_compartment,
  ipv4_route_tuple: BaselineRouteTupleV1?,
  ipv6_route_tuple: BaselineRouteTupleV1?,
  gateways,
  baseline_resolver_observation: BaselineResolverObservationV1?,
  discovery_mechanism: BaselineDiscoveryMechanismV1,
  mechanism_version,
  observed_at,
  expires_at,
  interface_epoch,
  route_epoch,
  authenticator,
}

BaselineResolverObservationV1 = {
  resolver_identity,
  namespace_or_compartment,
  resolver_endpoints,
  search_suffixes,
  resolver_configuration_epoch,
  mechanism: BaselineResolverDiscoveryMechanismV1,
  mechanism_version,
}

BaselineResolverDiscoveryMechanismV1 =
  | WindowsDnsConfigurationSnapshotV1
  | LinuxResolvedOrResolvConfSnapshotV1
  | DarwinSystemConfigurationDnsSnapshotV1
  | HermeticFakeBaselineResolverV1

PlatformStableInterfaceIdentityV1 =
  | WindowsInterface {
      interface_guid_bytes,
      interface_luid_u64,
      compartment_id,
    }
  | LinuxInterface {
      network_namespace_identity,
      interface_kind,
      permanent_hardware_address?,
      parent_link_identity?,
      creation_epoch,
    }
  | DarwinInterface {
      ifnet_generation_identity,
      interface_type,
      permanent_hardware_address?,
    }
  | HermeticFakeInterface {
      fixture_interface_identity,
    }

BaselineRouteTupleV1 = {
  address_family,
  destination_prefix,
  source_prefix_policy: BaselineSourcePrefixPolicyV1,
  next_hop?,
  route_table,
  metric,
  route_kind: BaselineRouteKindV1,
  stable_interface_identity: PlatformStableInterfaceIdentityV1,
}

BaselineSourcePrefixPolicyV1 =
  | AnySource
  | ExactSourcePrefix { normalized_prefix, prefix_length }

BaselineRouteKindV1 =
  | UnicastForward
  | HostLocalDelivery
  | LoopbackDelivery

BaselineDiscoveryMechanismV1 =
  | WindowsGetIpForwardTable2AndGetIfEntry2V1
  | LinuxRtmGetrouteGetlinkGetaddrV1
  | DarwinRouteSocketAndGetifaddrsV1
  | HermeticFakeBaselineV1

ConnectivityStateV1 = Reachable | Unreachable | NotApplicable

BaselineRelativeConnectivityDimensionV1 = {
  baseline_state: ConnectivityStateV1,
  current_state: ConnectivityStateV1,
  relation = NoWorseThanBaseline,
}

EgressOrdinaryConnectivityObservationV1 = {
  prepared_plan_digest,
  generation,
  observation_context: ProxyEvidenceObservationContextV1,
  activation_lease_id,
  lease_epoch,
  fence_token_digest,
  baseline_digest,
  observed_at,
  expires_at,
  outcome: EgressOrdinaryConnectivityOutcomeV1,
  authenticators,
}

EgressOrdinaryConnectivityOutcomeV1 =
  | Passed {
      ipv4,
      ipv6,
      dns,
      non_flowprobe_path,
    }
  | Failed { error_code = OrdinaryConnectivityFailed }
  | TimedOut { bounded_phase }
```

Interface name/index and current local address are locators, not the stable
identity. The anchor may represent a pre-existing administrator VPN or other
baseline default path when that is the observed ordinary network. “Physical”
in product language means this sealed pre-FlowProbe path or a platform protect
mechanism with equivalent escape from the pending capture path; it does not
authorize bypass of administrator policy.

`gateways` contains `0..=8` unique values sorted by address family, normalized
address bytes, and scope identifier. A duplicate, noncanonical scoped address,
or ninth gateway invalidates the anchor rather than being truncated.

The registered anchor root is signed only by `PlatformDiscoveryBackend` under
the exact pre-plan discovery context. Each present family route uses that
family, repeats the same stable interface identity as the root, and has a
normalized prefix, route kind, table, and metric. There is no opaque baseline
`evidence_digest`. Interface names and indices remain live locators and are not
members of `PlatformStableInterfaceIdentityV1`.
`platform_family` closes the whole aggregate. `Windows` requires a
`WindowsInterface`, `WindowsGetIpForwardTable2AndGetIfEntry2V1`, Windows
compartment identity in the root and every nested observation, and, when the
resolver observation is present, `WindowsDnsConfigurationSnapshotV1`. `Linux`
requires `LinuxInterface`, `LinuxRtmGetrouteGetlinkGetaddrV1`, one exact Linux
network namespace, and optional `LinuxResolvedOrResolvConfSnapshotV1`.
`Darwin` requires `DarwinInterface`,
`DarwinRouteSocketAndGetifaddrsV1`, one exact Darwin routing namespace, and
optional `DarwinSystemConfigurationDnsSnapshotV1`. `HermeticTestOnly` requires
`HermeticFakeInterface`, `HermeticFakeBaselineV1`, and optional
`HermeticFakeBaselineResolverV1`. Both family routes repeat the exact top-level
interface variant/value, and the resolver namespace equals the top-level one.
Cross-family route/interface/resolver/discovery members, a real/fake mix, or a
namespace/compartment mismatch invalidate the root.
Every optional hardware address is `1..=32` raw bytes. `parent_link_identity`
is an optional fixed 32-byte platform-stable identifier for one immediate link
parent, never a recursive object, name, index, or producer hash.
The optional baseline resolver observation contains `0..=8` unique inline
`EndpointIdentityV1` values ordered by canonical endpoint bytes and `0..=8`
unique normalized search suffix A-labels in configured order. It is descriptive
pre-FlowProbe state, not permission to resolve or an ARCH-004 DNS path. It never
contains `Digest(ResolverDependencyDescriptorV1)`: tag 11 is constructed first,
then tag 3 may point to it, so the root DAG has only the one-way tag-3-to-tag-11
edge. A preallocated ID or guessed digest cannot break that ordering.

The anchor is read-only during preflight. Its exact current tuple is re-read
before mutation and commit. A changed interface, gateway, table, metric,
namespace/compartment, family availability, or route epoch invalidates the
prepared plan.

`EgressOrdinaryConnectivityObservationV1.baseline_digest` is the exact
accepted ARCH-001 `PreparePlan.BaselineDigest` domain. The four displayed
dimensions in `Passed` are complete—no producer-defined list or opaque evidence digest is
accepted. `Reachable` may remain `Reachable`; `Unreachable` may remain
`Unreachable` or improve to `Reachable`; `NotApplicable` must remain
`NotApplicable`. Every other pair is worse and cannot carry
`NoWorseThanBaseline` or `Passed`. The root is used only postactivation or at
renewal, repeats that checkpoint's exact context and lease/fence, remains within
its freshness window, and has exactly two authenticators:
`PlatformDiscoveryBackend` then `PrivilegedHelper`. Either independently
recomputes the fixed ARCH-001 ordinary-connectivity oracle; a missing dimension,
context/lease/baseline mismatch, stale sample, unknown state, worse outcome, or
single signer is failure.

## 10. Preactivation path proof

### 10.1 Sealed proof specification

```text
EgressProofSpecificationV1 = {
  preparation_ticket_id,
  session_id,
  generation,
  proof_observation_nonce,
  runtime_instance_id,
  probe_actor_id,
  probe_factory_policy_id,
  actor_graph_digest,
  runtime_package_and_build_digest,
  runtime_config_template_digest,
  network_scope,
  egress_selection_safe_digest,
  baseline_anchor_digest,
  endpoint_resolution_digest?,
  local_proxy_identity_digest?,
  probe_target_profile_digests,
  target_authorization_receipt_digests,
  target_path_family_tuple_plans:
    exactly 1 TargetPathFamilyTuplePlanV1,
  timeout_budget,
  maximum_challenge_bytes,
  maximum_total_protocol_bytes,
  redirect_limit,
  retry_limit,
  concurrency_limit,
  nonce_commitments,
  expected_observation_schemas,
  expected_proxy_tls_evidence,
  expires_at,
}

PathFamilyTuplePlanV1 = {
  ordered_tuples: 1..=4 PathFamilyTupleV1,
  success_groups: 1..=4 PathFamilySuccessGroupV1,
}

PathFamilySuccessGroupV1 = {
  group_ordinal: 1..=4,
  acceptable_tuple_ordinals: 1..=4 u8,
}

TargetPathFamilyTuplePlanV1 = {
  target_profile_digest,
  path_family_tuple_plan: PathFamilyTuplePlanV1,
}

PathFamilyTupleV1 = {
  connector_family = Ipv4 | Ipv6,
  destination_family = Ipv4 | Ipv6 | ProxyOpaque,
}

`target_path_family_tuple_plans` is one-to-one with
`probe_target_profile_digests`, in the same `target_id` order, and each entry
repeats that profile digest. The compiler derives each target's
`path_family_tuple_plan` without producer choice. A family
policy expands in the exact order `Ipv4Only=[Ipv4]`, `Ipv6Only=[Ipv6]`,
`PreferIpv4=[Ipv4,Ipv6]`, `PreferIpv6=[Ipv6,Ipv4]`, and
`RequireBoth=[Ipv4,Ipv6]`; a family with no sealed candidate is removed only
from a `Prefer*` expansion and makes `Ipv*Only`/`RequireBoth` unavailable.
`Direct` uses the same family for connector and destination. An external
`ProxyName` uses the proxy family plus `ProxyOpaque`. External `LocalAddress`
uses the Cartesian connector/destination tuple.

Tuples are the unique Cartesian values in success-group-major order so every
group is one contiguous tuple range. With no `RequireBoth`, connector preference
is outer and destination preference inner; one group contains every tuple and
the first successful tuple satisfies it. With connector-only `RequireBoth`,
connector-required-family order is outer and each group contains that
connector's destination-preference tuples. With destination-only `RequireBoth`,
destination-required-family order is outer and each group contains that
destination's connector-preference tuples. With both `RequireBoth`, connector-
required-family order is outer, destination-required-family order inner, and
the four groups are singleton tuples. Direct and `ProxyName` apply the same rule
to their one visible family dimension. `success_groups` partitions all tuple
ordinals; group ordinals and every group's tuple ordinals are contiguous and
ascending, and each tuple occurs exactly once. This preserves `Prefer*` fallback
inside a required group while permitting one strictly forward serial schedule.

The tuple list is `1..=4`, contains no duplicate, and is a byte-exact
deterministic projection of tag 1 plus the sealed target/proxy candidate sets.
A runtime cannot choose a different group, pairing, or preference after
sealing. Each tag-13/28/29 result selects exactly the plan
entry whose `target_profile_digest` equals its own target; tuple plans from
another target cannot be combined or substituted.

ExpectedObservationSchemaV1 = {
  root_tag,
  schema_version = 1,
  required_signer_roles,
  maximum_observation_age,
}

ProofObservationNonceV1 =
  | HelperAssignedSlot { slot_id }
  | SealedHelperObservationNonce { helper_observation_nonce }

ExpectedProxyTlsEvidenceV1 =
  | NotApplicable
  | ExternalHttps {
      proxy_tls_policy_descriptor_digest,
      trust_material_descriptor_digest,
      tls_verifier_capability_report_digest,
      tls_verifier_capability_evidence_digest,
      tls_verifier_implementation_and_build_digest,
      delivery_root = { tag = 40, version = 1, signer = TrustMaterialBroker },
      runtime_load_root = { tag = 24, version = 1, signer = NetworkRuntime },
      adapter_artifact_root = { tag = 41, version = 1, signer = RuntimeAdapter },
      handshake_root = { tag = 42, version = 1, signer = NetworkRuntime },
      effective_trust_observation_root? =
        { tag = 47, version = 1, signer = TrustMaterialBroker },
      maximum_observation_age,
    }

ProbeTargetAuthorizationScopeV1 = {
  preparation_ticket_id,
  session_id,
  generation,
  policy_broker_challenge,
  exact_probe_target_subject_digest,
  policy_text_version,
}

ProbeTargetAuthorizationSubjectV1 = {
  target_id,
  endpoint,
  target_resolution_policy,
  resolved_endpoint_set_digest?,
  exact_network_scope,
  exact_egress_tag,
  address_authorization,
  port_authorization,
  challenge,
  transport_authorization: ProbeTransportAuthorizationV1,
  maximum_challenge_bytes,
  profile_version,
}

ProbeTargetProfileV1 = {
  probe_target_authorization_scope_digest,
  probe_target_authorization_receipt_digest,
  target_id,
  endpoint,
  target_resolution_policy,
  resolved_endpoint_set_digest?,
  exact_network_scope,
  exact_egress_tag,
  address_authorization,
  port_authorization,
  challenge,
  transport_authorization: ProbeTransportAuthorizationV1,
  maximum_challenge_bytes,
  profile_version,
}

ProbeAddressAuthorizationV1 =
  | PublicGlobalUnicastOnly {
      classifier_version = FlowProbeProbeAddressClassifierV1,
      classifier_snapshot_digest,
    }
  | ExactSpecialUse {
      classifier_version = FlowProbeProbeAddressClassifierV1,
      classifier_snapshot_digest,
      address_class,
      authorized_endpoint_scope,
    }
  | ExactProxyOpaqueName {
      exact_normalized_name,
    }

ProbeAuthorizedEndpointScopeV1 =
  | SingleLiteralEndpoint { endpoint_identity_digest }
  | CompleteResolvedSet { resolved_endpoint_set_digest }

ProbeAddressClassifierSnapshotV1 = {
  classifier_version = FlowProbeProbeAddressClassifierV1,
  source_registries,
  sorted_prefix_rules,
  sorted_exact_metadata_addresses,
}

ProbeAddressRegistrySourceV1 = {
  registry = IanaIpv4Special | IanaIpv6Special,
  last_modified_utc_date = 2025-10-09,
  content_sha256,
}

ProbeAddressPrefixRuleV1 = {
  address_family,
  normalized_prefix_bits,
  prefix_length,
  longest_match_priority,
  address_class,
}

ProbeAddressClassV1 =
  | MetadataService
  | HostLocalInterface
  | Loopback
  | LinkLocal
  | PrivateUse
  | SharedAddressSpace
  | UniqueLocal
  | Documentation
  | Benchmarking
  | ProtocolAssignment
  | Multicast
  | Unspecified
  | Broadcast
  | ReservedOrFutureUse

ProbePortAuthorizationV1 =
  | DefaultWebAndUnprivileged
  | ExactPort { port }

ProbeTargetResolutionPolicy =
  | FollowLocalAddress {
      resolver_dependency,
      family_policy,
    }
  | FollowProxyNameOpaque {
      exact_normalized_name,
      opaque_resolution_authorized = true,
    }

ProbeTargetAuthorizationReceiptV1 = {
  receipt_id,
  issuer_kind,
  issuer_identity_digest,
  installation_id,
  preparation_ticket_id,
  session_id,
  generation,
  exact_probe_target_authorization_scope_digest,
  decision_nonce,
  boot_epoch,
  issued_at,
  continuous_expires_at,
  signature,
}

ProbeChallenge =
  | TcpConnect
  | NonceEcho { protocol_version = 1 }

ProbeTransportAuthorizationV1 =
  | TcpOnly
  | TcpAndSocks5UdpCanary

NonceEchoCommitmentEntryV1 =
  | HelperAssignedSlot {
      target_id,
      family_tuple_ordinal,
      family_tuple: PathFamilyTupleV1,
    }
  | SealedCommitment {
      target_id,
      family_tuple_ordinal,
      family_tuple: PathFamilyTupleV1,
      commitment,
    }

NonceEchoChallengeResultV1 = {
  prepared_plan_digest,
  generation,
  proof_specification_digest,
  target_profile_digest,
  attempt_ordinal,
  family_tuple_ordinal,
  family_tuple: PathFamilyTupleV1,
  candidate_binding: ConnectionAttemptCandidateBindingV1,
  connection_binding_epoch,
  selected_connector_socket_child_observation_digest,
  socket_observation_accumulator_digest,
  commitment,
  delivery_consumption_record_digest?,
  outcome: NonceEchoOutcomeV1,
}

NonceEchoOutcomeV1 =
  | Passed {
      response_frame_digest,
      bytes_sent = 40,
      bytes_received = 40,
    }
  | Failed {
      error_code: TargetChallengeFailureCodeV1,
      bytes_sent,
      bytes_received,
    }
  | TimedOut { bytes_sent, bytes_received }
  | Cancelled { bytes_sent, bytes_received }

NonceEchoDeliveryPhaseContextV1 =
  | Preactivation {
      preparation_ticket_id,
      session_id,
      helper_observation_nonce,
      attempt_ordinal,
      family_tuple_ordinal,
      family_tuple: PathFamilyTupleV1,
      candidate_binding: ConnectionAttemptCandidateBindingV1,
      connection_binding_epoch,
      selected_connector_socket_child_observation_digest,
    }
  | Socks5UdpCanary {
      observation_context: ProxyEvidenceObservationContextV1,
      attempt_ordinal,
      family_tuple_ordinal,
      family_tuple: PathFamilyTupleV1,
      candidate_binding: ConnectionAttemptCandidateBindingV1,
      target_tunnel_connection_binding_epoch,
      target_tunnel_socket_child_observation_digest,
      udp_control_connection_binding_epoch,
      udp_control_socket_child_observation_digest,
      udp_socket_child_observation_digest,
      relay_endpoint_digest,
      relay_endpoint_set_digest,
      destination: Socks5UdpCanaryDestinationV1,
    }
  | Postactivation {
      helper_observation_nonce,
      capture_generation_marker_digest,
      attempt_ordinal,
      family_tuple_ordinal,
      family_tuple: PathFamilyTupleV1,
      candidate_binding: ConnectionAttemptCandidateBindingV1,
      connection_binding_epoch,
      selected_connector_socket_child_observation_digest,
    }
  | Renewal {
      activation_lease_id,
      lease_epoch,
      renewal_challenge_nonce,
      fence_token_digest,
      attempt_ordinal,
      family_tuple_ordinal,
      family_tuple: PathFamilyTupleV1,
      candidate_binding: ConnectionAttemptCandidateBindingV1,
      connection_binding_epoch,
      selected_connector_socket_child_observation_digest,
    }

NonceEchoDeliveryConsumptionRecordV1 = {
  prepared_plan_digest,
  generation,
  proof_specification_digest,
  target_profile_digest,
  commitment,
  phase_context: NonceEchoDeliveryPhaseContextV1,
  runtime_instance_id,
  runtime_gate_channel_binding_digest,
  delivery_id,
  state = ConsumedBeforeWrite,
  consumed_at,
  expires_at,
  authenticator,
}

NonceEchoOneUseDeliveryFrameV1 = {
  prepared_plan_digest,
  generation,
  proof_specification_digest,
  target_profile_digest,
  commitment,
  phase_context: NonceEchoDeliveryPhaseContextV1,
  runtime_instance_id,
  runtime_gate_channel_binding_digest,
  delivery_id,
  delivery_consumption_record_digest,
  raw_nonce,
  channel_authentication = ExistingAuthenticatedRuntimeChannel,
}
```

`redirect_limit` is always zero. `retry_limit` is at most one retry per sealed
candidate and cannot change selection. `maximum_challenge_bytes` is the per-
challenge-occurrence application-payload cap and is at most 1024 bytes in each
direction.
`maximum_total_protocol_bytes` is at most 256 KiB across the proof: each resolver
exchange is at most 64 KiB, HTTP response head 32 KiB, TLS certificate chain
64 KiB, OCSP response/responder chain 32 KiB each, and every SOCKS frame is
bounded by its one-octet/RFC 1928 fields. `RequireAssociate` counts both
independent TCP greetings, both applicable RFC 1929 exchanges, the CONNECT and
UDP ASSOCIATE request/reply frames, and the UDP canary envelope; the role-B
connection and role-C factory operation start no new byte allowance. The
compiler-fit rule above makes total-budget exhaustion impossible for every
locally deterministic write, maximum conforming peer frame, and reserved over-
bound sentinel. The runtime never accepts bytes beyond the sealed global total.
Hostile or malformed peer input beyond a phase's structural bound stops at that
reserved sentinel/truncation observation and maps through the phase's existing
closed failure relation—for example `ProxyResponseTooLarge`,
`ProxyTlsFailed`, the applicable SOCKS framing failure, `ProbeFailed`, or
`Socks5UdpCanaryFailed`; there is no generic total-budget failure code. No
target response body is read after the fixed challenge completes.

`probe_target_profile_digests` and `target_authorization_receipt_digests` each
contain exactly one value; the receipt digest equals the profile's
`probe_target_authorization_receipt_digest`, and the sole tuple-plan entry
repeats that profile digest. `nonce_commitments` contains `0..=4` unique entries
ordered by `family_tuple_ordinal` and has exactly one entry for every tuple of a
NonceEcho target's tuple plan and none for a TcpConnect target. `family_tuple`
equals that plan entry exactly, and every entry's `target_id` equals the sole
referenced `ProbeTargetProfileV1.target_id`. `concurrency_limit` is exactly 1; any
inconsistent count, duplicate, or extra target/receipt/plan is invalid before
sealing.
The subject/profile `transport_authorization` fields are byte-identical and are
part of the signed authorization scope. `TcpConnect` permits only `TcpOnly`.
For a `NonceEcho` target, every selection other than
`ExternalSocks5::RequireAssociate` also requires `TcpOnly`;
`ExternalSocks5::RequireAssociate` instead requires exactly
`TcpAndSocks5UdpCanary`. That latter value authorizes one additional SOCKS5 UDP
NonceEcho datagram exchange to the same target/candidate and port; it does not
authorize direct UDP, a second target, a different challenge, application UDP,
or reuse by another plan/generation. A missing or broader/narrower transport
scope is `ProbeTargetAuthorizationInvalid` before any UDP socket or nonce exists.
`ProtocolAttemptChallengeEvidenceV1.challenge_kind` and tag 27/tag 37 always
project only the profile's stream `challenge`; the additional transport
authorization is consumed solely by tag 50 and never creates an alternate
challenge result root.

`actor_graph_digest` is the plan's exact registered
`Digest(EgressActorGraphV1)` (tag 8). `probe_actor_id` resolves through that
graph to exactly one `NetworkRuntime` actor whose `runtime_instance_id` equals
the specification's `runtime_instance_id`; that actor has every selected
`PreactivationProof`, `PostactivationCanary`, and `SustainedHealth` declaration
used by this specification. `probe_factory_policy_id` resolves through the
plan's exact tag-14 resource set to exactly one factory whose actor, component,
and runtime fields equal that actor byte-for-byte and whose allowed path set
contains those same purposes. A missing, duplicate, cross-runtime,
cross-component, cross-actor, or cross-factory resolution invalidates the
specification before sealing. These fields select the one executor/factory
identity for all three verification contexts; an outer result cannot search the
graph again and choose another otherwise-applicable actor.

`expected_observation_schemas` contains `1..=32` unique
`ExpectedObservationSchemaV1` values in ascending `root_tag` order and is the
exact schema/role/freshness set required by the selected protocol, phase, actor
graph, and target set. It carries the typed entries directly; no digest of a
producer-owned schema table is accepted. An absent required root, extra tag,
wrong signer order, duplicated tag, or weakened freshness bound invalidates the
specification before plan sealing.
Each `required_signer_roles` list contains `1..=4` unique roles in the exact
order prescribed by the root-to-role table; a registered unsigned descriptor
is not listed as a future observation schema.

`endpoint_resolution_digest` is absent exactly for `Direct`. Every external
proxy variant requires it present as the pre-plan tag-4 `ProxyEndpoint` root for
the exact configured proxy endpoint: an IP literal uses
`LiteralNoResolution`, while a DNS name uses `ResolvedDns`. This root provides
the route/locality fact that decides `HostLocal` versus `Remote`; a target or
SOCKS-relay root cannot substitute for it.
`local_proxy_identity_digest` is present exactly when that proxy-endpoint root's
selected candidate is `HostLocal`; it names the one matching pre-plan tag-5
root and equals the local-proxy identity carried by the actor graph, exclusion
set, and completeness proof. It is absent for `Direct` and every `Remote`
candidate. An ambiguous candidate cannot be sealed.

`expected_proxy_tls_evidence` is `ExternalHttps` exactly for that selected tag
and otherwise `NotApplicable`. It seals immutable descriptor, exact live
capability-report, release-evidence, and verifier-build digests plus fixed root
tags/versions, signer-role set, and freshness bound. It never contains a future
delivery/load/artifact/handshake observation digest. The corresponding result,
canary, and renewal references must satisfy this expectation without changing
the proof specification or `PlanDigest`.
The optional tag-47 expectation is present exactly for `SystemRoots` and
`SystemRootsWithSpkiPins` and absent for both private-anchor variants.
The candidate specification contains `HelperAssignedSlot` with a fresh
non-authorizing 32-byte slot ID; during sealing the helper replaces it with a
fresh public 32-byte `SealedHelperObservationNonce` before computing the final
specification and plan digests. A candidate-supplied nonce or a prepared plan
that still contains the slot is invalid.

Receipt construction starts from the registered
`ProbeTargetAuthorizationSubjectV1`, not from a profile projection. The subject
contains all target fields, including network scope and egress tag, but contains
neither `probe_target_authorization_scope_digest` nor
`probe_target_authorization_receipt_digest`. The
scope binds its digest, the preparation ticket/session/generation, policy-text
version, and a fresh public 32-byte `policy_broker_challenge` generated after the
ticket. The broker signs `Digest(ProbeTargetAuthorizationScopeV1)`; only then is
`ProbeTargetProfileV1` constructed with both the scope and receipt digests. Every
remaining profile field MUST be byte-identical to the registered subject. No
profile-with-omitted-fields encoding, implicit tuple hash, or self-digest is
defined.

`ProbeAddressAuthorizationV1` is one closed choice, not an implementation-owned
list. `PublicGlobalUnicastOnly` is the default. `ExactSpecialUse` authorizes one
exact `ProbeAddressClassV1` and one exact endpoint scope. A literal target uses
`SingleLiteralEndpoint` whose registered `EndpointIdentityV1` equals the subject
endpoint; a locally resolved DNS target uses `CompleteResolvedSet` whose
registered `ResolvedEndpointSetV1` equals the subject resolution evidence.
Using the wrong scope variant, omitting a DNS candidate, or supplying a resolved
set for a literal is invalid. Every resolved candidate must have the same class.
`SingleLiteralEndpoint` requires `resolved_endpoint_set_digest` absent;
`CompleteResolvedSet` requires it present and equal to the same registered set;
`ExactProxyOpaqueName` also requires it absent because the proxy's address result
is unknowable. No placeholder digest is accepted.
`HostLocalInterface` additionally requires `CompleteResolvedSet`, with every
candidate carrying current `ResolvedEndpointSetV1` host-local locality/route
evidence. A literal address claimed host-assigned from a baseline route alone is
unsupported; the baseline anchor is not an address-inventory snapshot.
`ExactProxyOpaqueName` is valid only with `FollowProxyNameOpaque` and binds the
same normalized A-label byte-for-byte; it makes no address-family claim.

`ProbeAddressClassifierSnapshotV1` contains `1..=256` unique prefix rules sorted
by full canonical rule bytes and `0..=16` unique metadata IP addresses sorted by
`(address_family, normalized_address_bytes)`. A metadata entry is an address,
not an `EndpointIdentityV1`, so its class cannot vary by port.
`source_registries` is exactly two `ProbeAddressRegistrySourceV1` values in
registry-tag order. The only accepted v1 sources are the byte-exact IANA IPv4
and IPv6 special-purpose CSV
snapshots last modified 2025-10-09 with SHA-256 values
`e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73`
and `775feea0621dec8735a44fbf30f762e721e8f0a1b3ab7eb341961a88cfce2139`,
respectively, and those complete hashes are encoded in the two source values.
Every comma-separated address block in a CSV cell becomes a distinct
normalized rule, parent and exception rows are both retained, and
`longest_match_priority` equals `prefix_length`. The schema package embeds
exactly one byte-exact golden root made
from every normalized address block in those two files, the two multicast
prefixes `224.0.0.0/4` and `ff00::/8`, and the metadata addresses below; it
accepts only that root digest. An arbitrary producer-supplied, locally updated,
or partially parsed table is invalid. Changing a source byte, rule, mapping,
metadata address, or accepted digest requires a new classifier version and new
contract vectors.

`FlowProbeProbeAddressClassifierV1` applies the snapshot's longest-prefix rule
and this fixed priority before a receipt
is issued: exact product metadata addresses; an address present on the sealed
host-interface snapshot; unspecified; loopback; link-local; multicast;
broadcast; RFC 1918 private use; RFC 6598 shared space; RFC 4193 unique-local;
IANA documentation; IANA benchmarking; another IANA special-purpose protocol
assignment; IANA reserved/future-use; otherwise public global unicast. IPv4-
mapped IPv6 is first normalized to IPv4 and scoped IPv6 is accepted only where
the class permits a scope. The v1 metadata set is exactly
`169.254.169.254/32`, `169.254.170.2/32`, and `fd00:ec2::254/128`; it wins over
link-local or unique-local classification. The snapshot fixes all IANA IPv4 and
IPv6 special-purpose entries. Registry rows named Private-Use, Shared Address
Space, Unique-Local, Documentation, Benchmarking, Loopback, Link-Local,
Unspecified, Limited Broadcast, or Reserved map to the correspondingly named
closed class; every other registry row, including a globally reachable anycast
or transition assignment, maps to `ProtocolAssignment`, and a terminated row
with no current flags maps to `ReservedOrFutureUse`. The two full source hashes
bind the source rows and flags; each output rule binds its normalized prefix and
resulting closed class. The root does not claim to reproduce row names or flags
as separate fields. Classification never performs an ambient online registry
lookup. `Multicast`,
`Unspecified`, and `Broadcast` are terminal prohibited classifier results and
MUST NOT appear in `ExactSpecialUse`, even with an administrator receipt. An
unknown, mixed-class, stale, or differently classified candidate set is refused
before mutation.

`DefaultWebAndUnprivileged` means exactly ports `80`, `443`, or
`1024..=65535`. `ExactPort.port` is one nonzero `u16` and equals
`ProbeTargetAuthorizationSubjectV1.endpoint.port`. `ExactSpecialUse` and
`ExactProxyOpaqueName` require `ExactPort`; the default port variant is valid
only with `PublicGlobalUnicastOnly`. Scope, subject, profile, resolved
candidates, and actual connection port must agree byte-for-byte.

`ExactSpecialUse` may be issued only by `InstalledAdministratorPolicy` or
`HermeticTestOnly`; `AuthenticatedUserAction` cannot authorize a special-use
address. `ExactProxyOpaqueName` may be issued by an authenticated user or
administrator only for the exact displayed name/port and proxy-resolution
selection. `HermeticTestOnly` remains invalid in release builds. Issuer kind is
checked from the signed receipt, never inferred from UI state.

The target receipt uses the Ed25519 issuer and distinct signature domain defined
in section 4.4. Its boot epoch and suspend-aware continuous deadline are part of
the signature. During `PreparePlan`, the helper stores the corresponding
`AuthorizationConsumptionRecordV1`, binding the receipt tuple to the candidate-
plan digest and idempotency result. Only an exact replay of that result is allowed; cross-plan,
ticket, session, generation, boot, or suspend replay is
`ProbeTargetAuthorizationInvalid`.

For the preactivation `NonceEcho`, a candidate proof specification contains
exactly one `HelperAssignedSlot` per `(target, family_tuple_ordinal)` and no
producer-selected commitment. During `PreparePlan` sealing, the helper replaces
each slot with `SealedCommitment`,
then computes the final specification/plan digest returned in `Prepared`. A
prepared or executing plan containing a slot, or a candidate containing a
commitment, is invalid. The helper generates a fresh unpredictable 32-byte nonce
for each replacement. Replacement preserves the slot's exact `target_id`,
`family_tuple_ordinal`, and `family_tuple` byte-for-byte; only the variant and
new commitment change. The request frame is exactly 40 bytes:
`0x46 0x50 0x45 0x47 || 0x01 || 0x00 || uint16_be(32) || nonce`; the response is
the same frame with message type byte `0x01` and the identical nonce. A wrong
magic/version/type/length, partial frame, changed nonce, any trailing byte before
peer close, or failure to close within the target deadline is failure. The
commitment is exactly
`SHA-256("FlowProbe.Egress.NonceEcho.Commit.v1\0" || preparation_ticket_id ||
session_id || uint64_be(generation) || target_profile_digest ||
uint32_be(family_tuple_ordinal) || canonical_cbor(family_tuple) ||
helper_observation_nonce || nonce)`. The helper stores one sealed preactivation
commitment per target/tuple, in the specification order. Once the complete
attempt-bound phase context and exact runtime channel exist,
the helper creates a fresh 32-byte `delivery_id`, constructs and signs one
`NonceEchoDeliveryConsumptionRecordV1`, and atomically appends and fsyncs that
record to the ARCH-001 journal before the transient delivery frame leaves the
helper. The durable state is only `ConsumedBeforeWrite`; it does not claim that
zero, some, or all wire bytes were sent. The record and frame repeat the exact
final plan/proof specification, generation, target profile, commitment, phase
context, attempt ordinal, tuple ordinal/value, candidate binding, connection
epoch, selected child, runtime, channel, and delivery ID, and the frame names the record's
registered root digest. The record's authenticator is the exact
`PrivilegedHelper` authority for that plan and journal revision.

Before delivery, each raw preactivation nonce exists only in a bounded,
authenticated helper-memory table keyed by its preparation ticket, session,
generation, helper observation nonce, slot identity, target, and family tuple;
after plan sealing the entry also records the exact final plan/specification and
commitment. It is never persisted. An unvisited/skipped tuple, terminal or
cancelled result, expiry, runtime/channel loss, record-construction or fsync
failure, helper shutdown, and crash recovery all zeroize and permanently
invalidate every affected undelivered entry. Registering any terminal wrapper
or idempotent terminal result invalidates all remaining undelivered slots for
that plan. Because recovery cannot reconstruct the raw value, a helper crash
with an outstanding commitment fails that generation rather than regenerating
or redelivering a nonce under the old commitment.

`NonceEchoChallengeResultV1` repeats those attempt fields and additionally
names the first following accumulator. Tag 28/29's tag-37 result repeats the
same attempt tuple/candidate/epoch/child through its phase context. A tuple slot
may be delivered only once. Once its consumption record exists, that attempt
cannot `RetrySameCandidate` or `AdvanceNextCandidate`; success may continue only
to a different required tuple with that tuple's distinct sealed commitment.
An early attempt that terminates before delivery may advance while leaving the
same tuple slot unconsumed. Cross-attempt, cross-tuple, cross-candidate, or
cross-child challenge substitution is invalid.

Only after that fsync may the helper release the raw nonce once to the exact
runtime in the matching `NonceEchoOneUseDeliveryFrameV1`. A matching frame is
the only IPC in which a raw target nonce may appear. It is never journaled,
replayed, buffered into a generic message log, exposed to the Supervisor/
renderer, or retained by either endpoint after the first write attempt. If the
helper/runtime crashes after the durable record but before a provably complete
write, or if write progress/acknowledgement is ambiguous, the checkpoint fails;
the frame and nonce are never reconstructed or redelivered. Wrong plan/runtime/
channel/target/context/commitment/delivery binding, response-loss retry, or a
second delivery is refused. Both endpoints zeroize the raw nonce immediately
after that first write attempt.
The response digest is
`SHA-256("FlowProbe.Egress.NonceEcho.Result.v1\0" || commitment ||
response_frame)`; plan, journal, result, logs, and IPC retain only the commitment,
the signed consumption record, and `NonceEchoChallengeResultV1`, never the raw
target nonce. A passed result's `delivery_consumption_record_digest` names that
exact record. A failed/timed-out/cancelled result may omit it only when failure
occurred before the record was durably consumed and before any delivery frame or
raw-nonce byte existed; otherwise it is present and exact. In the preceding
sentence, “IPC retain” excludes only the transient
authenticated one-use frame for that exact phase context, target, commitment,
and delivery ID; no other IPC representation is permitted.
`Passed` requires exactly 40 sent/received bytes and the response digest present;
failure, timeout, or cancellation carries actual sent/received counts in
`0..=40` and no response digest.

Postactivation and every renewal use a different fresh unpredictable 32-byte
NonceEcho nonce generated only after that checkpoint's complete
`PhaseBoundProbeContextV1` and selected socket child exist. They do not reuse or reopen the plan-sealed
preactivation slot. Their commitment is exactly
`SHA-256("FlowProbe.Egress.NonceEcho.CheckpointCommit.v1\0" ||
prepared_plan_digest || uint64_be(generation) || target_profile_digest ||
canonical_cbor(PhaseBoundProbeContextV1) ||
uint32_be(attempt_ordinal) || uint32_be(family_tuple_ordinal) ||
canonical_cbor(family_tuple) || canonical_cbor(candidate_binding) ||
uint64_be(connection_binding_epoch) ||
selected_connector_socket_child_observation_digest || nonce)`. The helper performs one
authenticated `NonceEchoOneUseDeliveryFrameV1` delivery to the exact runtime,
using the same pre-delivery signed-record/fsync protocol and binding all
commitment inputs, including the exact child, `RuntimeInstanceId`, and already
authenticated runtime channel. A partial write, lost acknowledgement, response
loss, second delivery, different checkpoint context, or use in another child/
accumulator is refused, and both endpoints zeroize the nonce after the first
write attempt. The same
40-byte wire frame and response-digest domain apply. Every terminal
`PhaseBoundProbeChallengeResultV1`, not only `Passed`, binds the exact phase
context, connector child, first following helper/watchdog accumulator that
includes that child, and exact optional consumption record. The consumption
record field is absent for `TcpConnect`, mandatory for `NonceEchoPassed`, and
present for a non-passed NonceEcho exactly when durable consumption occurred.
Its absence on a non-passed result proves failure preceded both the record and
all raw-nonce/frame bytes; if present it equals the exact frame/record digest. A passed
NonceEcho additionally binds its commitment and
response digest; a passed TCP checkpoint binds the exact connected endpoint.
Failure, timeout, and cancellation byte counts are each in `0..=40` for
NonceEcho and exactly zero for TcpConnect; a result variant or nested
`challenge_kind` mismatch is invalid. `started_at <= completed_at < expires_at`
and the root's runtime instance/channel equal the child and active gate.
Across the three stream-challenge context variants, exactly one frame may exist for an exact
`(prepared_plan_digest, generation, target_profile_digest, phase_context,
attempt_ordinal, family_tuple, candidate_binding, connection_binding_epoch,
selected_child, commitment)` tuple. Each required family tuple/checkpoint has
its own fresh commitment and consumption key; none may be reused by another
attempt. `raw_nonce` is
exactly 32 bytes and must recompute the
variant's commitment; an unknown context, missing/extra context field, or raw
nonce in any other schema or channel is rejected.

The `Socks5UdpCanary` delivery context is separate from those stream-challenge
contexts and never produces a tag-27 or tag-37 root. After the plan is sealed,
the exact association has selected a literal relay, and the target-tunnel,
dedicated UDP-control, and UDP-relay children all exist, the helper generates a
fresh unpredictable 32-byte UDP nonce.
Its commitment is exactly
`SHA-256("FlowProbe.Egress.Socks5Udp.NonceEcho.Commit.v1\0" ||
prepared_plan_digest || uint64_be(generation) || proof_specification_digest ||
target_profile_digest || canonical_cbor(observation_context) ||
uint32_be(attempt_ordinal) || uint32_be(family_tuple_ordinal) ||
canonical_cbor(family_tuple) || canonical_cbor(candidate_binding) ||
uint64_be(target_tunnel_connection_binding_epoch) ||
target_tunnel_socket_child_observation_digest ||
uint64_be(udp_control_connection_binding_epoch) ||
udp_control_socket_child_observation_digest ||
udp_socket_child_observation_digest || relay_endpoint_digest ||
relay_endpoint_set_digest || canonical_cbor(destination) || nonce)`.
The destination is the deterministic target-profile/candidate projection used
by tag 50; the commitment contains no tag-50 or following-accumulator digest.
It is created after `PlanDigest`, is never inserted into the plan's
`nonce_commitments`, and therefore creates no plan/result cycle.

The helper then applies the same fresh delivery-ID, signed tag-48 append/fsync,
authenticated one-use frame, and raw-nonce zeroization protocol. The tag-48
record and delivery frame use the exact `Socks5UdpCanary` phase context and the
same sole target profile. The runtime may make at most one atomic UDP datagram
send for that commitment; zero bytes or the complete datagram are the only valid
send observations. Partial/ambiguous completion, retransmission, response-loss
retry, a second delivery, or reuse across stream/UDP, phase, target, attempt,
tuple, candidate, connection, control child, UDP child, relay, destination,
runtime, or channel fails the checkpoint and never regenerates the nonce. Here
"connection/control child" means both the target-tunnel and dedicated-control
epochs/children in their displayed commitment order; swapping A and B, using
another same-proxy child, or omitting either is invalid. A
crash, cancellation, timeout, association loss, delivery/fsync failure, or
terminal wrapper zeroizes and invalidates every affected undelivered UDP nonce.
The ordering is plan sealing, association/child selection, helper commitment,
tag-48 fsync, one-use delivery, one datagram attempt, terminal first-following
tag-34 census, and finally the signed tag-50 root; no later object feeds an
earlier digest.

Probe targets are explicit authorized profiles. By default, metadata-service,
wildcard, multicast, loopback, link-local, host-local, and ports outside
`80`, `443`, and `1024..=65535` are prohibited. A trusted administrator policy
or hermetic test receipt MAY explicitly allow one local/special-use class and
exact port. The policy broker verifies the normalized resolved candidates as
well as the configured name for `FollowLocalAddress`; a DNS rebinding cannot
escape the receipt. With a selection that uses `ProxyName`, FlowProbe cannot
observe the proxy's DNS result. Such a target therefore requires
`FollowProxyNameOpaque` and an exact administrator/user receipt that explicitly
authorizes the normalized name under `ProxyOpaque`; it cannot use the default
address-class policy or claim that metadata/private classes were excluded. The
receipt has the exact issuer/signature/replay rules above and its digest is
included in the helper `AuthorizationGrantDigest`. Renderer data,
URL text, a successful DNS lookup, or a copied digest cannot authorize a target.

There is no built-in mandatory public-cloud target. At least one target must be
capable of proving the requested selection in the current environment. A
missing target is `ProbeTargetRequired`/`InteractionRequired`.

### 10.2 Execution order and isolation

ARCH-001 `Preflighting` validates the proof specification, receipts, resolver
dependencies, candidate graph, and secret-free runtime template under the non-
mutating preparation ticket. It starts no new session-scoped Network Runtime,
Capture Core, probe, or data-plane service; already-running helper, broker, and
discovery components may perform only their typed preflight work. It does not
claim the actual path proof has run. The candidate plan binds the proof
specification and expected observation predicate, never a future result.

After the helper seals the plan and returns `Prepared`, ARCH-001 starts the exact
independent Network Runtime inert through its pre-sealed external permit. The
runtime-config validation/load, protected control handshake, package/build,
`RuntimeInstanceId`, and executor identity must all match the plan. Only then,
while still `Applying`, the same long-lived runtime executes the actual selected
path proof as its first network operation. No FlowProbe TUN, route, DNS,
firewall, trust, endpoint-bypass, policy-route, actor-identity policy, or other
shared OS network mutation may have occurred. The bounded proof result must be
authenticated, independently checked, and durably recorded before the first
privileged network mutation intent. Failure stops the runtime, removes the exact
private artifact, and fences the plan through ARCH-001 `RollingBack`; only a
durably verified runtime/artifact absence may reach `Inactive`, otherwise the
result is `RecoveryRequired`.

Creating runtime sockets and applying an accepted unprivileged per-socket bind
is not shared OS mutation. A mark, protect call, route, rule, or binding that
requires a new privileged resource cannot be improvised under the preparation
ticket; a tuple that cannot prove the future-safe path without such a mutation
is `Unsupported`. The proof must establish a preventive socket mechanism whose
behavior remains exclusionary after the later FlowProbe TUN/steering appears;
success merely because that route is not installed yet is invalid.

For every proof connection the exact runtime must:

1. use the selected protocol implementation and exact safe selection digest;
2. resolve only through the sealed resolver dependency;
3. apply the baseline-anchor interface binding, owned existing protect path, or
   equivalent per-socket mechanism before connect;
4. query the route/interface decision and prove it excludes the pending
   FlowProbe TUN and all pending FlowProbe routes;
5. perform the tag-specific proxy/TLS/authentication handshake if applicable;
6. perform the target challenge within bounds; and
7. close every preactivation proof connection and zeroize transient challenge/
   transcript state. For `RequireAssociate`, this includes both the TCP control
   connection and UDP child; the attempt's first-following accumulator/census
   must retain their creation-chain history while proving both absent from the
   current provenance and OS set before the one-way phase transition. Runtime
   proxy credentials remain only under the sealed runtime credential lifecycle.

No pending TUN or steering resource may exist at this point. The sealed socket
mechanism, route predicate, and planned exclusion graph must nevertheless prove
that adding the exact later capture resources cannot redirect this socket. A
proof that relies on ordinary route luck or on running before a recursive route
exists is invalid.

Proxy-endpoint DNS, destination DNS, TLS revocation/status traffic, SOCKS5 UDP
relay traffic, and all challenge connections are themselves subject to the
same explicit bypass requirement. No proof may use captured application
requests, cookies, authorization headers, request bodies, or recorded traffic.

### 10.3 Result

```text
ExternalObservationAuthenticatorV1 = {
  header,
  signature,
}

AuthenticatorHeaderV1 = {
  signer_role,
  signer_identity: ObservationSignerIdentityV1,
  public_key_identity_digest,
  authority_binding,
  algorithm = Ed25519,
}

ObservationSignerIdentityV1 =
  | ExternalExecutorIdentity {
      runtime_or_component_instance_id,
    }
  | PlanComponentIdentity {
      component_instance_id,
    }
  | HelperIdentity {
      helper_installation_id,
    }
  | WatchdogIdentity {
      watchdog_identity,
    }
  | ReleaseVerifierIdentity {
      release_verifier_identity,
    }

ObservationSignerRole =
  | NetworkRuntime
  | RuntimeAdapter
  | CaptureCore
  | SocketFactoryExecutor
  | PlatformDiscoveryBackend
  | TrustMaterialBroker
  | PrivilegedHelper
  | WatchdogOrReconciler
  | ReleaseVerifier

Arch001JournalTipV1 = {
  journal_head_digest_at_result: 32 bytes,
  state_revision_at_result: u64,
}

ObservationAuthorityBindingV1 =
  | ExternalExecutorGate {
      prepared_plan_digest,
      permit_id,
      runtime_or_component_instance_id,
      gate_channel_binding_digest,
    }
  | PreplanDiscoveryAuthenticatedChannel {
      preparation_ticket_id,
      session_id,
      generation,
      helper_assigned_observation_nonce,
      boot_epoch,
      suspend_epoch,
      component_instance_id,
      channel_binding_digest,
    }
  | PlanComponentAuthenticatedChannel {
      prepared_plan_digest,
      generation,
      component_instance_id,
      channel_binding_digest,
    }
  | HelperAuthority {
      helper_installation_id,
      boot_epoch,
      prepared_plan_digest,
      parent_journal_tip: Arch001JournalTipV1,
    }
  | WatchdogFenceDomain {
      watchdog_identity,
      boot_epoch,
      suspend_epoch,
      prepared_plan_digest,
      generation,
      activation_lease_id,
      lease_epoch,
      fence_token_digest,
      channel_binding_digest,
    }
  | ReleaseEvidenceAuthority {
      release_verifier_identity,
      trusted_release_keyset_revision_sha256,
    }

EgressPathProofResultV1 = {
  prepared_plan_digest,
  proof_specification_digest,
  helper_assigned_observation_nonce,
  generation,
  controller_id,
  runtime_instance_id,
  probe_actor_id,
  probe_factory_policy_id,
  runtime_executor_identity_digest,
  runtime_gate_channel_binding_digest,
  runtime_package_and_build_digest,
  runtime_config_template_digest,
  egress_selection_safe_digest,
  selected_tag,
  selected_network_scope,
  target_profile_digest,
  evidence: EgressPathProofEvidenceV1,
  baseline_anchor_digest,
  actor_network_isolation_readback_digests,
  socket_factory_policy_observation_digest,
  socket_observation_accumulator_digest,
  started_at,
  completed_at,
  expires_at,
  outcome: ProbeOutcome,
  authenticator,
}

EgressPathProofEvidenceV1 = ProtocolConnectionAttemptSequenceV1

ProtocolConnectionAttemptSequenceV1 =
  | AdmissionAborted {
      verification_sequence_id,
      terminal_accumulator_digest,
      abort_cause: ProtocolAdmissionAbortCauseV1,
    }
  | Executed {
      verification_sequence_id,
      sequence_admission_accumulator_digest,
      attempts: 1..=32 ProtocolConnectionAttemptV1,
      protocol_successful_attempt_ordinals: 0..=4 u8,
      attempt_boundary_terminal: ProtocolAttemptBoundaryTerminalV1,
      sequence_finalization_accumulator_digest,
    }

ProtocolAdmissionAbortCauseV1 =
  | CandidateAdmissionTerminal
  | PriorOrdinaryOperationTerminal
  | PostAdmissionPreAttemptTerminal {
      sequence_admission_accumulator_digest,
    }

ProtocolAttemptBoundaryTerminalV1 =
  | NotApplicable
  | FactoryOrCensusTerminalBeforeNextAttempt {
      after_attempt_ordinal: 1..=32,
    }

ProtocolConnectionAttemptV1 = {
  attempt_ordinal: 1..=32,
  family_tuple_ordinal: 1..=4,
  family_tuple: PathFamilyTupleV1,
  candidate_binding: ConnectionAttemptCandidateBindingV1,
  candidate_attempt_index = 1 | 2,
  terminal: ProtocolConnectionAttemptTerminalV1,
  continuation: AttemptContinuationV1,
}

AttemptContinuationV1 =
  | Terminal
  | RetrySameCandidate
  | AdvanceNextCandidate
  | AdvanceNextFamilyTuple

ConnectionAttemptCandidateBindingV1 =
  | DirectTarget {
      candidate_ordinal: 1..=8,
      target_endpoint_digest,
      connector_socket_family = Ipv4 | Ipv6,
    }
  | ExternalProxy {
      proxy_candidate_ordinal: 1..=8,
      selected_proxy_endpoint_digest,
      endpoint_locality = HostLocal | Remote,
      connector_socket_family = Ipv4 | Ipv6,
      destination: ExternalDestinationCandidateBindingV1,
    }

ExternalDestinationCandidateBindingV1 =
  | ProxyOpaque
  | LocalAddress {
      target_candidate_ordinal: 1..=8,
      target_endpoint_digest,
      destination_family = Ipv4 | Ipv6,
    }

ProtocolConnectionAttemptTerminalV1 =
  | BeforeConnector {
      terminal_phase: ProtocolPhaseV1,
      protocol_phase_outcomes: 1..=32 ProtocolPhaseOutcomeV1,
      proxy_tls_evidence: ProxyTlsEvidenceReferenceV1,
      socks5_udp_association_evidence:
        Socks5UdpAssociationEvidenceV1,
      following_socket_observation_accumulator_digest,
    }
  | ConnectorTerminal {
      connection_binding_epoch,
      destination_family_observation,
      protocol_phase_outcomes: 1..=32 ProtocolPhaseOutcomeV1,
      proxy_tls_evidence: ProxyTlsEvidenceReferenceV1,
      socks5_udp_association_evidence:
        Socks5UdpAssociationEvidenceV1,
      connector_socket_child_observation_digest,
      challenge: ProtocolAttemptChallengeEvidenceV1,
      following_socket_observation_accumulator_digest,
    }

ProtocolAttemptChallengeEvidenceV1 =
  | NoCompletedResult {
      challenge_kind = TcpConnect | NonceEcho,
    }
  | PreactivationCompleted {
      challenge_kind = TcpConnect | NonceEcho,
      challenge_result: ChallengeResultReferenceV1,
    }
  | PhaseBoundCompleted {
      challenge_kind = TcpConnect | NonceEcho,
      phase_bound_probe_result_digest,
    }

Every `connector_socket_child_observation_digest` is
`Digest(SocketPolicyChildObservationV1)` (tag 31), every
`following_socket_observation_accumulator_digest` is
`Digest(SocketObservationAccumulatorV1)` (tag 34), and every
`phase_bound_probe_result_digest` is
`Digest(PhaseBoundProbeChallengeResultV1)` (tag 37). These names do not create
generic digest domains. `terminal_accumulator_digest`,
`sequence_admission_accumulator_digest`, and
`sequence_finalization_accumulator_digest` are likewise exact tag-34 root
references. `SocketVerificationAdmissionBindingV1::Ordinary.
most_recent_open_accumulator_digest` and
`VerificationAdmissionPriorOpenStateV1::OpenAccumulator.
socket_observation_accumulator_digest` are also exact tag-34 root references;
neither field accepts a private factory-state hash or tag-15 observation.
Every `FactoryAdmissionReleaseBatchMemberV1.release_accumulator_digest` is the
exact staged `Digest(SocketObservationAccumulatorV1)` (tag 34), and every
`SocketVerificationAdmissionBindingV1::Ordinary.
release_batch_completion_digest` is
`Digest(FactoryAdmissionReleaseBatchCompletionV1)` (tag 56).

ProbeOutcome =
  | Passed
  | Failed { error_code: EgressOuterFailureCodeV1 }
  | TimedOut { bounded_phase: ProtocolPhaseV1 }
  | Cancelled

TypedNonChallengeFailureCodeV1 =
  | SocketFactoryInvariantUnproven
  | LoopDetectedOrUnproven
  | ExclusionReadBackFailed
  | OrdinaryConnectivityFailed

TargetChallengeFailureCodeV1 = ProbeFailed

ProxyTlsAuthenticateFailureCodeV1 =
  | ProxyTlsFailed
  | ProxyTrustSnapshotChanged
  | RuntimeArtifactContainmentFailed

ProxyTlsVerifyFailureCodeV1 =
  | ProxyTlsIdentityMismatch
  | ProxyTlsTrustFailed
  | ProxyTlsRevocationUnavailable
  | ProxyTlsAlpnMismatch
  | ProxyTlsPolicyViolation

ProxyTlsFailureCodeV1 =
  ProxyTlsAuthenticateFailureCodeV1 | ProxyTlsVerifyFailureCodeV1

Socks5UdpFailureCodeV1 =
  | Socks5UdpAssociateFailed
  | Socks5UdpCanaryFailed
  | Socks5RelayDomainUnsupported
  | Socks5RelayInvalid
  | Socks5FragmentationUnsupported

ProtocolFailureCodeV1 =
  | ProxyEndpointResolutionFailed
  | DestinationResolutionFailed
  | ExclusionMechanismUnavailable
  | BaselineAnchorChanged
  | InterfaceOrRouteChanged
  | ConnectionRefused
  | NetworkUnreachable
  | HostUnreachable
  | DestinationConnectFailed
  | ProxyConnectFailed
  | ConnectedLocalPeerUnproven
  | RuntimeCredentialDeliveryUnavailable
  | ProxyAuthenticationFailed
  | ProxyResponseMalformed
  | ProxyResponseTooLarge
  | ProxyTlsFailed
  | ProxyTlsIdentityMismatch
  | ProxyTlsTrustFailed
  | ProxyTlsRevocationUnavailable
  | ProxyTlsAlpnMismatch
  | ProxyTlsPolicyViolation
  | ProxyTrustSnapshotChanged
  | RuntimeArtifactContainmentFailed
  | Socks5MethodUnsupported
  | Socks5ReplyFailed
  | Socks5UdpAssociateFailed
  | Socks5UdpCanaryFailed
  | Socks5RelayDomainUnsupported
  | Socks5RelayInvalid
  | Socks5FragmentationUnsupported
  | ProbeFailed

EgressOuterFailureCodeV1 =
  ProtocolFailureCodeV1 | TypedNonChallengeFailureCodeV1

Every member of these code unions is the identically named member of the closed
section 16 `EgressErrorCode` domain; none is a second producer-defined error
namespace. `TypedNonChallengeFailureCodeV1` is disjoint from
`ProtocolFailureCodeV1`, `TargetChallengeFailureCodeV1`, both disjoint TLS
phase-specific failure unions, their aggregate `ProxyTlsFailureCodeV1`, and
`Socks5UdpFailureCodeV1`. The four typed non-
challenge codes arise only from the shared outer projection. `TimedOut` and
`Cancelled` arise only as their dedicated outcome variants and are not legal in
any `Failed.error_code` field. `TargetChallengeFailureCodeV1` is intentionally
a singleton: every challenge operation that reaches a deterministic `Failed`
terminal uses `ProbeFailed`; deadline and cancellation terminals use their
dedicated variants. `ProbePathUnproven` is not a protocol, challenge-result, or
`ProbeOutcome` failed code.

DestinationFamilyObservation =
  | LocalIpv4
  | LocalIpv6
  | ProxyOpaque

ProtocolConnectionRoleV1 =
  | DirectTarget
  | TargetTunnel
  | Socks5UdpAssociationControl

ProtocolPhaseV1 =
  | ResolveIfRequired
  | BindOrProtectSocket
  | ObserveRoute {
      connection_role: ProtocolConnectionRoleV1,
    }
  | ConnectDestination
  | Challenge
  | ResolveProxyEndpoint
  | BindOrProtectProxySocket {
      connection_role = TargetTunnel | Socks5UdpAssociationControl,
    }
  | TcpConnectProxy {
      connection_role = TargetTunnel | Socks5UdpAssociationControl,
    }
  | VerifyConnectedLocalPeerIfHostLocal {
      connection_role = TargetTunnel | Socks5UdpAssociationControl,
    }
  | AuthenticateProxyTls
  | VerifyIdentityTrustPolicyAndAlpn
  | HttpConnectExchange {
      attempt_index = 1 | 2,
      step = SendConnectAuthority | ReadBoundedResponseHead |
             TunnelOrTypedFailure,
    }
  | AcceptBasic407Challenge
  | OfferExactMethods {
      connection_role = TargetTunnel | Socks5UdpAssociationControl,
    }
  | CompleteSelectedAuthentication {
      connection_role = TargetTunnel | Socks5UdpAssociationControl,
    }
  | SendCONNECTWithExactResolutionForm
  | ValidateReply
  | ChallengeThroughTunnel
  | Passed
  | EstablishedAuthenticatedSOCKS5Control
  | SendUDP_ASSOCIATEWithUnspecifiedSameFamily
  | ValidateRelayReply
  | ClassifyAndExcludeRelay
  | SendBoundedFRAG0Canary
  | ValidateRelaySourceAndCanary
  | AssociationReady

ProtocolPhaseOutcomeV1 = {
  phase: ProtocolPhaseV1,
  outcome = Passed | Failed { error_code: ProtocolFailureCodeV1 } | TimedOut | Cancelled |
            NotApplicable,
}

The phase-to-failed-code relation is closed:

- `ResolveIfRequired` permits only `DestinationResolutionFailed`, and
  `ResolveProxyEndpoint` only `ProxyEndpointResolutionFailed`;
- `BindOrProtectSocket` and `BindOrProtectProxySocket {
  connection_role=TargetTunnel }` permit only
  `ExclusionMechanismUnavailable`; the dedicated-control bind phase can be
  passed, timed out, or cancelled but cannot carry `Failed`, because a queue,
  creation, mechanism, or option-readback failure after role A passed is the
  outer factory-invariant abort. `BindOrProtectSocket` exists only for
  `DirectTarget`; every proxy bind phase carries its displayed role. An
  `ObserveRoute` comparison first checks the
  sealed tag-11 anchor: expiry or any
  change in its platform/interface identity, namespace or compartment,
  selected-family route presence/value, gateway set, interface epoch, or route
  epoch permits only `BaselineAnchorChanged`. Only while that anchor remains
  fresh and byte-identical in those closed semantic fields does a changed child
  socket interface, resulting route tuple, namespace or compartment, interface
  epoch, route epoch, or capture-interface/route selection permit
  `InterfaceOrRouteChanged`. If both predicates are observed in one sample,
  `BaselineAnchorChanged` is the sole code and the child comparison cannot
  override it;
- `ObserveRoute { connection_role=DirectTarget }` is used only by `Direct`,
  while `TargetTunnel` is the original external-proxy connector and
  `Socks5UdpAssociationControl` is the later independent control TCP connection.
  `ConnectDestination` permits `DestinationConnectFailed` or a member of
  `RecoverableConnectFailureCodeV1`; either role of `TcpConnectProxy` permits
  `ProxyConnectFailed` or that recoverable union;
- `VerifyConnectedLocalPeerIfHostLocal { connection_role=TargetTunnel }`
  permits only `ConnectedLocalPeerUnproven`. The dedicated-control occurrence
  is `Passed` or `NotApplicable`; any failed/unprovable B peer check occurs
  before release and uses only `UdpControlChildReleaseAborted`;
- `AuthenticateProxyTls` permits only
  `ProxyTlsAuthenticateFailureCodeV1`, while
  `VerifyIdentityTrustPolicyAndAlpn` permits only
  `ProxyTlsVerifyFailureCodeV1`; the two unions are disjoint and the finer
  tag-42 category-to-code rules remain mandatory;
- `HttpConnectExchange { step = SendConnectAuthority }` permits only
  `RuntimeCredentialDeliveryUnavailable` before the first credential-bearing
  byte or `ProxyConnectFailed` for a connection/write failure;
  `ReadBoundedResponseHead` permits only `ProxyResponseMalformed`,
  `ProxyResponseTooLarge`, or `ProxyConnectFailed`; and
  `TunnelOrTypedFailure` permits only `ProxyAuthenticationFailed` for a rejected
  configured authentication exchange or `ProxyConnectFailed` for every other
  complete non-2xx response. `AcceptBasic407Challenge` is only `Passed`; a
  `Failed` entry at that phase is invalid, and second-exchange credential
  delivery remains attributed to its `SendConnectAuthority` step;
- either role of `OfferExactMethods` permits `Socks5MethodUnsupported` for a rejected or
  malformed method exchange or `ProxyConnectFailed` for connection I/O;
  `CompleteSelectedAuthentication { connection_role=TargetTunnel }` permits
  `RuntimeCredentialDeliveryUnavailable` before the first credential byte,
  `ProxyAuthenticationFailed` for a rejected/malformed authentication exchange,
  or `ProxyConnectFailed` for connection I/O. The
  `Socks5UdpAssociationControl` occurrence permits only
  `ProxyAuthenticationFailed` or `ProxyConnectFailed`: it performs a second
  RFC 1929 wire exchange from the credential already held by the same exact
  authenticated runtime and cannot request or pretend to fail a second broker
  delivery;
  `SendCONNECTWithExactResolutionForm` permits only `ProxyConnectFailed` for
  connection/write I/O, while unsupported address/form selection is preflight-
  only and creates no protocol wrapper; and `ValidateReply` permits only
  `Socks5ReplyFailed`, which includes non-success REP, malformed/truncated reply,
  or connection EOF/read failure after the exact CONNECT request;
- `Challenge` and `ChallengeThroughTunnel` permit only the singleton
  `TargetChallengeFailureCodeV1::ProbeFailed`;
- after the six role-bearing dedicated-control phases have their exact
  `Passed`/conditional-`NotApplicable` outcomes, the six fallible UDP-association
  phases permit only the exact applicable
  member of `Socks5UdpFailureCodeV1`:
  `EstablishedAuthenticatedSOCKS5Control` and
  `SendUDP_ASSOCIATEWithUnspecifiedSameFamily` permit only
  `Socks5UdpAssociateFailed`; relay validation permits
  `Socks5UdpAssociateFailed`, `Socks5RelayDomainUnsupported`, or
  `Socks5RelayInvalid`; classification permits `Socks5UdpAssociateFailed` only
  for control/association loss and `Socks5RelayInvalid` only for its local
  family/address-class/scope/locality/route/exclusion decision;
  `SendBoundedFRAG0Canary` permits `Socks5UdpAssociateFailed` for control/
  association loss or `Socks5UdpCanaryFailed` for nonce preparation, delivery,
  or the atomic datagram-send failure; and
  relay-source/canary validation permits `Socks5UdpAssociateFailed`,
  `Socks5UdpCanaryFailed`, `Socks5RelayInvalid`, or
  `Socks5FragmentationUnsupported`.

`Passed` and `AssociationReady` cannot
carry `Failed`, `TimedOut`, `Cancelled`, or `NotApplicable`. A code outside its
phase row, any typed non-challenge code in a nested outcome, or `TimedOut`/
`Cancelled` encoded as a failed code invalidates the wrapper.

RecoverableConnectFailureCodeV1 =
  | ConnectionRefused
  | NetworkUnreachable
  | HostUnreachable

Every member is the identically named section 16 `EgressErrorCode` value.

ChallengeResultReferenceV1 =
  | TcpConnect { connected_endpoint_digest }
  | NonceEcho { nonce_echo_challenge_result_digest }

PhaseBoundProbeContextV1 =
  | Postactivation {
      helper_observation_nonce,
      capture_generation_marker_digest,
    }
  | Renewal {
      activation_lease_id,
      lease_epoch,
      renewal_challenge_nonce,
      fence_token_digest,
    }

PhaseBoundProbeChallengeResultV1 = {
  prepared_plan_digest,
  generation,
  proof_specification_digest,
  target_profile_digest,
  attempt_ordinal,
  family_tuple_ordinal,
  family_tuple: PathFamilyTupleV1,
  candidate_binding: ConnectionAttemptCandidateBindingV1,
  runtime_instance_id,
  runtime_gate_channel_binding_digest,
  connection_binding_epoch,
  phase_context,
  selected_proxy_endpoint_digest?,
  selected_connector_socket_child_observation_digest,
  socket_observation_accumulator_digest,
  nonce_delivery_consumption_record_digest?,
  challenge_kind = TcpConnect | NonceEcho,
  started_at,
  completed_at,
  expires_at,
  outcome: PhaseBoundProbeOutcomeV1,
  authenticator,
}

PhaseBoundProbeOutcomeV1 =
  | TcpConnectPassed {
      connected_endpoint_digest,
    }
  | NonceEchoPassed {
      commitment,
      response_frame_digest,
      bytes_sent = 40,
      bytes_received = 40,
    }
  | Failed {
      challenge_kind,
      bounded_phase,
      error_code: TargetChallengeFailureCodeV1,
      bytes_sent,
      bytes_received,
    }
  | TimedOut {
      challenge_kind,
      bounded_phase,
      bytes_sent,
      bytes_received,
    }
  | Cancelled {
      challenge_kind,
      bytes_sent,
      bytes_received,
    }
```

`ProtocolAttemptChallengeEvidenceV1::PreactivationCompleted.challenge_result`
must match its `challenge_kind`. A passed TCP result uses
`Digest(EndpointIdentityV1)` for the connected target endpoint. NonceEcho uses
`Digest(NonceEchoChallengeResultV1)`. `NoCompletedResult` carries no placeholder
result digest and its challenge kind is the exact sealed intended challenge. It
is mandatory when the attempt terminates strictly before entering
`Challenge`/`ChallengeThroughTunnel` for a `ConnectorTerminal`. A
`BeforeConnector` carries no challenge field. The only challenge-phase exception is a
failed/timed-out/cancelled preactivation `TcpConnect`, because tag 13 registers
no separate negative TCP challenge root; there the final challenge phase itself
is the terminal fact. A generic evidence hash or cross-variant digest is invalid.
Target TLS is not a v1 probe challenge: HTTPS-to-proxy TLS remains governed by
section 4.5, while an application target that needs a TLS challenge is
`UnsupportedPendingArchitecture/TargetTlsProbeContractUnavailable`.
`ChallengeResultReferenceV1` and `NonceEchoChallengeResultV1` are used only by
tag 13. Tags 28/29 use `PhaseBoundCompleted` exactly when the challenge produced
a terminal result; if the connector terminates before that point they use
`NoCompletedResult`. They never use `PreactivationCompleted` or reuse a tag-27
reference. A present signed `PhaseBoundProbeChallengeResultV1` carries the
closed TCP or NonceEcho outcome inline.

`EgressPathProofResultV1.egress_selection_safe_digest` is the exact tag-1
digest in its sealed proof specification and prepared plan. The referenced
`RuntimeConfigTemplateV1` repeats that digest, the same
`runtime_package_and_build_digest`, and the selection's exact `selected_tag`;
`selected_network_scope` equals the plan/proof-specification network scope.
Tag 0, a producer-local projection, a template for another selection, or any
tag/scope/digest disagreement invalidates the result before its outcome is
examined.

The result's `runtime_instance_id`, `probe_actor_id`, and
`probe_factory_policy_id` equal its proof specification byte-for-byte. Its
singular tag-15 policy observation is the installed observation of that exact
tag-14 factory and repeats the selected actor/component/runtime fields. Every
tag-31 child and every tag-34 admission, attempt, finalization, or terminal root
reachable from `evidence` belongs to that same factory ID and epoch, and every
child repeats the same actor ID. The tag-13 `NetworkRuntime` authenticator uses
the ARCH-001 `ExternalExecutorGate` and protected control identity of that same
actor/runtime: its authority's `runtime_or_component_instance_id` equals
`runtime_instance_id`, and its gate/channel binding equals the result's
`runtime_gate_channel_binding_digest`. A valid observation from
another runtime, actor, component, factory, or factory epoch cannot be
substituted even when its protocol bytes, target, and censuses are otherwise
valid.

`EgressPathProofEvidenceV1`, `CanaryProbeEvidenceV1`, and
`HealthProbeEvidenceV1` all use the same closed admission/attempt sequence. A
fresh nonzero 32-byte `verification_sequence_id` is allocated once and never
reused across context, outer root, lease, factory epoch, or generation. Before
any attempt or protocol byte, under the same factory creation/lifecycle atomic
domain sealed and read back by tags 14/15, every ordinary child operation,
ordinary local close, peer/OS close-bookkeeping transition, and sequence
admission competes for one monotonically assigned linearization ordinal. The
runtime drains an already-started ordinary operation. If an ordinary operation
or close linearized first, its committed child and/or close-only result is fully
recorded in a separate next chronological `NonEmpty` or `Empty` Open tag-34
checkpoint, as its exact delta requires, with every removal in the closure
ledger. That catch-up checkpoint preserves the Open transition counter and
authority and is fully authenticated before admission may start. A terminal
factory/census outcome in that checkpoint instead ends the request as
`AdmissionAborted { abort_cause=PriorOrdinaryOperationTerminal }`; no separate
admission root is fabricated. If admission linearized first, no ordinary child
may start and no close-bookkeeping removal may linearize until the admission
root is authenticated; a later close remains legal under Exclusive admission
and appears in the next chronological checkpoint.

The separate mandatory admission tag-34 root is always `Empty`, names the
latest chronological accumulator as `previous` when one exists, preserves the
child chain, current-open set, provenance, and lifecycle/new-socket counts, and
performs exactly one atomic admission-state transition. A successful entry
check changes authenticated `Open` to `Exclusive { stage=Running }`; a provable
capacity rejection changes it directly to `TerminalHeld` with
`terminal_context=CandidateCapacityRejected`, while an authenticated admission-
census failure uses `CandidateAdmissionObservationFailed`. Neither ordinal
permits a hidden in-flight child, an unledgered close, or a `NonEmpty` admission
root. `InitialFactoryObservation` exists only in tag 15/readback and as the
before-state of a first tag-34 transition. For the unique factory selected to
execute a verification sequence, its first tag-34 root must be that sequence's
admission root. It cannot first manufacture an Open tag-34 checkpoint, admit an
`Ordinary` child, or run an ordinary catch-up operation under initial authority.
A different applicable factory that executes no attempt may produce one first,
zero-child `Empty` Complete/equal checkpoint solely for the tag-28 all-factory
precommit set. That root has no previous accumulator, preserves
`Open { release_scope=VerificationOnly,
release_authority=InitialFactoryObservation }` and transition counter zero, and
authorizes neither an Ordinary child nor an admission catch-up shortcut.

The admission capacity request repeats the exact outer tag-13/28/29 observation
context, proof specification, target, plan/generation/lease, factory ID/epoch,
fresh ID, and enclosing overall deadline. Its entry open count equals the exact
tag-46 provenance and tag-44 set cardinality; its entry lease-new count equals
tag 46. The requested incremental open peak and requested total-new count are
the compiler's exact worst-case values for the complete sealed serial tree, and
the requested socket-sequence half-open interval starts at the current next
sequence, has that total-new length, and cannot wrap. Both admission censuses
are `Complete`, equal, counter-stable, and fully authenticated before this full
request can exist. The accepted reservation wraps that request only when the
open-count plus peak fits `maximum_open_sockets` and the lease-new count plus
total fits `maximum_new_sockets_per_lease_epoch`. A rejected request may exceed
one or both; when both exceed, `OpenSocketLimitExceeded` is the unique reason,
otherwise the one exceeded bound selects its matching reason. No accepted
reservation may contain an over-limit sum, and no reserved child may start
before its admission root is authenticated.

`AdmissionAborted` is the sole zero-attempt form. Its
`terminal_accumulator_digest` is one exact tag-34 root with a `TerminalFailed`
latch and matching irreversible `TerminalHeld` admission state. For
`CandidateAdmissionTerminal`, that root has
`terminal_context=CandidateCapacityRejected` with the exact over-limit capacity
request, or `CandidateAdmissionObservationFailed` with the exact pending
candidate and `SocketCensusFailed` reason but no claimed entry count, sequence
interval, or reservation. For `PriorOrdinaryOperationTerminal`, it is instead
the separate catch-up root above, has
`terminal_context=PendingSequenceNotAdmitted` naming the fresh ID, exact sequence
context, deadline, and prior Open state byte-for-byte, and carries the first
exact factory failure from the drained ordinary operation. An ordinary catch-up
census that cannot prove its actual state yields no valid outer wrapper rather
than using that branch. `PostAdmissionPreAttemptTerminal` is valid only after a
successful admission root and before attempt 1 begins; its cause names that
exact root, its terminal context is `ActiveSequence` with the byte-identical
accepted reservation, and its terminal root is the next chronological `Empty`
checkpoint. The three causes are not interchangeable and none may invent or
omit a request/reservation. They have no attempt, protocol phase, nonce,
traversal, or challenge evidence, use the terminal root as the outer top-level
factory accumulator, and project only `SocketFactoryInvariantUnproven`; the
canonical accumulator scan includes the named successful admission root before
the post-admission terminal root. Failure to construct, dual-sign, authenticate,
or register the required terminal root yields no outer wrapper. `Executed`
requires an authenticated nonterminal
admission root in `Exclusive { stage=Running }`, `attempts` contains `1..=32`
entries, and
`attempt_ordinal` is exactly the contiguous one-based list position.
`family_tuple_ordinal` and `family_tuple` equal the referenced proof
specification's tuple plan. Tag 13 is the only exploratory
sequence: within a tuple, candidate pairs are serial and canonical—Direct orders
target candidates, `ProxyOpaque` orders proxy candidates, and external
`LocalAddress` orders `(proxy_candidate_ordinal, target_candidate_ordinal)`
lexicographically. Each dimension tries at most two candidates for its tuple
family and never races.

A literal target is the exact tag-18 endpoint/tag-33 digest at target ordinal
1 and has no tag-4 root. A DNS target ordinal is its tag-18-referenced positive
tag-4 `ActivationProbeTarget` candidate position. Every proxy ordinal is the
selection's tag-4 `ProxyEndpoint` candidate position, including ordinal 1 for
`LiteralNoResolution`. `ProxyOpaque` carries no target candidate. The endpoint,
ordinal, scope, and family must agree byte-for-byte with the applicable source.

In tag 13, `candidate_attempt_index` starts at 1 for each candidate pair. Index 2
is present only when the sealed `retry_limit` is 1 and index 1 ended at
`ConnectDestination` or `TcpConnectProxy` with `TimedOut` or `Failed` carrying
one exact `RecoverableConnectFailureCodeV1`, where `TcpConnectProxy` has only
`connection_role=TargetTunnel`, before any
TLS, proxy-authentication, credential, SOCKS, or target-challenge byte. The two
entries are consecutive. No retry follows cancellation, a released protocol
byte, a delivered target nonce, or any later phase. Candidate advancement has
the same early-failure restriction and occurs only after the preceding pair's
last allowed attempt. Thus one sealed preactivation NonceEcho commitment is
never consumed on one candidate and replayed on another. These are connection
attempts; the independently indexed one-or-two HTTP CONNECT exchanges in
section 11.2 remain inside one connection attempt and never change
`candidate_attempt_index`.

Tags 28 and 29 are verification sequences, not a second endpoint-selection
algorithm. Each names the same passed tag-13 preactivation proof and visits a
non-empty contiguous prefix of success groups starting at group 1, with exactly
one attempt for each visited group. Every group before the last visited group is
fully successful; the last may succeed or terminate negatively, and no later
group then appears. Attempt `n` repeats the family tuple and candidate binding
from that group's tag-13 `protocol_successful_attempt_ordinals` entry and has
`candidate_attempt_index=1`; its attempt ordinal is the new checkpoint-local
ordinal, not the old tag-13 ordinal.
A changed/reordered candidate or tuple, candidate retry/fallback, or an attempt
for a skipped preference tuple invalidates the wrapper. Any pre-connector-release or
protocol failure terminates the current verification sequence; tag 28 denies
commit and tag 29 denies renewal and fences the old lease. A future plan field
that requests tolerated transient renewal failure cannot be enabled by the v1
compiler and selects
`UnsupportedPendingArchitecture/TransientHealthToleranceDispositionUnavailable`
before execution. Neither case retries or hot-switches to a different sealed
candidate inside that checkpoint. Thus tag 28/29 have at most four attempts,
and only a passed current group may proceed to the next required group.

While admission is `Exclusive { stage=Running }`, the factory may release only a tag-31 child
whose `Reserved` binding names this sequence ID, the authenticated admission
accumulator, its unchanged admission counter, the next contiguous reserved
release ordinal, and the exact primary/B/C role required by the enclosing
attempt. It consumes one reserved socket sequence and one lease-new slot; a
later early terminal may leave only an unused suffix of the reservation. That
suffix allocates and skips no sequence number: `next_socket_sequence` advances
only through the actually committed reserved prefix, and the authenticated
post-outer Open transition returns the unused suffix to the ordinary allocator.
An
`Ordinary` child is held before socket creation and cannot consume either
reserved capacity or a sequence number. Existing unrelated operational sockets
may continue payload I/O. Their local or peer/OS closes remain legal, but every
removal is serialized and appears in the next accumulator's authenticated
closure-transition list and exact dual census. No unrelated child creation may
appear between the admission root and sequence finalization root. An attempted
bypass, wrong ID/context/role/ordinal, noncontiguous reserved child, capacity
borrow after an operational close, or unaccounted removal terminally fails the
factory with no later protocol release.

Every attempt checkpoint before the final branch retains the same
`Exclusive { stage=Running }` reservation. Tag 13's final attempt checkpoint
also serves as its sequence-finalization accumulator. For tags 28/29, a final
attempt that is not protocol-successful performs sequence-wide cleanup before
its first-following checkpoint; that checkpoint changes Running to
`FinalizedHeld`, or to `TerminalHeld` for a factory/census failure, and is both
the finalization and top-level root. A clean protocol-successful final-attempt
checkpoint instead remains Running. After the exact traversal/tag-51/tag-52
outcome to be projected has frozen, tags 28/29 then produce one fresh `Empty`
finalization accumulator. For `RequireAssociate`, that operation controlled-
closes every retained verification B+C pair on positive and every structurally
valid negative outer branch; for other selections it creates no socket and
closes no verification child. Its clean root changes the stage to
`FinalizedHeld`; a factory/close/bookkeeping failure uses an actual-state
`TerminalHeld` root, while an authenticated census failure uses
`TerminalHeld`/`SocketCensusFailed` without claiming a complete residual set.
A factory terminal between two attempts similarly creates the next `Empty`
finalization root without fabricating another attempt. A tag-28 traversal
negative or tag-28/tag-29 tag-51/tag-52 `Failed`/`TimedOut` result is published
only after the applicable cleanup; cleanup failure retains higher
`SocketFactoryInvariantUnproven` priority.

The probe factory's admission remains closed through outer signing, its
publication ordinal, the all-factory terminal-event drain, and publication of
the exact tag-13, tag-28, or tag-29 root. Three acyclic outer-result release
modes exist:

1. A tag-13 `Passed` outer root authorizes one immediate `Empty` tag-34
   transition of its clean `Exclusive { stage=FinalizedHeld }` probe factory to
   `Open { release_scope=VerificationOnly,
   release_authority=PreactivationProofPassed }`; proof acceptance waits for
   that root, and it can authorize only the next verification admission.
2. A tag-28 `Passed` outer root contains the canonical all-applicable-factory
   precommit checkpoint lists defined in section 14.2 and is first consumed by
   the existing ARCH-001 commit point. Only after the exact
   `ActivationCommitReceiptV1` is durable and the ResumeBarrier is
   `OpenForExactGeneration` does one bounded admission-release batch cover every
   listed factory. At the probe-factory index, an `Empty` tag-34 root transitions
   its outer-listed `FinalizedHeld` root directly to
   `Open { release_scope=OrdinaryAndVerification,
   release_authority=PostactivationCommitAccepted }`. At every other index, an
   `Empty` root performs the sole permitted scope-upgrade handoff from the
   outer-listed `Open { release_scope=VerificationOnly }` checkpoint to that
   same commit-bound Ordinary-and-verification authority.
3. A tag-29 `Healthy` outer root is first consumed by the existing
   `RenewActivationLease` operation. After its exact idempotent result is durably
   fsynced, the same bounded batch covers every factory in the tag-29 lists. The
   probe index transitions `FinalizedHeld` directly to
   `Open { release_scope=OrdinaryAndVerification,
   release_authority=RenewalLeaseAccepted }`; every other index performs the sole
   permitted same-scope handoff from its outer-listed current
   `Open { release_scope=OrdinaryAndVerification }` root to the new receipt-bound
   authority. `LeaseRenewed` preserves the same activation lease, lease epoch,
   and fence, so this handoff does not reset
   `new_socket_count_in_lease_epoch`; it only replaces the continuous expiry,
   challenge/result, journal-head, and current admission authority.

For tags 28/29, `ordered_factory_policy_ids` is the exact non-empty ascending
factory-ID projection of the outer root's paired policy/accumulator lists,
`factory_release_index` is the current factory's one-based position, and every
root in the batch repeats the same fresh nonzero `release_batch_id`, list, outer
ordinal, disposition ordinal, and receipt. Each
root uses `Empty`, names that factory's outer-listed top-level accumulator as
`previous`, preserves its chain, includes every intervening close-only local
lifecycle transition that linearized before the batch lock, and increments its
admission counter exactly once. Such a completed close is durable only in the
factory-local acceptance/closure ledger, counter, and provenance state until
this member first dual-authenticates it; it appends no independent tag-34 or
helper-journal record and does not advance `disposition_tip`. A close requiring
an earlier checkpoint/helper append, or whose local bookkeeping is incomplete,
aborts the batch. Before any member snapshot, the coordinator acquires every
listed factory's combined creation/lifecycle/close-bookkeeping gate in factory-
ID order and holds the entire set through completion. An external peer/OS close
or terminal event whose acceptance-event ordinal wins after acquisition but
before the final completion reservation aborts the batch; no already signed
member may hide it or be resampled selectively. An event first ordered after a
successfully committed reservation is instead the next health/rollback event.
The tag-34 member roots are fully constructed, dual-signed, and staged in factory-ID order,
then the helper-owned all-or-none observation-journal transaction in section 10
publishes all roots and its current-release state-index update together with the
registered tag-56 `FactoryAdmissionReleaseBatchCompletionV1` as the last record.
There is no committed, authoritative, or effective partial prefix. Pre-fsync or
torn tail bytes may exist physically, but the unchanged protected index keeps
them uncommitted; recovery ignores, quarantines, or truncates that tail and never
interprets it as a member transition.

The `Open` value inside each staged member's tag-46 census is a conditional
post-state identified by its `PostactivationCommitAccepted` or
`RenewalLeaseAccepted` authority, not a claim that the local guard has already
released that factory. While staged, the previously committed accumulator and
transition counter remain the factory's historical current state, but the
selected `ReleasePending` extension makes that state non-authorizing. Every
creation gate remains held, the candidate member is not a current accumulator
or committed chain node, and no child can name either old or candidate release
authority. A failed or discarded staging attempt consumes no transition counter
and requires no Open-to-prior rollback. Every applicable tag-14 guard must obtain
the same exact `FactoryAdmissionReleaseCurrentIndexV1` value and referenced
tag-56 vector only through a future registered ARCH-001 typed authenticated
release-proof read; the existing helper state-index writer remains the sole
writer. That proof read must be linearizable for every Ordinary admission,
return the selected composite epoch/head/revision/checksum plus the bounded
authenticated member/tag-56 range, provide an idempotent query/reconnect path to
the Supervisor, and reveal neither writable storage nor unrelated journal
records. It may not be a direct helper-journal/index read, copied authoritative
cache, sidecar, second selector, or arbitrary `Status` extension. The accepted
ARCH-001 protocol currently registers no such request, result schema, or replay
rule: its closed `StatusSnapshot` exposes only the common safe summary and tip.
Therefore every v1 profile remains
`UnsupportedPendingArchitecture/AdmissionReleaseProofReadUnavailable` until a
separate ARCH-001 architecture task registers that primitive. The following
state/index rules are the mandatory target contract for that future extension,
not permission for an ARCH-002 implementation to bypass the helper boundary.
The journal transaction's
single commit point both makes the complete vector authoritative and atomically
changes that shared index from the exact `ReleasePending` value to a `Committed`
value naming tag 56. At that point, and
only at that point, all listed conditional post-states and their increments
become the authoritative current admission states simultaneously. Current does
not yet mean locally admissible: the post-ack clock check, ordered health/fence
handoff, and future registered proof read must all pass before any gate releases
or product/child acceptance occurs. A guard may not
cache, mirror, install, acknowledge, or activate its member independently;
before every Ordinary admission the future registered proof read must validate
the complete current tag-56 vector containing its member. Thus every
guard observes either the prior index/states or the complete new index/states,
never a per-factory prefix. A native or cooperative factory unable to enforce
this shared-index rule is `UnsupportedPendingArchitecture`, not eligible for the
batch.

The completion value's ordered members are one-for-one with the binding's
factory list; every member names the exact staged tag-34 root and its exact
release ordinal. Its variant, outer digest/ordinal, receipt, batch ID, and member
list equal every member authority; its completion ordinal is allocated only by
the later atomic journal transaction. `release_batch_id` is the exact fresh
nonzero 32-byte value allocated once by the selected `ReleasePending`
disposition transition; no member or retry allocates it. Member IDs are unique
and ascending, indices are exact one-based
positions, and every serialization ordinal is a nonzero nonwrapping `u64`.
The root's plan/generation/lease/epoch/fence equal its outer, receipt, every
member root, and both signer authorities. The receipt's journal head/revision is
the durable parent of the transaction's first member; each later member and tag
56 follows the transaction-local parent chain exactly. `completed_at` is no
earlier than every member observation and is strictly before `expires_at`;
`expires_at` is no later than the outer root, every required tag-50/tag-51/tag-
52 observation and staged tag-34 member, receipt continuous lease,
ResumeBarrier, and parent-operation deadlines. `authenticators` contains
exactly `PrivilegedHelper` then `WatchdogOrReconciler`; both sign the same
authenticator-omitted registered tag-56 root through the common object/signature
domains in sections 2 and 10. This is an ARCH-002 atomic observation-journal
append and current-release-index update for the already installed local release
guard, not a new ARCH-001 framed request, response variant, lifecycle phase, or
second lease. It is nevertheless an internal state-changing helper transaction
inside the existing ARCH-001 mutation/CAS domain: it consumes the receipt's
exact current journal head/state revision and advances that same authoritative
head/revision as defined below. The exact
`FactoryAdmissionReleaseCurrentIndexV1::Committed.
release_batch_completion_digest` is
`Digest(FactoryAdmissionReleaseBatchCompletionV1)` (tag 56); the complete
Committed value is published atomically with the validated vector and has no
producer-selected projection. The one existing ARCH-001 protected state index,
rather than incidental pre-commit bytes or an ARCH-002 sidecar, is the sole
recovery commit marker.

`FactoryAdmissionReleaseCurrentIndexV1` is a closed extension field inside that
single ARCH-001 protected index; despite its type name it is not an independent
file, slot set, checksum authority, or selector. `Unset { index_epoch=0 }` is
legal only in a pristine installation before any egress-bearing `PreparePlan`
becomes durable and can never appear in tag 15. The future registered extension
of the existing ARCH-001 `PreparePlan` state transition—not a new request—must
make the helper hold the mutation lock, consume the exact current head/revision,
verify the complete prepared factory set, and atomically write `BoundClosed`
into the same composite index.
That transition is legal only from pristine `Unset` or a prior
`GenerationClosed` whose core session state proves the older generation fully
inactive/fenced and its actors stopped or cooperative leases revoked. It sets
`index_epoch` to the prior value plus one without wrap, binds the new exact plan,
generation, ascending complete factory-ID list, and
`bind_parent_journal_tip`, and is the value every tag-15 guard readback repeats.
A prior `Committed` or `ReleasePending` value cannot transition directly to a
new generation.

`BoundClosed` is non-authorizing: tag-13 VerificationOnly release leaves the
extension unchanged. The future registered extension of the existing ARCH-001
transaction that durably accepts a tag-28 `CommitActivation` result must
atomically change the exact same-generation
`BoundClosed` to `ReleasePending { prior_release=NeverCommitted,
pending_disposition=Postactivation }`. The corresponding extension of the
transaction that durably accepts a tag-29 `LeaseRenewed` result must atomically
change same-plan/generation `Committed`
to `ReleasePending { prior_release=Committed { ... },
pending_disposition=Renewal }`, where that prior digest is the exact currently
committed tag-56 root and its paired `batch_tip` is byte-identical to the CAS-
predecessor `Committed.batch_tip`; the predecessor's batch ID, plan, generation,
factory set, and index epoch must also be the exact selected values. Both
transitions preserve the factory-ID set, increment `index_epoch` once, allocate
one fresh nonzero 32-byte `release_batch_id`, embed the byte-identical outer
digest, event ordinals, and receipt later repeated by every batch member and tag
56, and set `disposition_tip` to the exact protected outer head/revision produced
by that accepted result. For Postactivation the tip equals
`{ activation_commit_receipt.commit_journal_head_digest,
activation_commit_receipt.committed_state_revision }`; for Renewal it equals
`{ lease_renewed_receipt.journal_head_digest_at_result,
lease_renewed_receipt.state_revision_at_result }` in
`Arch001JournalTipV1` field order. They are part of the existing commit/renewal
composite-index transaction, not a new request or provisional rewrite of its
idempotent result.

That disposition transaction also samples `disposition_observed_at` and freezes
`release_deadline` in the helper's accepted suspend-aware monotonic clock
domain. The sample is taken under the same mutation lock after the candidate
receipt record and stored response bytes—including their final result head/
revision—are completely constructed and fixed, but before the composite selector
is committed. Candidate record/response bytes may already be physically fsynced
but are not yet an accepted durable result. That one selector simultaneously
makes the receipt/result authoritative and selects the matching
`ReleasePending`; there is no accepted commit/renewal result paired with the old
`BoundClosed` or `Committed` extension. The deadline is strictly after that
sample and no later than the minimum of the outer tag-28/
tag-29 root, every required tag-50/tag-51/tag-52 root, every outer-listed
accumulator, the receipt continuous expiry, current ResumeBarrier/lease
deadline, and parent operation deadline. The later tag-56 `expires_at` is no
later than this exact deadline. Neither replay nor recovery may extend the
deadline, replace the batch ID, or refresh any pending field.

`ReleasePending` is non-authorizing and is the only legal CAS base for a tag-28/
tag-29 release batch. Its selected core tip/revision must equal
`disposition_tip`; no unrelated helper-journal record or old release authority
may intervene. Every candidate member and tag 56 repeats the exact pending batch
ID, disposition variant, outer digest/ordinals, receipt, plan/generation, and
factory list. The successful all-factory/tag-56 selector transaction changes
that exact value to same-plan/generation `Committed`, preserves the factory set,
increments `index_epoch` once, and replaces any prior release with the new exact
tag-56 root. `disposition_observed_at <= completed_at < expires_at <=
release_deadline`. Any crash or batch failure before that selector leaves the
selected pending value non-authorizing and unresumable, ignores/quarantines its
candidate tail, and enters the existing fence/recovery path rather than
allocating a new batch, restoring, or extending the old release.

Stop, preparation rollback, fence/recovery, or generation retirement changes
`BoundClosed`, `ReleasePending`, or `Committed` to `GenerationClosed` in the
same composite-index transaction as the existing core transition that proves
the barrier closed and every owned factory stopped or cooperative lease revoked.
`prior_release` is `NeverCommitted` from `BoundClosed` or postactivation
`ReleasePending`; from renewal `ReleasePending` it is that state's exact prior
tag-56 root, and from `Committed` it is the exact last
`Digest(FactoryAdmissionReleaseBatchCompletionV1)` tag-56 root. The reason and
`close_parent_journal_tip` must match that core transition. No `BoundClosed`,
`ReleasePending`, or `GenerationClosed` value authorizes Ordinary creation.
Until the accepted
ARCH-001 normal-stop finalization protocol can perform the stated atomic close,
normal-stop reuse remains the existing
`UnsupportedPendingArchitecture/NormalStopFinalizationProtocolUnavailable`.
An exact replay of an accepted ARCH-001 request returns only that request's
stored response. It never rewrites or reselects an older extension value: the
authoritative composite index remains the exact current `ReleasePending`,
`Committed`, or `GenerationClosed` descendant, and no replay repeats, resets, or
reuses an index epoch.

Every non-`Unset` variant carries a nonzero nonwrapping `index_epoch` exactly one
greater than the preceding authoritative extension value. Its
`index_checksum_sha256` is exactly
`SHA-256("FlowProbe.Egress.FactoryAdmissionReleaseCurrentIndex.v1\0" ||
canonical_cbor(variant_tag || all fields preceding index_checksum_sha256))` and
proves only extension-field integrity. For `Committed`, `release_batch_id` and
`release_batch_completion_digest` equal tag 56,
`batch_tip` is the head/revision produced by that last record,
and `committed_record_count` is the ordered-member count plus one. The existing
ARCH-001 outer index checksum covers all of its mandatory `InstallationEpoch`,
generation-high-water, record-sequence, previous-root, current-root,
authenticated state-revision, and this complete extension value.

The helper uses the existing protected index's one copy-on-write/double-slot
primitive and one selector. It writes and fsyncs the candidate journal vector
and an inactive **composite** index slot containing all ARCH-001 fields plus this
extension, validates both checksum layers and the chain, then atomically writes
and durably flushes that sole selector as a second persistence boundary and the
batch commit point. At that point the outer record sequence and state revision
have advanced by `committed_record_count`, the outer previous/current roots are
the last member/tag-56 records, and the extension's `batch_tip` equals
the outer tag-56 tip. Installation epoch and generation high-water obey the
unchanged ARCH-001 rules. Later legal same-authority socket-observation records
may advance the outer tip/revision while preserving this tag-56 extension as an
authenticated ancestor. The target transaction return, product acceptance, and
guard release require the selector's durable acknowledgement, the post-ack
freshness check, the ordered health/fence handoff, and the registered proof read;
selector acknowledgement alone is insufficient.
The composite index is authoritative only when its selected slot, both checksum
layers, all core/extension equality fields, and exact journal range decode to
every ordered member followed by the valid dual-signed tag-56 tip. A torn vector
or slot before selector commit retains the selected `ReleasePending` value. A
selector ambiguity, core/extension head or revision disagreement at initial
batch commit, broken later ancestry/revision chain, wrong epoch/sequence/count/
state transition, missing extension, or extension pointing to an incomplete/
invalid vector authorizes no member and enters fenced recovery; recovery accepts
only one checksum-valid whole pending value or one checksum-valid whole committed
value, never a mixed or guessed state.
Product `Active` or healthy acceptance and every Ordinary child wait for this
complete root. The future ARCH-001 release-proof read must give the Supervisor
and each guard the exact same authenticated selected value and bounded record
proof; the Supervisor additionally cross-checks the unchanged existing
`Status` common head/revision, safe phase, plan, generation, lease, fence, and
authority summary. A later tip is acceptable only when that typed proof shows a
same-authority chronological socket-observation suffix from tag 56 with no
fence/recovery transition. A lost local completion notification or Supervisor
restart uses the future idempotent proof query and ordinary `Status`; it never
re-executes the batch. The existing `Status` alone, a locally retained candidate,
or a direct index/journal read is insufficient. Until the proof operation is
registered, product `Active`, healthy-renewal acceptance, and every Ordinary
child remain unsupported and denied. Each future Ordinary tag-31 child names its
exact tag-56 digest and the guard independently proves the same selected-index
and ancestor conditions.
Tag 13's single release root
instead names its own finalization accumulator as previous and has no batch
binding or Ordinary child.

Every receipt field equals the accepted ARCH-001 durable journal, request,
common response envelope, and operation-specific response field byte-for-byte;
the tag-28/tag-29 digest is the exact mode-specific evidence committed by that
record. Commit/renewal consumes only the already published outer and its listed
top-level accumulators, never the future release roots, so no digest or state
cycle exists.
Under the helper mutation lock, the receipt's state revision and journal head
must still be the exact authoritative current CAS base before staging. The first
member uses that base; each encoded member and the final tag-56 record advances
the transaction-local head and state revision exactly once, without wrap. If the
base revision is `R` and there are `N` members, the protected index commits the
tag-56 tip at revision `R + N + 1` and `committed_record_count=N+1`. None of
those intermediate revisions is externally current. The selector commit makes
only the final head/revision authoritative; every subsequent state-changing
ARCH-001 request must expect that new revision, and a request using the older
commit/renewal result revision is `StaleStateRevision`. A concurrent stop,
renewal, fence, or recovery transaction competes under the same mutation lock
and exact-base CAS; only one can commit.

The ordinals in `VerificationAdmissionOpenAuthorityV1` and the later tag-56 root are
assigned by the one nonwrapping, serialized plan-generation acceptance event
gate used for outer publication and every relevant cancellation, deadline, FIN/
RST, association-loss, factory-terminal, census-terminal, queue-loss,
disposition, release-root, and batch-completion event. They are nonzero, unique,
and producer-independent. Tag 13 requires
`outer_publication_ordinal < release_serialization_ordinal`. Tags 28/29 require
`outer_publication_ordinal < disposition_serialization_ordinal`, then one
distinct `release_serialization_ordinal` per factory in exact factory-ID order,
then `batch_completion_serialization_ordinal`; the disposition value is the
exact durable ARCH-001 commit/`LeaseRenewed` result linearization. An event that
precedes disposition refuses the mutation. After a durable disposition, a
factory/census terminal, an unresolved or unbookkept close, or any external loss
whose acceptance-event ordinal precedes the final completion reservation aborts
the entire staged batch, publishes none of its roots as current, and causes a
later fence/recovery record. The sole non-aborting intervening close is an
ordinary local or peer/OS close that linearized and completed its factory-local
ledger/counter/provenance bookkeeping before combined-lock acquisition. It
appends no tag-34/helper-journal record, its ordinal precedes the affected member
release, and that member's closure ledger plus dual census first authenticates
it. Any independent post-receipt helper append makes the exact pending CAS base
stale and aborts/fences rather than being absorbed.
After every member is staged, the coordinator acquires the same plan-generation
acceptance-event gate and drains all events already queued through the last
member ordinal. Any applicable terminal in that drain aborts. While still
holding that gate and every factory lock, it reserves the unique completion
ordinal and logical `completed_at`, constructs and dual-signs tag 56 with those
values, and persists the candidate vector/index slot. After candidate durability
and validation and immediately before writing the selector, the helper performs
an uncached suspend-aware monotonic-clock read and requires it to be strictly
before `ReleasePending.release_deadline` and every expiry/deadline that bounds
tag 56; failure leaves `ReleasePending` selected and begins fencing. Only after
that check may it durably commit the index selector. The gate remains held until
the selector acknowledgement, so a
concurrent event is ordered wholly before the reservation and aborts, or wholly
after a successful completion and belongs to the next health/rollback decision;
there is no event between signing and durable commit. On selector success the
pre-signed ordinal/time become the effective logical completion point.
Immediately after durable selector acknowledgement, and before transaction
return, product acceptance, or any factory-gate release, the helper performs a
second uncached read under the still-held gates and requires the same strict
freshness inequalities. That post-ack pass is necessary but does not by itself
release a guard. While every creation gate remains held, control of the same
acceptance-event gate passes atomically to the health/fence consumer, which
drains every event ordered after the completion reservation and before the
handoff point. Any FIN/RST, association loss, deadline, queue/factory/census
terminal, fence, or unresolved close in that drain keeps all gates closed and
appends the next fence/health record; tag 56 remains historical and no product
acceptance or Ordinary child occurs. Only an empty drain may reserve one local
`AdmissionReleaseHandoff` event and then release all factory locks before making
the acceptance-event gate available. No per-factory unlock can admit traffic
because every Ordinary entry also serializes on that still-held global gate.
After handoff, a terminal and the first Ordinary admission contend on the same
gate: terminal-first closes/fences and denies the child, while admission-first
may publish exactly that child before the terminal becomes the next health/
rollback event. There is no unowned interval between batch completion and health
enforcement.

If the post-ack freshness check fails,
the selected `Committed` value remains immutable history—it is never rolled back
to `ReleasePending` or the prior index—but no guard or product accepts it; the
gates stay closed while a fence/recovery record is appended, and only after the
existing barrier/actor cleanup predicate passes does the composite index move to
`GenerationClosed`. A crash between selector acknowledgement and this recheck
is likewise fail-closed: each Ordinary entry independently rejects the expired
root, and recovery fences before admitting traffic. The two uncached samples are
not root fields and create no digest/time cycle. On any
construction, signing, persistence, or selector failure the root/index never
become authoritative, the reserved fields authorize nothing, and recovery
handles subsequently dequeued events. This conditional reservation creates no
digest/time cycle and never backdates a failed batch into success.
If batch completion wins first, no member root may be discarded or backdated;
the later terminal belongs to the ordered handoff/next-health decision above; it
may not race around that handoff to authorize a child. A crash before
the selector's durable commit leaves none of the candidate records current in
the protected index; recovery ignores, quarantines, or truncates any physical
tail, authorizes no Ordinary child, and enters fenced recovery. A crash after
that durable commit replays the byte-identical complete vector, tag 56, selected
index, and final head/revision; if the installed guard cannot reproduce them as
current, it releases nothing and enters recovery.
No replay reallocates ordinals to reverse a winner.

The ARCH-001 commit/`LeaseRenewed` record is already a final durable idempotent
result; this contract never calls it provisional or rewrites its replay. The
subsequent complete release batch is a new mandatory data-plane safety
postcondition. An exact replay of the older success tip cannot by itself
authorize product `Active`, a healthy-renewal report, or an Ordinary child: all
three also require the current complete authenticated tag-56 root and latest-
head/status check. At initial acceptance tag 56 is the durable tip. Later
Ordinary use requires it to remain an authenticated ancestor through only the
closed chronological socket-observation suffix authorized by the same Open
authority; any fence, recovery, different batch, or authority change supersedes
it. If construction, signing, atomic registration,
freshness, or the terminal-event drain fails, the guard releases nothing and
the existing owner-death/watchdog/fence path puts every held factory into
recovery. The currently accepted ARCH-001 contract registers neither the
`ReleasePending` composite transition nor the authenticated release-proof read
required above. Consequently this final handoff is
`UnsupportedPendingArchitecture/DurableAdmissionReleaseCommitUnavailable` and
`AdmissionReleaseProofReadUnavailable` for every v1 profile. A separate ARCH-001
architecture task must add both atomically, including closed request/result,
authorization, idempotency, selector, recovery, and proof-query semantics. The
target state machine above constrains that future work; ARCH-002 does not
fabricate either primitive in implementation.

Every outer negative—including a transient target challenge below a product
threshold—authorizes no Open root or release batch and remains FinalizedHeld for
fenced rollback/epoch replacement. ARCH-001 defines failed mandatory renewal
evidence as denial and has no durable tolerated-failure disposition; ARCH-002
cannot invent one. Such a disposition remains
`UnsupportedPendingArchitecture/TransientHealthToleranceDispositionUnavailable`
until an ARCH-001 architecture task registers its request, authority, durable
state transition, replay semantics, and response. If outer publication,
commit/renewal, or release-batch construction/authentication fails, no product-
level operational acceptance or Ordinary release occurs; a durable commit/
renewal whose batch fails is followed by a new fenced rollback/recovery record
and remains only historical evidence. `AdmissionAborted` and every
`TerminalHeld` finalization may still publish the typed outer factory failure,
but never have an Open root. The next sequence admission names the applicable
current release root or a later ordinary checkpoint as its chronological
predecessor.

`DirectTarget` repeats the exact target endpoint and socket family selected
from the authorized target set; that endpoint is the OS peer.
`ExternalProxy` repeats the exact proxy endpoint, family, and inline
`RouteLocalityOutcomeV1` projection from the tag-4 proxy set; the proxy is the
OS peer and the target remains a separate authorized challenge input inside the
tunnel. `LocalAddress` repeats the exact target candidate and destination family;
`ProxyOpaque` has neither. Its child uses the `ProxyEndpointSet` binding. A target substituted as
an external peer, proxy substituted as a Direct target, ambiguous/negative/
unsealed candidate, wrong ordinal, or family/locality disagreement invalidates
the whole sequence.

The enclosing root fixes every connector child without producer choice. Tag 13,
28, and 29 require respectively `path_purpose=PreactivationProof`,
`PostactivationCanary`, and `SustainedHealth`; the connector child transport is
exactly `Tcp`. `DirectTarget` requires `ProbeTargetProfiles` with the
specification's sole tag-18 digest and both child and child-route
`selected_endpoint_digest` equal its exact target candidate. `ExternalProxy`
requires `ProxyEndpointSet` with the specification's tag-4 `ProxyEndpoint` root
and both selected-endpoint fields equal its exact proxy candidate. Membership in
the same set, family, or locality is insufficient. For a passed `TcpConnect`
challenge, `connected_endpoint_digest` equals the Direct or `LocalAddress`
target candidate; with `ProxyOpaque` it equals `Digest(EndpointIdentityV1)` of
the authorized tag-18 profile's exact normalized DNS-name endpoint and port.
The proxy OS peer can never substitute for that tunneled target result.

Family equality is byte-exact. For `Direct`, tuple connector and destination
families, `DirectTarget.connector_socket_family`, target endpoint family,
tag-31 `address_family`, child route/resulting-route family, and
`ConnectorTerminal.destination_family_observation=LocalIpv4|LocalIpv6` are the
same family. For external `LocalAddress`, tuple connector family equals the
proxy endpoint, `ExternalProxy.connector_socket_family`, tag-31 family, and
child route family; tuple destination family separately equals the target
candidate family and terminal `LocalIpv4|LocalIpv6`. For `ProxyOpaque`, tuple
destination and terminal observation are both exactly `ProxyOpaque`, while the
connector equalities still hold. A cross-family child, route, endpoint, or
terminal projection invalidates the attempt before its outcome is examined.

Tag 13's first attempt uses tuple ordinal 1, the first canonical candidate pair,
and candidate-attempt index 1. For each tuple/dimension, only the first two
matching-family candidates from the sealed sorted set are eligible; a producer
cannot choose a later candidate or a different two-element subset. Tag 28/29's
first attempt instead repeats the passed tag-13 candidate for success group 1 as
defined above. Later attempts follow only the continuation rules below.

`BeforeConnector` is valid only after the exact runtime and tag-14 factory
policy observation exist but before the primary direct/role-A connector child
passes the pre-byte release guard. Its phases are the exact prefix through `terminal_phase`; its
following accumulator is a fresh post-cleanup checkpoint with no child for that
attempt, no allocated or committed child sequence, and no unexpected open
socket. `ConnectorTerminal` is valid only after
its exact child was signed, enqueued, and released. Its connection epoch,
destination-family observation, child, typed TLS/SOCKS roots, challenge, and
following accumulator all describe that same primary connection. Resolve and
primary connector creation/mechanism/readback/route/TCP-connect/HostLocal-peer
failures use `BeforeConnector`; later failures use `ConnectorTerminal`. In
particular, every role-B terminal remains `ConnectorTerminal`, preserves role A
and its completed challenge, and uses the exact pre-tag-50 association evidence
state. A failure before the runtime/factory observation exists produces no
tag-13/28/29 wrapper.

Within one attempt sequence, every `ConnectorTerminal` has a distinct primary
`connector_socket_child_observation_digest`, `connection_binding_epoch`, and
`(factory_policy_id, factory_epoch, child.socket_sequence)` tuple. A reached
`RequireAssociate` attempt may additionally introduce the dedicated role-B TCP
child and role-C UDP child. Their tag-31 roots and platform identities are all
distinct; TCP connection epochs satisfy `A < B`, and socket sequences satisfy
`A < B < C` for every present prefix. All child socket sequences and TCP
connection epochs remain strictly increasing across later attempts for that
factory/runtime generation; retry or candidate/family advancement cannot reuse
or relabel any released socket. The named following tag-34 root is the first
checkpoint whose `NonEmpty` new-child interval and recomputed accumulator chain
contain the exact ordered one-, two-, or three-child prefix, and no other
checkpoint interval may introduce any of those children again. A prior
checkpoint cannot contain them, and a later `Empty` checkpoint cannot
reintroduce them. `BeforeConnector` allocates no child root or socket sequence.
Cross-attempt or cross-role child/epoch reuse, equality, or substitution
invalidates the whole wrapper before success-group evaluation.

Every per-attempt `protocol_phase_outcomes` list contains `1..=32` entries in
the exact selected state-machine order. `BeforeConnector` ends at its
failed/timed-out/cancelled terminal phase. `ConnectorTerminal` contains the
prefix through its actual terminal state. Duplicate canonical phase values,
missing mandatory phases, reordering, a later phase after terminal, or an
unexpected phase is invalid. `NotApplicable` is accepted only for the explicit
conditional HostLocal peer phase on a `Remote` proxy or another displayed
conditional phase omitted by the selected closed variant. For
`ExternalSocks5::RequireAssociate`, a successful attempt has the eleven
section 11.4 target-tunnel entries followed by the six role-B setup/authentication
entries and seven association entries in section 11.5, including the target TCP
submachine's intermediate `Passed`, for exactly 24 entries. Role-bearing values
are distinct canonical phases; the same unqualified proxy phase name cannot be
used twice. There is no second `ResolveProxyEndpoint`.
The only three non-protocol terminations inside that sequence are the outer
`UdpControlChildReleaseAborted` before any role-B phase is entered,
`UdpControlFirstByteGuardAborted` after B publication but before its method
phase, and tag-50 `UdpChildReleaseAborted`. Their lists end respectively with
the target-tunnel `Passed`, the role-B conditional peer phase, and
`ClassifyAndExcludeRelay/Passed`; the latter does not enter
`SendBoundedFRAG0Canary`. Each terminates only because the same attempt's first-
following census selects the outer factory-invariant failure. No synthetic
failed protocol phase is added.

Within one HTTP connection attempt, the three steps of exchange 1 and optional
challenge/exchange 2 have distinct `HttpConnectExchange` values, so the
no-duplicate rule is compatible with `ChallengeOnce`. Across connection
attempts the same state label may recur; the enclosing attempt ordinal,
candidate ordinal, and candidate-attempt index make the occurrence unique.

`ProtocolAttemptChallengeEvidenceV1::PreactivationCompleted` is valid only in
tag 13. A NonceEcho reference names the exact tag-27 result for this attempt;
once a preactivation NonceEcho attempt enters the challenge phase it must use
that tag-27 result even for zero-byte failure before durable consumption. TCP
success names its exact connected target; a negative preactivation TCP challenge
uses the sole `NoCompletedResult` exception above. `PhaseBoundCompleted` is valid
only in tag 28 or 29 and names the exact tag-37 result with respectively
`Postactivation` or `Renewal` context. Its connection epoch, optional proxy
endpoint, child, and following accumulator equal the enclosing attempt.
Once a tag-28/tag-29 attempt enters either challenge phase it must use tag 37
for every passed, failed, timed-out, or cancelled TCP/NonceEcho terminal result,
including zero-byte NonceEcho failure before durable consumption.
`NoCompletedResult` carries no placeholder root and is otherwise valid only
strictly before challenge entry. Alternate encodings, cross-phase, or cross-
attempt challenge evidence are invalid.

Every entry's `continuation` is a total next-state function, not a producer-
selected option. In every tag, an accepted factory/census-negative checkpoint,
cancellation, or
non-recoverable protocol failure is `Terminal`. In tag 28, any nonzero or
`Unavailable` egress-bypass count is also `Terminal`. These checks take
precedence even when the protocol itself succeeded. A malformed,
unauthenticated, stale, or cross-context inner root instead invalidates the
wrapper and does not encode any valid continuation.

For exploratory tag 13 only, subject to an accepted complete/equal cleanup
checkpoint, an eligible early failure at candidate index 1 uses
`RetrySameCandidate` iff `retry_limit=1`. Otherwise, and after an eligible
index-2 failure, `AdvanceNextCandidate` is mandatory iff the immediately
following canonical pair exists in the current tuple. If that tuple's pairs are
exhausted, `AdvanceNextFamilyTuple` is mandatory iff another tuple remains in
the same current success group; it selects that group's immediately following
tuple and first pair/index 1. Exhausting every tuple of an unsatisfied group is
`Terminal`; execution never skips to a later required group that cannot make
the current one true. After tag 13 protocol success and a passing census, the
current group is satisfied, its remaining preference tuples are skipped, and
`AdvanceNextFamilyTuple` selects the immediately following group's first tuple/
pair/index 1, or `Terminal` after the final group.

For verification tags 28/29, every attempt already names the successful tag-13
candidate for its current group. A `BeforeConnector`, early connect failure, or
any later negative protocol/challenge/TLS/SOCKS result is `Terminal`; neither
`RetrySameCandidate` nor `AdvanceNextCandidate` is valid. Only protocol success,
a passing census, and, for tag 28, complete zero-traversal observations may use
`AdvanceNextFamilyTuple`, and only to the immediately following group's exact
tag-13-selected tuple/candidate at index 1; the final group is `Terminal`.

Across all tags, attempted tuple ordinals are strictly increasing and no
candidate pair or group can restart. `RetrySameCandidate` repeats tuple and
candidate binding with index 2; both advance variants begin at index 1. A wrong
next variant, an eligible tag-13 fallback changed to `Terminal`, a following
attempt after a terminal condition, a skipped eligible tuple/pair/group, or
premature group satisfaction invalidates the wrapper.

Attempt `n+1` starts only after attempt `n`'s following tag-34 checkpoint is
authenticated and its tag-46/tag-44 census outcomes are both `Complete`, equal,
counter-stable, and leak-free, and its factory latch is not `TerminalFailed`.
A structurally valid terminal latch, negative census, or complete-set/counter
mismatch forces
`Terminal` and outer `Failed { error_code =
SocketFactoryInvariantUnproven }`; a malformed or unauthenticated census
invalidates the wrapper. It can never authorize another socket release.

`protocol_successful_attempt_ordinals` is the strictly increasing attempt-order
list containing the first protocol-successful attempt for every visited group
that reaches protocol success. It references only existing attempts. A later
terminal latch, negative census, or tag-28 traversal observation does not erase that ordinal, but
prevents advancement to the next group. The list is empty or a proper prefix of
the groups when the outer result terminates before protocol success, and no
attempt follows a complete success-group set. At most four tuples times two proxy candidates times two target
candidates times two attempts per pair yields 32 attempts. Direct and
`ProxyOpaque` omit the absent candidate dimension and therefore have a smaller
bound.

An attempt is “protocol-successful” if and only if it is
`ConnectorTerminal`, has the complete legal phase trace, has a passed target
challenge and every applicable TLS/tag-50 root passed, and ends at `Passed` or,
for `RequireAssociate`, `AssociationReady`. `protocol_successful_attempt_ordinals`
contains exactly the first protocol-successful attempt for each visited group
that reaches protocol success. A later terminal latch, negative census, or traversal observation does not erase that
ordinal; it makes the sequence terminal and the outer outcome failed under the
priority rule. An attempt with merely a passed challenge but missing final
protocol/association phases is not successful. In particular,
none of `UdpControlChildReleaseAborted`,
`UdpControlFirstByteGuardAborted`, or `UdpChildReleaseAborted` is ever
protocol-successful despite its final completed phase having `Passed` or
`NotApplicable` as allowed above.

Outer outcome projection checks census checkpoints in one total canonical
order: the sequence admission accumulator; each `Executed` attempt's first-
following accumulator in attempt order; the sequence finalization accumulator
if its digest was not already seen; then, for tag 28 and tag 29 respectively,
every top-level factory accumulator from that outer root's paired lists in
ascending `factory_policy_id` order whose digest was not already seen.
`AdmissionAborted::{CandidateAdmissionTerminal,
PriorOrdinaryOperationTerminal}` contains only its terminal root;
`PostAdmissionPreAttemptTerminal` checks its referenced successful admission
root and then its terminal root. Tag 13's finalization digest and top-level
digest equal its final attempt checkpoint. Tag 28/29's finalization equals a
non-success final-attempt checkpoint, or is the mandatory fresh root after a
clean protocol-successful final-attempt checkpoint; digest de-duplication yields
exactly one scan position in either branch. Outer
outcome projection first checks the first
factory/census-negative checkpoint in that order. A structurally valid tag-46
`TerminalFailed` latch, tag-46/tag-44 negative census, or complete-set/counter
mismatch maps to
`SocketFactoryInvariantUnproven` as above. Otherwise it uses the last attempt
needed to decide the tuple plan. In tag 28, a counted traversal mismatch or
`Unavailable` on that attempt next maps to `LoopDetectedOrUnproven`. Otherwise
a non-success terminal protocol phase has the same outcome class as the tag-
specific outer outcome: `Failed` repeats exactly the nested `error_code`,
`TimedOut` repeats exactly the nested terminal phase in `bounded_phase`, and
`Cancelled` has no outer phase/error field because the unique final nested
`Cancelled` entry alone carries its phase. In tag 13, a
negative NonceEcho tag-27 result, the final
`Challenge`/`ChallengeThroughTunnel` phase, and the outer outcome all have the
same class/error; failed TCP challenge uses `NoCompletedResult` with the same
terminal phase. In tags 28/29, a negative tag-37 result, that final challenge
phase, and the outer outcome likewise match. No `Passed` phase follows a
negative challenge. A successful challenge is required before the `Passed`
phase, and `RequireAssociate` then continues only through its seven association
phases after its six dedicated-control setup/authentication phases. Once the
target-tunnel `Passed` marker exists, every ordinary role-B or later negative
terminal has `continuation=Terminal`, including a recoverable TCP connect code;
role A has already emitted method/authentication/CONNECT/challenge bytes, so no
retry or fallback can hide that completed prefix. Cancellation has one final
cancelled phase and no invented error code. All three child-release/guard abort variants
are accepted only in the first outer-projection branch: their same-attempt
first-following exact `TerminalFailed` latch selects
`SocketFactoryInvariantUnproven`, and none invents a non-success terminal
protocol phase to project.
Prior eligible early failures do not overwrite a later required success, but
their typed negative phases and cleanup checkpoints remain in the sequence.

Items 3 and 4 below may produce outer `Failed` only after every required
success attempt has passed every protocol and challenge. Item 1 terminates at
the first negative admission, attempt, inter-attempt, finalization, or top-level
factory checkpoint in canonical order; item 2 terminates after its corresponding
protocol-successful tag-28 attempt. Overall
failure priority is this exact order:

1. `SocketFactoryInvariantUnproven`: the first accumulator in the total order above names
   a structurally valid tag-46 `TerminalFailed` latch, a tag-46 or tag-44 census
   whose outcome is not `Complete`, or two complete census sets/counters that do
   not match;
2. `LoopDetectedOrUnproven`: tag 28's exact attempt-keyed traversal observation
   is a counted mismatch or `Unavailable`;
3. `ExclusionReadBackFailed`: tag 28/29's exact tag-51 root has the authenticated
   context-matched `Failed` or `TimedOut` variant;
4. `OrdinaryConnectivityFailed`: tag 28/29's exact tag-52 root has `Failed` or
   `TimedOut`.

Item 1 may terminate a zero-attempt sequence and otherwise terminates at the
first corresponding checkpoint; item 2 requires its corresponding attempt;
items 3 and 4 apply only after the required protocol/challenge success set exists. Tag 13
permits only item 1, tag 28 all four, and tag 29 items 1, 3, and 4. Within
a repeated canonical list, the first failing entry wins. Missing fields,
signature/role/context errors, stale or unknown roots, tag-55/tag-35 data that
cannot satisfy their success-only schemas, invalid lease/fence, or any other
structural mismatch invalidates the wrapper and is handled by the enclosing
typed transaction/renewal failure; it cannot manufacture a valid outer
`Failed`. If the required attempts and all applicable predicates pass, the
outer result is exactly `Passed` for tag 13/28 or `Healthy` for tag 29.

For `ExternalHttps`, each `BeforeConnector` attempt uses
`ExternalHttpsPrepared` with the exact context-bound material roots and no
tag-42 digest. Each `ConnectorTerminal` attempt uses
`ExternalHttpsHandshake`; its tag-42 connection epoch, child, and proxy endpoint
equal that attempt. A passed attempt requires a passed tag-42 root. A matching
`NotStarted` or terminal tag-42 negative root is allowed only on the same
non-success attempt. System-root modes carry the exact fresh TrustMaterialBroker
observation; private-anchor-only modes omit it. Other selections use
`NotApplicable`.

`socks5_udp_association_evidence` is `NotApplicable` unless the selection is
`ExternalSocks5::RequireAssociate`. `NotReached { udp_associate_control =
NotStarted }` is exact while the prefix ends before the first role-B
`BindOrProtectProxySocket`. `UnpublishedProtocolTerminal` is exact when a
pre-release cancellation/deadline, successful-readback semantic route mismatch,
or ordinary role-B connect outcome terminates before the dedicated control
child is atomically published; no role-B child root,
connection epoch, or socket sequence exists, and the first-following checkpoint
records only the unpublished socket's create/close lifecycle counters in
addition to role A's permanent creation chain. `Published` is exact after the
role-B child is released and before
`EstablishedAuthenticatedSOCKS5Control`; its epoch and child digest name that
one dedicated connection, including method/authentication failure or the
terminal-latch-after-release case, but excluding the dedicated first-byte guard
abort below.

Every A, A+B, or A+B+C prefix in this subsection is the ordered child delta and
state projection for the current attempt only. It never rebases the factory-
wide tag-34 creation chain, which remains cumulative over all prior attempts.
The current-open census accumulates every earlier successful active group's B+C
pair only while the sequence continues successfully; any terminal group follows
the sequence-wide controlled-close rule above.

`UdpControlChildReleaseAborted` is the first non-protocol exception before tag
50. It is legal only after the target-tunnel `Passed`, before any role-B phase
entry, with no role-B/UDP child, no association/tag-48/datagram material, and an
exact first-following tag-34 checkpoint whose tag-46 latch is
`TerminalFailed`. Its counter/reason equal that latch and the reason is one of
the factory-local failures permitted in section 12.3, including queue/create,
mechanism or option/route readback, independent HostLocal peer check, release,
signing, capacity, and publication failures. Its unique outer outcome is
`SocketFactoryInvariantUnproven`; a protocol code, retry, fallback, phase entry,
sequence allocation, or hidden released socket makes the wrapper invalid.

`UdpControlFirstByteGuardAborted` is the second pre-tag-50 exception. The full
factory operation succeeded and atomically published B, so its binding is
mandatory and A+B are permanently present in the creation chain. Before the
first method byte, the one-shot release guard failed exactly with
`FirstByteExpiryGuardFailed`; no `OfferExactMethods` entry, greeting,
authentication, UDP ASSOCIATE, tag 50, C, tag 48, nonce, or datagram exists.
The displayed last peer phase is `Passed` for `HostLocal` and `NotApplicable`
for `Remote`. The factory controlled-closes B before the first-following
checkpoint, so A+B are chain-present/current-absent. Counter/reason equal that
checkpoint's tag-46 `TerminalFailed` latch, and the sole outer result is
`SocketFactoryInvariantUnproven` with terminal continuation. Encoding this
boundary as `NotReached { Published }`, entering a fake method phase, or using a
protocol failure code is invalid.

Once `EstablishedAuthenticatedSOCKS5Control` appears, `Observed` is mandatory
with the exact context/sole-target/attempt ordinal/family tuple/candidate/target-
tunnel epoch and child/dedicated-control epoch and child/proxy/optional UDP
child/first-following-accumulator/control-exchange/relay/canary-bound tag-50
root, all byte-identical to that enclosing attempt and checkpoint. Its negative
outcome and bounded phase equal that attempt's terminal association phase even
when the first tag-50 phase itself fails, times out, or is cancelled; a
successful required attempt has `Observed` with `Passed` and terminates at
`AssociationReady`. The only later exception is `Observed` with
`UdpChildReleaseAborted`, whose exact passed-classification/absent-UDP-child/
`TerminalFailed`-latch boundary is defined in section 4.6 and whose outer result
is the shared factory-invariant failure. The three pre-tag-50 evidence states,
the two control aborts, and `Observed` are never alternate encodings of the
same prefix. No association or TLS root may be reused across attempts.

Every attempt's `following_socket_observation_accumulator_digest` is the first
fresh helper/watchdog checkpoint after that attempt reaches terminal and after
its required-close sequence has completed or durably latched a close/
bookkeeping failure. An ordinary protocol, timeout, or cancellation terminal is
valid only when every connection required to close has closed. The exceptional
cleanup-failure checkpoint instead carries the exact tag-46 `TerminalFailed`
reason/counter and the authenticated actual open state; it can select only the
factory/census-negative outer result. If that actual state or latch cannot be
proven, no wrapper is valid. Every
`ConnectorTerminal` child is introduced exactly once in that checkpoint's
`NonEmpty` creation-chain interval. It appears in that checkpoint's current
open provenance and independent OS set if and only if the same socket remains
open: a closed success/failure child is absent from both current sets but
remains permanently represented by the chain. A passed preactivation SOCKS5 UDP
association has three permanent creation-chain roots. Role A was already closed
after its successful NonceEcho target challenge; after the immutable tag-50
terminal snapshot the runtime controlled-closes B and C before this checkpoint,
so all three are chain-present/current-absent. A passed postactivation or
renewal association likewise has role A chain-present/current-absent and retains
the B and C local handles and provenance for this attempt through this
checkpoint, so those two are chain-present/current-present. Its verification
projection also contains every B+C pair retained by an earlier successful
active group and no role-A child from any such group; after successful group
`i`, that projection is the exact `i` retained B+C pairs. In `Renewal`, the
factory-wide set additionally contains the exact disjoint non-verification
`O_i` set observed by the same actor-wide dual census. The checkpoint does not
resample the earlier protocol-liveness decision. This retention applies
only while the active sequence continues successfully; the first later terminal
attempt uses the sequence-wide controlled-close rule above. A
`BeforeConnector` attempt has no child, uses an `Empty` delta, leaves
the creation chain unchanged, and still reflects its create/close lifecycle
counter transitions. Checkpoints form one gap-free chronological factory chain
across attempts. Tag 13's top-level accumulator equals the final attempt
checkpoint. `AdmissionAborted` uses its terminal root as top-level and has no
sequence-finalization field. For an `Executed` tag 28/29, the probe-factory top-
level reference always equals `sequence_finalization_accumulator_digest`: it is
the final attempt checkpoint when that attempt was not protocol-successful or
its first-following checkpoint terminally failed, and otherwise is the mandatory
next `Empty` finalization checkpoint after the frozen traversal/tag-51/tag-52
result. The later tag-13 Open root, or any tag-28/tag-29 release-batch member and
tag-56 completion root, is never an outer top-level accumulator or list member.
Other tag-28/tag-29 factory entries remain their exact final fresh checkpoints
in factory-ID order. A missing child, leaked socket, reused census context,
chain gap, or top-level mismatch invalidates the result.

`actor_network_isolation_readback_digests` contains exactly one tag-55
checkpoint for every `NoExternalNetworkPath` actor, ordered by `actor_id` with
bound `1..=32`. Tag 13 uses `PreactivationPlanCheckpoint`; tags 28/29 use
`ActivePlanCheckpoint` with their exact postactivation/renewal context. Every
root repeats the tag-54 policy/actor/mechanism/permit tuple and required
platform-then-helper signatures. All are accepted before the first attempt.
Missing, reordered, stale, single-signer, or nonzero-unexpected-surface data
invalidates the wrapper rather than becoming a producer-reported failure.

`baseline_anchor_digest` always names the exact registered
`BaselineEgressAnchorV1`; there is no arbitrary route hash.

At plan sealing the helper replaces the observation nonce slot with a fresh
helper-assigned nonce and includes it in the final proof-specification and plan
digests; the result's nonce must equal that sealed value byte-for-byte. The runtime
signs the result through its protected control identity after
redeeming the plan's external gate. The helper verifies the nonce, plan,
controller/connection, generation, runtime/gate/package/config identity,
signature, freshness, and expected schema, and independently queries the route,
interface, endpoint locality, and any OS-owned socket-policy evidence it can
observe. The Supervisor may relay the result but cannot rewrite or manufacture
it. A tuple without the protected runtime observation channel or independent
safety-critical OS read-back is unsupported.

Every helper observation nonce is an unpredictable 32-byte value and is public
anti-replay data, not a credential. An `ExternalObservationAuthenticatorV1`
contains a 64-byte Ed25519 signature. Its public key is not supplied or selected
by the result. `authority_binding` is a closed union because not every observer
is an ARCH-001 external executor. `NetworkRuntime`, `RuntimeAdapter`,
`CaptureCore`, and `SocketFactoryExecutor` use `ExternalExecutorGate`;
`PlatformDiscoveryBackend` uses `PreplanDiscoveryAuthenticatedChannel` for
registered pre-plan roots and `PlanComponentAuthenticatedChannel` for
plan/checkpoint roots; `TrustMaterialBroker` uses
`PlanComponentAuthenticatedChannel`; `PrivilegedHelper` uses
`HelperAuthority`; `WatchdogOrReconciler` uses `WatchdogFenceDomain`; and
`ReleaseVerifier` uses `ReleaseEvidenceAuthority`. Any other root/binding
combination is invalid even when the signer role is otherwise correct. The
`channel_binding_digest` inside `PreplanDiscoveryAuthenticatedChannel`,
`PlanComponentAuthenticatedChannel`, and `WatchdogFenceDomain` is respectively
the exact tag-0, tag-1, or tag-2 `AuthenticatedChannelContextV1` digest defined
above and repeats every displayed authority field, including generation and,
for watchdog, lease epoch. The tag-3 broker-to-materializer delivery and tag-4
adapter-to-runtime load bindings are separate body fields: the broker still
authenticates its signed root under its tag-1 plan-component authority, while a
runtime/adapter root still authenticates under its ARCH-001 external-executor
gate. Neither body channel digest can replace the signer authority binding.
The
release verifier identity
and Ed25519 key are members of the compile-time trusted release-key registry at
the exact displayed revision; that authority is independent of any runtime plan
and is accepted only for immutable capability-evidence roots.
`trusted_release_keyset_revision_sha256` is exactly
`SHA-256("FlowProbe.Egress.TrustedReleaseKeyset.v1\0" ||
canonical_cbor(TrustedReleaseKeysetRevisionV1))`, where the fixed-array schema
is `{ revision_id, keys }` and each `TrustedReleaseKeyV1` is
`{ release_verifier_identity, ed25519_public_key_32,
authorized_root_tags = [49, 53] }`. `revision_id` is NFC/control-free UTF-8 of
`1..=128` bytes; `keys` contains `1..=32` entries whose
`release_verifier_identity` values are pairwise unique and whose public-key
bytes are also pairwise unique, ordered by the unique identity's raw bytes; and
every public key is exactly 32 raw Ed25519 bytes. The signer header's role-bound
key digest must match the sole entry for its exact verifier identity. A
duplicate identity, key alias, text dump, map iteration order, key-only hash,
mutable runtime registry, unknown root tag, or differently ordered keyset is
not that revision.
Any other role/binding pairing is
unauthenticated. `ObservationSignerIdentityV1` must select the variant implied
by the authority binding and repeat its exact executor/component/helper/
watchdog/release-verifier identity. For pre-plan and plan observations the selected authority
binds the 32-byte public-key identity to the exact signer instance, role,
ticket/session/generation or plan/generation, and every displayed nonce,
gate/channel/helper/fence field. For release evidence
it binds the role, verifier identity, and trusted keyset revision to every exact
tuple and digest in the signed root. The key identity
is exactly
`SHA-256("FlowProbe.Egress.ObservationSignerKey.v1\0" ||
uint16_be(signer_role_tag) || ed25519_public_key_32_bytes)`.
The signature input is exactly
`"FlowProbe.Egress.ExternalObservation.v1\0" || uint16_be(root_schema_tag) ||
uint16_be(schema_version) || canonical_cbor(AuthenticatorHeaderV1) ||
SHA-256(canonical_root_signing_projection)`. The root signing projection is the
root's displayed fixed array with every complete authenticator field omitted;
no other root field is omitted or rewritten. The signer-specific header is not
part of that root projection: it is encoded separately as shown, so its role,
identity, key, complete `authority_binding`, and algorithm are all signed. Every
signer in a multi-signer root uses the same root projection and its own header.
A wrong role, binding variant, key, channel/authority field, root tag/version,
nonce, header encoding, or root projection is unauthenticated.
`Arch001JournalTipV1` is one closed fixed array in the displayed order:
`journal_head_digest_at_result` is exactly the accepted Privileged Helper
`JournalHeadDigestAtResult` 32-byte domain and `state_revision_at_result` is
exactly its paired accepted unsigned 64-bit `StateRevisionAtResult`; neither
component may be omitted, reordered, independently refreshed, or paired with
the other component from a different response or transaction point. Its only
six schema occurrences are `HelperAuthority.parent_journal_tip`,
`FactoryAdmissionReleaseCurrentIndexV1::BoundClosed.bind_parent_journal_tip`,
`FactoryAdmissionReleasePendingDispositionV1::Renewal.prior_release.batch_tip`,
`FactoryAdmissionReleaseCurrentIndexV1::ReleasePending.disposition_tip`,
`::Committed.batch_tip`, and `::GenerationClosed.close_parent_journal_tip`.
The digest-field inventory expands and checks the nested
`journal_head_digest_at_result` at every one of those paths.
`HelperAuthority.parent_journal_tip` is the exact parent tip read under the
helper's single mutation lock immediately before that root is signed. The signed
root/authenticator are appended afterward and create the next tip; that new tip
is not an input to the root or signature. Thus no journal-head/signature cycle
exists. The sole batching exception is the tag-28/
tag-29 admission-release transaction. Its first tag-34 member uses that exact
durable parent. Each later factory-ID-ordered member and the final tag-56 root
uses the exact transaction-local head/revision produced by encoding the
immediately preceding record. Under the same mutation lock, the helper stages
and fsyncs that complete ordered record vector and the inactive composite slot
of the one ARCH-001 copy-on-write protected index, including its current-release
extension, then uses that index's sole selector commit point defined above; no
tentative head, member root, or Open state is authoritative.
The tag-56 append is the transaction's last record and candidate tip. A signing,
watchdog, terminal-event, vector/index validation, selector, or fsync failure
commits none of the vector; physical precommit bytes are ignored or removed by
recovery. This exception changes append granularity and advances the existing
protected head/state revision only through the one final index commit; it is not
an ARCH-001 request, response, lifecycle phase, lease, or independently
replayable operation. No response claims to return tag 56. A lost local
completion notification or restart requires the future registered ARCH-001
typed authenticated release-proof query and cross-checks the unextended
`Status` common tip as defined above; until that query exists the state is
unsupported and fences rather than accepting. It never executes the batch again
or creates a nonce, ordinal, time, signature, or index transition. The journal
retains the registered root and authenticator, not a handshake transcript.

The helper enforces this root-to-role table before accepting any signed root;
there is no caller-selected or “compatible” role:

| Registered signed root | Exact required signer role(s) |
| --- | --- |
| `CapabilityReportV1` | one `PlatformDiscoveryBackend` with `PreplanDiscoveryAuthenticatedChannel` |
| `ResolvedEndpointSetV1` | one `PlatformDiscoveryBackend`; `PreplanDiscoveryAuthenticatedChannel` for proxy/target preflight, `PlanComponentAuthenticatedChannel` for SOCKS relay checkpoint |
| `LocalProxyIdentityV1` | one `PlatformDiscoveryBackend` with `PreplanDiscoveryAuthenticatedChannel` |
| `BaselineEgressAnchorV1` | one `PlatformDiscoveryBackend` with `PreplanDiscoveryAuthenticatedChannel` |
| `ConnectedLocalPeerObservationV1` | one `PlatformDiscoveryBackend` with `PlanComponentAuthenticatedChannel` |
| `TlsVerifierCapabilityEvidenceV1` | one `ReleaseVerifier` |
| `PlatformCapabilityEvidenceV1` | one `ReleaseVerifier` |
| `ActorNetworkIsolationReadbackV1` | `Preplan`: one `PlatformDiscoveryBackend` with `PreplanDiscoveryAuthenticatedChannel`; `PreactivationPlanCheckpoint` or `ActivePlanCheckpoint`: `PlatformDiscoveryBackend` with `PlanComponentAuthenticatedChannel`, then `PrivilegedHelper` with `HelperAuthority` |
| `EffectiveProxyTrustObservationV1` | one `TrustMaterialBroker` with `PlanComponentAuthenticatedChannel` |
| `NonceEchoDeliveryConsumptionRecordV1` | one `PrivilegedHelper` |
| `ProxyTrustMaterialDeliveryRecordV1` | one `TrustMaterialBroker` with `PlanComponentAuthenticatedChannel` |
| `ProxyTrustMaterialLoadObservationV1` | one `NetworkRuntime` |
| `ProxyTrustMaterialArtifactObservationV1` | one `RuntimeAdapter` |
| `ProxyTlsHandshakeObservationV1` | one `NetworkRuntime` |
| `Socks5UdpAssociationObservationV1` | one `NetworkRuntime` |
| `EgressPathProofResultV1` | one `NetworkRuntime` |
| `PhaseBoundProbeChallengeResultV1` | one `NetworkRuntime` |
| `SocketFactoryPolicyObservationV1` | `SocketFactoryExecutor` with `ExternalExecutorGate`, then `PlatformDiscoveryBackend` with `PlanComponentAuthenticatedChannel`, then `PrivilegedHelper` with `HelperAuthority` |
| `SocketPolicyChildObservationV1` | one `SocketFactoryExecutor` |
| `FactorySocketCensusObservationV1` | one `SocketFactoryExecutor` |
| `OsSocketCensusV1` | one `PlatformDiscoveryBackend` with `PlanComponentAuthenticatedChannel` |
| `SocketObservationAccumulatorV1` | `PrivilegedHelper` with `HelperAuthority`, then `WatchdogOrReconciler` with `WatchdogFenceDomain` |
| `FactoryAdmissionReleaseBatchCompletionV1` | `PrivilegedHelper` with `HelperAuthority`, then `WatchdogOrReconciler` with `WatchdogFenceDomain` |
| `EgressExclusionReadbackObservationV1` | `PlatformDiscoveryBackend` with `PlanComponentAuthenticatedChannel`, then `PrivilegedHelper` with `HelperAuthority` |
| `EgressOrdinaryConnectivityObservationV1` | `PlatformDiscoveryBackend` with `PlanComponentAuthenticatedChannel`, then `PrivilegedHelper` with `HelperAuthority` |
| `PostactivationCanaryResultV1` | `NetworkRuntime`, then `CaptureCore` |
| `SustainedHealthObservationV1` | `NetworkRuntime` with `ExternalExecutorGate`, `PlatformDiscoveryBackend` with `PlanComponentAuthenticatedChannel`, `PrivilegedHelper` with `HelperAuthority`, `WatchdogOrReconciler` with `WatchdogFenceDomain`, sorted by role tag in the encoded list |

The single-signer rows contain exactly one authenticator. The multi-signer rows
contain exactly the displayed unique role set and every signer signs the same
root projection. Registered roots without an authenticator field, including
`ActorNetworkIsolationPolicyV1`, `SocketIdentitySetV1`,
`NonceEchoChallengeResultV1`, authorization scopes, and
content descriptors, are digest-bound children of a signed/plan-bound root and MUST NOT
be given a fabricated standalone observation signature.

The result contains no response body, raw target-challenge nonce, raw certificate,
certificate chain, proxy field value, authentication challenge text,
credential, credential handle, authorization value, Cookie, arbitrary stderr,
or unbounded OS/proxy message. A certificate or handshake is represented only
by safe policy/identity/result digests and bounded reason codes.

The result expires on its own deadline, plan/runtime/controller/channel change,
generation/fence change, boot/suspend, baseline interface/route/resolver epoch
change, endpoint candidate/locality change, local proxy identity change, trust
policy change, or backend/package version change.

Capability/policy/interaction refusal occurs during typed preflight before a
Network Runtime is started and therefore produces no tag-13 runtime-signed
root. The preflight result preserves one of all seven `CapabilityDisposition`
variants and its mapped bounded error; a missing authorized target is
`InteractionRequired`/`ProbeTargetRequired`, never generic `Unsupported` and
never a fabricated runtime `ProbeOutcome`.
`ProbePathUnproven` is likewise a fail-closed orchestration error only when no
valid NetworkRuntime-signed path result can be constructed or accepted. It
carries no tag-13/tag-27/tag-28/tag-29/tag-37/tag-50 result and cannot be placed
in a nested phase, challenge result, or `ProbeOutcome`; once a registered
challenge phase has a deterministic failed terminal, its sole code is
`ProbeFailed`.

`Passed` proves the selected preactivation path and preventive socket behavior
of the exact inert runtime only. It does not prove that future full-tunnel
exclusions were installed, that the postactivation path is healthy, or that the
session committed.

## 11. Protocol state machines

### 11.1 Direct

```text
ResolveIfRequired
  -> BindOrProtectSocket
  -> ObserveRoute { connection_role=DirectTarget }
  -> ConnectDestination
  -> Challenge
  -> Passed
```

The route observation must select the sealed baseline anchor for the family.
Omitting an outbound/detour option, selecting sing-box's implicit default, or
successfully creating a socket is not a binding observation. Direct UDP or DNS
is unavailable until the owning ARCH-004 contract supplies the required actor,
policy, exclusion, and proof dependencies.

### 11.2 HTTP CONNECT

`ExternalHttp` uses HTTP/1.1 CONNECT only:

```text
ResolveProxyEndpoint
  -> BindOrProtectProxySocket { connection_role=TargetTunnel }
  -> ObserveRoute { connection_role=TargetTunnel }
  -> TcpConnectProxy { connection_role=TargetTunnel }
  -> VerifyConnectedLocalPeerIfHostLocal { connection_role=TargetTunnel }
  -> HTTP_CONNECT_EXCHANGE(1)
  -> [AcceptBasic407Challenge -> HTTP_CONNECT_EXCHANGE(2)]
  -> ChallengeThroughTunnel
  -> Passed
```

Each `HTTP_CONNECT_EXCHANGE(n)` expands to exactly three consecutive
`ProtocolPhaseV1::HttpConnectExchange` entries with the same `attempt_index=n`
and steps `SendConnectAuthority`, `ReadBoundedResponseHead`, then
`TunnelOrTypedFailure`. `None` uses exactly attempt 1 without credentials.
`PreemptiveOnce` uses exactly attempt 1 with its one-use credential delivery.
`ChallengeOnce` uses attempt 1 without credentials; only a valid bounded Basic
407 satisfying the exact same-connection reuse predicate below produces the
unique `AcceptBasic407Challenge` phase followed on that socket by attempt 2 with
the credential. A 2xx attempt 1 omits the conditional challenge and second
exchange. Any other response terminates attempt 1. A third exchange,
duplicate `(attempt_index, step)`, reordered step, or a second challenge phase
is invalid. For a `Remote` proxy, the peer-verification phase is present with
`NotApplicable`; for `HostLocal` it must be `Passed` before the first CONNECT or
credential byte.

The request target is normalized authority form `host:port`; an IPv6 literal is
bracketed. `Host` carries byte-identically the same authority. For
`LocalAddress`, `host` is the exact selected attempt
`target_endpoint_digest`'s IPv4/IPv6 literal and port; the original DNS name is
not emitted and cannot trigger proxy-side resolution. For `ProxyName`, `host`
is the target profile's exact normalized A-label and port and no local target
candidate exists. Scoped IPv6 cannot be represented by HTTP CONNECT or SOCKS5
ATYP in v1 and is `UnsupportedProtocolFeature` for an external proxy; it remains
available only to a separately authorized Direct target. A signed candidate,
authority, `Host`, family, or port substitution is invalid. CONNECT has no request content.
No user-controlled request path, arbitrary field, redirect, origin
`Authorization`, Cookie, or body is allowed.

Only a complete 2xx response establishes a tunnel. Per RFC 9110, response
`Content-Length` or `Transfer-Encoding` on successful CONNECT is ignored and
bytes after the response head are tunnel bytes. FlowProbe does not read or log a
CONNECT response body. The sole non-2xx connection-reuse case is challenge-
exchange 1 under sealed `ChallengeOnce`: it is HTTP/1.1 status 407, contains
exactly one accepted Basic challenge, exactly one valid `Content-Length: 0`, no
`Transfer-Encoding`, neither `Connection: close` nor `Proxy-Connection: close`,
and no buffered byte after the response head. Only that complete predicate may
enter `AcceptBasic407Challenge` and send exchange 2 on the same child/connection
epoch. Every other non-2xx response closes the connection and returns only the
status class/code, bounded authentication scheme, and reason code; it sends no
second request. A response body, ambiguous framing, close token, HTTP/1.0, or
extra byte is terminal rather than a reconnect.

With Basic authentication the runtime may send credentials preemptively to the
configured proxy or perform one bounded retry after a 407 Basic challenge,
according to the sealed profile. There are at most two CONNECT exchanges. It
must not follow redirects, send credentials to a changed authority, echo an
arbitrary challenge, or offer an unconfigured scheme.
The client accepts no Basic `charset` parameter other than case-insensitive
`UTF-8`; absence still uses the explicit `BasicUtf8V1` encoding rather than a
locale code page. Duplicate/conflicting challenges or another charset are a
typed authentication failure.

HTTP CONNECT is TCP-only. Required UDP, CONNECT-UDP, or forward-proxy behavior
returns `ProtocolTransportUnsupported` before mutation.

### 11.3 HTTPS proxy plus CONNECT

`ExternalHttps` runs:

```text
ResolveProxyEndpoint
  -> BindOrProtectProxySocket { connection_role=TargetTunnel }
  -> ObserveRoute { connection_role=TargetTunnel }
  -> TcpConnectProxy { connection_role=TargetTunnel }
  -> VerifyConnectedLocalPeerIfHostLocal { connection_role=TargetTunnel }
  -> AuthenticateProxyTls
  -> VerifyIdentityTrustPolicyAndAlpn
  -> HTTP_CONNECT_EXCHANGE sequence from section 11.2
  -> ChallengeThroughTunnel
  -> Passed
```

The TLS transcript is between FlowProbe and the proxy endpoint. CONNECT then
targets the destination inside authenticated TLS. The proxy reference identity,
trust mode, pins if any, minimum/maximum TLS versions, algorithm policy,
revocation policy, and ALPN are exact plan inputs. Any TLS alert,
trust/identity/usage/validity failure,
unsupported algorithm, missing required revocation evidence, pin mismatch, or
ALPN mismatch closes the connection and forbids plaintext retry.

The local FlowProbe interception CA is excluded from proxy trust. Target TLS
inside the tunnel is not terminated or validated by this preactivation proxy-
transport step. Contract v1 declares no target-TLS probe profile; requesting one
is `UnsupportedPendingArchitecture/TargetTlsProbeContractUnavailable`.

### 11.4 SOCKS5 TCP

```text
ResolveProxyEndpoint
  -> BindOrProtectProxySocket { connection_role=TargetTunnel }
  -> ObserveRoute { connection_role=TargetTunnel }
  -> TcpConnectProxy { connection_role=TargetTunnel }
  -> VerifyConnectedLocalPeerIfHostLocal { connection_role=TargetTunnel }
  -> OfferExactMethods { connection_role=TargetTunnel }
  -> CompleteSelectedAuthentication { connection_role=TargetTunnel }
  -> SendCONNECTWithExactResolutionForm
  -> ValidateReply
  -> ChallengeThroughTunnel
  -> Passed
```

The method-offer bytes are a deterministic projection of the sealed selection:
`None` sends exactly `VER=0x05, NMETHODS=0x01, METHODS=[0x00]`, while
`UsernamePasswordUtf8V1` sends exactly
`VER=0x05, NMETHODS=0x01, METHODS=[0x02]`. The server-selected method must equal
that sole offered value. Offering `[0x00,0x02]`, a reordered/duplicate/empty
set, selecting `0x00` for a username/password profile, `NO ACCEPTABLE METHODS`,
malformed version, or unsupported subnegotiation is
`Socks5MethodUnsupported`. Username/password lengths must fit RFC 1929's one-
octet bounds and their values remain secret.
Connection EOF/read/write failure in the method exchange is
`ProxyConnectFailed`, not a fabricated protocol selection. For username/
password, inability to consume and deliver the one-use credential before its
first byte is `RuntimeCredentialDeliveryUnavailable`; a server rejection or
malformed RFC 1929 reply is `ProxyAuthenticationFailed`; later connection I/O is
`ProxyConnectFailed`. `None` records the authentication phase as
`NotApplicable` and never obtains a credential.

`ProxyName` sends SOCKS5 `ATYP=DOMAINNAME` with the normalized configured
destination name. `LocalAddress` sends only the sealed `ATYP=IPv4` or
`ATYP=IPv6` candidate. The implementation MUST NOT resolve a `ProxyName` locally
or send a hostname after `LocalAddress` was selected. An unrepresentable or
unsupported requested form is rejected at preflight without a protocol wrapper.
If the sealed runtime emits bytes other than the deterministic selected form,
the adapter is nonconforming and the wrapper is structurally invalid; it cannot
encode that mismatch as `Failed`. An I/O failure while writing the correct form
is `ProxyConnectFailed`.

A non-success reply is preserved as a bounded reply code and closes the
connection. `Socks5ReplyFailed` covers a non-success REP, malformed/truncated
reply, and EOF/read failure after the exact request; the bounded reply detail
never contains arbitrary proxy text. BIND is not supported.

### 11.5 SOCKS5 UDP ASSOCIATE

When `RequireAssociate` is selected, the section 11.4 connection is the target
CONNECT tunnel, role A. Its successful NonceEcho challenge includes the required
peer close; the runtime removes A from current-open provenance before it starts
the independent UDP-association control connection, role B. `Passed` is
therefore only the target-tunnel submachine marker for this policy. Proof and
active health then additionally run:

```text
BindOrProtectProxySocket { connection_role=Socks5UdpAssociationControl }
  -> ObserveRoute { connection_role=Socks5UdpAssociationControl }
  -> TcpConnectProxy { connection_role=Socks5UdpAssociationControl }
  -> VerifyConnectedLocalPeerIfHostLocal {
       connection_role=Socks5UdpAssociationControl
     }
  -> OfferExactMethods { connection_role=Socks5UdpAssociationControl }
  -> CompleteSelectedAuthentication {
       connection_role=Socks5UdpAssociationControl
     }
  -> EstablishedAuthenticatedSOCKS5Control
  -> SendUDP_ASSOCIATEWithUnspecifiedSameFamily
  -> ValidateRelayReply
  -> ClassifyAndExcludeRelay
  -> SendBoundedFRAG0Canary
  -> ValidateRelaySourceAndCanary
  -> AssociationReady
```

Role B is a new TCP connection to the same sealed proxy candidate and starts
with a fresh SOCKS5 greeting at byte zero. It repeats method negotiation and,
when configured, the RFC 1929 wire authentication by reusing only the credential
already held in protected memory by the same exact runtime; it creates no second
broker delivery, permit, descriptor, or artifact. B has a distinct connection
binding epoch, tag-31 child, platform socket identity, socket sequence, route
observation, and, for `HostLocal`, tag-6 connected-peer proof. It uses the
existing actor `ProxyControl` path declaration, TCP transport, and exact tag-4
`ProxyEndpointSet`; it performs no second resolution and may not change proxy
candidate, family, route, factory, actor, runtime, generation, or lease.

Role A has already consumed the one SOCKS5 `CONNECT` request and is tunnel data
thereafter. Emitting `UDP ASSOCIATE`, another greeting, or any other SOCKS
command on A is structurally nonconforming and produces no typed protocol
wrapper. Conversely, B may carry only greeting/authentication followed by the
single `UDP ASSOCIATE`; target challenge or CONNECT payload on B is invalid.
The two roles and their connection epochs/children must be distinct, with A's
factory socket sequence and TCP connection epoch strictly before B's.

The dedicated B TCP control connection remains open for the lifetime of the UDP
association. The reply is first parsed as one exact bounded RFC 1928 frame.
`VER` must be `0x05`, `RSV` must be `0x00`, `ATYP` must be `0x01`, `0x03`, or
`0x04`, its address length must match that ATYP exactly, and no byte may be
truncated or trail the encoded port. A wrong `VER`/`RSV`, unknown ATYP, invalid
domain length, truncation, or trailing byte is `Socks5RelayInvalid` at
`ValidateRelayReply`. After that structural check, any nonzero `REP` byte
(`0x01..=0xff`, including an unknown future value) is
`Socks5UdpAssociateFailed` at `ValidateRelayReply`; its bounded BND address and
port are not selected or retained and may contain port zero. Only `REP=0x00`
continues to successful-relay validation, where the relay address and port
returned in `BND.ADDR`/`BND.PORT` must
encode a public-global-unicast IPv4 address or an IPv6 address that needs no
scope, plus a nonzero port. A domain-form relay is the terminal typed failure
`Socks5RelayDomainUnsupported`; v1 starts no relay resolver child. Unspecified, wildcard,
multicast, metadata-service, link-local/scoped IPv6, private, on-link special-
use, HostLocal, or ambiguous-locality results are rejected as
`Socks5RelayInvalid`. RFC 1928's IPv6 ATYP has no scope field, so a scope is never
inferred from the control socket or interface. The literal singleton result set obeys the
sealed relay family policy, and its sole candidate must be public-
global-unicast `Remote`, and it is classified independently of both proxy
endpoint and destination.

A “valid domain-form relay” for the typed refusal is only the byte-exact
successful RFC 1928 reply form `VER=0x05, REP=0x00, RSV=0x00, ATYP=0x03`, length
`1..=255`, exactly that many opaque name octets, and nonzero `BND.PORT`, with no
truncation or trailing framing byte. It maps to
`Socks5RelayDomainUnsupported`; FlowProbe performs no IDNA processing,
normalization, retention, logging, resolution, DNS actor/path/child, UDP-child
release, or canary write. Zero length/port, truncated or extra framing, and an
unknown ATYP map only to `Socks5RelayInvalid`, also with zero resolver/UDP child/
canary bytes. `RelayIpv4Only` accepts only a public-Remote IPv4 literal,
`RelayIpv6Only` only a public-Remote unscoped IPv6 literal, and
`RelayAnyUnicast` either; family mismatch is `Socks5RelayInvalid`.
Phase attribution is unique even when the code is shared:
`ValidateRelayReply` owns only reply framing, ATYP, encoded length, and nonzero
port validation, including the valid-domain refusal; after a literal passes that
phase, `ClassifyAndExcludeRelay` alone owns family-policy, address-class,
scope/locality/route, and exclusion mismatch. An input cannot select the same
code under both phases.

The UDP ASSOCIATE request uses the closed `UnspecifiedSameFamily` profile. On an
IPv4 control socket it sends `VER=0x05, CMD=0x03, RSV=0x00, ATYP=0x01,
DST.ADDR=0.0.0.0, DST.PORT=0`; on an IPv6 control socket it sends `ATYP=0x04`,
sixteen zero address octets, and port zero. It never sends a domain name or a
destination endpoint in this request. Generated port zero is permitted only in
this protocol-specific request. The separate tag-50 zero-source-port variants
can record hostile received wire input but cannot construct or authorize an
`Endpoint`; neither case relaxes the general `Endpoint` port rule.
A request that selects any different form is `UnsupportedProtocolFeature` at
preflight, before a runtime wrapper or shared mutation exists. If a sealed
runtime nevertheless emits bytes other than the exact form above, the adapter is
nonconforming and the wrapper is structurally invalid; it cannot manufacture a
tag-50 or outer `Failed` outcome from that byte stream.

The same exact runtime may establish a bounded association during preactivation
proof, and the authenticated proof observation records the concrete relay/
result-set/locality, route, socket mechanism, and association identity. It must
close that control/relay socket before the factory's one-way phase transition.
V1 defines no root that transfers a preactivation socket into
`ResumeBarrierProtected`; therefore `RequireAssociate` is additionally
`UnsupportedPendingArchitecture/PreactivationSocketPhaseTransitionUnavailable`
until a later accepted contract closes that handoff. It cannot retain or
silently recreate the association through commit. If a future version closes
that handoff, `FullTunnel` SOCKS5 UDP
is supportable only when the pre-sealed exclusion uses an endpoint-independent
preventive per-socket/actor mechanism that already covers every permitted relay
candidate. A relay-selected endpoint can never synthesize a new privileged
bypass route, rule, or allowlist entry after plan sealing. If the platform needs
such an endpoint-specific mutation, `RequireAssociate` is unsupported. A host-
local relay is not permitted in v1: there is no UDP bound-owner/accepted-process
root or relay special-address authorization receipt. Therefore every HostLocal or non-public relay is
an unimplemented capability case named
`UnsupportedPendingArchitecture/Socks5HostLocalRelayIdentityUnavailable` in the
support report, while an observed runtime reply maps only to
`Socks5RelayInvalid` at `ClassifyAndExcludeRelay` and emits no UDP canary byte. It cannot be
promoted by the proxy endpoint's authorization.

Each UDP request/response requires `RSV=0x0000` and the exact RFC 1928 relay
header. The client sends only `FRAG=0`, accepts packets only from the sealed relay
endpoint and expected association, and drops any other source. A malformed RSV,
address, or length is dropped before delivery and fails health. A received
nonzero `FRAG` is first dropped without delivery or reassembly; the association
health then reports the bounded `Socks5FragmentationUnsupported` error and
denies activation/renewal.

The destination address form follows the selection's single
`DestinationResolutionPolicy`: `ProxyName` uses the domain form and reports the
destination family as `ProxyOpaque`; `LocalAddress` uses only a locally resolved
sealed family candidate.
The association terminates when its TCP control connection terminates. Control
loss, relay change, source mismatch, policy drift, or canary failure denies
lease renewal; the generation does not recreate the association through a
different relay or fall back to direct UDP. ARCH-004 must define application
datagram behavior before product UDP support can become ready.

## 12. Registered `egress.*` extension

### 12.1 Resource and predicate kinds

This contract registers only these closed v1 kinds:

| Kind | Class | Purpose |
| --- | --- | --- |
| `egress.baseline-anchor.v1` | Observation predicate | Stable baseline interface/route/resolver identity and epoch |
| `egress.endpoint-resolution.v1` | Observation predicate | Sealed proxy/target address set, locality, resolver and route evidence |
| `egress.local-proxy-identity.v1` | Observation predicate | Stable local listener/process/executable/policy identity |
| `egress.actor-socket-policy.v1` | External runtime resource/predicate | One sealed actor-wide socket-factory invariant plus bounded child observations |
| `egress.loop-gate.v1` | ARCH-001 predicate contribution | Egress predicates attached to the one existing `ResumeBarrier`; not another gate/resource |
| `egress.preactivation-proof.v1` | Observation predicate | Exact selection proof before shared OS mutation |
| `egress.postactivation-canary.v1` | Observation predicate | Exact selected egress path and zero-capture-traversal proof after steering, before commit |
| `egress.sustained-health.v1` | Lease predicate | Fresh selection, identity, exclusion and path evidence while active |

No kind accepts a shell command, executable, arbitrary path, raw firewall/
route request, user sing-box JSON, arbitrary WFP/netlink/System Configuration
blob, dynamic native plugin, credential, TLS private material, or captured data.

The stems `egress.endpoint-bypass-route.*`, `egress.policy-route.*`, and
`egress.actor-identity-policy.*` are reserved but **not registered** by v1. The
reviewed platform candidates do not yet supply exact, safely compensable helper
schemas. A plan that needs any such mutation is
`UnsupportedPendingArchitecture`; it cannot send a generic payload under a
reserved name. A later accepted architecture contract must register a new
version with every exact field, identity, before/after image, one-OS-call
operation, CAS rule, compensation, recovery rule, canonical tag/vector, and
real-host gate required by the Privileged Network Helper contract.

### 12.2 Exact actor-socket resource

`egress.actor-socket-policy.v1` is the only v1 egress resource with an apply
step. The step installs one actor-wide socket-factory invariant through one
ARCH-001 external permit; it is not an external apply step per future socket and
never changes shared OS state:

```text
ActorSocketFactoryPolicyV1 = {
  factory_policy_id,
  actor_id,
  component_instance_id,
  runtime_instance_id?,
  platform_profile: SocketFactoryPlatformProfileV1,
  factory_build_identity: FactoryBuildIdentityV1,
  socket_creation_enforcement_policy:
    SocketCreationEnforcementPolicyV1,
  allowed_path_purposes,
  address_families,
  transports,
  baseline_anchor_digest,
  mechanism_set,
  socket_identity_recipe: SocketIdentityRecipeV1,
  pre_byte_release_authority = SocketFactoryExecutorUnderSealedInvariant,
  release_phase_policy = PreactivationThenResumeBarrierProtectedV1,
  release_phase_latch =
    MonotonicPreactivationToResumeBarrierProtectedBeforeSteeringV1,
  local_fail_closed_release_predicate:
    LocalFailClosedReleasePredicateV1,
  local_release_guard,
  census_snapshot_barrier_id,
  census_snapshot_deadline,
  factory_epoch,
  initial_socket_sequence = 0,
  maximum_open_sockets,
  maximum_new_sockets_per_lease_epoch,
  observation_accumulator = Sha256ChainV1,
  capability_report_digests,
  helper_observation_nonce_slot,
  apply_deadline,
  observation_freshness,
  compensation,
}

SocketFactoryCompensationV1 =
  | StopExactOwnedComponent {
      termination_slot: OwnedComponentTerminationSlotV1,
    }
  | RevokeExactCooperativeFactoryLease {
      actor_id,
      component_instance_id,
      runtime_instance_id?,
      cooperative_factory_lease_identity,
      provider_identity: CooperativeProviderIdentityV1,
      profile: CooperativeProtectProfileV1,
    }

OwnedComponentTerminationSlotV1 = {
  termination_slot_id,
  actor_id,
  component_instance_id,
  runtime_instance_id?,
  binding = LateBoundByActorSocketPolicyApply,
}

SocketFactoryPlatformProfileV1 =
  | WindowsNative
  | LinuxNative
  | DarwinNative
  | CooperativeOnWindows
  | CooperativeOnLinux
  | CooperativeOnDarwin
  | HermeticTestOnly

LocalSocketReleaseGuardV1 = {
  observation_queue_id,
  consumer_set = HelperAndWatchdog,
  delivery = AppendOnlyMultiReaderFanout,
  capacity_accounting = SlowestConsumerCursor,
  maximum_pending_observations,
  enqueue_deadline,
  release_order = SignedChildEnqueuedBeforeProtocolBytes,
  verification_sequence_admission =
    ExclusiveReservedChildReleaseUntilAcceptedOuterResultV1,
  ordinary_release_batch_completion =
    CompleteApplicableFactoryAdmissionReleaseBatchRequiredV1,
  ordinary_acceptance_event_gate =
    SamePlanGenerationAcceptanceEventGateV1,
  authoritative_state_index =
    SoleArch001ProtectedIndexWithFactoryAdmissionReleaseExtensionV1,
  current_release_index_writer = ExistingArch001ProtectedIndexWriter,
  current_release_index_read =
    RegisteredArch001AuthenticatedReleaseProofReadRequiredV1,
  channel_failure = CloseSocketAndFailFactoryEpoch,
}

FactoryBuildIdentityV1 = {
  package_name,
  package_version,
  source_revision_sha256,
  factory_binary_sha256,
  dependency_lock_sha256,
}

SocketCreationEnforcementPolicyV1 =
  | PreventiveSyscallBroker {
      policy_instance_identity,
      sole_socket_entrypoint = SealedFactoryBroker,
      alternate_socket_entrypoints = Denied,
    }
  | PreventiveSandboxDenyExceptFactory {
      policy_instance_identity,
      sole_socket_entrypoint = SealedFactoryApi,
      alternate_socket_entrypoints = Denied,
    }
  | CooperativeFactoryLease {
      cooperative_factory_lease_identity,
      provider_identity: CooperativeProviderIdentityV1,
      profile: CooperativeProtectProfileV1,
      alternate_socket_entrypoints = AttestedDenied,
    }

SocketIdentityRecipeV1 =
  | WindowsKernelSocketHandleIdentityV1
  | LinuxSocketCookieInodeNamespaceV1
  | DarwinKernelSocketIdentityV1
  | CooperativeProviderSocketIdentityV1
  | HermeticFakeSocketIdentityV1

LocalFailClosedReleasePredicateV1 = {
  exact_mechanism_readback = Required,
  exact_route_and_interface_readback = Required,
  host_local_peer_binding = RequiredWhenHostLocal,
  phase_release_evidence = Required,
  verification_admission_binding = Required,
  signed_queue_append_before_first_protocol_byte = Required,
  first_protocol_byte_expiry_recheck = Required,
  any_invariant_failure = CloseSocketAndFailFactoryEpoch,
}

SocketMechanismV1 =
  | WindowsUnicastInterface {
      interface_luid,
      compartment_id,
      ipv4 = Absent | Present {
        live_index_host_u32,
        setsockopt_payload_be_bytes_4,
      },
      ipv6 = Absent | Present {
        live_index_host_u32,
      },
    }
  | LinuxBindToDevice {
      network_namespace_identity,
      interface_stable_identity,
      live_ifindex_locator,
      live_ifname_bytes,
      setsockopt_payload_bytes,
      setsockopt_optlen,
    }
  | LinuxBindToIfIndex {
      network_namespace_identity,
      interface_stable_identity,
      live_ifindex_i32,
      fallback_policy = Prohibited,
    }
  | LinuxSocketMark {
      network_namespace_identity,
      socket_mark_value_u32,
      policy_rule_mark_u32,
      policy_rule_mask_u32,
      preexisting_policy_route: LinuxPolicyRouteExpectationV1,
    }
  | DarwinBoundInterface {
      interface_stable_identity,
      live_ifindex_locator,
      ipv4_option = IP_BOUND_IF,
      ipv6_option = IPV6_BOUND_IF,
    }
  | CooperativeProtect {
      provider_identity: CooperativeProviderIdentityV1,
      profile: CooperativeProtectProfileV1,
      attestation_policy: CooperativeAttestationPolicyV1,
    }
  | HermeticFakeSocketMechanism {
      fixture_mechanism_identity,
    }

LinuxPolicyRouteExpectationV1 = {
  network_namespace_identity,
  socket_mark_value_u32,
  policy_rule_mark_u32,
  policy_rule_mask_u32,
  selected_rule_priority,
  selected_rule_table,
  selected_rule_action = LookupTable,
  higher_priority_rules,
  lookup_family_scope,
  resulting_route: BaselineRouteTupleV1,
  baseline_anchor_digest,
  interface_epoch,
  route_epoch,
  observed_at,
  expires_at,
}

LinuxPolicyRuleV1 = {
  priority,
  mark_u32,
  mask_u32,
  action,
  table?,
}

CooperativeProviderIdentityV1 = {
  provider_public_key_bytes,
  package_name,
  package_version,
  binary_sha256,
}

CooperativeProtectProfileV1 = {
  profile_id,
  protocol_version,
  covered_families,
  covered_transports,
  covered_path_purposes,
  baseline_anchor_digest,
}

CooperativeAttestationPolicyV1 = {
  challenge_bytes = 32,
  signature_algorithm = Ed25519,
  freshness_bound,
  replay_scope = PlanGenerationFactoryAndSocketSequence,
}

SocketFactoryPolicyObservationV1 = {
  prepared_plan_digest,
  helper_assigned_observation_nonce,
  generation,
  factory_policy_id,
  actor_id,
  component_instance_id,
  runtime_instance_id?,
  platform_profile: SocketFactoryPlatformProfileV1,
  actor_socket_factory_policy_digest,
  compensation_binding: SocketFactoryCompensationBindingV1,
  factory_build_identity: FactoryBuildIdentityV1,
  socket_creation_enforcement_readback:
    SocketCreationEnforcementReadbackV1,
  factory_epoch,
  next_socket_sequence = 0,
  alternate_socket_path_absence: AlternateSocketPathAbsenceV1,
  observation_queue_id,
  local_release_guard_readback: LocalSocketReleaseGuardReadbackV1,
  release_phase_latch_state = Preactivation { transition_counter = 0 },
  verification_admission_state = Open {
    transition_counter = 0,
    release_authority = InitialFactoryObservation,
    release_scope = VerificationOnly,
  },
  census_snapshot_barrier_id,
  census_snapshot_barrier_readback: CensusSnapshotBarrierReadbackV1,
  observed_at,
  expires_at,
  authenticators,
}

SocketFactoryCompensationBindingV1 =
  | OwnedComponent {
      termination_slot: OwnedComponentTerminationSlotV1,
      retained_process_identity: RetainedProcessIdentityV1,
      observed_resource_identity,
      binding_state = BoundInHelperApplyJournal,
      bound_at,
    }
  | CooperativeFactory {
      cooperative_factory_lease_identity,
      provider_identity: CooperativeProviderIdentityV1,
      profile: CooperativeProtectProfileV1,
      binding_state = BoundInHelperApplyJournal,
      bound_at,
    }

SocketCreationEnforcementReadbackV1 = {
  capability_report_digest,
  policy: SocketCreationEnforcementPolicyV1,
  policy_instance_state = Active,
  sole_entrypoint_state = Enforced,
  alternate_entrypoint_state = Denied,
  read_back_at,
}

AlternateSocketPathAbsenceV1 = {
  query_scope = ExactActorProcessOrCooperativeScope,
  alternate_entrypoint_count = 0,
  unmediated_open_socket_count = 0,
  query_completed_at,
}

LocalSocketReleaseGuardReadbackV1 = {
  guard: LocalSocketReleaseGuardV1,
  producer_cursor = 0,
  helper_cursor = 0,
  watchdog_cursor = 0,
  queue_state = EmptyAndWritable,
  current_release_index_value:
    FactoryAdmissionReleaseCurrentIndexV1::BoundClosed,
  verification_admission_state = Open {
    transition_counter = 0,
    release_authority = InitialFactoryObservation,
    release_scope = VerificationOnly,
  },
  observed_at,
}

CensusSnapshotBarrierReadbackV1 = {
  census_snapshot_barrier_id,
  barrier_epoch = 0,
  lifecycle_counter,
  state = Ready,
  observed_at,
}

SocketPolicyChildObservationV1 = {
  prepared_plan_digest,
  generation,
  lease_epoch,
  factory_policy_id,
  platform_profile: SocketFactoryPlatformProfileV1,
  factory_epoch,
  socket_sequence,
  new_socket_count_in_lease_epoch,
  observation_queue_id,
  socket_identity: PlatformSocketIdentityV1,
  actor_id,
  path_purpose,
  address_family,
  transport,
  endpoint_binding: PathEndpointBindingV1,
  selected_endpoint_digest,
  exact_mechanism_values,
  route_and_interface_observation:
    SocketRouteAndInterfaceObservationV1,
  release_phase_latch_state: FactoryReleasePhaseLatchV1,
  verification_admission_binding: SocketVerificationAdmissionBindingV1,
  release_phase_evidence: SocketReleasePhaseEvidenceV1,
  connected_local_peer_observation_digest?,
  observed_at,
  expires_at,
  authenticator,
}

SocketRouteAndInterfaceObservationV1 = {
  platform_family: PlatformFamilyV1,
  selected_endpoint_digest,
  mechanism_values,
  stable_interface_identity: PlatformStableInterfaceIdentityV1,
  namespace_or_compartment,
  resulting_route: BaselineRouteTupleV1,
  baseline_anchor_digest,
  flowprobe_capture_interface_selected = false,
  flowprobe_capture_route_or_table_selected = false,
  interface_epoch,
  route_epoch,
  observed_at,
}

SocketCloseFailureStepV1 =
  | CloseRequestFailed
  | CloseCompletionUnproven

SocketCensusFailureV1 =
  | FactoryCensusNegative {
      outcome: Overflow | Unavailable | InconsistentSnapshot,
    }
  | IndependentOsCensusNegative {
      outcome: Overflow | Unavailable | InconsistentSnapshot,
    }
  | CompleteCensusMismatch {
      mismatch: FactoryLifecycleCounter | SocketIdentitySet,
    }

FactoryTerminalFailureReasonV1 =
  | ObservationQueueUnavailable
  | ObservationQueueCapacityExceeded
  | OpenSocketLimitExceeded
  | LeaseSocketCreationLimitExceeded
  | SocketCreationFailed
  | SocketMechanismApplyFailed
  | SocketOptionReadbackFailed
  | SocketRouteReadbackFailed
  | SocketConnectInvariantFailed
  | ConnectedLocalPeerCheckFailed
  | ReleaseEvidenceInvalid
  | ReleasePhaseLatchInvalid
  | ChildObservationSigningFailed
  | AtomicChildPublicationFailed
  | FirstByteExpiryGuardFailed
  | ResumeBarrierTransitionFailed
  | SocketCloseFailed {
      socket_sequence,
      socket_policy_child_observation_digest,
      failed_step: SocketCloseFailureStepV1,
    }
  | SocketCensusFailed {
      failure: SocketCensusFailureV1,
    }
  | LifecycleInvariantFailed

FactoryVerificationSequenceContextV1 = {
  proof_specification_digest,
  target_profile_digest,
  observation_context: ProxyEvidenceObservationContextV1,
}

FactoryVerificationCapacityRequestV1 = {
  verification_sequence_id,
  sequence_context: FactoryVerificationSequenceContextV1,
  entry_open_socket_count: 0..=1024,
  entry_new_socket_count_in_lease_epoch: 0..=4096,
  reserved_incremental_open_socket_peak: 1..=1024,
  reserved_total_new_socket_count: 1..=4096,
  first_reserved_socket_sequence,
  reserved_socket_sequence_end_exclusive,
  deadline,
}

FactoryVerificationReservationV1 = {
  capacity_request: FactoryVerificationCapacityRequestV1,
  capacity_result = AcceptedWithinBothLimits,
}

FactoryVerificationAdmissionCandidateV1 = {
  prepared_plan_digest,
  generation,
  lease_epoch,
  factory_policy_id,
  factory_epoch,
  verification_sequence_id,
  sequence_context: FactoryVerificationSequenceContextV1,
  requested_incremental_open_socket_peak: 1..=1024,
  requested_total_new_socket_count: 1..=4096,
  prior_open_state: VerificationAdmissionPriorOpenStateV1,
  deadline,
}

VerificationAdmissionOpenAuthorityV1 =
  | InitialFactoryObservation
  | PreactivationProofPassed {
      egress_path_proof_result_digest,
      outer_publication_ordinal,
      release_serialization_ordinal,
    }
  | PostactivationCommitAccepted {
      postactivation_canary_result_digest,
      outer_publication_ordinal,
      disposition_serialization_ordinal,
      release_serialization_ordinal,
      release_batch: FactoryAdmissionReleaseBatchBindingV1,
      activation_commit_receipt: ActivationCommitReceiptV1,
    }
  | RenewalLeaseAccepted {
      sustained_egress_health_digest,
      outer_publication_ordinal,
      disposition_serialization_ordinal,
      release_serialization_ordinal,
      release_batch: FactoryAdmissionReleaseBatchBindingV1,
      lease_renewed_receipt: LeaseRenewedReceiptV1,
    }

FactoryAdmissionReleaseBatchBindingV1 = {
  release_batch_id,
  ordered_factory_policy_ids: 1..=32,
  factory_release_index: 1..=32,
}

FactoryAdmissionReleaseBatchMemberV1 = {
  factory_policy_id,
  release_accumulator_digest,
  release_serialization_ordinal,
}

FactoryAdmissionReleaseBatchCompletionV1 =
  | Postactivation {
      release_batch_id,
      prepared_plan_digest,
      generation,
      activation_lease_id,
      lease_epoch,
      fence_token_digest,
      postactivation_canary_result_digest,
      outer_publication_ordinal,
      disposition_serialization_ordinal,
      activation_commit_receipt: ActivationCommitReceiptV1,
      ordered_members: 1..=32 FactoryAdmissionReleaseBatchMemberV1,
      batch_completion_serialization_ordinal,
      completed_at,
      expires_at,
      authenticators: 2 ExternalObservationAuthenticatorV1,
    }
  | Renewal {
      release_batch_id,
      prepared_plan_digest,
      generation,
      activation_lease_id,
      lease_epoch,
      fence_token_digest,
      sustained_egress_health_digest,
      outer_publication_ordinal,
      disposition_serialization_ordinal,
      lease_renewed_receipt: LeaseRenewedReceiptV1,
      ordered_members: 1..=32 FactoryAdmissionReleaseBatchMemberV1,
      batch_completion_serialization_ordinal,
      completed_at,
      expires_at,
      authenticators: 2 ExternalObservationAuthenticatorV1,
    }

FactoryAdmissionReleasePendingDispositionV1 =
  | Postactivation {
      prior_release = NeverCommitted,
      postactivation_canary_result_digest,
      outer_publication_ordinal,
      disposition_serialization_ordinal,
      activation_commit_receipt: ActivationCommitReceiptV1,
    }
  | Renewal {
      prior_release: Committed {
        release_batch_completion_digest,
        batch_tip: Arch001JournalTipV1,
      },
      sustained_egress_health_digest,
      outer_publication_ordinal,
      disposition_serialization_ordinal,
      lease_renewed_receipt: LeaseRenewedReceiptV1,
    }

FactoryAdmissionReleaseCurrentIndexV1 =
  | Unset { index_epoch = 0 }
  | BoundClosed {
      index_epoch,
      prepared_plan_digest,
      generation,
      ordered_factory_policy_ids: 1..=32,
      bind_parent_journal_tip: Arch001JournalTipV1,
      index_checksum_sha256,
    }
  | ReleasePending {
      index_epoch,
      prepared_plan_digest,
      generation,
      ordered_factory_policy_ids: 1..=32,
      release_batch_id,
      pending_disposition: FactoryAdmissionReleasePendingDispositionV1,
      disposition_observed_at,
      release_deadline,
      disposition_tip: Arch001JournalTipV1,
      index_checksum_sha256,
    }
  | Committed {
      index_epoch,
      prepared_plan_digest,
      generation,
      ordered_factory_policy_ids: 1..=32,
      release_batch_id,
      release_batch_completion_digest,
      batch_tip: Arch001JournalTipV1,
      committed_record_count: 2..=33,
      index_checksum_sha256,
    }
  | GenerationClosed {
      index_epoch,
      prepared_plan_digest,
      generation,
      ordered_factory_policy_ids: 1..=32,
      prior_release:
        NeverCommitted |
        Committed { release_batch_completion_digest },
      reason = PreparationAborted | NormalStopFinalized |
               FencedRollbackOrRecovery,
      close_parent_journal_tip: Arch001JournalTipV1,
      index_checksum_sha256,
    }

VerificationAdmissionReleaseScopeV1 =
  | VerificationOnly
  | OrdinaryAndVerification

ActivationCommitReceiptV1 = {
  session_id,
  attempt_id,
  prepared_plan_id,
  plan_digest,
  generation,
  controller_id,
  connection_binding_epoch,
  activation_lease_id,
  lease_epoch,
  fence_token_digest,
  postactivation_canary_result_digest,
  resume_barrier_operation_digest,
  resume_barrier_observed_state_digest,
  required_resume_barrier_state = OpenForExactGeneration,
  continuous_expires_at,
  commit_state = CommittedDurable,
  committed_state_revision,
  commit_journal_head_digest,
  committed_at,
}

LeaseRenewedReceiptV1 = {
  request_id,
  idempotency_key,
  session_id,
  attempt_id,
  generation,
  prepared_plan_id,
  plan_digest,
  controller_id,
  connection_binding_epoch,
  activation_lease_id,
  lease_epoch,
  fence_token_digest,
  consumed_renewal_challenge_nonce,
  continuous_expires_at,
  renewal_evidence_digest,
  next_renewal_challenge_nonce,
  next_challenge_expires_at,
  outcome_kind = Success,
  response_variant = LeaseRenewed,
  state_revision_at_result,
  journal_head_digest_at_result,
}

VerificationAdmissionPriorOpenStateV1 =
  | InitialFactoryObservation {
      socket_factory_policy_observation_digest,
      transition_counter = 0,
    }
  | OpenAccumulator {
      socket_observation_accumulator_digest,
      transition_counter,
    }

FactoryVerificationTerminalContextV1 =
  | CandidateCapacityRejected {
      capacity_request: FactoryVerificationCapacityRequestV1,
    }
  | CandidateAdmissionObservationFailed {
      candidate: FactoryVerificationAdmissionCandidateV1,
    }
  | ActiveSequence {
      reservation: FactoryVerificationReservationV1,
    }
  | PendingSequenceNotAdmitted {
      verification_sequence_id,
      sequence_context: FactoryVerificationSequenceContextV1,
      prior_open_state: VerificationAdmissionPriorOpenStateV1,
      deadline,
    }
  | NoActiveSequence {
      prior_open_state: VerificationAdmissionPriorOpenStateV1,
    }

FactoryVerificationAdmissionStateV1 =
  | Open {
      transition_counter,
      release_authority: VerificationAdmissionOpenAuthorityV1,
      release_scope: VerificationAdmissionReleaseScopeV1,
    }
  | Exclusive {
      transition_counter,
      stage: Running | FinalizedHeld,
      reservation: FactoryVerificationReservationV1,
    }
  | TerminalHeld {
      transition_counter,
      terminal_context: FactoryVerificationTerminalContextV1,
      factory_terminal_transition_counter,
      factory_terminal_failure_reason: FactoryTerminalFailureReasonV1,
    }

VerificationSocketRoleV1 =
  | PrimaryConnector
  | Socks5UdpAssociationControl
  | Socks5UdpRelay

SocketVerificationAdmissionBindingV1 =
  | Ordinary {
      most_recent_open_accumulator_digest,
      admission_transition_counter,
      release_batch_completion_digest,
    }
  | Reserved {
      verification_sequence_id,
      sequence_admission_accumulator_digest,
      admission_transition_counter,
      reserved_release_ordinal,
      verification_socket_role: VerificationSocketRoleV1,
    }

FactoryReleasePhaseLatchV1 =
  | Preactivation { transition_counter = 0 }
  | ResumeBarrierProtected {
      transition_counter,
      resume_barrier_resource_id,
      activation_lease_id,
      lease_epoch,
      fence_token_digest,
    }
  | TerminalFailed {
      transition_counter,
      reason: FactoryTerminalFailureReasonV1,
    }

SocketReleasePhaseEvidenceV1 =
  | Preactivation {
      external_executor_gate_readback,
      socket_factory_policy_observation_digest,
    }
  | ResumeBarrierProtected {
      resume_barrier_resource_id,
      resume_barrier_operation_digest,
      resume_barrier_observed_resource_identity,
      resume_barrier_observed_state_digest,
      activation_lease_id,
      lease_epoch,
      fence_token_digest,
      required_state = OpenForExactGeneration,
    }

ExternalExecutorGateReadbackV1 = {
  prepared_plan_digest,
  permit_id,
  runtime_or_component_instance_id,
  gate_channel_binding_digest,
  state = RedeemedForPreactivationOnly,
}

SocketCensusAddressFamilyV1 =
  | Ipv4
  | Ipv6
  | OtherExternalNetworkFamily

SocketCensusTransportV1 =
  | Tcp
  | Udp
  | RawOrOtherExternalTransport

NativePlatformSocketIdentityV1 =
  | WindowsTransportEndpointHandle {
      transport_endpoint_handle_u64,
      owner_process_id_u32,
      owner_process_creation_filetime_u64,
      compartment_id_u32,
      boot_epoch,
    }
  | LinuxSocketCookieInode {
      socket_cookie_u64,
      socket_inode_u64,
      network_namespace_identity,
      boot_epoch,
    }
  | DarwinKernelSocketGeneration {
      kernel_socket_id_u64,
      pcb_generation_u64,
      owner_process_id_i32,
      owner_pidversion_u32,
      boot_epoch,
    }

PlatformSocketIdentityV1 =
  | Native { identity: NativePlatformSocketIdentityV1 }
  | CooperativeProviderSocket {
      provider_public_key_bytes,
      protocol_version,
      profile_id,
      cooperative_factory_lease_identity,
      provider_socket_id_bytes_16,
      underlying_native_identity: NativePlatformSocketIdentityV1,
    }
  | HermeticFakeSocket {
      fixture_socket_ordinal_u64,
      fixture_namespace_identity,
    }

SocketCensusNamespaceIdentityV1 =
  | WindowsCompartment { compartment_id_u32 }
  | LinuxNetworkNamespace { network_namespace_identity }
  | DarwinHostNetworkStack { boot_epoch }
  | HermeticFakeNamespace { fixture_namespace_identity }

SocketIdentityTupleV1 = {
  platform_socket_identity: PlatformSocketIdentityV1,
  owner_process_or_cooperative_scope_identity: SocketCensusOwnerIdentityV1,
  network_namespace_or_compartment_identity:
    SocketCensusNamespaceIdentityV1,
  census_address_family: SocketCensusAddressFamilyV1,
  census_transport: SocketCensusTransportV1,
}

SocketCensusScopeV1 = {
  actor_id,
  component_instance_id,
  runtime_instance_id?,
  owner_scope_identity: SocketCensusOwnerIdentityV1,
  network_namespace_or_compartment_identity:
    SocketCensusNamespaceIdentityV1,
  address_family_scope = AllExternalNetworkFamilies,
  transport_scope = AllExternalNetworkTransports,
  states = AllSocketStateV1,
}

SocketCensusOwnerIdentityV1 =
  | ExactOwnedRuntimeProcess {
      actor_identity: ActorIdentityV1,
      retained_process_identity: RetainedProcessIdentityV1,
    }
  | ExactCooperativeScope {
      actor_identity: ActorIdentityV1,
      exclusion_policy_identity: ExclusionPolicyIdentityV1,
      cooperative_factory_lease_identity,
    }

SocketCensusSnapshotContextV1 = {
  helper_census_challenge_nonce,
  census_snapshot_barrier_id,
  snapshot_barrier_epoch,
  census_scope,
  deadline,
}

SocketIdentitySetV1 = {
  prepared_plan_digest,
  generation,
  lease_epoch,
  snapshot_context,
  sorted_unique_socket_tuples,
}

OpenSocketProvenanceV1 = {
  platform_socket_identity: PlatformSocketIdentityV1,
  socket_policy_child_observation_digest,
  socket_sequence,
}

SocketClosureCauseV1 =
  | VerificationProtocolClose {
      verification_sequence_id,
      attempt_ordinal: 1..=32,
    }
  | VerificationSequenceCleanup { verification_sequence_id }
  | OrdinaryLocal
  | PeerOrOs {
      terminal_event_serialization_ordinal?,
    }

SocketClosureTransitionV1 = {
  lifecycle_transition_ordinal,
  socket_sequence,
  socket_policy_child_observation_digest,
  cause: SocketClosureCauseV1,
}

FactorySocketCensusObservationV1 = {
  prepared_plan_digest,
  generation,
  lease_epoch,
  factory_policy_id,
  factory_epoch,
  observation_queue_id,
  snapshot_context,
  observed_socket_identity_set_digest,
  sorted_open_socket_provenance,
  new_socket_count_in_lease_epoch,
  release_phase_latch_state: FactoryReleasePhaseLatchV1,
  verification_admission_state: FactoryVerificationAdmissionStateV1,
  lifecycle_counter_before,
  lifecycle_counter_after,
  observed_at,
  expires_at,
  outcome,
  authenticator,
}

OsSocketCensusV1 = {
  prepared_plan_digest,
  generation,
  lease_epoch,
  snapshot_context,
  capability_report_digest,
  current_socket_creation_enforcement_readback:
    SocketCreationEnforcementReadbackV1,
  current_alternate_socket_path_absence:
    AlternateSocketPathAbsenceV1,
  discovery_backend_build_identity: DiscoveryBackendBuildIdentityV1,
  independently_observed_socket_identity_set_digest,
  query_started_at,
  query_completed_at,
  outcome,
  authenticator,
}

DiscoveryBackendBuildIdentityV1 = {
  backend,
  backend_version,
  package_version,
  source_revision_sha256,
  backend_binary_sha256,
  dependency_lock_sha256,
}

SocketCensusOutcomeV1 =
  | Complete
  | Overflow
  | Unavailable
  | InconsistentSnapshot

SocketObservationDeltaV1 =
  | Empty {
      next_socket_sequence,
    }
  | NonEmpty {
      first_socket_sequence,
      last_socket_sequence,
      child_observation_count,
      next_socket_sequence,
    }

FactoryClosureProjectionV1 =
  | CompleteFactoryProjection {
      closure_transitions_since_previous_accumulator:
        0..=5120 SocketClosureTransitionV1,
    }
  | Unproven

SocketObservationSnapshotProjectionV1 =
  | Complete {
      closure_transitions_since_previous_accumulator:
        0..=5120 SocketClosureTransitionV1,
      factory_socket_census_observation_digest,
      independent_os_socket_census_digest,
    }
  | CensusNegative {
      factory_socket_census_observation_digest,
      independent_os_socket_census_digest,
      failure: SocketCensusFailureV1,
      factory_closure_projection: FactoryClosureProjectionV1,
    }

SocketObservationAccumulatorV1 = {
  prepared_plan_digest,
  generation,
  lease_epoch,
  factory_policy_id,
  factory_epoch,
  observation_queue_id,
  snapshot_context,
  sequence_delta,
  previous_accumulator_digest?,
  starting_chain_digest,
  final_chain_digest,
  snapshot_projection: SocketObservationSnapshotProjectionV1,
  observed_at,
  expires_at,
  helper_authenticator,
  watchdog_authenticator,
}
```

`mechanism_set` is a non-empty canonical list of at most three complementary
variants; unknown, duplicate, contradictory, or irrelevant family mechanisms
are rejected. `maximum_open_sockets` is in `1..=1024` and
`maximum_new_sockets_per_lease_epoch` in `1..=4096`; exceeding either limit
closes the socket before first protocol bytes and fails health.
Plan preflight enumerates the exact incremental peak and cumulative counts for
the complete serial attempt tree. Each reached `RequireAssociate` attempt may allocate A, B,
and C in order; A closes before B starts, while a successful active group retains
B+C as later groups execute. The mandatory success-side close-only teardown
creates no child and leaves zero verification child current-open for the next
canary or renewal sequence while preserving the chain, so capacity never
assumes cross-sequence verification retention. Before the first attempt, the
live factory's mandatory admission transaction requires both its current actor-
wide open count plus that incremental peak to be no greater than
`maximum_open_sockets` and its current lease-new count plus the exact complete-
tree child total to be no greater than
`maximum_new_sockets_per_lease_epoch`. Unrelated operational sockets and earlier
lease-epoch creations count rather than being assumed absent. Static
insufficiency rejects plan sealing; dynamic insufficiency selects respectively
`OpenSocketLimitExceeded` or `LeaseSocketCreationLimitExceeded` in the admission
root before any attempt child or protocol byte; when both dynamic sums exceed,
`OpenSocketLimitExceeded` wins. Exclusive admission then
prevents an unrelated release from stealing either reservation, so neither
limit may first fail after role A or an earlier group has emitted bytes.

The admission transition counter is a nonwrapping `u64`, starts at zero in the
tag-15 factory observation, and advances exactly once for `Open -> Exclusive`,
`Open -> TerminalHeld`, `Exclusive -> TerminalHeld`, or an authorized
`Exclusive -> Open` or receipt-bound `Open -> Open` batch transition. A direct Open-to-terminal transition is
legal only with one of these mutually exclusive contexts: (1)
`CandidateCapacityRejected` plus the exact over-limit capacity request and
capacity reason; (2) `CandidateAdmissionObservationFailed` plus the exact
pending candidate and canonical `SocketCensusFailed`; (3)
`PendingSequenceNotAdmitted` plus the byte-identical ID/context/deadline of an
admission request whose already-started ordinary operation terminalized; or (4)
`NoActiveSequence` for a standalone ordinary/lifecycle factory terminal with no
pending request. Each increments the admission counter and the independent
release-phase latch counter once in the same checkpoint. Context substitution,
a fabricated accepted reservation, or use of `NoActiveSequence` by an
`AdmissionAborted` wrapper is invalid.
`verification_sequence_id` and every nonce/ID are fixed 32-byte nonzero values;
the deadline is positive and no later than the enclosing overall deadline.
`reserved_socket_sequence_end_exclusive` equals
`first_reserved_socket_sequence + reserved_total_new_socket_count` without
overflow. An accepted reservation's embedded capacity request satisfies both
limits; a capacity-rejected request exceeds at least one and is never an
accepted reservation. `Running -> FinalizedHeld` does not change the admission
counter or reservation; it changes only the closed stage at the finalization
barrier. `TerminalHeld` is valid only with the byte-identical transition
counter/reason in tag 46's `FactoryReleasePhaseLatchV1::TerminalFailed` and is
irreversible. An active-sequence terminal uses the exact accepted reservation;
a candidate or no-active terminal may not do so.

`Exclusive -> Open` is legal only in the authenticated `Empty` tag-13 root or
the probe-factory member of a complete tag-28/tag-29 batch defined above.
`Open -> Open` is legal only for a non-probe member of one of those complete
batches: tag 28 changes `VerificationOnly` to `OrdinaryAndVerification` under
`PostactivationCommitAccepted`; tag 29 preserves
`OrdinaryAndVerification` while replacing the prior authority with the current
`RenewalLeaseAccepted` receipt. No other scope upgrade or authority refresh is
valid. For either receipt-bound authority, the member's displayed Open value and
counter increment are only conditional while staged and become effective for
all factories at the shared tag-56 index commit described above; an aborted
staged member is not a transition. `InitialFactoryObservation` and
`PreactivationProofPassed` pair only with
`VerificationOnly`; `PostactivationCommitAccepted` and `RenewalLeaseAccepted`
pair only with `OrdinaryAndVerification`. Sequence admission may start from
either Open scope, but an `Ordinary` child may start only from
`OrdinaryAndVerification` after the authority's complete batch is current. The
typed authority, receipt, full batch list/index/completion, outer/disposition/
release ordinals, corresponding outer-listed previous root, counter, plan/
generation/lease/fence, and release scope must all match their one legal branch.
At batch completion every prior Open authority is superseded; its older receipt
or expiry can authorize no later Ordinary operation. A counter skip/reuse,
wrong context, changed reservation, early/partial/duplicate Open, omitted or
reordered factory, Ordinary child under VerificationOnly, Exclusive, or an
incomplete batch, Reserved child under Open or FinalizedHeld, or child admitted
from an unauthenticated admission/Open accumulator is
`LifecycleInvariantFailed` and no later child may be released.
`platform_profile` closes the policy, observation, child, identity recipe,
mechanism list, baseline, and route-interface tuple. `WindowsNative` requires
the tag-11 baseline family `Windows`, exactly one `WindowsUnicastInterface`,
`WindowsKernelSocketHandleIdentityV1`, and a `WindowsInterface` in every child
route. `LinuxNative` requires baseline family `Linux`, a non-empty unique subset
of `LinuxBindToDevice`, `LinuxBindToIfIndex`, and `LinuxSocketMark` in that
displayed order, `LinuxSocketCookieInodeNamespaceV1`, and a `LinuxInterface`.
`DarwinNative` requires baseline family `Darwin`, exactly one
`DarwinBoundInterface`, `DarwinKernelSocketIdentityV1`, and a
`DarwinInterface`. Each `CooperativeOnWindows/Linux/Darwin` profile requires
exactly one `CooperativeProtect`, `CooperativeProviderSocketIdentityV1`, and the
corresponding real baseline/route-interface family. `HermeticTestOnly` requires
exactly one `HermeticFakeSocketMechanism`,
`HermeticFakeSocketIdentityV1`, a Hermetic baseline, a
`HermeticFakeInterface`, and only the hermetic physical-path capability report.
The tag-15 policy observation and every tag-31 child repeat the tag-14 profile
byte-for-byte; `SocketRouteAndInterfaceObservationV1.platform_family` is its
mapped family. A native/cooperative mix, cross-OS recipe, mechanism, baseline,
route identity, namespace/compartment, or real/fake member is invalid before a
socket can be released.

The socket identity mapping is equally closed. `WindowsNative`, `LinuxNative`,
and `DarwinNative` require respectively `PlatformSocketIdentityV1::Native` with
`WindowsTransportEndpointHandle`, `LinuxSocketCookieInode`, and
`DarwinKernelSocketGeneration`. Cooperative profiles require
`CooperativeProviderSocket` whose provider key/protocol/profile equal the sole
`CooperativeProtect` mechanism and whose `underlying_native_identity` is the
corresponding Windows/Linux/Darwin variant. `HermeticTestOnly` requires only
`HermeticFakeSocket`. The Windows transport endpoint handle, Linux cookie and
inode, Darwin socket ID and PCB generation, and all process/generation/fixture
ordinals are nonzero; provider keys are exactly 32 bytes and
`provider_socket_id_bytes_16` exactly 16 bytes. Owner-process, boot, compartment/
namespace, and platform values equal the retained owner and census scope.

Every tag-31 child, `SocketIdentityTupleV1`, open provenance item, connected-peer
root, and egress-bypass traversal item for one socket repeats that complete
identity byte-for-byte. In every tuple, owner scope and namespace/compartment
equal `snapshot_context.census_scope`; census family and transport equal the
child and its declared path. The factory and platform backend recover the
identity independently under the barrier. A PID, file descriptor, mutable
endpoint/TCP state, provider-only opaque ID, or expected tuple supplied to the
platform query cannot substitute. If the exact packaged Windows/Darwin backend
cannot expose the displayed stable kernel identity, or a cooperative provider's
underlying native identity cannot be enumerated independently, census is
`Unavailable` and that profile remains unsupported rather than synthesizing an
identity.

Every native profile additionally requires
`SocketCreationEnforcementPolicyV1` to be `PreventiveSyscallBroker` or
`PreventiveSandboxDenyExceptFactory`, compensation
`StopExactOwnedComponent`, and every census `owner_scope_identity` to be
`ExactOwnedRuntimeProcess` with the matching `WindowsRetainedProcess`,
`LinuxRetainedPidfdProcess`, or `DarwinRetainedAuditTokenProcess`. Every
cooperative profile instead requires `CooperativeFactoryLease`,
`RevokeExactCooperativeFactoryLease`, and `ExactCooperativeScope` whose
`CooperativeSocketBindingIdentity` repeats the exact provider key/protocol/
profile and fresh lease identity from its sole `CooperativeProtect`/enforcement
tuple. The same lease identity appears in every cooperative socket identity,
census scope, and compensation binding. `HermeticTestOnly`
requires `PreventiveSyscallBroker`, `StopExactOwnedComponent`, and
`ExactOwnedRuntimeProcess` with `HermeticFakeRetainedProcess`. Actor identity,
runtime optionality, owner namespace/compartment, and platform socket identity
in every factory/OS census equal that same profile. A native policy with a
cooperative lease/compensation/scope, a cooperative policy with an owned-
process scope, or a cross-platform retained-process identity is invalid.

Every compensation repeats the tag-14 actor, component, and optional runtime
identity byte-for-byte. A pre-plan `StopExactOwnedComponent` contains only its
fresh 32-byte `OwnedComponentTerminationSlotV1`; it never predicts a future PID,
process handle, pidfd, audit token, or process-start value. During the one
`egress.actor-socket-policy.v1` apply, after the component exists and before the
factory is accepted, the helper atomically binds that slot to the exact retained
process plus ARCH-001 observed resource identity in its apply journal. Tag 15's
`OwnedComponent` binding repeats the slot and actual retained identity, which
equals every `ExactOwnedRuntimeProcess` census owner. Compensation resolves only
that immutable journal binding and stops the retained object even when
`runtime_instance_id` is absent; an unbound/mismatched slot is
`UnsupportedPendingArchitecture/OwnedProcessCompensationBindingUnavailable`,
not authority to stop an arbitrary Network Runtime.

`RevokeExactCooperativeFactoryLease` and tag 15's `CooperativeFactory` binding
repeat the enforcement policy's fresh 32-byte lease identity, complete provider
identity, and complete profile. The helper journals that tuple before accepting
the factory. Response loss may replay only the byte-identical apply or
compensation result; a changed actor/process/provider/lease cannot be targeted.
`allowed_path_purposes` contains `1..=14` unique purpose tags,
`address_families` `1..=2` unique family tags, and `transports` `1..=2` unique
transport tags; each is ascending tag order and exactly matches the actor graph.
`capability_report_digests` is a canonical `3..=5` list. Its first entry is the
sole `SocketCreationEnforcement` report, its second is the sole `SocketCensus`
report, and the remaining entries contain exactly one
`Digest(CapabilityReportV1)` (tag 2) for each `mechanism_set` entry in that
variant order. For every real platform profile, all reports have `Supported`
disposition, `SupportedByDesign`, `Ready`, `RealHostVerified`, and a tag-53
release root for the exact policy tuple. They repeat the same pre-plan discovery
context but remain distinct roots because `capability_key` enters the signed
tag-53 build identity; one report/digest cannot satisfy two list positions.
The first report has `Preventive` enforcement and mechanism
`PreventiveSyscallBrokerV1`, `PreventiveSandboxDenyExceptFactoryV1`, or
`CooperativeAttestedSocketFactoryLeaseV1` exactly matching the policy variant.
The second has `Detective` enforcement and the profile-exact mechanism:
`WindowsTransportEndpointHandleCensusV1` for `WindowsNative`,
`LinuxSocketCookieInodeCensusV1` for `LinuxNative`,
`DarwinKernelSocketGenerationCensusV1` for `DarwinNative`, or
`CooperativeUnderlyingNativeSocketCensusV1` for a cooperative profile. Every
remaining report has key `PhysicalPathBinding`, `Preventive` enforcement, and
the exact corresponding mechanism:
`WindowsUnicastInterfaceV1`, `LinuxBindToDeviceV1`,
`LinuxBindToIfIndexV1`, `LinuxSocketMarkPolicyRouteV1`,
`DarwinBoundInterfaceV1`, or `CooperativeProtectV1`. Its platform/network scope,
actor class, endpoint localities, families, transports, mechanism version,
backend/package tuple, and release-evidence root cover this policy exactly.
Missing, extra, duplicate, reordered, unrelated-key, cross-mechanism,
narrower-scope, or non-ready reports make the policy invalid. The first and
physical-path reports are invalid unless `Preventive`; the census report is
invalid unless `Detective`;
no mechanism carries a second scalar capability-report digest.
The census report's family/transport collections cover every family/transport
authorized by tag 14, but they are not a query filter: the mechanism must still
enumerate `AllExternalNetworkFamilies`, `AllExternalNetworkTransports`, and
`AllSocketStateV1`, including the closed `Other*` categories. Inability to
enumerate an externally capable unsupported category makes the live census
`Unavailable` and the profile unsupported.
For `HermeticTestOnly`, the three entries are respectively the exact
`HermeticFakeSocketCreationEnforcementV1`, `HermeticFakeSocketCensusV1`, and
`HermeticFakePhysicalPathBindingV1` `HermeticFixtureValidation` tag-2 tuples
from section 6.2, all with `NotRealHostVerified` and no tag-53 root. They are
accepted only by the fixture verifier and are rejected by release preflight
before a socket factory can be installed.
Every child `exact_mechanism_values` contains exactly the same number of values
and the same variant order as the policy's `mechanism_set`; omission,
substitution, duplicate, or reordering fails before release.
`SocketRouteAndInterfaceObservationV1.mechanism_values` is byte-identical to
that same child list. Its route family, interface identity, namespace/
compartment, selected endpoint digest, baseline digest, interface epoch, and route epoch match the policy
and fresh baseline root; selecting either a FlowProbe capture interface or any
capture route/table is an invalid root rather than a boolean producer choice.
The child's `selected_endpoint_digest` always names the exact tag-33 peer
endpoint and is repeated by the route observation. With `ProxyEndpointSet` it is
a selectable candidate in that tag-4 `ProxyEndpoint` root; this covers
`ProxyControl` and the preactivation/canary/health connector of every external
proxy selection. It is the actual TCP proxy peer, never the target inside the
tunnel. With `ProbeTargetProfiles` the selected plan is `Direct` and the field
equals the endpoint selected by the exact tag-18 profile named by the enclosing
proof/canary/health root, including membership in that profile's resolved set. With
`ResolverPath` it equals an exact resolver endpoint authorized by the accepted
ARCH-004 binding for that tag-3 descriptor; until ARCH-004 supplies that typed
membership, the DNS socket is unsupported and sends zero bytes. With
`OwnedActorAllExternalEndpoints` it is still constrained by the enclosing typed
runtime-destination, SOCKS-relay, certificate-status, recovery, or telemetry
root. In particular a `Socks5UdpRelay` child names the exact selectable
candidate in the tag-50 association's tag-4 `Socks5Relay` checkpoint; it never
reuses the proxy-control candidate or a probe-target endpoint. The broad loop
scope alone is never endpoint authority.
`ExternalLocalProxyAllExternalEndpoints` is invalid in a FlowProbe factory child
because that independently owned process has no FlowProbe tag-14 factory; its
complete process/cooperative exclusion is proven by tag-9/tag-35 readback.
The optional connected-peer field obeys the HostLocal/Remote and exact
cross-root equality rules in section 8.3 before the child may be signed or
released; child signature validity alone never makes a mismatched peer root
applicable.

`FactoryBuildIdentityV1` uses the domain-separated source and dependency-lock
`ReleaseArtifactCorpusV1` identities plus SHA-256 of the exact single packaged
factory binary bytes. The policy and
factory observation repeat the whole structure byte-for-byte; no standalone
build or implementation evidence digest is accepted. The observation's
`actor_socket_factory_policy_digest` is exactly
`Digest(ActorSocketFactoryPolicyV1)` (tag 14). Its enforcement, alternate-path,
release-guard, and census-barrier values are the displayed closed readback
structures, not implementation-private hashes. Any readback mismatch, nonzero
alternate count, cursor drift at installation, changed barrier, or later
policy-instance drift fails the factory epoch.
`CooperativeProviderIdentityV1.binary_sha256` hashes the exact packaged provider
binary and its public key is the raw 32-byte Ed25519 key registered by the
package manifest; package text, a file path, or a provider-supplied profile hash
cannot substitute for the complete identity/profile/attestation structures.
For v1 cooperative enforcement, that provider and the sealed factory are the
same packaged enforcement binary: package name/version and binary digest equal
`FactoryBuildIdentityV1` and the first capability report/tag-53 tuple. A split
adapter/provider build needs a later multi-producer evidence contract and is
`UnsupportedPendingArchitecture`, not a second unregistered build hash.

Windows option values are derived from the LUID/compartment and verified with
`getsockopt` plus route query; the index is only a live locator. `ipv4` is
present exactly when the policy permits IPv4, `ipv6` exactly when it permits
IPv6, and at least one is present. The IPv4 live index is in
`1..=0x00ff_ffff`; zero/unspecified and values requiring the reserved high eight
bits are invalid. The IPv6 live index is in `1..=0xffff_ffff`; zero/unspecified
is invalid. `setsockopt_payload_be_bytes_4` is exactly the four-byte network-
order encoding of `live_index_host_u32`; it is bytes, not a CBOR integer.
IPv6 `IPV6_UNICAST_IF` uses the host-order value. Read-back is normalized to the
same host-order live index before comparison with the current LUID/compartment.
A dual-family policy must check both calls and both read-backs. The pinned sing
Windows helper ignores the
IPv6 error after an unspecified-address IPv4 bind, so pinned `bind_interface`
is `UnsupportedPendingArchitecture/PinnedWindowsBindAdapterNonconforming`; only
an exact single-family call or packaged adapter that checks both results and
read-backs may satisfy this mechanism.

`LinuxBindToIfIndex` requires a nonzero live ifindex in the exact network
namespace, encoded as positive `i32`, a registered `CapabilityReportV1` for the
exact kernel/backend/package tuple, successful option read-back, and
`fallback_policy=Prohibited`. A failed call
is terminal for that socket; it never flips a process-global switch or silently
retries `SO_BINDTODEVICE`. `LinuxBindToDevice` separately requires the exact
live interface name derived from the stable identity: `live_ifname_bytes` is
`1..=(IFNAMSIZ-1)` bytes with no embedded/trailing NUL and
`setsockopt_payload_bytes` is exactly `live_ifname_bytes || 0x00`, with
`setsockopt_optlen = len(live_ifname_bytes) + 1 <= IFNAMSIZ`. Read-back uses an
`IFNAMSIZ` buffer and the returned option length, requires exactly one terminal
NUL and no bytes after it, removes that NUL, and compares the remaining bytes to
`live_ifname_bytes`. It also requires resulting route/interface read-back. The pinned sing v0.8.13
`bind_interface` path first
tries `SO_BINDTOIFINDEX` and changes process-global behavior to
`SO_BINDTODEVICE` on selected errors. It therefore maps to neither closed
variant and is
`UnsupportedPendingArchitecture/PinnedLinuxBindInterfaceNonconforming` until a
versioned adapter seals one branch and prohibits fallback.

Linux `SO_MARK` writes exactly the complete native `u32
socket_mark_value_u32`; its `setsockopt` payload has no mask. The separate
`policy_rule_mark_u32/policy_rule_mask_u32` describe the pre-existing route-rule
match. `socket_mark_value_u32` and `policy_rule_mask_u32` are nonzero, and the
masked value is also nonzero. `getsockopt(SO_MARK)` must return the complete
written value. The sealed rule proof includes exact priority order, privilege/
capability variant, and every higher-priority rule; it must select one unique,
non-conflicting rule with no higher-priority recapture. A zero mark, zero mask,
zero masked value, missing privilege, or another matching rule/table is invalid.
Route lookup must prove
`(socket_mark & mask) == (rule_mark & mask)` and that the resulting route uses
the sealed baseline anchor.
It is valid only with an already observed administrator/previously
registered route policy whose complete `LinuxPolicyRouteExpectationV1` is in
the registered actor policy—v1 cannot create that policy. The expectation
repeats the enclosing mark/mask/namespace and baseline digest byte-for-byte;
`higher_priority_rules` contains `0..=64` unique `LinuxPolicyRuleV1` values in
strict priority order, and every proof/commit/renewal route readback must
reproduce the exact selected rule/table/resulting route while showing no higher
priority recapture. A stale epoch, truncated rule set, opaque route hash, or
tuple mismatch is invalid. Darwin options apply only to sockets whose exact packaged runtime
implementation is proven to call them; Network.framework evidence cannot be
projected onto Go/sing-box sockets. `CooperativeProtect` is accepted only for a
signed, versioned external proxy integration that attests every required socket;
it gives FlowProbe no process-control authority.

`SocketCensusScopeV1` means every network socket owned by the exact process/
runtime/cooperative enforcement identity in the named namespace or compartment,
across every external-network-capable family, transport, and state. It is never
narrowed to the policy's expected IPv4/IPv6 or TCP/UDP factory sockets. A
platform-fixed classifier maps an externally capable but unsupported family or
transport to the closed `Other*` variant; such a tuple can never match a valid
child and therefore fails the checkpoint. Exact local-only IPC already declared
by the actor graph is outside this census; if the backend cannot distinguish it
from an external-capable socket, the outcome is `Unavailable`, not omission.
Only fields both observers can independently recover—a stable kernel socket
cookie/handle, exact owner scope, namespace/compartment, census family, and
transport—form `SocketIdentityTupleV1`. Mutable TCP state/endpoints and
factory-only actor/epoch/sequence data are excluded from that shared
identity. `SocketIdentitySetV1` contains `0..=2048` unique tuples sorted by full
canonical bytes; more sockets produces `Overflow`, never truncation. Factory-
only child/sequence attribution is the separate canonical
`sorted_open_socket_provenance`, with `0..=1024` unique entries sorted by
`platform_socket_identity`.

At each proof/commit/renewal census, the helper supplies a fresh public 32-byte
challenge and the pre-sealed barrier ID; the factory advances a monotonic
`snapshot_barrier_epoch`. The common context deadline is positive, no more than
one second, and within the parent observation deadline. Under its lifecycle
lock the factory pauses new socket release and close-bookkeeping removal,
records `lifecycle_counter_before`, and independently canonicalizes its current
open set and provenance without sending either to the platform backend. While
that barrier remains held, the platform enumerates the entire scope and signs
`OsSocketCensusV1`; then the factory rereads the counter, constructs and signs
`FactorySocketCensusObservationV1` with both counter values, and only then
releases the barrier. The lifecycle counter increments on every create, release,
close, ownership transfer, and open-set bookkeeping transition; it is an
unsigned `u64` that never wraps within a generation. The platform census request
contains only plan/scope/challenge/barrier/deadline—not the expected digest,
tuple list, factory provenance, lifecycle counter, or factory result—so it
cannot echo the producer's answer.
`DiscoveryBackendBuildIdentityV1` uses the domain-separated source and
dependency-lock `ReleaseArtifactCorpusV1` identities plus SHA-256 of the exact
single packaged backend binary. `OsSocketCensusV1.capability_report_digest` is
the policy's sole second-list `SocketCensus` report. That report's closed
mechanism, platform/scope/family/transport/actor tuple, backend/version/package,
and tag-53 source/binary/dependency/build identities match the
`DiscoveryBackendBuildIdentityV1` and enclosing tag-14 policy exactly. The
report's family/transport sets cover the tag-14 child-creation set; the census
request itself remains the unconditional all-family/all-transport/all-state
scope defined above. It is
fresh, `Supported`, `Ready`, `RealHostVerified`, and `Detective`; a missing,
stale, self-supplied, narrower, different-build, or path-binding report cannot
authorize a census. A lone build hash is not a census.
Its `current_socket_creation_enforcement_readback` is a fresh independent
platform read of the same exact policy instance and first-list enforcement
report sealed by tag 14; `current_alternate_socket_path_absence` repeats the
complete actor/cooperative scope and proves both counts remain zero under this
snapshot barrier. The policy, capability digest, active/enforced/denied states,
scope, and timestamps must be valid at `query_completed_at`. A withdrawn or
unreadable enforcement instance makes the census `Unavailable` and denies the
checkpoint even when the independently observed socket set happens to be empty
or equal.

Successful-checkpoint acceptance requires both outcomes `Complete`, a factory
latch other than `TerminalFailed`, identical snapshot context, factory lifecycle
counters equal, freshness before the common deadline, and
`FactorySocketCensusObservationV1.observed_socket_identity_set_digest ==
OsSocketCensusV1.independently_observed_socket_identity_set_digest`. Both fields
must name the same registered `SocketIdentitySetV1`. The factory provenance list
has exactly one entry for every tuple in that set and no others; each entry's
platform identity equals its tuple and its child root repeats the same complete
socket identity, plan, generation, factory, and sequence. An unexpected raw
socket is present in the OS set but lacks factory provenance; a closed socket
remaining in only one set, provenance alias/duplicate, create/close race,
nonce/barrier replay, partial query, overflow, counter wrap, or unavailable
backend is failure. The factory signer cannot substitute for the platform signer
or filter the platform query.
An authenticated tag-46 root may have `outcome=Complete`, equal lifecycle
counters, and an equal or empty socket set while its latch is `TerminalFailed`;
that is a structurally valid negative checkpoint, not successful acceptance.
It proves that cleanup enumeration completed after an independent factory
invariant failure and selects the shared outer factory-invariant code.

The one external apply action starts/attaches the exact factory for the sealed
actor/component and its optional runtime instance and returns one
`SocketFactoryPolicyObservationV1`; response
loss replays that byte-identical observation and the permit becomes consumed.
The factory implementation must make every alternate raw-socket/dialer path
unreachable through a preventive sandbox, syscall/socket broker, or equivalent
enforcement whose identity and read-back are sealed. Source review by itself is
not a `SocketCreationEnforcementReadbackV1`.
`SocketCreationEnforcementReadbackV1.capability_report_digest` is the policy's
sole first-list `SocketCreationEnforcement` report. Its mechanism exactly
matches the read-back policy variant; its complete platform/scope/family/
transport/actor tuple covers the factory; and its backend/version/package plus
tag-53 source/binary/dependency/build identities equal
`FactoryBuildIdentityV1`. It is fresh, `Supported`, `Ready`,
`RealHostVerified`, and `Preventive`. The factory signer cannot substitute a
`PhysicalPathBinding`, actor-isolation, stale-build, narrower-scope, or
producer-only assertion for this independent release capability.
The observation has exactly three authenticators in role-tag order:
`SocketFactoryExecutor` signs its installed factory/readback, the independent
`PlatformDiscoveryBackend` signs the actual policy instance and complete
alternate-entrypoint surface, and `PrivilegedHelper` signs the applied resource,
compensation binding, and journal identity. All sign the same projection. A
single signer, self-reported platform readback, helper intent without platform
state, or cross-instance signature is unauthenticated. If a platform cannot
independently read the displayed enforcement states/surface, that profile is
unsupported rather than reduced to the factory's assertion.

Each later socket is a bounded `Ordinary` data-plane or `Reserved` verification
operation under that installed invariant, not a new session mutation or
external permit. The sole pre-byte
release authority is the `SocketFactoryExecutor` under its already installed
`local_fail_closed_release_predicate` and `LocalSocketReleaseGuardV1`.
`observation_queue_id` is a fresh pre-sealed 32-byte non-authorizing local IPC
identity. `maximum_pending_observations` is in `1..=4096`; `enqueue_deadline` is
positive, no more than one second, and within the socket phase budget. The queue
is declared in the factory actor's referenced tag-54
`ActorNetworkIsolationPolicyV1.permitted_local_ipc`, is reproduced by the
current successful tag-55 readback, carries
only complete signed child roots, and is neither a helper request channel nor a
second gate/lease. It is one append-only multi-reader fanout: both the helper and
watchdog have independent monotonic cursors and receive every root. Capacity is
measured from the slower cursor; one reader cannot consume, hide, acknowledge,
or release a child on behalf of the other. The factory's local append is the
only pre-byte queue condition and no per-child remote acknowledgement exists.

All applicable policies in one plan/generation bind the installation's same sole
ARCH-001 protected state index and its exact
`FactoryAdmissionReleaseCurrentIndexV1` extension. In the target architecture,
their tag-15 readbacks prove every native or cooperative guard is bound to the
same future registered authenticated proof reader and observes the exact current-
generation `BoundClosed` value without access to protected helper storage. A
direct journal/index mapping, second index/selector, per-factory writable/cached
copy, missing reader binding, or non-linearizable proof invalidates installation.
Updating the composite slot is the one batch-level journal commit defined above,
not a per-child release RPC. The accepted ARCH-001 contract lacks this reader,
so current tag-15 readbacks cannot satisfy the target predicate and all profiles
remain unsupported. Once registered, an unavailable, stale, unvalidated,
partially readable, or core/extension-inconsistent proof makes every Ordinary
admission fail closed.

Verification admission is part of that same preventive local release guard and
the same creation/lifecycle lock, not a later census assertion. An `Ordinary`
operation may enter the ordered factory sequence only while admission is
`Open { release_scope=OrdinaryAndVerification }`, after the named most-recent
Open tag-34 root is fully authenticated and current against the helper journal/
fence, and with its matching counter. For a commit- or renewal-authorized Open
root, the child's registered `FactoryAdmissionReleaseBatchCompletionV1` must be
fresh and valid, and its `release_batch_completion_digest` must name that exact
tag-56 root, every factory member must name its matching batch-origin root/index/
receipt, and the latest ARCH-001
status must show through its existing closed summary that the receipt authority/
fence has not been superseded. Separately, the future registered release-proof
read—not `Status` and not a direct storage read—must prove that the sole protected
composite index carries the valid current-release extension naming the tag-56
digest, its core and extension head/revision fields agree at the batch tip, and
its helper-journal parent chain contains the receipt head as the authenticated
ancestor. Any later journal suffix contains only
same-authority chronological socket observations with no fence/recovery event. A root
or completion value from a staged, partial, failed, or superseded batch
authorizes nothing. A `Reserved` operation may enter only while the
named authenticated admission root remains `Exclusive { stage=Running }`, with
the same ID/counter and next unused reserved ordinal/role. Its admission may
have originated from either Open scope. `FinalizedHeld`, `TerminalHeld`, and
`VerificationOnly` for an Ordinary operation admit no child. The guard
transition and any already-started ordinary operation use exactly the same plan-
generation acceptance-event gate as outer disposition, tag 56, and the handoff
above; this is not a similarly named factory-local lock. Immediately before its
atomic child publication, every Ordinary operation acquires that gate, drains
all events ordered through its proposed publication point, and revalidates the
current proof/freshness while its factory lock remains held. A terminal in that
drain aborts with zero publication or protocol bytes; only an empty drain may
reserve the Ordinary publication ordinal and commit the child while still
holding the gate. An event ordered afterward is the next health/rollback event.
Thus guard transition, terminal, and publication have one linearization point
and there is no check-then-create interval.

Freshness is an entry invariant, not merely a later census check. For an
Ordinary child, operation start, atomic publication/`observed_at`, and its first-
byte guard all occur after the tag-56 completion's `completed_at` and before the
minimum of the Open accumulator's `expires_at`, that completion root's
`expires_at`, the authority receipt's `continuous_expires_at`, and the current
ResumeBarrier/lease deadline. For a Reserved child, those events occur before
the minimum of the admission accumulator's `expires_at`, the embedded capacity-
request deadline, and the enclosing sequence deadline. The referenced root
must remain current through atomic publication. For an Ordinary binding,
`most_recent_open_accumulator_digest` must still be the latest Open root and
counter. The corresponding tag-56 member is the batch-origin ancestor, not
necessarily that latest root: the complete chronological suffix from the member
root through the named latest root must be unbroken, Complete, and preserve the
byte-identical Open scope, authority/batch binding, and transition counter, with
no terminal or fence event. This permits later ordinary `NonEmpty` and close-only
`Empty` checkpoints without replaying or weakening the completion root. A
Reserved binding continues to name
the original admission root; the complete chronological suffix from that root
through the latest checkpoint must be unbroken, and every suffix root must
preserve the byte-identical `Exclusive { stage=Running }` reservation and
transition counter. A terminal, finalized, negative-census, missing, or
substituted suffix root invalidates the Reserved entry. Expiry, a newer Ordinary
Open root/counter, fence advancement, or terminal event before creation
completes produces no socket/child/sequence allocation or protocol byte and
transitions to the exact terminal factory context; it cannot borrow a later
root's freshness or be discovered only at the first-following checkpoint.

Under the factory's serialized creation lock it performs this exact order: prove
the admission binding and referenced accumulator are current; prove the queue
is alive and has capacity; create a no-send socket; apply the mechanism
before `connect`/`send`; obtain OS option and route read-back; invoke the one
bounded `connect`; after successful connect, perform the connected-local-peer
check when required; verify the phase-specific release evidence below;
tentatively allocate the next sequence and lease-epoch count; construct and sign
the complete child root; then execute one atomic local publication transaction
before the bounded deadline. That transaction makes the append-only queue entry
visible to both readers, commits the sequence/lease-epoch count, and hands the
socket to the runtime behind its one-shot no-send latch as one indivisible state
change. It either performs all three effects or none: on failure no child root is
visible, no sequence/count is committed, and no socket is handed off. There is
no separately fallible release step after a committed child. Only after the
transaction returns success may the runtime attempt the first TLS,
authentication, credential, challenge, or other application-protocol byte. Any
failed queue, creation, mechanism, option/route read-back, HostLocal peer,
release-evidence, phase-latch, signing, limit, or atomic publication step is an invariant
failure: it closes the socket with zero application-protocol/credential bytes,
marks that factory epoch terminal-failed, and prevents further socket creation.
Queue loss/full/timeout cannot be converted into an unsigned
or later observation. Existing ARCH-001 channel/barrier liveness then denies
proof/commit or closes the active data path. This is not a helper/watchdog child-
release RPC, acknowledgement, permit redemption, or mutation authority: ARCH-
001 registers no such per-socket request, and this contract does not invent or
reuse one.

For the pre-tag-50 role-B boundary, the complete ordered creation through
HostLocal-peer proof is likewise the single bounded factory operation defined
in section 4.6. Its normal unpublished protocol terminals retain the role-A
`ConnectorTerminal` wrapper; success publishes B and begins its zero-byte-safe
method phase; a factory step failure uses only
`UdpControlChildReleaseAborted`. No rule in this section may recast a role-B
failure as `BeforeConnector` or erase the already released role-A child and
completed challenge.

For the tag-50 pending-positive-classification boundary, that entire
ordered factory sequence is the single bounded sampler operation defined in
section 4.6. A terminal event observed before it starts creates no socket. Once
it starts, a later cancellation, deadline, or association-liveness event merely
latches the protocol terminal while the operation drains; it is not a failed
factory step and cannot interrupt or erase an already created unpublished
socket. The operation's own completion remains binary: success performs the
indivisible child publication and hands the latched terminal to the newly
entered send phase with zero protocol bytes, while any failed ordered step
enters `TerminalFailed` and the tag-50 `UdpChildReleaseAborted` branch. Missing
bounded completion, cleanup, or lifecycle evidence invalidates the wrapper.
This exception neither converts a factory-step failure into cancellation nor
permits any nonce, credential, challenge, or application-protocol byte while a
terminal is latched.

A primary Direct or role-A connect system call that returns exactly `ConnectionRefused`,
`NetworkUnreachable`, `HostUnreachable`, or the bounded connect timeout at
`ConnectDestination` or `TcpConnectProxy { connection_role=TargetTunnel }`,
after every preceding mechanism/route
invariant passed, is the sole `RecoverableConnectionOutcome` exception. It has
sent zero TLS, authentication, credential, challenge, or other application-
protocol bytes. The factory closes the unpublished socket, increments its
lifecycle counter for every create/close/open-set transition, emits no child,
does not allocate or commit a child sequence, preserves its epoch, records the
typed `BeforeConnector` terminal attempt, and produces the complete/equal fresh
cleanup checkpoint required before the sealed continuation may start. Any other
typed connect error closes the socket and is terminal for that attempt sequence;
an untyped or internally inconsistent connect result terminally fails the
factory epoch. Neither can silently become a retry. Tests must cross each exact
recoverable result followed by the permitted next attempt against every
mechanism/readback/peer/queue/inconsistent-connect failure followed by a
prohibited second attempt, while checking lifecycle counters and zero released
application-protocol bytes. The same syscall results at
`TcpConnectProxy { connection_role=Socks5UdpAssociationControl }` instead use
the role-A `ConnectorTerminal`, `NotReached { UnpublishedProtocolTerminal }`,
no B child/epoch/sequence, a per-attempt delta containing only A plus the
unpublished B create/close lifecycle delta, and `continuation=Terminal`; the
factory-wide chain still carries every prior attempt's permanent state, while
the terminal checkpoint controlled-closes and removes every B+C pair retained
by this verification sequence from the current-open sets. These outcomes never enter
`RecoverableConnectionOutcome` or authorize another attempt.

For `Preactivation`, the child contains the byte-exact read-back of its already
redeemed ARCH-001 external-executor gate, names the one sealed factory policy
observation, and does not name or require a `ResumeBarrier`, which is created
only after the proof. The helper accepts that child/accumulator only while its
own journal proves that no traffic-steering intent or resource exists; a
factory-signed assertion cannot substitute for that authority. For
`ResumeBarrierProtected`, the child instead contains the exact
ARCH-001 barrier resource ID, `OperationDigest`, `ObservedResourceIdentity`,
`ObservedStateDigest`, activation lease/epoch/fence, and locally read state
`OpenForExactGeneration`. Those values must equal the current helper journal and
plan; a closed, absent, stale-generation, differently owned, or merely inferred
barrier closes the socket with zero bytes. No field from one phase variant may
appear in the other.

The factory starts with latch counter zero. Under its lifecycle lock it closes
every socket created by a `Preactivation` child before the initial transition;
the next factory/OS census must prove that neither its socket set nor provenance
contains any such child. A preactivation socket cannot survive or be relabeled
across the transition; a protocol that needs that reuse is
`UnsupportedPendingArchitecture/PreactivationSocketPhaseTransitionUnavailable`.
After the closed `ResumeBarrier` resource is durably created and before the
helper records any traffic-steering intent, the factory observes that exact
plan-bound resource through its existing authenticated control boundary and
irreversibly enters `ResumeBarrierProtected` with counter one and the exact
barrier/lease/epoch/fence tuple. A fresh signed factory census must report it
before steering may proceed. Each accepted later lease/fence tuple advances the
counter by exactly one under the same lock before another socket may be released;
the counter is a nonzero `u64`, never repeats, decreases, or wraps. The latch
never returns to `Preactivation` within a generation, including rollback or
response loss. Every child and census repeats the current full latch value; its
variant and lease tuple must match `release_phase_evidence` and the child's
`lease_epoch`. A stale tuple, missing increment, reset/replay, barrier close or
read-back loss enters `TerminalFailed`. While protected and the barrier is not
open, no new socket is released.
Every transition into `TerminalFailed` increments the prior latch counter by
exactly one, uses exactly one closed `FactoryTerminalFailureReasonV1`, closes
the unpublished socket when one exists, and is irreversible for that factory
epoch. A creation-operation reason names the first failed step in creation
order. `SocketCloseFailed` is legal only while the terminal-cleanup rules,
including the successful preactivation required-close sequence, or
`VerificationAssociationTeardown` controlled-close an already published,
current-open child. It names the first failed child in the mandatory decreasing
`socket_sequence` order and that child's exact tag-31 digest. Within that child,
`CloseRequestFailed` means the bounded close request itself was not accepted;
`CloseCompletionUnproven` means it was accepted but absence could not be proved
at the close-step deadline. A later complete dual census must still authenticate
the actual residual set; otherwise no valid outer wrapper exists. This reason
is forbidden for an unpublished socket, creation/release abort, ordinary peer
close, or counter/open-set bookkeeping failure. Later best-effort close failures
cannot overwrite its child or step.
`FirstByteExpiryGuardFailed` applies only after a published child exists,
`ResumeBarrierTransitionFailed` only to the one-way barrier transition, and
`LifecycleInvariantFailed` only to counter/open-set bookkeeping. Unknown,
opaque, duplicate, later-overwriting, or phase-inapplicable reasons invalidate
the latch rather than creating a typed outer failure.

The factory emits one signed `SocketPolicyChildObservationV1` per sequence. Let
`A_seed = SHA-256("FlowProbe.Egress.SocketAccumulator.v1\0" ||
Digest(ActorSocketFactoryPolicyV1) || factory_epoch)`. For child sequence `i`,
starting at zero, `A_(i+1) = SHA-256("FlowProbe.Egress.SocketAccumulator.v1\0"
|| A_i || uint64_be(i) || Digest(SocketPolicyChildObservationV1))`. Thus the
first child produces `A_1`; the seed is never also a child result. Tag 13
supplies the executing probe factory's accumulator; each tag-28 precommit and
tag-29 renewal supplies one `SocketObservationAccumulatorV1` per applicable
factory. `NonEmpty` starts at
the previous `next_socket_sequence`, ends at `next_socket_sequence - 1`, has
count `next - first` in `1..=4096`, and its `final_chain_digest` is the
corresponding chain value. `starting_chain_digest` is `A_seed` on the first
checkpoint and the immediately preceding accumulator's `final_chain_digest`
thereafter. `Empty` represents zero new sockets, including a first empty epoch,
consecutive empty epochs, or close-only activity: sequence and creation chain do
not change, but the two fresh census roots may change. Its final chain equals its
starting chain. `previous_accumulator_digest` is absent only for the first
checkpoint and otherwise equals the immediately preceding registered accumulator
root. Sequence `u64::MAX` cannot wrap and requires a new generation. The common
snapshot context and authenticated census roots are mandatory for both delta
variants. `snapshot_projection=Complete` is the sole successful-checkpoint
projection: both census outcomes are `Complete`, the factory counters are
stable, the two identity sets are equal, provenance is exact, and its closure
list is authoritative. The sole prospective-field exception is the tag-46 root
inside a staged tag-28/tag-29 release member: its receipt-bound `Open` admission
value is the conditional post-state defined in section 10, while every socket,
counter, latch, closure, and census field remains an actual locked snapshot.
`Complete` authenticates that snapshot but does not make the proposed Open value
current; only the complete tag-56 protected-index commit does so for all members
at once. Before that commit the previous admission state/counter remains
effective, and after an aborted batch the staged root is not part of the chain.
No other checkpoint field or authority may be prospective.
`CensusNegative` is the sole structurally valid negative
projection. Its roots share the same snapshot context, but it makes no actual-
current-set claim and can never satisfy admission, an attempt, finalization,
release, commit, or renewal success. Its `failure` and the same checkpoint's
`TerminalFailed::SocketCensusFailed` and `TerminalHeld` reason are byte-identical.
It is legal only when census failure is the first factory-invariant defect for
that checkpoint. If a creation, close, release, lifecycle-bookkeeping, or other
factory terminal was already latched, the required actual-state wrapper must use
`snapshot_projection=Complete`; a simultaneous/later negative census makes the
actual residual state unprovable and therefore yields no valid outer wrapper.
It may not overwrite the earlier reason with `SocketCensusFailed` or downgrade
the actual-state obligation to a factory-side projection.

The negative failure is a total function in this exact priority: a non-
`Complete` factory outcome selects `FactoryCensusNegative`; otherwise a non-
`Complete` independent OS outcome selects `IndependentOsCensusNegative`;
otherwise unequal factory lifecycle counters select
`CompleteCensusMismatch { mismatch=FactoryLifecycleCounter }`; otherwise
unequal identity-set digests select
`CompleteCensusMismatch { mismatch=SocketIdentitySet }`. The last two are legal
only when both census outcomes are `Complete`; no other mismatch is a producer-
selectable negative. If the factory outcome and counters are Complete/stable,
`factory_closure_projection=CompleteFactoryProjection` carries the exact factory-
side ledger even when the OS outcome/set disagrees. Otherwise it is exactly
`Unproven` and contains no closure list. Neither form upgrades the negative into
an actual-state assertion. A malformed provenance, signature, context, or
unclassifiable disagreement invalidates the wrapper rather than selecting a
fifth failure.

The fixed
authenticators have roles `PrivilegedHelper` and `WatchdogOrReconciler`, sign the
same accumulator projection, and are both mandatory.

Let the closure source set be the previous accumulator's current-open
provenance (empty when there is no previous root) union every tag-31 child
introduced by this accumulator's `NonEmpty` delta. The
`closure_transitions_since_previous_accumulator` list contains every and only
source-set entry absent in the current set in a `Complete` snapshot projection,
or absent in the factory-projected set in a
`CensusNegative::CompleteFactoryProjection`. Thus a primary A or another child
created and closed before its first-following checkpoint still has one closure
transition, including when that checkpoint is the factory's first accumulator;
only an actually empty closure source produces an empty list. Its length is at
most `previous_current_open_count + child_observation_count`, hence at most
`1024 + 4096 = 5120`; 5121 or a value above the dynamic sum is invalid. It is
ordered by a strictly increasing nonzero lifecycle transition ordinal and binds
the exact tag-31 digest and socket sequence. Each ordinal is the exact factory
lifecycle-counter value assigned immediately after that child's removal from
open provenance. It is greater than the previous checkpoint's stable
`lifecycle_counter_after` and no greater than the current checkpoint's
`lifecycle_counter_before`; for a first accumulator the lower bound is tag 15's
`CensusSnapshotBarrierReadbackV1.lifecycle_counter`. Other create, release, or
bookkeeping increments may create gaps but may not reuse, swap, or fabricate a
removal ordinal. Duplicate, reordered, out-of-range, unknown, or unexplained
removal is invalid. `VerificationProtocolClose` is legal only for a child of the
current reserved sequence whose protocol phase requires the close, and carries
that child's attempt ordinal. Such closes follow protocol chronology—for
example, a passed SOCKS5 role A closes before B/C are created—and are ordered
only by their exact lifecycle ordinals. `VerificationSequenceCleanup` is legal
only for the frozen currently-open cleanup set of that sequence; those
transitions alone follow the mandatory decreasing socket-sequence order.
`OrdinaryLocal` records a requested close of an unrelated non-verification child.
`PeerOrOs` records an externally ended lifetime and may name either kind of
child. For a verification child its terminal-event ordinal is mandatory, equals
the shared serialized gate event, and the transition can never satisfy a clean
protocol or controlled-cleanup predicate; for an unrelated child that optional
ordinal is absent. A first appearance in the current set without one exact new
tag-31 chain entry is likewise invalid. The list plus the before/after lifecycle counters and
the two complete equal census sets make every renewal `O_i` close auditable; a
producer cannot call an accidentally closed business socket part of verification
cleanup or infer a close merely from a set difference.

Every tag-31 root has exactly one admission binding. Verification children of a
tag-13/28/29 `Executed` sequence use `Reserved`; its release ordinals are the
contiguous one-based order of committed children and its roles match the primary
connector, dedicated UDP-control TCP, or UDP relay positions in the attempt.
All other children use `Ordinary` and name the authenticated Open accumulator
whose scope is `OrdinaryAndVerification` and that authorized their entry. A
VerificationOnly Open root or a digest from a Running, FinalizedHeld,
TerminalHeld, stale-counter, different-factory, or different-lease root cannot
authorize an ordinary child, and an initial tag-15 observation is not an Open
accumulator substitute.

`maximum_new_sockets_per_lease_epoch` is cumulative, not a per-checkpoint
allowance. The first child in an epoch has count one; every later child increments
it by exactly one, and the factory census repeats the latest value even across
empty or close-only checkpoints. A reset without a strictly newer accepted
lease epoch, a gap/duplicate, or a value above the sealed maximum terminally
fails the factory before the new socket can send a byte.

The helper/watchdog perform no per-child release decision. They independently
verify the bounded child chain, canonical open set, platform-signed full census,
existing barrier state, and root/role bindings at renewal; a missing/duplicate
sequence, unknown purpose/family/transport/endpoint, unmatched OS socket,
unexpected raw socket, stale route, changed factory/runtime identity, or
observation-channel loss denies renewal and closes/fences the existing barrier
under ARCH-001. The journal retains only the bounded factory observation,
sequence/accumulator/open-set/census roots and digests, not an unbounded per-
packet transcript. Compensation stops the exact owned runtime or revokes only
the exact cooperative factory lease; it never stops an unowned external proxy.
A factory/runtime restart requires a new generation. Reconnect is permitted
only as a new sequence under the same sealed endpoint candidate and predicates.
If a packaged platform cannot synchronously enforce the local pre-byte invariant
without a nonexistent per-child helper operation, dynamic connections and
reconnect are
`UnsupportedPendingArchitecture/DynamicSocketReleaseInvariantUnavailable`; they
cannot be modeled as repeated use of the consumed ARCH-001 permit or as post-hoc
accumulator evidence.

`egress.loop-gate.v1` contains only the digest of mandatory egress predicates
and the stable resource ID of the already sealed ARCH-001 `ResumeBarrier`. Its
generation, lease, fence, owner-death, boot, suspend, and helper/watchdog-channel
behavior are exactly that core resource's behavior. It registers no operation,
second gate, lease, or recovery path and cannot weaken the core barrier.

### 12.3 Plan dependency order

The session graph is ordered:

1. during `Preflighting`, baseline, capability, endpoint, listener,
   authorization receipts, target profiles, secret-free runtime template, and
   tag-14 socket policies are sealed first; the actor graph may then reference
   those exact tag-4/tag-3/tag-18/tag-14 roots, after which the proof
   specification, expected proof predicate, and complete exclusion graph bind
   the same lists without a backward digest edge;
2. helper sealing of that exact graph and transition to `Prepared`; no new
   session-scoped Network Runtime, Capture/data-plane actor, or shared OS
   resource has started or been applied before this boundary. Already-live
   helper, broker, compiler, Supervisor, renderer, and discovery services may
   perform only their typed preflight/local-IPC work under the sealed tag-54
   isolation policy and applicable tag-55 `Preplan` readback;
3. private config materialization plus inert exact runtime/Capture actors under
   the ARCH-001 external-executor gates;
4. actor socket-policy observations and the actual preactivation proof from the
   authenticated runtime, durably recorded before any shared OS mutation;
5. the one ARCH-001 `ResumeBarrier` closed with the
   `egress.loop-gate.v1` predicate contribution; every factory then advances its
   one-way release-phase latch and a fresh census proves the exact barrier tuple
   before any future exactly registered egress or traffic-steering resource;
6. read-back, exclusion completeness, and local identity revalidation;
7. downstream TUN/route/rule/DNS resources that steer captured traffic;
8. open the generation's data-plane gate only through the accepted ARCH-001
   activation barrier;
9. postactivation canary, exact selected egress, exclusion completeness,
   baseline-relative ordinary connectivity, and mandatory health verification;
10. durable ARCH-001 commit; then publish `Active`.

No traffic-steering resource may depend on an unverified exclusion. If a
mandatory actor has no external network path, its preventive
`NoExternalNetworkPath` evidence is still a dependency.

Normal stop and emergency rollback have different safe order. On a normal stop
with every mandatory data-plane actor healthy, the Supervisor first refuses new
product operations but keeps the current ARCH-001 barrier/data plane available
while reverse compensation removes traffic steering, downstream DNS/rules/
routes, and TUN ownership. Only after read-back proves system traffic no longer
depends on FlowProbe does the helper close/fence the barrier; the exact runtime/
Capture actors then stop and their absence plus private-artifact cleanup are
verified. Egress exclusions remain until those actors are absent or proven
networkless, then compensate in reverse order if a future registered resource
exists. Quiescing the data plane while an owned route may still direct traffic
to it is forbidden.

For failed activation, lease loss, unsafe drift, suspend/boot, owner loss, or an
already failed mandatory actor, the helper cannot preserve normal-stop
availability. It immediately closes/fences the same barrier and performs bounded
emergency steering removal, while retaining exclusions as long as they reduce
recursion risk. Incomplete compensation is `RecoveryRequired`. Neither path
needs a proxy credential and neither restarts the old generation implicitly.

### 12.4 Journal, fencing, and replay

Every `egress.*` mutation inherits the exact ARCH-001 generation, controller,
activation lease, fence, conditional state revision, write-ahead intent,
postcondition fsync, idempotency key, response result-tip, takeover lock,
recovery delegate, and terminal publication rules. ARCH-002 creates no second
lease, fence, journal, recovery protocol, or normal-stop acknowledgement.

The accepted ARCH-001/helper request union currently exposes
`AcknowledgeRecovery` only under recovery authority, while the `core.session`
terminal predicate also requires a Supervisor acknowledgement of the final
revision after an ordinary healthy stop. It defines neither a typed normal-stop
acknowledgement nor a durable normal-stop-to-recovery-finalization transition.
Therefore the ordering above is a safety design, not an executable Ready claim:
every ARCH-002 mode also carries
`UnsupportedPendingArchitecture/NormalStopFinalizationProtocolUnavailable`
until a separate accepted ARCH-001 architecture task closes that request,
authority, state-transition, idempotency, and response schema. An implementation
MUST NOT reuse `AcknowledgeRecovery`, invent an unregistered request, infer
acknowledgement from disconnect, or publish terminal `Inactive` around this gap.

The sealed secret-free plan binds:

- network scope and safe egress-selection digest;
- credential, risk/target authorization receipt, TLS policy/trust-content
  descriptor, resolver policy, endpoint, and target profile digests;
- runtime package/build, secret-free config template, exact runtime instance,
  private-artifact identity recipe, and cleanup predicate;
- exact capability snapshot and version scope;
- baseline anchor, endpoint resolution/locality, and local proxy identity
  digests;
- complete actor graph and exclusion-set digest;
- preactivation proof specification, helper nonce slot, expected observation
  schemas/roles/freshness for material delivery, runtime load, adapter artifact,
  effective system-trust observation when applicable, proxy TLS handshake, and
  path proof, but never a future result;
- registered `egress.*` resource graph and predicates;
- mandatory postactivation and sustained-health predicates; and
- all downstream extension digests and ARCH-001 bindings.

After `Prepared`, the ARCH-001 journal records each authenticated trust-delivery,
effective system-trust observation, runtime-load, adapter-artifact,
proxy-handshake, path-proof, and phase-bound checkpoint result applicable to the
selected tag, with its expiry, as the terminal result of its pre-sealed
observation node. Those results are required by every dependent apply step but
do not retroactively change `PlanDigest`; response-loss replay returns the same
journaled roots.

Credential handles/values, usernames, passwords, authorization values, private
trust material, full runtime/user configuration, raw certificates, probe data,
and captured traffic are prohibited. Recovery is therefore capable of closing
the gate and compensating every egress resource without accessing secrets or
reconnecting to a proxy.

## 13. Platform backend requirements

### 13.1 Common rule

An API's existence establishes at most a candidate mechanism. A platform/mode
is release-supported only when the complete packaged tuple implements every
required kind, reports `Supported`, and passes the real-host matrix. No support
conclusion is inherited across native TUN, Packet Tunnel, transparent proxy,
WFP, route-based TUN, proxy-only, or other data paths.

### 13.2 Windows candidate

FlowProbe-owned sockets may use `IP_UNICAST_IF`/`IPV6_UNICAST_IF` or an accepted
WFP/route equivalent. The backend must set the option before connect, bind it to
the observed stable interface/compartment, cover both families, and obtain route
and policy read-back. Stable interface evidence is the interface GUID/LUID plus
current `MIB_IF_ROW2` and compartment; conversion to an interface index is
recomputed for each observation. GUID, LUID, row identity, and epoch are bound
to the plan; index alone is a live locator.

Only a `GetExtendedTcpTable` owner row in `MIB_TCP_STATE_LISTEN` is a TCP
listener observation. `GetExtendedUdpTable` supplies a bound UDP endpoint, not
a listener/connection claim. Either table is a point-in-time locator only. The
backend must add a
retained process handle, process creation/boot time, opened executable file
identity (`FILE_ID_INFO` plus volume), verified Authenticode signer/package/
service evidence as applicable, listener
tuple/compartment, and the exact WFP/cooperative enforcement identity. PID and
owner-table row are not stable identity. WFP `ALE_APP_ID` is an
application path identity used by filters; it is not immutable file identity
and must be revalidated against open-file and signer evidence before every
relevant ALE authorization and commit/renewal observation. File replacement at
the same path or a WFP reauthorization without the sealed identity fails closed.

A dynamic WFP session's objects disappear when the session closes. Such cleanup
cannot be the sole loop gate because helper failure could remove the exclusion
before traffic steering is fenced. WFP transaction atomicity likewise does not
prove path selection, durable ownership, or crash recovery; the accepted backend
must integrate persistent/fail-closed gate behavior and ARCH-001 journaling.
An ALE block/permit decision also does not choose the next hop; separate exact
socket and route observations remain mandatory.

An arbitrary local proxy is full-tunnel-ready only if an accepted preventive
WFP/callout, compartment, cooperative per-socket binding, or equivalent
mechanism proves all of that proxy's required TCP/UDP/DNS sockets use the
baseline anchor. A permit/block filter that does not force or protect the route
is insufficient.

Current result for every Windows full-tunnel combination is
`UnsupportedPendingArchitecture`/`Unsafe`/`DesignOnly`: the complete exclusion
backend is not implemented or real-host verified, and ADR-0004's independent
runtime attachment and resume-gate blockers remain.

### 13.3 Linux candidate

FlowProbe-owned sockets may use a helper-owned generation-scoped `SO_MARK` plus
exact policy rule/table and/or `SO_BINDTODEVICE`. The backend must prove the mark
was applied to every socket class, the rule selects the sealed route table, the
table selects the baseline anchor, and no higher-priority rule recaptures it.
Marks, table numbers, priorities, interface names, and ifindices are locators;
the complete owned tuples and journal identities are required.

The capability report records the exact privilege used for `SO_MARK` and the
kernel floor on which it is valid. The backend checks mark/table/rule collisions
and pinned sing-box `auto_redirect`/default-mark conflicts before mutation.
Conflicting ownership is unsupported; FlowProbe never reuses or overwrites an
ambient mark/rule because the numeric value appears free in one snapshot.

Listener discovery may use `sock_diag` tuple/state/bound-interface/UID/inode/
cookie evidence. Mapping that socket to a process is a separate bounded scan of
the selected namespace's `/proc/<pid>/fd` links, correlated with a retained
pidfd and `/proc/<pid>/stat` start time; executable provenance comes from the
opened `/proc/<pid>/exe` file plus `statx`/package evidence, not its path text.
Each snapshot is rechecked after pidfd acquisition so exit, PID reuse, FD
transfer, and namespace movement cannot be papered over. A local proxy identity
additionally requires boot evidence, exact listener identity, and a helper-
controlled enforcement identity. When the backend relies on duplicating the
listener's open file description, `pidfd_getfd` permission (ptrace access) and
Linux 5.6+ availability are explicit capability scope; denial or a changed FD
owner is not treated as ownership. Interface identity uses the network-
namespace identity plus a fresh `RTM_GETLINK` tuple and package/backend epoch;
ifindex/name remain live locators. A cgroup may be used only when
the helper proves stable controlled membership, prevents escape for the
session, marks/binds every required socket including workers, and conditionally
restores only FlowProbe-owned policy. UID, PID, socket inode, unit, or cgroup
name alone is insufficient.

Current result for every Linux full-tunnel combination is
`UnsupportedPendingArchitecture`/`Unsafe`/`DesignOnly`: no release tuple or
complete cgroup/mark mechanism is selected, implemented, packaged, and
real-host verified, and ADR-0004 blockers remain.

### 13.4 macOS candidate

Connections created through Network.framework may use `requiredInterface`;
that property does not affect sing-box's Go sockets. Other FlowProbe-owned
sockets may use BSD `IP_BOUND_IF`/`IPV6_BOUND_IF` before connect, and the pinned
sing-box/Go integration must prove its own exact binding and read-back. The
backend must discover the current interface rather than hard-code names, bind
both required families, and couple the observation to the stable platform
identity and route epoch.

The reviewed public design has no accepted mechanism that both proves stable
ownership of an arbitrary local listening proxy and forces all of that external
process's egress outside a native full-tunnel route. At reviewed XNU revision
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`, Apple labels the concrete `libproc`
process-information interfaces private and subject to change.
Network Extension `NEFlowMetaData` supplies source identity only inside its own
provider flow boundary, not an atomic listener-owner snapshot for the accepted
native independent-runtime path. FlowProbe cannot assume the external proxy
cooperates, use private APIs, or infer enforcement from PID, path, port, audit
observation, or process attribution.

Endpoint Security's public `es_process_t` can add event-time audit token,
executable, signing, and start-time provenance, while Security.framework can
validate code-signing identity. Neither API enumerates the current owning
socket for an arbitrary listener, atomically couples that listener to the
process, or forces its route. Those observations therefore cannot replace the
missing public listener-owner and preventive-exclusion mechanism.

Consequently local-external-proxy full-tunnel is explicitly
`UnsupportedPendingArchitecture`/`Unsafe`/`DesignOnly` on macOS. Direct and
remote-external full-tunnel also remain unsupported because ADR-0004's native
TUN authority/identity, independent attachment, resume gate, and real-host
requirements are unresolved. Packet Tunnel or transparent-proxy evidence cannot
be reused for the native path.

### 13.5 Current architecture matrix

| Platform | Network scope | Selection/locality | Static support | Readiness | Evidence | Required bounded reasons |
| --- | --- | --- | --- | --- | --- | --- |
| Windows candidate | FullTunnel | All | `UnsupportedPendingArchitecture` | `Unsafe` | `DesignOnly` | `ExclusionBackendMissing`, `ExternalRuntimeAttachmentMissing`, `ResumeGateMissing`, `RealHostUnverified` |
| Linux candidate | FullTunnel | All | `UnsupportedPendingArchitecture` | `Unsafe` | `DesignOnly` | `ReleaseTupleUnselected`, `ExclusionBackendMissing`, `ExternalRuntimeAttachmentMissing`, `ResumeGateMissing`, `RealHostUnverified` |
| macOS candidate | FullTunnel | Direct or remote external | `UnsupportedPendingArchitecture` | `Unsafe` | `DesignOnly` | `NativeTunAuthorityUnproven`, `ExternalRuntimeAttachmentMissing`, `ResumeGateMissing`, `RealHostUnverified` |
| macOS candidate | FullTunnel | Local external | `UnsupportedPendingArchitecture` | `Unsafe` | `DesignOnly` | Above reasons plus `LocalProxyExclusionMechanismMissing` |
| Any current platform | ProxyOnly | Any | `UnsupportedPendingArchitecture` | `Unsafe` | `DesignOnly` | `TypedEgressImplementationMissing`, `SustainedHealthMissing`, `RealHostUnverified` |

This table is normative current truth, not a permanent platform prohibition.
Every row additionally carries
`NormalStopFinalizationProtocolUnavailable`,
`DurableAdmissionReleaseCommitUnavailable`, and
`AdmissionReleaseProofReadUnavailable`. A row selecting the pinned HTTP, TLS,
authenticated-credential, or SOCKS UDP paths also carries the exact
`Pinned*Nonconforming` reason defined in section 5.1; a row without a complete
socket-factory/release invariant carries
`DynamicSocketReleaseInvariantUnavailable`. A row attempting to map pinned
Windows or Linux `bind_interface` behavior carries the corresponding
`PinnedWindowsBindAdapterNonconforming` or
`PinnedLinuxBindInterfaceNonconforming` reason from section 12.2. These global
reasons cannot be omitted merely because a platform-specific reason already
keeps the row unsupported.
An implementation task may change runtime results only after the relevant
accepted architecture, package tuple, implementation, and evidence exist. It
must not edit this accepted contract inside a feature task.

## 14. Commit and active health

### 14.1 Pre-commit predicates

Immediately before commit, under the ARCH-001 serialization/fence rules, every
mandatory predicate must be fresh and true:

- request, network scope, selection, plan, runtime instance, generation, lease,
  fence, and state revision match;
- all required capability reports map to `Supported` for the exact tuple;
- baseline anchor, resolver, endpoint set/locality, route, interface, namespace/
  compartment, boot/suspend, backend, and package epochs match the plan;
- local listener/process/executable/policy identity matches when required;
- every exclusion resource satisfies its observed-after predicate;
- the completeness proof covers every registered actor/path/family/transport;
- the preactivation proof remains unexpired;
- every applicable factory has a fresh helper/watchdog-signed accumulator whose
  factory and independently produced OS census roots are complete, context-
  matched, counter-stable, and equal;
- for `ExternalHttps`, the registered trust delivery, Network Runtime load,
  Runtime Adapter artifact-absence, and proxy TLS handshake roots are all
  present in both the passed preactivation proof's and passed canary's
  `ExternalHttpsHandshake` evidence, fresh, correctly signed, cross-bound, and
  passed; `ExternalHttpsPrepared` cannot satisfy commit. For other tags both
  references are `NotApplicable`;
- the postactivation canary proves the selected tag over the active path;
- every required SOCKS5 UDP verification association and relay identity was
  live at its immutable tag-50 snapshot, and the mandatory close-only teardown
  checkpoint proves that no verification child was promoted into the data plane;
- no DNS/UDP path lacks its accepted downstream policy; and
- ADR-0004 baseline-relative ordinary-connectivity and mode-specific health are
  satisfied.

One false, missing, ambiguous, degraded, insufficient enforcement for that
capability (including detective-only where preventive is required), expired, or version-
mismatched predicate denies commit. The session rolls back and cannot be
reported `Active`.

### 14.2 Postactivation canary

The postactivation canary reuses the sole exact
`EgressProofSpecificationV1.probe_target_profile_digests` entry and its verified
authorization receipt. It inherits the same address-class/port policy, sealed resolver,
zero-redirect rule, per-phase/overall deadlines, serial concurrency limit,
1024-byte challenge ceiling, 256-KiB total protocol ceiling, and no-body privacy
rule. The sealed retry limit remains an upper bound but the verification
sequence's effective candidate retry/fallback count is zero; activation cannot
substitute a new target/candidate or relax a bound.
`preactivation_proof_result_digest` is exactly
`Digest(EgressPathProofResultV1)` (tag 13) of the still-fresh `Passed` proof for
this plan/specification/runtime/target. Its protocol-successful group entries are the
only tuple/candidate source for this canary as defined by the shared sequence
rules; a different, failed, expired, or partial proof invalidates the wrapper.

```text
PostactivationCanaryResultV1 = {
  prepared_plan_digest,
  helper_assigned_observation_nonce,
  generation,
  activation_lease_id,
  lease_epoch,
  fence_token_digest,
  runtime_instance_id,
  capture_core_instance_id,
  proof_specification_digest,
  preactivation_proof_result_digest,
  target_profile_digest,
  target_authorization_receipt_digest,
  egress_selection_safe_digest,
  probe_evidence: CanaryProbeEvidenceV1,
  source_actor_id,
  actor_network_isolation_readback_digests,
  exclusion_readback_observation_digest,
  baseline_anchor_digest,
  ordinary_connectivity_observation_digest,
  socket_factory_policy_observation_digests,
  socket_observation_accumulator_digests,
  capture_generation_marker_digest,
  probe_factory_policy_id,
  egress_bypass_traversal_observations:
    0..=12 EgressBypassTraversalObservationV1,
  started_at,
  completed_at,
  expires_at,
  outcome,
  runtime_authenticator,
  capture_core_authenticator,
}

CanaryProbeEvidenceV1 = ProtocolConnectionAttemptSequenceV1

CanaryOutcome =
  | Passed
  | Failed { error_code: EgressOuterFailureCodeV1 }
  | TimedOut { bounded_phase: ProtocolPhaseV1 }
  | Cancelled

EgressBypassTraversalObservationV1 = {
  attempt_ordinal,
  child_ordinal_within_attempt: 1..=3,
  child_actor_id,
  family_tuple: PathFamilyTupleV1,
  socket_role: CanaryEgressSocketRoleV1,
  socket_child_observation_digest,
  platform_socket_identity: PlatformSocketIdentityV1,
  path_purpose: PathPurpose,
  address_family,
  transport,
  endpoint_binding: PathEndpointBindingV1,
  selected_endpoint_digest,
  path_exclusion_entry_digests:
    1..=128 Digest(EgressExclusionEntryV1),
  expectation = BypassedExactlyZero,
  outcome = Counted { observed_count = Zero | One | AtLeastTwo } |
            Unavailable,
}

CanaryEgressSocketRoleV1 =
  | Connector {
      candidate_binding: ConnectionAttemptCandidateBindingV1,
      connection_binding_epoch,
    }
  | Socks5UdpAssociationControl {
      target_tunnel_connection_binding_epoch,
      target_tunnel_socket_child_observation_digest,
      udp_control_connection_binding_epoch,
      association_state: Socks5UdpControlTraversalStateV1,
    }
  | Socks5UdpRelay {
      socks5_udp_association_observation_digest,
      target_tunnel_connection_binding_epoch,
      target_tunnel_socket_child_observation_digest,
      udp_control_connection_binding_epoch,
      udp_control_socket_child_observation_digest,
      relay_endpoint_digest,
    }

Socks5UdpControlTraversalStateV1 =
  | PreAssociationPublished
  | FirstByteGuardAborted
  | AssociationObserved {
      socks5_udp_association_observation_digest,
    }
```

`runtime_instance_id` and `source_actor_id` equal the passed tag-13 result and
its proof specification, while `probe_factory_policy_id` equals their selected
factory. The runtime authenticator's `ExternalExecutorGate` authority and
protected control identity are that exact actor/runtime; no other Network
Runtime channel can sign this canary. Its authority repeats the tag-13
prepared-plan/permit/runtime/gate-channel tuple byte-for-byte.
The factory-policy and accumulator lists each contain `1..=32` unique digests,
are ordered by the referenced tag-15 root's `factory_policy_id`, and are one-to-
one with every applicable socket-factory actor in the plan. The unique policy
whose ID equals `probe_factory_policy_id` is the probe-factory index; its tag-14
actor/component/runtime equal `source_actor_id` and `runtime_instance_id` and it
permits the `PostactivationCanary` purpose. At that index, the tag-34 value is
the sequence top-level root defined by the shared finalization rule and every
sequence tag-31 child carries that same actor and factory. At every other index
it is the latest fresh zero-child `Empty`, Complete/
equal checkpoint: it remains `Open { release_scope=VerificationOnly }`, has no
verification reservation, and contains the exact current actor-wide set. A
non-probe checkpoint that is missing, negative, terminal, stale, or introduces a
child selects or invalidates the outer result under the shared rules; it cannot
be omitted because it did not execute the probe. Duplicate, extra, reordered,
cross-factory, or tag-15/tag-34 plan/generation/factory mismatch invalidates the
wrapper. These are the exact per-factory predecessor lists consumed by the tag-
28 admission-release batch; no later producer-selected factory set exists.

Postactivation is quiescent before commit: only the role-A connector and, for a
reached `RequireAssociate`, its role-B dedicated control and role-C UDP relay
children may be released for a canary attempt.
Any resolver result used here is already sealed/fresh and v1 performs no online
certificate-status request; a new resolver, certificate-status, telemetry,
application, or other socket child in this window invalidates the canary. The
per-attempt first-following tag-34 `NonEmpty` interval therefore contains the
exact released prefix: A; A+B iff the dedicated control was published; and
A+B+C iff tag 50 names a released UDP child. `egress_bypass_traversal_observations`
contains exactly one entry for every such tag-31 child and no others, sorted by
attempt ordinal then child socket sequence; `child_ordinal_within_attempt` is
contiguous `1`, `1,2`, or `1,2,3`. At most four active success groups times
three children gives the bound twelve; a thirteenth item is invalid.

`Connector` repeats the attempt's candidate binding, connection epoch, and
connector tag-31 digest; its child actor equals outer `source_actor_id`, purpose
is `PostactivationCanary`, and transport is TCP. `Socks5UdpAssociationControl`
is present iff B was published. It repeats A's epoch/child and B's epoch; its
outer child digest is B, purpose is `ProxyControl`, transport is TCP, and its
selected endpoint is the same exact proxy candidate. `PreAssociationPublished`
is exact only with outer `NotReached { Published }`;
`FirstByteGuardAborted` is exact only with outer
`UdpControlFirstByteGuardAborted` and repeats its B binding;
`AssociationObserved` repeats the exact tag-50 root and is mandatory with outer
`Observed`. A pre-publication control-release abort or unpublished role-B
terminal has no B traversal item.
`Socks5UdpRelay` is present iff the same attempt's tag-50 root has C and repeats
that root, both TCP epochs/children, C, and
`SelectedLiteral.relay_endpoint_digest`; its purpose is `Socks5UdpRelay`,
transport is UDP, and its selected endpoint is that exact public-Remote relay.
Every entry
repeats its child's actor, family, transport, endpoint binding, selected endpoint,
and `PlatformSocketIdentityV1` byte-for-byte. The actor graph must contain the
one exact matching `RequiredPath`. Candidate/route/peer equality for the
connector, independent role-B HostLocal-peer and proxy equality, and tag-50/
relay equality for C are mandatory; an A/B swap, same-proxy different child,
same-family child, another association, or another declaration is not
interchangeable. A tag-28
`BeforeConnector` has no released child or traversal item and is already a
terminal failed canary under the shared active-sequence rule; it can never be
followed by a successful fallback that masks its uncounted SYN.

`path_exclusion_entry_digests` is the non-empty unique subsequence in tag-9 order
whose tag-10 actor/purpose/family/transport/endpoint union exactly covers this
egress attempt. Expectation is always `BypassedExactlyZero`; ARCH-002 does not
invent a separate captured-input actor or allow a producer to choose
`CapturedExactlyOnce`. Only `Counted { Zero }` satisfies it. `Counted { One }`,
`AtLeastTwo`, or `Unavailable` maps uniquely to
`LoopDetectedOrUnproven`, makes that attempt `Terminal`, and forbids any later
attempt. Missing, extra, wrong-family, cross-candidate, cross-child/epoch, or
cross-attempt coverage invalidates the wrapper. Real-host release testing of intended non-FlowProbe traffic is a
separate harness assertion in section 18, not an alternate value in this root.

The helper nonce is fresh for this pre-sealed observation node. The exact
runtime and Capture Core identities each authenticate their part through the
protected ARCH-001 channels; the Supervisor may relay but cannot create a
traversal or target result. Evidence binds:

- the exact selection and, when a connector exists, its actual target-or-proxy
  peer endpoint;
- capture-generation marker;
- source actor, every attempt-keyed egress-bypass/exclusion-entry set, every required fresh dual-signed actor-network-
  isolation readback, and the complete dual-signed exclusion-readback root;
- the registered baseline anchor and dual-signed baseline-relative ordinary-
  connectivity root;
- the closed TLS/SOCKS evidence prefix appropriate to the actual terminal
  phase;
- for `ConnectorTerminal`, the signed child observation and, once the target
  challenge phase is entered, its exact NetworkRuntime-signed
  `PhaseBoundProbeChallengeResultV1`; strictly before challenge entry it instead
  uses `NoCompletedResult` and no tag-37 root;
- the following helper/watchdog accumulator with equal factory/OS census roots;
  and
- Capture Core zero-traversal count for every released egress canary socket.

`runtime_authenticator` and `capture_core_authenticator` are
`ExternalObservationAuthenticatorV1` values in that fixed order with roles
`NetworkRuntime` and `CaptureCore`. Each signs the same canary signing projection
under its own gate-bound key/channel. One signer cannot contribute for the
other, and a partially signed result is unauthenticated.

`actor_network_isolation_readback_digests` contains exactly one tag-55
`ActivePlanCheckpoint` root for every actor whose graph declaration is
`NoExternalNetworkPath`, in ascending `actor_id` byte order; its bound is
`1..=32`. Every root uses `Postactivation`, this plan/generation, this helper
canary nonce, activation lease/epoch/fence, and the exact tag-54 policy plus
actor/identity/mechanism/permit tuple sealed in the graph. A missing, extra,
duplicate, reordered, expired, single-signer, changed-policy, or nonzero-
unexpected-surface root is canary failure.

Every canary attempt obeys the shared sequence rules. A `BeforeConnector`
attempt has no child or challenge field. A `ConnectorTerminal` that enters the
target challenge uses `PhaseBoundCompleted` for every terminal result; its tag-37 root uses `Postactivation` with
this canary nonce and capture-generation marker and repeats the exact attempt
ordinal, family tuple, candidate binding, connection epoch, child, first
following accumulator, challenge kind, proof specification, and target. A
connector that terminates strictly before target challenge entry instead uses
`NoCompletedResult` and has no tag-37 root. The optional proxy endpoint on a
present tag-37 root is the candidate binding's proxy endpoint and is absent for `Direct`. A
preactivation/renewal root, cross-attempt child, stale commitment, or different
checkpoint invalidates the canary wrapper.

`CanaryOutcome::Passed` is valid exactly when every success group has its first
successful attempt, every such tag-37 outcome is `TcpConnectPassed` or
`NonceEchoPassed`, every applicable TLS/SOCKS root is passed, all following
census checkpoints are complete/equal, every egress-bypass traversal observation matches,
and all actor-isolation, target-authorization, exclusion, baseline, ordinary-
connectivity, lease/fence, and authenticator predicates are valid. For
`RequireAssociate`, its top-level probe-factory accumulator is the exact
complete/equal close-only teardown root; the final attempt's retained B+C
checkpoint cannot occupy that field. Other selections retain no success child
but still use the mandatory next `Empty` finalization/census root after the
traversal, tag-51, and tag-52 results freeze; a clean protocol-successful final-
attempt checkpoint never occupies the top-level field. The same fresh
finalization is required before a structurally valid traversal/tag-51/tag-52
negative can be published. NonceEcho is
40/40; TCP has no outer byte-count projection. Negative attempt/challenge,
census, traversal, exclusion-readback, or ordinary-connectivity results follow
the shared exact priority mapping and cannot be wrapped by `Passed`.

The tag-51 and tag-52 roots use the exact `Postactivation` context and current
lease/fence. `Passed` requires respectively `Complete` and `Passed`, with exact
set/completeness/baseline fields. Their authenticated negative variants are
allowed only in a valid outer `Failed` using the shared mapping; stale,
cross-context, unknown, or structurally invalid roots invalidate the wrapper.
Attempt-local `ExternalHttps` and `RequireAssociate` evidence follows the
shared rules with this postactivation context; no TLS or association root may
be reused across attempts.

The attempt-keyed egress-bypass matrix above is exhaustive. A changed source
identity, path declaration, candidate, child, epoch, socket identity, or a
missing/extra/reordered observation invalidates the wrapper; a valid counted
traversal or inability to count uses `LoopDetectedOrUnproven`. Canary payload
and raw packets are not journaled.
Receipt failure, special-address rebinding, oversize, redirect, timeout, or an
unauthenticated result closes/fences the barrier and denies commit.

### 14.3 Lease-renewal evidence

`egress.sustained-health.v1` is mandatory for every active lease renewal. It
uses the exact closed observation:

```text
SustainedHealthObservationV1 = {
  prepared_plan_digest,
  renewal_challenge_nonce,
  generation,
  activation_lease_id,
  lease_epoch,
  fence_token_digest,
  runtime_instance_id,
  source_actor_id,
  probe_factory_policy_id,
  proof_specification_digest,
  preactivation_proof_result_digest,
  actor_graph_digest,
  actor_network_isolation_readback_digests,
  baseline_anchor_digest,
  endpoint_resolution_digest?,
  exclusion_readback_observation_digest,
  exclusion_completeness_proof_digest,
  local_proxy_identity_digest?,
  probe_evidence: HealthProbeEvidenceV1,
  socket_factory_policy_observation_digests,
  socket_observation_accumulator_digests,
  target_profile_digest,
  ordinary_connectivity_observation_digest,
  observed_at,
  expires_at,
  authenticators,
  outcome,
}

HealthProbeEvidenceV1 = ProtocolConnectionAttemptSequenceV1

HealthOutcome =
  | Healthy
  | Failed { error_code: EgressOuterFailureCodeV1 }
  | TimedOut { bounded_phase: ProtocolPhaseV1 }
  | Cancelled
```

`preactivation_proof_result_digest` is the same exact still-fresh passed tag-13
root accepted by the postactivation canary. Its plan, specification, runtime,
target, and complete success-group selection remain byte-identical; renewal does
not rerun candidate discovery or choose another preference fallback. A changed
candidate requires failure of the old lease and a new generation.
`runtime_instance_id`, `source_actor_id`, and `probe_factory_policy_id` equal
that tag-13 result and its proof specification byte-for-byte. The
`NetworkRuntime` authenticator uses that actor/runtime's
`ExternalExecutorGate` and protected control identity, and every tag-29 sequence
child/root belongs to that exact actor and factory. Its authority repeats the
tag-13 prepared-plan/permit/runtime/gate-channel tuple byte-for-byte.
Cross-runtime, cross-actor, cross-component, cross-factory, or cross-epoch
evidence substitution invalidates the wrapper and denies renewal.

`actor_graph_digest` is exactly the plan's registered
`Digest(EgressActorGraphV1)` and therefore carries the complete mandatory actor
set and every inline `ActorIdentityV1`; a producer cannot replace it with a
list of private identity hashes.
`actor_network_isolation_readback_digests` contains exactly one tag-55
`ActivePlanCheckpoint` root for every `NoExternalNetworkPath` actor, in ascending
`actor_id` byte order and with bound `1..=32`. Every root uses `Renewal`, this
plan/generation/lease epoch/challenge/fence, and the exact tag-54 policy plus
actor/identity/mechanism/permit tuple sealed in the graph. Missing, extra,
duplicate, reordered, stale, single-signer, changed-policy, or nonzero-
unexpected-surface data invalidates the health wrapper and operationally denies
renewal; it cannot be encoded as a valid `HealthOutcome::Failed`.
`endpoint_resolution_digest` has exactly the same presence and value as
`EgressProofSpecificationV1.endpoint_resolution_digest`: it is present for
every external proxy, including literal endpoints, and absent only for
`Direct`. Probe-target resolution and a SOCKS relay
checkpoint remain their separately typed target/association children and cannot
be substituted into this optional field.
`local_proxy_identity_digest` has exactly the same presence and value as
`EgressProofSpecificationV1.local_proxy_identity_digest`: it is the unique tag-5
root for a `HostLocal` selected proxy and equals the graph/exclusion identity;
it is absent for `Direct` and `Remote`. A changed listener/process/executable/
policy identity requires generation replacement rather than a health-time
substitution.
`exclusion_completeness_proof_digest` is exactly
`Digest(EgressExclusionCompletenessProofV1)` (tag 35), equals
`EgressExclusionReadbackObservationV1.completeness_proof_digest`, and equals the
tag-9 exclusion set's `completeness_proof_digest`. Its tag-1 selection, tag-8
actor graph, optional tag-5 identity, entry list, and covered tuple projection
are byte-identical to this plan; no health-local completeness hash exists.
The factory-policy and accumulator lists each contain `1..=32` unique digests,
are ordered by the referenced root's `factory_policy_id`, and are one-to-one
with every applicable socket-factory actor. At each index tag 15 repeats the
plan, generation, and factory and resolves its actor through the exact tag-14
policy; tag 34 repeats the plan, generation, current lease epoch, and factory.
The tag-14 actor reached from tag 15 equals the actor applicable to that tag-34
factory. Neither tag 15 invents a lease epoch nor tag 34 invents an actor field.
Exactly one index contains the tag-29 sequence's admission/finalization chain;
that index's factory ID equals `probe_factory_policy_id`, and its tag-14
actor/component/runtime equal `source_actor_id` and `runtime_instance_id`.
Every other index is that factory's latest
fresh chronological Complete/equal `Open { release_scope=
OrdinaryAndVerification }` checkpoint, including all ordinary creation/closure
activity that linearized through that checkpoint. Creation remains held from
that checkpoint onward. A close that wins after the checkpoint but before the
combined lifecycle/close-bookkeeping lock does not rewrite the outer
predecessor; the corresponding batch member's since-previous closure ledger and
dual census absorb it. These values are the exact
predecessors for the renewal admission-release batch. Each outer-listed
checkpoint atomically acquires its factory's creation gate; by outer publication
every listed creation gate is held, and all remain held through successful batch
completion or failure fencing/rollback. A close that linearizes before the coordinator acquires the full
all-factory lifecycle/close-bookkeeping lock is ledgered in its release root.
Duplicate,
missing, extra, digest-byte sorting that disagrees with factory-ID ordering, or
more than 32 entries invalidates the wrapper and denies renewal rather than
becoming a truncated or producer-reported failure.

It contains fresh safe digests for:

- selected protocol and the exact evidence prefix reached by the renewal;
- every current actor-network-isolation policy readback;
- baseline anchor, route/interface, resolver, address family, namespace/
  compartment, boot/suspend, backend, and package epochs;
- the registered dual-signed exclusion-readback root and registered completeness
  proof;
- each factory's `SocketObservationAccumulatorV1`, including its gap-free socket
  sequence range, exact open-socket set, and independent OS socket census;
- local proxy listener/process/executable/policy identity when present;
- for `ConnectorTerminal`, current HTTP/HTTPS proxy control through the selected
  phase, plus its NetworkRuntime-signed tag-37 result only when the challenge
  completed; otherwise `NoCompletedResult` and no tag-37 root;
- the closed SOCKS-association prefix required by the selected policy;
- for `ExternalHttps`, the exact delivery plus fresh context-bound runtime-state
  and adapter-absence roots, and a handshake root only after a connector exists;
  and
- helper/watchdog path facts
  through the exact barrier, accumulator, census, fence, and four-root signer
  set rather than an opaque path hash; and
- the registered dual-signed baseline-relative ordinary-connectivity root.

Every renewal attempt obeys the shared sequence rules. A `BeforeConnector`
attempt has no child or tag-37 field. A `ConnectorTerminal` that enters the
target challenge uses `PhaseBoundCompleted` for every terminal result; its tag-37 root uses `Renewal` with this
lease ID/epoch, challenge nonce, and fence; repeats the exact proof
specification, target, attempt ordinal, tuple, candidate binding, connection
epoch, child, and first following accumulator; and has the target's challenge
kind. A connector that terminates strictly before target challenge entry uses
`NoCompletedResult` and has no tag-37 root. A present tag-37 root's optional proxy
endpoint equals the `ExternalProxy` candidate and is absent for `Direct`.
Activation/canary reuse, cross-attempt commitments, a target substituted as an
external peer, or a child absent from the named accumulator invalidates the
health wrapper.

Attempt-local `ExternalHttps` roots use `CurrentStateReaffirmation`,
`CurrentAbsenceReaffirmation`, and the exact `Renewal` context. A
`BeforeConnector` attempt has `ExternalHttpsPrepared`; a
`ConnectorTerminal` attempt has its own `ExternalHttpsHandshake`. System-root
modes include the exact fresh context-bound effective-trust observation;
private-anchor-only modes omit it. Drift invalidates the generation. Passed
attempts require passed tag-42 roots. SOCKS association evidence likewise uses
the exact per-attempt renewal context and cannot be reused.

`authenticators` contains exactly four unique values in role order:
`NetworkRuntime`, `PlatformDiscoveryBackend`, `PrivilegedHelper`, then
`WatchdogOrReconciler`. They sign the same sustained-health projection through
their required authority bindings. Missing/duplicate signer, key/channel
substitution, stale authority, or a malformed top-level accumulator reference/
chain invalidates the wrapper and operationally denies renewal; it does not
create a valid signed `HealthOutcome::Failed`. Once tag 34 and its tag-46/tag-44
children are structurally valid and authenticated, a `TerminalFailed` factory
latch, negative census outcome, complete-set/counter disagreement, sequence gap, or OS-only socket without
child provenance maps exactly to `SocketFactoryInvariantUnproven` under the
shared rule.

`HealthOutcome::Healthy` is valid exactly when every success group has its
first successful attempt with passed tag-37/TLS/SOCKS evidence, all attempt
checkpoints are complete/equal, and exclusion-readback/completeness,
barrier/fence, actor/endpoint/local-proxy identity, and ordinary-connectivity
predicates have their exact successful variants. For `RequireAssociate`, the
probe factory's top-level accumulator is the exact complete/equal close-only
teardown root, leaving no ARCH-002 verification child current-open for the next
lease epoch while retaining its chain root and the exact actor-wide set of
unrelated operational children described by the shared teardown rule;
other selections use the mandatory next `Empty` finalization/census root after
the traversal, tag-51, and tag-52 results freeze. A clean protocol-successful
final-attempt checkpoint is never top-level, including when a structurally valid
traversal/tag-51/tag-52 negative follows it. Negative attempts and valid
factory/census-negative/tag-51/tag-52 roots use the shared outer projection. A stale,
unknown, cross-context, or structurally invalid inner root invalidates the
wrapper rather than being hidden inside `Healthy` or `Failed`.

For `Healthy`, `exclusion_readback_observation_digest` names a `Complete`
tag-51 root and `ordinary_connectivity_observation_digest` names a `Passed`
tag-52 root, both in this exact renewal context/lease/fence and with the sealed
set/completeness/baseline. Their authenticated negative variants are allowed
only under the exact shared failure code. The four health authenticators are
the canonical verifier identity set; no producer-supplied verifier or opaque
helper/watchdog path digest exists.

Process liveness alone is insufficient. A runtime restart creates a different
runtime instance and invalidates the old actor identity. A proxy reconnect may
continue only as the next gap-free socket-factory sequence when the sealed plan
permits the exact same endpoint candidate and all identity, route, protocol,
exclusion, connected-local-peer, and proof predicates remain identical. Proxy-
endpoint DNS refresh or candidate-set change always needs a new generation; an
active plan never adds a newly resolved candidate.
Any sustained target observation reuses an authorized activation target and
all of its resolver, address-class, port, byte, redirect, and deadline bounds.

### 14.4 Interface, route, and identity change

A default interface, gateway, address-family, route table/metric, resolver,
network namespace/compartment, endpoint candidate/locality, local listener,
executable/policy identity, WFP/cgroup/mark rule, boot/suspend, or backend epoch
change invalidates the relevant evidence immediately.

The first-packet gate must close or already be closed before traffic can use an
unproven path. The helper denies renewal, advances the fence when required, and
rolls back the old generation. The Supervisor MAY prepare a new generation
after rollback and recovery complete. It MUST NOT hot-patch the active plan,
keep reporting `Active`, or use direct fallback while it discovers a new route.

A future plan schema may reserve a bounded consecutive-failure count and elapsed
threshold for transient target challenges, but v1 cannot enable or execute that
policy. ARCH-001 has no durable disposition that both denies the current
mandatory renewal evidence and safely continues the old lease. Any plan that
requests such tolerance is rejected before execution with
`UnsupportedPendingArchitecture/TransientHealthToleranceDispositionUnavailable`.
Under the current contract every tag-29 `Failed`, `TimedOut`, or `Cancelled`
outcome denies renewal and fences the old lease even when all other predicates
remain proven.

## 15. DNS and UDP dependency boundary

ARCH-002 defines selection and no-leak requirements; ARCH-004 owns generic UDP
flow identity, DNS routing/visibility, and `transport.udp.*`/`dns.*` resource
semantics.

Until ARCH-004 registers a required path, capability, exclusion dependency,
proof, and health predicate:

- a DNS name requiring `LocalAddress` cannot be activated through an ambient
  resolver;
- proxy-endpoint bootstrap DNS cannot recurse through the pending FlowProbe TUN
  or silently use direct DNS;
- a policy requiring SOCKS5 UDP cannot be active merely because negotiation
  syntax exists; and
- HTTP/HTTPS proxy selections cannot carry UDP and cannot silently pass it
  directly.

At runtime, every DNS/UDP/DoH/DoT/QUIC path is either explicitly permitted
through the selected path and complete exclusion set or explicitly blocked. A
timeout, unsupported proxy feature, resolver loss, or relay loss never changes
it to direct. ARCH-004 may define an explicit user-authorized direct fallback
as a different request/policy, but it cannot report that policy as the original
selection.

## 16. Errors and safe diagnostics

```text
EgressErrorCode =
  | InvalidEgressSelection
  | UnsupportedEgressVariant
  | UnsupportedProtocolFeature
  | ProtocolTransportUnsupported
  | EgressUnsupported
  | EgressPolicyProhibited
  | EgressPermissionRequired
  | EgressInteractionRequired
  | EgressTemporarilyUnavailable
  | EgressDegradedRefused
  | ProxyEndpointResolutionFailed
  | DestinationResolutionFailed
  | EndpointLocalityAmbiguous
  | RiskAcceptanceReceiptInvalid
  | ProbeTargetRequired
  | ProbeTargetAuthorizationInvalid
  | ProbePolicyProhibited
  | ProbePathUnproven
  | ProofObservationUnauthenticated
  | ProbeFailed
  | RuntimeCredentialDeliveryUnavailable
  | RuntimeArtifactContainmentFailed
  | ProxyTrustMaterialDeliveryUnavailable
  | ProxyTrustSnapshotChanged
  | PinnedAdapterNonconforming
  | ProxyConnectFailed
  | ConnectionRefused
  | NetworkUnreachable
  | HostUnreachable
  | DestinationConnectFailed
  | ProxyAuthenticationFailed
  | ProxyResponseMalformed
  | ProxyResponseTooLarge
  | ProxyTlsFailed
  | ProxyTlsIdentityMismatch
  | ProxyTlsTrustFailed
  | ProxyTlsRevocationUnavailable
  | ProxyTlsAlpnMismatch
  | ProxyTlsPolicyViolation
  | Socks5MethodUnsupported
  | Socks5ReplyFailed
  | Socks5UdpAssociateFailed
  | Socks5UdpCanaryFailed
  | Socks5RelayDomainUnsupported
  | Socks5RelayInvalid
  | Socks5FragmentationUnsupported
  | ListenerOwnerUnavailable
  | ListenerOwnerAmbiguous
  | ListenerIdentityChanged
  | ConnectedLocalPeerUnproven
  | ExclusionMechanismUnavailable
  | ExclusionSetIncomplete
  | ExclusionReadBackFailed
  | SocketFactoryInvariantUnproven
  | SocketObservationSequenceGap
  | NormalStopFinalizationUnavailable
  | BaselineAnchorChanged
  | OrdinaryConnectivityFailed
  | InterfaceOrRouteChanged
  | LoopDetectedOrUnproven
  | SustainedHealthFailed
  | DependencyContractUnavailable
  | OperationKindNotRegistered
  | TimedOut
  | Cancelled
  | RecoveryRequired
```

Every error includes operation, phase, selected tag, requested network scope,
family when applicable, safe endpoint/profile/plan digests, capability source
dimensions when applicable, retryability, and one bounded reason code. It MAY
include a bounded redacted display endpoint only when operator action requires
it.

Errors and logs MUST NOT contain:

- username, password, bearer value, credential handle, proxy authorization,
  challenge contents, Cookie, URL userinfo, or environment/command line;
- raw request/response fields, response body, arbitrary proxy text, captured
  payload, target nonce, or packet dump;
- raw certificate chain, private anchor material, pin value, or local CA private
  material;
- arbitrary helper/runtime stderr or unbounded OS message; or
- a full executable path unless an explicitly privileged operator diagnostic
  surface requires a bounded, access-controlled value. Ordinary diagnostics use
  stable identity digests.

Secret-canary verification must scan plan, journal, status, logs, error payloads,
renderer IPC, crash artifacts, and terminal receipts.

## 17. Deterministic verification contract

Deterministic tests MUST use fake runtimes, fake helper/backends, hermetic proxy
servers, and deterministic target fixtures. They MUST include:

### 17.1 Model and encoding

- every `NetworkScope`, `EgressSelectionV1`, address-family, resolution,
  authentication, TLS, UDP, disposition, readiness, and error variant;
- unknown/duplicate/missing fields, unknown tags, invalid bounds, malformed
  host/address/port, and proof that no default/substitution occurs;
- zero, exact maximum, maximum-plus-one, duplicate, reordered, truncated, and
  cross-list count/position mismatch for every bounded collection, including
  capability dimensions, resolution candidates, targets/receipts/commitments,
  protocol phases, actor paths, mechanisms, exclusions, identities, factories,
  and accumulators;
- stable canonical digest vectors with one dedicated HermeticTestOnly nonzero
  32-byte tag-0 request handle and safe descriptor digests in every downstream
  root, byte-exact deterministic-CBOR fixtures for all 57 root
  schema tags, graph/set ordering, optional-field tags, nested union tags,
  helper/signature-domain separation, wrong schema/version replay, non-minimal
  integers, wrong field order/count, and trailing bytes;
- a mechanically checked digest DAG proving subjects precede scopes/receipts,
  opaque trust node/slot IDs precede material/TLS/selection/config/plan digests,
  and consumption/delivery/observation records never feed back into a plan;
- a mechanically generated digest-field inventory that rejects every unresolved
  suffix, generic evidence/observation/identity hash, wrong ARCH-001 alias,
  content hash used as live evidence, and channel/content domain substitution.
  For `FactoryAdmissionReleaseCurrentIndexV1.index_checksum_sha256`, cross the
  exact domain string, every non-Unset variant tag and fixed field order, self-
  field exclusion, canonical-CBOR bytes, and substitution with every other 32-byte checksum/root/
  journal-head domain; it proves only index-record integrity, never live state by
  itself;
- exact domain-separated source/lock/conformance corpus manifests, single-file
  packaged-binary hashes, DER-versus-SPKI preimages, runtime-package fixed-array
  framing, trusted-release-keyset order, and rejection of path/order/length/
  runner/vector omission, direct-file-hash, text-dump, PEM/raw-key, or mutable-
  installed-file substitutions;
- every `RuntimeConfigTemplateV1` optional-presence combination allowed by the
  selected tag, protected-object and material-slot bounds/order, exact RFC 8785
  bytes, reserved-tag collision, user-object reference/detour, resolver-purpose
  mismatch, descriptor substitution, secret insertion, reload enablement, and
  alternate/private template serialization; cross every tag-1 selection,
  runtime package, template, proof specification, proof result, selected tag,
  and network scope, accepting only the byte-identical sealed tuple;
- all five fixed `AuthenticatedChannelContextV1` tags and arrays, with every
  missing/extra/reordered tuple field, public-key role reversal, zero key/
  exporter, generation/nonce/lease/fence/node/slot/gate substitution, endpoint
  component/key substitution, delivery-target owner mismatch, signer-to-
  endpoint-key mismatch, unknown variant, kind replay, and body-channel-versus-
  authority-channel substitution;
- every signed root crossed with every legal signer role and authority-binding
  variant, accepting only the exact table row, header, key, channel/authority,
  order, and contributor set; byte changes to the separately encoded header or
  the authenticator-omitted root projection must fail, and no duplicate implicit
  role encoding is accepted; the plan-independent `ReleaseVerifier` accepts
  only tags 49 and 53 under the exact trusted keyset revision and cannot sign any live
  capability/readiness/handshake/health root; and
- pre-plan tags 2, 4 (`ProxyEndpoint`/`ActivationProbeTarget` only), 5, 11, and
  55 (`Preplan` only) crossed with wrong ticket/session/
  generation/nonce/boot/suspend/component/channel fields, plan-bound authority,
  response replay, and cross-plan substitution; only the exact pre-plan
  discovery binding and signer identity may pass; and
- tag-4 `Socks5RelayCheckpoint` crossed against pre-plan/other-phase authority
  and both tag-55 plan-checkpoint variants crossed against pre-plan/single-signer/wrong-order
  authority; only their exact `PlanComponentAuthenticatedChannel` and, for
  tag 55, following `HelperAuthority` may pass; unsigned tag-54 policy roots are
  never put through a signer cross-product; and
- exact requested/prepared/active equality plus new-generation behavior for
  every explicit mode change or proxy-only acceptance.

Family tests separately vary the outer proxy endpoint and locally resolved
destination policies. They prove `ProxyName` always reports `ProxyOpaque`,
rejects a client-enforced destination-family request, never seals nonexistent
future per-flow address results, and cannot conflict with a second SOCKS UDP
resolution/family field because none exists.
They also cover literal IPv4/IPv6 proxy endpoints in both `HostLocal` and
`Remote` route classes, requiring exactly one tag-4 `LiteralNoResolution`
candidate with no resolver fields; DNS proxy endpoints require `ResolvedDns`.
Every external proxy proof/health root must carry that exact tag-4 digest and
`Direct` must omit it. Literal/DNS variant swaps, wrong optionality, candidate/
endpoint disagreement, or a target/relay tag-4 substitution is rejected.

Attempt-sequence vectors cross every connector/destination
`Ipv4Only`/`Ipv6Only`/`PreferIpv4`/`PreferIpv6`/`RequireBoth` combination for
`Direct`, `ProxyOpaque`, and external `LocalAddress`. They assert exact success-
group-major tuple order, destination-major grouping when only destination is
`RequireBoth`, contiguous group partitions, tuple ordinals `1` and `4` accepted
at their exact positions and `0`/`5` rejected, and exactly one target/profile/
receipt/tuple-plan entry; zero, two, or concurrent targets are invalid.
Tag-13 vectors cover one and 32 attempts, reject 33, exercise candidate ordinals
`1`/`8` and `0`/`9`, candidate-attempt indices one/two, the first two canonical
same-family proxy/target candidates, all three recoverable connect codes plus
bounded connect timeout, retry/no-retry, candidate and tuple advancement, group
exhaustion, and every prohibited skip/restart/jump. The compiler enumerates the
full worst-case serial decision tree and rejects any timeout budget that cannot
fit every legal maximum path; a producer cannot abandon a still-eligible
fallback because it omitted its budget. `RequireAssociate` budget vectors count
role A, the independent role-B connect/method/authentication/UDP-ASSOCIATE
work, and role C's single factory-start-through-finalization
`target_challenge` interval, extended through the close-only checkpoint for the
final successful active group, under the same `overall` deadline. Cross factory
completion/drain with cancel/deadline at the start, exact limit, and limit-plus-
one ordinals; reject any B, C, or teardown reset/omission. Independently compute
both-direction maximum conforming bytes plus every bounded over-bound sentinel
for every legal branch, including the exact C UDP envelopes and all attempts/
groups; accept
`maximum_total_protocol_bytes` equal to that maximum and reject maximum-minus-
one before sealing. Runtime max-plus-one inputs must select only their existing
phase-specific over-bound code, never a generic total-budget outcome.

Tag-28/tag-29 vectors replay only each tag-13 group's exact winning tuple and
candidate at index one, visit a non-empty contiguous group prefix of length at
most four, and reject retry, preference fallback, candidate substitution, a
later group after failure, or a new endpoint. They distinguish protocol-success
ordinals from later census/traversal failure, cover empty/proper-prefix/complete
lists, and require a new generation for any winner change. `HostLocal` vectors
accept only the sole literal single candidate and reject DNS-local, mixed-
locality, multi-candidate, retry/fallback, and connected-peer substitution.
HTTP authority, actual socket child/route/peer, tag-37 optional proxy endpoint,
and every NonceEcho target/tuple/attempt binding use that exact selected
candidate rather than another member of the sealed set.

### 17.2 Capability matrix

- every `StaticSupport`, `Readiness`, `Evidence`, `Disposition`, and enforcement-
  strength mapping independently for `ProcessAttribution`,
  `LocalListenerOwnership`, `LoopExclusion`, `PhysicalPathBinding`,
  `ActorNetworkIsolation`, `SocketCreationEnforcement`, and `SocketCensus`;
- version, scope, family, transport, actor, endpoint-locality, and evidence
  mismatches; and
- socket-factory `capability_report_digests` exact three/five bounds plus two/six,
  missing/extra/duplicate/reordered entries, first-slot creation-enforcement,
  second-slot full-census, remaining mechanism-order path reports, and every
  wrong key/mechanism/version/
  platform/network/actor/locality/family/transport/enforcement/readiness/release-
  evidence cross-product; and
- `HttpsProxyTls` report/evidence/build/package-manifest cross-binding,
  including wrong release keyset, OS/architecture/release, source revision,
  package/backend/adapter/binary/dependency digest, suite/vector digest, test
  count/result, changed tuple, unknown build, same runtime signer with a swapped
  stack, and missing manifest entry; and
- every non-TLS `RealHostVerified` capability report/tag-53 release-root tuple,
  including wrong key/mechanism/scope/enforcement/build/test corpus/count/
  result/manifest entry, duplicate release-verifier identity/key, actor-
  isolation report/policy/readback mismatch, cross-platform isolation
  mechanism, fake-in-release use, and rejection of a tag-49/tag-53 cross-
  substitution; tag-15 accepts only the exact factory/platform/helper three-
  signer set and tag-44 must repeat the second report plus a fresh independent
  first-report policy-instance/alternate-surface readback. Withdrawn enforcement,
  an empty census after withdrawal, self-signed instance state, wrong signer
  order, split cooperative producer binaries, identity-recipe/profile mismatch,
  or inability to enumerate every `Other*`/all-state socket remains unsupported;
  and
- proof that process/helper/runtime restart cannot create readiness or recovery
  evidence.

### 17.3 Protocol fakes

- direct IPv4, IPv6, both-family, family preference, resolution failure, bind/
  mark failure, route mismatch, timeout, cancel, and challenge failure;
- HTTP CONNECT authority and IPv6 brackets, every status class, 2xx transition,
  sealed `PreemptiveOnce` versus `ChallengeOnce`, 407 Basic retry,
  missing/duplicate/wrong scheme, malformed/truncated/oversized fields,
  forbidden redirect/body/header injection, safe status projection, credential
  scoping, TCP-only refusal, and proof that the pinned built-in HTTP client
  remains nonconforming;
- HTTPS proxy valid system/private trust, DNS-ID/IP-ID, SNI, TLS 1.2/1.3,
  wrong host/IP, unknown/FlowProbe-local CA, expired/not-yet-valid/wrong-usage
  certificate, filtered-root failure, wrong/substituted selected anchor,
  FlowProbe-CA anchor absent from the filtered set, a terminal anchor absent
  from the exact loaded set, valid and invalid single-certificate-anchor paths,
  every v1 algorithm/key-size/signature
  boundary, every closed cipher/group and TLS1.2 ServerKeyExchange/TLS1.3
  CertificateVerify signature scheme, including cross-version rejection, chain count/DER
  ceiling, rejection of `id-RSASSA-PSS`/RSA-PSS-PSS codepoints and every
  certificate-signature ECDSA issuer-curve/hash mismatch, plus acceptance of a
  TLS 1.2 P-256/`0x0503` ServerKeyExchange and rejection of the same pair in TLS
  1.3 CertificateVerify, rejection of a TLS 1.2 P-521 leaf, acceptance of TLS
  1.3 P-521/`0x0603`, and rejection of every TLS 1.2 negotiated-cipher/
  leaf-key/ServerKeyExchange-signature-family cross-product outside the exact
  ECDHE_ECDSA-or-Ed25519 and ECDHE_RSA mappings,
  leaf-SPKI AND semantics, rejection of the pinned insecure pin field,
  pre-sealed pin rotation, request-only handle absence, broker one-use delivery
  record, independent runtime-load and adapter-artifact roots, tuple/signer
  substitution, runtime gate/header/load-root/artifact-root channel-binding
  substitution, broker/delivery/materialize/load/remove/handshake time ordering,
  initial versus current-state/absence context binding, cleanup, ambient-root
  denial, exact ClientHello and proxy-handshake roots, unavailable negotiated-
  group/server-signature data in pinned Go public state, and store-epoch drift,
  resolve/socket/bind/route/TCP/HostLocal-peer failure before a connector with
  `ExternalHttpsPrepared` and no tag-42 root, post-release PrepareClientHello/
  expiry-guard/zero-byte-first-write `NotStarted`, partial versus complete
  ClientHello writes, TLS receive-budget exact/max/max-plus-one, and rejection
  of every prefix/byte/outcome mismatch, all three pre-ClientHello subphases
  crossed with `Failed`/`TimedOut`/`Cancelled` and accepted only as the exact
  `AuthenticateProxyTls` projection, every post-ClientHello failure category
  crossed against both TLS outer phases and accepted only under its defined
  phase/error mapping,
  same-plan different TLS child/connection epoch/proxy endpoint substitution,
  TLS-on-socket-A followed by CONNECT/target on socket B, and reconnect without
  a fresh child/local-peer/TLS root,
  `NoOnlineCheck` exact reporting, unconditional v1
  fresh-OCSP refusal, ALPN absent/http1.1/other, no IP-literal SNI, no resumption/
  early data, TLS alert,
  mixed TLS-1.2/1.3 offer downgrade protection with both `DOWNGRD\x01` and
  `DOWNGRD\x00` rejection, an ordinary suffix, and every minimum/maximum/
  negotiated-version/result-variant mismatch,
  TLS 1.2 empty-renegotiation SCSV/server acknowledgement and rejection of
  missing/non-empty acknowledgement or negotiated SCSV,
  TLS 1.2 extended-master-secret offer/echo/derivation and rejection of
  omission, unsolicited/non-empty echo, or legacy derivation,
  successful TLS followed by CONNECT/auth failure, and no HTTP fallback;
- SOCKS5 exact method negotiation, RFC 1929 length/status, `ProxyName` versus
  `LocalAddress`, IPv4/IPv6/domain forms, every reply code, malformed frames,
  method/auth/CONNECT send/read I/O versus credential-delivery versus protocol-
  rejection phase/code attribution, runtime wrong-form structural invalidity,
  BIND rejection, credential-risk policy, and exact compiler network mapping:
  `Disable` emits TCP only and never UDP, while `RequireAssociate` emits exactly
  TCP plus UDP and rejects TCP-only, omitted/default, reordered, or extended
  sets; and
- UDP ASSOCIATE over a dedicated role-B TCP connection: require a fresh greeting
  and independently repeated method/RFC-1929 exchange, exact IPv4/IPv6
  unspecified-same-family request, dedicated-control lifetime, and exact B
  request/reply digests and partial/over-bound evidence. Reject A=B, equal or
  reversed epochs/sequences, any second greeting/UDP ASSOCIATE byte on the
  CONNECT tunnel A, and any CONNECT/target payload on B; prove there is one
  broker delivery but two wire authentication sessions when credentials apply,
  reply-digest presence exactly for `Partial`/`Observed` and absence for
  `NotObserved`/`OverBound`, the exact 262-byte structural/`TrailingBytes`
  ceiling and 263-byte `OverBound` takeover even when the earlier prefix was a
  complete reply,
  earliest structural-reason priority including decisively invalid prefixes
  crossed with later EOF/timeout/cancel, exact reply `VER/REP/RSV` and all
  `REP=0x01..=0xff` mappings, wrong version/reserved byte, literal IPv4/IPv6 relay success, valid domain reply mapped to
  `Socks5RelayDomainUnsupported` with zero resolver/DNS actor/path/child and zero
  UDP child/canary bytes, malformed/unknown ATYP kept distinct, public-Remote
  literal singleton tag-4 evidence, local/non-public relay rejection,
  endpoint-independent full-tunnel exclusion, rejection of relay-selected
  privileged mutation, signed `TcpAndSocks5UdpCanary` target/receipt scope and
  TCP-only refusal, exact fresh UDP commitment/tag-48 one-use delivery, 40-byte
  FPEG request/response payload, IPv4/IPv6/domain whole-datagram lengths 50/62/
  `47+name_length`, relay-source validation, IPv4/IPv6/domain destinations,
  `RSV=0`, `FRAG=0`, drop-before-health-error for malformed/nonzero FRAG,
  loss/replacement, canary bounds, proof of no direct or UDP-over-TCP fallback,
  exact tag-50 target/attempt/tuple/candidate/context/runtime/A epoch+child/B
  epoch+child/C UDP-child/first-following-accumulator/relay/source/destination/frame/
  fragmentation bindings, cross-field and cross-digest-domain substitution,
  unique canary rejection priority, `NotSelected`/`SelectedLiteral` by terminal phase,
  response-datagram/frame digest and source/byte-count presence for every canary
  evidence variant, exact distinction between no datagram and a consumed empty
  datagram, expected/wrong-source 0/1/2/3-byte whole datagrams, empty-byte
  response-digest preimages, nonzero and zero-port IPv4/IPv6 sources crossed
  with normal and oversize datagrams, rejection of zero-port validation,
  IPv4/IPv6 zero-port content-domain and family/scope substitution, and proof
  that no raw zero-port source address/scope enters tag 50 or normal logs,
  serial terminal-event priority across simultaneous cancel/deadline/control-
  loss/datagram readiness and every pairwise/multi-event fake, including
  partial-reply-plus-FIN ownership and control loss versus a classification or
  already completed datagram/result, plus already-latched loss versus each new
  nonce/tag-48/delivery/write/frame/send readiness with zero new record or byte;
  exercise role-B factory start against pre-start cancel/deadline; every queue/
  create/mechanism/option-route-readback/HostLocal-peer/latch/sign/capacity/
  publication invariant failure; every successful-readback route drift and exact
  connect refusal/unreachable/timeout; and a terminal latch during the full
  operation. Accept only `NotStarted`, `UnpublishedProtocolTerminal`, published
  B plus immediate zero-byte method terminal, or the exact pre-publication
  `UdpControlChildReleaseAborted`/`TerminalFailed` branch. Cross HostLocal and
  every cancellation/deadline ordering against successful-readback route drift,
  all three connect refusal/unreachable codes, and bounded connect timeout:
  completion-first retains the ordinary phase outcome, terminal-first retains
  `Cancelled`/`TimedOut` on the active role-B phase, and neither publishes B or
  overwrites the winning ordinal. Cross HostLocal and
  Remote first-byte-guard failure after B publication and accept only
  `UdpControlFirstByteGuardAborted`, A+B chain-present/current-absent, zero
  greeting/auth/ASSOCIATE/UDP bytes, and outer factory priority. Reject a
  `BeforeConnector` encoding, B retry/fallback, a fake method protocol code, a
  second credential delivery, missing B tag-6 proof, and every A/B identity,
  epoch, role, route, peer-root, or same-proxy-child substitution;
  exercise positive classification followed by cancellation/deadline/liveness
  before the full child operation starts and during each queue/create/mechanism/
  option-route-readback/connect/latch/sign/final-publication step; after start,
  cross the drained operation's success and factory failure against every
  latched terminal and accept only the child-present immediate send terminal or
  `UdpChildReleaseAborted`/`TerminalFailed` branch. Also cross
  `EchoValidated` with each terminal event before and at the ordinal-bearing
  `AssociationReadyFinalization`; retain the echo terminal result and accept
  `AssociationReady/Passed` only when finalization wins with no snapshot-to-
  commit gap. After that snapshot, cross preactivation A/B/C chain-present and
  all-current-absent against postactivation/renewal per-attempt A-current-absent
  plus B/C-current-present tag-34 checkpoints; for one through four consecutive
  successful active groups require an exact verification projection of one
  through four retained B+C pairs with every A absent. For renewal, seed legal
  `RuntimeDestinationTcp` children in the same actor-wide factory and require
  them in addition to that projection; postactivation remains quiescent. After the
  final group, cross the `VerificationAssociationTeardown` completion ordinal
  against every queued loss/cancel/deadline: an earlier event denies success,
  while completion-first controlled-closes every retained pair and produces the exact next
  `Empty` tag-34 root with unchanged chain, final-attempt previous digest,
  close-inclusive counters, complete/equal sets with an empty verification-child
  projection, and non-terminal latch. Require tag 28's full set to be empty;
  for tag 29 require the full set to equal the final-attempt set minus the
  retained pairs and exactly recorded ordinary-close subset, with no new or
  unexplained child. Require tag 28/29's probe-factory top-level reference to
  name that root before outer publication. Inject provable close/bookkeeping/
  census failures and accept only the dual-signed actual-state factory-negative
  root and outer `SocketFactoryInvariantUnproven`; for every retained child
  position and each `SocketCloseFailureStepV1`, require the first failure in
  decreasing socket-sequence order to bind that exact child digest and reject a
  later-child, step, or reason substitution. Inject tag-34 construction,
  helper/watchdog signing, authentication/registration, and outer-signature
  failures and require no valid outer wrapper. Reject retained pairs, an invented child,
  missing/reordered cleanup, final-attempt top-level substitution, or treating
  controlled close as liveness loss. Cross FIN/RST
  and cancellation/deadline queueing during checkpoint and
  signature work, forced premature handle/provenance removal, tag-34 freshness/
  signer/census failure, and tag-50/outer deadline expiry,
  cross prior completed read/write/send/datagram records against later cancel/
  deadline/liveness ordinals, terminal-first network-operation cancellation
  against completion-first evidence, and cancel/deadline/liveness during each
  in-flight helper nonce/append/fsync/delivery/cleanup operation, requiring
  bounded drain and the exact actual durable/delivery/zeroization evidence or
  invalidating the wrapper when that proof is unavailable,
  every UDP-child queue/create/mechanism/option-route-readback/connect/latch/
  sign/limit/atomic-publication failure before the indivisible publication accepted only as
  `UdpChildReleaseAborted` plus absent child, `NotReached`, last passed
  classification, exact matching `TerminalFailed` counter/reason, terminal
  continuation, and outer `SocketFactoryInvariantUnproven`; accept only a clean
  complete/equal actual-state cleanup census. An independently negative census
  after the creation failure yields no valid wrapper and may not overwrite the
  already-latched reason. Reject a non-terminal latch, reason/counter mismatch,
  present child, nonce/tag-48/
  datagram, entered send phase, wrong outer code, retry, or relay/canary
  relabeling. Prove the atomic publication has no visible-child/uncommitted-
  sequence/unreleased-handoff split state; a post-publication C first-byte/send
  guard failure instead uses the child-present canary path with exact durable
  tag-48, constructed `Attempted` request, zero datagrams, `NotReceived`, and
  higher-priority terminal-latch projection,
  every fallible association phase crossed with failed/timed-out/cancelled; the
  `NotReached::{NotStarted,UnpublishedProtocolTerminal,Published}`, both control-
  abort variants, and `Observed` unique-prefix boundaries; exact A, A+B, and
  A+B+C traversal prefixes including B's `ProxyControl` item; the exact twelve-
  entry upper bound and thirteenth-entry rejection; the exact 24-entry success
  trace and 23/25-entry rejection; and
  proof that the
  pinned built-in UDP path remains nonconforming.

### 17.4 Probe and privacy

- plan-sealed specification versus post-`Prepared` exact-runtime result,
  prohibition on any pre-seal process/service, exact runtime/package/config/gate
  identity, public helper nonce and exact Ed25519 role/key/domain/channel
  substitution, dual-signer canary contribution, durable result
  before first shared mutation, and actual selected handshake versus config-only
  success;
- zero shared OS mutation during preactivation, pending-TUN recursion attempts,
  socket-factory/child mechanism omission, route change mid-probe,
  resolver/TTL change, forged/replayed/expired risk or target receipt, receipt-
  subject/scope/final byte-equality and digest-cycle prevention, broker issuance
  replay, closed consumption-record `RiskAcceptance`/`ProbeTarget` reference
  variants, receipt/scope cross-pair and generic/class-sibling rejection,
  consumption-record post-plan ordering, cross-plan/ticket/session/generation/boot/
  suspend replay, renderer-selected SSRF target,
  literal/resolved/ProxyOpaque presence matrix, classifier snapshot/version/
  source-byte hash/longest-prefix/mapping drift, metadata address-versus-port
  independence, IPv4-mapped normalization, mixed-class rejection,
  public/default-port boundaries, administrator-only exact special-use,
  permanently prohibited multicast/unspecified/broadcast, malicious target/
  metadata/link-local/port policy and DNS rebinding, redirect
  attempt, resolver/HTTP/TLS/OCSP/challenge/total-byte oversize, timeout,
  cancellation, concurrency/retry ceilings, and no mandatory public-cloud target;
- byte-exact NonceEcho magic/version/type/length, partial/extra/wrong/stale nonce,
  preactivation/checkpoint commitment and result domains, cross-target/phase/
  child replay, exact sole-target `target_id`, slot-to-commitment target/tuple
  preservation, commitment reuse under a changed context, tag-48 helper role/
  journal/domain/field binding, fresh delivery ID, record fsync before frame,
  crash before/after record fsync and before/during/after first write, partial/
  lost-ack failure with no frame reconstruction or redelivery, cancelled/failed/timeout byte
  counts, skipped tuple/terminal/cancel/expiry/runtime-or-channel-loss/record-or-
  fsync-failure/shutdown/crash invalidation of every undelivered in-memory slot,
  UDP nonce generation before tag-48 construction/fsync failure, durable-record
  delivery-not-received and received-before-datagram-construction branches,
  helper cleanup versus runtime signer authority, exact UDP phase-context and
  target/relay/destination/runtime/channel equality, TCP/UDP commitment and
  request/response digest-domain interchange rejection, runtime/channel
  substitution, terminal-time and first-following-
  accumulator binding, explicit target-TLS profile refusal, and missing-target
  interaction result; and
- full outer-outcome by inner-phase-outcome cross-products for preactivation,
  canary, and renewal, including every legal `BeforeConnector` terminal prefix
  and every legal `ConnectorTerminal` prefix; reject every phase/terminal-
  variant combination outside that boundary; require failed code equality,
  timed-out bounded-phase equality, and a fieldless outer `Cancelled` whose
  phase exists only on the unique final nested cancelled entry;
  accept the exact 24-entry successful `ExternalSocks5::RequireAssociate`
  trace under both `None` (both role-A and role-B
  `CompleteSelectedAuthentication` entries are `NotApplicable`) and
  `UsernamePasswordUtf8V1` (both are `Passed`), reject 23/25/33 entries, and
  never truncate a trace at 16;
  reject missing/future/placeholder child, accumulator, tag-37, TLS, SOCKS, or
  challenge evidence, prefix regression, terminal-phase disagreement, and a
  pre-runtime failure carrying a fabricated runtime root. Only an exact passed
  challenge plus every typed predicate may produce outer `Passed`/`Healthy`,
  NonceEcho byte counts must match, and an inner terminal failure maps to the
  exact outer terminal class and representable code/phase only in the absence of a higher-priority
  predicate. Cross every protocol/tag-42/tag-50 negative with census and, for
  tag 28, traversal negatives, plus every passed-challenge with
  non-challenge-predicate failure singly and multiply; only the first applicable
  failure in the closed priority order and its exact typed code may produce an
  outer `Failed`, while a stale/unknown/cross-context predicate root invalidates
  the result. Cross every protocol phase against the closed failed-code matrix,
  reject every nested typed-non-challenge/`TimedOut`/`Cancelled` failed code and
  reject `ProbePathUnproven` in every protocol phase, challenge result, and
  runtime-signed outer `ProbeOutcome`,
  and cover the unique `NoCompletedResult` versus tag-27/tag-37 boundary for a
  `ConnectorTerminal` pre-challenge prefix, preactivation TCP-negative, and every
  entered challenge; and
- credential/header/body/certificate/raw-target-nonce/path canaries proving no
  secret or payload appears in plan, journal, result, logs, errors, crash output,
  or any IPC except the exact matching `NonceEchoOneUseDeliveryFrameV1` for each
  closed phase context; the tests reject unknown/mixed context fields, wrong
  target/child/lease/fence binding, cross-phase replay, response-loss
  redelivery, and second
  delivery while the public helper anti-replay nonce remains verifiable.

Credential tests cover Basic UTF-8/colon/control/size and RFC 1929 field bounds,
one broker-to-runtime delivery versus repeated connections in one instance,
407/reconnect reuse only for the exact proxy, response-loss replay, rotation/
reload/new-instance refusal, owner-only no-follow artifact creation, deletion
after handshake, runtime crash, dump/swap policy evidence, zeroization, and
terminal artifact absence.

### 17.5 Listener identity and exclusion

- PID reuse, port reuse, listener close/rebind, FD transfer, process handle or
  pidfd loss, process creation change, executable replacement, symlink/hardlink
  path alias, signer/package change, namespace/compartment move, worker spawn,
  `SO_REUSEPORT`, wildcard/dual-stack mismatch, multiple owner, and endpoint DNS
  rebinding, plus listener replacement between pre-connect discovery and first
  proxy/authentication byte with connected-kernel-peer proof or refusal; both
  in-band and out-of-band cooperative-attestation attempts remain unsupported,
  and an in-band attempt emits zero ClientHello bytes;
- endpoint-set CNAME-chain zero/max/max-plus-one/loop/reorder cases, inline
  route/locality disagreement and stale epochs; local-listener nested owner/
  process/executable/policy substitution; every Windows/Linux local-listener
  and connected-owner member crossed against the other family; and an arbitrary 32-byte resolution,
  route, listener, or kernel-owner digest rejected because no such field exists;
- cross every tag-4 resolution/route/interface, tag-11 baseline/interface/
  route/resolver, and tag-14/tag-15/tag-31 profile/mechanism/identity-recipe/
  route-interface member across Windows, Linux, Darwin, cooperative, and
  Hermetic variants; also cross every profile with native/cooperative
  enforcement policy, compensation, census-owner scope, and retained-process
  identity. Accept only the exact closed aggregate and reject every real/fake,
  owned/cooperative, or cross-OS tuple in release builds;
- discovery-to-seal, seal-to-apply, apply-to-steering, steering-to-commit, and
  active-renewal race injection;
- remove each mandatory actor/path/family/transport/endpoint/DNS/probe/renderer/helper/
  watchdog/policy-broker/Supervisor/secret-broker/trust-material-broker/compiler/runtime-adapter/
  platform-backend entry one at a time and require pre-commit refusal; reject an
  unknown component/purpose and an unproved `NoExternalNetworkPath` declaration;
- exercise the complete `RequiredPath`/entry shared binding matrix: proxy
  control/tag-4, two DNS purposes/tag-3, three probe phases/the exact ordered
  tag-18 list for `Direct` versus the proxy tag-4 set for every external
  selection, five owned dynamic purposes/the same-actor tag-14 factory, and
  three local-proxy upstream purposes/tag-5; reject every wrong variant,
  target endpoint substituted as an external OS peer, proxy endpoint
  substituted as a Direct target, SOCKS relay/proxy-control candidate swap,
  missing/extra/reordered target, cross-actor factory, declaration/entry/
  completeness mismatch, and all-external scope used as destination authority;
- tag-54 actor-isolation-policy/tag-55 readback wrong actor, policy root,
  initialization branch, Preplan/Preactivation/Active checkpoint context,
  policy/readback epoch, proof/lease/fence, extra
  entrypoint/socket capability, extra/missing/reordered IPC permit,
  peer/schema/frame overflow, missing/extra/reordered checkpoint list,
  pre-plan replay at commit/renewal, single-signer checkpoint, and unsigned or
  generic sandbox-evidence substitution;
- for `HostLocal`, remove each `ExternalLocalProxyUpstreamDns/Tcp/Udp` purpose,
  substitute the identity, set `runtime_instance_id`, use the broad endpoint
  scope on another actor, add an unclosed worker/raw socket, or cover only
  selected destinations, and require refusal without process compensation;
- for every HostLocal connection, omit the peer root or substitute another
  plan/runtime/factory/sequence/socket/endpoint/listener/process/executable/
  exclusion identity, invert peer-child-TLS time, expire the peer after child
  signing but before release/first write, exceed peer expiry with a longer child
  expiry, fail the atomic first-byte expiry guard, or attach a peer root to a
  Remote child, and require zero protocol/credential bytes;
- cross `Direct`, `Remote`, and `HostLocal` through proof/health local-identity
  optionality and graph/exclusion equality; cross `EgressPathProofResultV1`
  endpoint/locality optionality against every selection and tag-4 candidate,
  rejecting negative, ambiguous, unsealed, changed, or mismatched values;
- install/replay/compensate the single socket-factory external permit; create
  bounded sockets/reconnects with gap-free sequence/accumulator/open-set/OS-
  census evidence and explicit first/consecutive empty and close-only
  checkpoints; prove any child count
  still produces only the one initial ARCH-001 permit trace; inject duplicate/
  missing sequences, alternate raw dialer, census extra/missing/duplicate/stale
  tuple or provenance, expected-digest/list echo attempts, nonce/barrier replay,
  create/close/barrier races, lifecycle-counter change/wrap, partial query,
  overflow, stale route, queue unavailable/full/timeout, atomic child-publication
  failure with no partially visible append/sequence/handoff state, wrong queue/epoch, Windows zero/24-bit/byte-order/
  ignored-IPv6 errors, Linux zero mark/mask, conflicting masked rules,
  `SO_BINDTOIFINDEX` failure/process-global fallback, factory restart, and helper
  observation-channel loss; also inject a surviving preactivation socket,
  steering intent before the empty transition census, a factory claim about an
  empty helper journal, phase-counter reuse/decrease/wrap, lease/fence change
  without an increment, a stale latch tuple, and socket creation while the
  barrier is closed, with zero application-protocol bytes on the socket whose
  publication/release fails; `UdpChildReleaseAborted` preserves the preceding
  SOCKS A+B/challenge prefix but has zero UDP-child/canary bytes;
  `UdpControlChildReleaseAborted` preserves only the current attempt's A and
  publishes no B phase/child, while `UdpControlFirstByteGuardAborted` preserves
  that attempt's A+B with both current-absent and zero B greeting bytes; neither
  prefix erases an earlier attempt's cumulative creation chain, and both apply
  the terminal cleanup rule to every earlier retained B+C current-open pair.
  Cross the exact primary Direct/HTTP/HTTPS/
  SOCKS, role-B, and role-C first-byte-guard projections, require the matching
  `FirstByteExpiryGuardFailed` latch and outer factory priority, and reject every
  role/phase/code/tag-42/tag-48/child-presence substitution. Separately
  require proof and canary roots to bind the next signed
  accumulator/census checkpoint; and
- exercise the complete verification-admission state machine. The executing
  factory's first tag-34 root is an `Empty` admission root from tag 15; an
  initial non-probe factory permits only its zero-child tag-28 precommit
  checkpoint. Reject a fabricated initial Open accumulator, Ordinary child, or
  catch-up root. Race admission against an already-started Ordinary create,
  local close, and peer/OS close in both shared-ordinal orders: ordinary-first
  drains into one separately authenticated chronological catch-up root before a
  distinct admission root, while admission-first admits no new Ordinary child
  and ledgers later removal without stealing reserved capacity. Cover all three
  `AdmissionAborted` causes and reject cross-context/request/reservation/root
  substitution; cover a post-admission factory terminal before attempt 1 and an
  inter-attempt factory/census terminal after each legal continuation. A cancel
  or deadline at admission-to-attempt-1 or between-attempt boundaries must
  become the determined attempt's `BeforeConnector`, never a zero-attempt or
  factory-boundary shortcut;
- cross capacity at each open and lease-new limit, one over each, and both over,
  requiring `OpenSocketLimitExceeded` to win the double exceed. Reject an
  accepted reservation whose full peak/total interval exceeds either limit, a
  rejected request substituted for a reservation, wrong ID/context/role/root/
  counter/release ordinal, noncontiguous Reserved child, or an Ordinary child
  under `VerificationOnly`, `Exclusive`, or stale Open authority. Verify existing
  `O_i` sockets continue payload I/O during Exclusive, may only close through the
  exact ledger, and cannot be replaced by a new unrelated child. Verify an
  unused reserved suffix consumes no socket sequence or lease-new count and that
  subsequent Reserved children accept the original admission root only through
  an unbroken Complete `Exclusive Running` suffix. Cross operation start,
  publication, and first byte at, below, and above every Open/admission,
  tag-50/tag-51/tag-52, receipt, lease, and parent deadline;
- cross closure-ledger empty/dynamic-maximum/5120/5121 bounds, first-root child-
  created-and-closed, counter lower/upper bounds and legal non-removal gaps,
  duplicate/reordered/unknown removals, and all four closure causes. Require a
  normal SOCKS sequence ledger such as A protocol-close followed later by C then
  B sequence-cleanup (`A -> C -> B`) in true lifecycle order; enforce decreasing
  socket sequence only within each frozen cleanup operation. A verification
  `PeerOrOs` removal requires its exact terminal-event ordinal and cannot satisfy
  clean teardown. Cross every factory/OS non-Complete pair and multi-defect case
  against the fixed census-failure priority, `CompleteFactoryProjection` versus
  `Unproven`, lifecycle-counter versus identity-set mismatch, and Complete-
  success equality. If a create/close/release/lifecycle failure was already
  latched, require a Complete actual-state projection; a later negative census
  yields no wrapper and never replaces the first reason; and
- cover every sequence-finalization topology: tag 13 and a non-protocol-success
  tag-28/tag-29 attempt finalize in their own cleaned checkpoint; a clean
  protocol-successful tag-28/tag-29 attempt always has one later `Empty`
  finalization root after frozen traversal/tag-51/tag-52, for positive and every
  structurally valid negative branch. `RequireAssociate` closes all retained
  B+C pairs on those branches; other selections still execute the no-child
  census barrier. Reject an extra root when the attempt checkpoint is already
  terminal/cleaned, a missing fresh root after protocol success, leaked retained
  pairs, or a factory-negative root hidden behind a lower-priority outer result;
- cross all three recoverable connect codes and bounded connect timeout at only
  Direct or `TcpConnectProxy { connection_role=TargetTunnel }` against retry/
  next-candidate/next-tuple continuation; cross the same four outcomes at role B
  against `ConnectorTerminal`+A, `UnpublishedProtocolTerminal`, no B sequence,
  and mandatory terminal continuation; and cross every creation,
  mechanism/readback, route, peer, release-latch, queue, signing, sequence, and
  inconsistent-connect failure against terminal factory/no second attempt. A
  `BeforeConnector` uses an `Empty` creation delta with changed lifecycle counts;
  every `ConnectorTerminal` child appears in exactly one first-following
  `NonEmpty` chain interval. A closed TLS/HTTP/SOCKS/challenge success or failure
  child is absent from both current provenance and OS set, while a live passed
  SOCKS association has, in its per-attempt projection, A chain-present/current-
  absent and B+C present in both current provenance and OS set. Across one
  through four consecutive successful active groups, require the cumulative
  verification projection of one through four retained B+C pairs and no group
  A, plus any independently seeded renewal operational set, followed on success
  by the mandatory close-only root with only the verification projection empty.
  Run consecutive successful renewal sequences and require each to start with
  zero prior ARCH-002 verification child current-open but the exact cumulative
  historical chain and exact legal actor-wide operational set, with no cross-
  lease verification-capacity growth,
  prior-pair reuse, or unsampled close. Cross
  a first-group terminal and one through three earlier successful groups
  followed by every ordinary protocol/cancel/timeout evidence variant and
  require the terminal checkpoint's verification current-open projection to be
  empty after controlled close while unrelated renewal children remain exact.
  Inject each close request/completion failure in mandatory decreasing sequence
  order and every bookkeeping failure, and require the
  factory/census negative with the actual cleanup state instead of the ordinary
  terminal; every opposite,
  duplicate, or mixed snapshot is rejected. Active/canary early connect failure
  never retries or falls back and cannot be hidden by a later success; and
- factory build-identity, actor-policy digest, enforcement/readback, alternate-
  path, release-guard, census-barrier, child mechanism/route, Linux complete
  higher-priority-rule set, and cooperative-profile field substitutions; no
  opaque factory-policy/readback/route digest is accepted. Cross every native/
  cooperative/Hermetic `PlatformSocketIdentityV1`, namespace/owner/family/
  transport tuple, late-bound owned termination slot and actual retained
  process binding, cooperative lease/provider/profile binding, child/provenance/
  peer/traversal equality, zero/fixed-size identity boundary, and cross-OS/
  cross-lease substitution; and
- route/mark/interface fake evidence proving every socket uses the sealed
  baseline anchor and that detective-only evidence is refused; cross a changed
  tag-11 anchor alone, a stable anchor with changed child interface/route alone,
  and both changes in one sample, accepting only `BaselineAnchorChanged`,
  `InterfaceOrRouteChanged`, and the fixed baseline-first priority respectively;
  and
- external proxy stop/recovery proving FlowProbe never kills or modifies the
  external process and removes only its own exclusion resources.

### 17.6 Transaction and health

- failure and response loss before/after every `egress.*` durable intent, OS
  apply, read-back, result fsync, steering apply, gate open, postactivation
  canary, success-side verification teardown/close-only census, commit, renewal,
  gate close, compensation, and recovery boundary;
- stale generation/lease/fence/revision, owner loss, helper/watchdog/runtime
  crash, boot/suspend, journal replay/corruption, external drift, and
  idempotent result replay under the ARCH-001 protocol;
- interface/default-route/gateway/DNS/family/VPN change, DHCP/RA-like epoch
  change, proxy/control/UDP-relay death or replacement, exclusion drift,
  sustained target failure below/at/above every future threshold candidate, and
  ordinary-connectivity loss. Every threshold-enabled plan must be rejected as
  `TransientHealthToleranceDispositionUnavailable`; without that future plan,
  every tag-29 `Failed`/`TimedOut`/`Cancelled` denies renewal. Tag-51 exclusion
  and tag-52 connectivity roots must reject unknown,
  missing, extra, reordered, cross-context, cross-lease/fence/baseline/set,
  stale, failed, and single-signer variants; and
- tag-28 traversal vectors contain exactly one zero-count observation for every
  released role-A connector, optional role-B association control, and optional
  role-C SOCKS UDP child, sorted by attempt/sequence,
  with exact actor/purpose/family/transport/endpoint/socket identity and complete
  tag-10 coverage. They cross zero/one/at-least-two/unavailable, missing/extra/
  duplicate/reordered/cross-attempt or cross-role child, exact per-attempt
  A/A+B/A+B+C prefixes, cumulative prior-group retention, four-group twelve-
  entry success, and thirteenth-entry rejection.
  Only zero satisfies
  the egress bypass; intended non-FlowProbe traffic's exactly-once assertion
  remains a separate real-host harness fact. Tags 28 and 29 each cross an
  attempt accumulator negative with every remaining top-level factory
  accumulator in factory-ID order and reject a producer-selected first failure.
  After every clean protocol-successful final attempt, both tags insert the
  finalization root after all attempt roots in outcome-priority order. For
  `RequireAssociate` that root cleanly tears down retained B+C on every
  structurally valid positive or traversal/tag-51/tag-52 negative branch; clean
  teardown is necessary but sufficient for `Passed`/`Healthy` only when every
  other predicate passes. A teardown-negative owns the outer factory failure;
  and
- bind tag 12, tag 13, tag 28, and tag 29 to one exact actor graph, runtime,
  source/probe actor, component, probe factory ID/epoch, tag-14 policy, tag-15
  observation, and every sequence tag-31/tag-34 root. Swap each field
  independently with another valid runtime/actor/component/factory/epoch and
  reject the wrapper even when the protocol, target, child set, and censuses are
  otherwise byte-identical. Reject a `PlanComponentAuthenticatedChannel` for
  any NetworkRuntime signer and require the exact selected runtime's
  `ExternalExecutorGate`/permit/gate-channel tuple throughout; and
- cross tag-13 `VerificationOnly` release against tag-28 commit and tag-29
  renewal all-factory handoff for 1, 2, and 32 factories, with the probe factory
  at the first, middle, and last index; reject zero/33, missing, duplicate,
  reordered, cross-factory, wrong-index, wrong-scope, wrong-receipt, wrong outer,
  and wrong previous-root lists. Tag 28 non-probe predecessors must be the exact
  initial zero-child Complete/equal `VerificationOnly` checkpoints; tag 29 non-
  probe predecessors must be their latest Complete/equal Open checkpoints. Cover
  probe `FinalizedHeld -> Open`, the sole tag-28 non-probe
  `Open(VerificationOnly) -> Open(OrdinaryAndVerification)` upgrade, the sole
  tag-29 same-scope authority refresh, and rejection of every other Open-to-Open
  transition. An outer negative, terminal factory, or failed batch produces no
  effective Open root or Ordinary child;
- exercise the target sole composite ARCH-001 protected index through both exact
  release paths: `Unset -> BoundClosed -> ReleasePending(Postactivation) ->
  Committed` and `Committed -> ReleasePending(Renewal) -> Committed`, plus
  `BoundClosed|ReleasePending|Committed -> GenerationClosed -> BoundClosed`.
  A pristine installation has only `Unset { index_epoch=0 }`, and that value is
  rejected in every tag-15 readback. The first egress-bearing `PreparePlan` and
  every later one after an authenticated prior-generation close must atomically
  bind `Unset` or `GenerationClosed` to `BoundClosed` with epoch plus one, the
  exact new plan/generation, complete ascending factory list, and exact bind-
  parent tip. Reject a non-pristine `Unset`, any direct `Committed` or
  `ReleasePending` to new `BoundClosed`, an unclosed/fenced old actor, a wrong
  parent, and epoch reset, reuse, skip, or wrap. Tag 13 leaves the byte-identical
  `BoundClosed` value selected;
- require the future registered commit/renewal composite transition to create
  `ReleasePending` with epoch plus one, a fresh nonzero batch ID, exact outer
  digest/ordinals/typed receipt, disposition-time sample, immutable earliest
  release deadline, disposition tip, plan/generation, and factory list. The
  Postactivation tip must equal the commit receipt head/revision and its prior
  release is only `NeverCommitted`; the Renewal tip must equal the `LeaseRenewed`
  result head/revision and its prior digest **and paired batch tip** must equal
  the exact CAS-predecessor `Committed`. Cross every wrong disposition, receipt,
  outer, plan, generation, list, batch ID, tip component, prior digest/tip pair,
  deadline/clock domain, predecessor, and epoch. While pending, old and candidate
  tag-56 roots, Ordinary/Reserved creation, a second pending transition, a return
  to old `Committed`, and a new generation are all denied. A pre-lock ordinary
  close may change only the factory-local ledger/counter/provenance and must be
  first authenticated by its batch member without advancing the helper tip; any
  independent post-receipt checkpoint/helper append makes the pending CAS stale;
- require tag 56 to change only the byte-identical current `ReleasePending` to
  same-generation `Committed`, preserve the factory set, repeat the exact batch/
  disposition fields, and advance the epoch once. Any pre-selector crash,
  persistence/signature/terminal/freshness failure, or expired pending state is
  unresumable: it keeps pending non-authorizing, consumes no candidate counter,
  allocates no replacement batch ID, and fences through safe cleanup to
  `GenerationClosed`. Stop, preparation rollback, fence/recovery, and generation
  retirement must likewise close `BoundClosed`, `ReleasePending`, or `Committed`
  with the exact reason, close-parent tip, and respectively no committed release,
  the pending Renewal's exact prior tag 56, or the current exact tag 56. The next
  generation binds only from selected `GenerationClosed`; its `BoundClosed`
  makes every old tag-56 root and readback non-authorizing;
- at every bind, disposition-to-pending, batch commit, close, and next-generation
  rebind boundary, inject candidate-slot checksum, composite core/extension,
  selector-write/flush, response-loss, and crash failures before and after each
  durability point. Require one old or one new whole composite value, never a
  mixed state. Replaying an accepted ARCH-001 request returns only its stored
  response and never repeats or reselects an index transition. Reject every
  `Arch001JournalTipV1` field reorder/width/domain error, head/revision cross-
  pairing, and substitution among the six legal nested tip paths. At initial
  batch commit the core tip equals `Committed.batch_tip`; a later outer tip is
  legal only through an authenticated same-authority descendant suffix, while
  either-direction core/extension mismatch, broken ancestry, or revision
  discontinuity fences recovery. Also prove current ARCH-001 rejects a direct
  helper-storage read and arbitrary `Status` extension and lacks the mandatory
  typed authenticated proof query, so every profile remains exactly
  `UnsupportedPendingArchitecture/AdmissionReleaseProofReadUnavailable` and
  `DurableAdmissionReleaseCommitUnavailable` rather than accepting a substitute;
- verify tag-56 canonical encoding/digest and exact helper-then-watchdog role/
  authority signatures. For the all-factory helper journal transaction, require
  the receipt result head/revision as the exact current CAS base and first
  member's durable parent, exact transaction-local parent heads/revisions for
  every factory-ID-ordered tag-34 member and tag 56 last, final authoritative
  revision `R + member_count + 1`, the exact copy-on-write index epoch/head/
  count/checksum, and one
  atomic protected-selector commit to that tag-56 digest. Require no committed,
  authoritative, or effective prefix. Inject root/signature/watchdog/vector-
  fsync/index-slot/selector failures at every member and every byte/record
  boundary, including torn or complete-but-uncommitted physical tails. Crash
  before/after candidate-vector plus inactive-slot durability, and before/after
  the distinct selector durable commit; the entire intermediate window keeps
  the selected non-authorizing `ReleasePending` value authoritative, never the
  superseded prior `Committed`. Also cover stored ARCH-001 response replay, stale
  receipt, wrong tag-56 member digest/ordinal/expiry, and later fence/recovery
  suffix. Before index commit none of the staged roots authorizes a child, the
  exact pending protected index remains authoritative, and recovery ignores,
  quarantines, or truncates the tail. After commit all roots, tag 56, and the
  selected index replay byte-identically; any checksum/epoch/head/count/vector
  mismatch, selector ambiguity, missing index, or unsafe suffix fences recovery.
  In the future target architecture, observe every factory guard before and
  after the selector linearization:
  before it all conditional Open members are non-current, their transition
  counters are unconsumed, and a child attempt at each index is denied; after it
  every member/counter becomes current only through the same registered proof
  reader and post-selector handoff. Reject one-factory early activation, direct
  storage access, cached/mirrored index values, per-factory acknowledgement, a
  missing proof-reader binding, and reuse of an aborted staged counter.
  Race a stop, next renewal, fence, recovery, and ordinary helper mutation at
  the same base revision; require one mutation-lock/CAS winner and
  `StaleStateRevision` for every loser or later request using the old receipt
  revision;
- race each adjacent acceptance boundary in both orders: outer publication vs
  terminal, disposition vs terminal, combined-lock acquisition vs an ordinary
  close or unresolved external loss, each staged release member vs terminal,
  final event-drain/completion reservation vs terminal, tag-56 signing vs a
  queued terminal, candidate-vector durability vs persistence failure, and
  selector durable commit vs terminal, pre-selector uncached clock read vs
  expiry, selector acknowledgement vs expiry, post-ack clock read vs expiry,
  post-ack late-event drain vs terminal, handoff vs terminal, and handoff vs the
  first Ordinary admission. Prove the acceptance gate remains held from final
  drain through selector acknowledgement, the second clock check, and atomic
  health/fence handoff. A terminal ordered before the reserved completion aborts;
  one ordered after selector commit but before handoff leaves tag 56 historical,
  keeps every creation gate closed, and appends fence/health; a failed selector
  leaves the signed ordinal/time/root non-authoritative. Cross precheck-pass with
  postcheck-fail and a crash between selector acknowledgement and postcheck;
  neither permits product acceptance or a child. From each outer-
  listed checkpoint, new Ordinary creation is held; a close before the full
  all-factory lifecycle lock is acquired changes no helper tip and is included
  in that member's ledger only after local bookkeeping completes and the member
  first dual-authenticates it; an unresolved close at
  acquisition or any external loss ordered before the completion reservation
  aborts the batch. After handoff, require the terminal and every Ordinary
  publication to acquire the same acceptance gate: terminal-first denies the
  child, admission-first publishes exactly one child before the terminal becomes
  the next-health/rollback event.
  Terminal-before-disposition denies the mutation. After durable disposition,
  the completed pre-lock ordinary-close exception remains ledgered; every other
  terminal before tag 56 leaves the final ARCH-001 result historical and appends
  fenced recovery. Completion-first preserves tag 56, but the later event must
  win the ordered handoff or subsequent shared-gate race before any later child
  when its ordinal is earlier. Verify an old tag-56 root and old renewal receipt
  become non-authorizing as soon as Renewal `ReleasePending` is selected and
  remain so after a later batch, while later same-authority Ordinary
  `NonEmpty`/`Empty` checkpoints form an unbroken Complete Open suffix from the
  batch member to `most_recent_open_accumulator_digest`; and
- proof that failure closes/fences the old path, denies commit or renewal,
  performs reverse rollback, never hot-patches the plan, never direct-falls
  back, and never reports the refused original mode active.

The transaction model separately proves normal stop keeps the healthy data path
available until steering/DNS/routes/TUN no longer depend on it, then closes the
single ARCH-001 barrier and stops actors; emergency failure closes/fences that
same barrier first. It rejects a second egress gate/lease/journal and every
unregistered privileged `egress.endpoint-bypass-route.*`,
`egress.policy-route.*`, or `egress.actor-identity-policy.*` operation.
Until ARCH-001 is extended, it also proves every tuple remains unsupported,
rejects reuse of recovery acknowledgement for a healthy stop, and never
publishes terminal `Inactive` without a registered typed final-revision
acknowledgement.

Tests MUST NOT weaken an expected result to match an unsafe implementation.

## 18. Real-host release gates

For every exact OS/architecture/release/package/backend/network-scope/egress-tag/
family/transport combination claimed supported, a privileged clean-host gate
must exercise the shipped artifacts. At minimum each claimed platform requires:

1. a direct egress loop canary;
2. a local external proxy loop canary using the claimed listener-identity and
   exclusion mechanism;
3. IPv4 and IPv6 canaries for every claimed family;
4. TCP and SOCKS5 UDP canaries for every claimed transport;
5. before/during/after ordinary-connectivity oracles;
6. exactly-one Capture Core traversal for intended traffic and zero traversal
   for every excluded runtime/Capture/helper/watchdog/probe/local-proxy path;
7. interface/default-route and endpoint/listener replacement tests;
8. start, normal stop, runtime/proxy/helper/watchdog crash, owner loss,
   response-loss, suspend/resume first-packet barrier, boot recovery, and drift
   tests at every mutating boundary; and
9. artifact, backend, capability, plan, journal, packet-marker, target-nonce commitment,
   and final baseline-equivalence evidence sufficient to reproduce the claim.

The local proxy canary uses synthetic credentials and payloads only. It proves
the external proxy remains independently owned and that its egress bypasses the
captured path. A remote proxy, loopback-only proxy without TUN, fake runtime,
source inspection, upstream sing-box test, process-start check, or one OS API
probe cannot substitute.

A failure in any required canary removes `Supported` for that exact scope. It
does not automatically remove a narrower separately proven scope, but the
narrower scope must be reported exactly and never as the failed one.

## 19. Primary protocol and platform references

Normative protocol behavior derives from:

- [RFC 9110 section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
  for CONNECT, tunnel establishment, proxy authentication, and response framing;
- [RFC 9110 section 11.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7)
  and [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html) for
  `Proxy-Authorization` scoping and the selected HTTP Basic encoding;
- [RFC 9112 section 3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2)
  for HTTP/1.1 authority-form versus absolute-form request targets;
- [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html) for SOCKS5 method,
  address, CONNECT, UDP ASSOCIATE, relay, source, lifetime, and FRAG behavior;
- [RFC 768](https://datatracker.ietf.org/doc/html/rfc768) for the optional/zero
  UDP source port and minimum eight-octet UDP length that permits an empty
  application datagram, and
  [RFC 8085 section 5.1](https://www.rfc-editor.org/rfc/rfc8085.html#section-5.1)
  for exact receiver source-address/port checks and its `SHOULD NOT`, rather
  than wire-level prohibition, on source port zero;
- [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929.html) for username/password
  subnegotiation and field limits;
- [RFC 5246 section 7.4.3](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.3)
  for TLS 1.2 server `ServerKeyExchange`,
  [section 7.4.1.2](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.2)
  for the TLS 1.2 ClientHello session ID,
  [section 7.4.8](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.8)
  for the distinct client `CertificateVerify`, and
  [RFC 8446 section 4.1.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2)
  for ClientHello/HelloRetryRequest ordering,
  [section 4.1.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.3)
  for ServerHello downgrade sentinels,
  [section 4.2.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.1)
  for the complete preferred supported-version list,
  [sections 4.2.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3),
  [4.2.7](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.7),
  [4.2.8](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8),
  [4.2.10](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.10), and
  [4.2.11](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11)
  for signature algorithms, early data, and PSK key exchange,
  [RFC 8446 section 4.4.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3)
  for TLS 1.3 server `CertificateVerify`,
  [RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3)
  for SNI,
  [RFC 5280 section 6](https://www.rfc-editor.org/rfc/rfc5280.html#section-6)
  for certificate path validation, and
  [RFC 8422 sections 2.1 and 2.2](https://www.rfc-editor.org/rfc/rfc8422.html#section-2.1)
  for the TLS 1.2 ECDHE_ECDSA/EdDSA and ECDHE_RSA authentication-family
  mapping, and
  [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html) for TLS deployment
  constraints, and
  [RFC 5746 sections 3.3 and 3.4](https://www.rfc-editor.org/rfc/rfc5746.html#section-3.3)
  for TLS 1.2 secure-renegotiation signaling and server acknowledgement, and
  [RFC 7627 sections 4, 5.1, and 5.2](https://www.rfc-editor.org/rfc/rfc7627.html#section-4)
  for TLS 1.2 extended-master-secret negotiation and derivation, and
  [RFC 4055 sections 3.1 and 3.3](https://www.rfc-editor.org/rfc/rfc4055.html#section-3.1)
  for RSA-PSS subject-key and signature parameter distinction, and
  [RFC 5077 section 3.2](https://www.rfc-editor.org/rfc/rfc5077.html#section-3.2)
  for the TLS 1.2 session-ticket extension;
- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html) for the explicitly
  unsupported-until-implemented fresh-OCSP policy; and
- [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html) for configured service
  reference identity, DNS-ID, IP-ID, and matching; and
- the byte-pinned [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv)
  and [IPv6 special-purpose registries](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv)
  for `ProbeAddressClassifierSnapshotV1`.

Candidate implementation semantics are evidenced by:

- pinned sing-box 1.13.19 revision
  [`b5ebaa1fc0f2b94256180b95468e73ef53caa27d`](https://github.com/SagerNet/sing-box/tree/b5ebaa1fc0f2b94256180b95468e73ef53caa27d),
  whose [`go.mod` pins sing v0.8.13](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/go.mod#L37),
  especially its [HTTP CONNECT/TLS outbound](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/protocol/http/outbound.go#L29-L66),
  [SOCKS TCP/UDP outbound](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/protocol/socks/outbound.go#L38-L116),
  [dial option schema](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/outbound.go#L65-L94),
  [outbound TLS option schema](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/tls.go#L97-L120),
  [standard TLS pin behavior](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/tls/std_client.go#L114-L121),
  [pin verification callback](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/tls/std_client.go#L223-L239),
  and [interface/mark application](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/dialer/default.go#L52-L135),
  together with sing v0.8.13's
  [HTTP client state machine](https://github.com/SagerNet/sing/blob/v0.8.13/protocol/http/client.go#L115-L150),
  [SOCKS UDP association](https://github.com/SagerNet/sing/blob/v0.8.13/protocol/socks/client.go#L136-L150),
  [SOCKS packet decoder](https://github.com/SagerNet/sing/blob/v0.8.13/protocol/socks/packet.go#L39-L99),
  [Windows bind behavior](https://github.com/SagerNet/sing/blob/v0.8.13/common/control/bind_windows.go#L25-L56),
  [Linux bind fallback](https://github.com/SagerNet/sing/blob/v0.8.13/common/control/bind_linux.go#L13-L40),
  and [Linux mark behavior](https://github.com/SagerNet/sing/blob/v0.8.13/common/control/mark_linux.go#L7-L11);
- pinned Go 1.24.7
  [`crypto/tls.ConnectionState`](https://github.com/golang/go/blob/go1.24.7/src/crypto/tls/common.go#L235-L311)
  and [default groups/signature schemes](https://github.com/golang/go/blob/go1.24.7/src/crypto/tls/defaults.go#L18-L44);
- Microsoft [GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable),
  [GetExtendedUdpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable),
  [process access](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights),
  [process handle lifetime](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers),
  [process creation time](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes),
  [`GetIfEntry2`/`MIB_IF_ROW2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2),
  [GUID-to-LUID](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceguidtoluid)
  and [LUID-to-index](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoindex)
  interface mappings,
  [`GetFileInformationByHandleEx`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex)
  with [`FILE_ID_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info),
  [`WinVerifyTrust`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust),
  [`CreateFileMappingW`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw)
  and [`UnmapViewOfFile`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile),
  [WFP condition identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-),
  [WFP object and dynamic-session lifetime](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management),
  [IPv4 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options),
  and [IPv6 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options);
- pinned Linux man-pages
  [`socket(7)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man7/socket.7?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c)
  for `SO_MARK` and `SO_BINDTODEVICE`,
  Linux v6.6 [`SO_BINDTOIFINDEX` UAPI](https://github.com/torvalds/linux/blob/v6.6/include/uapi/asm-generic/socket.h#L106-L110),
  [set path](https://github.com/torvalds/linux/blob/v6.6/net/core/sock.c#L1505-L1507),
  and [get path](https://github.com/torvalds/linux/blob/v6.6/net/core/sock.c#L1972-L1974),
  [`pidfd_open(2)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man2/pidfd_open.2?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`pidfd_getfd(2)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man2/pidfd_getfd.2?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`unlink(2)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man2/unlink.2?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`mmap(2)`/`munmap(2)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man2/mmap.2?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`sock_diag(7)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man7/sock_diag.7?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`proc_pid_fd(5)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man5/proc_pid_fd.5?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`proc_pid_stat(5)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man5/proc_pid_stat.5?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`proc_pid_exe(5)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man5/proc_pid_exe.5?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`statx(2)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man2/statx.2?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`rtnetlink(7)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man7/rtnetlink.7?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  kernel [route rules](https://docs.kernel.org/netlink/specs/rt-rule.html),
  [routes](https://docs.kernel.org/netlink/specs/rt-route.html),
  [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html), and
  [cgroup socket-address BPF program types](https://docs.kernel.org/6.9/bpf/libbpf/program_types.html); and
- Apple Network.framework
  [`requiredInterface`](https://developer.apple.com/documentation/network/nwparameters/requiredinterface)
  and the pinned XNU public socket constants
  [`IP_BOUND_IF`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/in.h#L443)
  and [`IPV6_BOUND_IF`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet6/in6.h#L642),
  plus Endpoint Security [`es_process_t`](https://developer.apple.com/documentation/endpointsecurity/es_process_t)
  and Security.framework
  [`SecCodeCopySigningInformation`](https://developer.apple.com/documentation/security/seccodecopysigninginformation%28_%3A_%3A_%3A%29),
  contrasted with XNU's private-marked
  [`libproc` interfaces](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.h#L38-L42)
  and provider-scoped
  [`NEFlowMetaData`](https://developer.apple.com/documentation/networkextension/neflowmetadata).

These platform sources document primitives, not complete FlowProbe ownership,
transaction, recovery, loop-prevention, packaging, or release support.

## 20. Compatibility and migration

FlowProbe is unreleased. Implementations replace the incomplete boolean direct-
probe scaffolding with this typed contract directly. No legacy tag, default
coercion, compatibility adapter, migration journal, or old-mode alias is
defined. Production compatibility or migration requires a separate explicitly
authorized task.
