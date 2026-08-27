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
- use a port in `1..=65535`.

Every object embedded in an ARCH-001 plan, helper request, journal observation,
signature, or digest inherits the exact deterministic-CBOR profile in the
Privileged Network Helper contract: fixed-length arrays in displayed field
order, zero-based union tags in displayed alternative order, shortest integers,
bounded NFC text, no maps, floating point, generic CBOR tags, indefinite
lengths, trailing bytes, or unknown fields. An optional field is encoded as the
closed union `Absent | Present { value }`, with tags zero and one; an absent
value is never encoded as an empty string, zero digest, empty list, or null.

Only a root in the following registry may be independently digested, signed, or
named by an ARCH-001 plan/journal field. A nested value has no independent
digest domain unless it also appears here. The fixed root-schema tags are:

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
                                         37 TlsTargetChallengeResultV1
                                         38 ProxyRiskAuthorizationSubjectV1
                                         39 ProbeTargetAuthorizationSubjectV1
                                         40 ProxyTrustMaterialDeliveryRecordV1
                                         41 ProxyTrustMaterialArtifactObservationV1
                                         42 ProxyTlsHandshakeObservationV1
                                         43 SocketIdentitySetV1
                                         44 OsSocketCensusV1
                                         45 ProbeAddressClassifierSnapshotV1
                                         46 FactorySocketCensusObservationV1
```

For registered root schema tag `T`, version `V`, and its fixed-array CBOR value
`X`, every ARCH-002 root digest is exactly
`SHA-256("FlowProbe.Egress.Object.v1\0" || uint16_be(T) || uint16_be(V) || X)`.
A field that names a digest owned by another accepted contract MUST name that
contract's exact schema, version, and digest domain in the enclosing registered
root; arbitrary evidence bytes or an implementation-private hash are invalid.
A digest used in a different schema, version, plan, helper request, or field
domain is invalid. Helper frame/request authentication remains the separate
helper domain; this object digest never substitutes for controller proof or a
frame/observation signature. The compile-time schema package MUST contain byte-
exact golden vectors for every registered root and nested union, including each
rejection boundary, and two independent codecs must accept/reject the same
vectors before support. Tags `0..=46` are contiguous and immutable in v1; a
codec with a missing, duplicated, or renumbered tag is nonconforming.

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

EndpointScopeV1 =
  | SingleEndpoint { endpoint_identity_digest }
  | ResolvedSet { resolved_endpoint_set_digest }

IpFamilyPolicy =
  | Ipv4Only
  | Ipv6Only
  | PreferIpv4
  | PreferIpv6
  | RequireBoth

ResolverDependencyDescriptorV1 = {
  resolver_path_id,
  resolver_policy_digest,
  resolver_actor_id,
  baseline_anchor_digest,
  family_scope,
  maximum_candidates,
  expires_at,
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
`input_endpoint_digest`, or `endpoint_host_and_port_digest` is
`Digest(EndpointIdentityV1)`. Endpoint collections use
`Digest(ResolvedEndpointSetV1)`. An endpoint digest never hashes an informal
display string.

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
overall deadline. There are at most four target profiles, two concurrent proof
connections, two address attempts per family, and two HTTP CONNECT exchanges
including an authentication retry.

HTTP response status plus fields are limited to 32 KiB, 100 fields, and 8 KiB
per field line. A target marker is limited to 256 bytes. Implementations MAY set
lower product or administrator limits but MUST report the effective values in
the safe plan descriptor. Exceeding a bound returns a typed failure and closes
the connection.

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
  | ExplicitRiskAcceptance { receipt_digest }

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
  receipt_class = RiskAcceptance | ProbeTarget,
  receipt_digest,
  issuer_identity_digest,
  receipt_id,
  decision_nonce,
  preparation_ticket_id,
  session_id,
  generation,
  authorization_scope_digest,
  candidate_plan_digest,
  prepare_idempotency_key,
  prepared_plan_id,
  plan_digest,
}
```

`credential_handle` is an opaque, non-displayable capability held only by the
Supervisor/secret broker boundary. It MUST NOT be passed to the helper or
renderer and MUST NOT appear in a durable plan, journal, runtime command line,
environment, status, error, or ordinary log.

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
`ExplicitRiskAcceptance.receipt_digest` to that receipt. No projection with a
missing closed-union member is defined or accepted. All duplicated ticket/
session/generation/scope fields in the receipt and scope must match. Both
receipt classes expire no later than five minutes after issue on a suspend-aware
continuous clock and are invalid after boot or suspend epoch change.

Receipt keys are Ed25519. The 32-byte issuer public key and installation/policy
scope form `issuer_identity_digest`; `receipt_id` and `decision_nonce` are fresh
32-byte values. The 64-byte signature is over the fixed-array canonical receipt
without its signature, prefixed by
`FlowProbe.Egress.RiskReceipt.v1\0`. Target receipts use the distinct domain
`FlowProbe.Egress.TargetReceipt.v1\0`. A receipt is usable only by the exact
candidate plan whose `AuthorizationGrantDigest` contains it. The broker's
durable issuance key is `(policy_broker_challenge, authorization_scope_digest)`:
an exact response-loss retry returns the byte-identical receipt, while reuse of
the challenge with a different scope is rejected. During
`PreparePlan`, the helper durably stores one
`AuthorizationConsumptionRecordV1` for the non-secret tuple
`(receipt_class, receipt_digest, issuer_identity_digest, receipt_id,
decision_nonce, preparation_ticket_id, session_id, generation,
authorization_scope_digest)`. For risk receipts the
scope digest is exactly `Digest(ProxyRiskAuthorizationScopeV1)`; for target
receipts it is exactly `Digest(ProbeTargetAuthorizationScopeV1)`. The record
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
  exact_owner_identity_digest,
  access_policy = OwnerOnlyExclusiveNoFollowNonInheritable,
  cleanup_policy = RemoveAfterAuthenticatedLoad,
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
      lease_epoch,
      renewal_challenge_nonce,
      fence_token_digest,
    }

ProxyTrustRuntimeStateV1 =
  | InitialLoad {
      loaded_anchor_set_digest,
      loaded_spki_pin_set_digest?,
      initial_loaded_at,
    }
  | CurrentStateReaffirmation {
      initial_load_observation_digest,
      loaded_anchor_set_digest,
      loaded_spki_pin_set_digest?,
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
      materialized_owner_identity_digest,
      owner_access = OwnerOnly,
      exclusive_create = Enforced,
      no_follow = Enforced,
      link_or_reparse_point = Absent,
      non_inheritable = Enforced,
      materialized_at,
      absence_query_scope = ExactObservedResourceIdentity,
      artifact_absent_after_load = true,
      residual_artifact_handles = Absent,
      removed_at,
    }
  | CurrentAbsenceReaffirmation {
      initial_artifact_observation_digest,
      materialized_anchor_set_digest,
      materialized_spki_pin_set_digest?,
      absence_query_scope = ExactObservedResourceIdentity,
      artifact_absent_after_load = true,
      residual_artifact_handles = Absent,
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
  client_hello_policy_image,
  started_at,
  completed_at,
  expires_at,
  outcome,
  authenticator,
}

ClientHelloPolicyImageV1 = {
  offered_versions_wire_order,
  offered_cipher_suite_codepoints_wire_order,
  offered_group_codepoints_wire_order,
  offered_signature_scheme_codepoints_wire_order,
  offered_alpn = Absent | Http11,
  sni_observation,
}

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

ProxyTlsHandshakeOutcomeV1 =
  | Passed {
      reference_identity_result,
      trust_chain_result,
      certificate_time_and_usage_result,
      certificate_algorithm_observation,
      revocation_result,
      pin_result?,
      loaded_anchor_set_digest,
      loaded_spki_pin_set_digest?,
      negotiated_version,
      negotiated_cipher_suite_codepoint_u16,
      negotiated_group_codepoint_u16,
      server_authentication_scheme,
      negotiated_alpn = Absent | Http11,
      session_resumed = false,
      early_data_sent = false,
      renegotiation_count = 0,
    }
  | Failed { bounded_phase, error_code }
  | TimedOut { bounded_phase }

ProxyTlsEvidenceReferenceV1 =
  | NotApplicable
  | ExternalHttps {
      proxy_tls_policy_descriptor_digest,
      trust_material_descriptor_digest,
      delivery_record_digest,
      runtime_load_observation_digest,
      adapter_artifact_observation_digest,
      tls_handshake_observation_digest,
      fresh_effective_trust_snapshot_digest?,
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
or exactly `http/1.1`; any other selected protocol is
`UnsupportedProtocolFeature`. TLS 1.2 renegotiation, TLS 1.3 early data, and
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
  SHA-256/384/512, RSA-PSS-RSAE/PSS with SHA-256/384/512, RSA-PKCS1 with
  SHA-256/384/512, or Ed25519. The ECDSA signature scheme does not encode a
  curve; the separately validated certificate public key and named group carry
  their own constraints;
- TLS 1.3 server `CertificateVerify` permits ECDSA with SHA-256/384/512,
  RSA-PSS-RSAE/PSS with SHA-256/384/512, or Ed25519, and prohibits RSA-PKCS1;
- accepted certificate public keys are RSA 2048..=8192 bits, ECDSA P-256/P-384/
  P-521, or Ed25519, and certificate signatures are RSA PKCS#1/PSS or ECDSA with
  SHA-256 or stronger, or Ed25519; and
- DSA, static RSA key exchange, CBC, RC4, 3DES, MD5, SHA-1, unknown algorithms,
  a chain deeper than eight certificates, or a chain larger than 64 KiB DER is
  rejected.

An implementation that cannot configure and verify this exact suite/group/
signature policy is unsupported; it MUST NOT delegate any portion to a drifting
runtime default.

An effective system snapshot contains `1..=1024` anchors totaling at most 4 MiB
DER, sorted by DER SHA-256. It is observed for at most five minutes and binds the
platform store scope, backend/version, store revision, boot epoch, complete
FlowProbe interception-CA exclusion set, and final filtered-anchor-set digest.
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
artifact handle, and signs `ProxyTrustMaterialLoadObservationV1`. The load root
proves runtime-internal state; the artifact root, which depends on it, proves
adapter-owned creation and deletion. The broker record binds only the expected
target/recipe/slot and consumer channel; it never claims an actual observed file
identity.

Neither signer may attest the other's facts, and both bind the same plan,
descriptor, delivery record, runtime instance, node ID, node `OperationDigest`,
and actual artifact identity. Initial facts obey
`consumed_at <= delivered_at <= materialized_at <= initial_loaded_at <=
removed_at`; every preactivation TLS handshake starts at or after `removed_at`
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
roots repeat `SustainedHealthObservationV1.lease_epoch`,
`renewal_challenge_nonce`, and `fence_token_digest`. A root from another phase or
an earlier checkpoint is invalid even if all material digests are unchanged.

The helper verifies both signatures and cross-field equality, compares safe
material values with the broker record and expected ARCH-001 operation/result
identities, and stores only registered roots/digests. It does not read raw
anchors. Missing material, slot reuse, time inversion, snapshot drift, runtime/
config substitution, ambient-root/reload fallback, inherited/residual handle,
single-signer evidence, or cleanup failure makes every affected HTTPS mode
unsupported and blocks commit or renewal.

Every TLS connection to an HTTPS proxy emits one registered
`ProxyTlsHandshakeObservationV1` signed by the `NetworkRuntime`. The observation
binds the context-matched independent material observations and delivery record,
the exact socket child/connection, and an actual wire-order ClientHello policy
image. Offered versions contain `1..=2` unique values, cipher suites `1..=16`,
groups `1..=8`, and signature schemes `1..=16`; each list is in emitted wire
order and contains exactly the allowed policy subset, with no GREASE, SHA-1,
unknown, or drifting default entry. ALPN and SNI follow their closed unions.

Only `Passed` carries reference-identity, chain/time/usage/algorithm/revocation/
pin results and negotiated values; failure/timeout carries only a bounded phase
and reason, so no placeholder success facts exist. `Tls12ServerKeyExchange` is
valid only with TLS 1.2 and records the exact 16-bit signature/hash codepoint;
`Tls13ServerCertificateVerify` is valid only with TLS 1.3 and the fixed server
context. A TLS 1.2 ECDSA codepoint does not assert a certificate curve; the
certificate key and negotiated group are independently checked. A passed root
requires every decision to pass, material/load/artifact equality,
`DnsANameEmitted` exactly for `DnsId`, `AbsentForIpId` exactly for `IpId`, no
resumption, zero early-data bytes, zero renegotiations, a policy-permitted ALPN,
and completion before `expires_at`. The root retains no raw certificate, chain,
transcript, SNI buffer, OCSP bytes, or alert text.
`pin_result`, `loaded_spki_pin_set_digest`, and the corresponding delivery/load/
artifact pin fields are present exactly for a pin-bearing trust mode and absent
otherwise; a present result must prove the leaf SPKI is in the exact delivered
set. The loaded anchor and pin digests in `Passed` equal the delivery, load,
artifact, policy, and descriptor values byte-for-byte.

### 4.6 SOCKS5 UDP policy

```text
Socks5UdpPolicy =
  | Disable
  | RequireAssociate {
      relay_resolver_dependency?,
      relay_family_policy,
      probe_datagram_bytes,
    }

SocksRelayFamilyPolicy =
  | RelayIpv4Only
  | RelayIpv6Only
  | RelayAnyUnicast
```

`probe_datagram_bytes` is in `1..=1024`, applies only to the ARCH-002 synthetic
canary, and must fit the bounded relay buffer after RFC 1928 overhead. ARCH-004
owns application-datagram size, flow, fragmentation, and transport policy.
`Disable` means a request requiring UDP is rejected. `RequireAssociate` means
UDP MUST traverse one RFC 1928 association through the selected proxy or the
request is rejected. Neither variant authorizes direct UDP or UDP-over-TCP.
The association's destination addressing inherits the selection's single
`destination_resolution`; there is no second family/resolution choice to
conflict with it. `relay_resolver_dependency` is absent only if a returned relay
name is prohibited; when present it is the sole permitted resolver for a SOCKS
reply whose `BND.ADDR` is a domain name.
`relay_family_policy` uses exactly `SocksRelayFamilyPolicy`; the proxy returns
one association endpoint, so preference and `RequireBoth` semantics are not
claimed.

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
P.egress_selection_digest == Digest(SafeEgressSelectionV1::from(R.egress_selection))
A.network_scope == P.network_scope
A.egress_tag == R.egress_selection.tag
A.plan_digest == Digest(P)
```

`SafeEgressSelectionV1::from` is the sole permitted projection. It preserves the
variant and every field in displayed order, replaces each HTTP/SOCKS credential
handle with the exact `RuntimeCredentialDescriptorV1` digest, and changes
nothing else. TLS trust is already represented by the exact
`ProxyTlsPolicyDescriptorV1` digest. A projection that drops or rewrites an
authentication exchange, receipt, trust, resolver, UDP, family, timeout, or
policy choice is invalid.

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

The pinned built-in SOCKS UDP path does not provide the sealed relay resolver,
relay locality/source proof, or drop-before-delivery validation of RSV/FRAG.
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
path. None implies either of the others.

### 6.2 Capability report

```text
CapabilityReportV1 = {
  key,
  disposition,
  static_support,
  readiness,
  evidence,
  mechanism,
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
  evidence_digest,
  reason_code,
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
  input_endpoint_digest,
  resolution_purpose,
  resolver_dependency_digest,
  normalized_candidates,
  canonical_name_chain_digest?,
  negative_or_positive,
  observed_at,
  expires_at,
  resolver_epoch,
  route_epoch,
  evidence_digest,
}

ResolvedCandidate = {
  address,
  family,
  scope?,
  locality,
  route_observation_digest,
}

ResolutionPurpose =
  | ProxyEndpoint
  | ActivationProbeTarget
  | Socks5Relay
  | RuntimeDestinationObservation

EndpointLocality =
  | HostLocal { local_class }
  | Remote
  | Ambiguous

HostLocalClass =
  | Loopback
  | HostAssignedAddress
  | OsHostLocalRoute
```

The set contains at most the dependency's eight candidates, deduplicated and
ordered by the selected purpose-specific family policy. Proxy endpoint and
activation-target sets are discovered in ARCH-001 `Preflighting` and sealed in
the candidate plan. A SOCKS relay set is produced by the sealed observation
recipe after the runtime returns `BND.ADDR`; a future runtime-destination set is
per-flow evidence under the sealed policy and is never pretended to have existed
in the activation plan. Ambient re-resolution by a runtime library is forbidden
whenever `LocalAddress` is selected. The runtime receives the selected address
set plus the original hostname needed for HTTP authority, SNI, or certificate
identity; `ProxyName` sends the name to the proxy and has no local result set.

TTL expiry, resolver epoch change, route epoch change, or a candidate-set change
invalidates the result. A negative result cannot be replaced by an ambient
lookup. CNAME or service-discovery intermediates never replace the configured
TLS reference identity.

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

If a candidate set contains both host-local and remote addresses, every candidate
that policy may select must have the required evidence for its locality. The
exact chosen proxy-endpoint or activation-target candidate is pinned in the
plan. A SOCKS relay chosen later is bound to its pre-sealed observation result;
a per-flow runtime destination remains flow evidence. Revalidation immediately
before commit must reproduce every commit-relevant address, locality, resolver
epoch, and route epoch.
DNS rebinding from remote to local or local to remote invalidates the plan.

## 8. Local listener identity

### 8.1 Discovery record

```text
LocalProxyIdentityV1 = {
  proxy_profile_digest,
  selected_endpoint,
  transport,
  address_family,
  namespace_or_compartment,
  listener_identity,
  listener_owner_observation,
  live_process_observation,
  stable_executable_or_platform_identity,
  exclusion_policy_identity,
  provenance,
  observed_at,
  expires_at,
  boot_epoch,
  route_epoch,
  evidence_digest,
}

ConnectedLocalPeerObservationV1 = {
  prepared_plan_digest,
  generation,
  runtime_instance_id,
  socket_factory_epoch,
  socket_sequence,
  connected_socket_identity,
  connected_peer_tuple,
  sealed_local_proxy_identity_digest,
  peer_binding_evidence,
  retained_peer_process_identity_digest,
  stable_executable_or_platform_identity_digest,
  exclusion_policy_identity_digest,
  observed_before_first_proxy_byte = true,
  observed_at,
  expires_at,
  authenticator,
}

ConnectedPeerBindingEvidenceV1 =
  | KernelEstablishedConnectionOwner { observation_digest }
  | CooperativeCryptographicPeer {
      profile_digest,
      tls_or_attestation_identity_digest,
      signed_process_and_policy_binding_digest,
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
closed after `connect` succeeds. For plaintext HTTP/SOCKS it occurs before the
runtime sends any protocol or credential byte. For HTTPS, a bounded TLS
handshake may precede the observation only when a sealed private-anchor or AND-
pin identity participates in an accepted cooperative attestation that binds the
same process and exclusion-policy identity; no CONNECT or proxy credential may
be sent first. While the actor socket factory
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

A platform that cannot prove which process accepted the established connection
MUST NOT send plaintext proxy bytes or credentials to that local endpoint. It
may become supportable only through an accepted cryptographic/cooperative peer
attestation bound to the same process and exclusion identity; ordinary HTTPS
server authentication alone is insufficient. Otherwise
the path is `UnsupportedPendingArchitecture/ConnectedLocalPeerUnproven`.
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
  identity_digest,
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
      sandbox_or_policy_evidence_digest,
      permitted_local_ipc_digest?,
    }
  | RequiredPath {
      purpose,
      families,
      transports,
      endpoint_set_digest?,
      resolver_dependency?,
    }

PathPurpose =
  | ProxyEndpointBootstrapDns
  | RuntimeDestinationDns
  | Socks5RelayDns
  | ProxyControl
  | RuntimeDestinationTcp
  | Socks5UdpRelay
  | CertificateStatus
  | PreactivationProof
  | PostactivationCanary
  | SustainedHealth
  | RecoveryConnectivityProbe
  | ProductTelemetry
```

The graph contains at least one instance for every component in the trust table,
even when that component is an in-process library. Every instance has at least
one declaration. `NoExternalNetworkPath` requires a preventive sandbox, socket-
creation policy, or equivalent measured evidence; source review or a convention
is insufficient. Local typed IPC is listed separately and does not authorize an
Internet socket. A probe is a `PathPurpose` on the actual component that opens
the socket: the preactivation, postactivation, and selected connector paths are
normally declarations of the same `NetworkRuntime` instance, not fictional
probe processes. If an implementation introduces a separate process, it adds a
distinct actor instance before sealing. Certificate-status, resolver,
telemetry, helper/watchdog, platform-backend, secret-broker, trust-material-
broker, and recovery paths are treated identically. An unknown component class
or purpose makes the graph invalid rather than implicitly networkless.
The release Renderer entry is mandatory and uses `NoExternalNetworkPath` with
preventive renderer sandbox/socket-deny policy evidence. Its local typed IPC is
separately bounded. The renderer policy identity is sealed, re-read before
commit and at renewal, and any drift closes the gate; source review, UI intent,
or omission from the graph is not evidence that it is networkless.

### 9.2 Exclusion entries

```text
EgressExclusionSetV1 = {
  network_scope,
  egress_selection_digest,
  baseline_anchor_digest,
  actor_graph_digest,
  entries,
  completeness_proof_digest,
}

EgressExclusionEntryV1 = {
  actor_id,
  purpose,
  families,
  transports,
  endpoint_scope,
  identity_digest,
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
  egress_selection_digest,
  actor_graph_digest,
  sorted_exclusion_entry_digests,
  covered_actor_path_family_transport_endpoint_tuples,
  required_tuple_count,
  completeness_checker_schema_and_version,
  completeness_checker_build_digest,
  outcome = Complete,
}
```

Each required path has exactly one or more entries whose union covers every
declared family, transport, endpoint, DNS bootstrap, proxy control connection,
SOCKS5 UDP relay, certificate-status connection, and target probe. Entries must
name the sealed baseline egress anchor and prevent use of any FlowProbe capture
interface, route/table, redirect, or recursive proxy input.

The completeness checker is closed over the actor graph and selected protocol.
It rejects an unrecognized actor/path/purpose. Omitting one entry, covering only
IPv4 for a dual-stack path, covering TCP but not a required UDP/DNS path, or
using only `Detective` evidence in full-tunnel is `ExclusionSetIncomplete`.
`EgressExclusionSetV1.completeness_proof_digest` is exactly
`Digest(EgressExclusionCompletenessProofV1)`. Its sorted entry digests and covered
tuples must be one-to-one with the set and graph; a producer cannot supply an
opaque checker hash or a count without the canonical tuple list.

### 9.3 Baseline egress anchor

```text
BaselineEgressAnchorV1 = {
  platform_stable_interface_identity,
  namespace_or_compartment,
  ipv4_route_tuple?,
  ipv6_route_tuple?,
  gateways,
  route_table_and_metric,
  resolver_dependency_digest?,
  observed_at,
  expires_at,
  interface_epoch,
  route_epoch,
  evidence_digest,
}
```

Interface name/index and current local address are locators, not the stable
identity. The anchor may represent a pre-existing administrator VPN or other
baseline default path when that is the observed ordinary network. “Physical”
in product language means this sealed pre-FlowProbe path or a platform protect
mechanism with equivalent escape from the pending capture path; it does not
authorize bypass of administrator policy.

The anchor is read-only during preflight. Its exact current tuple is re-read
before mutation and commit. A changed interface, gateway, table, metric,
namespace/compartment, family availability, or route epoch invalidates the
prepared plan.

## 10. Preactivation path proof

### 10.1 Sealed proof specification

```text
EgressProofSpecificationV1 = {
  preparation_ticket_id,
  session_id,
  generation,
  runtime_instance_id,
  runtime_package_and_build_digest,
  runtime_config_template_digest,
  network_scope,
  egress_selection_safe_digest,
  baseline_anchor_digest,
  endpoint_resolution_digest?,
  local_proxy_identity_digest?,
  probe_targets,
  target_authorization_receipt_digests,
  timeout_budget,
  maximum_challenge_bytes,
  maximum_total_protocol_bytes,
  redirect_limit,
  retry_limit,
  concurrency_limit,
  nonce_commitments,
  expected_observation_schema_digest,
  expected_proxy_tls_evidence,
  expires_at,
}

ExpectedProxyTlsEvidenceV1 =
  | NotApplicable
  | ExternalHttps {
      proxy_tls_policy_descriptor_digest,
      trust_material_descriptor_digest,
      delivery_root = { tag = 40, version = 1, signer = TrustMaterialBroker },
      runtime_load_root = { tag = 24, version = 1, signer = NetworkRuntime },
      adapter_artifact_root = { tag = 41, version = 1, signer = RuntimeAdapter },
      handshake_root = { tag = 42, version = 1, signer = NetworkRuntime },
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
  target_resolution_evidence_digest?,
  exact_network_scope,
  exact_egress_tag,
  address_authorization,
  port_authorization,
  challenge,
  expected_identity_digest?,
  maximum_challenge_bytes,
  profile_version,
}

ProbeTargetProfileV1 = {
  authorization_scope_digest,
  authorization_receipt_digest,
  target_id,
  endpoint,
  target_resolution_policy,
  target_resolution_evidence_digest?,
  exact_network_scope,
  exact_egress_tag,
  address_authorization,
  port_authorization,
  challenge,
  expected_identity_digest?,
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
  source_registry_revision_ids,
  sorted_prefix_rules,
  sorted_exact_metadata_addresses,
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
  | TlsHandshake { tls_policy_descriptor_digest }
  | NonceEcho { protocol_version = 1 }

NonceEchoCommitmentEntryV1 =
  | HelperAssignedSlot { target_id }
  | SealedCommitment { target_id, commitment }

NonceEchoChallengeResultV1 = {
  prepared_plan_digest,
  generation,
  target_profile_digest,
  commitment,
  response_frame_digest?,
  bytes_sent = 40,
  bytes_received,
  outcome,
}

NonceEchoOutcome =
  | Passed
  | Failed { error_code }
  | TimedOut
```

`redirect_limit` is always zero. `retry_limit` is at most one retry per sealed
candidate and cannot change selection. `maximum_challenge_bytes` includes all
application challenge bytes and is at most 1024 bytes in each direction.
`maximum_total_protocol_bytes` is at most 256 KiB across the proof: each resolver
exchange is at most 64 KiB, HTTP response head 32 KiB, TLS certificate chain
64 KiB, OCSP response/responder chain 32 KiB each, and every SOCKS frame is
bounded by its one-octet/RFC 1928 fields. Exceeding a per-phase or total limit
closes the connection and yields a typed failure. No target response body is
read after the fixed challenge completes.

`expected_proxy_tls_evidence` is `ExternalHttps` exactly for that selected tag
and otherwise `NotApplicable`. It seals only descriptor digests, fixed root
tags/versions, signer-role set, and freshness bound. It never contains a future
delivery/load/artifact/handshake observation digest. The corresponding result,
canary, and renewal references must satisfy this expectation without changing
the proof specification or `PlanDigest`.

Receipt construction starts from the registered
`ProbeTargetAuthorizationSubjectV1`, not from a profile projection. The subject
contains all target fields, including network scope and egress tag, but contains
neither `authorization_scope_digest` nor `authorization_receipt_digest`. The
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
`SingleLiteralEndpoint` requires `target_resolution_evidence_digest` absent;
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
not an `EndpointIdentityV1`, so its class cannot vary by port. Source revision
identifiers are `1..=4` bounded ASCII tokens in ascending byte order. The only
accepted v1 sources are the byte-exact IANA IPv4 and IPv6 special-purpose CSV
snapshots last modified 2025-10-09 with SHA-256 values
`e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73`
and `775feea0621dec8735a44fbf30f762e721e8f0a1b3ab7eb341961a88cfce2139`,
respectively. `source_registry_revision_ids` is exactly the two ascending ASCII
tokens `iana-ipv4-special-2025-10-09-sha256-e3e39e76d00b1677` and
`iana-ipv6-special-2025-10-09-sha256-775feea0621dec87`; the complete hashes above,
not the shortened display tokens alone, are verified when generating the fixed
snapshot. Every comma-separated address block in a CSV cell becomes a distinct
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
with no current flags maps to `ReservedOrFutureUse`. The snapshot binds each
normalized prefix, source-row identity, global flag, and class mapping;
classification never performs an ambient online registry lookup. `Multicast`,
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

For `NonceEcho`, a candidate proof specification contains exactly one
`HelperAssignedSlot` per such target and no producer-selected commitment. During
`PreparePlan` sealing, the helper replaces each slot with `SealedCommitment`,
then computes the final specification/plan digest returned in `Prepared`. A
prepared or executing plan containing a slot, or a candidate containing a
commitment, is invalid. The helper generates a fresh unpredictable 32-byte nonce
for each replacement. The request frame is exactly 40 bytes:
`0x46 0x50 0x45 0x47 || 0x01 || 0x00 || uint16_be(32) || nonce`; the response is
the same frame with message type byte `0x01` and the identical nonce. A wrong
magic/version/type/length, partial frame, changed nonce, any trailing byte before
peer close, or failure to close within the target deadline is failure. The
commitment is exactly
`SHA-256("FlowProbe.Egress.NonceEcho.Commit.v1\0" || preparation_ticket_id ||
session_id || uint64_be(generation) || target_profile_digest || nonce)`. The
helper stores one sealed commitment per NonceEcho target, ordered by
`target_id`, and releases the raw nonce once to the exact runtime in one
authenticated delivery frame bound to preparation ticket, final plan digest,
generation, target profile digest, commitment, `RuntimeInstanceId`, and the
already authenticated runtime gate/channel. That one-use frame is the only IPC
in which the raw target nonce may appear. It is never journaled, replayed,
buffered into a generic message log, exposed to the Supervisor/renderer, or
retained by either endpoint after acknowledgement; wrong plan/runtime/channel/
target/commitment binding, response-loss retry, or a second delivery is refused.
The runtime zeroizes it after use. The response digest is
`SHA-256("FlowProbe.Egress.NonceEcho.Result.v1\0" || commitment ||
response_frame)`; plan, journal, result, logs, and IPC retain only the commitment
and `NonceEchoChallengeResultV1`, never the raw target nonce. In the preceding
sentence, “IPC retain” excludes only the transient authenticated one-use frame
defined above; no other IPC representation is permitted.
`Passed` requires exactly 40 received bytes and the response digest present;
failure/timeout requires it absent and reports only the bounded reason and actual
received-byte count in `0..=40`.

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
mutating preparation ticket. It does not start a runtime, probe process, or
internal service and does not claim the actual path proof has run. The candidate
plan binds the proof specification and expected observation predicate, never a
future result.

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
7. close the proof connection when it is not the selected long-lived SOCKS5 UDP
   association and zeroize transient challenge/transcript state. Runtime proxy
   credentials remain only under the sealed runtime credential lifecycle.

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
  signer_identity_digest,
  public_key_identity_digest,
  authority_binding,
  algorithm = Ed25519,
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

ObservationAuthorityBindingV1 =
  | ExternalExecutorGate {
      prepared_plan_digest,
      permit_id,
      runtime_or_component_instance_id,
      gate_channel_binding_digest,
    }
  | PlanComponentAuthenticatedChannel {
      prepared_plan_digest,
      component_instance_id,
      channel_binding_digest,
    }
  | HelperAuthority {
      helper_installation_identity_digest,
      boot_epoch,
      prepared_plan_digest,
      journal_head_and_revision,
    }
  | WatchdogFenceDomain {
      watchdog_identity_digest,
      boot_epoch,
      suspend_epoch,
      prepared_plan_digest,
      activation_lease_id,
      fence_token_digest,
      channel_binding_digest,
    }

EgressPathProofResultV1 = {
  prepared_plan_digest,
  proof_specification_digest,
  helper_assigned_observation_nonce,
  generation,
  controller_id,
  connection_binding_epoch,
  runtime_instance_id,
  runtime_executor_identity_digest,
  runtime_gate_channel_binding_digest,
  runtime_package_and_build_digest,
  runtime_config_template_digest,
  selected_tag,
  selected_network_scope,
  selected_endpoint_digest?,
  endpoint_locality?,
  target_profile_digest,
  connector_socket_family,
  destination_family_observation,
  protocol_phase_outcomes,
  proxy_tls_evidence,
  socks5_relay_observation_digest?,
  baseline_anchor_digest,
  socket_factory_policy_observation_digest,
  proof_socket_child_observation_digest,
  socket_observation_accumulator_digest,
  route_observation_digest,
  challenge_kind,
  challenge_result,
  started_at,
  completed_at,
  expires_at,
  outcome,
  reason_code,
  authenticator,
}

ProbeOutcome =
  | Passed
  | Failed { error_code }
  | TimedOut { bounded_phase }
  | Cancelled
  | Refused { capability_disposition, error_code }

DestinationFamilyObservation =
  | LocalIpv4
  | LocalIpv6
  | ProxyOpaque

ProtocolPhaseOutcomeV1 = {
  phase,
  outcome = Passed | Failed { error_code } | TimedOut | NotApplicable,
  safe_evidence_digest?,
}

ChallengeResultReferenceV1 =
  | TcpConnect { connected_endpoint_digest }
  | TlsHandshake { tls_target_challenge_result_digest }
  | NonceEcho { nonce_echo_challenge_result_digest }

TlsTargetChallengeResultV1 = {
  target_profile_digest,
  tls_policy_descriptor_digest,
  started_at,
  completed_at,
  outcome,
}

TlsTargetOutcome =
  | Passed {
      reference_identity_result,
      trust_result,
      algorithm_result,
      negotiated_version,
      negotiated_cipher_suite_codepoint_u16,
      negotiated_group_codepoint_u16,
      server_authentication_scheme,
      leaf_spki_sha256,
    }
  | Failed { bounded_phase, error_code }
  | TimedOut { bounded_phase }
```

`challenge_result` variant must match `challenge_kind`. A passed TCP result uses
`Digest(EndpointIdentityV1)` for the connected endpoint. TLS uses
`Digest(TlsTargetChallengeResultV1)` and contains only the bounded policy
decisions shown above, never the raw certificate or transcript. NonceEcho uses
`Digest(NonceEchoChallengeResultV1)`. A generic evidence hash or cross-variant
digest is invalid. A passed TLS target result uses
`Tls12ServerKeyExchange` exactly with TLS 1.2 or
`Tls13ServerCertificateVerify` exactly with TLS 1.3 and enforces the same
closed signature/key policy; a cross-version or absent server-authentication
signature is invalid.

`protocol_phase_outcomes` contains at most sixteen entries in the exact state-
machine order for the selected tag; duplicate, missing mandatory, reordered, or
unexpected phases are invalid. `NotApplicable` is accepted only for a phase the
closed variant explicitly omits. `phase` is the closed set of state labels shown
in sections 11.1 through 11.5 for that tag; arbitrary phase text is rejected.

For `ExternalHttps`, `proxy_tls_evidence` is the `ExternalHttps` variant and
names the exact policy, material descriptor, delivery, runtime-load, adapter-
artifact, and proxy-handshake roots for this plan/runtime/node/connection. The
three observation roots use the `Preactivation` context with this proof
specification and helper nonce. System-root modes also require a fresh
`EffectiveProxyTrustSnapshotV1`; private-anchor-only modes require that optional
absent. Cross-bindings, freshness, and the handshake's passed outcome are
mandatory before CONNECT bytes. For every other egress tag the field is exactly
`NotApplicable`. A generic `safe_evidence_digest` in a protocol phase cannot
substitute for any of these roots; that field may name only a phase-specific
registered or accepted-upstream observation schema named by the proof
specification.

`socket_observation_accumulator_digest` names the helper/watchdog-signed
checkpoint taken after the proof connection reaches its terminal bounded state.
It includes the proof child in the creation chain when that child is new, and
its factory/OS census roots use a fresh census challenge and barrier epoch for
this proof. The accumulator does not reference `EgressPathProofResultV1`, so the
runtime may bind the completed checkpoint without a digest cycle. A child that
is absent from the chain or current open-set provenance, an extra scoped OS
socket, or a reused census context invalidates the proof.

At plan sealing the helper replaces the observation nonce slot with a fresh
helper-assigned nonce and includes it in the final plan digest. The runtime
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
`PlatformDiscoveryBackend` and `TrustMaterialBroker` use
`PlanComponentAuthenticatedChannel`; `PrivilegedHelper` uses
`HelperAuthority`; and `WatchdogOrReconciler` uses `WatchdogFenceDomain`. Any
other role/binding pairing is unauthenticated. The selected authority binds the
32-byte public-key identity to the exact signer instance, role, plan,
generation, and its displayed gate/channel/helper/fence fields. The key identity
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
Response-loss replay returns the byte-identical signed root; it never creates a
new nonce or signature. The journal retains the registered root and
authenticator, not a handshake transcript.

The helper enforces this root-to-role table before accepting any signed root;
there is no caller-selected or “compatible” role:

| Registered signed root | Exact required signer role(s) |
| --- | --- |
| `ConnectedLocalPeerObservationV1` | one `PlatformDiscoveryBackend` |
| `ProxyTrustMaterialDeliveryRecordV1` | one `TrustMaterialBroker` |
| `ProxyTrustMaterialLoadObservationV1` | one `NetworkRuntime` |
| `ProxyTrustMaterialArtifactObservationV1` | one `RuntimeAdapter` |
| `ProxyTlsHandshakeObservationV1` | one `NetworkRuntime` |
| `EgressPathProofResultV1` | one `NetworkRuntime` |
| `SocketFactoryPolicyObservationV1` | one `SocketFactoryExecutor` |
| `SocketPolicyChildObservationV1` | one `SocketFactoryExecutor` |
| `FactorySocketCensusObservationV1` | one `SocketFactoryExecutor` |
| `OsSocketCensusV1` | one `PlatformDiscoveryBackend` |
| `SocketObservationAccumulatorV1` | `PrivilegedHelper`, then `WatchdogOrReconciler` |
| `PostactivationCanaryResultV1` | `NetworkRuntime`, then `CaptureCore` |
| `SustainedHealthObservationV1` | `NetworkRuntime`, `PlatformDiscoveryBackend`, `PrivilegedHelper`, `WatchdogOrReconciler`, sorted by role tag in the encoded list |

The single-signer rows contain exactly one authenticator. The multi-signer rows
contain exactly the displayed unique role set and every signer signs the same
root projection. Registered roots without an authenticator field, including
`SocketIdentitySetV1`, challenge-result roots, authorization scopes, and content
descriptors, are digest-bound children of a signed/plan-bound root and MUST NOT
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

`Refused` preserves one of all seven `CapabilityDisposition` variants and the
mapped bounded error. A missing authorized target is
`Refused { InteractionRequired, ProbeTargetRequired }`; it is never collapsed
to generic `Unsupported`.

`Passed` proves the selected preactivation path and preventive socket behavior
of the exact inert runtime only. It does not prove that future full-tunnel
exclusions were installed, that the postactivation path is healthy, or that the
session committed.

## 11. Protocol state machines

### 11.1 Direct

```text
ResolveIfRequired
  -> BindOrProtectSocket
  -> ObserveRoute
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
  -> BindOrProtectProxySocket
  -> ObserveRoute
  -> TcpConnectProxy
  -> SendConnectAuthority
  -> ReadBoundedResponseHead
  -> TunnelOrTypedFailure
  -> ChallengeThroughTunnel
  -> Passed
```

The request target is normalized authority form `host:port`; an IPv6 literal is
bracketed. `Host` carries the same authority. CONNECT has no request content.
No user-controlled request path, arbitrary field, redirect, origin
`Authorization`, Cookie, or body is allowed.

Only a complete 2xx response establishes a tunnel. Per RFC 9110, response
`Content-Length` or `Transfer-Encoding` on successful CONNECT is ignored and
bytes after the response head are tunnel bytes. FlowProbe does not read or log a
CONNECT response body. Non-2xx responses close the connection and return only
the status class/code, bounded authentication scheme, and reason code.

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
  -> BindOrProtectProxySocket
  -> ObserveRoute
  -> TcpConnectProxy
  -> AuthenticateProxyTls
  -> VerifyIdentityTrustPolicyAndAlpn
  -> HTTP/1.1 CONNECT state machine
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
transport step unless the target challenge itself is the separately declared
`TlsHandshake` profile.

### 11.4 SOCKS5 TCP

```text
ResolveProxyEndpoint
  -> BindOrProtectProxySocket
  -> ObserveRoute
  -> TcpConnectProxy
  -> OfferExactMethods
  -> CompleteSelectedAuthentication
  -> SendCONNECTWithExactResolutionForm
  -> ValidateReply
  -> ChallengeThroughTunnel
  -> Passed
```

The client offers only `NO AUTHENTICATION REQUIRED` when `None` is selected, or
only the configured supported set containing username/password when that method
is selected. A method not offered, `NO ACCEPTABLE METHODS`, malformed version,
or unsupported subnegotiation is a typed failure. Username/password lengths must
fit RFC 1929's one-octet bounds and their values remain secret.

`ProxyName` sends SOCKS5 `ATYP=DOMAINNAME` with the normalized configured
destination name. `LocalAddress` sends only the sealed `ATYP=IPv4` or
`ATYP=IPv6` candidate. The implementation MUST NOT resolve a `ProxyName` locally
or send a hostname after `LocalAddress` was selected.

A non-success reply is preserved as a bounded reply code and closes the
connection. BIND is not supported.

### 11.5 SOCKS5 UDP ASSOCIATE

When `RequireAssociate` is selected, proof and active health additionally run:

```text
EstablishedAuthenticatedSOCKS5Control
  -> SendUDP_ASSOCIATEWithUnspecifiedSameFamily
  -> ValidateRelayReply
  -> ClassifyAndExcludeRelay
  -> SendBoundedFRAG0Canary
  -> ValidateRelaySourceAndCanary
  -> AssociationReady
```

The TCP control connection remains open for the lifetime of the UDP
association. The relay address and port returned in `BND.ADDR`/`BND.PORT` must
encode an IPv4 address, scoped IPv6 address, or bounded normalized DNS name and
a nonzero port. Unspecified, wildcard, multicast, metadata-service, invalid
scope, or ambiguous locality is rejected. A DNS relay name is resolved only by
the sealed `relay_resolver_dependency` through the baseline path; if that field
is absent, the domain reply is `Socks5RelayInvalid`. The result set obeys the
sealed relay family policy/candidate bounds and is classified independently of
both proxy endpoint and destination.

The UDP ASSOCIATE request uses the closed `UnspecifiedSameFamily` profile. On an
IPv4 control socket it sends `VER=0x05, CMD=0x03, RSV=0x00, ATYP=0x01,
DST.ADDR=0.0.0.0, DST.PORT=0`; on an IPv6 control socket it sends `ATYP=0x04`,
sixteen zero address octets, and port zero. It never sends a domain name or a
destination endpoint in this request. Port zero is permitted only in this
protocol-specific request and does not relax the general `Endpoint` port rule.
A different request form is `UnsupportedProtocolFeature`, not an ambient client
default.

The same exact runtime establishes the association during preactivation proof
and retains its TCP control connection and chosen relay through commit. The
authenticated proof observation records the concrete relay/result-set/locality,
route, socket mechanism, and association identity. In `FullTunnel`, SOCKS5 UDP
is supportable only when the pre-sealed exclusion uses an endpoint-independent
preventive per-socket/actor mechanism that already covers every permitted relay
candidate. A relay-selected endpoint can never synthesize a new privileged
bypass route, rule, or allowlist entry after plan sealing. If the platform needs
such an endpoint-specific mutation, `RequireAssociate` is unsupported. A host-
local relay must also match the sealed stable local-proxy and enforcement
identity; private/on-link/special-use relays require an exact authorized proxy
profile rule and remain `Remote`, not implicitly trusted.

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
| `egress.postactivation-canary.v1` | Observation predicate | Exact selected path and one-traversal proof after steering, before commit |
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
  factory_implementation_and_build_digest,
  socket_creation_enforcement_digest,
  allowed_path_purposes,
  address_families,
  transports,
  baseline_anchor_digest,
  mechanism_set,
  socket_identity_recipe,
  expected_option_image,
  expected_route_observation_schema,
  pre_byte_release_authority = SocketFactoryExecutorUnderSealedInvariant,
  local_fail_closed_release_predicate,
  local_release_guard,
  census_snapshot_barrier_id,
  census_snapshot_deadline,
  factory_epoch,
  initial_socket_sequence = 0,
  maximum_open_sockets,
  maximum_new_sockets_per_lease_epoch,
  observation_accumulator = Sha256ChainV1,
  capability_report_digest,
  helper_observation_nonce_slot,
  apply_deadline,
  observation_freshness,
  compensation,
}

SocketFactoryCompensationV1 =
  | StopExactOwnedRuntime
  | RevokeExactCooperativeFactoryLease

LocalSocketReleaseGuardV1 = {
  observation_queue_id,
  consumer_set = HelperAndWatchdog,
  maximum_pending_observations,
  enqueue_deadline,
  release_order = SignedChildEnqueuedBeforeProtocolBytes,
  channel_failure = CloseSocketAndFailFactoryEpoch,
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
      setsockopt_optlen,
    }
  | LinuxBindToIfIndex {
      network_namespace_identity,
      interface_stable_identity,
      live_ifindex_i32,
      capability_report_digest,
      fallback_policy = Prohibited,
    }
  | LinuxSocketMark {
      network_namespace_identity,
      socket_mark_value_u32,
      policy_rule_mark_u32,
      policy_rule_mask_u32,
      preexisting_policy_route_observation_digest,
    }
  | DarwinBoundInterface {
      interface_stable_identity,
      live_ifindex_locator,
      ipv4_option = IP_BOUND_IF,
      ipv6_option = IPV6_BOUND_IF,
    }
  | CooperativeProtect {
      provider_identity_digest,
      protocol_version,
      exact_profile_digest,
      attestation_policy_digest,
    }

SocketFactoryPolicyObservationV1 = {
  prepared_plan_digest,
  helper_assigned_observation_nonce,
  generation,
  factory_policy_id,
  actor_id,
  runtime_instance_id?,
  factory_implementation_and_build_digest,
  socket_creation_enforcement_digest,
  factory_epoch,
  next_socket_sequence = 0,
  alternate_socket_path_absence_digest,
  exact_policy_readback_digest,
  observation_queue_id,
  local_release_guard_readback_digest,
  census_snapshot_barrier_id,
  census_snapshot_barrier_readback_digest,
  observed_at,
  expires_at,
  authenticator,
}

SocketPolicyChildObservationV1 = {
  prepared_plan_digest,
  generation,
  lease_epoch,
  factory_policy_id,
  factory_epoch,
  socket_sequence,
  observation_queue_id,
  socket_identity,
  actor_id,
  path_purpose,
  address_family,
  transport,
  endpoint_scope,
  exact_mechanism_values,
  route_and_interface_observation,
  connected_local_peer_observation_digest?,
  observed_at,
  expires_at,
  authenticator,
}

SocketCensusAddressFamilyV1 =
  | Ipv4
  | Ipv6
  | OtherExternalNetworkFamily

SocketCensusTransportV1 =
  | Tcp
  | Udp
  | RawOrOtherExternalTransport

SocketIdentityTupleV1 = {
  platform_socket_identity,
  owner_process_or_cooperative_scope_identity,
  network_namespace_or_compartment_identity,
  census_address_family,
  census_transport,
}

SocketCensusScopeV1 = {
  actor_id,
  component_instance_id,
  runtime_instance_id?,
  process_or_cooperative_enforcement_identity_digest,
  network_namespace_or_compartment_identity,
  address_family_scope = AllExternalNetworkFamilies,
  transport_scope = AllExternalNetworkTransports,
  states = AllSocketStateV1,
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
  platform_socket_identity,
  socket_policy_child_observation_digest,
  socket_sequence,
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
  discovery_backend_and_build_digest,
  independently_observed_socket_identity_set_digest,
  query_started_at,
  query_completed_at,
  outcome,
  authenticator,
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
  factory_socket_census_observation_digest,
  independent_os_socket_census_digest,
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
`setsockopt_optlen` is exactly its byte length. It also requires socket-option
and resulting route/interface read-back. The pinned sing v0.8.13
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
registered route policy whose immutable digest is in the plan—v1 cannot create
that policy. Darwin options apply only to sockets whose exact packaged runtime
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

Acceptance requires both outcomes `Complete`, identical snapshot context,
factory lifecycle counters equal, freshness before the common deadline, and
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

The one external apply action starts/attaches the exact factory under the sealed
runtime instance and returns one `SocketFactoryPolicyObservationV1`; response
loss replays that byte-identical observation and the permit becomes consumed.
The factory implementation must make every alternate raw-socket/dialer path
unreachable through a preventive sandbox, syscall/socket broker, or equivalent
enforcement whose identity and read-back are sealed. Source review by itself is
not `socket_creation_enforcement_digest` evidence.

Each later socket is ordinary bounded data-plane behavior under that installed
invariant, not a new session mutation or external permit. The sole pre-byte
release authority is the `SocketFactoryExecutor` under its already installed
`local_fail_closed_release_predicate` and `LocalSocketReleaseGuardV1`.
`observation_queue_id` is a fresh pre-sealed 32-byte non-authorizing local IPC
identity. `maximum_pending_observations` is in `1..=4096`; `enqueue_deadline` is
positive, no more than one second, and within the socket phase budget. The queue
is declared in the factory actor's bounded `permitted_local_ipc_digest`, carries
only complete signed child roots, and is neither a helper request channel nor a
second gate/lease.

Under the factory's serialized creation lock it performs this exact order: prove
the queue is alive and has capacity; create a no-send socket; apply the mechanism
before `connect`/`send`; obtain OS option and route read-back; perform the
connected-local-peer check when required; verify the existing `ResumeBarrier`
liveness/read-back; tentatively allocate the next sequence; construct and sign
the complete child root; enqueue that root before the bounded deadline;
atomically commit the sequence; then and only then release the socket for the
first protocol byte. Any failed step closes the socket with zero protocol/
credential bytes, marks that factory epoch terminal-failed, and prevents further
socket creation. Queue loss/full/timeout cannot be converted into an unsigned
or later observation. Existing ARCH-001 channel/barrier liveness then denies
proof/commit or closes the active data path. This is not a helper/watchdog child-
release RPC, acknowledgement, permit redemption, or mutation authority: ARCH-
001 registers no such per-socket request, and this contract does not invent or
reuse one.

The factory emits one signed `SocketPolicyChildObservationV1` per sequence. Let
`A_seed = SHA-256("FlowProbe.Egress.SocketAccumulator.v1\0" ||
Digest(ActorSocketFactoryPolicyV1) || factory_epoch)`. For child sequence `i`,
starting at zero, `A_(i+1) = SHA-256("FlowProbe.Egress.SocketAccumulator.v1\0"
|| A_i || uint64_be(i) || Digest(SocketPolicyChildObservationV1))`. Thus the
first child produces `A_1`; the seed is never also a child result. Every proof,
pre-commit checkpoint, and renewal supplies one
`SocketObservationAccumulatorV1` per applicable factory. `NonEmpty` starts at
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
snapshot context and factory/OS census equality above are mandatory for both
delta variants. The fixed
authenticators have roles `PrivilegedHelper` and `WatchdogOrReconciler`, sign the
same accumulator projection, and are both mandatory.

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

1. during `Preflighting`, baseline, capability, endpoint, listener, authorization
   receipts, secret-free runtime template, proof specification, expected proof
   predicate, actor graph, socket policies, and complete exclusion graph;
2. helper sealing of that exact graph and transition to `Prepared`; no FlowProbe
   internal service has started and no FlowProbe OS resource has been applied
   before this boundary;
3. private config materialization plus inert exact runtime/Capture actors under
   the ARCH-001 external-executor gates;
4. actor socket-policy observations and the actual preactivation proof from the
   authenticated runtime, durably recorded before any shared OS mutation;
5. the one ARCH-001 `ResumeBarrier` closed with the
   `egress.loop-gate.v1` predicate contribution, then any future exactly
   registered egress privileged resources;
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
  proxy TLS handshake, and path proof, but never a future result;
- registered `egress.*` resource graph and predicates;
- mandatory postactivation and sustained-health predicates; and
- all downstream extension digests and ARCH-001 bindings.

After `Prepared`, the ARCH-001 journal records each authenticated trust-delivery,
runtime-load, adapter-artifact, proxy-handshake, and path-proof result applicable
to the selected tag, with its expiry, as the terminal result of its pre-sealed
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
`NormalStopFinalizationProtocolUnavailable`. A row selecting the pinned HTTP,
TLS, authenticated-credential, or SOCKS UDP paths also carries the exact
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
  present in `ProxyTlsEvidenceReferenceV1::ExternalHttps`, fresh, correctly
  signed, cross-bound, and passed; for other tags the reference is
  `NotApplicable`;
- the postactivation canary proves the selected tag over the active path;
- any required SOCKS5 UDP association and relay identity are live;
- no DNS/UDP path lacks its accepted downstream policy; and
- ADR-0004 baseline-relative ordinary-connectivity and mode-specific health are
  satisfied.

One false, missing, ambiguous, degraded, detective-only, expired, or version-
mismatched predicate denies commit. The session rolls back and cannot be
reported `Active`.

### 14.2 Postactivation canary

The postactivation canary reuses one of the exact
`EgressProofSpecificationV1.probe_targets` and its verified authorization
receipt. It inherits the same address-class/port policy, sealed resolver,
zero-redirect rule, per-phase/overall deadlines, retry/concurrency limits,
1024-byte challenge ceiling, 256-KiB total protocol ceiling, and no-body privacy
rule; activation cannot substitute a new target or relax a bound.

```text
PostactivationCanaryResultV1 = {
  prepared_plan_digest,
  helper_assigned_observation_nonce,
  generation,
  runtime_instance_id,
  capture_core_instance_id,
  proof_specification_digest,
  target_profile_digest,
  target_authorization_receipt_digest,
  egress_selection_safe_digest,
  selected_endpoint_digest?,
  proxy_tls_evidence,
  source_actor_id,
  exclusion_entry_digest,
  baseline_route_observation_digest,
  canary_socket_child_observation_digest,
  socket_observation_accumulator_digest,
  capture_generation_marker_digest,
  target_nonce_commitment?,
  nonce_echo_challenge_result_digest?,
  capture_traversal_count,
  bytes_sent,
  bytes_received,
  started_at,
  completed_at,
  outcome,
  runtime_authenticator,
  capture_core_authenticator,
}

CanaryOutcome =
  | Passed
  | Failed { error_code }
  | TimedOut { bounded_phase }
  | Cancelled
```

The helper nonce is fresh for this pre-sealed observation node. The exact
runtime and Capture Core identities each authenticate their part through the
protected ARCH-001 channels; the Supervisor may relay but cannot create a
traversal or target result. Evidence binds:

- the exact selection and endpoint;
- capture-generation marker;
- source actor and exclusion entry;
- selected baseline interface/route;
- the signed child observation for the canary connection and the following
  helper/watchdog accumulator with equal factory/OS census roots;
- the exact `NonceEchoChallengeResultV1` digest when the challenge is
  `NonceEcho`; and
- Capture Core traversal count.

`runtime_authenticator` and `capture_core_authenticator` are
`ExternalObservationAuthenticatorV1` values in that fixed order with roles
`NetworkRuntime` and `CaptureCore`. Each signs the same canary signing projection
under its own gate-bound key/channel. One signer cannot contribute for the
other, and a partially signed result is unauthenticated.

The canary child is signed and enqueued before its first protocol byte. The
referenced accumulator is the next checkpoint after that canary reaches a
terminal bounded outcome, includes that child when newly created, and uses a
fresh census challenge/barrier context distinct from preactivation. Missing
child/provenance, an unchanged replayed context, or a factory/OS set mismatch is
canary failure even when the target response itself passed.

For `ExternalHttps`, `proxy_tls_evidence` is `ExternalHttps` and its runtime
load, adapter absence, and TLS handshake roots all use the `Postactivation`
context with this canary nonce and `capture_generation_marker_digest`. A system-
root mode carries a freshly observed snapshot; private-anchor-only mode carries
none. Other egress tags use `NotApplicable`. Missing, stale, preactivation-
replayed, or mixed-context TLS evidence is unauthenticated canary failure.

The required traversal count is exactly one for traffic intended to be
captured, and zero for egress/control traffic declared bypassed. More than one
capture traversal, a changed source identity, or inability to count is
`LoopDetectedOrUnproven`. Canary payload and raw packets are not journaled.
Nonce fields are absent for `TcpConnect` and `TlsHandshake`; manufacturing a
placeholder nonce is invalid.
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
  lease_epoch,
  fence_token_digest,
  runtime_and_actor_identity_digests,
  selected_connector_observation_digest,
  baseline_anchor_digest,
  endpoint_resolution_digest,
  exclusion_readback_set_digest,
  exclusion_completeness_digest,
  local_proxy_identity_digest?,
  proxy_control_or_socks_association_digest?,
  proxy_tls_evidence,
  socket_factory_policy_observation_digests,
  socket_observation_accumulator_digests,
  authorized_probe_result_digest,
  helper_watchdog_path_digest,
  ordinary_connectivity_digest,
  observed_at,
  expires_at,
  verifier_identity_set_digest,
  authenticators,
  outcome,
}

HealthOutcome = Healthy | Failed { error_code }
```

It contains fresh safe digests for:

- selected protocol/endpoint and current connector proof;
- baseline anchor, route/interface, resolver, address family, namespace/
  compartment, boot/suspend, backend, and package epochs;
- every exclusion resource read-back and completeness proof;
- each factory's `SocketObservationAccumulatorV1`, including its gap-free socket
  sequence range, exact open-socket set, and independent OS socket census;
- local proxy listener/process/executable/policy identity when present;
- HTTP/HTTPS proxy control health or SOCKS5 control/UDP relay health as selected;
- for `ExternalHttps`, the exact delivery plus fresh context-bound runtime-state,
  adapter-absence, and handshake roots; and
- probe and helper/watchdog paths; and
- baseline-relative ordinary connectivity.

For `ExternalHttps`, `proxy_tls_evidence` uses the `ExternalHttps` variant. Its
runtime load is `CurrentStateReaffirmation`, adapter artifact state is
`CurrentAbsenceReaffirmation`, and handshake is a fresh bounded connection; all
three use the `Renewal` context with this lease epoch, challenge nonce, and fence
token. System-root modes include a fresh `EffectiveProxyTrustSnapshotV1` whose
store revision, boot epoch, FlowProbe-CA subtraction, and filtered anchor set
match the descriptor's original snapshot apart from observation time/deadline;
any drift invalidates the generation. Private-anchor-only modes require the
snapshot optional absent. Other egress tags require `NotApplicable`. Replaying
activation/canary evidence or merely referencing the old load/cleanup roots is
not renewal evidence.

`authenticators` contains exactly four unique
`ExternalObservationAuthenticatorV1` values in ascending signer-role order:
`NetworkRuntime`, `PlatformDiscoveryBackend`, `PrivilegedHelper`, and
`WatchdogOrReconciler`. Every contributor signs the same sustained-health
signing projection. The runtime owns connector/probe state, the platform backend
owns route/listener/census observations, and helper/watchdog own journal/fence
and independent renewal enforcement; no role may replace another. The renewal
challenge is a fresh public 32-byte helper nonce. Missing signer, duplicate
role, key/channel substitution, sequence gap, accumulator mismatch, or OS socket
without a child observation makes the outcome `Failed` and denies renewal.

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

A plan may define a bounded consecutive-failure count and elapsed threshold for
a transient target challenge only when all preventive exclusions, actor
identities, route bindings, and ordinary-connectivity predicates remain proven.
The thresholds are sealed, monotonic, and capped by the current lease deadline.
Crossing either threshold irreversibly denies the old renewal.

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
  | ProxyAuthenticationFailed
  | ProxyResponseMalformed
  | ProxyResponseTooLarge
  | ProxyTlsFailed
  | ProxyTlsIdentityMismatch
  | ProxyTlsTrustFailed
  | ProxyTlsRevocationUnavailable
  | Socks5MethodUnsupported
  | Socks5ReplyFailed
  | Socks5UdpAssociateFailed
  | Socks5RelayResolutionFailed
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
- stable canonical digest vectors with secret handles replaced only by safe
  descriptor digests, byte-exact deterministic-CBOR fixtures for all 47 root
  schema tags, graph/set ordering, optional-field tags, nested union tags,
  helper/signature-domain separation, wrong schema/version replay, non-minimal
  integers, wrong field order/count, and trailing bytes;
- a mechanically checked digest DAG proving subjects precede scopes/receipts,
  opaque trust node/slot IDs precede material/TLS/selection/config/plan digests,
  and consumption/delivery/observation records never feed back into a plan;
- every signed root crossed with every legal signer role and authority-binding
  variant, accepting only the exact table row, header, key, channel/authority,
  order, and contributor set; byte changes to the separately encoded header or
  the authenticator-omitted root projection must fail, and no duplicate implicit
  role encoding is accepted; and
- exact requested/prepared/active equality plus new-generation behavior for
  every explicit mode change or proxy-only acceptance.

Family tests separately vary the outer proxy endpoint and locally resolved
destination policies. They prove `ProxyName` always reports `ProxyOpaque`,
rejects a client-enforced destination-family request, never seals nonexistent
future per-flow address results, and cannot conflict with a second SOCKS UDP
resolution/family field because none exists.

### 17.2 Capability matrix

- every `StaticSupport`, `Readiness`, `Evidence`, `Disposition`, and enforcement-
  strength mapping independently for `ProcessAttribution`,
  `LocalListenerOwnership`, and `LoopExclusion`;
- version, scope, family, transport, actor, endpoint-locality, and evidence
  mismatches; and
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
  certificate, filtered-root failure, every v1 algorithm/key-size/signature
  boundary, every closed cipher/group and TLS1.2 ServerKeyExchange/TLS1.3
  CertificateVerify signature scheme, including cross-version rejection, chain count/DER
  ceiling, leaf-SPKI AND semantics, rejection of the pinned insecure pin field,
  pre-sealed pin rotation, request-only handle absence, broker one-use delivery
  record, independent runtime-load and adapter-artifact roots, tuple/signer
  substitution, broker/delivery/materialize/load/remove/handshake time ordering,
  initial versus current-state/absence context binding, cleanup, ambient-root
  denial, exact ClientHello and proxy-handshake roots, unavailable negotiated-
  group/server-signature data in pinned Go public state, and store-epoch drift,
  `NoOnlineCheck` exact reporting, unconditional v1
  fresh-OCSP refusal, ALPN absent/http1.1/other, no IP-literal SNI, no resumption/
  early data, TLS alert,
  successful TLS followed by CONNECT/auth failure, and no HTTP fallback;
- SOCKS5 exact method negotiation, RFC 1929 length/status, `ProxyName` versus
  `LocalAddress`, IPv4/IPv6/domain forms, every reply code, malformed frames,
  BIND rejection, and credential-risk policy; and
- UDP ASSOCIATE exact IPv4/IPv6 unspecified-same-family request, control
  lifetime, IPv4/IPv6/domain relay replies, sealed relay
  resolver versus ambient-DNS denial, local/remote relay classification,
  endpoint-independent full-tunnel exclusion, rejection of relay-selected
  privileged mutation, relay-source validation, IPv4/IPv6/domain destinations,
  `RSV=0`, `FRAG=0`, drop-before-health-error for malformed/nonzero FRAG,
  loss/replacement, canary bounds, proof of no direct or UDP-over-TCP fallback,
  and proof that the pinned built-in UDP path remains nonconforming.

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
  replay, consumption-record post-plan ordering, cross-plan/ticket/session/generation/boot/
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
  commitment/result domains and cross-target replay, TLS target profiles, and
  missing-target interaction result; and
- credential/header/body/certificate/raw-target-nonce/path canaries proving no
  secret or payload appears in plan, journal, result, logs, errors, crash output,
  or any IPC except the exact one-use authenticated NonceEcho delivery frame;
  the tests reject wrong binding, replay, response-loss redelivery, and second
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
  proxy/authentication byte with connected-kernel-peer proof or refusal;
- discovery-to-seal, seal-to-apply, apply-to-steering, steering-to-commit, and
  active-renewal race injection;
- remove each mandatory actor/path/family/transport/endpoint/DNS/probe/renderer/helper/
  watchdog/policy-broker/Supervisor/secret-broker/trust-material-broker/compiler/runtime-adapter/
  platform-backend entry one at a time and require pre-commit refusal; reject an
  unknown component/purpose and an unproved `NoExternalNetworkPath` declaration;
- install/replay/compensate the single socket-factory external permit; create
  bounded sockets/reconnects with gap-free sequence/accumulator/open-set/OS-
  census evidence and explicit first/consecutive empty and close-only
  checkpoints; prove any child count
  still produces only the one initial ARCH-001 permit trace; inject duplicate/
  missing sequences, alternate raw dialer, census extra/missing/duplicate/stale
  tuple or provenance, expected-digest/list echo attempts, nonce/barrier replay,
  create/close/barrier races, lifecycle-counter change/wrap, partial query,
  overflow, stale route, queue unavailable/full/timeout, failure after enqueue
  but before release, wrong queue/epoch, Windows zero/24-bit/byte-order/
  ignored-IPv6 errors, Linux zero mark/mask, conflicting masked rules,
  `SO_BINDTOIFINDEX` failure/process-global fallback, factory restart, and helper
  observation-channel loss, with zero protocol bytes on every pre-release
  failure; separately require proof and canary roots to bind the next signed
  accumulator/census checkpoint; and
- route/mark/interface fake evidence proving every socket uses the sealed
  baseline anchor and that detective-only evidence is refused; and
- external proxy stop/recovery proving FlowProbe never kills or modifies the
  external process and removes only its own exclusion resources.

### 17.6 Transaction and health

- failure and response loss before/after every `egress.*` durable intent, OS
  apply, read-back, result fsync, steering apply, gate open, postactivation
  canary, commit, renewal, gate close, compensation, and recovery boundary;
- stale generation/lease/fence/revision, owner loss, helper/watchdog/runtime
  crash, boot/suspend, journal replay/corruption, external drift, and
  idempotent result replay under the ARCH-001 protocol;
- interface/default-route/gateway/DNS/family/VPN change, DHCP/RA-like epoch
  change, proxy/control/UDP-relay death or replacement, exclusion drift,
  sustained target failure below/at/above threshold, and ordinary-connectivity
  loss; and
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
- [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929.html) for username/password
  subnegotiation and field limits;
- [RFC 5246 section 7.4.3](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.3)
  for TLS 1.2 server `ServerKeyExchange`,
  [section 7.4.8](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.8)
  for the distinct client `CertificateVerify`, and
  [RFC 8446 section 4.4.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3)
  for TLS 1.3 server `CertificateVerify`,
  [RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3)
  for SNI,
  [RFC 5280 section 6](https://www.rfc-editor.org/rfc/rfc5280.html#section-6)
  for certificate path validation, and
  [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html) for TLS deployment
  constraints;
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
