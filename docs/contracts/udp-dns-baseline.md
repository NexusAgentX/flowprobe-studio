# Contract: UDP and DNS baseline v0.2

Status: Normative for v0.2

Task: ARCH-004

This contract defines bounded generic UDP metadata, policy-safe datagram
forwarding, and truthful DNS visibility. The key words **MUST**, **MUST NOT**,
**SHOULD**, and **MAY** are normative.

## 1. Scope and preserved boundaries

This contract owns:

- generic datagram-flow identity, lifecycle, counts, timing, provenance, and
  metadata limits;
- explicit UDP pass, block, unsupported, and separately authorized direct-
  fallback behavior;
- DNS query/response metadata, correlation, privacy, retention, and redaction;
- independent DNS routing, interception, decoding, and leak-prevention claims;
- IPv4/IPv6 and UDP/TCP/DoT/DoH/DoQ capability reporting;
- `transport.udp.*` and `dns.*` ARCH-001 extension resources;
- reuse of ARCH-002 selection, exclusion, socket admission, and health; and
- deterministic and packaged real-host verification.

This contract does not define arbitrary UDP application decoders, IP-fragment
reassembly, UDP payload retention, DNS answer-content capture, a recursive
resolver, a new helper protocol, or platform support by assertion.

The accepted architecture remains frozen:

- sing-box is an independent managed Network Runtime;
- Capture Core is protocol-oriented and does not import sing-box internals;
- protected runtime configuration belongs to the Config Compiler;
- the privileged helper performs only registered typed OS mutations;
- analyzers use versioned host capabilities; and
- raw/normalized traffic is source material while semantic output is derived.

## 2. Claim vocabulary

Observation sources and the two bounded inference rules used below are closed:

```text
Arch004ObservationSourceV1 =
  | DatagramBoundary
  | OriginalDestinationBoundary
  | ProcessIdentityBoundary
  | DnsPlaintextDecoder
  | DnsEncryptedOuterClassifier
  | RuntimeProtectedHook
  | NativeSystemResolverHook

ExactDnsEncryptedOuterClassifier =
  Arch004ObservationSourceV1::DnsEncryptedOuterClassifier

Arch004InferenceRuleV1 =
  | EndpointRoleFromAuthenticatedFlow
  | ProcessFromExclusiveSocketOwner

Arch004ConfidenceV1 = Exact | High | Medium | Low
```

No consumer may coerce `Inferred`, `Opaque`, or `Unavailable` to `Observed`.
Unknown variants fail decoding rather than selecting a default.

The following claim dimensions are independent:

```text
ClaimDispositionV1 =
  | Proven
  | Unsupported
  | PolicyProhibited
  | PermissionRequired
  | InteractionRequired
  | TemporarilyUnavailable
  | Degraded

ClaimNotProvenDispositionV1 =
  | Unsupported
  | PolicyProhibited
  | PermissionRequired
  | InteractionRequired
  | TemporarilyUnavailable
  | Degraded

DnsAncillaryClaimDispositionV1 =
  | Proven
  | Unsupported
  | TemporarilyUnavailable
  | Degraded

DnsClaimKindV1 = Routing | Interception | Decoding | LeakPrevention

DnsClaimScopeV1 = {
  network_scope: NetworkScope,
  families: SortedUniqueNonEmptyVector<AddressFamilyV1>,
  transports: SortedUniqueNonEmptyVector<DnsTransportV1>,
  resolver_scope: DnsCapabilityResolverScopeV1,
}

DnsPlainUdpQueryEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.transport: Exact(PlainUdp),
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::UdpQuery,
  }

DnsPlainUdpResponseEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.transport: Exact(PlainUdp),
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::UdpResponse,
  }

DnsStreamQueryEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.transport: PlainTcp | Tls,
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::StreamQuery,
  }

DnsStreamResponseEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.transport: PlainTcp | Tls,
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::StreamResponse,
  }

DnsHttpsQueryEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.transport: Exact(Https),
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::HttpQuery,
  }

DnsHttpsResponseEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.transport: Exact(Https),
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::HttpResponse,
  }

DnsDoqQueryEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.transport: Exact(Quic),
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::QuicQuery,
  }

DnsDoqResponseEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.transport: Exact(Quic),
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::QuicResponse,
  }

DnsRuntimeResolverQueryEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::RuntimeResolverQuery,
  }

DnsRuntimeResolverResponseEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::RuntimeResolverResponse,
  }

DnsNativeSystemResolverQueryEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::NativeSystemResolverQuery,
  }

DnsNativeSystemResolverResponseEvidenceRefV1 =
  DnsPlaintextBoundaryEvidenceRefV1 {
    body.message_key: DnsPlaintextBoundaryMessageKeyV1::NativeSystemResolverResponse,
  }

DnsPort53InterceptionProbeV1 =
  | PlainUdp {
      query_ref: DnsPlainUdpQueryEvidenceRefV1 {
        body.producer_source: RuntimeProtectedHook,
      },
    }
  | PlainTcp {
      query_ref: DnsStreamQueryEvidenceRefV1 {
        body.transport: Exact(PlainTcp),
        body.producer_source: RuntimeProtectedHook,
      },
    }

DnsConfiguredInterceptionProbeV1 =
  | RuntimeHook {
      transport: DnsTransportV1,
      query_ref: DnsRuntimeResolverQueryEvidenceRefV1 {
        body.producer_source: RuntimeProtectedHook,
        body.transport: Exact(transport),
      },
    }
  | NativeSystemHook {
      transport: DnsTransportV1,
      query_ref: DnsNativeSystemResolverQueryEvidenceRefV1 {
        body.producer_source: NativeSystemResolverHook,
        body.transport: Exact(transport),
      },
    }

DnsPlainUdpDecodingPairV1 =
  | BoundaryPair {
      producer_source: DnsPlaintextDecoder | RuntimeProtectedHook,
      query_ref: DnsPlainUdpQueryEvidenceRefV1 {
        body.producer_source: Exact(producer_source),
      },
      response_ref: DnsPlainUdpResponseEvidenceRefV1 {
        body.producer_source: Exact(producer_source),
      },
    }
  | RuntimeHookPair {
      query_ref: DnsRuntimeResolverQueryEvidenceRefV1 {
        body.transport: Exact(PlainUdp),
        body.producer_source: RuntimeProtectedHook,
      },
      response_ref: DnsRuntimeResolverResponseEvidenceRefV1 {
        body.transport: Exact(PlainUdp),
        body.producer_source: RuntimeProtectedHook,
      },
    }
  | NativeSystemHookPair {
      query_ref: DnsNativeSystemResolverQueryEvidenceRefV1 {
        body.transport: Exact(PlainUdp),
        body.producer_source: NativeSystemResolverHook,
      },
      response_ref: DnsNativeSystemResolverResponseEvidenceRefV1 {
        body.transport: Exact(PlainUdp),
        body.producer_source: NativeSystemResolverHook,
      },
    }

DnsPlainTcpDecodingPairV1 =
  | StreamPair {
      producer_source: DnsPlaintextDecoder | RuntimeProtectedHook,
      query_ref: DnsStreamQueryEvidenceRefV1 {
        body.transport: Exact(PlainTcp),
        body.producer_source: Exact(producer_source),
      },
      response_ref: DnsStreamResponseEvidenceRefV1 {
        body.transport: Exact(PlainTcp),
        body.producer_source: Exact(producer_source),
      },
    }
  | RuntimeHookPair {
      query_ref: DnsRuntimeResolverQueryEvidenceRefV1 {
        body.transport: Exact(PlainTcp),
        body.producer_source: RuntimeProtectedHook,
      },
      response_ref: DnsRuntimeResolverResponseEvidenceRefV1 {
        body.transport: Exact(PlainTcp),
        body.producer_source: RuntimeProtectedHook,
      },
    }
  | NativeSystemHookPair {
      query_ref: DnsNativeSystemResolverQueryEvidenceRefV1 {
        body.transport: Exact(PlainTcp),
        body.producer_source: NativeSystemResolverHook,
      },
      response_ref: DnsNativeSystemResolverResponseEvidenceRefV1 {
        body.transport: Exact(PlainTcp),
        body.producer_source: NativeSystemResolverHook,
      },
    }

DnsTlsDecodingPairV1 =
  | StreamHookPair {
      producer_source: DnsPlaintextDecoder | RuntimeProtectedHook,
      query_ref: DnsStreamQueryEvidenceRefV1 {
        body.transport: Exact(Tls),
        body.producer_source: Exact(producer_source),
      },
      response_ref: DnsStreamResponseEvidenceRefV1 {
        body.transport: Exact(Tls),
        body.producer_source: Exact(producer_source),
      },
    }
  | RuntimeHookPair {
      query_ref: DnsRuntimeResolverQueryEvidenceRefV1 {
        body.transport: Exact(Tls),
        body.producer_source: RuntimeProtectedHook,
      },
      response_ref: DnsRuntimeResolverResponseEvidenceRefV1 {
        body.transport: Exact(Tls),
        body.producer_source: RuntimeProtectedHook,
      },
    }
  | NativeSystemHookPair {
      query_ref: DnsNativeSystemResolverQueryEvidenceRefV1 {
        body.transport: Exact(Tls),
        body.producer_source: NativeSystemResolverHook,
      },
      response_ref: DnsNativeSystemResolverResponseEvidenceRefV1 {
        body.transport: Exact(Tls),
        body.producer_source: NativeSystemResolverHook,
      },
    }

DnsHttpsDecodingPairV1 = {
  producer_source: DnsPlaintextDecoder | RuntimeProtectedHook,
  query_ref: DnsHttpsQueryEvidenceRefV1 {
    body.producer_source: Exact(producer_source),
  },
  response_ref: DnsHttpsResponseEvidenceRefV1 {
    body.producer_source: Exact(producer_source),
  },
}

DnsHttpsCarrierDecodingWitnessV1 = {
  carrier: DnsDecodedHttpCarrierV1,
  pair: DnsHttpsDecodingPairV1,
}

DnsDoqDecodingPairV1 = {
  producer_source: DnsPlaintextDecoder | RuntimeProtectedHook,
  query_ref: DnsDoqQueryEvidenceRefV1 {
    body.producer_source: Exact(producer_source),
  },
  response_ref: DnsDoqResponseEvidenceRefV1 {
    body.producer_source: Exact(producer_source),
  },
}

DnsRoutingProvenWitnessV1 =
  | SelectedPath {
      egress_path_proof_ref: EgressPathProofEvidenceRefV1,
    }
  | NativeSystemPath {
      route_readback_ref: ResourceReadbackEvidenceRefV1,
    }

DnsInterceptionProvenWitnessV1 =
  | Port53Intercept {
      intercept_readback_ref: ResourceReadbackEvidenceRefV1,
      plaintext_probe: DnsPort53InterceptionProbeV1,
    }
  | NativeOrRuntimeHook {
      route_readback_ref: ResourceReadbackEvidenceRefV1,
      plaintext_hook: DnsConfiguredInterceptionProbeV1,
    }

DnsDecodingProvenWitnessV1 =
  | PlainUdp {
      pair: DnsPlainUdpDecodingPairV1,
    }
  | PlainTcp {
      pair: DnsPlainTcpDecodingPairV1,
    }
  | Tls {
      pair: DnsTlsDecodingPairV1,
    }
  | Https {
      carrier_witnesses:
        SortedUniqueNonEmptyVector<
          DnsHttpsCarrierDecodingWitnessV1, 1..=3>,
    }
  | Quic {
      pair: DnsDoqDecodingPairV1,
      query_fin_ref: DnsQuicQueryFinEvidenceRefV1,
      response_fin_ref: DnsQuicResponseFinEvidenceRefV1,
    }

DnsLeakPreventionProvenWitnessV1 =
  | SelectedPath {
      egress_path_proof_ref: EgressPathProofEvidenceRefV1,
      no_pending_tun_recursion_ref:
        NoPendingTunRecursionEvidenceRefV1,
    }
  | NativeSystemPath {
      route_readback_ref: ResourceReadbackEvidenceRefV1,
      no_pending_tun_recursion_ref:
        NoPendingTunRecursionEvidenceRefV1,
    }

DnsStandardClaimProvenWitnessV1 =
  | Routing(DnsRoutingProvenWitnessV1)
  | Interception(DnsInterceptionProvenWitnessV1)
  | Decoding(DnsDecodingProvenWitnessV1)
  | LeakPrevention(DnsLeakPreventionProvenWitnessV1)

DnsClaimV1<ProvenWitnessType> =
  | Proven {
      kind: DnsClaimKindV1,
      scope: DnsClaimScopeV1,
      primary_witness: ProvenWitnessType,
      reason: ExactNoBlockingReason,
    }
  | NotProven {
      kind: DnsClaimKindV1,
      scope: DnsClaimScopeV1,
      outcome: DnsStandardClaimNotProvenOutcomeV1,
    }

DnsRoutingClaimV1 =
  DnsClaimV1<DnsRoutingProvenWitnessV1> { kind: Routing }
DnsInterceptionClaimV1 =
  DnsClaimV1<DnsInterceptionProvenWitnessV1> { kind: Interception }
DnsDecodingClaimV1 =
  DnsClaimV1<DnsDecodingProvenWitnessV1> { kind: Decoding }
DnsLeakPreventionClaimV1 =
  DnsClaimV1<DnsLeakPreventionProvenWitnessV1> {
    kind: LeakPrevention,
  }
```

A status surface MUST show all four dimensions. A configured route is not
interception, interception is not decoding, decoding is not leak prevention,
and leak prevention is not visibility.

## 3. Common identifiers and time

All IDs below are opaque fixed-length random values from the trusted owner and
MUST NOT be derived solely from an address tuple, process ID, DNS wire ID, or
wall time:

```text
DatagramFlowId
DatagramObservationEpoch
DatagramOccurrenceId
DnsTransactionId
DnsQueryOccurrenceId
DnsResponseOccurrenceId
DnsDecoderInstanceId
DnsResolverInstanceId
UdpAdmissionId
HostConnectionIdV1 = ExactType(NormalizedFlow.connection_id)
DnsConnectionEpochV1 = OpaqueConnectionEpoch
DnsFramedMessageSequenceV1 = MonotonicSequence
HostHttpTransactionIdV1 = Bytes32
QuicStreamIdV1 = Integer<0..=4611686018427387903>

DnsPlaintextHookIdentityV1 = {
  component_instance_id: ComponentInstanceId,
  producer_build: BoundedBuildIdentity,
  producer_spec_entry_digest: Digest(DnsPlaintextProducerStreamSpecV1),
  registration_digest:
    Digest(DnsPlaintextBoundaryProducerRegistrationV1),
  observation_stream_id: Bytes32,
  outer_transport: PlainTcp | Tls | Https | Quic,
}

AuthenticatedDnsQueryTokenDigestV1 = Bytes32
AuthenticatedDnsResponseTokenDigestV1 = Bytes32

DnsPathBoundResolverSelectionV1 = {
  resolver_path_binding_set_digest:
    Digest(Arch004ResolverPathBindingSetV1),
  resolver_path_member_binding_digest:
    Digest(Arch004ResolverPathBindingMemberV1),
  selected_member_ordinal: U8,
  selected_endpoint_identity_digest: Digest(EndpointIdentityV1),
}

DnsOpaqueResolverSelectionV1 = {
  capability_matrix_spec_digest: Digest(DnsCapabilityMatrixV1),
  capability_cell_spec_digest: Digest(DnsCapabilityCellSpecV1),
  capability_cell_key: DnsCapabilityCellKeyV1,
  resolver_scope: DnsCapabilityResolverScopeV1,
  selected_mechanism:
    DnsVisibilityMechanismV1::{
      NativeConfigured | Port53Hijacked | MetadataObserved
    },
  reason: Exact(ResolverIdentityNotObservable),
}

DnsPlanTimeResolverSelectionV1 =
  | PathBound(DnsPathBoundResolverSelectionV1)
  | NativeNoBinding {
      capability_matrix_spec_digest: Digest(DnsCapabilityMatrixV1),
      capability_cell_spec_digest: Digest(DnsCapabilityCellSpecV1),
      capability_cell_key: DnsCapabilityCellKeyV1,
      resolver_scope: DnsCapabilityResolverScopeV1::
        ExactNativeResolverScope,
    }
  | ObservedNoBinding {
      capability_matrix_spec_digest: Digest(DnsCapabilityMatrixV1),
      capability_cell_spec_digest: Digest(DnsCapabilityCellSpecV1),
      capability_cell_key: DnsCapabilityCellKeyV1,
      resolver_scope: Exact(DnsCapabilityResolverScopeV1::NoResolverScope),
      observed_endpoint_identity_digest: Digest(EndpointIdentityV1),
    }
  | Opaque(DnsOpaqueResolverSelectionV1)

DnsNativeSystemResolverSelectionV1 =
  DnsPlanTimeResolverSelectionV1::{PathBound | NativeNoBinding}

DnsHostAssociationPlacementV1 =
  | HostOnly
  | SelectedEgressPath {
      socket_child_observation_digest:
        Digest(SocketPolicyChildObservationV1),
      egress_path_proof_ref: EgressPathProofEvidenceRefV1,
    }

DnsEncryptedOuterPathSelectionV1 =
  | SelectedPath {
      capability_matrix_spec_digest: Digest(DnsCapabilityMatrixV1),
      capability_cell_spec_digest: Digest(DnsCapabilityCellSpecV1),
      capability_cell_key: DnsCapabilityCellKeyV1 {
        transport: Tls | Https | Quic,
      },
      resolver_scope:
        DnsCapabilityResolverScopeV1::PlannedResolverDependency,
      resolver_selection: DnsPathBoundResolverSelectionV1,
      socket_child_observation_digest:
        Digest(SocketPolicyChildObservationV1),
      egress_path_proof_root_digest: Digest(EgressPathProofResultV1),
      outer_association_key: DnsEncryptedOuterHostAssociationKeyV1,
    }

DnsEncryptedOuterIdentityProjectionV1 = {
  association_key: DnsEncryptedOuterHostAssociationKeyV1,
  connection_epoch: DnsConnectionEpochV1,
  family: AddressFamilyV1,
  transport: Tls | Https | Quic,
  selected_path_digest:
    Digest(DnsEncryptedOuterPathSelectionV1::SelectedPath),
}

DnsEncryptedOuterSubjectV1 = {
  association_key: DnsEncryptedOuterHostAssociationKeyV1,
  connection_epoch: DnsConnectionEpochV1,
  family: AddressFamilyV1,
  transport: Tls | Https | Quic,
  resolver_selection: DnsPathBoundResolverSelectionV1,
  selected_path_digest:
    Digest(DnsEncryptedOuterPathSelectionV1::SelectedPath),
  outer_identity: Digest(DnsEncryptedOuterIdentityProjectionV1),
}

DnsPlaintextOuterAttributionV1 =
  | NotSelectedEncryptedPath
  | ExactOuter(DnsEncryptedOuterSubjectV1)
  | UnresolvedSelectedEncryptedPath {
      family: AddressFamilyV1,
      transport: Tls | Https | Quic,
      resolver_selection: DnsPathBoundResolverSelectionV1,
    }

DnsPlaintextBoundaryClassificationV1 =
  | Decoded
  | DecodeOpaque
  | Malformed

DnsBoundaryMessageKeyV1 =
  | UdpQuery {
      occurrence_id: DnsQueryOccurrenceId,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | UdpResponse {
      occurrence_id: DnsResponseOccurrenceId,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | StreamQuery {
      connection_epoch: DnsConnectionEpochV1,
      sequence: DnsFramedMessageSequenceV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | StreamResponse {
      connection_epoch: DnsConnectionEpochV1,
      sequence: DnsFramedMessageSequenceV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | HttpQuery {
      http_transaction_id: HostHttpTransactionIdV1,
      message_ordinal: MonotonicSequence,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | HttpResponse {
      http_transaction_id: HostHttpTransactionIdV1,
      message_ordinal: MonotonicSequence,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | QuicQuery {
      stream_id: QuicStreamIdV1,
      message_ordinal: ExactU8(0),
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | QuicResponse {
      stream_id: QuicStreamIdV1,
      message_ordinal: ExactU8(1),
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | RuntimeResolverQuery {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      family: AddressFamilyV1,
      selection: DnsPathBoundResolverSelectionV1,
      token_digest: AuthenticatedDnsQueryTokenDigestV1,
    }
  | RuntimeResolverResponse {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      family: AddressFamilyV1,
      selection: DnsPathBoundResolverSelectionV1,
      correlated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
      token_digest: AuthenticatedDnsResponseTokenDigestV1,
    }
  | NativeSystemResolverQuery {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_resource_identity_digest: Digest(DnsRouteResourceIdentityV1),
      family: AddressFamilyV1,
      selection: DnsNativeSystemResolverSelectionV1,
      token_digest: AuthenticatedDnsQueryTokenDigestV1,
    }
  | NativeSystemResolverResponse {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_resource_identity_digest: Digest(DnsRouteResourceIdentityV1),
      family: AddressFamilyV1,
      selection: DnsNativeSystemResolverSelectionV1,
      correlated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
      token_digest: AuthenticatedDnsResponseTokenDigestV1,
    }
  | EncryptedOuter {
      outer_observation_id: Digest(DnsEncryptedOuterIdentityProjectionV1),
      path_selection: DnsEncryptedOuterPathSelectionV1,
    }

DnsPlaintextBoundaryMessageKeyV1 =
  DnsBoundaryMessageKeyV1::{
    UdpQuery | UdpResponse | StreamQuery | StreamResponse |
    HttpQuery | HttpResponse | QuicQuery | QuicResponse |
    RuntimeResolverQuery | RuntimeResolverResponse |
    NativeSystemResolverQuery | NativeSystemResolverResponse
  }
```

Evidence references and post-seal observation context are closed:

```text
Arch004JournalEvidenceRoleV1 =
  | AppliedResult
  | CompensatedResult
  | ObservedAbsentResult
  | ActiveHealthResult
  | RecoveryResolution

Arch004InlineObservationKindV1 =
  | DatagramBoundaryReadback
  | OriginalDestinationReadback
  | ProcessIdentityReadback
  | RawFragmentBoundaryReadback
  | DnsPlaintextBoundaryReadback
  | DnsEncryptedOuterReadback
  | DnsQuicFinReadback
  | Arch004ResourceReadback
  | Arch004OwnershipAbsenceReadback
  | DnsHostAssociationReadback
  | DynamicCapacityTerminalReadback
  | MetadataRetentionReadback
  | ResourceJournalRetentionReadback
  | RawFragmentRetentionReadback

Arch002EvidenceRootTagV1 =
  | SafeEgressSelection               // tag 1
  | CapabilityReport                  // tag 2
  | ResolverDependencyDescriptor      // tag 3
  | ResolvedEndpointSet               // tag 4
  | EgressActor                       // tag 7
  | EgressActorGraph                  // tag 8
  | EgressExclusionSet                // tag 9
  | EgressExclusionEntry              // tag 10
  | BaselineEgressAnchor              // tag 11
  | EgressProofSpecification          // tag 12
  | EgressPathProofResult             // tag 13
  | ActorSocketFactoryPolicy          // tag 14
  | SocketFactoryPolicyObservation    // tag 15
  | ExternalObservationAuthenticator  // tag 26
  | NonceEchoChallengeResult          // tag 27
  | PostactivationCanaryResult        // tag 28
  | SustainedHealthObservation        // tag 29
  | SocketPolicyChildObservation      // tag 31
  | EndpointIdentity                  // tag 33
  | SocketObservationAccumulator      // tag 34
  | EgressExclusionCompletenessProof  // tag 35
  | PhaseBoundProbeChallengeResult    // tag 37
  | SocketIdentitySet                 // tag 43
  | OsSocketCensus                    // tag 44
  | FactorySocketCensusObservation    // tag 46
  | Socks5UdpAssociationObservation   // tag 50
  | EgressExclusionReadbackObservation // tag 51
  | EgressOrdinaryConnectivityObservation // tag 52
  | PlatformCapabilityEvidence        // tag 53
  | ActorNetworkIsolationPolicy       // tag 54
  | ActorNetworkIsolationReadback     // tag 55
  | FactoryAdmissionReleaseBatchCompletion // tag 56

Arch004CapacityCommitAuthoritySpecV1 = {
  signer_role: Exact(ObservationSignerRole::CaptureCore),
  component_instance_id: ComponentInstanceId,
  component_build: BoundedBuildIdentity,
  public_key_identity_digest: Bytes32,
  post_cas_gate_registration_digest: Bytes32,
  authority_binding_kind:
    Exact(ObservationAuthorityBindingV1::ExternalExecutorGate),
}

Arch004CapacityReplayRegistryAuthoritySpecV1 = {
  signer_role: Exact(ObservationSignerRole::CaptureCore),
  component_instance_id: ComponentInstanceId,
  component_build: BoundedBuildIdentity,
  public_key_identity_digest: Bytes32,
  registry_gate_registration_digest: Bytes32,
  transport_registry_identity_digest: Bytes32,
  channel_key_store_identity_digest: Bytes32,
  authority_binding_kind:
    Exact(ObservationAuthorityBindingV1::ExternalExecutorGate),
}

Arch004CapacityLedgerRecoveryBudgetV1 = {
  head_store_slot_count: ExactU16(2),
  post_cas_sidecar_slot_count: ExactU16(2),
  publication_batch_marker_slot_count: ExactU16(2),
  operation_watermark_slot_count: ExactU16(2),
  max_head_store_slot_accounted_bytes: PositiveU64,
  max_post_cas_sidecar_store_slot_accounted_bytes: PositiveU64,
  max_publication_batch_marker_store_slot_accounted_bytes: PositiveU64,
  max_operation_watermark_store_slot_accounted_bytes: PositiveU64,
  joint_cow_wal_store_slot_count: ExactU16(2),
  max_joint_cow_wal_store_slot_accounted_bytes: PositiveU64,
  max_total_accounted_bytes: PositiveU64,
}

Arch004CapacityReplayEpochRecoveryBudgetV1 = {
  pending_admission_slot_count: ExactU16(2),
  owner_epoch_state_slot_count: ExactU16(2),
  event_store_slot_count: ExactU16(2),
  transport_closure_head_slot_count: ExactU16(2),
  channel_key_store_closure_head_slot_count: ExactU16(2),
  max_pending_admission_store_slot_accounted_bytes: PositiveU64,
  max_owner_epoch_state_store_slot_accounted_bytes: PositiveU64,
  max_event_store_store_slot_accounted_bytes: PositiveU64,
  max_transport_closure_head_store_slot_accounted_bytes: PositiveU64,
  max_channel_key_store_closure_head_store_slot_accounted_bytes: PositiveU64,
  max_total_accounted_bytes: PositiveU64,
}

Arch004CapacityLedgerManifestV1 = {
  installation_id: InstallationId,
  ledger_id: Arch004CapacityLedgerId,
  operation_replay_sequence_domain_id: Bytes32,
  exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
  accounting_function_build: BoundedBuildIdentity,
  accounting_function_version: BoundedVersion,
  commit_authority_spec: Arch004CapacityCommitAuthoritySpecV1,
  commit_authority_spec_digest:
    Digest(Arch004CapacityCommitAuthoritySpecV1),
  replay_registry_authority_spec:
    Arch004CapacityReplayRegistryAuthoritySpecV1,
  replay_registry_authority_spec_digest:
    Digest(Arch004CapacityReplayRegistryAuthoritySpecV1),
  ledger_recovery_budget: Arch004CapacityLedgerRecoveryBudgetV1,
  ledger_recovery_budget_digest:
    Digest(Arch004CapacityLedgerRecoveryBudgetV1),
  replay_epoch_recovery_budget:
    Arch004CapacityReplayEpochRecoveryBudgetV1,
  replay_epoch_recovery_budget_digest:
    Digest(Arch004CapacityReplayEpochRecoveryBudgetV1),
}

Arch004PlanLeaseFenceBindingV1 = {
  installation_id: InstallationId,
  session_id: SessionId,
  generation: Generation,
  prepared_plan_id: PreparedPlanId,
  plan_digest: PlanDigest,
  activation_lease_id: ActivationLeaseId,
  lease_epoch: LeaseEpoch,
  fence: FenceToken,
  capacity_ledger_manifest_digest:
    Digest(Arch004CapacityLedgerManifestV1),
}

Arch004LeaseObservationContextV1 = {
  binding: Arch004PlanLeaseFenceBindingV1,
  observed_at: MonotonicInstant,
  expires_at: SuspendAwareDeadline,
}

DnsPlaintextProducerKeyV1 =
  | CaptureCoreDecoder {
      decoder_instance_id: DnsDecoderInstanceId,
      component_instance_id: ComponentInstanceId,
      producer_build: BoundedBuildIdentity,
    }
  | RuntimeProtectedHook {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      component_instance_id: ComponentInstanceId,
      producer_build: BoundedBuildIdentity,
    }
  | NativeSystemResolverHook {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_resource_identity_digest: Digest(DnsRouteResourceIdentityV1),
      component_instance_id: ComponentInstanceId,
      producer_build: BoundedBuildIdentity,
    }

DnsPlaintextProducerStreamSpecV1 = {
  producer: DnsPlaintextProducerKeyV1,
  partition_ordinal: U16,
  allowed_families:
    SortedUniqueNonEmptyVector<AddressFamilyV1, 1..=2>,
  allowed_transports:
    SortedUniqueNonEmptyVector<DnsTransportV1, 1..=5>,
}

DnsPlaintextProducerRegistrySpecV1 = {
  schema_version: ExactU16(1),
  entries:
    SortedUniqueNonEmptyVector<
      DnsPlaintextProducerStreamSpecV1,
      1..=64>,
}

DnsPlaintextBoundaryProducerRegistrationV1 = {
  spec_entry: DnsPlaintextProducerStreamSpecV1,
  spec_entry_digest: Digest(DnsPlaintextProducerStreamSpecV1),
  registry_ordinal: U16,
  lease_binding: Arch004PlanLeaseFenceBindingV1,
  observation_stream_id: Bytes32,
  activated_at: MonotonicInstant,
}

DnsPlaintextBoundaryRegistrySnapshotV1 = {
  registry_spec: DnsPlaintextProducerRegistrySpecV1,
  registry_spec_digest: Digest(DnsPlaintextProducerRegistrySpecV1),
  lease_binding: Arch004PlanLeaseFenceBindingV1,
  registry_owner_observer_instance_id: DnsDecoderInstanceId,
  registry_owner_component_instance_id: ComponentInstanceId,
  registry_owner_build: BoundedBuildIdentity,
  registrations:
    SortedUniqueNonEmptyVector<
      DnsPlaintextBoundaryProducerRegistrationV1,
      1..=64>,
  registration_count: PositiveBoundedU16,
  registration_leaf_set_root: Digest,
  frozen_at: MonotonicInstant,
  expires_at: SuspendAwareDeadline,
}

DnsPlaintextBoundaryCensusLeafV1 = {
  registration_digest: Digest(DnsPlaintextBoundaryProducerRegistrationV1),
  observation_stream_id: Bytes32,
  barrier_id: Bytes32,
  barrier_next_ordinal: U64,
  sealed_stream_prefix_count: U64,
  sealed_stream_prefix_root: Digest,
  matching_boundary_count: ExactU64(0),
  matching_boundary_set_root: Digest,
  unresolved_candidate_count: ExactU64(0),
  unresolved_candidate_set_root: Digest,
  barrier_acknowledged_at: MonotonicInstant,
}

DnsPlaintextBoundaryCensusV1 = {
  registry_snapshot: DnsPlaintextBoundaryRegistrySnapshotV1,
  registry_snapshot_digest: Digest(DnsPlaintextBoundaryRegistrySnapshotV1),
  barrier_id: Bytes32,
  target: DnsEncryptedOuterSubjectV1,
  window_start: MonotonicInstant,
  window_end: MonotonicInstant,
  leaves:
    SortedUniqueNonEmptyVector<
      DnsPlaintextBoundaryCensusLeafV1,
      1..=64>,
  leaf_count: PositiveBoundedU16,
  leaf_set_root: Digest,
  total_matching_boundary_count: ExactU64(0),
  total_unresolved_candidate_count: ExactU64(0),
  finalized_at: MonotonicInstant,
}

The registry and census hashes are canonical and independently replayable:

```text
Digest(DnsPlaintextProducerStreamSpecV1) = SHA-256(
  "FlowProbe.Dns.PlaintextProducerStreamSpec.v1\0" ||
  deterministic_cbor(stream_spec))

Digest(DnsPlaintextProducerRegistrySpecV1) = SHA-256(
  "FlowProbe.Dns.PlaintextProducerRegistrySpec.v1\0" ||
  deterministic_cbor(registry_spec))

Digest(DnsEncryptedOuterPathSelectionV1::SelectedPath) = SHA-256(
  "FlowProbe.Dns.EncryptedOuterPathSelection.v1\0" ||
  deterministic_cbor(path_selection))

Digest(DnsEncryptedOuterIdentityProjectionV1) = SHA-256(
  "FlowProbe.Dns.EncryptedOuterIdentityProjection.v1\0" ||
  deterministic_cbor(identity_projection))

observation_stream_id = SHA-256(
  "FlowProbe.Dns.PlaintextObservationStream.v1\0" ||
  spec_entry_digest || deterministic_cbor(lease_binding))

Digest(DnsPlaintextBoundaryProducerRegistrationV1) = SHA-256(
  "FlowProbe.Dns.PlaintextBoundaryProducerRegistration.v1\0" ||
  deterministic_cbor(registration))

registration_leaf_set_root = SHA-256(
  "FlowProbe.Dns.PlaintextBoundaryRegistryLeafSet.v1\0" ||
  deterministic_cbor(registrations))

Digest(DnsPlaintextBoundaryRegistrySnapshotV1) = SHA-256(
  "FlowProbe.Dns.PlaintextBoundaryRegistrySnapshot.v1\0" ||
  deterministic_cbor(snapshot))

leaf_set_root = SHA-256(
  "FlowProbe.Dns.PlaintextBoundaryCensusLeafSet.v1\0" ||
  deterministic_cbor(leaves))

empty_matching_boundary_set_root = SHA-256(
  "FlowProbe.Dns.PlaintextBoundaryMatchingSet.v1\0" ||
  deterministic_cbor([]))

empty_unresolved_candidate_set_root = SHA-256(
  "FlowProbe.Dns.PlaintextBoundaryUnresolvedSet.v1\0" ||
  deterministic_cbor([]))
```

The plan-sealed `DnsObserver` body contains the complete registry spec. Its
entries contain only stable producer, partition, family and transport identity;
they contain no prepared-plan ID, plan digest, lease/fence, stream ID,
observation, result or evidence reference. The snapshot repeats that exact spec
and digest. Its registration vector is the exact deterministic one-to-one,
same-order projection of every spec entry under the current lease/fence, with
`registry_ordinal` equal to the zero-based vector index and
`observation_stream_id` equal to the formula above. It contains each producer
partition exactly once. `registration_count = registrations.len`, its leaf-set
root is the formula above, every family/transport is allowed by the matching
spec entry, and the registry owner is the prepared plan's sole authoritative
Capture Core DNS-observer registry. A missing, extra, duplicate, reordered,
dormant, expired, cross-plan or unregistered producer invalidates the snapshot.
The complete spec and registration vector remain unchanged from `frozen_at`
through census finalization; otherwise the encrypted status is `Unavailable`
and a new stable window is required. Adding, removing or repartitioning a
producer requires a new sealed plan and lease/fence.

The plan compiler's producer-universe function is closed: it emits every
enabled Capture Core decoder partition for the exact decoder build and limits,
every runtime hook reachable from the plan's runtime resolver resources and
binding sets, and every native hook reachable from its native route resources
and capability cells, then sorts the complete stream-spec bytes. No other code
path may emit `DnsPlaintextBoundaryReadback`. The plan is invalid if a reachable
producer/partition is absent or if an entry has no reachable producer. Release
conformance compares this deterministic projection with the build's actual
registration table, including disabled and newly added hook negatives; the
Capture Core TCB is not allowed to self-register an extra stream after seal.

Resolving `snapshot.lease_binding.plan_digest` under its prepared-plan ID yields
exactly one `dns.observer.v1` resource plan for the registry owner. The
resource identity's decoder/component/build equals the snapshot owner, and the
following digest is byte-identical in all four places: the `DnsObserver` plan
body's complete `plaintext_producer_registry_spec`, its intended-postcondition
digest, the `Running` image digest, and `snapshot.registry_spec_digest`. The
snapshot's embedded `registry_spec` hashes to that value. Its lease binding is
the exact current resource lease/fence binding; no other observer plan, prior
lease, or unsealed registry can authorize a stream.

Every `PassiveObserver` context names that exact snapshot digest and repeats its
registry-owner instance/component/build plus the snapshot's complete lease
binding and expiry. A producer registration never
contains a context or census digest, so the dependency is acyclic. Every
registered stream is dedicated to signed `DnsPlaintextBoundaryReadback` leaves;
its ordinals start at zero and advance by exactly one with no gaps. Its prefix
root is:

```text
root[0] = SHA-256(
  "FlowProbe.Dns.PlaintextBoundaryStreamSeed.v1\0" ||
  registration_digest || observation_stream_id)

root[n + 1] = SHA-256(
  "FlowProbe.Dns.PlaintextBoundaryStreamAppend.v1\0" ||
  root[n] || uint64_be(n) ||
  canonical_body_digest(DnsPlaintextBoundaryReadback[n]))
```

Every plaintext leaf's `producer_spec_entry_digest`, stream ID and ordinal equal
the unique registration, derived stream ID and zero-based position in that
stream. The resolved `PassiveObserver` context names the same snapshot and lease
binding. Producer-key variant maps exactly to `DnsPlaintextDecoder`,
`RuntimeProtectedHook`, or `NativeSystemResolverHook`; family and transport are
members of that spec entry's allowed sets. A copied stream ID, producer/source
substitution, disallowed family/transport, duplicate ordinal, or cross-context
leaf is invalid before census matching.

For every registration,
`spec_entry_digest = Digest(spec_entry)`, `lease_binding =
snapshot.lease_binding`, and `observation_stream_id` is the derived value above.
A `CaptureCoreDecoder` entry repeats the resolved context/observer-plan decoder
instance, component and build. A `RuntimeProtectedHook` entry repeats the
runtime/resolver IDs carried by the runtime message key and request/response
association. A `NativeSystemResolverHook` entry repeats the backend, stable
scope and route-resource digest carried by the native message key and
association. In all hook-bearing Dot/DoH/DoQ keys, the
`DnsPlaintextHookIdentityV1` component/build, spec-entry digest, typed
registration digest, stream ID and outer transport equal that same resolved
registration and boundary. No field may be borrowed from another producer or
partition.

For each census leaf, `registration_digest` resolves exactly one snapshot
registration and its stream ID is byte-identical. Census leaves occur in
registry order and the set of leaf registration digests equals the set of
registration digests; `leaf_count = leaves.len = registration_count`;
`leaf_set_root` is the formula above. `barrier_next_ordinal =
sealed_stream_prefix_count`, and `sealed_stream_prefix_root` is the replayed
root at that exclusive ordinal. Every ordinal below it resolves exactly one
valid signed leaf. Leaf observation times are nondecreasing, the producer drains
all observations through `window_end`, acknowledges the common barrier no
earlier than that time, and after acknowledgement cannot append a backdated leaf
at or before the window end. Missing ordinals, a root/count mismatch, a different
barrier ID, or late backfill invalidates the census.

`PlaintextOuterAssociationProjection` is defined only by
`DotConnection -> DotOuterConnection`, `DohHttpTransaction ->
DohOuterConnection`, and `DoqStream -> DoqOuterConnection`, preserving the exact
host connection and outer epoch while dropping only plaintext hook/HTTP/stream
children. For a Dot/DoH/DoQ boundary, `ExactOuter.subject.association_key` is
that projection, its connection epoch is `OuterEpochProjection` of the key,
family/transport equal the boundary, selected-path digest equals the exact
observed selected path, and outer identity is the canonical projection digest.
`PlainUdp` and `PlainTcp` require `NotSelectedEncryptedPath`. An encrypted-
transport boundary whose exact resolver selection is `NativeNoBinding`,
`ObservedNoBinding`, or `Opaque` also requires that variant after validation
proves it belongs to no planned selected path; it is retained in the complete
stream prefix but is outside this census predicate. A runtime/native hook may
use no `ExactOuter` in V1 because its request/response association has no host-
connection identity. For runtime/native `Tls`/`Https`/`Quic` with `PathBound`,
attribution is mandatorily `UnresolvedSelectedEncryptedPath` with family/
transport equal to the leaf and resolver selection byte-identical to its
authenticated message key and request/response association. A host-bound
Dot/DoH/DoQ boundary with `PathBound` uses `ExactOuter` as defined above. If an
exact selection cannot be resolved or its selected/non-selected disposition is
ambiguous, the encrypted status is `Unavailable`; a producer cannot substitute
a sibling selection to escape either census count.

A prefix leaf matches the census if and only if its signature/context,
registration, stream and ordinal are valid, its time lies in the inclusive
census window, `leaf.family/transport = census.target.family/transport`, its
resolved context lease binding equals
`census.registry_snapshot.lease_binding`, and its
`outer_attribution = ExactOuter(census.target)`. An unresolved candidate is a
leaf in the same window and lease whose attribution is
`UnresolvedSelectedEncryptedPath` with the target family, transport and
resolver selection. All three plaintext classifications count. Each census
leaf's two counts are the checked counts over its complete prefix and both are
exactly zero; their set roots equal the corresponding empty roots above. The
checked sums equal `total_matching_boundary_count = 0` and
`total_unresolved_candidate_count = 0`. A signature or zero literal alone never
establishes completeness; validation replays the accepted plan registry and
every sealed stream prefix.

Arch004ObservationContextV1 =
  | NetworkPath {
      lease: Arch004LeaseObservationContextV1,
      network_scope: NetworkScope,
      egress_selection_safe_digest: Digest(SafeEgressSelectionV1),
      actor_id: EgressActorV1.actor_id,
      socket_factory_policy_digest: Digest(ActorSocketFactoryPolicyV1),
      exclusion_set_digest: Digest(EgressExclusionSetV1),
    }
  | DatagramObserver {
      lease: Arch004LeaseObservationContextV1,
      observer_actor_id: EgressActorV1.actor_id,
      component_instance_id: ComponentInstanceId,
      boundary_build: BoundedBuildIdentity,
      network_scope: NetworkScope,
      exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
      ambient_network: Prohibited,
    }
  | PassiveObserver {
      lease: Arch004LeaseObservationContextV1,
      observer_instance_id: DnsDecoderInstanceId,
      component_instance_id: ComponentInstanceId,
      decoder_build: BoundedBuildIdentity,
      plaintext_boundary_registry_snapshot_digest:
        Digest(DnsPlaintextBoundaryRegistrySnapshotV1),
      exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
      ambient_network: Prohibited,
    }
  | ResourceExecution {
      lease: Arch004LeaseObservationContextV1,
      platform_subject: Arch004PlatformSubjectV1,
      resource_identity: Arch004ResourceIdentityV1,
      executor: Arch004ResourceExecutorV1,
      owner_marker: OwnerMarker,
      resource_plan_digest: Digest(Arch004ResourcePlanV1),
    }
  | CapabilityEvaluation {
      lease: Arch004LeaseObservationContextV1,
      platform_subject: Arch004PlatformSubjectV1,
      network_scope: NetworkScope,
      egress_selection_safe_digest: Digest(SafeEgressSelectionV1),
      exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
      evaluator_component_instance_id: ComponentInstanceId,
      evaluator_build: BoundedBuildIdentity,
      evaluator_gate:
        ObservationAuthorityBindingV1::ExternalExecutorGate,
    }
  | CapacityAccounting {
      lease: Arch004LeaseObservationContextV1,
      ledger_manifest_digest:
        Digest(Arch004CapacityLedgerManifestV1),
      ledger_id: Arch004CapacityLedgerId,
      subject: Arch004CapacitySubjectV1,
      owner: Arch004CapacityOwnerV1,
      capacity_requirement_digest:
        Digest(Arch004CapacityRequirementV1),
      exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
      accounting_function_build: BoundedBuildIdentity,
      accounting_function_version: BoundedVersion,
    }
  | CapacityCommit {
      lease: Arch004LeaseObservationContextV1,
      ledger_manifest_digest:
        Digest(Arch004CapacityLedgerManifestV1),
      ledger_id: Arch004CapacityLedgerId,
      commit_authority_spec_digest:
        Digest(Arch004CapacityCommitAuthoritySpecV1),
      commit_authority_gate:
        ObservationAuthorityBindingV1::ExternalExecutorGate,
    }
  | CapacityReplayRegistry {
      lease: Arch004LeaseObservationContextV1,
      ledger_manifest_digest:
        Digest(Arch004CapacityLedgerManifestV1),
      ledger_id: Arch004CapacityLedgerId,
      replay_registry_authority_spec_digest:
        Digest(Arch004CapacityReplayRegistryAuthoritySpecV1),
      owner_epoch_key_digest:
        Digest(Arch004CapacityOperationOwnerEpochKeyV1),
      mode: LiveRegistry | HistoricalCloseOnly |
        HistoricalCompleteAcknowledgedClosure |
        HistoricalFinalizeInstalledRecord,
      replay_registry_authority_gate:
        ObservationAuthorityBindingV1::ExternalExecutorGate,
    }

Arch004ExternalObservationAuthenticatorV1 = {
  header: AuthenticatorHeaderV1,
  signature: Bytes64,
}

Arch004InlineObservationBodyV1 =
  | DatagramBoundaryReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      occurrence_id: DatagramOccurrenceId,
      flow_id: DatagramFlowId,
      direction: DatagramDirectionV1,
      payload_bytes: BoundedU32,
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | OriginalDestinationReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      flow_id: DatagramFlowId,
      observation_epoch: DatagramObservationEpoch,
      endpoint: EndpointV1,
      mechanism: ClosedOriginalDestinationMechanism,
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | ProcessIdentityReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      flow_id: DatagramFlowId,
      observation_epoch: DatagramObservationEpoch,
      platform_identity: ClosedPlatformProcessIdentity,
      mechanism: ClosedProcessObservationMechanism,
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | RawFragmentBoundaryReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      fragment_observation_id: Bytes32,
      family: AddressFamilyV1,
      direction: RawDatagramDirectionObservationV1,
      observed_length: BoundedU32,
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | DnsPlaintextBoundaryReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      producer_source: DnsPlaintextDecoder | RuntimeProtectedHook |
        NativeSystemResolverHook,
      producer_spec_entry_digest:
        Digest(DnsPlaintextProducerStreamSpecV1),
      observation_stream_id: Bytes32,
      observation_stream_ordinal: U64,
      host_association_key: DnsPlaintextHostAssociationKeyV1,
      message_key: DnsPlaintextBoundaryMessageKeyV1,
      classification: DnsPlaintextBoundaryClassificationV1,
      family: AddressFamilyV1,
      transport: DnsTransportV1,
      outer_attribution: DnsPlaintextOuterAttributionV1,
      bounded_message_length: BoundedU32,
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | DnsEncryptedOuterReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      producer_source: ExactDnsEncryptedOuterClassifier,
      host_association_key: DnsEncryptedOuterHostAssociationKeyV1,
      message_key: DnsBoundaryMessageKeyV1::EncryptedOuter,
      family: AddressFamilyV1,
      transport: Tls | Https | Quic,
      outer_identity: Digest(DnsEncryptedOuterIdentityProjectionV1),
      observed_at: MonotonicInstant,
      last_observed_at: MonotonicInstant,
      bounded_transport_bytes?: U64,
      zero_plaintext_census: DnsPlaintextBoundaryCensusV1,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | DnsQuicFinReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      host_association_key: DnsHostAssociationKeyV1::DoqStream,
      stream_id: QuicStreamIdV1,
      final_message_ordinal: ExactU8(0) | ExactU8(1),
      fin_role: ExactAscii("Client") | ExactAscii("Server"),
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | Arch004ResourceReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      resource_identity: Arch004ResourceIdentityV1,
      observed_image: Arch004ResourceImageV1,
      predicate: Arch004SuccessPredicateV1,
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | Arch004OwnershipAbsenceReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      resource_identity: Arch004ResourceIdentityV1,
      resource_plan_digest: Digest(Arch004ResourcePlanV1),
      preserved_external_image: Arch004ResourceImageV1,
      owner_marker_universe_root: Digest,
      owner_marker_universe_count: U64,
      observed_flowprobe_owner_marker_count: ExactU64(0),
      dependent_effect_universe_root: Digest,
      dependent_effect_universe_count: U64,
      reachable_flowprobe_dependent_effect_count: ExactU64(0),
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | DnsHostAssociationReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      association_key: DnsHostAssociationKeyV1,
      placement: DnsHostAssociationPlacementV1,
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | DynamicCapacityTerminalReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      subject: Arch004DynamicCapacitySubjectV1,
      predecessor_active_digest: Digest(Arch004DynamicCapacityActiveV1),
      terminal_reason: ClosedDynamicCapacityTerminalReasonV1,
      ended_at: MonotonicInstant,
      unreachability_predicate:
        Arch004DynamicCapacityUnreachabilityPredicateV1,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | MetadataRetentionReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      subject: Arch004RetainedMetadataSubjectV1,
      predecessor_active_digest:
        Digest(Arch004RetainedMetadataActiveV1),
      predecessor_active_publication_indirection_digest:
        Digest(Arch004CapacityPublishedDestinationIndirectionV1),
      semantic_terminal: Arch004SemanticMetadataTerminalRefV1,
      reason: Arch004RetainedMetadataTerminalReasonV1,
      all_revisions_metadata_indexes_and_lineage_unreachable: true,
      ended_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | ResourceJournalRetentionReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      observation: Arch004ResourceJournalRetentionObservationV1,
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | RawFragmentRetentionReadback {
      context_digest: Digest(Arch004ObservationContextV1),
      fragment_observation_id: Bytes32,
      transition: Arch004RawFragmentRetentionTransitionV1,
      observed_at: MonotonicInstant,
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }

EvidenceRefV1 =
  | Arch001JournalRecord {
      registered_resource_kind: Arch004ResourceKindV1,
      journal_evidence_role: Arch004JournalEvidenceRoleV1,
      schema_version: PositiveBoundedU16,
      canonical_body_digest: Digest,
      journal_location: Arch001JournalLocation,
    }

  | Arch002RegisteredRoot {
      root_registry_version: ExactU16(1),
      root_tag: Arch002EvidenceRootTagV1,
      schema_version: PositiveBoundedU16,
      canonical_body_digest: Digest,
      prepared_plan_id: PreparedPlanId,
      plan_digest: PlanDigest,
      root_ordinal: MonotonicSequence,
    }
  | Arch004InlineObservation {
      observation_kind: Arch004InlineObservationKindV1,
      schema_version: PositiveBoundedU16,
      canonical_body_digest: Digest,
      body: Arch004InlineObservationBodyV1,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      observation_stream_id: Bytes32,
      observation_ordinal: MonotonicSequence,
    }

DatagramBoundaryEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: DatagramBoundaryReadback,
    body: Arch004InlineObservationBodyV1::DatagramBoundaryReadback,
  }
OriginalDestinationEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: OriginalDestinationReadback,
    body: Arch004InlineObservationBodyV1::OriginalDestinationReadback,
  }
ProcessIdentityEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: ProcessIdentityReadback,
    body: Arch004InlineObservationBodyV1::ProcessIdentityReadback,
  }
RawFragmentBoundaryEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: RawFragmentBoundaryReadback,
    body: Arch004InlineObservationBodyV1::RawFragmentBoundaryReadback,
  }
DnsPlaintextBoundaryEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: DnsPlaintextBoundaryReadback,
    body: Arch004InlineObservationBodyV1::DnsPlaintextBoundaryReadback,
  }
DnsEncryptedOuterEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: DnsEncryptedOuterReadback,
    body: Arch004InlineObservationBodyV1::DnsEncryptedOuterReadback,
  }
DnsQuicQueryFinEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: DnsQuicFinReadback,
    body: Arch004InlineObservationBodyV1::DnsQuicFinReadback {
      final_message_ordinal: ExactU8(0),
      fin_role: ExactAscii("Client"),
    },
  }
DnsQuicResponseFinEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: DnsQuicFinReadback,
    body: Arch004InlineObservationBodyV1::DnsQuicFinReadback {
      final_message_ordinal: ExactU8(1),
      fin_role: ExactAscii("Server"),
    },
  }
ResourceReadbackEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: Arch004ResourceReadback,
    body: Arch004InlineObservationBodyV1::Arch004ResourceReadback,
  }
OwnershipAbsenceEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: Arch004OwnershipAbsenceReadback,
    body: Arch004InlineObservationBodyV1::Arch004OwnershipAbsenceReadback,
  }
DnsHostAssociationEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: DnsHostAssociationReadback,
    body: Arch004InlineObservationBodyV1::DnsHostAssociationReadback,
  }
ExclusiveSocketOwnerEvidenceRefV1 =
  EvidenceRefV1::Arch002RegisteredRoot {
    root_tag: OsSocketCensus | FactorySocketCensusObservation,
  }
EgressPathProofEvidenceRefV1 =
  EvidenceRefV1::Arch002RegisteredRoot {
    root_tag: EgressPathProofResult,
  }
NoPendingTunRecursionEvidenceRefV1 =
  EvidenceRefV1::Arch002RegisteredRoot {
    root_tag: ActorNetworkIsolationReadback,
  }
EgressExclusionReadbackEvidenceRefV1 =
  EvidenceRefV1::Arch002RegisteredRoot {
    root_tag: EgressExclusionReadbackObservation,
  }
PlatformCapabilityEvidenceRefV1 =
  EvidenceRefV1::Arch002RegisteredRoot {
    root_tag: PlatformCapabilityEvidence,
  }
CapabilityReportEvidenceRefV1 =
  EvidenceRefV1::Arch002RegisteredRoot {
    root_tag: CapabilityReport,
  }
Arch004ResourceActiveHealthEvidenceRefV1 =
  EvidenceRefV1::Arch001JournalRecord {
    journal_evidence_role: ActiveHealthResult,
  }
MetadataRetentionEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: MetadataRetentionReadback,
    body: Arch004InlineObservationBodyV1::MetadataRetentionReadback,
  }
ResourceJournalRetentionEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: ResourceJournalRetentionReadback,
    body: Arch004InlineObservationBodyV1::ResourceJournalRetentionReadback,
  }
ResourceJournalPersistenceEvidenceRefV1 =
  ResourceJournalRetentionEvidenceRefV1 {
    body.observation:
      Arch004ResourceJournalRetentionObservationV1::Persistence,
  }
ResourceJournalTerminalEvidenceRefV1 =
  ResourceJournalRetentionEvidenceRefV1 {
    body.observation:
      Arch004ResourceJournalRetentionObservationV1::Terminal,
  }
DynamicCapacityTerminalEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: DynamicCapacityTerminalReadback,
    body: Arch004InlineObservationBodyV1::DynamicCapacityTerminalReadback,
  }
RawFragmentRetentionEvidenceRefV1 =
  EvidenceRefV1::Arch004InlineObservation {
    observation_kind: RawFragmentRetentionReadback,
    body: Arch004InlineObservationBodyV1::RawFragmentRetentionReadback,
  }
```

`DatagramFlowId` is the exact type and value of the enclosing accepted
`NormalizedFlow.flow_id`; this contract defines no second flow-ID namespace.
Every post-seal observation record binds the applicable ARCH-001
`InstallationId`, `SessionId`,
`Generation`, `PreparedPlanId`, `PlanDigest`, `ActivationLeaseId`, `LeaseEpoch`,
and current fence. It also binds the exact ARCH-002 `NetworkScope`,
`Digest(SafeEgressSelectionV1)`, actor, socket factory, and exclusion-set root
when a network path is involved. No alias, implementation-owned projection, or
opaque registration digest may replace either accepted ARCH-002 type.
Receipt-free authorization subjects and the resolver candidate binding are the
only pre-plan bodies: they bind preparation ticket/session/generation and
contain no future prepared ID, plan digest, lease, fence, result, or consumption
record. Their separately defined post-plan records add those values without
feeding them back into a candidate digest.

`EvidenceRefV1` is a closed tagged reference to an exact
ARCH-001 journal/result record, an exact registered ARCH-002 root, or an inline
versioned UDP/DNS observation defined here. It names the object type, schema
version, canonical-body digest, and resolving journal/root location. An opaque
producer hash, private serialization hash, unregistered evidence type, dangling
reference, or body/digest mismatch is invalid.

The variant fixes the resolving authority; a journal location cannot resolve an
ARCH-002 root and an inline ordinal cannot resolve a helper result. An ARCH-002
reference accepts only the displayed closed subset of tags from the exact
root-registry version and
the named root at that ordinal. An inline reference accepts only the displayed
observation kind and requires its canonical body to carry the exact context
digest. Inline kinds are leaf producer read-backs: their canonical bodies MUST
NOT contain `EvidenceRefV1`, a digest of another inline read-back, or an
unlisted ancestor/high-level transaction, flow, matrix, resource result, or
host-association body. A `DnsHostAssociationReadback::SelectedEgressPath`
placement is the first network-path exception: it may contain exactly one
accepted tag-31 child digest and one accepted tag-13 evidence ref, neither of
which can point back into ARCH-004. A `DnsEncryptedOuterReadback` is the second:
it may contain exactly one typed plaintext census whose prefix roots cover only
strictly earlier `DnsPlaintextBoundaryReadback` leaves. The path selection is a
pure outer-association value plus accepted ARCH-002 root digests and contains no
ARCH-004 evidence reference. The census cannot cover the current outer leaf, a
host-association leaf, capability cell/matrix, DNS transaction, successor, or
any descendant. Its only dependency order is `plan registry spec -> plaintext
leaves -> stream prefix roots -> encrypted outer census/readback -> capability
cell observation`, so no reverse edge or digest cycle is legal. The displayed capacity read-backs
are the other exceptions: they may contain exactly their typed immutable
predecessor/semantic-terminal/commitment/receipt digests. A journal-persistence
read-back additionally contains exactly one closed
`Arch004ResourceJournalInnerRecordRefV1` plus only the strictly prior receipt
and Active named by its persistence body; it cannot contain the successor
Active, current outer envelope, transition, or head. No exception may name a
descendant or resulting state/head. The stream ID plus ordinal resolves one immutable append-only
leaf and prevents self/descendant digest cycles. Every context equality is
checked byte-for-byte and expires as one unit; no producer may splice a plan,
lease, fence, actor, factory, exclusion root, observer, decoder, limit set, or
egress value from another observation.

Inline kind tags and body variants are one-to-one in displayed order, schema
version is exactly 1, and `canonical_body_digest` is
`SHA-256("FlowProbe.Arch004.InlineObservation.v1\0" || uint16_be(kind_tag) ||
deterministic_cbor(body))`. The ref context, body context, and resolved stream
record context are byte-identical. Original-destination/process read-backs also
repeat the exact flow ID and observation epoch; DNS read-backs repeat the exact
host-association and message key; raw fragments repeat their fresh observation
ID; resource read-backs repeat the exact resource identity and normalized
image; and dynamic-capacity terminal read-backs repeat the exact subject,
predecessor active digest, terminal reason/time, and closed unreachability
predicate. Raw-fragment retention read-backs repeat the exact fragment ID and
typed live/queued predecessor plus transition. Metadata-retention leaves repeat
the exact typed semantic terminal, retained predecessor and its publication
indirection, reason, unreachability predicate and terminal time; that time is
not earlier than the resolved retained Active. Journal persistence/terminal leaves repeat the
displayed allocation, revision, one typed inner record, prior/current
accumulator roots, cumulative count/bytes, prior receipt/Active, journal roots,
current Active predecessor and deletion disposition. Capacity leaves cannot reference their terminal object, any released
state, resulting transition/head, or another inline leaf. A kind/body mismatch,
private digest, cross-subject leaf, cycle, or authenticator over another preimage
is invalid.

For `DnsPlaintextBoundaryEvidenceRefV1`, the envelope
`observation_stream_id/observation_ordinal` is byte-identical to
`body.observation_stream_id/body.observation_stream_ordinal`; both equal the
resolved registry stream and contiguous stream position. The body context,
envelope context and resolved stream-record context all name the same
`PassiveObserver` snapshot. Two locator pairs for one signed body, or one
locator pair resolving a different body, are invalid.

Evidence use sites are closed; a field cannot accept another `EvidenceRefV1`
variant merely because its digest resolves. The exact mapping is:

| Use site | Only accepted ref/body | Required context and equality |
| --- | --- | --- |
| observed datagram claim, occurrence | `DatagramBoundaryEvidenceRefV1` | `DatagramObserver`; occurrence, flow, direction, bytes, time, actor and boundary build equal |
| observed original destination | `OriginalDestinationEvidenceRefV1` | `DatagramObserver`; flow, epoch, endpoint, mechanism and time equal |
| observed process identity | `ProcessIdentityEvidenceRefV1` | `DatagramObserver`; flow, epoch, platform identity, mechanism and time equal |
| capability-cell routing `Proven` | `DnsRoutingProvenWitnessV1` | `CapabilityEvaluation`; mandatory selected path or native route read-back with exact cell transport/scope/resource/context; no post-seal binding-set back-reference |
| capability-cell interception `Proven` | `DnsInterceptionProvenWitnessV1` | `CapabilityEvaluation`; mandatory current intercept/native-route read-back and authenticated plaintext probe from the exact selected mechanism/path |
| capability-cell decoding `Proven` | `DnsDecodingProvenWitnessV1` | `CapabilityEvaluation`; mandatory same-probe query/response plaintext pair for the exact transport, HTTPS carrier when applicable, and both query/response FIN leaves for DoQ |
| capability-cell leak-prevention `Proven` | `DnsLeakPreventionProvenWitnessV1` | `CapabilityEvaluation`; mandatory selected path or native route read-back plus exact no-pending-TUN-recursion proof; no post-seal binding-set back-reference |
| capability-cell standard `NotProven` | `DnsStandardClaimNegativeEvidenceRefV1` | `CapabilityEvaluation`; exact cell/spec/scope/platform/claim/reason/disposition, reason-specific basis, evaluation time and tag-`0x4006` signer equal |
| capability-cell original destination | `OriginalDestinationEvidenceRefV1` inside `DnsOriginalDestinationCapabilityClaimV1::Proven`, or `DnsOriginalDestinationNegativeEvidenceRefV1` inside its exact `NotProven` outcome | `CapabilityEvaluation`; cell/spec/scope/platform, probe flow, exact negative-reason tag, prior evidence/deadline when expired, evaluation time and freshness all equal |
| capability-cell process provenance | `ProcessIdentityEvidenceRefV1 | ExclusiveSocketOwnerEvidenceRefV1` inside `DnsProcessProvenanceCapabilityClaimV1::Proven`, or `DnsProcessProvenanceNegativeEvidenceRefV1` inside its exact `NotProven` outcome | `CapabilityEvaluation`; cell/spec/scope/platform, probe flow/socket, exact negative-reason tag, prior evidence/deadline when expired, evaluation time and freshness all equal |
| inferred endpoint role | `DatagramBoundaryEvidenceRefV1` | same authenticated flow and endpoint-role input |
| inferred process | `ExclusiveSocketOwnerEvidenceRefV1` | exact tag-44/46 census entry, boot/process/socket identity and current plan |
| raw fragment | `RawFragmentBoundaryEvidenceRefV1` | `DatagramObserver`; fragment ID, family, direction, length and time equal |
| DNS observed class, decoded/malformed/decode-opaque message | `DnsPlaintextBoundaryEvidenceRefV1` | `PassiveObserver`; plan registry entry, stream ID/ordinal, producer source, association, message key, exact closed classification, family/transport, outer attribution, bounded length and time equal |
| decoded DNS semantic result | complete `DnsDecodedSemanticObservationV1` | exact signed plaintext boundary/context; family/transport, QR role, wire ID, opcode, correlation commitment, projected-question digest, optional response summary, time and tag-`0x4009` Capture Core signer equal |
| encrypted DNS capability status | `DnsEncryptedOuterEvidenceRefV1` | `PassiveObserver`; classifier source, exact selected planned path and outer subject/epoch, family/transport, derived outer ID/message key, optional bytes, first/last/finalization times, complete plan-sealed plaintext census with both matching and unresolved-candidate counts zero, and signer equal |
| DoQ query/response FIN | respectively `DnsQuicQueryFinEvidenceRefV1` / `DnsQuicResponseFinEvidenceRefV1` | `PassiveObserver`; hook-bearing DoQ association, stream, ordinal 0/client or 1/server role and time equal |
| DNS host association | `DnsHostAssociationEvidenceRefV1` | `PassiveObserver`; complete key and enclosing host object/epoch equal; `HostOnly` except selected encrypted outer, whose placement contains the exact cell tag-31 child/tag-13 path ref |
| passive observed resolver endpoint | `DnsObservedResolverEndpointEvidenceRefV1` | exact host-association ref/key, family/transport, canonical endpoint identity projection, remote endpoint, context/time and tag-`0x4007` Capture Core signer equal |
| resolver-bootstrap query result | complete `Arch004ResolverBootstrapResultV1` | `NetworkPath`; current member, predecessor set/member/Ready observation, descriptor/use-site/input/family, bounded outcome, freshness and tag-`0x4008` RuntimeAdapter signer equal |
| resolver member path, no-recursion, platform support | respectively `EgressPathProofEvidenceRefV1`, `NoPendingTunRecursionEvidenceRefV1`, `PlatformCapabilityEvidenceRefV1` | `NetworkPath` and exact registered ARCH-002 plan/root values equal |
| resource condition, after/before/absence/drift/health read-back | `ResourceReadbackEvidenceRefV1` | `ResourceExecution`; identity, normalized image, predicate, executor, owner, plan and time equal |
| ownership abandonment | `OwnershipAbsenceEvidenceRefV1` | `ResourceExecution`; exact identity/plan/context/preserved foreign image, complete per-kind owner-marker and dependent-effect universe roots/counts, both observed counts zero and time equal |
| committed capacity state or resource publication | complete `Arch004CapacityPostCasCommitReceiptV1` | `CapacityCommit`; exact plan-bound ledger manifest/authority/gate, durable slot record, transition, resulting head/snapshot, complete state-role projection, durably recorded CAS-linearization time and tag-`0x400A` signer equal; signing occurs only after slot fsync/readback, while consumer-specific subject/owner/requirement comes from the selected state or publication bundle, never this ledger-level context |
| staged capacity destination | complete `Arch004CapacityDestinationPublicationCertificateV1` | `CapacityCommit`; exact signed receipt, deterministic publication transaction, complete batch/destination/projection roots, flat current-operation validation capsule and tag-`0x400C` signer equal; signing is available only after every private staged copy reads back and never by itself proves WAL commit or publishes a destination |
| activated capacity destination | exact `Arch004CapacityPublishedDestinationIndexEntryV1` under either current-checkpoint membership or settled activation | `CapacityCommit`; while activation checkpoint is current, its exact PublicIndirection participant plus the exact Prepared region proves commit; after rotation, the same region requires its tag-`0x400D` activation-receipt suffix and settlement bound. In both branches location/indirection/certificate and tag-`0x400C` capsule are exact; a pre-commit certificate or unlisted Prepared entry is not activation evidence |
| activated retained-metadata Active | exact `Arch004CapacityPublishedDestinationIndexEntryV1` selecting `RetainedMetadataPublication` under the same current-or-settled branch | `CapacityCommit`; public location, current participant or settled activation receipt, Active body/digest, retained subject, retention requirement, target Reserved state, semantic terminal, flat capsule and tag-`0x400C` certificate equal the sole retention Transfer candidate and destination; a raw Active digest, private staging ID or unlisted Prepared entry is never a locator |
| capacity operation owner-epoch registry, channel event, terminal or unreachability | complete matching body | `CapacityReplayRegistry`; exact plan-bound ledger/domain/authority/mode/owner-epoch key, frozen registry, contiguous channel stream or replayed closure census and tag-`0x400B` signer equal; HistoricalCloseOnly may create only the deterministic terminal suffix and absorbing terminal after lease expiry |
| dynamic terminal, retained-metadata terminal, journal persistence/terminal, or raw-fragment transition | matching refined inline capacity ref | `CapacityAccounting`; ledger, requirement, owner, subject/allocation, predecessor, exact bytes and transition equal |

ARCH-004 defines these local tags only inside its own signature domain; they do
not amend or masquerade as an accepted ARCH-002 root-registry tag:

```text
Arch004ExternalObservationRootSchemaTagV1 =
  | InlineObservation                 = 0x4000
  | DatagramOccurrence                = 0x4001
  | ResolverReadyMemberObservation    = 0x4002
  | ResolverPathBindingSetObservation = 0x4003
  | DnsCapabilityMatrixObservation    = 0x4004
  | DnsAncillaryCapabilityNegativeObservation = 0x4005
  | DnsStandardClaimNegativeObservation       = 0x4006
  | DnsObservedResolverEndpointObservation    = 0x4007
  | ResolverBootstrapResultObservation        = 0x4008
  | DnsDecodedSemanticObservation             = 0x4009
  | CapacityPostCasCommitReceipt              = 0x400A
  | CapacityReplayOwnerEpochObservation       = 0x400B
  | CapacityDestinationPublicationCertificate = 0x400C
  | CapacityDestinationActivationReceipt      = 0x400D
```

The distinct `Arch004ExternalObservationAuthenticatorV1` reuses the accepted
header shape, key identity, role/authority binding and Ed25519 verification
rules, but its signature has only the following ARCH-004-local input semantics:

```text
"FlowProbe.Arch004.ExternalObservation.v1\0" ||
uint16_be(Arch004ExternalObservationRootSchemaTagV1::InlineObservation) ||
uint16_be(1) ||
canonical_cbor(authenticator.header) ||
SHA-256(canonical_cbor([
  observation_kind_tag,
  1,
  body_with_complete_authenticator_field_omitted,
  observation_context_digest,
  observation_stream_id,
  observation_ordinal,
]))
```

The kind tag is the exact displayed ordinal, and the four trailing values are
the byte-identical fields of the enclosing `Arch004InlineObservation` ref.
Only after that signature is attached is `canonical_body_digest` computed over
the complete signed body. An authenticator or its signature bytes are never
part of their own signing preimage.
ARCH-002 root refs retain the signer/role required by their registered root;
ARCH-001 journal refs retain helper authority and the closed role/body mapping
below. A valid signature from the wrong producer role, a ref with the right
kind but another message/subject, or a body copied under another context is
invalid. Claim/capability evidence vectors may contain only the row witnesses
needed by their exact predicate; unrelated valid evidence is rejected rather
than ignored.

Signer role is closed by context and kind. Datagram-boundary, original-
destination, process-identity, raw-fragment, DNS plaintext/encrypted/FIN,
host-association, dynamic-capacity, metadata-retention, journal-retention and
raw-fragment-retention leaves use `CaptureCore` with the exact registered
component and `ExternalExecutorGate` in their context. Standard-claim and
ancillary negative capability observations likewise use `CaptureCore`, and each
signer/component,
authority header and gate are byte-identical to the referenced
`CapabilityEvaluation.evaluator_component_instance_id` and `evaluator_gate`.
The tag-`0x4007` observed-resolver-endpoint signer is also `CaptureCore`, uses
the exact host-association observation context/gate, and repeats the same
component, lease and observation window. The tag-`0x4008` resolver-bootstrap
result signer is `RuntimeAdapter` under the predecessor resolver actor's exact
`NetworkPath` runtime gate; current/predecessor member, plan/lease/fence,
descriptor/use-site/query and result window all repeat that context.
The tag-`0x4009` decoded-semantic signer is `CaptureCore` under the exact
plaintext boundary's `PassiveObserver` context/gate; it binds that signed
boundary to the privacy-projected question digest, correlation commitment and
role-specific parsed header/response result without retaining raw message
bytes.
The tag-`0x400A` post-CAS receipt signer is the singleton Capture Core capacity-
ledger commit authority under the exact ledger-level `CapacityCommit` context. The
context resolves the plan-sealed ledger manifest and authority spec. The
authenticator header has `signer_role = CaptureCore`,
`signer_identity.ExternalExecutorIdentity.runtime_or_component_instance_id =
commit_authority_spec.component_instance_id`, `public_key_identity_digest =
commit_authority_spec.public_key_identity_digest`, and `authority_binding`
byte-identical to `context.commit_authority_gate`; no other accepted Capture
Core key is interchangeable. That gate's component identity, prepared-plan
digest, permit and channel binding are the exact registered post-CAS gate
projection described in section 15. Its signing path is reachable only after
compare-and-swap, durable dual-slot head write, fsync, and byte-for-byte
readback of the displayed commit record. A pre-CAS candidate, losing CAS branch,
caller-provided commit record or ordinary observation signer cannot obtain this
signature.
The tag-`0x400C` destination-publication signer is the same singleton commit
authority and exact `CapacityCommit` gate identity, key, permit and channel, but
uses its distinct schema tag and surface. It may sign exactly one deterministic
certificate per bounded batch destination only after the canonical signed
receipt and every private staged copy in that batch have fsynced and read back.
It also seals the exact flat validation capsule projected from the current head
candidate set. The certificate contains no activation time, indirection, marker
or Open replay, and that capsule contains no staged copy, current or prior full
certificate/indirection, batch body, or recursively resolvable predecessor.
Recovery therefore recreates byte-identical fixed-depth input. The gate returns
the signature only to the atomic activation transaction; a crash or abort
before that transaction leaves it unreachable, and a certificate alone never
makes a staging object addressable. Tag `0x400A` and `0x400C` signatures are not
interchangeable and neither surface authorizes another head CAS.
The tag-`0x400D` destination-activation signer is that same singleton authority
under the same exact `CapacityCommit` gate identity, key, permit and channel,
but its surface is reachable only after global-WAL recovery selects the named
committed checkpoint and the exact PublicIndirection participant and Prepared
public-index target both read back. It signs one deterministic activation
receipt per participant, binding the committed-checkpoint/body/commit-marker
digests, activation tuple, public location, Prepared-entry, indirection and
certificate digests and activation time. Its `activated_at` is byte-identical
to the immutable Prepared region's `public_indirection.activated_at` and the
activation transaction's `publication_linearized_at`; signing or recovery may
not substitute suffix-append or recovery time. The receipt is stored only in the
matching Active public-index entry. It cannot be generated for a merely
Prepared, aborted, sibling or digest-substituted transaction. Tags `0x400A`,
`0x400C` and `0x400D` are pairwise non-interchangeable, and none authorizes
another head transaction.
The tag-`0x400B` replay-owner-epoch signer is the plan-sealed singleton Capture
Core replay-registry authority under `CapacityReplayRegistry`. Its header
component, build, public key and `ExternalExecutorGate` equal
`replay_registry_authority_spec` and the context gate. `LiveRegistry` may sign
only a fresh per-operation frozen registry snapshot and its contiguous channel
events while the exact lease is live; after the owner-epoch head's exact
Closing-candidate CAS/fsync/readback, it may also sign that unique acknowledged
terminal. `HistoricalCloseOnly` is a separate gate surface that accepts only an
already frozen snapshot and each channel's durable last live prefix after that
lease expires. It may append only the deterministic terminal suffix that
retires the already accepted request and already issued tokens and records
`ChannelClosed`, after its own signed historical readback enumerates the
registered channel's complete transport-handle and key-slot universes as empty.
It then seals the barrier, installs the exact Closing candidate and may sign its
Expired terminal and complete unreachability package.
If a valid `ResponseAcknowledged` record was durably installed at or before the
request deadline but its remaining acknowledged-close suffix was interrupted,
`HistoricalFinalizeInstalledRecord` first produces the exact observation for
that installed record if its live wrapper was lost. Then
`HistoricalCompleteAcknowledgedClosure` may, after lease expiry, append and sign
only the uniquely derived missing token-retirement and channel-close suffix. It
may install the one acknowledged census/Closing candidate; it cannot create,
remove or change the acknowledgement record, nonce, time, request, prefix or
branch.
`HistoricalFinalizeInstalledRecord` cannot append an event or create a snapshot,
census or candidate. After lease expiry it may sign only (a) an exact unsigned
event record already present in the durable event-store prefix, with the exact
reconstructed predecessor/resulting store digests, or (b) the byte-identical
terminal candidate already selected by a prior Closing CAS/readback and the
exact `OperationRequestOwnerUnreachability` envelope that merely repeats that
installed candidate's snapshot, census, signed terminal and close time. It may
not change or omit any repeated body/digest. The candidate path
includes acknowledged candidates installed while `LiveRegistry` or
`HistoricalCompleteAcknowledgedClosure` was valid. None of the historical modes
may register a channel, accept another request, issue a token, rewrite a prior
ordinal, sign tag `0x400A`, or reach the capacity-ledger CAS. Mode-specific gate
bindings and preimages are not interchangeable, but signer mode is wrapper
metadata and never changes an installed event record or terminal-candidate byte.
For a committed epoch, the manifest key, gates and implementations remain
recoverable until the owner epoch is Closed, the selected Closed replay and its
successor watermark have fsynced/read back. For a pre-CAS-retired epoch they
remain recoverable until the exact terminal and the atomic
`Idle.last_admission_revision >= retired admission_revision` tombstone have
fsynced/read back; this branch intentionally has no successor operation
watermark. Plan replacement, build rotation or live-lease expiry cannot retire
them earlier, or the ledger could remain blocked or accept a retired request.
Resolver-path binding leaves use
`RuntimeAdapter` and the exact resolver actor/runtime gate. A
`ResourceExecution` leaf maps `ActorSocketFactoryOwner ->
SocketFactoryExecutor`, `CaptureCore -> CaptureCore`,
`NetworkRuntimeAdapter -> RuntimeAdapter`, and `PrivilegedHelper ->
PrivilegedHelper`. No other signer role or authority-binding variant is valid.

The journal branch has the same closed role/body mapping:
`AppliedResult` resolves only `Arch004ResourceResultV1::Applied |
AlreadyApplied`; `ObservedAbsentResult` only `Unapplied` with its before/absence
proof; `CompensatedResult` only `RestoredBefore | AlreadyBefore |
CreatedOwnedObjectAbsent`; `RecoveryResolution` only
`Arch004ResourceRecoveryResolutionV1`; and `ActiveHealthResult` only
`Arch004ResourceHealthObservationV1`. Resource kind, identity, plan, lease
projection, schema version, journal location, and canonical digest must all
agree. A role/type substitution, self-reference, or journal record from another
resource/context is invalid.

New digest-bound bodies use deterministic CBOR and reject unknown or duplicate
fields. `DnsCapabilityMatrixV1.matrix_digest` is exactly:

```text
Digest(Arch004ObservationContextV1) = SHA-256(
  "FlowProbe.Arch004.ObservationContext.v1\0" ||
  deterministic_cbor(context)
)

SHA-256(
  "FlowProbe.Dns.CapabilityMatrix.v1\0" ||
  deterministic_cbor({ cells, complete_key_set })
)

Digest(DnsCapabilityCellSpecV1) = SHA-256(
  "FlowProbe.Dns.CapabilityCellSpec.v1\0" ||
  deterministic_cbor(cell_spec)
)

Digest(DnsCapabilityCellObservationV1) = SHA-256(
  "FlowProbe.Dns.CapabilityCellObservation.v1\0" ||
  deterministic_cbor(cell_observation)
)

DnsCapabilityMatrixObservationV1.observation_digest = SHA-256(
  "FlowProbe.Dns.CapabilityMatrixObservation.v1\0" ||
  deterministic_cbor({ matrix_spec_digest,
    observation_context_digest, cells, authenticator })
)

DnsCapabilityMatrixObservationV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    DnsCapabilityMatrixObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor([
    matrix_spec_digest, observation_context_digest, cells
  ]))

Digest(DnsAncillaryCapabilityNegativeObservationV1) = SHA-256(
  "FlowProbe.Dns.AncillaryCapabilityNegativeObservation.v1\0" ||
  deterministic_cbor(observation)
)

DnsAncillaryCapabilityNegativeObservationV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    DnsAncillaryCapabilityNegativeObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor([
    observation_context_digest, cell_spec_digest, scope, platform_subject,
    reason, evaluated_at
  ]))

Digest(DnsStandardClaimNegativeObservationV1) = SHA-256(
  "FlowProbe.Dns.StandardClaimNegativeObservation.v1\0" ||
  deterministic_cbor(observation)
)

DnsStandardClaimNegativeObservationV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    DnsStandardClaimNegativeObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor([
    observation_context_digest, cell_spec_digest, scope, platform_subject,
    claim_kind, disposition, reason, basis, evaluated_at
  ]))

Digest(DnsObservedResolverEndpointObservationV1) = SHA-256(
  "FlowProbe.Dns.ObservedResolverEndpointObservation.v1\0" ||
  deterministic_cbor(observation)
)

Digest(DnsObservedResolverStreamHostCoreV1) = SHA-256(
  "FlowProbe.Dns.ObservedResolverStreamHostCore.v1\0" ||
  deterministic_cbor(host_core)
)

DnsObservedResolverEndpointObservationV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    DnsObservedResolverEndpointObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor([
    observation_context_digest, host_association_evidence_ref, host_object_ref,
    network_scope, family, transport, endpoint, endpoint_identity_digest,
    observed_at
  ]))

Digest(Arch004ResolverBootstrapResultV1) = SHA-256(
  "FlowProbe.Dns.ResolverBootstrapResult.v1\0" ||
  deterministic_cbor(result)
)

Arch004ResolverBootstrapResultV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    ResolverBootstrapResultObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor([
    observation_context_digest, current_member_binding_digest,
    resolver_dependency_descriptor_digest, use_site,
    input_endpoint_identity, input_endpoint_identity_digest,
    predecessor_binding_set_digest,
    predecessor_binding_set_observation_digest,
    predecessor_member_binding_digest,
    predecessor_member_ready_observation_digest, required_family, outcome,
    observed_at, expires_at
  ]))

Digest(DnsDecodedSemanticObservationV1) = SHA-256(
  "FlowProbe.Dns.DecodedSemanticObservation.v1\0" ||
  deterministic_cbor(observation)
)

Digest(DnsProjectedQuestionVectorV1) = SHA-256(
  "FlowProbe.Dns.ProjectedQuestionVector.v1\0" ||
  deterministic_cbor(projected_questions)
)

DnsDecodedSemanticObservationV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    DnsDecodedSemanticObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor([
    observation_context_digest, boundary_evidence_ref, family, transport,
    role, wire_id, opcode, correlation_question_commitment,
    projected_questions_digest, response_summary, observed_at
  ]))

Digest(Arch004CapacityCommitAuthoritySpecV1) = SHA-256(
  "FlowProbe.Arch004.CapacityCommitAuthoritySpec.v1\0" ||
  deterministic_cbor(commit_authority_spec))

Digest(Arch004CapacityReplayRegistryAuthoritySpecV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReplayRegistryAuthoritySpec.v1\0" ||
  deterministic_cbor(replay_registry_authority_spec))

Digest(Arch004CapacityLedgerRecoveryBudgetV1) = SHA-256(
  "FlowProbe.Arch004.CapacityLedgerRecoveryBudget.v1\0" ||
  deterministic_cbor(ledger_recovery_budget))

Digest(Arch004CapacityReplayEpochRecoveryBudgetV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReplayEpochRecoveryBudget.v1\0" ||
  deterministic_cbor(replay_epoch_recovery_budget))

Digest(Arch004CapacityLedgerManifestV1) = SHA-256(
  "FlowProbe.Arch004.CapacityLedgerManifest.v1\0" ||
  deterministic_cbor(capacity_ledger_manifest))

Digest(Arch004RetainedMetadataActiveV1) = SHA-256(
  "FlowProbe.Arch004.RetainedMetadataActive.v1\0" ||
  deterministic_cbor(retained_metadata_active))

Digest(Arch004RetainedMetadataTerminalV1) = SHA-256(
  "FlowProbe.Arch004.RetainedMetadataTerminal.v1\0" ||
  deterministic_cbor(retained_metadata_terminal))

Arch004CapacityCandidatePublicationSetV1.state_projection_root = SHA-256(
  "FlowProbe.Arch004.CapacityCandidateStateProjection.v1\0" ||
  deterministic_cbor(states[*].projection))

Arch004CapacityCandidatePublicationSetV1.predecessor_state_proof_root =
  SHA-256(
    "FlowProbe.Arch004.CapacityCandidatePredecessorProofs.v1\0" ||
    deterministic_cbor(predecessor_state_proofs))

Arch004CapacityCandidatePublicationSetV1.candidate_set_root = SHA-256(
  "FlowProbe.Arch004.CapacityCandidatePublicationMembers.v1\0" ||
  deterministic_cbor({ operation_id, publishing_transition_digest, states,
    state_count, state_projection_root, predecessor_state_proofs,
    predecessor_state_proof_root, generic_release_cause_preimage,
    publication_preimage }))

Digest(Arch004CapacityCandidatePublicationSetV1) = SHA-256(
  "FlowProbe.Arch004.CapacityCandidatePublicationSet.v1\0" ||
  deterministic_cbor(candidate_publication_set))

Digest(Arch004CapacityDurableCommitRecordV1) = SHA-256(
  "FlowProbe.Arch004.CapacityDurableCommitRecord.v1\0" ||
  deterministic_cbor(durable_commit_record))

Digest(Arch004CapacityDurableHeadSlotImageV1) = SHA-256(
  "FlowProbe.Arch004.CapacityDurableHeadSlotImage.v1\0" ||
  deterministic_cbor(durable_head_slot_image))

Digest(Arch004CapacityDurableHeadGenesisV1) = SHA-256(
  "FlowProbe.Arch004.CapacityDurableHeadGenesis.v1\0" ||
  deterministic_cbor(durable_head_genesis))

Digest(Arch004CapacityDurableHeadEmptyTargetV1) = SHA-256(
  "FlowProbe.Arch004.CapacityDurableHeadEmptyTarget.v1\0" ||
  deterministic_cbor(durable_head_empty_target))

Digest(Arch004CapacityDurableHeadStoreSlotV1) = SHA-256(
  "FlowProbe.Arch004.CapacityDurableHeadStoreSlot.v1\0" ||
  deterministic_cbor(durable_head_store_slot))

published_state_set_root = SHA-256(
  "FlowProbe.Arch004.CapacityPostCasPublishedStates.v1\0" ||
  deterministic_cbor(published_states))

Digest(Arch004CapacityPostCasCommitReceiptV1) = SHA-256(
  "FlowProbe.Arch004.CapacityPostCasCommitReceipt.v1\0" ||
  deterministic_cbor(receipt))

Arch004CapacityReservedStateProofV1.proof_root = SHA-256(
  "FlowProbe.Arch004.CapacityReservedStateProofMembers.v1\0" ||
  deterministic_cbor({ state, state_digest, basis_bundle,
    basis_bundle_digest, post_cas_receipt, origin_public_indirection,
    origin_public_indirection_digest, publishing_transition,
    publishing_transition_digest, resulting_head, resulting_head_digest,
    resulting_snapshot, resulting_snapshot_digest, creation_role }))

Digest(Arch004CapacityReservedStateProofV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReservedStateProof.v1\0" ||
  deterministic_cbor(reserved_state_proof))

Arch004CapacityStateProofEntryV1.proof_root = SHA-256(
  "FlowProbe.Arch004.CapacityStateProofMembers.v1\0" ||
  deterministic_cbor({ state, state_digest, basis_bundle,
    basis_bundle_digest, post_cas_receipt, predecessor_reserved_proof,
    publishing_transition, publishing_transition_digest, resulting_head,
    resulting_head_digest, resulting_snapshot, resulting_snapshot_digest,
    creation_role }))

Digest(Arch004CapacityStateProofEntryV1) = SHA-256(
  "FlowProbe.Arch004.CapacityStateProof.v1\0" ||
  deterministic_cbor(state_proof))

Digest(Arch004CapacityOperationOwnerEpochKeyV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochKey.v1\0" ||
  deterministic_cbor(owner_epoch_key))

Arch004CapacityOperationOwnerEpochKeyV1.request_owner_epoch_id = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochId.v1\0" ||
  sequence_domain_id || uint64_be(request_sequence) ||
  uint64_be(admission_revision) || operation_intent_digest ||
  deterministic_cbor(request_owner))

Digest(Arch004CapacityOperationOwnerEpochChannelRegistrationV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochChannelRegistration.v1\0" ||
  deterministic_cbor(registration))

Digest(Arch004CapacityOperationOwnerEpochRetryTokenV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochRetryToken.v1\0" ||
  deterministic_cbor(retry_token))

Digest(Arch004CapacityRequestRetirementBasisV1) = SHA-256(
  "FlowProbe.Arch004.CapacityRequestRetirementBasis.v1\0" ||
  deterministic_cbor(request_retirement_basis))

Arch004CapacityOperationOwnerEpochRegistrySnapshotV1.registration_set_root =
  SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochRegistrations.v1\0" ||
    deterministic_cbor(registrations))

Arch004CapacityOperationOwnerEpochRegistrySnapshotV1.event_store_id =
  SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochEventStoreId.v1\0" ||
    ledger_id || Digest(owner_epoch_key))

Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochRegistrySnapshot.v1\0" ||
  deterministic_cbor(registry_snapshot))

Arch004CapacityOperationOwnerEpochChannelEventRecordV1.
  observation_stream_id = SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochChannelStream.v1\0" ||
    registry_snapshot_digest || registration_digest)

Digest(Arch004CapacityOperationOwnerEpochChannelEventRecordV1) =
  SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochChannelEventRecord.v1\0" ||
    deterministic_cbor(channel_event_record))

Digest(Arch004CapacityOperationOwnerEpochChannelEventObservationV1) =
  SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochChannelEventObservation.v1\0" ||
    deterministic_cbor(channel_event_observation))

Arch004CapacityOperationOwnerEpochChannelEventStreamV1.event_prefix_root =
  SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochEventPrefix.v1\0" ||
    deterministic_cbor(event_records))

Arch004CapacityOperationOwnerEpochEventStoreV1.stream_set_root = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochEventStreams.v1\0" ||
  deterministic_cbor(streams))

Digest(Arch004CapacityOperationOwnerEpochEventStoreV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochEventStore.v1\0" ||
  deterministic_cbor(event_store))

Digest(Arch004CapacityOperationOwnerEpochClosureBranchLatchV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochClosureBranchLatch.v1\0" ||
  deterministic_cbor(closure_branch_latch))

Arch004CapacityOperationOwnerEpochTransportClosureHeadV1.
  active_transport_handle_set_root = SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochLiveTransportHandles.v1\0" ||
    deterministic_cbor(active_transport_handle_digests))

Digest(Arch004CapacityOperationOwnerEpochTransportClosureHeadV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochTransportClosureHead.v1\0" ||
  deterministic_cbor(transport_closure_head))

Arch004CapacityOperationOwnerEpochKeyStoreClosureHeadV1.
  loaded_channel_key_identity_set_root = SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochLoadedChannelKeys.v1\0" ||
    deterministic_cbor(loaded_channel_key_identity_digests))

Digest(Arch004CapacityOperationOwnerEpochKeyStoreClosureHeadV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochKeyStoreClosureHead.v1\0" ||
  deterministic_cbor(key_store_closure_head))

Digest(Arch004CapacityOperationOwnerEpochHistoricalClosureReadbackV1) =
  SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochHistoricalClosureReadback.v1\0" ||
    deterministic_cbor(historical_closure_readback))

Arch004CapacityOperationOwnerEpochHistoricalClosureReadbackV1.
  expected_transport_handle_digest =
    registration.transport_handle_identity_digest

Arch004CapacityOperationOwnerEpochHistoricalClosureReadbackV1.
  expected_channel_key_identity_digest =
    registration.channel_key_identity_digest

Arch004CapacityOperationOwnerEpochChannelCensusLeafV1.
  sealed_event_prefix_root = SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochSignedEventPrefix.v1\0" ||
    deterministic_cbor(sealed_event_prefix))

Arch004CapacityOperationOwnerEpochChannelCensusLeafV1.
  sealed_event_record_prefix_root = SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochEventPrefix.v1\0" ||
    deterministic_cbor(sealed_event_prefix[*].event_record))

Arch004CapacityOperationOwnerEpochChannelCensusLeafV1.
  pending_request_set_root = SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochPendingRequests.v1\0" ||
    deterministic_cbor(pending_request_keys))

Arch004CapacityOperationOwnerEpochChannelCensusLeafV1.
  pending_retry_token_set_root = SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochPendingRetryTokens.v1\0" ||
    deterministic_cbor(pending_retry_tokens))

Digest(Arch004CapacityOperationOwnerEpochChannelCensusLeafV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochChannelCensusLeaf.v1\0" ||
  deterministic_cbor(channel_census_leaf))

Arch004CapacityOperationOwnerEpochClosureCensusV1.leaf_set_root = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochCensusLeaves.v1\0" ||
  deterministic_cbor(leaves))

Arch004CapacityOperationOwnerEpochClosureCensusV1.
  registered_channel_key_set_root = SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochRegisteredChannelKeys.v1\0" ||
    deterministic_cbor(registry_snapshot.registrations[*].{
      registry_ordinal, channel_binding_digest }))

Arch004CapacityOperationOwnerEpochClosureCensusV1.
  closed_channel_key_set_root = SHA-256(
    "FlowProbe.Arch004.CapacityOperationOwnerEpochRegisteredChannelKeys.v1\0" ||
    deterministic_cbor(
      leaves[*].closed_event.event_record.event.ChannelClosed.channel_key))

Digest(Arch004CapacityOperationOwnerEpochClosureCensusV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochClosureCensus.v1\0" ||
  deterministic_cbor(closure_census))

Digest(Arch004CapacityOperationOwnerEpochTerminalCandidateV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochTerminalCandidate.v1\0" ||
  deterministic_cbor(owner_epoch_terminal_candidate))

Digest(Arch004CapacityOperationOwnerEpochTerminalV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochTerminal.v1\0" ||
  deterministic_cbor(owner_epoch_terminal))

Digest(Arch004CapacityOperationOwnerEpochStateHeadV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOwnerEpochStateHead.v1\0" ||
  deterministic_cbor(owner_epoch_state_head))

Digest(Arch004CapacityOperationReplayRequestV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationReplayRequest.v1\0" ||
  deterministic_cbor(replay_request))

Arch004CapacityReplaySelectorEnvelopeV1 =
  replay_request.{ ledger_id, sequence_domain_id, request_sequence,
    admission_revision }

Digest(Arch004CapacityReplaySelectorEnvelopeV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReplaySelectorEnvelope.v1\0" ||
  deterministic_cbor(replay_selector_envelope))

Digest(Arch004CapacityPendingOperationAdmissionV1) = SHA-256(
  "FlowProbe.Arch004.CapacityPendingOperationAdmission.v1\0" ||
  deterministic_cbor(pending_operation_admission))

Digest(Arch004CapacityReplayRecoveryStorePayloadV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReplayRecoveryStorePayload.v1\0" ||
  deterministic_cbor(replay_recovery_store_payload))

Digest(Arch004CapacityReplayRecoveryStoreSlotV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReplayRecoveryStoreSlot.v1\0" ||
  deterministic_cbor(replay_recovery_store_slot))

Digest(Arch004CapacityOperationReplayWatermarkV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationReplayWatermark.v1\0" ||
  deterministic_cbor(watermark))

Digest(Arch004CapacityOperationReplayWatermarkSlotV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationReplayWatermarkSlot.v1\0" ||
  deterministic_cbor(watermark_slot))

Digest(Arch004CapacityOperationReplayWatermarkStoreSlotV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationReplayWatermarkStoreSlot.v1\0" ||
  deterministic_cbor(watermark_store_slot))

Arch004CapacityRetiredReplayCommitmentV1(open_replay) = SHA-256(
  "FlowProbe.Arch004.CapacityRetiredReplayCommitment.v1\0" ||
  Digest(open_replay))

Digest(Arch004CapacityReleaseReplayCapsuleV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReleaseReplayCapsule.v1\0" ||
  deterministic_cbor(capsule))

Digest(Arch004CapacityPostCasSidecarV1) = SHA-256(
  "FlowProbe.Arch004.CapacityPostCasSidecar.v1\0" ||
  deterministic_cbor(sidecar))

Digest(Arch004CapacityPostCasSidecarStorePayloadV1) = SHA-256(
  "FlowProbe.Arch004.CapacityPostCasSidecarStorePayload.v1\0" ||
  deterministic_cbor(sidecar_store_payload))

Digest(Arch004CapacityPostCasSidecarStoreSlotV1) = SHA-256(
  "FlowProbe.Arch004.CapacityPostCasSidecarStoreSlot.v1\0" ||
  deterministic_cbor(sidecar_store_slot))

Arch004CapacityOpenOperationReplayV1.replay_response_root = SHA-256(
  "FlowProbe.Arch004.CapacityOperationReplayResponse.v1\0" ||
  deterministic_cbor({ replay_request, replay_request_digest,
    operation_id, publishing_transition_digest, result, opened_at }))

Digest(Arch004CapacityOpenOperationReplayV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOpenOperationReplay.v1\0" ||
  deterministic_cbor(open_operation_replay))

Digest(Arch004CapacityOperationOutcomeV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationOutcome.v1\0" ||
  deterministic_cbor(capacity_operation_outcome))

Digest(Arch004CapacityOperationReplayAcknowledgementV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationReplayAcknowledgement.v1\0" ||
  deterministic_cbor(acknowledgement))

Digest(Arch004CapacityOperationReplayExpiryV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationReplayExpiry.v1\0" ||
  deterministic_cbor(expiry))

Digest(Arch004CapacityOperationRequestOwnerUnreachabilityV1) = SHA-256(
  "FlowProbe.Arch004.CapacityOperationRequestOwnerUnreachability.v1\0" ||
  deterministic_cbor(owner_unreachability))

Digest(Arch004CapacityClosedOperationReplayV1) = SHA-256(
  "FlowProbe.Arch004.CapacityClosedOperationReplay.v1\0" ||
  deterministic_cbor(closed_operation_replay))

Arch004CapacityReceiptPublicationBatchV1.destination_set_root = SHA-256(
  "FlowProbe.Arch004.CapacityReceiptDestinations.v1\0" ||
  deterministic_cbor(destinations))

Arch004CapacityReceiptPublicationBatchV1.staged_copy_set_root = SHA-256(
  "FlowProbe.Arch004.CapacityStagedDestinationCopies.v1\0" ||
  deterministic_cbor(staged_destination_copies))

Digest(Arch004CapacityReceiptPublicationBatchV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReceiptPublicationBatch.v1\0" ||
  deterministic_cbor(batch))

Digest(Arch004CapacityReceiptDestinationV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReceiptDestination.v1\0" ||
  deterministic_cbor(receipt_destination))

Digest(Arch004CapacityReceiptDestinationProjectionV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReceiptDestinationProjection.v1\0" ||
  deterministic_cbor(destination_projection))

Arch004CapacityPublicationTransactionIdV1 = SHA-256(
  "FlowProbe.Arch004.CapacityPublicationTransactionId.v1\0" ||
  durable_commit_record_digest || receipt_digest)

Arch004CapacityStagedDestinationCopyV1.staging_object_id = SHA-256(
  "FlowProbe.Arch004.CapacityStagedDestinationObjectId.v1\0" ||
  publication_transaction_id || uint64_be(destination_ordinal) ||
  destination_digest)

Digest(Arch004CapacityStagedDestinationCopyV1) = SHA-256(
  "FlowProbe.Arch004.CapacityStagedDestinationCopy.v1\0" ||
  deterministic_cbor(staged_destination_copy))

Digest(Arch004CapacityPriorStatePublicationAttestationV1) = SHA-256(
  "FlowProbe.Arch004.CapacityPriorStatePublicationAttestation.v1\0" ||
  deterministic_cbor(prior_state_publication_attestation))

Digest(Arch004CapacityBatchValidationStateV1) = SHA-256(
  "FlowProbe.Arch004.CapacityBatchValidationState.v1\0" ||
  deterministic_cbor(batch_validation_state))

Arch004CapacityBatchValidationCapsuleV1.
  predecessor_state_attestation_set_root = SHA-256(
    "FlowProbe.Arch004.CapacityPriorStatePublicationAttestations.v1\0" ||
    deterministic_cbor(predecessor_state_attestations))

Arch004CapacityBatchValidationCapsuleV1.validation_root = SHA-256(
  "FlowProbe.Arch004.CapacityBatchValidationMembers.v1\0" ||
  deterministic_cbor({ receipt, receipt_digest,
    candidate_publication_set_digest, operation_id,
    publishing_transition_digest, common_expected_old_head,
    common_expected_old_head_digest, common_before_snapshot,
    common_before_snapshot_digest, common_after_snapshot,
    common_after_snapshot_digest, candidate_states, candidate_state_count,
    candidate_state_projection_root, candidate_predecessor_state_proof_root,
    predecessor_state_attestations,
    predecessor_state_attestation_count,
    predecessor_state_attestation_set_root, publication_preimage,
    generic_release_cause_preimage }))

Digest(Arch004CapacityBatchValidationCapsuleV1) = SHA-256(
  "FlowProbe.Arch004.CapacityBatchValidationCapsule.v1\0" ||
  deterministic_cbor(batch_validation_capsule))

Digest(Arch004CapacityDestinationPublicationCertificateV1) = SHA-256(
  "FlowProbe.Arch004.CapacityDestinationPublicationCertificate.v1\0" ||
  deterministic_cbor(destination_publication_certificate))

Digest(Arch004CapacityPublishedDestinationIndirectionV1) = SHA-256(
  "FlowProbe.Arch004.CapacityPublishedDestinationIndirection.v1\0" ||
  deterministic_cbor(published_destination_indirection))

Digest(Arch004CapacityDestinationActivationReceiptV1) = SHA-256(
  "FlowProbe.Arch004.CapacityDestinationActivationReceipt.v1\0" ||
  deterministic_cbor(destination_activation_receipt))

Digest(Arch004CapacityPublishedDestinationPreparedIndexRegionV1) = SHA-256(
  "FlowProbe.Arch004.CapacityPublishedDestinationPreparedIndexRegion.v1\0" ||
  deterministic_cbor(prepared_index_region))

Digest(Arch004CapacityPublishedDestinationActivationSuffixV1) = SHA-256(
  "FlowProbe.Arch004.CapacityPublishedDestinationActivationSuffix.v1\0" ||
  deterministic_cbor(activation_suffix))

Digest(Arch004CapacityPublishedDestinationIndexEntryV1) = SHA-256(
  "FlowProbe.Arch004.CapacityPublishedDestinationIndexEntry.v1\0" ||
  deterministic_cbor(published_destination_index_entry))

Arch004CapacityReceiptPublicationBatchMarkerV1.
  public_indirection_set_root = SHA-256(
    "FlowProbe.Arch004.CapacityPublishedDestinationIndirections.v1\0" ||
    deterministic_cbor(public_indirections))

Digest(Arch004CapacityReceiptPublicationBatchMarkerV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReceiptPublicationBatchMarker.v1\0" ||
  deterministic_cbor(publication_batch_marker))

Digest(Arch004CapacityReceiptPublicationBatchMarkerStorePayloadV1) =
  SHA-256(
    "FlowProbe.Arch004.CapacityReceiptPublicationBatchMarkerStorePayload.v1\0" ||
    deterministic_cbor(publication_batch_marker_store_payload))

Digest(Arch004CapacityReceiptPublicationBatchMarkerStoreSlotV1) = SHA-256(
  "FlowProbe.Arch004.CapacityReceiptPublicationBatchMarkerStoreSlot.v1\0" ||
  deterministic_cbor(publication_batch_marker_store_slot))

Digest(Arch004CapacityJointCowCurrentEntryV1) = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowCurrentEntry.v1\0" ||
  deterministic_cbor(current_entry))

Digest(Arch004CapacityJointCowParticipantV1) = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowParticipant.v1\0" ||
  deterministic_cbor(participant))

Arch004CapacityJointCowParticipantV1.old_target_raw_frame_digest = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowFixedTargetRawFrame.v1\0" ||
  installation_id || ledger_id || sequence_domain_id ||
  deterministic_cbor(kind) || deterministic_cbor(target_physical_slot) ||
  uint64_be(raw_target_frame.len) || raw_target_frame)

For every non-genesis checkpoint, Arch004CapacityJointCowCheckpointBodyV1.
  replaced_wal_slot_raw_frame_digest = SHA-256(
    "FlowProbe.Arch004.CapacityJointCowWalTargetRawFrame.v1\0" ||
    installation_id || ledger_id || sequence_domain_id ||
    deterministic_cbor(wal_slot) || uint64_be(raw_wal_slot_frame.len) ||
    raw_wal_slot_frame)

Arch004CapacityJointCowCheckpointBodyV1.participant_set_root = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowParticipants.v1\0" ||
  deterministic_cbor(participants))

Arch004CapacityJointCowCheckpointBodyV1.base_fixed_participant_root = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowBaseParticipants.v1\0" ||
  deterministic_cbor(base_fixed_participants))

Arch004CapacityJointCowCheckpointBodyV1.replay_fixed_participant_root = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowReplayParticipants.v1\0" ||
  deterministic_cbor(replay_fixed_participants))

Arch004CapacityJointCowCheckpointBodyV1.
  public_indirection_participant_root = SHA-256(
    "FlowProbe.Arch004.CapacityJointCowPublicIndirections.v1\0" ||
    deterministic_cbor(public_indirection_participants))

Arch004CapacityJointCowCheckpointBodyV1.resulting_current_tuple_root = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowCurrentTuple.v1\0" ||
  deterministic_cbor(resulting_current_tuple))

Arch004CapacityJointCowWalTransactionIdV1 = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowTransactionId.v1\0" ||
  deterministic_cbor({ installation_id, ledger_id, sequence_domain_id,
    wal_revision, predecessor_committed_checkpoint_digest,
    wal_attempt_nonce }))

Digest(Arch004CapacityJointCowCheckpointBodyV1) = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowCheckpointBody.v1\0" ||
  deterministic_cbor(checkpoint_body))

Digest(Arch004CapacityJointCowPrepareMarkerV1) = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowPrepareMarker.v1\0" ||
  deterministic_cbor(prepare_marker))

Arch004CapacityJointCowTargetWriteCapabilityIdV1 = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowTargetWriteCapability.v1\0" ||
  Digest(Arch004CapacityJointCowCheckpointBodyV1) ||
  Digest(Arch004CapacityJointCowPrepareMarkerV1))

Digest(Arch004CapacityJointCowAbortMarkerV1) = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowAbortMarker.v1\0" ||
  deterministic_cbor(abort_marker))

Arch004CapacityJointCowAbortCleanupCapabilityIdV1 = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowAbortCleanupCapability.v1\0" ||
  Digest(Arch004CapacityJointCowCheckpointBodyV1) ||
  Digest(Arch004CapacityJointCowPrepareMarkerV1) ||
  Digest(Arch004CapacityJointCowAbortMarkerV1))

Digest(Arch004CapacityJointCowCommitMarkerV1) = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowCommitMarker.v1\0" ||
  deterministic_cbor(commit_marker))

Digest(Arch004CapacityJointCowFinalDecisionV1) = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowFinalDecision.v1\0" ||
  deterministic_cbor(final_decision))

Digest(Arch004CapacityCommittedJointCowCheckpointV1) = SHA-256(
  "FlowProbe.Arch004.CapacityCommittedJointCowCheckpoint.v1\0" ||
  deterministic_cbor(committed_checkpoint))

Digest(Arch004CapacityJointCowWalStoreSlotV1) = SHA-256(
  "FlowProbe.Arch004.CapacityJointCowWalStoreSlot.v1\0" ||
  deterministic_cbor(joint_cow_wal_store_slot))

Arch004CapacityReleaseReplayCapsuleV1.replay_response_root = SHA-256(
  "FlowProbe.Arch004.CapacityReleaseReplayResponse.v1\0" ||
  deterministic_cbor({ replay_request, replay_request_digest,
    released_state_proof, released_state_proof_digest }))

Arch004CapacityOperationOwnerEpochRegistrySnapshotV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    CapacityReplayOwnerEpochObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor(["RegistrySnapshot", authority_context_digest,
    owner_epoch_key, ledger_id, sequence_domain_id, revision, event_store_id,
    event_store_store_slot_max_accounted_bytes,
    transport_registry_identity_digest,
    channel_key_store_identity_digest, registrations, registration_count,
    registration_set_root, frozen_at]))

Arch004CapacityOperationOwnerEpochChannelEventObservationV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    CapacityReplayOwnerEpochObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor(["ChannelEvent", event_record,
    event_record_digest, resulting_event_store_revision,
    resulting_event_store_digest, authority_context_digest]))

Arch004CapacityOperationOwnerEpochHistoricalClosureReadbackV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    CapacityReplayOwnerEpochObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor(["HistoricalClosureReadback",
    authority_context_digest, registry_snapshot_digest, registration,
    registration_digest, channel_key, accepting_lease_expires_at,
    expected_transport_handle_digest, transport_registry_head,
    transport_registry_head_digest, expected_channel_key_identity_digest,
    channel_key_store_head, channel_key_store_head_digest, observed_at]))

Arch004CapacityOperationOwnerEpochTerminalV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    CapacityReplayOwnerEpochObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor(["OwnerEpochTerminal", candidate,
    candidate_digest, signing_context_digest]))

Arch004CapacityOperationRequestOwnerUnreachabilityV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    CapacityReplayOwnerEpochObservation) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor(["OwnerUnreachability", replay_request_digest,
    registry_snapshot, registry_snapshot_digest, closure_census,
    closure_census_digest, owner_epoch_terminal,
    owner_epoch_terminal_digest, terminal_authority_context_digest,
    observed_at]))

Arch004CapacityPostCasCommitReceiptV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    CapacityPostCasCommitReceipt) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor([
    observation_context_digest, durable_commit_record,
    durable_commit_record_digest, published_states, published_state_count,
    published_state_set_root, committed_at
  ]))

Arch004CapacityDestinationPublicationCertificateV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    CapacityDestinationPublicationCertificate) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor([
    observation_context_digest, publication_transaction_id, head_slot,
    head_slot_generation, activation_wal_revision,
    activation_wal_transaction_id, durable_commit_record_digest, receipt_digest,
    publication_batch_digest, destination_ordinal, destination_digest,
    staged_copy_digest, destination_projection,
    destination_projection_digest, destination_count, destination_set_root,
    staged_copy_set_root, validation_capsule, validation_capsule_digest
  ]))

Arch004CapacityDestinationActivationReceiptV1.signature_input =
  "FlowProbe.Arch004.ExternalObservation.v1\0" ||
  uint16_be(Arch004ExternalObservationRootSchemaTagV1::
    CapacityDestinationActivationReceipt) || uint16_be(1) ||
  canonical_cbor(authenticator.header) ||
  SHA-256(canonical_cbor([
    observation_context_digest, activation_wal_revision,
    activation_wal_transaction_id, activation_committed_checkpoint_digest,
    activation_checkpoint_body_digest, activation_commit_marker_digest,
    publication_transaction_id, destination_ordinal,
    public_storage_location_id, prepared_index_region_digest,
    public_indirection_digest, publication_certificate_digest, activated_at
  ]))
```

Each digest field itself is excluded from its own body. Plans bind expected
observation schemas, predicates, limits, and actor/resource identities, never a
future observation result. Post-seal results are authenticated; results used as
durable resource state are journaled under the existing ARCH-001/002 ordering,
while transient capability status carries the complete signed matrix body
inline and never persists a naked digest. They are not fed back into the plan
digest.

Durations and ordering use one declared suspend-aware monotonic clock domain.
Wall time MAY be included for display only when its source and uncertainty are
explicit. Latency is calculated only from samples in the same monotonic domain
and boot/suspend epoch. A clock discontinuity closes affected observations and
invalidates health; it never produces a negative duration.

## 4. Datagram flow identity

```text
DatagramDirectionV1 =
  | ApplicationToNetwork
  | NetworkToApplication

RawDatagramDirectionObservationV1 =
  | DirectionObserved { direction: DatagramDirectionV1 }
  | DirectionUnavailable { reason: UdpUnavailableReasonV1 }

AddressFamilyV1 = Ipv4 | Ipv6

EndpointV1 = {
  family: AddressFamilyV1,
  address: IpAddress,
  port: U16,
  zone?: BoundedZoneId,
}

EndpointIdentityProjectionV1(endpoint: EndpointV1) = EndpointIdentityV1 {
  normalized_host:
    endpoint.family == Ipv4
      ? Host::Ipv4 { octets: endpoint.address.exact_ipv4_octets }
      : Host::Ipv6 {
          octets: endpoint.address.exact_ipv6_octets,
          scope_id: endpoint.zone,
        },
  port: endpoint.port,
}

OriginalDestinationV1 =
  | ObservedOriginal {
      endpoint: EndpointV1,
      mechanism: ClosedOriginalDestinationMechanism,
      mechanism_version: BoundedVersion,
      observation_ref: OriginalDestinationEvidenceRefV1,
    }
  | InferredOriginal {
      endpoint: EndpointV1,
      inference_rule:
        Exact(Arch004InferenceRuleV1::EndpointRoleFromAuthenticatedFlow),
      inputs_ref: DatagramBoundaryEvidenceRefV1,
      confidence: ClosedConfidence,
    }
  | OriginalDestinationUnavailable { reason: UdpUnavailableReasonV1 }

UdpPathResourceIdentityV1 = {
  resource_kind: ExactAscii("transport.udp.path.v1"),
  schema_version: 1,
  stable_identity: UdpPathStableIdentityV1,
  installation_id: InstallationId,
  session_id: SessionId,
  generation: Generation,
}

ExactUdp = Exact(UDP)
ExactRuntimeDestinationUdp = Exact(PathPurpose::RuntimeDestinationUdp)
ExactOwnedActorAllExternalEndpoints =
  PathEndpointBindingV1::OwnedActorAllExternalEndpoints {
    actor_socket_factory_policy_digest:
      Digest(ActorSocketFactoryPolicyV1),
  }

Arch004UdpPathBindingV1 =
  | DirectRuntimeDestination {
      binding_id: FreshBytes32,
      udp_path_resource_identity: UdpPathResourceIdentityV1,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      dormant_declaration_actor_graph_digest: Digest(EgressActorGraphV1),
      dormant_declaration_key: {
        actor_id: EgressActorV1.actor_id,
        socket_factory_policy_digest: Digest(ActorSocketFactoryPolicyV1),
        family: AddressFamilyV1,
        transport: ExactUdp,
        path_purpose: ExactRuntimeDestinationUdp,
        endpoint_binding: ExactOwnedActorAllExternalEndpoints,
      },
      selected_endpoint_identity_digest: Digest(EndpointIdentityV1),
      tentative_socket_child_observation_digest:
        Digest(SocketPolicyChildObservationV1),
      route_and_interface_observation_ref: EgressPathProofEvidenceRefV1,
      no_send_latch: Closed,
      publication_deadline: SuspendAwareDeadline,
    }
  | Socks5UdpRelay {
      binding_id: FreshBytes32,
      udp_path_resource_identity: UdpPathResourceIdentityV1,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      association_observation_digest:
        Digest(Socks5UdpAssociationObservationV1),
      operational_socket_child_observation_digest:
        Digest(SocketPolicyChildObservationV1),
      selected_relay_endpoint_identity_digest: Digest(EndpointIdentityV1),
      publication_deadline: SuspendAwareDeadline,
    }

DatagramFlowIdentityV1 = {
  flow_id: DatagramFlowId,
  observation_epoch: DatagramObservationEpoch,
  capture_session_id?: CaptureSessionId,
  runtime_instance_id: RuntimeInstanceId,
  family: AddressFamilyV1,
  application_endpoint: EndpointV1,
  network_endpoint: EndpointV1,
  original_destination: OriginalDestinationV1,
  network_scope: NetworkScope,
  egress_selection_safe_digest: Digest(SafeEgressSelectionV1),
  udp_path_resource_identity: UdpPathResourceIdentityV1,
  udp_path_binding_digest: Digest(Arch004UdpPathBindingV1),
  operational_socket_child_observation_digest:
    Digest(SocketPolicyChildObservationV1),
  socks5_association_observation_digest?:
    Digest(Socks5UdpAssociationObservationV1),
}
```

The egress digest is byte-for-byte the tag-1 digest required by accepted
ARCH-002 and the network scope is the exact accepted `NetworkScope`. The socket
child digest resolves to the exact operational UDP socket whose actor, purpose,
family, endpoint binding, mechanism, factory epoch, route/interface evidence,
and selected egress equal this flow and its sealed plan. The optional SOCKS5
digest is present if and only if the safe selection is
`ExternalSocks5(RequireAssociate)`; it resolves to the current accepted
`Socks5UdpAssociationObservationV1` root and its operational UDP child is the
same child named above. `Direct` omits it. A private path handle, connection
pointer, relay label, or second digest alias has no contract encoding.

`flow_id` is allocated before publishing the first metadata event. A tuple does
not survive an idle close, hard-lifetime close, runtime restart, plan change,
lease change, NAT rebinding, interface/default-route epoch change, selected
egress change, relay change, or original-destination provenance change. The
next datagram receives a new flow ID.

Endpoint normalization preserves IPv4 versus IPv4-mapped IPv6 distinction
unless the observing API explicitly supplies a canonical mapping. A zero UDP
source port is representable and does not by itself make a datagram malformed.
IPv6 link-local endpoints require a bounded zone identity when the platform
requires one; an absent required zone makes the destination unavailable.

An inferred destination MUST NOT satisfy a policy or release gate that requires
observed original-destination evidence.

## 5. Flow metadata and lifecycle

```text
DatagramDirectionCountersV1 =
  | EmptyObserved {
      datagrams: { value: ExactU64(0), overflowed: false },
      payload_bytes: { value: ExactU64(0), overflowed: false },
      observed_wire_bytes?: { value: ExactU64(0), overflowed: false },
      observation_source: ClosedCounterObservationSource,
      occurrence_accumulator_digest: Digest,
    }
  | NonEmptyObserved {
      datagrams: { value: PositiveU64, overflowed: false },
      payload_bytes: { value: U64, overflowed: false },
      observed_wire_bytes?: { value: U64, overflowed: false },
      observation_source: ClosedCounterObservationSource,
      last_direction_ordinal: U64,
      occurrence_accumulator_digest: Digest,
    }
  | CountersUnavailable { reason: UdpUnavailableReasonV1 }

ProcessProvenanceV1 =
  | ProcessObserved {
      platform_identity: ClosedPlatformProcessIdentity,
      mechanism: ClosedProcessObservationMechanism,
      observed_at: MonotonicInstant,
      evidence_ref: ProcessIdentityEvidenceRefV1,
    }
  | ProcessInferred {
      bounded_display_identity?: BoundedProcessLabel,
      inference_rule:
        Exact(Arch004InferenceRuleV1::ProcessFromExclusiveSocketOwner),
      confidence: ClosedConfidence,
      inputs_ref: ExclusiveSocketOwnerEvidenceRefV1,
    }
  | ProcessUnavailable { reason: UdpUnavailableReasonV1 }

DatagramContentStateV1 =
  | MetadataOnly
  | Opaque { reason: UdpOpaqueReasonV1 }
  | Unavailable { reason: UdpUnavailableReasonV1 }

DatagramCounterBoundaryV1 = {
  outbound_source: ClosedCounterObservationSource,
  inbound_source: ClosedCounterObservationSource,
  occurrence_identity_owner: EgressActorV1.actor_id,
  boundary_version: BoundedVersion,
}

DatagramOccurrenceV1 = {
  occurrence_id: DatagramOccurrenceId,
  flow_id: DatagramFlowId,
  direction: DatagramDirectionV1,
  direction_ordinal: U64,
  flow_ordinal: U64,
  observation_source: ClosedCounterObservationSource,
  payload_bytes: BoundedU32,
  observed_wire_bytes?: BoundedU32,
  fragment_observation: DatagramFragmentObservationV1,
  observed_at: MonotonicInstant,
  observation_ref: DatagramBoundaryEvidenceRefV1,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

RawDatagramFragmentMetadataV1 = {
  fragment_observation_id: Bytes32,
  reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  family: AddressFamilyV1,
  direction: RawDatagramDirectionObservationV1,
  observed_length: BoundedU32,
  fragment_offset?: BoundedU32,
  more_fragments?: Bool,
  observed_at: MonotonicInstant,
  observation_ref: RawFragmentBoundaryEvidenceRefV1,
}

DatagramFlowStateV1 =
  | Active
  | Closed {
      ended_at: MonotonicInstant,
      close_reason: DatagramCloseReasonV1,
    }

DatagramFlowV1 = {
  identity: DatagramFlowIdentityV1,
  revision: U64,
  predecessor_digest?: Digest(DatagramFlowV1),
  reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  process: ProcessProvenanceV1,
  outbound: DatagramDirectionCountersV1,
  inbound: DatagramDirectionCountersV1,
  counter_boundary: DatagramCounterBoundaryV1,
  first_observed_at: MonotonicInstant,
  last_observed_at: MonotonicInstant,
  idle_timeout: PositiveBoundedDuration,
  hard_lifetime: PositiveBoundedDuration,
  content: DatagramContentStateV1,
  fragment_aggregate: DatagramFragmentAggregateV1,
  state: DatagramFlowStateV1,
  extension_version: 1,
}
```

Observed counters use UDP application payload bytes. `observed_wire_bytes`
is optional and cannot be synthesized from payload length when IP extension
headers, fragments, encapsulation, or platform APIs make it unknown. Checked
counter overflow closes metadata collection with `CounterLimitReached`; it MUST
NOT wrap or saturate silently.

Flow records are immutable append-only revisions, not mutable snapshots. The
digest is exactly
`SHA-256("FlowProbe.DatagramFlow.v1\0" || deterministic_cbor(record))`.
`Digest(DatagramOccurrenceV1)` is exactly
`SHA-256("FlowProbe.DatagramOccurrence.v1\0" ||
deterministic_cbor(occurrence))`.
`Digest(RawDatagramFragmentMetadataV1)` is exactly
`SHA-256("FlowProbe.RawDatagramFragmentMetadata.v1\0" ||
deterministic_cbor(raw_fragment_metadata))`.

Before the occurrence digest is computed, its registered DatagramObserver
authenticator verifies exactly:

```text
"FlowProbe.Arch004.ExternalObservation.v1\0" ||
uint16_be(Arch004ExternalObservationRootSchemaTagV1::DatagramOccurrence) ||
uint16_be(1) ||
canonical_cbor(authenticator.header) ||
SHA-256(canonical_cbor([
  occurrence_id,
  flow_id,
  direction,
  direction_ordinal,
  flow_ordinal,
  observation_source,
  payload_bytes,
  observed_wire_bytes,
  fragment_observation,
  observed_at,
  observation_ref,
]))
```

This is the complete `DatagramOccurrenceV1` projection with only its own
`authenticator` field omitted. The observation ref already commits the exact
context, stream, ordinal, boundary body and its independent signature. Thus
neither signature is in its own preimage, while flow/direction ordinals,
source, byte counts, fragment state and boundary evidence cannot be swapped
under a valid occurrence signature.
The signer role is exactly `CaptureCore`; its accepted `ExternalExecutorGate`,
executor/component identity, gate channel, key, plan/generation, lease/fence,
and observation context are byte-identical
to the resolved `DatagramBoundaryReadback` and its `DatagramObserver` context.
A second valid Capture Core key, another boundary component, or an external-
executor header from the same plan cannot authenticate the occurrence.
Revision zero is `Active` and has no predecessor. Every successor has revision
exactly one greater, names the exact predecessor digest, and preserves the complete
identity, plan/fence bindings, process provenance, counter boundary, timeouts,
content grade. First/last times, each available counter, and every fragment-
aggregate count are monotonically nondecreasing, and `first_observed_at <=
last_observed_at`. The only state transitions are `Active -> Active` and
`Active -> Closed`. A `Closed` revision additionally requires `ended_at >=
last_observed_at` and is absorbing: it has no successor. Only the highest valid
descendant of a chain is current. A delayed ancestor, competing fork, lower
counter, missing predecessor, or `Closed -> Active` transition is invalid and
cannot overwrite or resurrect a flow.

The flow owner compare-and-appends against the exact current predecessor. A
racing datagram update and close produce exactly one successor; if close wins,
the later datagram starts a new flow ID rather than forking or reopening the old
chain.

The plan selects exactly one authoritative complete-datagram observation
boundary for each direction. Each accepted datagram receives one fresh
`DatagramOccurrenceId` from that boundary and contributes exactly once to its
direction's counters. TUN, runtime, socket-factory, and passive decoder
observations of the same occurrence are supporting evidence, not additional
counter events. A second source, occurrence-ID reuse, or cross-plane duplicate
is rejected; the implementation may deduplicate only by the exact authenticated
occurrence identity and cannot guess equality from tuple, length, payload hash,
or time.

For each direction, authenticated `direction_ordinal` values start at zero,
advance by exactly one, use the source fixed by `DatagramCounterBoundaryV1`, and start from
`SHA-256("FlowProbe.DatagramOccurrenceAccumulatorSeed.v1\0" ||
deterministic_cbor({flow_id, direction, counter_boundary}))`. Each occurrence
then forms `SHA-256("FlowProbe.DatagramOccurrenceAccumulator.v1\0" ||
prior_digest || Digest(DatagramOccurrenceV1))`. Before a direction's first
occurrence, `EmptyObserved` carries zero values and exactly that seed digest.
Afterward `NonEmptyObserved.datagrams == last_direction_ordinal + 1` and equals
the checked fold through its named ordinal/digest; its observation source equals
the applicable boundary source. Missing, repeated, out-of-order, differently
sourced, or unauthenticated occurrences cannot advance the counters. An
unavailable counter stays unavailable for the chain rather than later adopting
an unrelated source.

Fragment interpretation is per occurrence rather than a frozen flow scalar.
The aggregate starts at
`SHA-256("FlowProbe.DatagramFragmentAccumulatorSeed.v1\0" || flow_id)` and
folds each occurrence in ordinal order as
`SHA-256("FlowProbe.DatagramFragmentAccumulator.v1\0" || prior_digest ||
flow_ordinal || deterministic_cbor(fragment_observation))`. `flow_ordinal` is a
separate all-direction sequence starting at zero and advancing by one for every
accepted occurrence; it never aliases a per-direction ordinal. The aggregate's
three checked counts and last flow ordinal equal that fold exactly. A flow may therefore
observe complete datagrams with different fragment provenance over time without
rewriting an earlier fact. A raw incomplete IP fragment remains outside the
flow/occurrence chain.

```text
DatagramFragmentObservationV1 =
  | NotFragmentedObserved
  | FragmentedOpaque {
      family: AddressFamilyV1,
      reason: ClosedFragmentReasonV1,
    }
  | FragmentStateUnavailable { reason: UdpUnavailableReasonV1 }

DatagramFragmentAggregateV1 = {
  not_fragmented_observed_count: U64,
  fragmented_opaque_count: U64,
  fragment_state_unavailable_count: U64,
  last_flow_ordinal: U64,
  fragment_accumulator_digest: Digest,
}

DatagramCloseReasonV1 =
  | IdleTimeout
  | HardLifetimeReached
  | ApplicationClosed
  | RuntimeClosed
  | PathInvalidated
  | EgressChanged
  | RelayLost
  | InterfaceEpochChanged
  | CounterLimitReached
  | ResourcePressure
  | PolicyBlocked
  | SessionStopping
  | SessionRollback
  | ObservationLost
```

The baseline performs no fragment reassembly. A `DatagramFlowV1` is created only
at a boundary that supplies a complete UDP datagram and its endpoint tuple. A
raw IP fragment that lacks the complete UDP header/datagram MUST NOT be assigned
to a guessed flow or count. It may produce bounded L0 opaque-fragment metadata
as `RawDatagramFragmentMetadataV1`, and no invented ports or original
destination. Direction is always known for a flow occurrence; a raw non-flow
fragment instead uses the explicit `DirectionUnavailable` variant when its
boundary cannot establish direction. A DNS decoder cannot
claim a complete message unless a supported upstream boundary supplied that
complete message. Reordering and loss change observed counts/correlation only;
they do not retroactively mutate flow identity.

`fragment_observation_id` is fresh, is the storage/current key for one raw
fragment record, and equals the ID in its `RawFragmentBoundaryReadback` leaf.
Cross-fragment evidence substitution is invalid even when every other bounded
field and context happens to match.

## 6. Bounded metadata

The release manifest defines this closed finite-positive limit set:

```text
PositiveSuspendAwareNanosecondsV1 = {
  nanoseconds: Integer<1..=18446744073709551615>,
  clock_domain: ExactAscii("ARCH001.SuspendAwareMonotonic"),
}

UdpDnsLimitSetV1 = {
  max_active_datagram_flows: PositiveU64,
  max_datagram_flows_per_session: PositiveU64,
  max_metadata_events_per_second: PositiveU64,
  max_metadata_bytes_per_flow: PositiveU64,
  max_aggregate_udp_metadata_bytes: PositiveU64,
  max_aggregate_dns_metadata_bytes: PositiveU64,
  max_flow_idle_timeout: PositiveSuspendAwareNanosecondsV1,
  max_flow_hard_lifetime: PositiveSuspendAwareNanosecondsV1,
  max_outstanding_dns_transactions: PositiveU64,
  max_dns_message_bytes: Integer<1..=65535>,
  max_dns_questions: PositiveBoundedU16,
  max_dns_name_wire_octets: Integer<1..=255>,
  max_active_dns_stream_connections: PositiveU64,
  max_dns_stream_buffer_bytes_per_connection: PositiveU64,
  max_aggregate_dns_stream_buffer_bytes: PositiveU64,
  max_active_doh_http_transactions: PositiveU64,
  max_dns_decoder_work_units_per_message: PositiveU64,
  max_dns_correlation_lifetime: PositiveSuspendAwareNanosecondsV1,
  max_dns_retransmission_links: PositiveBoundedU16,
  max_resolver_bootstrap_depth: PositiveBoundedU8,
  max_bounded_reason_bytes: PositiveBoundedU32,
  max_active_capacity_reservations: PositiveU64,
  max_aggregate_resource_journal_bytes: PositiveU64,
}
```

`UdpDnsLimitSetV1` uses exactly the displayed field order and no others. Every
count, byte, rate, work, and depth value is an unsigned integer in its displayed
range; the only durations are canonical unsigned nanoseconds in the declared
suspend-aware clock domain. Its digest is
`SHA-256("FlowProbe.UdpDns.LimitSet.v1\0" ||
deterministic_cbor(UdpDnsLimitSetV1))`.

The plan selects values no greater than the release maxima and commits the
complete limit set plus implementation build. Zero, negative, infinite,
unversioned, or omitted limits are invalid.

The 23 fields map position-for-position to `Arch004LimitDimensionV1` in section
15. A dimension reorder, alias unit, wider integer, unknown field, or duration
from another clock domain changes or invalidates the canonical body; no producer
may normalize it after plan seal.

The DNS wire-name limit MUST be no greater than the RFC limit, and the complete
message limit MUST fit the supported transport framing. The decoder applies its
work-unit limit to compression-pointer traversal, label traversal, questions,
and section skipping so a small cyclic or adversarial message cannot consume
unbounded CPU.

Limit admission and release are atomic across per-object and aggregate counters.
Before creating a flow, transaction, DNS stream connection, DoH transaction, or
growing a stream buffer, the owner reserves both the exact per-object amount
and its aggregate bytes/count. It rolls back the complete reservation on any
failure. A connection/buffer object with no retained semantic successor releases
exactly once after its typed terminal/unreachability proof; a flow or DNS
transaction terminal atomically transfers the charge to the corresponding
retained-metadata subject and only that subject's later unreachability proof may
release it. A failed reservation
creates no partial record and reads no additional unbounded body. Per-connection
limits therefore cannot be multiplied by opening unbounded TCP, DoT, DoH, or
DoQ connections. Resource pressure MAY turn plaintext DNS decoding into
`DecodeOpaque(BoundedDecoderResultUnavailable)` while policy-safe forwarding
continues. It MUST NOT
create an ambient direct path or bypass socket admission.

Aggregate metadata charges include every retained revision, occurrence index,
lineage edge, correlation commitment/table entry, queue item, and bounded index
overhead under one release-audited accounting function. Moving an object from
live memory to a queue or persisted staging area does not release its charge
until the previous representation is atomically removed; compression or
allocator luck cannot be used to admit beyond the sealed worst-case charge.

## 7. UDP forwarding policy

```text
UdpRequestPolicyV1 =
  | UseSelectedEgress
  | Block
  | AuthorizedDirectFallback {
      authorization_receipt: DirectFallbackAuthorizationReceiptV1,
      authorization_scope: DirectFallbackAuthorizationScopeV1,
      original_egress_selection_safe_digest:
        Digest(SafeEgressSelectionV1),
      direct_egress_selection_safe_digest:
        Digest(SafeEgressSelectionV1),
    }
```

The authorization vocabulary is closed:

```text
DirectFallbackReceiptIssuerKindV1 =
  | TrustedProductPolicyBroker
  | InstalledAdministratorPolicy

DirectFallbackReceiptIssuerIdentityV1 = {
  issuer_kind: DirectFallbackReceiptIssuerKindV1,
  issuer_keyset_id: Bytes32,
  issuer_key_id: Bytes32,
  issuer_keyset_version: BoundedVersion,
  ed25519_public_key_32: Bytes32,
  installation_id: InstallationId,
  policy_broker_scope_id: Bytes32,
  policy_broker_scope_version: BoundedVersion,
}

DirectFallbackDestinationScopeV1 =
  | ExactEndpointIdentity {
      endpoint_identity_digest: Digest(EndpointIdentityV1),
    }
  | ExactEndpointIdentitySet {
      endpoint_identity_digests:
        SortedUniqueVector<Digest(EndpointIdentityV1), 1..=32>,
    }

DirectFallbackProcessScopeV1 =
  | ExactObservedProcess {
      platform_identity: ClosedPlatformProcessIdentity,
    }
  | ExactApplicationActor {
      actor_id: EgressActorV1.actor_id,
    }

DirectFallbackAuthorizationSubjectV1 = {
  installation_id: InstallationId,
  preparation_ticket_id: PreparationTicketId,
  session_id: SessionId,
  generation: Generation,
  exact_network_scope: NetworkScope,
  original_egress_selection_safe_digest:
    Digest(SafeEgressSelectionV1),
  direct_egress_selection_subject: SafeEgressSelectionV1::Direct,
  destination_scope: DirectFallbackDestinationScopeV1,
  family_scope: SortedUniqueNonEmptyVector<AddressFamilyV1>,
  application_process_scope: DirectFallbackProcessScopeV1,
  policy_text_version: BoundedVersion,
  boot_epoch: BootEpoch,
  suspend_epoch: SuspendEpoch,
}

DirectFallbackAuthorizationScopeV1 = {
  subject_digest: Digest(DirectFallbackAuthorizationSubjectV1),
  policy_broker_challenge: FreshBytes32,
  continuous_deadline: SuspendAwareDeadline,
}

DirectFallbackAuthorizationReceiptV1 = {
  issuer_kind: DirectFallbackReceiptIssuerKindV1,
  issuer_identity_digest: Digest(DirectFallbackReceiptIssuerIdentityV1),
  receipt_id: FreshBytes32,
  decision_nonce: FreshBytes32,
  installation_id: InstallationId,
  preparation_ticket_id: PreparationTicketId,
  session_id: SessionId,
  generation: Generation,
  exact_authorization_scope_digest:
    Digest(DirectFallbackAuthorizationScopeV1),
  boot_epoch: BootEpoch,
  suspend_epoch: SuspendEpoch,
  issued_at: MonotonicInstant,
  continuous_expires_at: SuspendAwareDeadline,
  signature: Ed25519Signature64,
}

DirectFallbackAuthorizationConsumptionV1 = {
  receipt_digest: Digest(DirectFallbackAuthorizationReceiptV1),
  authorization_scope_digest: Digest(DirectFallbackAuthorizationScopeV1),
  issuer_identity_digest: Digest(DirectFallbackReceiptIssuerIdentityV1),
  receipt_id: FreshBytes32,
  decision_nonce: FreshBytes32,
  preparation_ticket_id: PreparationTicketId,
  session_id: SessionId,
  generation: Generation,
  candidate_plan_digest: CandidatePlanDigest,
  prepare_idempotency_key: PrepareIdempotencyKey,
  prepared_plan_id: PreparedPlanId,
  plan_digest: PlanDigest,
  journal_record_location: Arch001JournalLocation,
}
```

`direct_egress_selection_subject` fixes the exact accepted tag-1 `Direct`
variant and all of its resolver and timeout fields before authorization. The
final direct `SafeEgressSelectionV1` is constructed only after the receipt and
must reproduce that subject byte-for-byte; this receipt-free subject prevents
a digest cycle. The original and direct digests in `UdpRequestPolicyV1` must
equal their accepted tag-1 objects and the receipt scope. The direct digest
must decode to `Direct`; another tag is invalid.
Every admitted fallback flow's normalized destination identity, family, and
observed process or exact application actor must be a member of the signed
subject scope; inferred process identity cannot satisfy `ExactObservedProcess`.

The local canonical digests are exactly:

```text
Digest(DirectFallbackAuthorizationSubjectV1) =
  SHA-256("FlowProbe.Udp.DirectFallbackSubject.v1\0" ||
    deterministic_cbor(subject))
Digest(DirectFallbackAuthorizationScopeV1) =
  SHA-256("FlowProbe.Udp.DirectFallbackScope.v1\0" ||
    deterministic_cbor(scope))
Digest(DirectFallbackAuthorizationReceiptV1) =
  SHA-256("FlowProbe.Udp.DirectFallbackReceiptObject.v1\0" ||
    deterministic_cbor(receipt_including_signature))
Digest(DirectFallbackAuthorizationConsumptionV1) =
  SHA-256("FlowProbe.Udp.DirectFallbackConsumption.v1\0" ||
    deterministic_cbor(consumption))
```

The issuer identity is exactly
`SHA-256("FlowProbe.Udp.DirectFallbackIssuer.v1\0" ||
deterministic_cbor({issuer_kind, ed25519_public_key_32, installation_id,
issuer_keyset_id, issuer_key_id, issuer_keyset_version,
policy_broker_scope_id, policy_broker_scope_version}))`, using the compile-time
trusted product-policy-broker registry. The receipt signature is Ed25519 over
`"FlowProbe.Udp.DirectFallbackReceipt.v1\0" ||
deterministic_cbor(receipt_without_signature)`. Both Supervisor and helper
verify the registry identity, signature, fresh challenge/nonce, every duplicated
scope field, clock/boot/suspend epochs, and an expiry no later than five minutes
after issue. The scope's `continuous_deadline` equals the receipt's
`continuous_expires_at`; issue time is not after that deadline.
The broker's durable issuance key is `(policy_broker_challenge,
Digest(DirectFallbackAuthorizationScopeV1))`: an exact response-loss retry
returns the byte-identical receipt, while reuse of a challenge with another
scope is rejected.

During `PreparePlan`, the helper durably writes one consumption record for the
receipt/scope tuple in the same transaction as the final prepared identifiers.
The existing ARCH-001 helper journal envelope authenticates the displayed
consumption digest and location; no signature field is embedded back into its
own digest.
It binds the authority to exactly one candidate plan and resulting
`PreparedPlanId + PlanDigest`; its digest is post-plan evidence and never a plan
input. Only byte-identical response-loss replay under the same prepare
idempotency key returns the same result. Cross-plan, cross-ticket, expired,
copied, replayed, already-consumed, or differently scoped authority is rejected.

`AuthorizedDirectFallback` is a distinct user/admin request. A renderer value,
checkbox state, cached acknowledgement, copied digest, timeout, or failure
cannot mint the receipt. Missing or invalid authority selects
`DirectFallbackAuthorizationInvalid`; it never falls back to `UseSelectedEgress`
or ambient direct routing.

Every `Ready` disposition repeats the exact UDP resource identity, operational
path-binding digest, socket-child digest, and optional SOCKS5 association digest
used by the flow and sealed policy. The optional digest is present only for
`ExternalSocks5(RequireAssociate)` and byte-equals the association root; a
private path handle or a stale association cannot satisfy readiness.

The binding digest is exactly:

```text
Digest(Arch004UdpPathBindingV1) = SHA-256(
  "FlowProbe.Udp.PathBinding.v1\0" || deterministic_cbor(binding)
)
```

For `Direct`, only `DirectRuntimeDestination` is legal. The dormant declaration
key must resolve inside the named tag-8 actor graph to the same actor, factory,
family, UDP transport, `RuntimeDestinationUdp` purpose, and
`OwnedActorAllExternalEndpoints` exclusion scope. That broad endpoint scope is
preventive only; the operational destination comes exclusively from the exact
tag-33 selected endpoint in this binding. The tentative tag-31 child repeats
the same actor/factory/family/UDP/Direct selection and route/interface evidence.
It contains no digest of this outer binding.

After constructing the tentative child, the factory validates this one-way
binding while the socket remains behind the closed no-send latch. Its existing
ARCH-002 atomic publication transaction simultaneously publishes the child,
accepts this exact binding, commits sequence/count accounting, and hands off the
still-latched socket. Failure has none of those effects and sends zero bytes.
Only successful publication permits the first-byte guard to consume the
accepted binding and open the latch. Pre-publication validation failure,
publication failure, post-publication non-expiry consume failure, and expiry use
the four mutually exclusive ARCH-005 terminal reasons and append-only closure
evidence; no retry, ambient lookup, broad-scope endpoint authority, or child-to-
binding back-reference is allowed.

For `ExternalSocks5(RequireAssociate)`, only `Socks5UdpRelay` is legal and every
association, child, relay endpoint, context, and resource field must match.
HTTP/HTTPS, SOCKS5 disabled, blocked, unsupported, and policy-prohibited rows
publish no path binding.

The path mapping is closed:

| Selected egress | UDP result |
| --- | --- |
| `Direct` | Ready only with an exact direct UDP connector, physical-path proof, exclusion entry, factory admission, and current health |
| `ExternalHttp` | `Unsupported/HttpProxyUdpUnsupported` |
| `ExternalHttps` | `Unsupported/HttpsProxyUdpUnsupported` |
| `ExternalSocks5(Disable)` | `Unsupported/Socks5UdpDisabled` |
| `ExternalSocks5(RequireAssociate)` | Ready only through the exact live accepted association/relay and operational UDP child |

No CONNECT-UDP, HTTP/3 datagram, MASQUE, UDP-over-TCP, generic detour, ambient
system route, or direct datagram satisfies these rows. Adding one requires a new
tagged architecture contract.

If a policy-incompatible datagram arrives, FlowProbe returns the selected typed
failure or blocks it. It never relabels a direct send as proxy success, reports
a drop as forwarded, or changes policy after plan seal.

## 8. ARCH-002 exclusion and socket admission

Every FlowProbe-owned UDP or DNS network operation MUST be represented by an
ADR-0005 actor/path/purpose entry. This includes:

- direct UDP connectors;
- SOCKS5 role-B control and operational role-C relay children;
- protected runtime and registered platform-native DNS, bootstrap resolution,
  UDP/TCP/DoT/DoH/DoQ transports;
- DNS port-53 handler forwarding;
- Capture Core forwarding, health, proof, and recovery traffic; and
- helper/watchdog network traffic if any accepted backend declares it.

An operation opens a socket only through the accepted actor-wide socket factory
with current ordinary admission and the current ARCH-002 durable admission
release proof. It binds family, transport, purpose, resolver/target, selected
egress, path mechanism, and current resume barrier. A missing actor, transport,
family, purpose, resolver, or relay entry makes the exclusion set incomplete.

DNS bootstrap cannot recurse through the pending FlowProbe TUN or silently use
ambient direct DNS. A DNS dependency cycle is rejected during plan construction.

## 9. DNS transport and visibility matrix

```text
DnsTransportV1 =
  | PlainUdp
  | PlainTcp
  | Tls
  | Https
  | Quic

DnsHttpCarrierV1 =
  | Http1_1
  | Http2
  | Http3
  | HttpCarrierUnavailable

DnsDecodedHttpCarrierV1 =
  | Http1_1
  | Http2
  | Http3

DnsHttpsCarrierCoverageV1 =
  | NotHttps
  | HttpsObserved {
      carriers:
        SortedUniqueNonEmptyVector<DnsDecodedHttpCarrierV1, 1..=3>,
    }
  | HttpsCarrierUnavailable

DnsVisibilityMechanismV1 =
  | NativeConfigured
  | Port53Hijacked
  | MetadataObserved
  | EncryptedOpaque
  | Unavailable

DnsObservedVisibilityMechanismV1 =
  DnsVisibilityMechanismV1::{
    NativeConfigured | Port53Hijacked | MetadataObserved
  }

DnsCapabilityCellKeyV1 = {
  family: AddressFamilyV1,
  transport: DnsTransportV1,
}

Arch004PlatformSubjectV1 = {
  os: ClosedOperatingSystemV1,
  architecture: ClosedArchitectureV1,
  release: BoundedReleaseIdentity,
  package_build: BoundedBuildIdentity,
  backend: BoundedBackendIdentity,
  backend_version: BoundedVersion,
  runtime_build: BoundedBuildIdentity,
  decoder_build: BoundedBuildIdentity,
}

DnsCapabilityCellSpecV1 = {
  key: DnsCapabilityCellKeyV1,
  selected_mechanism: DnsVisibilityMechanismV1,
  network_scope: NetworkScope,
  resolver_scope: DnsCapabilityResolverScopeV1,
  expected_routing: ClaimDispositionV1,
  expected_interception: ClaimDispositionV1,
  expected_decoding: ClaimDispositionV1,
  expected_leak_prevention: ClaimDispositionV1,
  expected_original_destination: DnsAncillaryClaimDispositionV1,
  expected_process_provenance: DnsAncillaryClaimDispositionV1,
  expected_static_support: StaticSupport,
  expected_readiness: Readiness,
  expected_evidence: Evidence,
  platform_subject: Arch004PlatformSubjectV1,
  https_carrier_coverage: DnsHttpsCarrierCoverageV1,
}

DnsCapabilityTransportPathEvidenceV1 =
  | PlainUdpPath {
      udp_path_active_state: Arch004ActiveResourceEvidenceV1,
      udp_path_binding_digest: Digest(Arch004UdpPathBindingV1),
    }
  | StreamPath {
      transport: PlainTcp | Tls | Https | Quic,
      socket_child_observation_digest:
        Digest(SocketPolicyChildObservationV1),
      egress_path_proof_ref: EgressPathProofEvidenceRefV1,
    }
  | NativeSystemPath {
      transport: DnsTransportV1,
      route_readback_ref: ResourceReadbackEvidenceRefV1,
    }
  | PassiveObservedPath {
      transport: DnsTransportV1,
      host_association_evidence_ref: DnsHostAssociationEvidenceRefV1,
    }

DnsProcessCapabilityEvidenceRefV1 =
  ProcessIdentityEvidenceRefV1 | ExclusiveSocketOwnerEvidenceRefV1

DnsOriginalDestinationNegativeProbeBasisV1 = {
  probe_flow_id: DatagramFlowId,
  probe_observation_epoch: DatagramObservationEpoch,
  flow_record_ref: Arch004RecordRefV1::DatagramFlowRecord,
  boundary_evidence_ref: DatagramBoundaryEvidenceRefV1,
  failure_capability_report_ref: CapabilityReportEvidenceRefV1,
}

DnsProcessProvenanceNegativeProbeBasisV1 = {
  probe_flow_id: DatagramFlowId,
  probe_observation_epoch: DatagramObservationEpoch,
  flow_record_ref: Arch004RecordRefV1::DatagramFlowRecord,
  socket_owner_evidence_ref: ExclusiveSocketOwnerEvidenceRefV1,
  boundary_evidence_ref: DatagramBoundaryEvidenceRefV1,
  failure_capability_report_ref: CapabilityReportEvidenceRefV1,
}

DnsStandardClaimNegativeBasisV1 =
  | InheritedBlocker {
      source: Arch001 | Arch002,
      capability_report_ref: CapabilityReportEvidenceRefV1,
    }
  | ResourceReadbackFailure {
      readback_refs:
        SortedUniqueNonEmptyVector<ResourceReadbackEvidenceRefV1, 1..=8>,
    }
  | ExclusionReadbackFailure {
      exclusion_readback_ref: EgressExclusionReadbackEvidenceRefV1,
    }
  | CapabilityReportFailure {
      capability_report_ref: CapabilityReportEvidenceRefV1,
    }
  | ResolverBindingFailure {
      evidence_refs:
        SortedUniqueNonEmptyVector<
          ResolverBindingSetUnavailableEvidenceRefV1, 1..=8>,
    }
  | ResolverBootstrapFailure {
      evidence_refs:
        SortedUniqueNonEmptyVector<
          ResolverBootstrapUnavailableEvidenceRefV1, 1..=8>,
    }
  | CapabilityEvidenceExpired {
      prior_observation_context_digest:
        Digest(Arch004ObservationContextV1::CapabilityEvaluation),
      prior_cell_spec_digest: Digest(DnsCapabilityCellSpecV1),
      prior_scope: DnsClaimScopeV1,
      prior_platform_subject: Arch004PlatformSubjectV1,
      prior_cell_key: DnsCapabilityCellKeyV1,
      prior_primary_witness: DnsStandardClaimProvenWitnessV1,
      expired_at: SuspendAwareDeadline,
    }
  | PassiveMechanismLimitation {
      host_association_evidence_ref: DnsHostAssociationEvidenceRefV1,
    }
  | EncryptedMechanismLimitation {
      encrypted_outer_evidence_ref: DnsEncryptedOuterEvidenceRefV1,
    }
  | SelectedMechanismLimitation {
      observer_readback_ref: ResourceReadbackEvidenceRefV1,
    }
  | UnavailableMechanismLimitation {
      resource_reason: DnsBlockingReasonV1,
    }

DnsStandardClaimNegativeObservationV1 = {
  observation_context_digest: Digest(Arch004ObservationContextV1),
  cell_spec_digest: Digest(DnsCapabilityCellSpecV1),
  scope: DnsClaimScopeV1,
  platform_subject: Arch004PlatformSubjectV1,
  claim_kind: DnsClaimKindV1,
  disposition: ClaimNotProvenDispositionV1,
  reason: DnsBlockingReasonV1,
  basis: DnsStandardClaimNegativeBasisV1,
  evaluated_at: MonotonicInstant,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

DnsStandardClaimNegativeEvidenceRefV1 = {
  observation: DnsStandardClaimNegativeObservationV1,
  observation_digest: Digest(DnsStandardClaimNegativeObservationV1),
}

DnsStandardClaimNotProvenOutcomeV1 = {
  disposition: ClaimNotProvenDispositionV1,
  reason: DnsBlockingReasonV1,
  evidence_ref: DnsStandardClaimNegativeEvidenceRefV1,
}

DnsAncillaryCapabilityNegativeReasonV1 =
  | OriginalDestinationUnavailable {
      probe_basis: DnsOriginalDestinationNegativeProbeBasisV1,
    }
  | OriginalDestinationRealHostUnverified {
      probe_basis: DnsOriginalDestinationNegativeProbeBasisV1,
      unresolved_real_host_endpoint: EndpointV1,
    }
  | OriginalDestinationEvidenceExpired {
      probe_basis: DnsOriginalDestinationNegativeProbeBasisV1,
      prior_evidence_refs:
        SortedUniqueNonEmptyVector<OriginalDestinationEvidenceRefV1, 1..=8>,
      expired_at: SuspendAwareDeadline,
    }
  | ProcessProvenanceUnavailable {
      probe_basis: DnsProcessProvenanceNegativeProbeBasisV1,
    }
  | ProcessProvenanceRealHostUnverified {
      probe_basis: DnsProcessProvenanceNegativeProbeBasisV1,
      unresolved_real_host_endpoint: EndpointV1,
    }
  | ProcessProvenanceEvidenceExpired {
      probe_basis: DnsProcessProvenanceNegativeProbeBasisV1,
      prior_evidence_refs:
        SortedUniqueNonEmptyVector<DnsProcessCapabilityEvidenceRefV1, 1..=8>,
      expired_at: SuspendAwareDeadline,
    }

DnsAncillaryCapabilityNegativeObservationV1 = {
  observation_context_digest: Digest(Arch004ObservationContextV1),
  cell_spec_digest: Digest(DnsCapabilityCellSpecV1),
  scope: DnsClaimScopeV1,
  platform_subject: Arch004PlatformSubjectV1,
  reason: DnsAncillaryCapabilityNegativeReasonV1,
  evaluated_at: MonotonicInstant,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

DnsAncillaryCapabilityNegativeEvidenceRefV1 = {
  observation: DnsAncillaryCapabilityNegativeObservationV1,
  observation_digest:
    Digest(DnsAncillaryCapabilityNegativeObservationV1),
}

DnsOriginalDestinationNegativeEvidenceRefV1 =
  DnsAncillaryCapabilityNegativeEvidenceRefV1 {
    observation.reason:
      OriginalDestinationUnavailable |
      OriginalDestinationRealHostUnverified |
      OriginalDestinationEvidenceExpired,
  }

DnsProcessProvenanceNegativeEvidenceRefV1 =
  DnsAncillaryCapabilityNegativeEvidenceRefV1 {
    observation.reason:
      ProcessProvenanceUnavailable |
      ProcessProvenanceRealHostUnverified |
      ProcessProvenanceEvidenceExpired,
  }

DnsCapabilityResourceEvidenceV1 =
  | NativeConfigured {
      transport_path: DnsCapabilityTransportPathEvidenceV1::
        PlainUdpPath | StreamPath | NativeSystemPath,
      dns_route_active_state: Arch004ActiveResourceEvidenceV1,
      dns_observer_active_state: Arch004ActiveResourceEvidenceV1,
    }
  | Port53Hijacked {
      transport_path: DnsCapabilityTransportPathEvidenceV1::
        PlainUdpPath | StreamPath { transport: Exact(PlainTcp) },
      dns_route_active_state: Arch004ActiveResourceEvidenceV1,
      dns_intercept_active_state: Arch004ActiveResourceEvidenceV1,
      dns_observer_active_state: Arch004ActiveResourceEvidenceV1,
    }
  | MetadataObservedOnSelectedPath {
      transport_path: DnsCapabilityTransportPathEvidenceV1::
        PlainUdpPath | StreamPath | NativeSystemPath,
      dns_observer_active_state: Arch004ActiveResourceEvidenceV1,
    }
  | MetadataObservedPassive {
      transport_path:
        DnsCapabilityTransportPathEvidenceV1::PassiveObservedPath,
      dns_observer_active_state: Arch004ActiveResourceEvidenceV1,
    }
  | EncryptedOpaqueOnSelectedPath {
      transport_path: DnsCapabilityTransportPathEvidenceV1::StreamPath {
        transport: Tls | Https | Quic,
      },
      dns_observer_active_state: Arch004ActiveResourceEvidenceV1,
    }
  | Unavailable { reason: DnsBlockingReasonV1 }

DnsOriginalDestinationCapabilityNotProvenV1 =
  | OriginalDestinationUnavailable {
      disposition: Exact(Unsupported),
      evidence_ref: DnsOriginalDestinationNegativeEvidenceRefV1 {
        observation.reason: OriginalDestinationUnavailable,
      },
    }
  | CapabilityEvidenceExpired {
      disposition: Exact(TemporarilyUnavailable),
      evidence_ref: DnsOriginalDestinationNegativeEvidenceRefV1 {
        observation.reason: OriginalDestinationEvidenceExpired,
      },
    }
  | RealHostUnverified {
      disposition: Exact(Degraded),
      evidence_ref: DnsOriginalDestinationNegativeEvidenceRefV1 {
        observation.reason: OriginalDestinationRealHostUnverified,
      },
    }

DnsProcessProvenanceCapabilityNotProvenV1 =
  | ProcessProvenanceUnavailable {
      disposition: Exact(Unsupported),
      evidence_ref: DnsProcessProvenanceNegativeEvidenceRefV1 {
        observation.reason: ProcessProvenanceUnavailable,
      },
    }
  | CapabilityEvidenceExpired {
      disposition: Exact(TemporarilyUnavailable),
      evidence_ref: DnsProcessProvenanceNegativeEvidenceRefV1 {
        observation.reason: ProcessProvenanceEvidenceExpired,
      },
    }
  | RealHostUnverified {
      disposition: Exact(Degraded),
      evidence_ref: DnsProcessProvenanceNegativeEvidenceRefV1 {
        observation.reason: ProcessProvenanceRealHostUnverified,
      },
    }

DnsOriginalDestinationCapabilityClaimV1 =
  | Proven {
      scope: DnsClaimScopeV1,
      evidence_refs:
        SortedUniqueNonEmptyVector<OriginalDestinationEvidenceRefV1, 1..=8>,
      reason: ExactNoBlockingReason,
    }
  | NotProven {
      scope: DnsClaimScopeV1,
      outcome: DnsOriginalDestinationCapabilityNotProvenV1,
    }

DnsProcessProvenanceCapabilityClaimV1 =
  | Proven {
      scope: DnsClaimScopeV1,
      evidence_refs:
        SortedUniqueNonEmptyVector<DnsProcessCapabilityEvidenceRefV1, 1..=8>,
      reason: ExactNoBlockingReason,
    }
  | NotProven {
      scope: DnsClaimScopeV1,
      outcome: DnsProcessProvenanceCapabilityNotProvenV1,
    }

DnsCapabilityCellObservationV1 = {
  cell_spec_digest: Digest(DnsCapabilityCellSpecV1),
  observation_context_digest: Digest(Arch004ObservationContextV1),
  mechanism: DnsVisibilityMechanismV1,
  routing: DnsRoutingClaimV1,
  interception: DnsInterceptionClaimV1,
  decoding: DnsDecodingClaimV1,
  leak_prevention: DnsLeakPreventionClaimV1,
  original_destination: DnsOriginalDestinationCapabilityClaimV1,
  process_provenance: DnsProcessProvenanceCapabilityClaimV1,
  static_support: StaticSupport,
  readiness: Readiness,
  evidence: Evidence,
  https_carrier_coverage: DnsHttpsCarrierCoverageV1,
  resource_evidence: DnsCapabilityResourceEvidenceV1,
  expires_at: SuspendAwareDeadline,
  reason: DnsCapabilityReasonV1,
}

DnsCapabilityMatrixV1 = {
  cells: ExactVector<DnsCapabilityCellSpecV1, 10>,
  complete_key_set: {
    families: [Ipv4, Ipv6],
    transports: [PlainUdp, PlainTcp, Tls, Https, Quic],
  },
  matrix_digest: Digest,
}

DnsCapabilityMatrixObservationV1 = {
  matrix_spec_digest: Digest(DnsCapabilityMatrixV1),
  observation_context_digest: Digest(Arch004ObservationContextV1),
  cells: ExactVector<DnsCapabilityCellObservationV1, 10>,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
  observation_digest: Digest,
}
```

The matrix has exactly ten cells in family-major order:
`Ipv4/{PlainUdp,PlainTcp,Tls,Https,Quic}` followed by
`Ipv6/{PlainUdp,PlainTcp,Tls,Https,Quic}`. The observation vector uses the same
positions and each observation's `cell_spec_digest` resolves to the spec at
that position. An unsupported family/transport still has an explicit cell.
Missing, duplicate, reordered, extra, wildcard, or default cells are invalid.

The matrix observation's `observation_context_digest` and all ten cell
`observation_context_digest` values are byte-identical and resolve one current
`CapabilityEvaluation` context. Its platform subject/network scope equal all
ten specs, and its installation/session/generation/plan/lease epoch/fence,
egress, limit set, observed/expiry window and capability-evaluator component
are one inseparable tuple. The matrix authenticator is exactly `CaptureCore`
under `context.evaluator_gate`; its header authority binding is byte-identical
to that complete `ExternalExecutorGate`, signer identity repeats
`evaluator_component_instance_id`, and gate prepared-plan/component values
equal the lease and plan graph. Its header and local
tag-`0x4004` signature validate the formula above. A cross-plan cell vector,
another valid evaluator key, or a top-level context that merely overlaps the
cell freshness window is invalid.

`DnsCapabilityMatrixObservationV1` is itself the complete authenticated carrier.
A binding-set observation embeds that exact signed body. A
`NoResolverDependencies` capability/status response likewise carries the whole
body inline; no consumer may accept or persist `observation_digest` without the
resolving body and valid signature.

Every matrix has one byte-identical `network_scope`,
`DnsCapabilityResolverScopeV1`, and `platform_subject` across all ten specs.
For every observed cell, the scopes of `routing`, `interception`, `decoding`,
`leak_prevention`, `original_destination`, and `process_provenance` are all
byte-identical to the single value
`{ network_scope: spec.network_scope, families: [spec.key.family],
transports: [spec.key.transport], resolver_scope: spec.resolver_scope }`.
Both vectors are exact sorted singletons. A wider family/transport vector,
another network, another planned resolver dependency/use site, an
implementation-owned/post-seal binding-set scope substituted after seal, or six mutually
consistent scopes that nevertheless differ from the spec are invalid.

The four standard claim dispositions and the two ancillary claim dispositions
are position-for-position exact with `expected_routing`,
`expected_interception`, `expected_decoding`, `expected_leak_prevention`,
`expected_original_destination`, and `expected_process_provenance`: `Proven`
selects the proven variant and every other disposition selects `NotProven` with
`outcome.disposition` exactly equal to that value. Static support, readiness,
and evidence grade are
respectively byte-identical to `expected_static_support`,
`expected_readiness`, and `expected_evidence`. V1 defines no implicit order or
meet-or-exceed coercion among those external enums; changing any value requires
a different sealed cell spec.

The matrix is plan-specific and names exactly one selected visibility mechanism
per cell. If a platform exposes several candidate mechanisms, plan construction
selects and proves one; the others do not become implicit aggregate coverage.
Each cell observation's `mechanism` is byte-for-byte its referenced spec's
`selected_mechanism`; post-seal observation cannot substitute or degrade to a
different mechanism. Failure to realize the selected mechanism produces no
alternate-mechanism cell: it fails/fences the plan with the applicable blocking
reason. Each emitted transaction repeats that sealed mechanism and the
mechanism that actually produced it.

`https_carrier_coverage` is `NotHttps` for all non-`Https` cells. An `Https`
cell uses `HttpsObserved` with one to three sorted unique decoded carriers or
`HttpsCarrierUnavailable`; there is no empty vector. A cell that claims decoded
DoH requires `HttpsObserved`, and an unobserved carrier cannot be inserted into
its set. The observation coverage is byte-for-byte its referenced spec coverage:
no carrier may be added, removed, reordered, or replaced after seal. Every
ready HTTPS resolver member's single observed carrier is a member of that exact
sealed set. HTTP/3 DoH remains `Https`, not `Quic`; `Quic` is the semantic DoQ
cell.

The spec is receipt/result-free and is the only capability matrix body allowed
inside a candidate plan. The observation is post-seal: its context, exact
closed resource active-state evidence, and typed evidence references cannot feed back into
`matrix_digest` or any resolver binding digest. Matrix/cell observations use
the `CapabilityEvaluation` context; resource results use `ResourceExecution`.
Their complete context digests are intentionally different, but their embedded
lease projections (installation/session/generation/prepared plan/plan digest/
lease epoch/fence and overlapping freshness window) must be byte-identical. A
cell observation must exactly meet every expected claim/support/readiness/
evidence field of its spec and repeat the same platform subject through the
named backend/results.
Cross-host, cross-package, cross-backend,
cross-path, stale, or differently ordered observations are invalid.

`resource_evidence` is selected exactly by the cell mechanism.
`NativeConfigured` requires its matching variant and forbids intercept evidence;
`Port53Hijacked` requires path, route, intercept, and observer active states;
`MetadataObserved` chooses exactly the selected-path or passive variant and
forbids route/intercept evidence. `EncryptedOpaque` uses only its selected-path
variant; a passive encrypted connection has no DNS-specific classification
authority. `Unavailable` contains no active-state source. Every active
state must resolve to the stated resource kind, same platform subject and byte-
equal lease projection, and a successful current applied/recovery-applied body.

Transport and mechanism jointly select the only legal path variant:

| Cell transport | Allowed mechanisms/path evidence |
| --- | --- |
| `PlainUdp` | `NativeConfigured` with `PlainUdpPath|NativeSystemPath`; `Port53Hijacked` with `PlainUdpPath`; `MetadataObserved` with `PlainUdpPath|NativeSystemPath|PassiveObservedPath`; `Unavailable` |
| `PlainTcp` | `NativeConfigured` with `StreamPath(PlainTcp)|NativeSystemPath`; `Port53Hijacked` with `StreamPath(PlainTcp)`; `MetadataObserved` with `StreamPath(PlainTcp)|NativeSystemPath|PassiveObservedPath`; `Unavailable` |
| `Tls` | `NativeConfigured` with `StreamPath(Tls)|NativeSystemPath`; `MetadataObserved` with `StreamPath(Tls)|NativeSystemPath|PassiveObservedPath`; `EncryptedOpaque` with `StreamPath(Tls)` and a planned resolver dependency; `Unavailable` |
| `Https` | `NativeConfigured` with `StreamPath(Https)|NativeSystemPath`; `MetadataObserved` with `StreamPath(Https)|NativeSystemPath|PassiveObservedPath`; `EncryptedOpaque` with `StreamPath(Https)` and a planned resolver dependency; `Unavailable` |
| `Quic` | `NativeConfigured` with `StreamPath(Quic)|NativeSystemPath`; `MetadataObserved` with `StreamPath(Quic)|NativeSystemPath|PassiveObservedPath`; `EncryptedOpaque` with `StreamPath(Quic)` and a planned resolver dependency; `Unavailable` |

`PlainUdpPath` resolves the exact current UDP path resource and operational
binding for the cell actor/family/network/egress. `StreamPath` resolves one
current tag-31 socket child and tag-13 path proof with that exact transport,
endpoint, actor, factory, exclusion set and plan; it deliberately does not
reference the resolver member/cell and therefore creates no hash cycle.
`NativeSystemPath` repeats the exact current native route read-back, and
`PassiveObservedPath` repeats the exact host-association flow/connection and
observed transport without claiming route ownership. A transport mismatch,
UDP resource used for a stream cell, passive path recoded as selected, or any
of the unlisted 5x5 substitutions is invalid.
`PlainUdpPath` is legal if and only if `cell.key.transport=PlainUdp`.
Every `StreamPath.transport`, `NativeSystemPath.transport`, and
`PassiveObservedPath.transport` is byte-identical to `cell.key.transport`.
The `Port53Hijacked` branch is `PlainUdpPath` exactly for `PlainUdp` and
`StreamPath(PlainTcp)` exactly for `PlainTcp`; no other branch or transport can
encode that mechanism.
A missing observer, optionalized
port-53 intercept, fabricated route for passive observation, result from another
path/build, or extra hidden result invalidates the cell.

The four standard `Proven` claims use their closed mandatory
`primary_witness`; no generic evidence vector or supplemental ref can replace
it. Every primary leaf is fresh in the same lease/fence window and resolves the
same platform, network, path, transport, family, evaluator scope and exact
resource evidence as the cell. `Routing.SelectedPath` uses the exact tag-13
proof from `StreamPath`, or the tag-13 proof committed by the exact UDP binding;
`Routing.NativeSystemPath` uses the same current DNS-route read-back as
`NativeSystemPath`. The witness binds only the plan-time
`PlannedResolverDependency` scope and preexisting path proof; it never points
back to the post-seal binding-set observation that embeds this matrix.

`Interception.Port53Intercept` is legal only for `Port53Hijacked` and its
read-back resolves the exact current `dns.intercept.v1` state while its probe is
`RuntimeProtectedHook` plaintext on the same family/PlainUdp-or-PlainTcp path.
`Interception.NativeOrRuntimeHook` is legal only when `NativeConfigured` has an
authenticated `RuntimeProtectedHook` or `NativeSystemResolverHook`; its route
read-back and probe source match the selected backend. A datagram boundary,
passive plaintext observation, configured route without a hook, or observer
active state alone never proves interception.

The decoding primary variant tag equals `cell.key.transport`. Its query and
response leaves are a same-probe pair: endpoint, family, transport,
hook/source, lease, and stable flow/connection/HTTP transaction/QUIC stream or
runtime/backend/route selection core are byte-identical. Generic association
tags are the same; runtime/native resolver association tags and authenticated
tokens are respectively request/query then response/response, never
byte-identical across roles. `Https.carrier_witnesses` are sorted uniquely by carrier,
their carrier key set is byte-identical to the cell's complete
`HttpsObserved.carriers` set, and each pair uses that exact HTTP carrier and one
same-carrier HTTP association. A claimed second/third carrier without its own
query/response pair is invalid. `Quic` additionally carries the exact client query FIN and
server response FIN for that same client-bidirectional DoQ stream; FIN evidence
is supplemental to, never a substitute for, the plaintext pair.

Leak-prevention mirrors routing but also requires the exact current
no-pending-TUN-recursion leaf. A selected-path/native-route witness or recursion
leaf from a sibling actor/path cannot be combined. The
only legal positive-witness combinations are:

| Mechanism/path mode | Routing | Interception | Decoding | Leak prevention |
| --- | --- | --- | --- | --- |
| `NativeConfigured` selected/native | matching selected/native witness | matching authenticated native/runtime-hook witness or `NotProven` | exact transport decoding witness when its closed producer branch exists; otherwise `NotProven` | matching selected/native witness |
| `Port53Hijacked` | selected-path witness | port-53 witness | `PlainUdp` or `PlainTcp` decoding witness | selected-path witness |
| `MetadataObserved` selected | matching selected/native witness | `NotProven` | exact transport decoding witness | matching selected/native witness |
| `MetadataObserved` passive | `NotProven` | `NotProven` | exact transport decoding witness | `NotProven` |
| `EncryptedOpaque` selected | selected-path witness | `NotProven` | `NotProven` | selected-path witness |
| `Unavailable` | `NotProven` | `NotProven` | `NotProven` | `NotProven` |

For a platform-native `NativeSystemPath`, V1 has native query/response decoding
pairs only for `PlainUdp`, `PlainTcp`, and `Tls`. Native-system `Https` and
`Quic` cells may still prove their configured route and leak-prevention state,
but their decoding claim is exactly `NotProven` with
`MechanismDoesNotProveDecoding`; a generic plaintext decoder or runtime hook
cannot be recoded as a native-system hook. The `DnsHttpsDecodingPairV1` and
`DnsDoqDecodingPairV1` producer unions intentionally omit
`NativeSystemResolverHook`, and DoQ FIN evidence is never synthesized from a
native resolver API.

A standard `NotProven` claim carries no free-form evidence array. It carries
exactly one complete signed local tag-`0x4006` negative observation whose cell,
scope, platform, claim kind, reason, disposition and evaluation time equal the
enclosing claim/cell and current `CapabilityEvaluation` context byte-for-byte.
Its reason-specific basis is closed as follows:

| Reason group | Required negative basis |
| --- | --- |
| `InheritedArch001Blocker`, `InheritedArch002Blocker` | `InheritedBlocker` with the same source and exact current accepted upstream blocker report |
| `RuntimeAttachmentMissing`, `ResumeGateMissing`, `SocketAdmissionUnavailable`, `WindowsDnsInterfaceNotExclusivelyOwned`, `LinuxResolvedLinkNotExclusivelyOwned`, `NetworkManagerCasUnavailable`, `MacOsConditionalDnsMutationUnavailable`, `MacOsActiveApplyCompletionUnproven` | `ResourceReadbackFailure` with the exact failed current predicate/read-back set |
| `LoopExclusionIncomplete` | `ExclusionReadbackFailure` with the exact negative tag-51 observation; a positive no-recursion root cannot substitute |
| `RealHostUnverified`, `PinnedRuntimeMismatch`, `PinnedQuicBuildTagUnavailable`, `PinnedDnsResponseBoundUnavailable`, `LinuxReleaseTupleUnselected`, `LinuxResolverManagerUnknownOrMixed`, `WindowsNativeInterceptBackendUnregistered`, `LinuxNativeInterceptBackendUnregistered`, `MacOsNativeInterceptBackendUnregistered`, `DecoderUnavailable`, `ResolverNativeScopeUnavailable`, `ResolverBackendUnsupported` | `CapabilityReportFailure` with the exact plan/platform/backend report |
| `ResolverBindingSetUnavailable` | `ResolverBindingFailure` with the exact member/set path witnesses |
| `ResolverBootstrapUnavailable` | `ResolverBootstrapFailure` with the exact source/predecessor witnesses |
| `CapabilityEvidenceExpired` | `CapabilityEvidenceExpired` with the same claim-kind prior primary witness, exact prior CapabilityEvaluation context/cell spec/scope/platform/key and deadline; `evaluated_at > expired_at` |
| `MechanismDoesNotProveRouting`, `MechanismDoesNotProveInterception`, `MechanismDoesNotProveLeakPrevention` on a passive path | `PassiveMechanismLimitation` with the exact same host-association leaf |
| `MechanismDoesNotProveDecoding` for encrypted traffic | `EncryptedMechanismLimitation` with the exact same encrypted-outer leaf |
| a selected metadata/hook configuration that lacks the dimension | `SelectedMechanismLimitation` with the exact current observer/resource read-back |
| an unavailable mechanism | `UnavailableMechanismLimitation` whose nested resource reason equals `resource_evidence::Unavailable.reason` |

No other reason/basis pair is encodable after seal;
`UseSiteFamilyPolicyUnavailable` remains pre-seal-only. The tag-`0x4006`
authenticator and digest validate the formula above and never point to the
enclosing cell/matrix observation, so the evidence graph remains acyclic.
For expiry, the prior context is strictly earlier, repeats the current
installation/session/generation/plan/lease/fence, network, resolver scope,
platform and cell key, and differs only by its bounded observation window. All
prior primary leaves resolve that context and exact cell spec; cross-plan,
cross-family/transport/scope/platform, unsigned or producer-invented deadlines
are invalid.
Reason scope is also closed. `ResolverBindingSetUnavailable` and
`ResolverBootstrapUnavailable` are legal only for
`PlannedResolverDependency`; their basis repeats that scope's descriptor digest,
path ID and use site through exact plan-time member/source fields.
Bootstrap basis may carry only the complete signed strictly-earlier predecessor
set/observation defined below; it never references the current/enclosing set or
a descendant. `ResolverNativeScopeUnavailable` is legal only
for `ExactNativeResolverScope`; `ResolverBackendUnsupported` may use planned or
native scope only when its report names that exact backend/path. `NoResolverScope`
accepts only mechanism/host-observation, inherited, resource, expiry or decoder
reasons applicable without a resolver path. A planned/native/no-scope
substitution is invalid even when the reason, report and signature are otherwise
valid.
When the selected mechanism/path mode itself cannot establish the dimension,
the claim uses exactly the corresponding
`MechanismDoesNotProve{Routing,Interception,Decoding,LeakPrevention}` reason and
`Unsupported`; it cannot fabricate an inherited/platform root. Permission- or
interaction-required dispositions are legal only through an exact current
`InheritedArch001Blocker`/`InheritedArch002Blocker` whose embedded disposition
is copied from that accepted upstream plan blocker. Every other reason follows
the total table below. This structure makes a lone FIN, passive boundary,
unrelated capability report, or observer-running result unencodable as a
positive claim.

There is deliberately no second generic evidence vector at cell level. The
complete cell witness set is the exact union of the four standard mandatory
primary witnesses, two ancillary claim-local witnesses, every standard/ancillary
negative observation selected by those claims, and the closed active-state
objects in `resource_evidence`. Each proven original-
destination or process witness resolves the exact current probe flow/socket in
the cell scope. Every ancillary unavailable/real-host outcome contains exactly
its complete signed local tag-`0x4005` negative observation for this cell,
dimension, platform and scope. An expired outcome's same signed body carries
the exact nonempty prior positive evidence vector and its deadline, with
`evaluated_at > expired_at` and matrix evaluation time byte-identical to
`evaluated_at`; expired evidence is not described as current. There is no empty
or inherited-blocker ancillary outcome. A claim witness omitted from its own
field, an unrelated but valid root, or a witness parked in another claim is
invalid.
Every tag-`0x4005` probe basis names the exact same probe flow/epoch and current
boundary leaf in the enclosing cell scope. Its typed current DatagramFlow record
resolves `probe_flow_id` and `probe_observation_epoch`; a process basis also
resolves the exact current socket-owner census entry, with no naked socket
digest. Its failure report is for that dimension, platform/backend and probe
socket/path. A real-host variant also
binds the unresolved endpoint. Expired prior refs all repeat that probe subject,
cell spec/scope/platform and an earlier evaluation window with the same plan/
lease/fence. A report for another probe or a signed negative assertion without
the typed basis is invalid.

Matching an expected non-proven disposition makes the observation conform to
its spec but does not make the path ready. `NoBlockingReason` is legal only when
all six observed claims are `Proven`, all three exact support/readiness/evidence
values are their positive usable variants, the mechanism is not `Unavailable`,
the mechanism's exact typed resources are current, the platform subject
matches, and all evidence is fresh. Any failed condition uses
`Blocking(DnsBlockingReasonV1)` with the first applicable reason in the displayed
claim order `routing, interception, decoding, leak_prevention,
original_destination, process_provenance`, followed by resource, support,
readiness, evidence and freshness. A standard `NotProven` contributes its exact
reason; an ancillary outcome contributes its same-named reason; and
`resource_evidence::Unavailable.reason` must equal the resulting cell blocker
when it is the first failure. `NotProven` and resource `Unavailable` accept only
the blocking subtype; `Proven` accepts only `ExactNoBlockingReason`. A ready resource branch
cannot coexist with a resource blocker, and an unsupported/stale cell cannot use
`NoBlockingReason`. Unknown, contradictory, or producer-selected reason mapping
rejects the cell rather than choosing a default.

`PlainUdp` and `PlainTcp` are not restricted to port 53 in the data model, but
`Port53Hijacked` requires an exact accepted port-53 policy and read-back.
Nonstandard plaintext ports can be `MetadataObserved` only through a registered
decoder boundary.

`Tls`, `Https`, and `Quic` map to DoT, DoH, and DoQ only when a supported
plaintext hook proves DNS message semantics and binds them to the outer
transport. `EncryptedOpaque` is legal only for the exact selected planned
resolver path after the closed census below proves zero matching authenticated
plaintext DNS boundaries for the complete outer association/epoch/window.
Otherwise the cell is `Unavailable`; passive or ordinary encrypted traffic is
never upgraded from generic host metadata by port, endpoint, SNI, ALPN, process,
or transport alone.

The following never proves decoded DNS by itself:

- destination port 53, 443, 853, or another known port;
- resolver IP address or hostname;
- SNI, certificate identity, ALPN, HTTP path, process name, or configuration;
- QUIC or TLS packet classification;
- a `hijack-dns`, DNS-server, route, or sniff option in JSON; or
- successful runtime startup or config validation.

## 10. DNS question and response metadata

```text
DnsNameRetentionModeV1 =
  | EphemeralExact
  | PersistKeyedDigest
  | PersistExactAuthorized {
      authorization_receipt_digest:
        Digest(DnsExactNameAuthorizationReceiptV1),
      authorization_scope_digest:
        Digest(DnsExactNameAuthorizationScopeV1),
      exact_retention_deadline: SuspendAwareDeadline,
    }
  | Redacted

DnsNameV1 =
  | ExactNormalized {
      canonical_wire_name: BoundedDnsName,
      original_case_preserved: false,
    }
  | KeyedDigest {
      key_epoch: DnsPrivacyKeyEpoch,
      digest: KeyedDigestValue,
      label_count: U8,
    }
  | NameRedacted

DnsQuestionV1 = {
  name: DnsNameV1,
  qtype: U16,
  qclass: U16,
}

DnsOpcodeV1 = Integer<0..=15>
DnsExtendedRcodeV1 = Integer<0..=4095>

DnsResponseSummaryV1 = {
  opcode: DnsOpcodeV1,
  rcode: DnsExtendedRcodeV1,
  truncated: Bool,
  authoritative: Bool,
  recursion_available: Bool,
  answer_count: U16,
  authority_count: U16,
  additional_count: U16,
}
```

Exact-name authority is receipt-free until the broker decision and uses this
closed vocabulary:

```text
DnsExactNameReceiptIssuerKindV1 =
  | TrustedProductPolicyBroker
  | InstalledAdministratorPolicy

DnsExactNameReceiptIssuerIdentityV1 = {
  issuer_kind: DnsExactNameReceiptIssuerKindV1,
  issuer_keyset_id: Bytes32,
  issuer_key_id: Bytes32,
  issuer_keyset_version: BoundedVersion,
  ed25519_public_key_32: Bytes32,
  installation_id: InstallationId,
  policy_broker_scope_id: Bytes32,
  policy_broker_scope_version: BoundedVersion,
}

DnsExactNameConsumerV1 =
  | StoragePrivacyOwner {
      component_instance_id: ComponentInstanceId,
    }
  | FirstPartyLiveView {
      consumer_id: Bytes32,
      host_capability_digest: Digest,
    }

DnsQuestionCodeScopeV1 =
  | AllU16Values
  | ExactValues(SortedUniqueVector<U16, 1..=256>)

DnsExactNameQuestionScopeV1 = {
  domain_scope: AllCanonicalNamesInBoundCaptureSession,
  families: SortedUniqueNonEmptyVector<AddressFamilyV1>,
  transports: SortedUniqueNonEmptyVector<DnsTransportV1>,
  qtype_scope: DnsQuestionCodeScopeV1,
  qclass_scope: DnsQuestionCodeScopeV1,
}

DnsExactNameAuthorizationSubjectV1 = {
  installation_id: InstallationId,
  preparation_ticket_id: PreparationTicketId,
  session_id: SessionId,
  generation: Generation,
  capture_session_id: CaptureSessionId,
  exact_network_scope: NetworkScope,
  requested_mode: PersistExact,
  authorized_consumer_scope:
    SortedUniqueNonEmptyVector<DnsExactNameConsumerV1>,
  authorized_dns_scope: DnsExactNameQuestionScopeV1,
  out_of_scope_persisted_mode: PersistKeyedDigest | Redacted,
  maximum_retention_deadline: SuspendAwareDeadline,
  policy_text_version: BoundedVersion,
  boot_epoch: BootEpoch,
  suspend_epoch: SuspendEpoch,
}

DnsExactNameAuthorizationScopeV1 = {
  subject_digest: Digest(DnsExactNameAuthorizationSubjectV1),
  policy_broker_challenge: FreshBytes32,
  decision_deadline: SuspendAwareDeadline,
}

DnsExactNameAuthorizationReceiptV1 = {
  issuer_kind: DnsExactNameReceiptIssuerKindV1,
  issuer_identity_digest: Digest(DnsExactNameReceiptIssuerIdentityV1),
  receipt_id: FreshBytes32,
  decision_nonce: FreshBytes32,
  installation_id: InstallationId,
  preparation_ticket_id: PreparationTicketId,
  session_id: SessionId,
  generation: Generation,
  capture_session_id: CaptureSessionId,
  exact_authorization_scope_digest:
    Digest(DnsExactNameAuthorizationScopeV1),
  boot_epoch: BootEpoch,
  suspend_epoch: SuspendEpoch,
  issued_at: MonotonicInstant,
  continuous_expires_at: SuspendAwareDeadline,
  signature: Ed25519Signature64,
}

DnsExactNameAuthorizationConsumptionV1 = {
  receipt_digest: Digest(DnsExactNameAuthorizationReceiptV1),
  authorization_scope_digest: Digest(DnsExactNameAuthorizationScopeV1),
  issuer_identity_digest: Digest(DnsExactNameReceiptIssuerIdentityV1),
  receipt_id: FreshBytes32,
  decision_nonce: FreshBytes32,
  preparation_ticket_id: PreparationTicketId,
  session_id: SessionId,
  generation: Generation,
  capture_session_id: CaptureSessionId,
  candidate_plan_digest: CandidatePlanDigest,
  prepare_idempotency_key: PrepareIdempotencyKey,
  prepared_plan_id: PreparedPlanId,
  plan_digest: PlanDigest,
  journal_record_location: Arch001JournalLocation,
}
```

The authorization subject fixes the exact capture session, consumer set,
network scope, permitted DNS question/domain/type/class scope, and maximum
retention deadline before a receipt exists. It cannot contain a receipt digest.
The consumer set contains exactly one `StoragePrivacyOwner`; every optional
live-view entry names its existing host capability. Analyzer access is not a
variant and remains separately authorized under the analyzer contract.
The final `PersistExactAuthorized` value must reproduce its receipt, scope, and
retention deadline exactly; the retention deadline may outlive the short
decision receipt only because it is explicitly signed in the subject.
Every persisted exact question must match the signed capture session, family,
transport, qtype, and qclass scope, and only a named consumer may receive it.
An out-of-scope question uses exactly the signed non-exact mode and corresponding
name variant; it is never persisted exact by best-effort interpretation.

Projection is per question and publication is per complete ordered vector. For
`PersistExactAuthorized`, the privacy owner evaluates every transient exact
canonical question independently against the signed family, transport, domain,
qtype, and qclass scope. An in-scope member becomes `ExactNormalized`; an
out-of-scope member becomes exactly the subject's
`out_of_scope_persisted_mode` (`KeyedDigest` or `NameRedacted`). Mixed-scope
multi-question messages therefore have one deterministic mixed representation.
The owner reserves capacity and constructs the entire projected vector before
publishing the transaction revision. If authorization, digesting, redaction,
capacity, or any member projection fails, it publishes none of the vector and
returns the closed privacy/resource outcome; a partial question vector is never
observable.

The local canonical digests are exactly:

```text
Digest(DnsExactNameAuthorizationSubjectV1) =
  SHA-256("FlowProbe.Dns.ExactNameSubject.v1\0" ||
    deterministic_cbor(subject))
Digest(DnsExactNameAuthorizationScopeV1) =
  SHA-256("FlowProbe.Dns.ExactNameScope.v1\0" ||
    deterministic_cbor(scope))
Digest(DnsExactNameAuthorizationReceiptV1) =
  SHA-256("FlowProbe.Dns.ExactNameReceiptObject.v1\0" ||
    deterministic_cbor(receipt_including_signature))
Digest(DnsExactNameAuthorizationConsumptionV1) =
  SHA-256("FlowProbe.Dns.ExactNameConsumption.v1\0" ||
    deterministic_cbor(consumption))
```

Issuer identity is exactly
`SHA-256("FlowProbe.Dns.ExactNameIssuer.v1\0" ||
deterministic_cbor({issuer_kind, ed25519_public_key_32, installation_id,
issuer_keyset_id, issuer_key_id, issuer_keyset_version,
policy_broker_scope_id, policy_broker_scope_version}))` from the compile-time
trusted policy-broker registry. The Ed25519 signature is over
`"FlowProbe.Dns.ExactNameReceipt.v1\0" ||
deterministic_cbor(receipt_without_signature)`. The receipt decision expires no
later than five minutes after issue and is invalid after boot/suspend change.
Both Supervisor and helper verify signature, registry, fresh challenge/nonce,
all duplicated scope fields, and deadline ordering. The scope's
`decision_deadline` equals the receipt's `continuous_expires_at`, is not before
issue, and is no later than five minutes after it.
The durable issuance key is `(policy_broker_challenge,
Digest(DnsExactNameAuthorizationScopeV1))`; exact response-loss retry returns
the byte-identical receipt and challenge reuse with another scope is rejected.

The helper durably consumes the receipt/scope tuple once during `PreparePlan`
and binds it to the exact candidate plan, prepare idempotency key, and returned
`PreparedPlanId + PlanDigest`; the post-plan consumption digest is never a plan
input. The existing ARCH-001 helper journal envelope authenticates that digest
and location without a self-signature field. Only byte-identical response-loss
replay returns the same result.
Cross-session, cross-plan, cross-mode, stale, copied, re-scoped, or second-use
authority is invalid. A renderer flag, stored receipt reference, or possession
of an exact-name record is not authorization.

Names are normalized from the DNS wire representation rather than forced
through UTF-8 or IDNA. Compression is expanded under the work bound, ASCII
letters are case-folded for correlation, all other label octets use an escaped
bounded display, and a terminal root label is represented canonically. Invalid
label types, pointer
loops, pointers outside the message, expanded names beyond the bound, and
invalid framing are malformed. A malformed message MUST NOT emit a partial
exact name.

`rcode` contains the complete observed response code, including an accepted
extended RCODE when the bounded parser observes the corresponding EDNS field.
If the extension is malformed, the message is malformed rather than silently
falling back to the low header bits.
Conforming values are in the twelve-bit DNS extended-RCODE range; other `U16`
values are rejected.

The baseline records no answer owner names, RDATA, ECS values, cookies, raw
packets, DoH headers, TLS secrets, or HTTP bodies. Counts and flags above are
metadata, not proof that every resource record was semantically decoded.

## 11. DNS correlation

```text
DnsCorrelationDiscriminatorV1 =
  | Udp {
      flow_id: DatagramFlowId,
      query_occurrence_id: DnsQueryOccurrenceId,
      wire_id: U16,
      query_opcode: DnsOpcodeV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | Tcp {
      connection_epoch: DnsConnectionEpochV1,
      framed_query_sequence: DnsFramedMessageSequenceV1,
      wire_id: U16,
      query_opcode: DnsOpcodeV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | DotPlaintextHook {
      outer_connection_epoch: DnsConnectionEpochV1,
      framed_query_sequence: DnsFramedMessageSequenceV1,
      wire_id: U16,
      hook_identity: DnsPlaintextHookIdentityV1,
      query_opcode: DnsOpcodeV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | DohPlaintextHook {
      outer_connection_epoch: DnsConnectionEpochV1,
      http_transaction_id: HostHttpTransactionIdV1,
      hook_identity: DnsPlaintextHookIdentityV1,
      query_opcode: DnsOpcodeV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | DoqPlaintextHook {
      quic_connection_epoch: DnsConnectionEpochV1,
      stream_id: QuicStreamIdV1,
      hook_identity: DnsPlaintextHookIdentityV1,
      query_opcode: DnsOpcodeV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
      negotiated_alpn: ExactAscii("doq"),
      stream_kind: Exact(ClientInitiatedBidirectional),
      stream_usage: Exact(ExactlyOneQueryAndAtMostOneResponse),
      query_dns_message_id: ExactU16(0),
      query_message_ordinal: ExactU8(0),
      query_fin_observation_ref: DnsQuicQueryFinEvidenceRefV1,
      framing: Exact(Rfc9250TwoOctetLengthPrefixedWithinPlanBound),
      quic_datagram_used: false,
      unidirectional_stream_used: false,
    }
  | RuntimeResolverHook {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsPathBoundResolverSelectionV1,
      authenticated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
      query_opcode: DnsOpcodeV1,
    }
  | NativeSystemResolverHook {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_resource_identity_digest: Digest(DnsRouteResourceIdentityV1),
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsNativeSystemResolverSelectionV1,
      authenticated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
      query_opcode: DnsOpcodeV1,
    }

DnsResponseCompletionEvidenceV1 =
  | Udp {
      response_occurrence_id: DnsResponseOccurrenceId,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
      observation_ref: DnsPlaintextBoundaryEvidenceRefV1,
    }
  | Tcp {
      framed_response_sequence: DnsFramedMessageSequenceV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
      observation_ref: DnsPlaintextBoundaryEvidenceRefV1,
    }
  | DotPlaintextHook {
      framed_response_sequence: DnsFramedMessageSequenceV1,
      hook_identity: DnsPlaintextHookIdentityV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
      observation_ref: DnsPlaintextBoundaryEvidenceRefV1,
    }
  | DohPlaintextHook {
      http_transaction_id: HostHttpTransactionIdV1,
      response_message_ordinal: MonotonicSequence,
      hook_identity: DnsPlaintextHookIdentityV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
      observation_ref: DnsPlaintextBoundaryEvidenceRefV1,
    }
  | DoqPlaintextHook {
      stream_id: QuicStreamIdV1,
      response_message_ordinal: ExactU8(1),
      response_dns_message_id: ExactU16(0),
      query_and_response_same_stream: true,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
      response_observation_ref: DnsPlaintextBoundaryEvidenceRefV1,
      server_fin_observation_ref: DnsQuicResponseFinEvidenceRefV1,
    }
  | RuntimeResolverHook {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsPathBoundResolverSelectionV1,
      correlated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
      authenticated_response_token_digest:
        AuthenticatedDnsResponseTokenDigestV1,
      response_host_association: DnsHostAssociationV1 {
        key: DnsHostAssociationKeyV1::RuntimeResolverResponse,
      },
      observation_ref: DnsPlaintextBoundaryEvidenceRefV1,
    }
  | NativeSystemResolverHook {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_resource_identity_digest: Digest(DnsRouteResourceIdentityV1),
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsNativeSystemResolverSelectionV1,
      correlated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
      authenticated_response_token_digest:
        AuthenticatedDnsResponseTokenDigestV1,
      response_host_association: DnsHostAssociationV1 {
        key: DnsHostAssociationKeyV1::NativeSystemResolverResponse,
      },
      observation_ref: DnsPlaintextBoundaryEvidenceRefV1,
    }

DnsUnmatchedResponseContextV1 =
  | Udp {
      flow_id: DatagramFlowId,
      wire_id: U16,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | Tcp {
      connection_epoch: DnsConnectionEpochV1,
      wire_id: U16,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | DotPlaintextHook {
      outer_connection_epoch: DnsConnectionEpochV1,
      wire_id: U16,
      hook_identity: DnsPlaintextHookIdentityV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | DohPlaintextHook {
      outer_connection_epoch: DnsConnectionEpochV1,
      http_transaction_id: HostHttpTransactionIdV1,
      hook_identity: DnsPlaintextHookIdentityV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | DoqPlaintextHook {
      quic_connection_epoch: DnsConnectionEpochV1,
      stream_id: QuicStreamIdV1,
      hook_identity: DnsPlaintextHookIdentityV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
      negotiated_alpn: ExactAscii("doq"),
      stream_kind: Exact(ClientInitiatedBidirectional),
      stream_usage: Exact(ExactlyOneQueryAndAtMostOneResponse),
      query_dns_message_id: ExactU16(0),
      response_dns_message_id: ExactU16(0),
      query_message_ordinal: ExactU8(0),
      response_message_ordinal: ExactU8(1),
      query_fin_observation_ref: DnsQuicQueryFinEvidenceRefV1,
      server_fin_observation_ref: DnsQuicResponseFinEvidenceRefV1,
      framing: Exact(Rfc9250TwoOctetLengthPrefixedWithinPlanBound),
      quic_datagram_used: false,
      unidirectional_stream_used: false,
    }
  | RuntimeResolverHook {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsPathBoundResolverSelectionV1,
      correlated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
    }
  | NativeSystemResolverHook {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_resource_identity_digest: Digest(DnsRouteResourceIdentityV1),
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsNativeSystemResolverSelectionV1,
      correlated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
    }

DnsCorrelationQuestionCommitmentV1 = {
  key_epoch: DnsCorrelationKeyEpoch,
  capture_session_id: CaptureSessionId,
  ordered_question_count: PositiveBoundedU16,
  commitment: HmacSha256Value,
}

DnsProjectedQuestionVectorV1 =
  BoundedNonEmptyVector<DnsQuestionV1>

DnsDecodedSemanticRoleV1 =
  | Query
  | Response

DnsDecodedSemanticObservationV1 = {
  observation_context_digest:
    Digest(Arch004ObservationContextV1::PassiveObserver),
  boundary_evidence_ref: DnsPlaintextBoundaryEvidenceRefV1 {
    body.classification: Exact(Decoded),
  },
  family: AddressFamilyV1,
  transport: DnsTransportV1,
  role: DnsDecodedSemanticRoleV1,
  wire_id: U16,
  opcode: DnsOpcodeV1,
  correlation_question_commitment: DnsCorrelationQuestionCommitmentV1,
  projected_questions_digest: Digest(DnsProjectedQuestionVectorV1),
  response_summary?: DnsResponseSummaryV1,
  observed_at: MonotonicInstant,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

DnsDecodedSemanticEvidenceRefV1 = {
  observation: DnsDecodedSemanticObservationV1,
  observation_digest: Digest(DnsDecodedSemanticObservationV1),
}

DnsPlaintextMessageConsumptionKeyV1 = {
  lease_binding: Arch004PlanLeaseFenceBindingV1,
  host_association_key: DnsPlaintextHostAssociationKeyV1,
  message_key: DnsPlaintextBoundaryMessageKeyV1,
}

DnsPlaintextMessageConsumptionOwnerV1 =
  | QueryChain {
      boundary_evidence_ref: DnsPlaintextBoundaryEvidenceRefV1,
      semantic_observation_digest: Digest(DnsDecodedSemanticObservationV1),
      transaction_id: DnsTransactionId,
      initial_revision_digest: Digest(DnsTransactionV1 { revision: 0 }),
    }
  | MatchedCompletion {
      boundary_evidence_ref: DnsPlaintextBoundaryEvidenceRefV1,
      semantic_observation_digest: Digest(DnsDecodedSemanticObservationV1),
      transaction_id: DnsTransactionId,
      matched_revision_digest:
        Digest(DnsTransactionV1 {
          payload: Decoded(CorrelatableQuery(MatchedResponse)),
        }),
    }
  | UnmatchedTransaction {
      boundary_evidence_ref: DnsPlaintextBoundaryEvidenceRefV1,
      semantic_observation_digest: Digest(DnsDecodedSemanticObservationV1),
      transaction_id: DnsTransactionId,
      initial_revision_digest:
        Digest(DnsTransactionV1 {
          revision: 0,
          payload: Decoded(UnmatchedResponse),
        }),
    }
  | DecodeOpaqueTerminal {
      boundary_evidence_ref: DnsPlaintextBoundaryEvidenceRefV1 {
        body.classification: Exact(DecodeOpaque),
      },
      transaction_id: DnsTransactionId,
      initial_revision_digest:
        Digest(DnsTransactionV1 {
          revision: 0,
          payload: DecodeOpaque,
        }),
    }
  | MalformedTerminal {
      boundary_evidence_ref: DnsPlaintextBoundaryEvidenceRefV1 {
        body.classification: Exact(Malformed),
      },
      transaction_id: DnsTransactionId,
      initial_revision_digest:
        Digest(DnsTransactionV1 {
          revision: 0,
          payload: Malformed,
        }),
    }

DnsPlaintextMessageConsumptionEntryV1 = {
  key: DnsPlaintextMessageConsumptionKeyV1,
  owner: DnsPlaintextMessageConsumptionOwnerV1,
}

DnsCorrelationLookupKeyV1 =
  | Udp {
      host_association_key: DnsHostAssociationKeyV1::UdpDatagramFlow,
      wire_id: U16,
      opcode: DnsOpcodeV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | Tcp {
      host_association_key: DnsHostAssociationKeyV1::TcpConnection,
      wire_id: U16,
      opcode: DnsOpcodeV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | DotPlaintextHook {
      host_association_key: DnsHostAssociationKeyV1::DotConnection,
      wire_id: U16,
      opcode: DnsOpcodeV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | DohPlaintextHook {
      host_association_key: DnsHostAssociationKeyV1::DohHttpTransaction,
      opcode: DnsOpcodeV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | DoqPlaintextHook {
      host_association_key: DnsHostAssociationKeyV1::DoqStream,
      opcode: DnsOpcodeV1,
      resolver_selection: DnsPlanTimeResolverSelectionV1,
    }
  | RuntimeResolverHook {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsPathBoundResolverSelectionV1,
      authenticated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
      opcode: DnsOpcodeV1,
    }
  | NativeSystemResolverHook {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_resource_identity_digest: Digest(DnsRouteResourceIdentityV1),
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsNativeSystemResolverSelectionV1,
      authenticated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
      opcode: DnsOpcodeV1,
    }

DnsDecodedCorrelationStateV1 =
  | QueryPending {
      query_observed_at: MonotonicInstant,
    }
  | MatchedResponse {
      query_observed_at: MonotonicInstant,
      response: DnsResponseSummaryV1,
      completion_evidence: DnsResponseCompletionEvidenceV1,
      response_semantic_observation_ref:
        DnsDecodedSemanticEvidenceRefV1 {
          observation.role: Exact(Response),
        },
      response_observed_at: MonotonicInstant,
      latency: NonNegativeBoundedDuration,
    }
  | QueryTimedOut {
      query_observed_at: MonotonicInstant,
      correlation_deadline: SuspendAwareDeadline,
      timed_out_at: MonotonicInstant,
    }

DnsUnmatchedResponsePayloadV1 = {
  response_context: DnsUnmatchedResponseContextV1,
  correlation_question_commitment: DnsCorrelationQuestionCommitmentV1,
  questions: BoundedNonEmptyVector<DnsQuestionV1>,
  response: DnsResponseSummaryV1,
  completion_evidence: DnsResponseCompletionEvidenceV1,
  response_semantic_observation_ref:
    DnsDecodedSemanticEvidenceRefV1 {
      observation.role: Exact(Response),
    },
  response_observed_at: MonotonicInstant,
  reason: ClosedUnmatchedResponseReasonV1,
}

DnsDecodedPayloadV1 =
  | CorrelatableQuery {
      discriminator: DnsCorrelationDiscriminatorV1,
      correlation_question_commitment: DnsCorrelationQuestionCommitmentV1,
      questions: BoundedNonEmptyVector<DnsQuestionV1>,
      query_semantic_observation_ref:
        DnsDecodedSemanticEvidenceRefV1 {
          observation.role: Exact(Query),
        },
      state: DnsDecodedCorrelationStateV1,
    }
  | UnmatchedResponse(DnsUnmatchedResponsePayloadV1)

DnsMalformedMetadataV1 = {
  family: AddressFamilyV1,
  boundary_message_key: DnsPlaintextBoundaryMessageKeyV1,
  safe_message_length?: BoundedU32,
  observed_at: MonotonicInstant,
  reason: ClosedDnsMalformedReasonV1,
  observation_ref: DnsPlaintextBoundaryEvidenceRefV1,
}

DnsDecodeOpaqueMetadataV1 = {
  family: AddressFamilyV1,
  transport: DnsTransportV1,
  boundary_message_key: DnsPlaintextBoundaryMessageKeyV1,
  safe_message_length?: BoundedU32,
  observed_at: MonotonicInstant,
  reason: ClosedDnsDecodeOpaqueReasonV1,
  observation_ref: DnsPlaintextBoundaryEvidenceRefV1,
}

DnsObservationPayloadV1 =
  | Decoded(DnsDecodedPayloadV1)
  | DecodeOpaque(DnsDecodeOpaqueMetadataV1)
  | Malformed(DnsMalformedMetadataV1)

DnsTransactionOpaqueReasonV1 =
  | DecodeOpaque(ClosedDnsDecodeOpaqueReasonV1)

DnsTransactionObservationClassV1 =
  | ObservedPlaintext {
      source: DnsPlaintextDecoder | RuntimeProtectedHook |
        NativeSystemResolverHook,
      observed_at: MonotonicInstant,
      evidence_ref: DnsPlaintextBoundaryEvidenceRefV1,
    }
  | Opaque { reason: DnsTransactionOpaqueReasonV1 }

DnsTruncatedRetryResolverAuthorityCoreV1 =
  | FlowProbeRuntime {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      protected_config_digest: Digest,
    }
  | NativeSystem {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_stable_identity_digest: Digest(DnsRouteStableIdentityV1),
    }

DnsTruncatedRetryResolverCoreV1 = {
  resolver_dependency_descriptor_digest:
    Digest(ResolverDependencyDescriptorV1),
  use_site: Arch004ResolverUseSiteV1,
  resolver_actor_id: EgressActorV1.actor_id,
  resolver_authority: DnsTruncatedRetryResolverAuthorityCoreV1,
  selected_endpoint_identity_digest: Digest(EndpointIdentityV1),
  family: AddressFamilyV1,
  network_scope: NetworkScope,
  egress_selection_safe_digest: Digest(SafeEgressSelectionV1),
}

DnsTransactionLineageV1 =
  | Original
  | RetransmissionOf {
      prior_transaction_id: DnsTransactionId,
      prior_revision_digest: Digest(DnsTransactionV1),
      lineage_depth: PositiveBoundedU16,
    }
  | TruncatedRetryOf {
      prior_transaction_id: DnsTransactionId,
      prior_terminal_digest: Digest(DnsTransactionV1),
      logical_resolver_core_digest:
        Digest(DnsTruncatedRetryResolverCoreV1),
      lineage_depth: PositiveBoundedU16,
    }

DnsHostAssociationKeyV1 =
  | UdpDatagramFlow {
      flow_id: DatagramFlowId,
      observation_epoch: DatagramObservationEpoch,
    }
  | TcpConnection {
      host_connection_id: HostConnectionIdV1,
      connection_epoch: DnsConnectionEpochV1,
    }
  | DotConnection {
      host_connection_id: HostConnectionIdV1,
      outer_connection_epoch: DnsConnectionEpochV1,
      plaintext_hook_identity: DnsPlaintextHookIdentityV1,
    }
  | DotOuterConnection {
      host_connection_id: HostConnectionIdV1,
      outer_connection_epoch: DnsConnectionEpochV1,
    }
  | DohHttpTransaction {
      host_connection_id: HostConnectionIdV1,
      outer_connection_epoch: DnsConnectionEpochV1,
      http_transaction_id: HostHttpTransactionIdV1,
      http_carrier: DnsDecodedHttpCarrierV1,
      plaintext_hook_identity: DnsPlaintextHookIdentityV1,
    }
  | DohOuterConnection {
      host_connection_id: HostConnectionIdV1,
      outer_connection_epoch: DnsConnectionEpochV1,
    }
  | DoqStream {
      host_connection_id: HostConnectionIdV1,
      quic_connection_epoch: DnsConnectionEpochV1,
      stream_id: QuicStreamIdV1,
      plaintext_hook_identity: DnsPlaintextHookIdentityV1,
    }
  | DoqOuterConnection {
      host_connection_id: HostConnectionIdV1,
      quic_connection_epoch: DnsConnectionEpochV1,
    }
  | RuntimeResolverRequest {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsPathBoundResolverSelectionV1,
      authenticated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
    }
  | RuntimeResolverResponse {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsPathBoundResolverSelectionV1,
      correlated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
      authenticated_response_token_digest:
        AuthenticatedDnsResponseTokenDigestV1,
    }
  | NativeSystemResolverRequest {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_resource_identity_digest: Digest(DnsRouteResourceIdentityV1),
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsNativeSystemResolverSelectionV1,
      authenticated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
    }
  | NativeSystemResolverResponse {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_resource_identity_digest: Digest(DnsRouteResourceIdentityV1),
      family: AddressFamilyV1,
      semantic_transport: DnsTransportV1,
      selection: DnsNativeSystemResolverSelectionV1,
      correlated_query_token_digest:
        AuthenticatedDnsQueryTokenDigestV1,
      authenticated_response_token_digest:
        AuthenticatedDnsResponseTokenDigestV1,
    }

DnsPlaintextHostAssociationKeyV1 =
  DnsHostAssociationKeyV1::{
    UdpDatagramFlow | TcpConnection | DotConnection |
    DohHttpTransaction | DoqStream | RuntimeResolverRequest |
    RuntimeResolverResponse | NativeSystemResolverRequest |
    NativeSystemResolverResponse
  }

DnsEncryptedOuterHostAssociationKeyV1 =
  DnsHostAssociationKeyV1::{
    DotOuterConnection | DohOuterConnection | DoqOuterConnection
  }

OuterEpochProjection(
  DnsHostAssociationKeyV1::DotOuterConnection {
    outer_connection_epoch, .. }) = outer_connection_epoch
OuterEpochProjection(
  DnsHostAssociationKeyV1::DohOuterConnection {
    outer_connection_epoch, .. }) = outer_connection_epoch
OuterEpochProjection(
  DnsHostAssociationKeyV1::DoqOuterConnection {
    quic_connection_epoch, .. }) = quic_connection_epoch

PlaintextOuterAssociationProjection(
  DnsHostAssociationKeyV1::DotConnection {
    host_connection_id, outer_connection_epoch, .. }) =
  DnsHostAssociationKeyV1::DotOuterConnection {
    host_connection_id, outer_connection_epoch }
PlaintextOuterAssociationProjection(
  DnsHostAssociationKeyV1::DohHttpTransaction {
    host_connection_id, outer_connection_epoch, .. }) =
  DnsHostAssociationKeyV1::DohOuterConnection {
    host_connection_id, outer_connection_epoch }
PlaintextOuterAssociationProjection(
  DnsHostAssociationKeyV1::DoqStream {
    host_connection_id, quic_connection_epoch, .. }) =
  DnsHostAssociationKeyV1::DoqOuterConnection {
    host_connection_id, quic_connection_epoch }

The encrypted outer association variant is closed by transport:
`Tls -> DotOuterConnection`, `Https -> DohOuterConnection`, and
`Quic -> DoqOuterConnection`. No other key/transport pair has an outer-epoch
projection.

DnsHostAssociationV1 = {
  key: DnsHostAssociationKeyV1,
  association_observation_ref: DnsHostAssociationEvidenceRefV1,
}

DnsTransactionV1 = {
  transaction_id: DnsTransactionId,
  revision: U64,
  predecessor_digest?: Digest(DnsTransactionV1),
  reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  creation_ordinal: MonotonicSequence,
  host_association: DnsHostAssociationV1 {
    key: DnsPlaintextHostAssociationKeyV1,
  },
  family: AddressFamilyV1,
  transport: DnsTransportV1,
  https_carrier?: DnsHttpCarrierV1,
  visibility_mechanism: DnsObservedVisibilityMechanismV1,
  observation: DnsTransactionObservationClassV1,
  resolver: ResolverIdentityV1,
  lineage: DnsTransactionLineageV1,
  retention_mode: DnsNameRetentionModeV1,
  payload: DnsObservationPayloadV1,
  extension_version: 1,
}
```

The payload/mechanism matrix is closed:

| Visibility mechanism | Permitted payload |
| --- | --- |
| `NativeConfigured`, `Port53Hijacked`, `MetadataObserved` | `Decoded` after a complete bounded parse, `DecodeOpaque` when an authenticated plaintext decoder cannot finish within the sealed bound, or `Malformed` after an authenticated bounded parser proves malformed input |

`host_association` is mandatory. A runtime-resolver `CorrelatableQuery`
(pending, matched, or timed out) requires `RuntimeResolverRequest`; a native
system query requires `NativeSystemResolverRequest`. Each is byte-identical to
its discriminator and resolver identity in runtime/backend, resolver or stable
scope, route resource, family, semantic transport, complete selection proof and
authenticated query-token digest. A corresponding `UnmatchedResponse` requires
the same-family `RuntimeResolverResponse` or `NativeSystemResolverResponse` and
is byte-identical to `completion.response_host_association`. A matched query
retains its immutable request association; its completion separately carries
the response association. The two role tags and tokens differ, while their
runtime/resolver or backend/scope/route, family, transport and selection core
are byte-identical; the response association additionally repeats the exact
authenticated query-token digest used by the lookup key. Request and response associations are not
interchangeable or required to have the same variant. A non-native plaintext `Decoded`, `DecodeOpaque`, or
`Malformed` record follows transport: `PlainUdp -> UdpDatagramFlow`, `PlainTcp
-> TcpConnection`, `Tls -> DotConnection`, `Https -> DohHttpTransaction`, and
`Quic -> DoqStream`. Outer-only TLS/HTTPS/QUIC evidence never creates a
`DnsTransactionV1` and its outer-connection-only association key is not in the
transaction key subtype.

The separate `DnsEncryptedOuterReadback` exists only for the signed capability
status of an exact planned resolver dependency. It uses the matching
`DotOuterConnection`, `DohOuterConnection`, or `DoqOuterConnection`, repeats
`EncryptedOuter { outer_observation_id, path_selection }`, family/transport,
first/last times, bounded byte count and complete typed plaintext census, and
keeps endpoint data in the registered host connection. Its `SelectedPath`
contains the exact path-bound resolver set/member/ordinal/endpoint selection and resolves
the exact sealed `EncryptedOpaqueOnSelectedPath` cell. The selected
path's pure `outer_association_key` equals the outer read-back key. Its socket-
child and tag-13 proof digests are exactly the child and passed path proof
resolved by the cell's `StreamPath`. Those roots repeat the cell/outer
plan, generation, lease/fence, actor, factory, family, network scope, endpoint/
path, route/interface, exclusion root and safe-egress projection. This binds the
exact host connection/epoch to the selected resolver path without requiring the
ordinary connection to reuse the tag-13 preactivation probe socket or epoch.

Before finalizing that status, Capture Core closes a complete census barrier
over every registered plaintext decoder/hook stream for the exact outer
association, identity, epoch, selected resolver path and observation window.
The embedded snapshot/vector/roots/counts satisfy the replay rules above; a
free root or signed zero is insufficient. The following values are
byte-identical, where `census = readback.zero_plaintext_census` and
`context = ResolvePassiveObserver(readback.context_digest)`:

```text
readback.host_association_key =
  readback.message_key.path_selection.outer_association_key =
  census.target.association_key
OuterEpochProjection(readback.host_association_key) =
  census.target.connection_epoch
Digest(readback.message_key.path_selection) =
  census.target.selected_path_digest
readback.message_key.path_selection.resolver_selection =
  census.target.resolver_selection
readback.message_key.outer_observation_id = readback.outer_identity =
  census.target.outer_identity =
  Digest(DnsEncryptedOuterIdentityProjectionV1 {
    association_key: census.target.association_key,
    connection_epoch: census.target.connection_epoch,
    family: census.target.family,
    transport: census.target.transport,
    selected_path_digest: census.target.selected_path_digest,
  })
readback.family = census.target.family
readback.transport = census.target.transport
readback.observed_at = census.window_start
readback.last_observed_at = census.window_end
context.plaintext_boundary_registry_snapshot_digest =
  census.registry_snapshot_digest
census.registry_snapshot_digest = Digest(census.registry_snapshot)
context.lease.binding = census.registry_snapshot.lease_binding
context.lease.expires_at = census.registry_snapshot.expires_at
context.observer_instance_id =
  census.registry_snapshot.registry_owner_observer_instance_id
context.component_instance_id =
  census.registry_snapshot.registry_owner_component_instance_id
context.decoder_build = census.registry_snapshot.registry_owner_build
```

The consuming `EncryptedOpaqueOnSelectedPath` cell's
`dns_observer_active_state` resolves the same `dns.observer.v1` plan and a
current `DnsObserverResourceImageV1::Running`. Its plan digest/lease binding
equal the census snapshot; its resource identity decoder/component/build equal
the snapshot owner; and its Running image's decoder/build, registry-spec digest
and limit-set digest equal the plan body, snapshot and passive context. A
sibling, stopped, prior-lease or differently registered observer cannot
authorize the status.

The context and registry snapshot repeat the same installation, session,
generation, prepared plan, lease, epoch, fence, registry owner and expiry.
Every registration activates no later than `snapshot.frozen_at`, and
`context.lease.observed_at <= snapshot.frozen_at <= observed_at <=
last_observed_at <= census.finalized_at <= context.lease.expires_at`; all
census barrier acknowledgements are after `last_observed_at` and at or before
finalization. The registry snapshot is frozen before the window starts and
unchanged through finalization. Both the checked
matching-plaintext sum and the unresolved-selected-path sum are exactly zero.
A missing/incomplete census, a matching or unresolved-candidate plaintext leaf, a passive
`NoResolverScope` connection, ordinary HTTPS/QUIC, or a later producer guess is
generic host metadata or an `Unavailable` capability cell, never encrypted DNS
status. The singleton `EncryptedOpaque` capability therefore means only
“planned resolver path observed, no authenticated plaintext DNS boundary in the
closed window”; it is not a DNS transaction or decoded visibility claim.

The selected path contains only the pure outer-association key and accepted
tag-31/tag-13 root digests; it carries no host-association evidence reference,
matrix/cell observation, outer-leaf, census, transaction or normalized-flow-
extension digest. The dependency direction is one-way from accepted plan/ARCH-
002 roots through plaintext leaves and census to the outer leaf; the later cell
observation compares the plan-time spec and typed path one way. A sibling
cell/path, outer-association-key splice, or outer leaf from another association is
invalid. An unavailable capability or resolver
path emits no `DnsTransactionV1`; its typed matrix/member observation and
bounded counter/status surface are authoritative. Every
connection epoch, HTTP transaction, QUIC stream, hook, resolver token, carrier,
outer observation, and UDP flow value must equal the corresponding
discriminator, payload observation, and completion evidence. The association
key must be byte-identical to the leaf `DnsHostAssociationReadback` key named by
the association reference; that leaf cannot point to
the containing transaction or a descendant. A missing, cross-flow, cross-
connection, cross-stream, or implementation-private association is invalid.
`DnsTransactionV1.family` is byte-identical to the family resolved by its host
flow/connection object and every discriminator, completion, plaintext message
key and resolver member that carries family. UDP endpoint identity is not
duplicated in the discriminator: the registered `DatagramFlowV1` supplies its
application/network endpoints and the resolver branch supplies the exact
selected or observed resolver endpoint. Native query/response keys and
tokens carry it explicitly; a token digest alone cannot supply or change
family.

`DnsTransactionFamilyProjectionV1(txn)` is the total function `txn.family`
validated by the following branch equalities: UDP requires its datagram flow,
resolver evidence and every occurrence to use that family; TCP/DoT/DoH/
DoQ requires the current normalized host connection (and HTTP transaction or
QUIC stream child) to use it; a native hook additionally requires query
discriminator, response completion when present, host-association key,
plaintext message keys and runtime resolver evidence to repeat it. Opaque,
malformed, pending, matched, timed-out and unmatched-response
variants all use the same projection. Two different repeated families, or a
branch with no resolving host object/native field, is structurally invalid
rather than producer-selected.

If a producer cannot construct an exact registered host association, it creates
no `DnsTransactionV1`; it updates only the applicable bounded unavailable
capability/counter. Later discovery of an association starts a fresh transaction
and never rewrites a previously unassociated pseudo-record.

`DecodeOpaque` and `Malformed` have no fields capable of
serializing a name, qtype, qclass, wire ID, response code, correlation state, or
latency. A decoder cannot combine an opaque mechanism with a
decoded payload. `Malformed` emits only its closed reason and safe bounded outer
metadata; `DecodeOpaque` emits only its closed resource/decoder reason and safe
plaintext-boundary metadata. Partial parse products are discarded in both.

`Decoded` and `Malformed` require an `ObservedPlaintext` registered plaintext-
boundary or decoder-attempt class respectively. Its source and evidence-body
`producer_source` are byte-identical, and the signed boundary classification is
exactly `Decoded` or `Malformed`. `DecodeOpaque` requires `Opaque` plus an
authenticated registered plaintext decoder attempt whose signed classification
is exactly `DecodeOpaque`; its class reason is exactly
`DecodeOpaque(payload.reason)`. An inferred or
unavailable class has no encoding in
`DnsTransactionObservationClassV1` and cannot authorize a decoded payload,
exact name, or correlation. A mismatched class/payload pair is invalid.

DNS plaintext evidence has one exact message-key projection. UDP query and
response refs use `UdpQuery(query_occurrence_id)` and
`UdpResponse(response_occurrence_id)` from their respective record. TCP/DoT
use `StreamQuery`/`StreamResponse` with the exact connection epoch and framed
sequence. DoH uses `HttpQuery`/`HttpResponse` with the exact HTTP transaction
and ordinal. DoQ uses `QuicQuery(stream,0)`/`QuicResponse(stream,1)`; its
completion additionally resolves `DnsQuicFinReadback` with the same
`DoqStream` association, stream, response ordinal, server role, context, and
observation time. Runtime hooks use
`RuntimeResolverQuery`/`RuntimeResolverResponse`; native-system hooks use
`NativeSystemResolverQuery`/`NativeSystemResolverResponse`. Each body repeats
the exact runtime/resolver or backend/scope/route resource, family, complete
path-bound or no-binding selection, transaction transport and role-appropriate
authenticated token. Generic and query bodies repeat the transaction
host-association key. A matched runtime/native response body instead repeats
`completion.response_host_association`; for an unmatched response that value is
also the transaction association. Their stable cores are exact as defined
above, and the response boundary/completion/association all repeat the same
correlated query-token digest. A query ref to response
bytes, another frame/HTTP transaction/stream/token, a generic QUIC FIN, or a
source/body mismatch is invalid.

A `Decoded` payload requires path-bound `FlowProbeRuntimeResolver` or
`NativeSystemResolver`; no-binding
`NativeSystemResolverNoBinding`; or passive `ObservedResolverEndpoint`, with
the exact current signed matrix/cell and host/path evidence required by that
variant. Only the path-bound variants assert selected-route identity.
They exist only for a binding member whose cell is `NoBlockingReason`, which
already requires all six claims `Proven`; a blocked
`MetadataObservedOnSelectedPath` or passive observation cannot reuse that
member merely because its decoder saw bytes. Such visibility may emit an
`ObservedResolverEndpoint` only through an independently valid
`NoResolverScope` cell and tag-`0x4007` host observation; otherwise it emits no
DNS transaction rather than inventing path authority.
`NativeSystemResolver` and `NativeSystemResolverNoBinding` may be decoded only
for `PlainUdp`, `PlainTcp`, or `Tls`, using the matching closed native-system
pair. Native-system `Https`/`Quic` records are opaque in V1 or produce no DNS
transaction when the required observation is unavailable; they cannot borrow a
generic decoder/runtime producer or fabricated DoQ FIN. `ResolverOpaque`
cannot produce decoded DNS and may accompany only the opaque/malformed branches
defined above. It cannot be promoted to a routed, intercepted, or decoded
claim. V1 defines no producer-asserted DNS-transaction unavailable payload: if
the selected capability, resolver path, boundary, or exact host association is
unavailable, no DNS transaction is emitted; only the typed capability/member
observation and bounded counter/status surface change.

DNS transaction records are immutable append-only revisions with exact digest
`SHA-256("FlowProbe.Dns.Transaction.v1\0" || deterministic_cbor(record))`.
Revision zero has no predecessor. A `CorrelatableQuery` revision zero is exactly
`QueryPending`; `MatchedResponse` and `QueryTimedOut` are legal only as the
revision-one successor of that exact pending predecessor. `UnmatchedResponse`,
`DecodeOpaque`, and `Malformed` are exactly revision zero and terminal. A
successor has revision exactly one greater,
names the exact predecessor digest, and preserves transaction ID, creation
ordinal, reserved-capacity-state digest, host association, plan/fence,
transport/carrier, mechanism, the complete observation class/evidence ref,
resolver, lineage, retention authority,
and the complete `CorrelatableQuery` discriminator, commitment, questions,
query semantic observation ref and signed `query_observed_at`. A successor
cannot change any query field or query evidence. A matched successor adds one
response semantic observation and transport completion whose boundary ref,
response summary and signed time are exact; a timed-out successor adds only the
derived deadline and terminal time. `DnsResponseCompletionEvidenceV1` owns the
canonical response boundary reference; the signed response semantic observation
embeds that byte-identical reference. No response occurrence or framing field
enters or rewrites the immutable query discriminator. The only state successors are
`CorrelatableQuery(QueryPending) -> CorrelatableQuery(MatchedResponse)` and
`CorrelatableQuery(QueryPending) -> CorrelatableQuery(QueryTimedOut)`.
`UnmatchedResponse`, every other decoded terminal, and every decode-opaque or
malformed payload has no successor. Only the highest valid
descendant is current; a fork, delayed pending ancestor, competing terminal, or
terminal-to-pending transition is invalid and cannot overwrite current state.

The correlation owner linearizes a successor with compare-and-append on the
exact predecessor digest. Exactly one of a racing response and timeout can win;
the loser cannot fork the chain. A response observed after a committed timeout
is a new terminal `UnmatchedResponse` transaction with its own ID and occurrence
evidence.

The same storage transaction also compare-and-inserts the derived
`DnsPlaintextMessageConsumptionEntryV1`. Its key is the resolved boundary
context's complete lease binding plus the body host-association and message key;
it excludes producer, registry stream/ordinal, classification, semantic digest,
transaction ID and creation ordinal. Thus the same canonical DNS message has
one outcome even if another registered producer signs another boundary leaf.

Before capacity admission, transaction-ID or creation-ordinal allocation,
pending-table lookup, timeout evaluation, or any other mutable operation, the
correlation owner derives that canonical consumption key and performs one
linearizable index preflight. If no entry exists, normal query, response,
decode-opaque, or malformed processing may continue. If an entry exists, its
owner's complete boundary evidence ref and, for a decoded owner, semantic
observation digest and role/classification MUST equal the incoming request
byte-for-byte. Exact equality is response-loss replay and immediately returns
the owner's original transaction ID, revision digest, terminal/matched result,
and prior success outcome without rerunning lookup, CAS, allocation, charging,
or append. Any difference under the same key is a conflict with no mutation.
In particular, a retry of a response already owned by `MatchedCompletion`
returns that matched successor even after the pending query has left the
pending table; it can never fall through to create `UnmatchedTransaction`.

A query message has exactly one `QueryChain` owner and every successor preserves
that owner, boundary ref and semantic digest. A response message is consumed
exactly once by one `MatchedCompletion` or one `UnmatchedTransaction`, never
both. `DecodeOpaqueTerminal` and `MalformedTerminal` consume the same key space,
so a message cannot equivocate between either terminal and `Decoded`. For a
decoded owner, semantic role equals the query/response message-key variant, the
semantic observation embeds the owner's byte-identical boundary ref, and the
owner transaction revision carries both. For every owner, the boundary body
lease/association/message key derives the index key and its classification
matches the owner variant. Another boundary ref, semantic digest,
producer/ordinal, owner request, classification or outcome under a pre-existing
key is a conflict with no transaction/index change; caller-proposed transaction
IDs and creation ordinals are ignored on exact replay and cannot replace the
stored result. The unique index is charged as
`DnsCorrelationEntry`, transfers with retained transaction metadata, and is
released only when the entire chain, source evidence and accepting lease are
unreachable. Thus pruning cannot make an otherwise still-valid signed boundary
replayable.

The reusable 16-bit DNS wire ID is never a transaction ID. Correlation first
derives the closed `DnsCorrelationLookupKeyV1`, then requires byte-for-byte
equality of the transient ordered canonical question tuples. It happens before
any privacy projection. Query occurrence IDs, query frame ordinals and response
occurrence/frame ordinals identify evidence but are deliberately excluded from
the shared lookup key because the opposite message cannot reproduce them.
For UDP/TCP/DoT the key is the exact signed host-association key, parsed wire ID,
opcode and resolver selection. DoH uses its exact HTTP transaction/hook, opcode
and selection; DoQ uses its exact connection/stream/hook, opcode and selection.
Runtime/native responses repeat the authenticated query-token digest in their
completion, response host key and response boundary key; that value plus the
stable runtime/resolver or backend/scope/route/family/transport/selection core
and opcode is the shared key. The query discriminator and query semantic leaf
derive one byte-identical key; the response boundary, completion and response
semantic leaf derive the other. An unmatched response's `response_context`
carries the exact byte-for-byte projection of every field it owns from that
response key; fields absent from the context schema, such as UDP observation
epoch or host connection ID, remain supplied by the signed response boundary
and are not invented by the context. For UDP/TCP/DoT the shared fields include
wire ID and selection; for DoH/DoQ the HTTP transaction or stream/hook and
selection; and for runtime/native the query-token digest, runtime/resolver or
backend/scope/route, family, transport and selection. The semantic leaf supplies
the exact opcode in every branch. The transaction association separately equals
the signed response boundary association. Any disagreement among these
projections is invalid.

Only after the consumption-index preflight proves the response key absent, the
atomic pending-table lookup collects current `QueryPending` records
with that exact key and transient question tuple whose derived correlation
deadline is strictly later than the signed response observation time and whose
signed query observation time is not later than that response time. Exactly one
candidate may be completed. A response timestamped before the query or an
already expired pending record is not a candidate even if its timeout successor
has not yet been appended. Zero
candidates or more than one candidate produces a separate
`UnmatchedResponse(NoMatchingPendingQuery)`; V1 never picks nearest time or a
producer-chosen candidate. The owner also authenticates the independent commitment:

```text
HMAC-SHA-256(
  session_correlation_key,
  "FlowProbe.Dns.CorrelationQuestion.v1\0" ||
  deterministic_cbor({capture_session_id,
    ordered_exact_canonical_question_name_bytes_qtype_qclass})
)
```

The session-scoped key is generated by the unprivileged correlation/privacy
owner, never enters a plan/helper/runtime/renderer/analyzer/log, and is deleted
at the capture-session retention boundary. The commitment remains available in
redacted and ephemeral persisted records, reveals no raw name, and can match
only records from the same session/key epoch. In every `CorrelatableQuery` and
`UnmatchedResponse`, `ordered_question_count` is exactly `questions.len`,
`capture_session_id` is the transaction's registered capture session, and
`key_epoch` selects the correlation owner's current non-retired key for that
session at admission. `commitment` is the HMAC above under that exact selected
key over the displayed ordered tuple; count, session, epoch, key, and tuple are
not independently mutable. Lineage preserves this complete commitment body.
A decoded semantic observation resolves the exact signed `Decoded` plaintext
boundary and repeats its context, association/message role, family, transport
and `observed_at`. Its `wire_id` and `opcode` are the bounded parser result;
DoQ fixes the ID to zero. Its commitment is the byte-identical value above and
`projected_questions_digest` is exactly
`Digest(DnsProjectedQuestionVectorV1)` of the transaction's complete ordered
privacy-projected questions. `Query` omits `response_summary`; `Response`
requires the complete byte-identical `DnsResponseSummaryV1`, and its top-level
`opcode` equals `response_summary.opcode`. A query transaction
uses exactly one `Query` observation; matched and unmatched responses use
exactly one `Response` observation whose boundary ref equals their completion
evidence. A `CorrelatableQuery` observation class/evidence/time is exactly its
query semantic boundary and remains unchanged in every successor. An
`UnmatchedResponse` observation class/evidence/time is exactly its response
semantic boundary. `query_observed_at` and `response_observed_at` equal the corresponding
signed semantic and boundary times. Changing a wire ID, opcode, question,
RCODE, flag, count, role or time while retaining the same evidence is invalid.
A commitment match cannot replace
the exact transient equality check while plaintext is available. A mismatched,
absent, ambiguous, late, or duplicate response remains unmatched; it is never
attached by nearest time.

The payload tag encodes the DNS QR role. A `CorrelatableQuery` is admitted only
from a header with QR=0 and records its exact four-bit opcode in the query
discriminator. `MatchedResponse` and `UnmatchedResponse` admit only QR=1 and
record the response opcode in `DnsResponseSummaryV1`. A response completes a
pending query only when its opcode equals `query_opcode`; every response for
which the atomic lookup finds no exact pending discriminator plus transient
ordered-question match becomes a new `UnmatchedResponse` with the sole reason
`NoMatchingPendingQuery`. V1 does not guess whether absence was caused by an
opcode/question mismatch, timeout, duplicate, epoch, or transport mismatch.
QR inversion, a value outside `0..=15`, or an attempt to use a query occurrence
as completion evidence is invalid and cannot be coerced into another state.

Correlation-key rotation first times out or closes every pending transaction
under the old epoch and starts a new epoch; matching and lineage never cross
epochs. The old secret is retained only through the bounded close/projection
operation and is then zeroized.

Lineage is a separate acyclic predecessor graph. A lineage edge names a
strictly lower creation ordinal, cannot name self or a descendant, and must
remain within `max_dns_retransmission_links`. Every edge preserves capture
session, family, `NetworkScope`, exact `Digest(SafeEgressSelectionV1)` and
correlation-question commitment. `RetransmissionOf` additionally preserves the
complete resolver identity and transport and uses a new transaction and
occurrence ID.
`TruncatedRetryOf` requires the named terminal predecessor to be decoded
`PlainUdp/MatchedResponse` with `truncated=true`; the new transaction is
`PlainTcp`, is path-bound, uses a distinct current PlainTcp binding member/cell,
and has a new ID. Both predecessor and successor resolve the byte-identical
`DnsTruncatedRetryResolverCoreV1` named by the lineage digest: descriptor/use
site/actor, closed resolver authority, selected endpoint,
family, network scope and egress are unchanged, while transport-specific
set/member/observation and
socket evidence are required to change from PlainUdp to PlainTcp. No-binding
native/passive identities cannot encode this V1 lineage. A
forward edge, cycle, excessive depth, unrelated question, logical resolver-core change,
or non-truncated predecessor is invalid. One transaction is never rewritten
from UDP to TCP.

The authority projection is total over the two path-bound success identities.
For `FlowProbeRuntimeResolver` it repeats the selected member's runtime instance
and the outer resolver instance/config digest; both transactions resolve those
values through their current `P/H` route evidence. For
`NativeSystemResolver` it repeats the outer backend/scope and
`Digest(M.resolver_resource_identity.stable_identity)`. The authority variant
and every field are byte-identical across the edge. Changing runtime instance,
resolver instance/config, native backend/scope, stable interface/link/service,
or resolver kind is a logical resolver-core change even when the selected
endpoint happens to match.

TCP, DoT, and DoQ framing is bounded before allocation. DoH correlation uses the
host HTTP transaction identity, not DNS ID zero or stream ordering guesses.
`https_carrier` is mandatory only for `Https` and omitted for every other
transport. A `DohPlaintextHook` decoded transaction requires a
`DnsDecodedHttpCarrierV1` that equals its `DohHttpTransaction` host association;
`HttpCarrierUnavailable` is legal only for a native-runtime or opaque record
whose boundary does not expose a host HTTP carrier.

A DoH plaintext decoder accepts only a complete bounded RFC 8484 DNS message
from a registered host HTTP transaction: POST requires the accepted DNS message
media type, while GET requires one bounded unpadded base64url `dns` parameter
with no ambiguous duplicate. Unsupported methods, media types, encodings,
partial bodies, and over-bound inputs are opaque. The transient message bytes
are released after metadata parsing and are not persisted by this contract.
HTTP/1.1, HTTP/2, and HTTP/3 use the same rule and retain their exact carrier.

A decoded DoQ transaction additionally requires the closed fields carried by
its `DoqPlaintextHook` discriminator and completion/context variants. The
resolver identity is either a path-bound binding-set/member/authenticated Ready
observation or a `NoResolverScope` `ObservedResolverEndpoint` with the exact
tag-`0x4007` hook-bearing DoQ association; the two branches are not
interchangeable. ALPN is exactly `doq`; the stream is client-initiated
bidirectional and carries exactly one ordinal-zero query plus at most one
ordinal-one response; every DNS message ID is zero; framing is the bounded RFC
9250 two-octet form; and QUIC datagrams/unidirectional streams are false. The
typed ordinal-zero client-FIN ref is mandatory for the query. A matched or
unmatched decoded response additionally carries the byte-equal stream and the
typed ordinal-one server-FIN ref. Both FIN leaves repeat the same hook-bearing
DoQ host association, connection epoch, stream, context and observed time.

A matched response requires the response fields and server FIN; a pending query
omits both. A second query/response on the stream, nonzero DNS ID, missing or
different ALPN, server-initiated/unidirectional stream, QUIC datagram, cross-
stream pairing, trailing frame, unauthenticated peer, or resolver/association mismatch
is never decoded DoQ. It becomes bounded `Malformed` when authenticated
plaintext proves malformed input. With no authenticated plaintext, it creates
no DNS transaction; an exact selected planned resolver path may separately
report the closed `EncryptedOpaque` capability status above. Generic QUIC
remains generic QUIC.

An observed query or unmatched decoded response has between one and the plan's
maximum number of questions. `MatchedResponse` requires all response fields,
the transport-matching `DnsResponseCompletionEvidenceV1`, exact opcode
equality, and one comparable monotonic/boot/suspend domain;
`latency = response_observed_at - query_observed_at` exactly, and the signed
response time is strictly earlier than the query's derived correlation deadline.
Pending and
timed-out queries have no response-completion field. A timeout's
`correlation_deadline` is exactly suspend-aware addition of the query time and
the current plan's `UdpDnsLimitSetV1.max_dns_correlation_lifetime`;
`timed_out_at >= correlation_deadline` in that same clock domain, and the
correlation owner compare-and-appends the terminal successor at
`timed_out_at`. An arbitrary/decreased deadline, an early timeout, or a
producer-selected latency is invalid. The response-evidence variant must
match the transaction transport and repeat every shared HTTP, QUIC, hook, or
resolver identity byte-for-byte. The closed variants make every other
optionality unrepresentable.

UDP matched transactions carry the query occurrence in the immutable
discriminator and the response occurrence through the canonical completion
boundary reference, repeated byte-for-byte by the signed response semantic
observation; query-pending/timed-out transactions carry only the query
occurrence, while an unmatched response carries only its response occurrence.
TCP and DoT apply the same query-versus-response ownership split to framed
sequences, with the response boundary repeated identically in the semantic
observation. Lineage is independent of
completion: a retransmission or truncated retry may itself be pending, matched,
or timed out.

## 12. Resolver identity

```text
Arch004ResolverBootstrapV1 =
  | LiteralEndpointRoot {
      endpoint_identity_digest: Digest(EndpointIdentityV1),
    }
  | PreviouslyResolvedDependency {
      predecessor_binding_set_digest:
        Digest(Arch004ResolverPathBindingSetV1),
      predecessor_member_binding_digest:
        Digest(Arch004ResolverPathBindingMemberV1),
      predecessor_member_family: AddressFamilyV1,
    }

DnsRouteResourceIdentityV1 = {
  resource_kind: ExactAscii("dns.route.v1"),
  schema_version: 1,
  stable_identity: DnsRouteStableIdentityV1,
  installation_id: InstallationId,
  session_id: SessionId,
  generation: Generation,
}

Arch004ExternalEgressVariantV1 =
  | ExternalHttp
  | ExternalHttps
  | ExternalSocks5

Arch004ResolverUseSiteV1 =
  | DirectDestination {
      field_path: ExactAscii(
        "SafeEgressSelectionV1.Direct.destination_resolution.LocalAddress.resolver_dependency"),
    }
  | ExternalProxyEndpoint {
      egress_variant: Arch004ExternalEgressVariantV1,
      field_path: ExactAscii(
        "proxy_endpoint_policy.resolver_dependency"),
    }
  | ExternalDestination {
      egress_variant: Arch004ExternalEgressVariantV1,
      field_path: ExactAscii(
        "destination_resolution.LocalAddress.resolver_dependency"),
    }
  | ActivationProbeTarget {
      probe_target_profile_digest: Digest(ProbeTargetProfileV1),
      target_id: ProbeTargetProfileV1.target_id,
      target_ordinal: PositiveBoundedU16,
      field_path: ExactAscii(
        "target_resolution_policy.FollowLocalAddress.resolver_dependency"),
    }
  | TlsRevocationResponder {
      proxy_tls_policy_descriptor_digest:
        Digest(ProxyTlsPolicyDescriptorV1),
      field_path: ExactAscii(
        "revocation_policy.RequireFreshOcsp.responder_resolver_dependency"),
    }

Arch004ResolverPathBindingMemberV1 = {
  member_ordinal: U8,
  dependency_depth: BoundedU8,
  family: AddressFamilyV1,
  resolver_resource_identity: DnsRouteResourceIdentityV1,
  semantic_transport: DnsTransportV1,
  allowed_https_carriers?:
    SortedUniqueNonEmptyVector<DnsDecodedHttpCarrierV1, 1..=3>,
  configured_endpoint_identity_digest: Digest(EndpointIdentityV1),
  bootstrap: Arch004ResolverBootstrapV1,
  socket_factory_policy_digest: Digest(ActorSocketFactoryPolicyV1),
  exclusion_entry_digests:
    SortedUniqueNonEmptyVector<Digest(EgressExclusionEntryV1)>,
  physical_path_capability_report_digest: Digest(CapabilityReportV1),
  capability_cell_key: DnsCapabilityCellKeyV1,
}

Arch004ResolverPathBindingSetV1 = {
  installation_id: InstallationId,
  preparation_ticket_id: PreparationTicketId,
  session_id: SessionId,
  generation: Generation,
  plan_node_identity: DnsRouteResourceIdentityV1,
  network_scope: NetworkScope,
  egress_selection_safe_digest: Digest(SafeEgressSelectionV1),
  resolver_dependency_descriptor_digest:
    Digest(ResolverDependencyDescriptorV1),
  resolver_path_id: ResolverDependencyDescriptorV1.resolver_path_id,
  resolver_actor_id: ResolverDependencyDescriptorV1.resolver_actor_id,
  use_site: Arch004ResolverUseSiteV1,
  family_policy: IpFamilyPolicy,
  ordered_members:
    BoundedNonEmptyVector<Arch004ResolverPathBindingMemberV1, 1..=2>,
  exclusion_set_digest: Digest(EgressExclusionSetV1),
  baseline_anchor_digest: Digest(BaselineEgressAnchorV1),
  pending_flowprobe_tun_recursion: Prohibited,
  ambient_resolver_fallback: Prohibited,
  exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
  capability_matrix_spec_digest: Digest(DnsCapabilityMatrixV1),
  expected_observation_schema:
    ExactAscii("Arch004ResolverPathBindingSetObservationV1"),
  expected_observation_schema_version: 1,
}

Arch004ResolverBootstrapResolutionOutcomeV1 =
  | Positive {
      normalized_candidates:
        SortedUniqueNonEmptyVector<
          EndpointV1,
          1..=ResolverDependencyDescriptorV1.maximum_candidates,
          key=deterministic_cbor(EndpointIdentityProjectionV1(candidate))>,
    }
  | Negative { kind: NxDomain | NoData }

Arch004ResolverBootstrapResultV1 = {
  observation_context_digest:
    Digest(Arch004ObservationContextV1::NetworkPath),
  current_member_binding_digest:
    Digest(Arch004ResolverPathBindingMemberV1),
  resolver_dependency_descriptor_digest:
    Digest(ResolverDependencyDescriptorV1),
  use_site: Arch004ResolverUseSiteV1,
  input_endpoint_identity: EndpointIdentityV1 {
    normalized_host: Host::DnsName,
  },
  input_endpoint_identity_digest: Digest(EndpointIdentityV1),
  predecessor_binding_set_digest:
    Digest(Arch004ResolverPathBindingSetV1),
  predecessor_binding_set_observation_digest:
    Digest(Arch004ResolverPathBindingSetObservationV1),
  predecessor_member_binding_digest:
    Digest(Arch004ResolverPathBindingMemberV1),
  predecessor_member_ready_observation_digest:
    Digest(Arch004ResolverPathMemberObservationV1::Ready),
  required_family: AddressFamilyV1,
  outcome: Arch004ResolverBootstrapResolutionOutcomeV1,
  observed_at: MonotonicInstant,
  expires_at: SuspendAwareDeadline,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

Arch004ResolverReadyEndpointSourceV1 =
  | LiteralEndpointRoot {
      endpoint_identity_digest: Digest(EndpointIdentityV1),
    }
  | PreviouslyResolvedDependency {
      predecessor_binding_set_digest:
        Digest(Arch004ResolverPathBindingSetV1),
      predecessor_binding_set_observation_digest:
        Digest(Arch004ResolverPathBindingSetObservationV1),
      predecessor_member_binding_digest:
        Digest(Arch004ResolverPathBindingMemberV1),
      predecessor_member_ready_observation_digest:
        Digest(Arch004ResolverPathMemberObservationV1::Ready),
      resolution_result: Arch004ResolverBootstrapResultV1 {
        outcome: Arch004ResolverBootstrapResolutionOutcomeV1::Positive,
      },
      resolution_result_digest:
        Digest(Arch004ResolverBootstrapResultV1),
    }

ResolverBindingSetUnavailableEvidenceRefV1 =
  EgressPathProofEvidenceRefV1 |
  NoPendingTunRecursionEvidenceRefV1 |
  ResourceReadbackEvidenceRefV1 |
  PlatformCapabilityEvidenceRefV1

Arch004PredecessorResolverBootstrapEvidenceV1 = {
  current_member_binding_digest:
    Digest(Arch004ResolverPathBindingMemberV1),
  endpoint_source:
    Arch004ResolverBootstrapV1::PreviouslyResolvedDependency,
  predecessor_binding_set: Arch004ResolverPathBindingSetV1,
  predecessor_binding_set_digest:
    Digest(Arch004ResolverPathBindingSetV1),
  predecessor_binding_set_observation:
    Arch004ResolverPathBindingSetObservationV1,
  predecessor_binding_set_observation_digest:
    Digest(Arch004ResolverPathBindingSetObservationV1),
  predecessor_member_ordinal: U8,
  predecessor_member_binding_digest:
    Digest(Arch004ResolverPathBindingMemberV1),
  predecessor_member_observation_digest:
    Digest(Arch004ResolverPathMemberObservationV1),
  evaluated_at: MonotonicInstant,
}

ResolverBootstrapUnavailableEvidenceRefV1 =
  | PredecessorMemberUnavailable {
      predecessor: Arch004PredecessorResolverBootstrapEvidenceV1,
      predecessor_unavailable_reason: ResolverUnavailableReasonV1,
    }
  | PredecessorResolutionNegative {
      predecessor: Arch004PredecessorResolverBootstrapEvidenceV1,
      resolution_result: Arch004ResolverBootstrapResultV1 {
        outcome: Arch004ResolverBootstrapResolutionOutcomeV1::Negative,
      },
      resolution_result_digest:
        Digest(Arch004ResolverBootstrapResultV1),
    }
  | PredecessorResolutionExpired {
      predecessor: Arch004PredecessorResolverBootstrapEvidenceV1,
      resolution_result: Arch004ResolverBootstrapResultV1,
      resolution_result_digest:
        Digest(Arch004ResolverBootstrapResultV1),
      expired_at: SuspendAwareDeadline,
    }

Arch004ResolverMemberUnavailableCauseV1 =
  | CapabilityCellBlocked {
      capability_cell_observation_digest:
        Digest(DnsCapabilityCellObservationV1),
      cell_blocking_reason: DnsBlockingReasonV1,
    }
  | BindingSetUnavailable {
      evidence_refs:
        SortedUniqueNonEmptyVector<
          ResolverBindingSetUnavailableEvidenceRefV1, 1..=8>,
    }
  | BindingSetObservationExpired {
      expired_matrix_observation_digest:
        Digest(DnsCapabilityMatrixObservationV1),
      expired_at: SuspendAwareDeadline,
    }
  | BootstrapUnavailable {
      endpoint_source:
        Arch004ResolverBootstrapV1::PreviouslyResolvedDependency,
      evidence_refs:
        SortedUniqueNonEmptyVector<
          ResolverBootstrapUnavailableEvidenceRefV1, 1..=8>,
    }
  | NativeScopeUnavailable {
      evidence_refs:
        SortedUniqueNonEmptyVector<
          PlatformCapabilityEvidenceRefV1, 1..=4>,
    }
  | BackendUnsupported {
      evidence_refs:
        SortedUniqueNonEmptyVector<
          PlatformCapabilityEvidenceRefV1, 1..=4>,
    }

Arch004ResolverPathMemberObservationV1 =
  | Ready {
      member_binding_digest: Digest(Arch004ResolverPathBindingMemberV1),
      observation_context_digest: Digest(Arch004ObservationContextV1),
      selected_endpoint: EndpointV1,
      selected_endpoint_identity_digest: Digest(EndpointIdentityV1),
      observed_https_carrier?: DnsDecodedHttpCarrierV1,
      endpoint_source: Arch004ResolverReadyEndpointSourceV1,
      operational_socket_child_observation_digests:
        ExactVector<Digest(SocketPolicyChildObservationV1), 1>,
      exclusion_and_physical_path_observation_ref:
        EgressPathProofEvidenceRefV1,
      no_pending_tun_recursion_observation_ref:
        NoPendingTunRecursionEvidenceRefV1,
      resolver_route_active_state: Arch004ActiveResourceEvidenceV1,
      resolver_route_health_evidence_ref:
        Arch004ResourceActiveHealthEvidenceRefV1,
      capability_cell_observation_digest:
        Digest(DnsCapabilityCellObservationV1),
      authenticator: Arch004ExternalObservationAuthenticatorV1,
    }
  | Unavailable {
      member_binding_digest: Digest(Arch004ResolverPathBindingMemberV1),
      observation_context_digest: Digest(Arch004ObservationContextV1),
      cause: Arch004ResolverMemberUnavailableCauseV1,
    }

Arch004ResolverBindingSetOutcomeV1 =
  | OnlyReady { selected_member_ordinal: ExactU8(0) }
  | PreferSelected { selected_member_ordinal: U8 }
  | RequireBothReady
  | RequireBothUnavailable
  | AllUnavailable

Arch004ResolverPathBindingSetObservationV1 = {
  binding_set_digest: Digest(Arch004ResolverPathBindingSetV1),
  observation_context_digest: Digest(Arch004ObservationContextV1),
  ordered_member_observations:
    BoundedNonEmptyVector<Arch004ResolverPathMemberObservationV1, 1..=2>,
  outcome: Arch004ResolverBindingSetOutcomeV1,
  capability_matrix_observation: DnsCapabilityMatrixObservationV1,
  capability_matrix_observation_digest:
    Digest(DnsCapabilityMatrixObservationV1),
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

ObservedResolverEndpointAssociationEvidenceRefV1 =
  DnsHostAssociationEvidenceRefV1 {
    body.association_key:
      DnsHostAssociationKeyV1::UdpDatagramFlow |
      DnsHostAssociationKeyV1::TcpConnection |
      DnsHostAssociationKeyV1::DotConnection |
      DnsHostAssociationKeyV1::DohHttpTransaction |
      DnsHostAssociationKeyV1::DoqStream,
  }

DnsObservedResolverStreamHostCoreV1 = {
  host_connection_id: HostConnectionIdV1,
  connection_epoch: DnsConnectionEpochV1,
  network_scope: NetworkScope,
  family: AddressFamilyV1,
  transport: PlainTcp | Tls | Https | Quic,
  local_endpoint: EndpointV1,
  remote_endpoint: EndpointV1,
  host_core_revision: U64,
}

DnsObservedResolverHostObjectRefV1 =
  | UdpDatagramFlow {
      flow_record_ref: Arch004RecordRefV1::DatagramFlowRecord,
    }
  | StreamConnection {
      host_core: DnsObservedResolverStreamHostCoreV1 {
        transport: Exact(PlainTcp),
      },
      host_core_digest: Digest(DnsObservedResolverStreamHostCoreV1),
      storage_locator: Arch004RecordStorageLocatorV1,
    }
  | DotConnection {
      host_core: DnsObservedResolverStreamHostCoreV1 {
        transport: Exact(Tls),
      },
      host_core_digest: Digest(DnsObservedResolverStreamHostCoreV1),
      storage_locator: Arch004RecordStorageLocatorV1,
      plaintext_hook_identity: DnsPlaintextHookIdentityV1,
    }
  | DohHttpTransaction {
      host_core: DnsObservedResolverStreamHostCoreV1 {
        transport: Exact(Https),
      },
      host_core_digest: Digest(DnsObservedResolverStreamHostCoreV1),
      storage_locator: Arch004RecordStorageLocatorV1,
      http_transaction_id: HostHttpTransactionIdV1,
      http_carrier: DnsDecodedHttpCarrierV1,
      plaintext_hook_identity: DnsPlaintextHookIdentityV1,
    }
  | DoqStream {
      host_core: DnsObservedResolverStreamHostCoreV1 {
        transport: Exact(Quic),
      },
      host_core_digest: Digest(DnsObservedResolverStreamHostCoreV1),
      storage_locator: Arch004RecordStorageLocatorV1,
      stream_id: QuicStreamIdV1,
      plaintext_hook_identity: DnsPlaintextHookIdentityV1,
    }

DnsObservedResolverEndpointObservationV1 = {
  observation_context_digest: Digest(Arch004ObservationContextV1),
  host_association_evidence_ref:
    ObservedResolverEndpointAssociationEvidenceRefV1,
  host_object_ref: DnsObservedResolverHostObjectRefV1,
  network_scope: NetworkScope,
  family: AddressFamilyV1,
  transport: DnsTransportV1,
  endpoint: EndpointV1,
  endpoint_identity_digest: Digest(EndpointIdentityV1),
  observed_at: MonotonicInstant,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

DnsObservedResolverEndpointEvidenceRefV1 = {
  observation: DnsObservedResolverEndpointObservationV1,
  observation_digest: Digest(DnsObservedResolverEndpointObservationV1),
}

ResolverIdentityV1 =
  | FlowProbeRuntimeResolver {
      resolver_instance_id: DnsResolverInstanceId,
      protected_config_digest: Digest,
      selected_transport: DnsTransportV1,
      selected_member_ordinal: U8,
      resolver_path_binding_set_digest:
        Digest(Arch004ResolverPathBindingSetV1),
      resolver_path_binding_set_observation_digest:
        Digest(Arch004ResolverPathBindingSetObservationV1),
    }
  | NativeSystemResolver {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      selected_member_ordinal: U8,
      resolver_path_binding_set_digest:
        Digest(Arch004ResolverPathBindingSetV1),
      resolver_path_binding_set_observation_digest:
        Digest(Arch004ResolverPathBindingSetObservationV1),
    }
  | NativeSystemResolverNoBinding {
      backend: ClosedSystemResolverBackend,
      stable_scope: BoundedResolverScope,
      route_resource_identity: DnsRouteResourceIdentityV1,
      route_resource_identity_digest: Digest(DnsRouteResourceIdentityV1),
      capability_matrix_observation: DnsCapabilityMatrixObservationV1,
      capability_matrix_observation_digest:
        Digest(DnsCapabilityMatrixObservationV1),
      capability_cell_observation_digest:
        Digest(DnsCapabilityCellObservationV1),
    }
  | ObservedResolverEndpoint {
      observed_endpoint: EndpointV1,
      observed_endpoint_identity_digest: Digest(EndpointIdentityV1),
      resolver_endpoint_evidence_ref:
        DnsObservedResolverEndpointEvidenceRefV1,
      resolver_scope: Exact(DnsCapabilityResolverScopeV1::NoResolverScope),
      capability_matrix_observation: DnsCapabilityMatrixObservationV1,
      capability_matrix_observation_digest:
        Digest(DnsCapabilityMatrixObservationV1),
      capability_cell_observation_digest:
        Digest(DnsCapabilityCellObservationV1),
    }
  | ResolverOpaque { selection: DnsOpaqueResolverSelectionV1 }
```

The local binding/result digests are exactly:

```text
Digest(Arch004ResolverPathBindingMemberV1) =
  SHA-256("FlowProbe.Dns.ResolverPathBindingMember.v1\0" ||
    deterministic_cbor(binding_member))
Digest(Arch004ResolverPathBindingSetV1) =
  SHA-256("FlowProbe.Dns.ResolverPathBindingSet.v1\0" ||
    deterministic_cbor(binding_set))
Digest(Arch004ResolverPathMemberObservationV1) =
  SHA-256("FlowProbe.Dns.ResolverPathMemberObservation.v1\0" ||
    deterministic_cbor(member_observation))
Digest(Arch004ResolverPathBindingSetObservationV1) =
  SHA-256("FlowProbe.Dns.ResolverPathBindingSetObservation.v1\0" ||
    deterministic_cbor(observation))
```

For a `Ready` member, the signature input is exactly
`"FlowProbe.Arch004.ExternalObservation.v1\0" ||
uint16_be(Arch004ExternalObservationRootSchemaTagV1::
ResolverReadyMemberObservation) ||
uint16_be(1) || canonical_cbor(authenticator.header) ||
SHA-256(canonical_cbor(ready_variant_fixed_array_with_only_the_complete_
authenticator_field_omitted))`. The binding-set observation uses the same local
domain and exact concatenation with
`Arch004ExternalObservationRootSchemaTagV1::
ResolverPathBindingSetObservation` and
`SHA-256(canonical_cbor(set_observation_fixed_array_with_only_the_complete_
authenticator_field_omitted))`. Both signers reuse the accepted
`Arch004ExternalObservationAuthenticatorV1` key/header validation and are exactly
`RuntimeAdapter` under
the byte-identical resolver actor/runtime external-executor gate and
`NetworkPath` plan/lease/fence context. The displayed
digest is computed only after the relevant signature is attached. The set
preimage therefore covers the complete already-signed member vector, including
each cell digest and typed unavailable cause; neither signature is part of its
own preimage. A domain swap, partial member projection, unsigned replacement
cell, or signature copied between member and set is invalid.

`Arch004ResolverPathBindingSetV1` is the sole accepted ARCH-004 realization of
ARCH-002's `RequiresAcceptedArch004Binding` marker. Its descriptor, path ID,
actor, safe egress digest, baseline anchor, and network scope must equal the
enclosing accepted `ResolverDependencyDescriptorV1`, `SafeEgressSelectionV1`,
and ARCH-001 plan graph byte-for-byte. `use_site` is the exact registered root,
variant, field path, and ordinal that consumes that descriptor. For the first
four use-site variants, `family_policy` is copied from that site's accepted
field and is never inferred from the descriptor's broader `family_scope`. Each member's
capability key selects exactly one cell from the named complete matrix; `Https`
requires a non-empty sorted `allowed_https_carriers` set byte-equal to that
cell's planned `HttpsObserved` set, while other transports omit it. A ready
HTTPS member records exactly one observed carrier from that set; non-HTTPS
members omit the observation. Each member's
actor/resource, factory policy, exclusion entry/root, physical path, and the
set's limit are the same registered roots used by the plan. A parallel resolver
object or a later implementation-owned digest is invalid.

The binding set and every member are receipt/result-free candidate bodies: they contain no
`PreparedPlanId`, `PlanDigest`, socket observation, or resolution result. The
final ARCH-001 plan commits its digest and only the post-seal observation binds
the resulting prepared IDs, preventing a plan-digest or future-result cycle.
For every reachable `(ResolverDependencyDescriptorV1, Arch004ResolverUseSiteV1)`
pair, the graph contains exactly one edge from that tag-3 root and its registered
consumer root to one `Arch004ResolverPathBindingSetV1` nested in the registered
`dns.route.v1` node. `resolver_bindings` is `NoResolverDependencies` if and only
if the exact reachable-pair cardinality is zero; otherwise it is `BindingSets`
whose cardinality equals that pair count. Reusing one descriptor at several
sites creates one set per site and may therefore preserve different family
policies. The binding-set digest does not feed back into tag 1 or tag 18. A
zero/nonzero branch mismatch, missing set, extra set, duplicate-pair,
differently keyed, or unreachable set rejects plan preparation.

Accepted ARCH-002 defines no `IpFamilyPolicy` for
`RequireFreshOcsp.responder_resolver_dependency`. Consequently the registered
`TlsRevocationResponder` use site cannot construct a binding set in v0.2: its
candidate is `UnsupportedPendingArchitecture/UseSiteFamilyPolicyUnavailable`
before plan seal and sends zero resolver or OCSP bytes. It cannot borrow
`family_scope`, another use site's policy, or ambient DNS. The exact-one-set rule
above applies to every lookup-capable pair in an accepted plan; a candidate with
this unresolved use site is not such a plan.

Member expansion is deterministic from the exact consuming use site's
`IpFamilyPolicy`: `Ipv4Only=[Ipv4]`, `Ipv6Only=[Ipv6]`,
`PreferIpv4=[Ipv4,Ipv6]`, `PreferIpv6=[Ipv6,Ipv4]`, and
`RequireBoth=[Ipv4,Ipv6]`. A family with no sealed candidate may be removed only
from a `Prefer*` vector. `Ipv*Only` with its family missing and `RequireBoth`
with either family missing are unavailable before seal. A `RequireBoth` set has
exactly two members in `[Ipv4,Ipv6]` order, and its set observation is valid only
when both independently have current route, exclusion, socket-child, proof,
capability-cell, and health evidence. No single-family observation can satisfy
the set.

Every member's `member_ordinal` equals its zero-based vector position and the
observation vector is position-for-position. `OnlyReady` is legal if and only
if `family_policy` is `Ipv4Only` or `Ipv6Only` and its sole member is `Ready`.
`PreferSelected` is the only ready outcome for `PreferIpv4`/`PreferIpv6`, even
when candidate pruning left one member; it names the first `Ready` member in
policy order, every earlier member is `Unavailable`, later outcomes are
retained as observed, and at least one member is ready. `RequireBothReady` is
legal only for `RequireBoth` and requires exact
`[Ipv4 Ready, Ipv6 Ready]`; it authorizes both ordinals, but a transaction may
select only the ordinal whose member family equals that transaction family. A
`RequireBoth` set with either or both members
unavailable uses `RequireBothUnavailable`, preserves both member observations,
selects no endpoint even if its sibling remains ready, and derives failure from
the first unavailable member in `[Ipv4, Ipv6]` policy order.
`AllUnavailable` is used only for `Ipv*Only` or `Prefer*` and requires every
member unavailable. Both unavailable outcomes are terminal for the requested
resolver path and carry no producer-chosen aggregate reason. The bounded
status surface uses the `ResolverUnavailableReasonV1` deterministically
projected from the first member's typed cause in policy order. DNS claim
projection then applies the separate total mapping below; it does not pretend
the two reason enums are the same type. An unavailable outcome authorizes no
`ResolverIdentityV1` and no DNS transaction. A ready `ResolverIdentityV1` may select
only the ordinal of the outcome's allowed ready member; it cannot skip an
earlier ready preferred member or erase a required sibling.

Bootstrap is an acyclic plan dependency graph. A member is a literal endpoint
root or names a strictly earlier binding set and exact member with smaller
dependency depth. A literal member has depth zero; a predecessor member has
exactly its referenced member's depth plus one and cannot exceed
`max_resolver_bootstrap_depth`. The pre-plan bootstrap carries no future
observation digest. A `Ready` observation for `LiteralEndpointRoot` uses only
the matching literal `endpoint_source`; its digest equals the configured
endpoint root and selected endpoint identity. A `Ready` observation for
`PreviouslyResolvedDependency` uses only the matching predecessor source and
names the exact predecessor set/body digest, exact member digest, that member's
already-current `Ready` observation, and the complete signed local
`Arch004ResolverBootstrapResultV1::Positive` containing the exact selected
endpoint. The two source variants are mutually
exclusive; none of these fields is optional or inferred from a selected
address. The predecessor observation is available only after execution order
makes it current. It cannot name self, a
descendant, the pending FlowProbe TUN, an ambient resolver, or an address
obtained through the path being created. DNS names in ARCH-002 therefore remain
`UnsupportedPendingArchitecture` unless this exact binding set is sealed;
config text or a successful ambient lookup cannot satisfy the marker.

For the positive predecessor source, the current member/set evaluation time is
in the same monotonic/boot/suspend domain and satisfies
`result.observed_at <= evaluated_at <= result.expires_at`; the result context,
predecessor Ready observation and current set context have the same plan,
lease/fence and overlapping validity window. An expired result cannot authorize
`Ready` and instead uses the fixed `PredecessorResolutionExpired` failure at
that same evaluation time.

`BootstrapUnavailable` is legal only for
`PreviouslyResolvedDependency`; a literal-root route/socket failure uses
`BindingSetUnavailable`. Every bootstrap-unavailable ref carries the complete
strictly earlier predecessor set and its complete signed observation, with
digests equal to the displayed bodies. Its endpoint source, set/member digests,
member ordinal and family are byte-identical to the current member's bootstrap;
the predecessor member is at a smaller dependency depth, was published before
the current observation, and is neither the current/enclosing set nor any
descendant. `PredecessorMemberUnavailable` selects that exact predecessor
member's `Unavailable` observation and its first-cause-derived reason. The
the two result variants require that member to be the outcome-authorized current
`Ready` observation and carry the complete signed local tag-`0x4008` result
produced through it. The common `evaluated_at` equals the current member/set
evaluation time. `Negative` requires its exact negative outcome and
`result.observed_at <= evaluated_at <= result.expires_at`; `Expired` has fixed
precedence and requires
`result.observed_at <= result.expires_at = expired_at < evaluated_at`.
`PredecessorMemberUnavailable` requires
the predecessor signed set/member observation still to be current at this same
time; stale predecessor evidence has no V1 bootstrap-failure encoding. The
local result's descriptor/use site, input endpoint, family, plan/lease/fence,
predecessor set/member/Ready observation, bounded candidate outcome and
RuntimeAdapter authenticator all resolve the named predecessor path. A digest-
only result, unrelated predecessor, producer-chosen evaluation time, stale body through a non-expired
branch, or broad path/capability root cannot prove this cause.

Every local bootstrap result carries the complete registered tag-33 DNS-name
input endpoint and its canonical identity digest; it is byte-identical to the
current member's configured endpoint root. `required_family` equals the current
member family in every outcome. A positive candidate replaces only that input's
host with one canonical address (and required IPv6 zone), preserves the exact
input port, and has `candidate.family = required_family`. Candidates are
nonempty, bounded by the descriptor, and sorted uniquely by deterministic CBOR
of their endpoint-identity projections. Negative has no candidate field.
`Ready` selects exactly the first positive candidate in that canonical vector;
a duplicate/reordered address, changed port, cross-family address, noncanonical
zone, producer-selected later candidate, empty positive, or candidate-bearing
negative result is invalid.

An observation is post-seal evidence and never feeds back into the plan digest.
Every socket-child digest resolves to accepted tag-31 evidence with the exact
actor, purpose, family, selected endpoint, factory policy, egress, exclusion
root, physical route/interface, and current plan/fence. The selected endpoint
must be the literal root or a member of the bounded predecessor resolution
result selected by the closed `endpoint_source`; dependency depth is zero for
the former and exactly predecessor depth plus one for the latter.
An expired, mismatched, empty, recursive, or unregistered observation is
unavailable rather than silently retried through another resolver.

The set observation contains exactly one member observation per binding member,
in the same order, with no missing, duplicate, or extra member. A resolver
identity selects one member ordinal and endpoint while preserving the complete
set digest/observation; this selection does not erase a `RequireBoth` sibling's
readiness obligation.

For each path-bound success identity, both stored set digests resolve this one
set and observation, `selected_member_ordinal` selects an outcome-authorized
`Ready` member. Let `M=set.ordered_members[i]` and
`R=observation.ordered_member_observations[i]`. Then
`M.member_ordinal=i`, `R.member_binding_digest=Digest(M)`, and the transaction
family/transport, `M.family`/`M.semantic_transport`, `M.capability_cell_key`,
and `R.selected_endpoint.family` are exact. The ready endpoint digest is
`Digest(EndpointIdentityProjectionV1(R.selected_endpoint))`.

Let `P` be the unique registered `Arch004ResourcePlanV1` whose identity is
`DnsRoute(M.resolver_resource_identity)`, and `A` be
`R.resolver_route_active_state`. Let `H` be the exact
`Arch004ResourceHealthObservationV1` resolved by
`R.resolver_route_health_evidence_ref`. `A` proves the current published Active
lifecycle state for exactly `P`; `H.active_state_source=A`, repeats identity,
plan, lease/fence and success predicate, carries the fresh current image and
read-back set, and is unexpired at the member/set observation time. Backend and
desired state come from `P`; current image comes only from `H`, never the
historical apply after-image in `A` or the route node that merely
contains this binding set. Missing, duplicate, inactive, sibling-plan, or
matrix-only route evidence, drifted read-back, or expired health invalidates
every Ready member.

A `FlowProbeRuntimeResolver` is legal only when the
selected member's `resolver_resource_identity.stable_identity` is
`RuntimeResolver`; its `resolver_instance_id` equals
`M.resolver_resource_identity.stable_identity.resolver_instance_id`, and
its `protected_config_digest` and `selected_transport` equal both the current
active `RuntimeResolverImageV1::Present` from `H` and `P`'s
`RuntimeResolverPresent` desired state. The runtime instance/resolver instance,
configured endpoint digest and transport are byte-identical across stable
identity, backend, desired state, active image, member, runtime host association,
discriminator/completion and plaintext boundary; the source is exactly
`RuntimeProtectedHook`. Every runtime request/response/message key carries a
`DnsPathBoundResolverSelectionV1` whose set/member binding digests and ordinal
are byte-identical to `S/M/i` and whose endpoint digest is
`Digest(EndpointIdentityProjectionV1(R.selected_endpoint))`; a sibling token or
another endpoint under the same runtime instance is invalid.

A `NativeSystemResolver` is legal only for a platform route
member, and its `(backend, stable_scope)` is the exact projection below of that
member's resource identity, backend, desired state and current active route
image. Its transaction source is exactly `NativeSystemResolverHook`, and the
native host association/message keys repeat the member family and transport:

| Route stable identity | Required native backend/scope | Required image/endpoint projection |
| --- | --- | --- |
| `WindowsInterfaceDns` | `WindowsInterfaceDnsSettingsV1`; `WindowsInterface` with the same interface GUID; backend/identity repeat owned-adapter digest and member family | exactly one selected server source is owned by `P.backend.managed_fields`: `NameServer` selects only `H.observed_image.name_servers`, or `ProfileNameServer` selects only `H.observed_image.profile_name_servers`; that exact vector contains the Ready endpoint and the other/unmanaged vector cannot satisfy it |
| `LinuxResolvedLinkField` | `LinuxSystemdResolvedOwnedLinkFieldV1`; `LinuxOwnedLink` with the same namespace, owner marker and device kind; stable field is exactly `DnsEx` | current image is `DnsEx` and its endpoint vector contains the selected Ready endpoint; another managed field cannot be resolver identity |
| `LinuxNetworkManagerAppliedConnection` | `LinuxNetworkManagerAppliedConnectionV1`; `LinuxNetworkManagerConnection` with the same connection UUID and device identity | the current exact family projection selected by `M.family` contains the Ready endpoint and every UUID/device/image field agrees |

Every native-system request/response/message key repeats backend, stable scope,
`Digest(M.resolver_resource_identity)`, family and transport. Its
`selection::PathBound` is byte-identical to the resolver identity's set/
member/ordinal and Ready endpoint digest. `selection::NativeNoBinding` is legal only
with `NativeSystemResolverNoBinding` and repeats the plan-time matrix/cell spec
digests, exact cell key and native resolver scope later resolved by that
identity's complete signed matrix; it cannot appear in a path-bound identity.
Neither selection contains a set/matrix/cell observation digest, so no witness
inside the embedded matrix points back to its enclosing set observation. Thus membership
of a multi-server OS image is not enough: the authenticated query and response
must commit the exact selected endpoint for a path-bound transaction.
The outer `ResolverIdentityV1` validates its set/matrix observation digests only
after those signed bodies are complete and then compares them one-way to these
plan-time/spec selections; observation digests never enter a hook message key.

Resolver selection in transaction evidence is closed:

| Resolver identity | Required plan-time selection in discriminator, completion and every plaintext message key |
| --- | --- |
| `FlowProbeRuntimeResolver` | `PathBound` with exact `S`, `M`, `i` and Ready endpoint digest |
| path-bound `NativeSystemResolver` | the same exact `PathBound` projection |
| `NativeSystemResolverNoBinding` | `NativeNoBinding` with its matrix/cell spec digests, cell key and exact native scope |
| `ObservedResolverEndpoint` | `ObservedNoBinding` with its matrix/cell spec digests, transaction cell key and tag-`0x4007` endpoint digest |
| `ResolverOpaque` on `DecodeOpaque` or `Malformed` plaintext | `Opaque` with the exact sealed matrix/cell spec digests, cell key, scope, selected mechanism and fixed resolver reason |

The query discriminator, response completion when present, unmatched response
context, every query/response boundary key and native host-association key use
byte-identical selection bytes.
`Opaque` is legal only in a generic UDP/stream/HTTP/QUIC plaintext boundary key.
Its matrix/
cell spec digests resolve the exact plan cell; key family/transport and scope
equal the transaction, and `selected_mechanism` is byte-identical to both that
spec and `txn.visibility_mechanism`. It cannot enter a runtime/native token key
or authorize a decoded payload, correlation discriminator, response completion,
route, or positive capability claim.
`ResolverOpaqueReasonV1` has the single value
`ResolverIdentityNotObservable`; V1 does not let a producer guess whether the
missing identity was caused by encryption, proxy behavior, or redaction.
Encrypted outer capability status has no resolver identity or transaction
selection. Cross-branch substitution, a sibling member/spec/endpoint, an opaque
reason or mechanism mismatch, or query/response selection drift is invalid.

All resolver transaction evidence also shares one lease projection. Its
Datagram/PassiveObserver context, host-association leaf, optional tag-`0x4007`
observation, set observation and capability matrix repeat installation,
session, generation, prepared-plan/plan digest, lease epoch/fence, boot/suspend
epoch, exact limit set and overlapping observation window. Network scope and
safe-egress repeat where carried. Evidence that authorizes a current success or
opaque observation has every production, observation, and evaluation time
inside the matrix cell/set/lease validity window. A typed expiry outcome is the
only exception: its complete signed antecedent remains internally valid in the
same clock/lease/fence domain, while its exact current evaluation time is
strictly later than the selected deadline. Expiry evidence cannot authorize a
success, and a later time without the complete prior signed body is invalid.
The tag-`0x4007` authenticator header authority
binding equals the plan-registered Capture Core gate used by the association
leaf and matrix evaluator even though `PassiveObserver` does not duplicate a
gate field. A cross-renew, cross-plan or same-scope/different-lease splice is
invalid.

`RuntimeResolver` instead projects to the runtime identity above and cannot be
recoded as a native platform resolver. An endpoint,
runtime instance/config, transport, backend, scope, family, active image, or
selected ordinal from another member is invalid even when both outer digests
and signatures are valid.
The stable-tag mapping is exhaustive and mutually exclusive:
`RuntimeResolver -> FlowProbeRuntimeResolver`; each of
`WindowsInterfaceDns | LinuxResolvedLinkField |
LinuxNetworkManagerAppliedConnection -> NativeSystemResolver`. V1 has no
generic `NetworkResolver` alias that can bypass the member route plan/current
health projection.

The set observation and every member observation have one byte-identical
`NetworkPath` context digest, including actor, path, plan, lease epoch, fence,
clock window, egress, factory and exclusion root. This applies to unsigned
`Unavailable` members because the set signature covers their complete bodies.
The embedded matrix's `CapabilityEvaluation` context is a different tagged
body, but its lease tuple, network scope, safe-egress digest, exact limit set,
plan/generation/fence and observation window are byte-identical to the set
context; its evaluator gate is the exact plan-registered Capture Core sibling
for that resolver actor. Cross-context members or a matrix from another
evaluator/lease are invalid even when the outer set signature verifies.

The set's `capability_matrix_observation_digest` resolves an observation whose
body is byte-identical to the embedded `capability_matrix_observation`, whose
own `observation_digest` equals that digest, and whose spec digest is byte-
identical to the set's `capability_matrix_spec_digest`.
For each member, `capability_cell_key` is exactly
`{ family: member.family, transport: member.semantic_transport }` and selects
the unique family-major cell position. A `Ready` member's
`capability_cell_observation_digest` is exactly the observation body at that
position. That cell has `NoBlockingReason`, has all six claims `Proven`, carries
the exact positive support/readiness/evidence values and current typed resource
evidence, and has the exact set network scope. Its
planned resolver scope is
`PlannedResolverDependency { resolver_dependency_descriptor_digest,
resolver_path_id, use_site }` copied byte-for-byte from this set; it never
contains the future binding-set digest. HTTPS carrier, platform subject,
family, transport, endpoint path, lease/fence, and freshness all agree. A
ready member cannot cite another cell, another matrix, a blocking cell, or one
whose otherwise valid evidence belongs to a sibling scope.

An unavailable member is equally position-bound. `CapabilityCellBlocked`
names exactly the embedded matrix cell at the member's unique key position;
that cell has the same matrix/cell context and exact
`reason = Blocking(cell_blocking_reason)`. `BindingSetObservationExpired`
names exactly this set observation's embedded matrix digest, and `expired_at`
is the earlier of that key cell's `expires_at` and the common capability-
context lease expiry; the set-observation time is strictly later.
`BootstrapUnavailable.endpoint_source` is byte-identical to the member
binding's `bootstrap`, and every typed evidence ref resolves that exact member,
source, predecessor (when present), context and failed endpoint/path predicate.
`NativeScopeUnavailable` is legal only for a native-system-resolver member;
`BackendUnsupported` names that member's exact platform/backend evidence. Both
carry at least one current platform-capability ref, and every ref repeats the
exact member stable identity, native backend/scope, family, platform subject,
plan/lease/fence context and failed predicate; an empty vector or a report for
a sibling interface/link/connection is invalid.
`BindingSetUnavailable` evidence is limited to the displayed path, recursion,
resource-readback and platform witnesses and repeats the member/set context.

Cause selection uses the first applicable row in this fixed order:
`CapabilityCellBlocked`, `BindingSetObservationExpired`,
`BootstrapUnavailable`, `NativeScopeUnavailable`, `BackendUnsupported`, then
`BindingSetUnavailable`. Every cause other than `CapabilityCellBlocked` and
`BindingSetObservationExpired` requires the selected matrix cell itself to
remain current and `NoBlockingReason`; it cannot duplicate
a blocker already encoded by the cell. A wrong key/matrix/context, mismatched
blocking reason, later deadline, another member's bootstrap, broad evidence
kind, or lower-priority duplicate cause is invalid.

`ResolverUnavailableReasonV1` is derived from the cause tag, never stored a
second time. The direct tags map to their same-named reason. A
`CapabilityCellBlocked` cause uses this total mapping:

| Cell blocker | Resolver-unavailable reason |
| --- | --- |
| `CapabilityEvidenceExpired` | `BindingSetObservationExpired` |
| `ResolverBindingSetUnavailable` | `BindingSetUnavailable` |
| `ResolverBootstrapUnavailable` | `BootstrapUnavailable` |
| `ResolverNativeScopeUnavailable` | `NativeScopeUnavailable` |
| `ResolverBackendUnsupported` | `BackendUnsupported` |
| `PinnedRuntimeMismatch`, `PinnedQuicBuildTagUnavailable`, `PinnedDnsResponseBoundUnavailable`, `LinuxReleaseTupleUnselected`, `LinuxResolverManagerUnknownOrMixed`, `MacOsConditionalDnsMutationUnavailable`, `MacOsActiveApplyCompletionUnproven`, `WindowsNativeInterceptBackendUnregistered`, `LinuxNativeInterceptBackendUnregistered`, `MacOsNativeInterceptBackendUnregistered`, `DecoderUnavailable` | `BackendUnsupported` |
| `InheritedArch001Blocker`, `InheritedArch002Blocker`, `RuntimeAttachmentMissing`, `ResumeGateMissing`, `LoopExclusionIncomplete`, `SocketAdmissionUnavailable`, `RealHostUnverified`, `WindowsDnsInterfaceNotExclusivelyOwned`, `LinuxResolvedLinkNotExclusivelyOwned`, `NetworkManagerCasUnavailable`, `OriginalDestinationUnavailable`, `ProcessProvenanceUnavailable`, `MechanismDoesNotProveRouting`, `MechanismDoesNotProveInterception`, `MechanismDoesNotProveDecoding`, `MechanismDoesNotProveLeakPrevention` | `BindingSetUnavailable` |

These rows enumerate every blocker legal in a sealed member exactly once;
`UseSiteFamilyPolicyUnavailable` is the sole pre-seal-only V1 blocker and is
rejected here. Projecting an unavailable binding member into its DNS cell/claim
status uses exactly:
`BindingSetUnavailable -> ResolverBindingSetUnavailable`,
`BindingSetObservationExpired -> CapabilityEvidenceExpired`,
`BootstrapUnavailable -> ResolverBootstrapUnavailable`,
`NativeScopeUnavailable -> ResolverNativeScopeUnavailable`, and
`BackendUnsupported -> ResolverBackendUnsupported`. A producer-selected
reason, cross-cell blocker, or non-total fallback is invalid.

The pre-seal `UseSiteFamilyPolicyUnavailable` DNS blocker has no member-cause
variant because such a candidate never constructs or seals a binding set. A
no-binding native cell reports scope/backend blockers, or freshness expiry,
directly in its signed matrix status. None of those status outcomes constructs
a resolver identity or DNS transaction.

The three no-binding resolver variants are closed. For
`NativeSystemResolverNoBinding`, the complete signed matrix is the exact
`NoResolverDependencies` matrix embedded in the current DNS-route plan, its
digest equals the embedded body and `observation_digest`, and the selected cell
is the family/transport cell whose `ExactNativeResolverScope(stable_scope)` is
byte-identical and whose reason is `NoBlockingReason`. That cell is exactly
`NativeConfigured` with
`resource_evidence::NativeConfigured.transport_path::NativeSystemPath`; a
`PlainUdpPath`, `StreamPath`, port-53, metadata, passive, encrypted, or
unavailable resource branch cannot be recoded as no-binding native success.
Backend and stable scope
equal the native request hook and resource image; the selected cell key equals
the transaction family/transport and every `NativeNoBinding` plan-time
selection. `ClosedSystemResolverBackend` and `BoundedResolverScope` contain
only the three platform-native Windows/resolved/NetworkManager branches;
runtime backend/scope values have no no-binding or native-unavailable encoding.
The path-bound stable-tag table above is total for this route body as well:
Windows repeats interface/owned-adapter/family, resolved is exactly the owned
link's `DnsEx` field, and NetworkManager repeats UUID/device and selects the
transaction family's DNS projection. A `Domains`/other resolved field or
cross-family Windows/NM route cannot be resolver authority.
Every native discriminator, completion, host-association and plaintext key
repeats one `route_resource_identity_digest`. It is exactly
the outer identity's displayed route body/digest and
`Digest(DnsRouteResourceIdentityV1)` from both the selected cell's
`dns_route_active_state` and its `NativeSystemPath.route_readback_ref`; that
identity's unique `Arch004ResourcePlanV1` is the same route node that embeds
this `NoResolverDependencies` matrix. A sibling route digest, even with the
same backend/scope and a self-consistent query/response token pair, is invalid.
`ObservedResolverEndpoint`
uses only a `NoResolverScope` matrix cell at the transaction's family/transport;
its complete signed tag-`0x4007` evidence embeds the exact same
`txn.host_association.association_observation_ref`, repeats that leaf's key and
context, resolves the exact current host object through its typed locator, and
binds the observed remote endpoint, network scope, family, transport and time.
That cell must prove decoding but may
keep routing/interception/leak claims explicitly blocked, so passive visibility
does not become selected-route authority.
Its association variant is closed by transport:
`PlainUdp -> UdpDatagramFlow`, `PlainTcp -> TcpConnection`,
`Tls -> DotConnection`, `Https -> DohHttpTransaction`, and
`Quic -> DoqStream`. For UDP, the signed observation endpoint is exactly the
current `DatagramFlow.identity.application_endpoint`. That application
endpoint, `network_endpoint`, and the flow identity share one family, but
`network_endpoint` is only the
possibly different direct/relay peer used for path validation and can never be
substituted as resolver identity. For stream/HTTP/QUIC, the signed observation
endpoint equals `host_core.remote_endpoint`; `host_core.local_endpoint`,
`remote_endpoint`, and `host_core.family` are one family. Both the observation and
identity field use
`Digest(EndpointIdentityProjectionV1(observed_endpoint))`; the outer identity's
endpoint and digest equal those values. The host-object variant and association
key are position-for-position (`UdpDatagramFlow -> UdpDatagramFlow`,
`TcpConnection -> StreamConnection`, `DotConnection -> DotConnection`,
`DohHttpTransaction -> DohHttpTransaction`, `DoqStream -> DoqStream`), and the resolved object's network scope is
byte-identical to the matrix `CapabilityEvaluation`/cell spec scope. Its family
equals endpoint family, transaction family and the selected cell key. Native request/response tokens,
encrypted-outer-only associations, `ExactNativeResolverScope`, another
transaction association ref, or an unsigned endpoint assertion are not accepted
by this variant.
The stream/HTTP/QUIC host-core digest covers only the displayed immutable
connection projection and never `NormalizedFlow` extensions, this DNS
transaction, or any descendant record. Its locator resolves a byte-identical
host-core revision. TCP repeats connection/epoch; DoT additionally repeats outer
epoch and plaintext-hook identity; DoH repeats outer epoch, HTTP transaction,
carrier and hook; DoQ repeats QUIC epoch, stream and hook, all byte-for-byte with
the association leaf, plaintext boundary and discriminator. Hashing a full `NormalizedFlow` that can
carry `FlowProbeDnsTransactionV1`, or any reverse edge to the enclosing
transaction, is invalid and cannot satisfy tag-`0x4007`.

A no-binding native success must remain current. Once its signed cell deadline
has passed, or when scope/backend evidence is blocking, the status surface keeps
the complete signed matrix/cell and exact reason but emits no resolver identity
or transaction. A digest-only matrix, another cell/scope, empty evidence, or
path-only reason cannot replace that status. Conversely, a path-bound resolver
may not discard its set/observation and recode itself as a no-binding success.

Configuration text is not resolver identity. A path-bound resolver binds the
selected endpoint after resolution and route classification. Only the
path-bound `NativeSystemResolver` binds a registered backend and stable per-
interface, link, or service scope through a binding set; the disjoint no-binding
variant proves its backend/scope through the complete signed native matrix.
An ambient lookup with no supported scope is unavailable.

## 13. DNS privacy and retention

The default persisted mode is `PersistKeyedDigest`. Its key is generated and
held by the unprivileged storage/privacy owner, not the helper, runtime, renderer,
or analyzer. The digest domain includes installation, key epoch, normalized
name bytes, qtype, and qclass so cross-installation correlation is not possible.
Key rotation intentionally breaks linkage across epochs.

The value is exactly
`HMAC-SHA-256(key_epoch_secret,
"FlowProbe.Dns.Name.v1\0" || deterministic_cbor({installation_id,
key_epoch, canonical_wire_name, qtype, qclass}))`. The secret never enters a
plan, helper journal, renderer, analyzer, error, or log. A plain SHA-256 value is
nonconforming.

The persisted name variant is a deterministic per-question projection of the
transaction retention mode: `PersistKeyedDigest` stores only `KeyedDigest`;
`Redacted` stores only `NameRedacted`; and `PersistExactAuthorized` stores
`ExactNormalized` only for an in-scope member while every out-of-scope member
uses the one signed fallback mode. `EphemeralExact` may expose
`ExactNormalized` only in the bounded live record; its persisted form is
`NameRedacted`. A non-deterministic variant, wrong fallback, or partially
published vector is a privacy-integrity failure, not a coercion.

`EphemeralExact` permits exact names only in bounded live memory and authorized
live views; persistence and ordinary logs receive `NameRedacted`.
`PersistExactAuthorized` requires the exact signed receipt, scope, durable
one-use consumption record, capture session, permitted question scope, consumer
scope, and retention deadline defined in section 10. Expired decision authority
cannot create a new plan, and retention past the signed maximum is deleted. It
does not authorize payload, answer, ECS, cookie, HTTP-header capture, another
session, or another consumer.

Authorized consumers receive the least revealing representation permitted by
their capability. Analyzer access remains a separate versioned permission and
MUST NOT be inferred from storage presence. Retention deletion removes exact
names, keyed indexes, transaction metadata, and associated flow metadata at the
declared capture-session boundary. Derived semantic data must be independently
rebuildable or deleted according to its host policy.

Diagnostics use only closed codes, bounded counts, transport/family, and safe
state. They never include full DNS names, packets, resolver credentials, DoH
headers, TLS keys, Authorization/Cookie values, or arbitrary parser text.

## 14. Malformed input and fail-safe forwarding

The decoder treats these as bounded malformed outcomes:

- DNS headers shorter than twelve octets;
- impossible section counts under the message/work bound;
- invalid labels, compression loops, out-of-range pointers, and expanded-name
  overflow;
- truncated TCP/DoT/DoQ length framing, zero/invalid declared lengths, and
  trailing incomplete frames;
- syntactically invalid EDNS fields or record structures that violate the
  accepted bounded DNS grammar.

A malformed observation emits at most a bounded code, safe transport/family,
message length when known, and observation provenance. It emits no partial name,
payload prefix, arbitrary error, or fabricated DNS fields.

Parser failure alone MUST NOT terminate a policy-safe admitted pass-through
flow. The content is not treated as decoded, bounded malformed metadata is
recorded, and forwarding continues on the same selected path if its policy,
exclusion, admission, and health remain valid. If safe
forwarding itself cannot be proved, the datagram is blocked or the data-plane
gate closes and ARCH-001 rollback begins.

Plaintext decoder admission, memory, work-unit, cancellation, or deadline
exhaustion is `DecodeOpaque`, never `EncryptedOpaque` and never `Malformed`.
Unsupported DoH method/media/encoding or a syntactically valid but unsupported
EDNS version/record semantic at an otherwise authenticated plaintext boundary,
a grammar-valid message whose question count is zero, a declared message/
question bound above the sealed limit, or correlation-table admission exhaustion
is also `DecodeOpaque`. V1's decoded projection is defined exactly when the
header question count is in `1..=UdpDnsLimitSetV1.max_dns_questions` and all those
questions parse completely; zero is never producer-selected as malformed, and
max-plus-one is never partially decoded. A response whose
opcode/questions do not select exactly one pending query is an
`UnmatchedResponse`, not malformed; duplicate/ambiguous candidates use the same
single unmatched reason. `Malformed` is reserved for bounded parser
evidence that the supplied message or framing violates the accepted DNS
grammar. `EncryptedOpaque` is a capability-cell status only and requires the
selected planned resolver path plus the closed zero-plaintext census above; it
is never a DNS transaction payload.

## 15. Loss, reordering, timeout, and exhaustion

Loss and reorder never cause unbounded buffering. Outstanding query entries
expire at the plan's finite correlation deadline. A late response is unmatched.
When the outstanding table is full, a new decode reservation fails atomically;
the pass-through decision remains independently governed by section 7.

Excess active flows, events, or buffers use one closed result:

```text
ResourceLimitOutcomeV1 =
  | DecodeOpaqueAndContinueSelectedPath
  | BlockNewDatagram
  | RefuseActivation
  | CloseFlow
  | FenceAndRollback

Arch004LimitDimensionV1 =
  | ActiveDatagramFlows
  | DatagramFlowsPerSession
  | MetadataEventsPerSecond
  | MetadataBytesPerFlow
  | AggregateUdpMetadataBytes
  | AggregateDnsMetadataBytes
  | FlowIdleTimeout
  | FlowHardLifetime
  | OutstandingDnsTransactions
  | DnsMessageBytes
  | DnsQuestions
  | DnsNameWireOctets
  | ActiveDnsStreamConnections
  | DnsStreamBufferBytesPerConnection
  | AggregateDnsStreamBufferBytes
  | ActiveDohHttpTransactions
  | DnsDecoderWorkUnitsPerMessage
  | DnsCorrelationLifetime
  | DnsRetransmissionLinks
  | ResolverBootstrapDepth
  | BoundedReasonBytes
  | ActiveCapacityReservations
  | AggregateResourceJournalBytes

Arch004LimitOutcomeEntryV1 = {
  dimension: Arch004LimitDimensionV1,
  outcome: ResourceLimitOutcomeV1,
}

Arch004LimitOutcomePolicyV1 = {
  exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
  entries: ExactVector<Arch004LimitOutcomeEntryV1, 23>,
}
```

The entry vector is in the displayed dimension order and maps every limit to
exactly one outcome. Its digest is
`SHA-256("FlowProbe.Arch004.LimitOutcomePolicy.v1\0" ||
deterministic_cbor(policy))`. It may choose the first only
when forwarding does not need the missing metadata for policy, exclusion,
health, or leak prevention. There is no generic fail-open outcome.
`ActiveCapacityReservations` and `AggregateResourceJournalBytes` never select
`DecodeOpaqueAndContinueSelectedPath`; exhaustion refuses the admission or
journal append before side effect, or fences/rolls back when durability can no
longer be preserved.

## 16. Transactional resource registry

The following resource kinds are registered under the ARCH-001 envelope:

```text
transport.udp.path.v1
transport.udp.admission.v1
dns.route.v1
dns.intercept.v1
dns.observer.v1
```

The registry is closed and encodable:

```text
Arch004ResourceKindV1 =
  | TransportUdpPath
  | TransportUdpAdmission
  | DnsRoute
  | DnsIntercept
  | DnsObserver

Arch004ResourceExecutorV1 =
  | ActorSocketFactoryOwner
  | CaptureCore
  | NetworkRuntimeAdapter
  | PrivilegedHelper

UdpPathStableIdentityV1 = {
  actor_id: EgressActorV1.actor_id,
  socket_factory_policy_digest: Digest(ActorSocketFactoryPolicyV1),
  family: AddressFamilyV1,
  egress_selection_safe_digest: Digest(SafeEgressSelectionV1),
  resource_key: Bytes32,
}

UdpAdmissionResourceIdentityV1 = {
  resource_kind: ExactAscii("transport.udp.admission.v1"),
  schema_version: 1,
  admission_id: UdpAdmissionId,
  installation_id: InstallationId,
  session_id: SessionId,
  generation: Generation,
}

DnsRouteStableIdentityV1 =
  | RuntimeResolver {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
    }
  | WindowsInterfaceDns {
      interface_guid: WindowsInterfaceGuid,
      owned_adapter_identity_digest: Digest(WindowsOwnedAdapterIdentityV1),
      family: AddressFamilyV1,
    }
  | LinuxResolvedLinkField {
      network_namespace_identity_digest:
        Digest(LinuxNetworkNamespaceIdentityV1),
      installation_generation_ifalias_owner_marker: OwnerMarker,
      device_kind: ExactSupportedLinkKind,
      field: LinuxResolvedManagedFieldV1,
    }
  | LinuxNetworkManagerAppliedConnection {
      connection_uuid: NetworkManagerConnectionUuid,
      device_stable_identity_digest: Digest(LinuxStableDeviceIdentityV1),
    }

DnsInterceptResourceIdentityV1 = {
  resource_kind: ExactAscii("dns.intercept.v1"),
  schema_version: 1,
  runtime_instance_id: RuntimeInstanceId,
  protected_rule_identity: Bytes32,
  network_scope: NetworkScope,
  installation_id: InstallationId,
  session_id: SessionId,
  generation: Generation,
}

DnsObserverResourceIdentityV1 = {
  resource_kind: ExactAscii("dns.observer.v1"),
  schema_version: 1,
  decoder_instance_id: DnsDecoderInstanceId,
  component_instance_id: ComponentInstanceId,
  decoder_build: BoundedBuildIdentity,
  installation_id: InstallationId,
  session_id: SessionId,
  generation: Generation,
}

Arch004ResourceIdentityV1 =
  | UdpPath(UdpPathResourceIdentityV1)
  | UdpAdmission(UdpAdmissionResourceIdentityV1)
  | DnsRoute(DnsRouteResourceIdentityV1)
  | DnsIntercept(DnsInterceptResourceIdentityV1)
  | DnsObserver(DnsObserverResourceIdentityV1)

WindowsDnsManagedFieldV1 =
  | Domain
  | NameServer
  | SearchList
  | RegistrationEnabled
  | RegisterAdapterName
  | EnableLlmnr
  | QueryAdapterName
  | ProfileNameServer

WindowsDnsInterfaceSettingsImageV1 = {
  version: ExactU32(1),
  family: AddressFamilyV1,
  managed_fields: SortedUniqueNonEmptyVector<WindowsDnsManagedFieldV1>,
  derived_flags: U64,
  domain?: BoundedDnsSuffix,
  name_servers: BoundedOrderedVector<EndpointV1>,
  search_list: BoundedOrderedVector<BoundedDnsSuffix>,
  registration_enabled?: Bool,
  register_adapter_name?: Bool,
  enable_llmnr?: Bool,
  query_adapter_name?: Bool,
  profile_name_servers: BoundedOrderedVector<EndpointV1>,
}

LinuxResolvedManagedFieldV1 =
  | DnsEx
  | Domains
  | DefaultRoute
  | Llmnr
  | MulticastDns
  | DnsOverTls
  | Dnssec
  | DnssecNegativeTrustAnchors

LinuxResolvedFieldImageV1 =
  | DnsEx(BoundedOrderedVector<EndpointV1>)
  | Domains(BoundedOrderedVector<{
      canonical_name: BoundedDnsSuffix,
      route_only: Bool,
    }>)
  | DefaultRoute(Bool)
  | Llmnr(Off | Resolve | Yes)
  | MulticastDns(Off | Resolve | Yes)
  | DnsOverTls(Off | Opportunistic | Yes)
  | Dnssec(Off | AllowDowngrade | Yes)
  | DnssecNegativeTrustAnchors(
      SortedUniqueVector<BoundedDnsSuffix>)

NetworkManagerDnsFamilyProjectionV1 = {
  dns_servers: BoundedOrderedVector<EndpointV1>,
  dns_search: BoundedOrderedVector<BoundedDnsSuffix>,
  dns_options: SortedUniqueVector<BoundedDnsOptionV1>,
  dns_priority: I32,
  ignore_auto_dns: Bool,
}

NetworkManagerDnsProjectionV1 = {
  ipv4: NetworkManagerDnsFamilyProjectionV1,
  ipv6: NetworkManagerDnsFamilyProjectionV1,
}

NetworkManagerAppliedConnectionImageV1 = {
  connection_uuid: NetworkManagerConnectionUuid,
  device_stable_identity_digest: Digest(LinuxStableDeviceIdentityV1),
  applied_version_id: NonZeroU64,
  complete_settings_digest: Digest,
  dns_projection: NetworkManagerDnsProjectionV1,
}

RuntimeResolverImageV1 =
  | Absent
  | Present {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      protected_config_digest: Digest,
      semantic_transport: DnsTransportV1,
      configured_endpoint_identity_digest: Digest(EndpointIdentityV1),
    }

DnsRouteImageV1 =
  | RuntimeResolver(RuntimeResolverImageV1)
  | WindowsInterfaceDns(WindowsDnsInterfaceSettingsImageV1)
  | LinuxResolvedLinkField(LinuxResolvedFieldImageV1)
  | LinuxNetworkManagerAppliedConnection(
      NetworkManagerAppliedConnectionImageV1)

DnsRouteBackendV1 =
  | RuntimeProtectedResolverV1 {
      pinned_runtime_revision: ExactAscii(
        "b5ebaa1fc0f2b94256180b95468e73ef53caa27d"),
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      protected_config_digest: Digest,
    }
  | WindowsInterfaceDnsSettingsV1 {
      api_version: ExactU32(1),
      interface_guid: WindowsInterfaceGuid,
      owned_adapter_identity_digest: Digest(WindowsOwnedAdapterIdentityV1),
      family: AddressFamilyV1,
      managed_fields: SortedUniqueNonEmptyVector<WindowsDnsManagedFieldV1>,
    }
  | LinuxSystemdResolvedOwnedLinkFieldV1 {
      platform_subject: Arch004PlatformSubjectV1,
      resolved_backend_version: BoundedVersion,
      stable_identity: DnsRouteStableIdentityV1::LinuxResolvedLinkField,
    }
  | LinuxNetworkManagerAppliedConnectionV1 {
      platform_subject: Arch004PlatformSubjectV1,
      network_manager_version: BoundedVersion,
      connection_uuid: NetworkManagerConnectionUuid,
      device_stable_identity_digest: Digest(LinuxStableDeviceIdentityV1),
    }

DnsRouteMutationConditionV1 =
  | RuntimeOwnedInstance {
      runtime_instance_id: RuntimeInstanceId,
      protected_handshake_digest: Digest,
    }
  | ExactExclusiveOwnedObject {
      owner_marker: OwnerMarker,
      whole_object_and_dependent_closure_digest: Digest,
    }
  | NetworkManagerAppliedVersionCas {
      expected_version_id: NonZeroU64,
      expected_complete_settings_digest: Digest,
    }

Arch004SuccessPredicateV1 =
  | UdpPathBindingAcceptedAndLatched
  | UdpAdmissionCounterOpen
  | RuntimeResolverConfigAndPathReadback
  | WindowsInterfaceDnsExactManagedImage
  | LinuxResolvedExactFieldImage
  | NetworkManagerExactAppliedConnectionImage
  | RuntimePort53RuleAndHandlerReadback
  | ObserverRunningWithinBoundsNoAmbientNetwork

Arch004DnsRouteSuccessPredicateV1 =
  | RuntimeResolverConfigAndPathReadback
  | WindowsInterfaceDnsExactManagedImage
  | LinuxResolvedExactFieldImage
  | NetworkManagerExactAppliedConnectionImage

DnsInterceptBackendV1 =
  | RuntimeProtectedPort53HijackV1 {
      pinned_runtime_revision: ExactAscii(
        "b5ebaa1fc0f2b94256180b95468e73ef53caa27d"),
      runtime_instance_id: RuntimeInstanceId,
      protected_config_digest: Digest,
      protected_rule_identity: Bytes32,
      families: SortedUniqueNonEmptyVector<AddressFamilyV1>,
      transports: ExactSet<PlainUdp, PlainTcp>,
      destination_port: ExactU16(53),
      network_scope: NetworkScope,
      handler_actor_id: EgressActorV1.actor_id,
      handler_resource_identity: DnsRouteResourceIdentityV1,
      exclusion_set_digest: Digest(EgressExclusionSetV1),
      authenticated_readback_predicate: Arch004SuccessPredicateV1,
    }

DnsInterceptImageV1 =
  | Absent
  | Present {
      runtime_instance_id: RuntimeInstanceId,
      protected_config_digest: Digest,
      protected_rule_identity: Bytes32,
      families: SortedUniqueNonEmptyVector<AddressFamilyV1>,
      transports: ExactSet<PlainUdp, PlainTcp>,
      handler_actor_id: EgressActorV1.actor_id,
    }

UdpPathResourceImageV1 =
  | DormantDeclarationReady {
      actor_graph_digest: Digest(EgressActorGraphV1),
      resource_identity: UdpPathResourceIdentityV1,
    }
  | OperationalBindingReady {
      binding_digest: Digest(Arch004UdpPathBindingV1),
    }

UdpAdmissionResourceImageV1 =
  | Closed
  | Open {
      admission_id: UdpAdmissionId,
      exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
      current_reserved_count: U64,
    }

DnsObserverResourceImageV1 =
  | Inert
  | Running {
      decoder_instance_id: DnsDecoderInstanceId,
      decoder_build: BoundedBuildIdentity,
      plaintext_producer_registry_spec_digest:
        Digest(DnsPlaintextProducerRegistrySpecV1),
      exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
      ambient_network: Prohibited,
      state_revision: U64,
    }
  | Stopped

Arch004ResourceBackendV1 =
  | UdpPathFactory {
      actor_socket_factory_policy_digest:
        Digest(ActorSocketFactoryPolicyV1),
    }
  | UdpAdmissionOwner { owner_actor_id: EgressActorV1.actor_id }
  | DnsRoute(DnsRouteBackendV1)
  | DnsIntercept(DnsInterceptBackendV1)
  | DnsObserverCaptureCore { decoder_build: BoundedBuildIdentity }

Arch004ResourceImageV1 =
  | UdpPath(UdpPathResourceImageV1)
  | UdpAdmission(UdpAdmissionResourceImageV1)
  | DnsRoute(DnsRouteImageV1)
  | DnsIntercept(DnsInterceptImageV1)
  | DnsObserver(DnsObserverResourceImageV1)

DnsRouteDesiredStateV1 =
  | RuntimeResolverPresent {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
      protected_config_digest: Digest,
      semantic_transport: DnsTransportV1,
      configured_endpoint_identity_digest: Digest(EndpointIdentityV1),
    }
  | WindowsInterfaceDnsExact {
      settings: WindowsDnsInterfaceSettingsImageV1,
    }
  | LinuxResolvedExactField {
      field: LinuxResolvedManagedFieldV1,
      value: LinuxResolvedFieldImageV1,
    }
  | LinuxNetworkManagerDnsProjection {
      connection_uuid: NetworkManagerConnectionUuid,
      device_stable_identity_digest: Digest(LinuxStableDeviceIdentityV1),
      expected_before_complete_settings_digest: Digest,
      desired_dns_projection: NetworkManagerDnsProjectionV1,
      preserve_every_non_dns_field: true,
      reapply_flags: ExactU32(0),
    }

Arch004IntendedPostconditionV1 =
  | UdpPath {
      resource_identity: UdpPathResourceIdentityV1,
      dormant_declaration_actor_graph_digest: Digest(EgressActorGraphV1),
      expected_dynamic_binding_schema:
        ExactAscii("Arch004UdpPathBindingV1"),
      expected_dynamic_binding_schema_version: ExactU16(1),
      no_send_latch_until_atomic_publication: true,
      predicate:
        Arch004SuccessPredicateV1::UdpPathBindingAcceptedAndLatched,
    }
  | UdpAdmission {
      admission_id: UdpAdmissionId,
      exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
      initial_reserved_count: ExactU64(0),
      predicate: Arch004SuccessPredicateV1::UdpAdmissionCounterOpen,
    }
  | DnsRoute {
      desired_state: DnsRouteDesiredStateV1,
      predicate: Arch004DnsRouteSuccessPredicateV1,
    }
  | DnsIntercept {
      runtime_instance_id: RuntimeInstanceId,
      protected_config_digest: Digest,
      protected_rule_identity: Bytes32,
      families: SortedUniqueNonEmptyVector<AddressFamilyV1>,
      transports: ExactSet<PlainUdp, PlainTcp>,
      handler_actor_id: EgressActorV1.actor_id,
      predicate:
        Arch004SuccessPredicateV1::RuntimePort53RuleAndHandlerReadback,
    }
  | DnsObserver {
      decoder_instance_id: DnsDecoderInstanceId,
      decoder_build: BoundedBuildIdentity,
      plaintext_producer_registry_spec_digest:
        Digest(DnsPlaintextProducerRegistrySpecV1),
      exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
      ambient_network: Prohibited,
      predicate:
        Arch004SuccessPredicateV1::ObserverRunningWithinBoundsNoAmbientNetwork,
    }

Arch004MutationConditionV1 =
  | NoExternalMutation
  | DnsRoute(DnsRouteMutationConditionV1)
  | RuntimeRuleOwnedInstance {
      runtime_instance_id: RuntimeInstanceId,
      protected_rule_identity: Bytes32,
    }

Arch004CompensationAlgorithmV1 =
  | RestoreTypedBeforeImageIfExactAfter
  | RemoveExactExclusivelyOwnedCreatedObject
  | CloseExactUdpPathBinding
  | ReleaseExactUdpAdmission
  | StopExactObserverInstance
  | RemoveRuntimeRuleAfterConsumersStop

Arch004ConflictKeyV1 =
  | UdpPath {
      actor_id: EgressActorV1.actor_id,
      family: AddressFamilyV1,
      resource_key: Bytes32,
    }
  | UdpAdmission { admission_id: UdpAdmissionId }
  | RuntimeResolver {
      runtime_instance_id: RuntimeInstanceId,
      resolver_instance_id: DnsResolverInstanceId,
    }
  | WindowsInterfaceDns {
      interface_guid: WindowsInterfaceGuid,
      family: AddressFamilyV1,
    }
  | LinuxResolvedField {
      stable_link_identity_digest: Digest(DnsRouteStableIdentityV1),
      field: LinuxResolvedManagedFieldV1,
    }
  | LinuxNetworkManagerConnection {
      connection_uuid: NetworkManagerConnectionUuid,
      device_stable_identity_digest: Digest(LinuxStableDeviceIdentityV1),
    }
  | RuntimePort53Rule {
      runtime_instance_id: RuntimeInstanceId,
      network_scope: NetworkScope,
      family: AddressFamilyV1,
      transport: PlainUdp | PlainTcp,
    }
  | DnsObserver { decoder_instance_id: DnsDecoderInstanceId }

Arch004CapacityKindV1 =
  | ActiveDatagramFlow
  | DatagramFlowPerSession
  | MetadataEventRateSlot
  | UdpMetadataBytes
  | DnsMetadataBytes
  | OutstandingDnsTransaction
  | DatagramOccurrenceIndexEntry
  | DnsLineageEdge
  | DnsCorrelationEntry
  | QueueSlot
  | PersistedStagingBytes
  | DnsStreamConnection
  | DnsStreamBufferBytes
  | DohHttpTransaction
  | DecoderWorkUnits
  | ResourceJournalBytes

Arch004CapacityChargeV1 = {
  kind: Arch004CapacityKindV1,
  count: U64,
  worst_case_bytes: U64,
}

Arch004CapacityCeilingCellV1 = {
  kind: Arch004CapacityKindV1,
  maximum_count: U64,
  maximum_worst_case_bytes: U64,
}

Arch004CapacityUsageCellV1 = {
  kind: Arch004CapacityKindV1,
  checked_used_count: U64,
  checked_used_worst_case_bytes: U64,
}

Arch004CapacityLedgerId = Bytes32
Arch004CapacityReservationId = Bytes32
Arch004CapacityJointCowWalRevisionV1 = U64
Arch004CapacityJointCowWalTransactionIdV1 = Bytes32

Arch004CapacityOwnerV1 =
  | CaptureCore { component_instance_id: ComponentInstanceId }
  | CorrelationPrivacyOwner { component_instance_id: ComponentInstanceId }
  | StoragePrivacyOwner { component_instance_id: ComponentInstanceId }
  | ResourceExecutor {
      identity: Arch004ResourceIdentityV1,
      executor: Arch004ResourceExecutorV1,
    }

Arch004DynamicCapacitySubjectV1 =
  | DnsStream {
      host_connection_id: HostConnectionIdV1,
      connection_epoch: DnsConnectionEpochV1,
    }
  | DohTransaction {
      http_transaction_id: HostHttpTransactionIdV1,
    }
  | BufferGrowth {
      owner_identity: Bytes32,
      growth_ordinal: MonotonicSequence,
    }
  | QueueOrStagingItem {
      owner_identity: Bytes32,
      item_identity: Bytes32,
    }

Arch004ResourceJournalInnerSchemaV1 =
  | InitialResult
  | CompensationResult
  | RecoveryResolution
  | HealthObservation

Arch004ResourceJournalRoleBudgetV1 = {
  schema: Arch004ResourceJournalInnerSchemaV1,
  maximum_record_count: PositiveBoundedU16,
  maximum_accounted_bytes: PositiveU64,
  mandatory_terminal_reserve_count: U16,
  mandatory_terminal_reserve_accounted_bytes: U64,
}

Arch004ResourceJournalRoleUsageV1 = {
  schema: Arch004ResourceJournalInnerSchemaV1,
  used_record_count: U16,
  used_accounted_bytes: U64,
}

Arch004ResourceJournalAllocationIdentityV1 = {
  allocation_id: FreshBytes32,
  installation_id: InstallationId,
  preparation_ticket_id: PreparationTicketId,
  session_id: SessionId,
  generation: Generation,
  step_id: StepId,
  resource_identity: Arch004ResourceIdentityV1,
  journal_stream_id: Bytes32,
  journal_accounting_build: BoundedBuildIdentity,
  journal_accounting_version: BoundedVersion,
  role_budgets: ExactVector<Arch004ResourceJournalRoleBudgetV1, 4>,
  maximum_inner_record_count: PositiveBoundedU16,
  maximum_accounted_journal_bytes: PositiveU64,
  permitted_inner_schemas:
    ExactSet<Arch004ResourceJournalInnerSchemaV1, 4>,
}

Arch004GenerationJournalRetentionSubjectV1 = {
  allocation_identity: Arch004ResourceJournalAllocationIdentityV1,
}

Arch004CapacitySubjectV1 =
  | ResourceNode { identity: Arch004ResourceIdentityV1 }
  | DatagramFlow { flow_id: DatagramFlowId }
  | RawFragmentMetadata { fragment_observation_id: Bytes32 }
  | DnsTransaction { transaction_id: DnsTransactionId }
  | Retained(Arch004RetainedMetadataSubjectV1)
  | GenerationJournalRetention(
      Arch004GenerationJournalRetentionSubjectV1)
  | Dynamic(Arch004DynamicCapacitySubjectV1)

Arch004CapacityRequirementV1 = {
  subject: Arch004CapacitySubjectV1,
  owner: Arch004CapacityOwnerV1,
  exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
  accounting_function_build: BoundedBuildIdentity,
  accounting_function_version: BoundedVersion,
  applicable_kinds:
    SortedUniqueNonEmptyVector<Arch004CapacityKindV1>,
  charges: SortedUniqueNonEmptyVector<Arch004CapacityChargeV1>,
}

Arch004CapacityReservationCommitmentV1 = {
  ledger_id: Arch004CapacityLedgerId,
  reservation_id: Arch004CapacityReservationId,
  reservation_ordinal: U64,
  requirement_digest: Digest(Arch004CapacityRequirementV1),
  subject: Arch004CapacitySubjectV1,
  owner: Arch004CapacityOwnerV1,
  observation_context_digest: Digest(Arch004ObservationContextV1),
  reserved_at: MonotonicInstant,
}

Arch004CapacityLedgerSnapshotV1 = {
  ledger_id: Arch004CapacityLedgerId,
  installation_id: InstallationId,
  limit_set_digest: Digest(UdpDnsLimitSetV1),
  accounting_function_build: BoundedBuildIdentity,
  accounting_function_version: BoundedVersion,
  revision: U64,
  next_reservation_ordinal: U64,
  ceilings: ExactVector<Arch004CapacityCeilingCellV1, 16>,
  active_reservations:
    SortedUniqueVector<
      Arch004CapacityReservationCommitmentV1,
      0..=UdpDnsLimitSetV1.max_active_capacity_reservations>,
  active_reservations_root: Digest,
  checked_usage: ExactVector<Arch004CapacityUsageCellV1, 16>,
  checked_usage_root: Digest,
}

Arch004CapacityLedgerHeadV1 = {
  ledger_id: Arch004CapacityLedgerId,
  revision: U64,
  snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  last_transition_digest?: Digest(Arch004CapacityLedgerTransitionV1),
  transition_accumulator_root: Digest,
}

Arch004SuccessfulCompensationRefV1 =
  | RestoredBefore {
      inner_record:
        Arch004ResourceJournalInnerRecordRefV1::CompensationResult {
          required_variant: Exact(RestoredBefore),
        },
    }
  | AlreadyBefore {
      inner_record:
        Arch004ResourceJournalInnerRecordRefV1::CompensationResult {
          required_variant: Exact(AlreadyBefore),
        },
    }
  | CreatedOwnedObjectAbsent {
      inner_record:
        Arch004ResourceJournalInnerRecordRefV1::CompensationResult {
          required_variant: Exact(CreatedOwnedObjectAbsent),
        },
    }

Arch004RecoveryReleaseRefV1 =
  | Unapplied {
      inner_record:
        Arch004ResourceJournalInnerRecordRefV1::RecoveryResolution {
          required_outcome: Exact(Unapplied),
        },
    }
  | Compensated {
      inner_record:
        Arch004ResourceJournalInnerRecordRefV1::RecoveryResolution {
          required_outcome: Exact(Compensated),
        },
    }
  | OwnershipAbandoned {
      inner_record:
        Arch004ResourceJournalInnerRecordRefV1::RecoveryResolution {
          required_outcome: Exact(OwnershipAbandoned),
        },
    }

DatagramFlowClosedRefV1 = {
  terminal_flow_digest: Digest(DatagramFlowV1),
  required_state: ExactAscii("Closed"),
}

DnsTransactionTerminalKindV1 =
  | MatchedResponse
  | QueryTimedOut
  | UnmatchedResponse
  | DecodeOpaque
  | Malformed

DnsTransactionTerminalRefV1 = {
  terminal_transaction_digest: Digest(DnsTransactionV1),
  required_terminal_kind: DnsTransactionTerminalKindV1,
}

Arch004RetainedMetadataSubjectV1 =
  | RetainedDatagramFlow {
      flow_id: DatagramFlowId,
      semantic_terminal: DatagramFlowClosedRefV1,
    }
  | RetainedDnsTransaction {
      transaction_id: DnsTransactionId,
      semantic_terminal: DnsTransactionTerminalRefV1,
    }

Arch004SemanticMetadataTerminalRefV1 =
  | DatagramFlow(DatagramFlowClosedRefV1)
  | DnsTransaction(DnsTransactionTerminalRefV1)

Arch004RetainedMetadataActiveV1 = {
  subject: Arch004RetainedMetadataSubjectV1,
  revision: ExactU64(0),
  retention_requirement_digest: Digest(Arch004CapacityRequirementV1),
  reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  semantic_terminal: Arch004SemanticMetadataTerminalRefV1,
  opened_at: MonotonicInstant,
}

Arch004RetainedMetadataTerminalReasonV1 =
  | RetentionExpired
  | SessionStopping
  | PolicyDeleted

Arch004RetainedMetadataTerminalV1 = {
  subject: Arch004RetainedMetadataSubjectV1,
  revision: ExactU64(1),
  predecessor_active_digest: Digest(Arch004RetainedMetadataActiveV1),
  reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  reason: Arch004RetainedMetadataTerminalReasonV1,
  unreachability_evidence_ref: MetadataRetentionEvidenceRefV1,
  ended_at: MonotonicInstant,
}

Arch004ResourceJournalInnerRecordRefV1 =
  | InitialResult {
      body_digest: Digest(Arch004ResourceResultV1),
      required_variant: Applied | AlreadyApplied | Unapplied |
        AmbiguousRecoveryRequired,
      journal_location: Arch001JournalLocation,
    }
  | CompensationResult {
      body_digest: Digest(Arch004ResourceCompensationResultV1),
      required_variant: RestoredBefore | AlreadyBefore |
        CreatedOwnedObjectAbsent | ExternalDriftPreserved |
        AmbiguousRecoveryRequired,
      journal_location: Arch001JournalLocation,
    }
  | RecoveryResolution {
      body_digest: Digest(Arch004ResourceRecoveryResolutionV1),
      required_outcome: Applied | Unapplied | Compensated |
        ExternalDriftPreserved | StillRecoveryRequired |
        OwnershipAbandoned,
      journal_location: Arch001JournalLocation,
    }
  | HealthObservation {
      body_digest: Digest(Arch004ResourceHealthObservationV1),
      journal_location: Arch001JournalLocation,
    }

Arch004ResourceJournalPersistenceBodyV1 = {
  allocation_identity: Arch004ResourceJournalAllocationIdentityV1,
  allocation_revision: U64,
  predecessor_receipt_digest?:
    Digest(Arch004ResourceJournalPersistenceReceiptV1),
  predecessor_active_digest?:
    Digest(Arch004GenerationJournalRetentionActiveV1),
  inner_record: Arch004ResourceJournalInnerRecordRefV1,
  inner_record_encoded_bytes: PositiveU64,
  reserved_append_accounted_bytes: PositiveU64,
  prior_record_accumulator_root: Digest,
  record_accumulator_root: Digest,
  cumulative_inner_record_count: PositiveBoundedU16,
  cumulative_inner_record_bytes: PositiveU64,
  cumulative_accounted_journal_bytes: PositiveU64,
  role_usage_after:
    ExactVector<Arch004ResourceJournalRoleUsageV1, 4>,
  journal_root_before: Digest,
  journal_root_after: Digest,
  durable_at: MonotonicInstant,
}

Arch004ResourceJournalPersistenceReceiptV1 = {
  body: Arch004ResourceJournalPersistenceBodyV1,
  evidence_ref: ResourceJournalPersistenceEvidenceRefV1,
}

Arch004ResourceJournalRetentionObservationV1 =
  | Persistence {
      body: Arch004ResourceJournalPersistenceBodyV1,
    }
  | Terminal {
      subject: Arch004GenerationJournalRetentionSubjectV1,
      predecessor_active_digest:
        Digest(Arch004GenerationJournalRetentionActiveV1),
      terminal_revision: PositiveU64,
      reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      disposition: Arch004GenerationJournalRetentionDispositionV1,
      ended_at: MonotonicInstant,
    }

Arch004GenerationJournalRetentionActiveV1 = {
  subject: Arch004GenerationJournalRetentionSubjectV1,
  revision: U64,
  predecessor_active_digest?:
    Digest(Arch004GenerationJournalRetentionActiveV1),
  latest_receipt_digest:
    Digest(Arch004ResourceJournalPersistenceReceiptV1),
  journal_reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  retained_charge: Arch004CapacityChargeV1 {
    kind: Exact(ResourceJournalBytes),
  },
  maximum_inner_record_count: PositiveBoundedU16,
  maximum_accounted_journal_bytes: PositiveU64,
  cumulative_inner_record_count: PositiveBoundedU16,
  cumulative_inner_record_bytes: PositiveU64,
  cumulative_accounted_journal_bytes: PositiveU64,
  role_usage: ExactVector<Arch004ResourceJournalRoleUsageV1, 4>,
  record_accumulator_root: Digest,
  latest_journal_root: Digest,
  updated_at: MonotonicInstant,
}

Arch004GenerationJournalRetentionDispositionV1 =
  | Deleted {
      all_record_partition_and_index_bytes_unreachable: true,
    }

Arch004GenerationJournalRetentionTerminalV1 = {
  subject: Arch004GenerationJournalRetentionSubjectV1,
  revision: PositiveU64,
  predecessor_active_digest:
    Digest(Arch004GenerationJournalRetentionActiveV1),
  reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  disposition: Arch004GenerationJournalRetentionDispositionV1,
  evidence_ref: ResourceJournalTerminalEvidenceRefV1,
  ended_at: MonotonicInstant,
}

The terminal evidence and terminal record are one exact projection. The
resolved `Terminal` observation repeats the terminal subject, predecessor,
revision, reserved-state digest, disposition and `ended_at` byte-for-byte;
`ResourceJournalRetentionReadback.observed_at = Terminal.ended_at`. The terminal
revision is exactly the predecessor Active revision plus one, its reserved-state
digest equals the predecessor's `journal_reserved_capacity_state_digest`, and
its end time is not earlier than the predecessor's `updated_at`. The evidence
leaf never names the terminal digest, so the terminal may reference the leaf
without a digest cycle. Any free revision/time, cross-reservation splice or
second terminal from the same current Active is invalid.

Arch004RawFragmentRetentionTerminalReasonV1 =
  | RetentionExpired
  | SessionStopping
  | PolicyDropped

Arch004RawFragmentRetentionTransitionV1 =
  | QueueOrStage {
      predecessor_live_digest: Digest(Arch004RawFragmentRetentionLiveV1),
      queue_or_staging_item_identity: Bytes32,
      live_representation_removed: true,
      queued_or_staged_representation_present: true,
      charge_transfer_atomic: true,
    }
  | TerminalFromLive {
      predecessor_live_digest: Digest(Arch004RawFragmentRetentionLiveV1),
      reason: Arch004RawFragmentRetentionTerminalReasonV1,
      all_live_queue_staging_persisted_partition_record_and_index_references_unreachable:
        true,
    }
  | TerminalFromQueueOrStage {
      predecessor_queue_digest:
        Digest(Arch004RawFragmentRetentionQueuedV1),
      reason: Arch004RawFragmentRetentionTerminalReasonV1,
      all_live_queue_staging_persisted_partition_record_and_index_references_unreachable:
        true,
    }

Arch004RawFragmentRetentionLiveV1 = {
  fragment_observation_id: Bytes32,
  raw_fragment_metadata_digest: Digest(RawDatagramFragmentMetadataV1),
  revision: ExactU64(0),
  reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  created_at: MonotonicInstant,
}

Arch004RawFragmentRetentionQueuedV1 = {
  fragment_observation_id: Bytes32,
  raw_fragment_metadata_digest: Digest(RawDatagramFragmentMetadataV1),
  revision: ExactU64(1),
  predecessor_live_digest: Digest(Arch004RawFragmentRetentionLiveV1),
  reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  queue_or_staging_item_identity: Bytes32,
  transition_evidence_ref: RawFragmentRetentionEvidenceRefV1,
}

Arch004RawFragmentRetentionTerminalV1 =
  | FromLive {
      fragment_observation_id: Bytes32,
      raw_fragment_metadata_digest: Digest(RawDatagramFragmentMetadataV1),
      revision: ExactU64(1),
      predecessor_live_digest: Digest(Arch004RawFragmentRetentionLiveV1),
      reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      reason: Arch004RawFragmentRetentionTerminalReasonV1,
      ended_at: MonotonicInstant,
      transition_evidence_ref: RawFragmentRetentionEvidenceRefV1,
    }
  | FromQueueOrStage {
      fragment_observation_id: Bytes32,
      raw_fragment_metadata_digest: Digest(RawDatagramFragmentMetadataV1),
      revision: ExactU64(2),
      predecessor_queue_digest:
        Digest(Arch004RawFragmentRetentionQueuedV1),
      reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      reason: Arch004RawFragmentRetentionTerminalReasonV1,
      ended_at: MonotonicInstant,
      transition_evidence_ref: RawFragmentRetentionEvidenceRefV1,
    }

Every raw-fragment transition ref resolves the exact displayed transition and
fragment ID. A queue transition's leaf time is not earlier than the predecessor
Live `created_at`. For `FromLive`, `ended_at` equals the terminal transition
leaf's `observed_at` and is not earlier than the predecessor Live `created_at`.
For `FromQueueOrStage`, `ended_at` equals the terminal transition leaf's
`observed_at` and is not earlier than the predecessor queue transition leaf's
`observed_at`. Subject metadata, reservation, reason and predecessor fields are
byte-identical across the state and transition. A leaf cannot authorize two
different terminal times or a terminal before its predecessor.

Arch004CapacityReleaseCauseV1 =
  | NonJournalResourceCompensated {
      result: Arch004SuccessfulCompensationRefV1,
    }
  | NonJournalResourceRecovered {
      result: Arch004RecoveryReleaseRefV1,
    }
  | CapacityTransferredToRetention {
      retained_active_digest: Digest(Arch004RetainedMetadataActiveV1),
    }
  | RetainedMetadataTerminal {
      terminal_digest: Digest(Arch004RetainedMetadataTerminalV1),
    }
  | ResourceJournalTransferred {
      journal_active_digest:
        Digest(Arch004GenerationJournalRetentionActiveV1),
    }
  | GenerationJournalRetentionTerminal {
      terminal_digest:
        Digest(Arch004GenerationJournalRetentionTerminalV1),
    }
  | RawFragmentRetentionTerminal {
      terminal_digest: Digest(Arch004RawFragmentRetentionTerminalV1),
    }
  | DynamicCapacityObjectTerminal {
      terminal_object_digest:
        Digest(Arch004DynamicCapacityTerminalV1),
    }

Arch004DynamicCapacityActiveV1 = {
  subject: Arch004DynamicCapacitySubjectV1,
  revision: ExactU64(0),
  reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  opened_at: MonotonicInstant,
}

Arch004DynamicCapacityTerminalV1 = {
  subject: Arch004DynamicCapacitySubjectV1,
  revision: ExactU64(1),
  predecessor_active_digest: Digest(Arch004DynamicCapacityActiveV1),
  reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  terminal_reason: ClosedDynamicCapacityTerminalReasonV1,
  ended_at: MonotonicInstant,
  evidence_ref: DynamicCapacityTerminalEvidenceRefV1,
}

Arch004DynamicCapacityUnreachabilityPredicateV1 =
  | DnsStreamClosedAndBuffersReleased
  | DohTransactionClosedAndBodyReleased
  | BufferGrowthRemovedFromOwner
  | QueueOrStagingItemRemovedFromAllIndexes

The dynamic terminal predicate mapping is unique:
`DnsStream -> DnsStreamClosedAndBuffersReleased`,
`DohTransaction -> DohTransactionClosedAndBodyReleased`,
`BufferGrowth -> BufferGrowthRemovedFromOwner`, and
`QueueOrStagingItem -> QueueOrStagingItemRemovedFromAllIndexes`. Terminal,
read-back and predecessor Active repeat the same narrowed subject and
`Reserved` digest byte-for-byte. A cross-kind predicate cannot authorize
release.

Arch004CapacityStateBasisBundleV1 = {
  owner_subject: Arch004CapacitySubjectV1,
  expected_old_head: Arch004CapacityLedgerHeadV1,
  expected_old_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  before_snapshot: Arch004CapacityLedgerSnapshotV1,
  before_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  after_snapshot: Arch004CapacityLedgerSnapshotV1,
  after_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  member_root: Digest,
  accounted_bytes: PositiveU64,
}

Arch004CapacityPublishedStateRoleV1 =
  | AdmitReserved
  | ReleaseReleased
  | TransferSourceReleased
  | TransferTargetReserved { target_ordinal: U64 }
  | ReleaseCurrentResourceReleased

Arch004CapacityPublishedStateEntryV1 = {
  role: Arch004CapacityPublishedStateRoleV1,
  state_digest: Digest(Arch004CapacityReservationStateV1),
  commitment_digest: Digest(Arch004CapacityReservationCommitmentV1),
  subject: Arch004CapacitySubjectV1,
}

Arch004CapacityCandidateStateV1 = {
  projection: Arch004CapacityPublishedStateEntryV1,
  state: Arch004CapacityReservationStateV1,
  state_digest: Digest(Arch004CapacityReservationStateV1),
  basis_bundle: Arch004CapacityStateBasisBundleV1,
  basis_bundle_digest: Digest(Arch004CapacityStateBasisBundleV1),
}

Arch004CapacityGenericReleaseCausePreimageV1 =
  | RetainedMetadataTerminal {
      cause: Arch004CapacityReleaseCauseV1::RetainedMetadataTerminal,
      terminal: Arch004RetainedMetadataTerminalV1,
    }
  | GenerationJournalRetentionTerminal {
      cause:
        Arch004CapacityReleaseCauseV1::GenerationJournalRetentionTerminal,
      terminal: Arch004GenerationJournalRetentionTerminalV1,
    }
  | RawFragmentRetentionTerminal {
      cause: Arch004CapacityReleaseCauseV1::RawFragmentRetentionTerminal,
      terminal: Arch004RawFragmentRetentionTerminalV1,
    }
  | DynamicCapacityObjectTerminal {
      cause: Arch004CapacityReleaseCauseV1::DynamicCapacityObjectTerminal,
      terminal: Arch004DynamicCapacityTerminalV1,
    }

Arch004CapacityRecoveryPublicationPreimageV1 =
  | None
  | RetainedMetadataTransfer {
      active: Arch004RetainedMetadataActiveV1,
    }
  | JournalPublication {
      persistence_receipt: Arch004ResourceJournalPersistenceReceiptV1,
      predecessor_active?: Arch004GenerationJournalRetentionActiveV1,
      successor_active: Arch004GenerationJournalRetentionActiveV1,
      envelope: Arch004JournalPublicationEnvelopeV1,
    }

Arch004CapacityCandidatePublicationSetV1 = {
  operation_id: FreshBytes32,
  publishing_transition_digest:
    Digest(Arch004CapacityLedgerTransitionV1),
  states:
    BoundedOrderedVector<
      Arch004CapacityCandidateStateV1,
      0..=checked_add(
        UdpDnsLimitSetV1.max_active_capacity_reservations, 1)>,
  state_count: U64,
  state_projection_root: Digest,
  predecessor_state_proofs:
    SortedUniqueVector<Arch004CapacityReservedStateProofV1, 0..=4>,
  predecessor_state_proof_root: Digest,
  generic_release_cause_preimage?:
    Arch004CapacityGenericReleaseCausePreimageV1,
  publication_preimage:
    Arch004CapacityRecoveryPublicationPreimageV1,
  candidate_set_root: Digest,
  accounted_bytes: PositiveU64,
}

Arch004CapacityDurableHeadSlotV1 =
  | Slot0
  | Slot1

Arch004CapacityDurableCommitRecordV1 = {
  ledger_id: Arch004CapacityLedgerId,
  durable_commit_index: PositiveU64,
  commit_observation_context:
    Arch004ObservationContextV1::CapacityCommit,
  commit_observation_context_digest:
    Digest(Arch004ObservationContextV1::CapacityCommit),
  commit_lease_binding_digest:
    Digest(Arch004PlanLeaseFenceBindingV1),
  commit_authority_spec_digest:
    Digest(Arch004CapacityCommitAuthoritySpecV1),
  commit_gate_permit_id: PermitId,
  commit_gate_channel_binding_digest: Bytes32,
  cas_linearized_at: MonotonicInstant,
  candidate_publication_set_digest:
    Digest(Arch004CapacityCandidatePublicationSetV1),
  candidate_state_count: U64,
  candidate_state_projection_root: Digest,
  head_slot: Arch004CapacityDurableHeadSlotV1,
  head_slot_generation: PositiveU64,
  expected_old_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  publishing_transition_digest:
    Digest(Arch004CapacityLedgerTransitionV1),
  resulting_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  resulting_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
}

Arch004CapacityDurableHeadSlotImageV1 = {
  slot: Arch004CapacityDurableHeadSlotV1,
  slot_generation: PositiveU64,
  durable_commit_record: Arch004CapacityDurableCommitRecordV1,
  durable_commit_record_digest:
    Digest(Arch004CapacityDurableCommitRecordV1),
  candidate_publication_set:
    Arch004CapacityCandidatePublicationSetV1,
  candidate_publication_set_digest:
    Digest(Arch004CapacityCandidatePublicationSetV1),
  publishing_transition: Arch004CapacityLedgerTransitionV1,
  publishing_transition_digest:
    Digest(Arch004CapacityLedgerTransitionV1),
  resulting_head: Arch004CapacityLedgerHeadV1,
  resulting_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  resulting_snapshot: Arch004CapacityLedgerSnapshotV1,
  resulting_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
}

Arch004CapacityDurableHeadGenesisV1 = {
  installation_id: InstallationId,
  ledger_id: Arch004CapacityLedgerId,
  slot: Exact(Arch004CapacityDurableHeadSlotV1::Slot0),
  slot_generation: ExactU64(1),
  genesis_head: Arch004CapacityLedgerHeadV1 {
    revision: ExactU64(0),
    last_transition_digest: Exact(None),
  },
  genesis_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  genesis_snapshot: Arch004CapacityLedgerSnapshotV1 {
    revision: ExactU64(0),
  },
  genesis_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
}

Arch004CapacityDurableHeadEmptyTargetV1 = {
  installation_id: InstallationId,
  ledger_id: Arch004CapacityLedgerId,
  slot: Exact(Arch004CapacityDurableHeadSlotV1::Slot1),
  slot_generation: ExactU64(0),
  next_slot_generation: ExactU64(1),
}

Arch004CapacityDurableHeadStoreSlotV1 =
  | EmptyTarget {
      body: Arch004CapacityDurableHeadEmptyTargetV1,
      body_digest: Digest(Arch004CapacityDurableHeadEmptyTargetV1),
    }
  | Genesis {
      body: Arch004CapacityDurableHeadGenesisV1,
      body_digest: Digest(Arch004CapacityDurableHeadGenesisV1),
    }
  | Committed {
      body: Arch004CapacityDurableHeadSlotImageV1,
      body_digest: Digest(Arch004CapacityDurableHeadSlotImageV1),
    }

Arch004CapacityPostCasReceiptUseV1 =
  | StateResolution { published_state_ordinal: U64 }
  | ResourcePublication {
      owner_subject: Arch004GenerationJournalRetentionSubjectV1,
    }

Arch004CapacityPostCasCommitReceiptV1 = {
  observation_context_digest:
    Digest(Arch004ObservationContextV1::CapacityCommit),
  durable_commit_record: Arch004CapacityDurableCommitRecordV1,
  durable_commit_record_digest:
    Digest(Arch004CapacityDurableCommitRecordV1),
  published_states:
    BoundedOrderedVector<
      Arch004CapacityPublishedStateEntryV1,
      0..=checked_add(
        UdpDnsLimitSetV1.max_active_capacity_reservations, 1)>,
  published_state_count: U64,
  published_state_set_root: Digest,
  committed_at: MonotonicInstant,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

Arch004CapacityPostCasCommitReceiptRefV1 = {
  receipt: Arch004CapacityPostCasCommitReceiptV1,
  receipt_digest: Digest(Arch004CapacityPostCasCommitReceiptV1),
  use: Arch004CapacityPostCasReceiptUseV1,
}

// Validator-only refinement. The proof is serialized out-of-line and charged;
// the refinement itself is never embedded into a reservation state or any
// object that carries its state digest.
Arch004CommittedCapacityStateResolutionV1 = {
  published_destination_index_entry:
    Arch004CapacityPublishedDestinationIndexEntryV1,
  published_destination_index_entry_digest:
    Digest(Arch004CapacityPublishedDestinationIndexEntryV1),
  published_destination_indirection:
    Arch004CapacityPublishedDestinationIndirectionV1,
  published_destination_indirection_digest:
    Digest(Arch004CapacityPublishedDestinationIndirectionV1),
  staged_destination_copy: Arch004CapacityStagedDestinationCopyV1,
  staged_destination_copy_digest:
    Digest(Arch004CapacityStagedDestinationCopyV1),
  state_publication_proof: Arch004CapacityStateProofEntryV1,
  state_publication_proof_digest:
    Digest(Arch004CapacityStateProofEntryV1),
}

Arch004CapacityReservationStateV1 =
  | Reserved {
      commitment: Arch004CapacityReservationCommitmentV1,
      commitment_digest:
        Digest(Arch004CapacityReservationCommitmentV1),
      revision: ExactU64(0),
      expected_old_head_digest: Digest(Arch004CapacityLedgerHeadV1),
      before_snapshot_digest:
        Digest(Arch004CapacityLedgerSnapshotV1),
      after_snapshot_digest:
        Digest(Arch004CapacityLedgerSnapshotV1),
      state_basis_bundle_digest:
        Digest(Arch004CapacityStateBasisBundleV1),
    }
  | Released {
      commitment: Arch004CapacityReservationCommitmentV1,
      commitment_digest:
        Digest(Arch004CapacityReservationCommitmentV1),
      revision: ExactU64(1),
      predecessor_reserved_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      expected_old_head_digest: Digest(Arch004CapacityLedgerHeadV1),
      before_snapshot_digest:
        Digest(Arch004CapacityLedgerSnapshotV1),
      after_snapshot_digest:
        Digest(Arch004CapacityLedgerSnapshotV1),
      state_basis_bundle_digest:
        Digest(Arch004CapacityStateBasisBundleV1),
      release_cause: Arch004CapacityReleaseCauseV1,
      released_at: MonotonicInstant,
    }

Arch004CapacityOperationOwnerEpochKeyV1 = {
  request_owner: Arch004CapacityOwnerV1,
  request_owner_epoch_id: Bytes32,
  sequence_domain_id: Bytes32,
  request_sequence: PositiveU64,
  admission_revision: PositiveU64,
  operation_intent_digest:
    Digest(Arch004CapacityLedgerOperationIntentV1),
  installation_id: InstallationId,
  session_id: SessionId,
  generation: Generation,
}

Arch004CapacityOperationOwnerEpochChannelKeyV1 = {
  registry_ordinal: U16,
  channel_binding_digest: Bytes32,
}

Arch004CapacityOperationOwnerEpochChannelRegistrationV1 = {
  owner_epoch_key: Arch004CapacityOperationOwnerEpochKeyV1,
  registry_ordinal: U16,
  accepting_lease: Arch004LeaseObservationContextV1,
  accepting_lease_digest: Digest(Arch004LeaseObservationContextV1),
  channel_binding_digest: Bytes32,
  transport_handle_identity_digest: Bytes32,
  channel_key_identity_digest: Bytes32,
  registered_at: MonotonicInstant,
}

Arch004CapacityOperationOwnerEpochRegistrySnapshotV1 = {
  owner_epoch_key: Arch004CapacityOperationOwnerEpochKeyV1,
  ledger_id: Arch004CapacityLedgerId,
  sequence_domain_id: Bytes32,
  revision: ExactU64(0),
  authority_context:
    Arch004ObservationContextV1::CapacityReplayRegistry {
      mode: Exact(LiveRegistry),
    },
  authority_context_digest:
    Digest(Arch004ObservationContextV1::CapacityReplayRegistry),
  event_store_id: Bytes32,
  event_store_store_slot_max_accounted_bytes: PositiveU64,
  transport_registry_identity_digest: Bytes32,
  channel_key_store_identity_digest: Bytes32,
  registrations:
    SortedUniqueNonEmptyVector<
      Arch004CapacityOperationOwnerEpochChannelRegistrationV1,
      1..=64>,
  registration_count: PositiveBoundedU16,
  registration_set_root: Digest,
  frozen_at: MonotonicInstant,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

Arch004CapacityOperationOwnerEpochRequestKeyV1 = {
  replay_request_digest:
    Digest(Arch004CapacityOperationReplayRequestV1),
  request_sequence: PositiveU64,
}

Arch004CapacityOperationOwnerEpochRetryTokenV1 = {
  owner_epoch_key_digest:
    Digest(Arch004CapacityOperationOwnerEpochKeyV1),
  registry_snapshot_digest:
    Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1),
  registration_digest:
    Digest(Arch004CapacityOperationOwnerEpochChannelRegistrationV1),
  request_key: Arch004CapacityOperationOwnerEpochRequestKeyV1,
  token_nonce: FreshBytes32,
}

Arch004CapacityOperationOwnerEpochClosureBranchLatchV1 =
  | Acknowledged {
      accepting_lease_digest: Digest(Arch004LeaseObservationContextV1),
      replay_deadline: SuspendAwareDeadline,
      accepting_lease_expires_at: SuspendAwareDeadline,
      branch_latch_record:
        Arch004CapacityOperationOwnerEpochChannelEventRecordV1 {
          event:
            Arch004CapacityOperationOwnerEpochChannelEventV1::
              ResponseAcknowledged,
        },
      branch_latch_record_digest:
        Digest(Arch004CapacityOperationOwnerEpochChannelEventRecordV1),
    }
  | Expired {
      accepting_lease_digest: Digest(Arch004LeaseObservationContextV1),
      replay_deadline: SuspendAwareDeadline,
      accepting_lease_expires_at: SuspendAwareDeadline,
      branch_latch_record:
        Arch004CapacityOperationOwnerEpochChannelEventRecordV1 {
          event:
            Arch004CapacityOperationOwnerEpochChannelEventV1::
              RequestTransportRetired,
        },
      branch_latch_record_digest:
        Digest(Arch004CapacityOperationOwnerEpochChannelEventRecordV1),
    }

Arch004CapacityOperationOwnerEpochTransportClosureHeadV1 = {
  transport_registry_identity_digest: Bytes32,
  owner_epoch_key_digest:
    Digest(Arch004CapacityOperationOwnerEpochKeyV1),
  revision: U64,
  closure_barrier_id: Bytes32,
  closure_branch_latch:
    Arch004CapacityOperationOwnerEpochClosureBranchLatchV1,
  closure_branch_latch_digest:
    Digest(Arch004CapacityOperationOwnerEpochClosureBranchLatchV1),
  active_transport_handle_digests: ExactVector<Bytes32, 0>,
  active_transport_handle_count: ExactU64(0),
  active_transport_handle_set_root: Digest,
  successor_registration: Exact(Prohibited),
  observed_at: MonotonicInstant,
}

Arch004CapacityOperationOwnerEpochKeyStoreClosureHeadV1 = {
  channel_key_store_identity_digest: Bytes32,
  owner_epoch_key_digest:
    Digest(Arch004CapacityOperationOwnerEpochKeyV1),
  revision: U64,
  closure_barrier_id: Bytes32,
  closure_branch_latch:
    Arch004CapacityOperationOwnerEpochClosureBranchLatchV1,
  closure_branch_latch_digest:
    Digest(Arch004CapacityOperationOwnerEpochClosureBranchLatchV1),
  loaded_channel_key_identity_digests: ExactVector<Bytes32, 0>,
  loaded_channel_key_identity_count: ExactU64(0),
  loaded_channel_key_identity_set_root: Digest,
  successor_key_load: Exact(Prohibited),
  observed_at: MonotonicInstant,
}

Arch004CapacityOperationOwnerEpochHistoricalClosureReadbackV1 = {
  authority_context:
    Arch004ObservationContextV1::CapacityReplayRegistry {
      mode: Exact(HistoricalCloseOnly),
    },
  authority_context_digest:
    Digest(Arch004ObservationContextV1::CapacityReplayRegistry),
  registry_snapshot_digest:
    Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1),
  registration:
    Arch004CapacityOperationOwnerEpochChannelRegistrationV1,
  registration_digest:
    Digest(Arch004CapacityOperationOwnerEpochChannelRegistrationV1),
  channel_key: Arch004CapacityOperationOwnerEpochChannelKeyV1,
  accepting_lease_expires_at: SuspendAwareDeadline,
  expected_transport_handle_digest: Bytes32,
  transport_registry_head:
    Arch004CapacityOperationOwnerEpochTransportClosureHeadV1,
  transport_registry_head_digest:
    Digest(Arch004CapacityOperationOwnerEpochTransportClosureHeadV1),
  expected_channel_key_identity_digest: Bytes32,
  channel_key_store_head:
    Arch004CapacityOperationOwnerEpochKeyStoreClosureHeadV1,
  channel_key_store_head_digest:
    Digest(Arch004CapacityOperationOwnerEpochKeyStoreClosureHeadV1),
  observed_at: MonotonicInstant,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

Arch004CapacityOperationOwnerEpochChannelClosureBasisV1 =
  | AcknowledgedRequest {
      request_key: Arch004CapacityOperationOwnerEpochRequestKeyV1,
      acknowledgement_nonce: Bytes32,
      open_replay_digest:
        Digest(Arch004CapacityOpenOperationReplayV1),
    }
  | AcknowledgedUnusedSibling
  | HistoricalExpired {
      readback:
        Arch004CapacityOperationOwnerEpochHistoricalClosureReadbackV1,
      readback_digest:
        Digest(Arch004CapacityOperationOwnerEpochHistoricalClosureReadbackV1),
    }

Arch004CapacityRequestRetirementBasisV1 =
  | PreCasAccepted {
      pending_admission_digest:
        Digest(Arch004CapacityPendingOperationAdmissionV1::Accepted),
      accepted_head_digest: Digest(Arch004CapacityLedgerHeadV1),
      accepted_watermark_digest:
        Digest(Arch004CapacityOperationReplayWatermarkV1),
    }
  | OpenReplay {
      open_replay_digest:
        Digest(Arch004CapacityOpenOperationReplayV1),
    }

Arch004CapacityOperationOwnerEpochChannelEventV1 =
  | RequestAccepted {
      request_key: Arch004CapacityOperationOwnerEpochRequestKeyV1,
    }
  | OperationReplayOpened {
      request_key: Arch004CapacityOperationOwnerEpochRequestKeyV1,
      open_replay_digest:
        Digest(Arch004CapacityOpenOperationReplayV1),
    }
  | RequestTransportRetired {
      request_key: Arch004CapacityOperationOwnerEpochRequestKeyV1,
      retirement_basis: Arch004CapacityRequestRetirementBasisV1,
    }
  | ResponseAcknowledged {
      request_key: Arch004CapacityOperationOwnerEpochRequestKeyV1,
      acknowledgement_nonce: Bytes32,
      open_replay_digest:
        Digest(Arch004CapacityOpenOperationReplayV1),
    }
  | RetryTokenIssued {
      retry_token: Arch004CapacityOperationOwnerEpochRetryTokenV1,
      retry_token_digest:
        Digest(Arch004CapacityOperationOwnerEpochRetryTokenV1),
    }
  | RetryTokenRetired {
      retry_token: Arch004CapacityOperationOwnerEpochRetryTokenV1,
      retry_token_digest:
        Digest(Arch004CapacityOperationOwnerEpochRetryTokenV1),
    }
  | ChannelClosed {
      channel_key: Arch004CapacityOperationOwnerEpochChannelKeyV1,
      closure_basis:
        Arch004CapacityOperationOwnerEpochChannelClosureBasisV1,
    }

Arch004CapacityOperationOwnerEpochChannelEventRecordV1 = {
  registry_snapshot_digest:
    Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1),
  registration_digest:
    Digest(Arch004CapacityOperationOwnerEpochChannelRegistrationV1),
  observation_stream_id: Bytes32,
  event_ordinal: U64,
  installed_revision: PositiveU64,
  predecessor_event_store_digest:
    Digest(Arch004CapacityOperationOwnerEpochEventStoreV1),
  event: Arch004CapacityOperationOwnerEpochChannelEventV1,
  observed_at: MonotonicInstant,
}

Arch004CapacityOperationOwnerEpochChannelEventObservationV1 = {
  event_record:
    Arch004CapacityOperationOwnerEpochChannelEventRecordV1,
  event_record_digest:
    Digest(Arch004CapacityOperationOwnerEpochChannelEventRecordV1),
  resulting_event_store_revision: PositiveU64,
  resulting_event_store_digest:
    Digest(Arch004CapacityOperationOwnerEpochEventStoreV1),
  authority_context:
    Arch004ObservationContextV1::CapacityReplayRegistry,
  authority_context_digest:
    Digest(Arch004ObservationContextV1::CapacityReplayRegistry),
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

Arch004CapacityOperationOwnerEpochChannelEventStreamV1 = {
  registration_digest:
    Digest(Arch004CapacityOperationOwnerEpochChannelRegistrationV1),
  observation_stream_id: Bytes32,
  event_records:
    BoundedOrderedVector<
      Arch004CapacityOperationOwnerEpochChannelEventRecordV1,
      0..=32>,
  event_count: U16,
  event_prefix_root: Digest,
}

Arch004CapacityOperationOwnerEpochEventStoreStateV1 =
  | Open
  | Sealed {
      barrier_id: Bytes32,
      sealed_at: MonotonicInstant,
    }

Arch004CapacityOperationOwnerEpochEventStoreV1 = {
  event_store_id: Bytes32,
  owner_epoch_key: Arch004CapacityOperationOwnerEpochKeyV1,
  registry_snapshot_digest:
    Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1),
  revision: U64,
  streams:
    SortedUniqueNonEmptyVector<
      Arch004CapacityOperationOwnerEpochChannelEventStreamV1,
      1..=64>,
  stream_count: PositiveBoundedU16,
  stream_set_root: Digest,
  state: Arch004CapacityOperationOwnerEpochEventStoreStateV1,
  accounted_bytes: PositiveU64,
}

Arch004CapacityOperationOwnerEpochChannelCensusLeafV1 = {
  registration:
    Arch004CapacityOperationOwnerEpochChannelRegistrationV1,
  registration_digest:
    Digest(Arch004CapacityOperationOwnerEpochChannelRegistrationV1),
  channel_key: Arch004CapacityOperationOwnerEpochChannelKeyV1,
  barrier_id: Bytes32,
  barrier_next_ordinal: PositiveU64,
  sealed_event_prefix:
    BoundedOrderedVector<
      Arch004CapacityOperationOwnerEpochChannelEventObservationV1,
      1..=32>,
  sealed_event_prefix_count: PositiveBoundedU16,
  sealed_event_prefix_root: Digest,
  sealed_event_record_prefix_root: Digest,
  closed_event:
    Arch004CapacityOperationOwnerEpochChannelEventObservationV1 {
      event_record.event:
        Arch004CapacityOperationOwnerEpochChannelEventV1::ChannelClosed,
    },
  closed_event_digest:
    Digest(Arch004CapacityOperationOwnerEpochChannelEventObservationV1),
  pending_request_keys:
    ExactVector<Arch004CapacityOperationOwnerEpochRequestKeyV1, 0>,
  pending_request_count: ExactU64(0),
  pending_request_set_root: Digest,
  pending_retry_tokens:
    ExactVector<Arch004CapacityOperationOwnerEpochRetryTokenV1, 0>,
  pending_retry_token_count: ExactU64(0),
  pending_retry_token_set_root: Digest,
  barrier_acknowledged_at: MonotonicInstant,
}

Arch004CapacityOperationOwnerEpochClosureCensusV1 = {
  registry_snapshot:
    Arch004CapacityOperationOwnerEpochRegistrySnapshotV1,
  registry_snapshot_digest:
    Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1),
  sealed_event_store:
    Arch004CapacityOperationOwnerEpochEventStoreV1 {
      state: Arch004CapacityOperationOwnerEpochEventStoreStateV1::Sealed,
    },
  sealed_event_store_digest:
    Digest(Arch004CapacityOperationOwnerEpochEventStoreV1),
  transport_registry_closure_head:
    Arch004CapacityOperationOwnerEpochTransportClosureHeadV1,
  transport_registry_closure_head_digest:
    Digest(Arch004CapacityOperationOwnerEpochTransportClosureHeadV1),
  channel_key_store_closure_head:
    Arch004CapacityOperationOwnerEpochKeyStoreClosureHeadV1,
  channel_key_store_closure_head_digest:
    Digest(Arch004CapacityOperationOwnerEpochKeyStoreClosureHeadV1),
  barrier_id: Bytes32,
  leaves:
    SortedUniqueNonEmptyVector<
      Arch004CapacityOperationOwnerEpochChannelCensusLeafV1,
      1..=64>,
  leaf_count: PositiveBoundedU16,
  leaf_set_root: Digest,
  registered_channel_key_set_root: Digest,
  closed_channel_key_set_root: Digest,
  total_pending_request_count: ExactU64(0),
  total_pending_retry_token_count: ExactU64(0),
  finalized_at: MonotonicInstant,
}

Arch004CapacityOperationOwnerEpochTerminalCandidateV1 = {
  owner_epoch_key: Arch004CapacityOperationOwnerEpochKeyV1,
  revision: ExactU64(1),
  predecessor_open_registry_snapshot_digest:
    Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1),
  closure_census:
    Arch004CapacityOperationOwnerEpochClosureCensusV1,
  closure_census_digest:
    Digest(Arch004CapacityOperationOwnerEpochClosureCensusV1),
  registry_snapshot_digest:
    Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1),
  state: Exact(Closed),
  closed_at: MonotonicInstant,
}

Arch004CapacityOperationOwnerEpochTerminalV1 = {
  candidate: Arch004CapacityOperationOwnerEpochTerminalCandidateV1,
  candidate_digest:
    Digest(Arch004CapacityOperationOwnerEpochTerminalCandidateV1),
  signing_context:
    Arch004ObservationContextV1::CapacityReplayRegistry,
  signing_context_digest:
    Digest(Arch004ObservationContextV1::CapacityReplayRegistry),
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

Arch004CapacityOperationOwnerEpochStateHeadV1 =
  | Open {
      registry_snapshot:
        Arch004CapacityOperationOwnerEpochRegistrySnapshotV1,
      registry_snapshot_digest:
        Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1),
    }
  | Closing {
      terminal_candidate:
        Arch004CapacityOperationOwnerEpochTerminalCandidateV1,
      terminal_candidate_digest:
        Digest(Arch004CapacityOperationOwnerEpochTerminalCandidateV1),
    }
  | Closed {
      terminal: Arch004CapacityOperationOwnerEpochTerminalV1,
      terminal_digest:
        Digest(Arch004CapacityOperationOwnerEpochTerminalV1),
    }

Arch004CapacityOperationReplayRequestV1 = {
  ledger_id: Arch004CapacityLedgerId,
  request_owner: Arch004CapacityOwnerV1,
  request_owner_epoch_id: Bytes32,
  owner_epoch_registry_snapshot:
    Arch004CapacityOperationOwnerEpochRegistrySnapshotV1,
  owner_epoch_registry_snapshot_digest:
    Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1),
  operation_intent_digest:
    Digest(Arch004CapacityLedgerOperationIntentV1),
  admission_revision: PositiveU64,
  accepting_lease: Arch004LeaseObservationContextV1,
  accepting_lease_digest: Digest(Arch004LeaseObservationContextV1),
  request_channel_binding_digest: Bytes32,
  replay_deadline: SuspendAwareDeadline,
  acknowledgement_nonce: FreshBytes32,
  sequence_domain_id: Bytes32,
  expected_old_watermark_digest:
    Digest(Arch004CapacityOperationReplayWatermarkV1),
  request_sequence: PositiveU64,
}

Arch004CapacityReplaySelectorEnvelopeV1 = {
  ledger_id: Arch004CapacityLedgerId,
  sequence_domain_id: Bytes32,
  request_sequence: PositiveU64,
  admission_revision: PositiveU64,
}

Arch004CapacityPendingOperationAdmissionV1 =
  | Idle {
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      last_admission_revision: U64,
    }
  | Accepted {
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      admission_revision: PositiveU64,
      operation_intent: Arch004CapacityLedgerOperationIntentV1,
      operation_intent_digest:
        Digest(Arch004CapacityLedgerOperationIntentV1),
      replay_request: Arch004CapacityOperationReplayRequestV1,
      replay_request_digest:
        Digest(Arch004CapacityOperationReplayRequestV1),
      accepted_head_digest: Digest(Arch004CapacityLedgerHeadV1),
      accepted_watermark_digest:
        Digest(Arch004CapacityOperationReplayWatermarkV1),
      owner_epoch_open_head_digest:
        Digest(Arch004CapacityOperationOwnerEpochStateHeadV1::Open),
      event_store_id: Bytes32,
      accepted_event_store_digest:
        Digest(Arch004CapacityOperationOwnerEpochEventStoreV1),
      request_accepted_record_digest:
        Digest(Arch004CapacityOperationOwnerEpochChannelEventRecordV1),
      accepted_at: MonotonicInstant,
      accounted_bytes: PositiveU64,
    }

Arch004CapacityReplayRecoveryStoreKindV1 =
  | PendingAdmission
  | OwnerEpochState
  | OwnerEpochEventStore
  | TransportClosureHead
  | ChannelKeyStoreClosureHead

Arch004CapacityReplayRecoveryStorePayloadV1 =
  | Vacant
  | PendingAdmission {
      body: Arch004CapacityPendingOperationAdmissionV1,
      body_digest: Digest(Arch004CapacityPendingOperationAdmissionV1),
    }
  | OwnerEpochState {
      body: Arch004CapacityOperationOwnerEpochStateHeadV1,
      body_digest:
        Digest(Arch004CapacityOperationOwnerEpochStateHeadV1),
    }
  | OwnerEpochEventStore {
      body: Arch004CapacityOperationOwnerEpochEventStoreV1,
      body_digest:
        Digest(Arch004CapacityOperationOwnerEpochEventStoreV1),
    }
  | TransportClosureHead {
      body: Arch004CapacityOperationOwnerEpochTransportClosureHeadV1,
      body_digest:
        Digest(Arch004CapacityOperationOwnerEpochTransportClosureHeadV1),
    }
  | ChannelKeyStoreClosureHead {
      body: Arch004CapacityOperationOwnerEpochKeyStoreClosureHeadV1,
      body_digest:
        Digest(Arch004CapacityOperationOwnerEpochKeyStoreClosureHeadV1),
    }

Arch004CapacityReplayRecoveryStoreSlotV1 =
  | EmptyTarget {
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      store_kind: Arch004CapacityReplayRecoveryStoreKindV1,
      slot: Exact(Arch004CapacityDurableHeadSlotV1::Slot1),
      slot_generation: ExactU64(0),
      next_slot_generation: ExactU64(1),
    }
  | Occupied {
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      store_kind: Arch004CapacityReplayRecoveryStoreKindV1,
      slot: Arch004CapacityDurableHeadSlotV1,
      slot_generation: PositiveU64,
      storage_revision: U64,
      payload: Arch004CapacityReplayRecoveryStorePayloadV1,
      payload_digest:
        Digest(Arch004CapacityReplayRecoveryStorePayloadV1),
    }

Arch004CapacityRetiredReplayCommitmentV1 = Bytes32

Arch004CapacityOperationReplayWatermarkV1 = {
  ledger_id: Arch004CapacityLedgerId,
  sequence_domain_id: Bytes32,
  revision: U64,
  highest_closed_sequence: U64,
  last_closed_replay_commitment?:
    Arch004CapacityRetiredReplayCommitmentV1,
  predecessor_watermark_digest?:
    Digest(Arch004CapacityOperationReplayWatermarkV1),
}

Arch004CapacityOperationReplayWatermarkSlotV1 = {
  slot: Arch004CapacityDurableHeadSlotV1,
  slot_generation: PositiveU64,
  watermark: Arch004CapacityOperationReplayWatermarkV1,
  watermark_digest:
    Digest(Arch004CapacityOperationReplayWatermarkV1),
}

Arch004CapacityOperationReplayWatermarkStoreSlotV1 =
  | EmptyTarget {
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      slot: Exact(Arch004CapacityDurableHeadSlotV1::Slot1),
      slot_generation: ExactU64(0),
      next_slot_generation: ExactU64(1),
    }
  | Occupied {
      body: Arch004CapacityOperationReplayWatermarkSlotV1,
      body_digest:
        Digest(Arch004CapacityOperationReplayWatermarkSlotV1),
    }

Arch004CapacityReleaseReplayCapsuleV1 = {
  replay_request: Arch004CapacityOperationReplayRequestV1,
  replay_request_digest:
    Digest(Arch004CapacityOperationReplayRequestV1),
  released_state_proof:
    Arch004CapacityStateProofEntryV1 {
      state: Arch004CapacityReservationStateV1::Released,
      publishing_transition.operation:
        Arch004CapacityLedgerOperationV1::Release,
      creation_role:
        Arch004CapacityPublishedStateRoleV1::ReleaseReleased,
    },
  released_state_proof_digest:
    Digest(Arch004CapacityStateProofEntryV1),
  replay_response_root: Digest,
  accounted_bytes: PositiveU64,
}

Arch004CapacityOperationReplayResultV1 =
  | PublishedBatch {
      receipt: Arch004CapacityPostCasCommitReceiptV1,
      receipt_digest: Digest(Arch004CapacityPostCasCommitReceiptV1),
      publication_marker:
        Arch004CapacityReceiptPublicationBatchMarkerV1,
      publication_marker_digest:
        Digest(Arch004CapacityReceiptPublicationBatchMarkerV1),
    }
  | GenericRelease {
      capsule: Arch004CapacityReleaseReplayCapsuleV1,
      capsule_digest: Digest(Arch004CapacityReleaseReplayCapsuleV1),
    }

Arch004CapacityOpenOperationReplayV1 = {
  replay_request: Arch004CapacityOperationReplayRequestV1,
  replay_request_digest:
    Digest(Arch004CapacityOperationReplayRequestV1),
  operation_id: FreshBytes32,
  publishing_transition_digest:
    Digest(Arch004CapacityLedgerTransitionV1),
  result: Arch004CapacityOperationReplayResultV1,
  replay_response_root: Digest,
  opened_at: MonotonicInstant,
  accounted_bytes: PositiveU64,
}

Arch004CapacityOperationOutcomeV1 =
  | Committed {
      open_replay: Arch004CapacityOpenOperationReplayV1,
      open_replay_digest:
        Digest(Arch004CapacityOpenOperationReplayV1),
    }
  | AlreadyCommitted {
      open_replay: Arch004CapacityOpenOperationReplayV1,
      open_replay_digest:
        Digest(Arch004CapacityOpenOperationReplayV1),
    }
  | Failed {
      error: Arch004ErrorV1 {
        code: Arch004ErrorCodeV1::Capacity(Arch004CapacityErrorCodeV1),
      },
    }

Arch004CapacityOperationReplayResultReceipt(
  open: Arch004CapacityOpenOperationReplayV1)
    -> Arch004CapacityPostCasCommitReceiptV1 =
  match open.result {
    PublishedBatch { receipt, .. } => receipt,
    GenericRelease { capsule, .. } =>
      capsule.released_state_proof.post_cas_receipt.receipt,
  }

Arch004CapacityOperationReplayAcknowledgementV1 = {
  open_replay_digest: Digest(Arch004CapacityOpenOperationReplayV1),
  operation_id: FreshBytes32,
  request_owner: Arch004CapacityOwnerV1,
  accepting_lease_digest: Digest(Arch004LeaseObservationContextV1),
  request_channel_binding_digest: Bytes32,
  acknowledgement_nonce: Bytes32,
  owner_epoch_terminal:
    Arch004CapacityOperationOwnerEpochTerminalV1 {
      signing_context.mode:
        LiveRegistry | HistoricalCompleteAcknowledgedClosure |
        HistoricalFinalizeInstalledRecord,
    },
  owner_epoch_terminal_digest:
    Digest(Arch004CapacityOperationOwnerEpochTerminalV1),
  acknowledged_at: MonotonicInstant,
  closed_at: MonotonicInstant,
}

Arch004CapacityOperationRequestOwnerUnreachabilityV1 = {
  replay_request_digest:
    Digest(Arch004CapacityOperationReplayRequestV1),
  registry_snapshot:
    Arch004CapacityOperationOwnerEpochRegistrySnapshotV1,
  registry_snapshot_digest:
    Digest(Arch004CapacityOperationOwnerEpochRegistrySnapshotV1),
  closure_census:
    Arch004CapacityOperationOwnerEpochClosureCensusV1,
  closure_census_digest:
    Digest(Arch004CapacityOperationOwnerEpochClosureCensusV1),
  owner_epoch_terminal:
    Arch004CapacityOperationOwnerEpochTerminalV1,
  owner_epoch_terminal_digest:
    Digest(Arch004CapacityOperationOwnerEpochTerminalV1),
  terminal_authority_context:
    Arch004ObservationContextV1::CapacityReplayRegistry {
      mode: HistoricalCloseOnly |
        HistoricalFinalizeInstalledRecord,
    },
  terminal_authority_context_digest:
    Digest(Arch004ObservationContextV1::CapacityReplayRegistry),
  authenticator: Arch004ExternalObservationAuthenticatorV1,
  observed_at: MonotonicInstant,
}

Arch004CapacityOperationReplayExpiryV1 = {
  open_replay_digest: Digest(Arch004CapacityOpenOperationReplayV1),
  replay_request_digest:
    Digest(Arch004CapacityOperationReplayRequestV1),
  request_owner: Arch004CapacityOwnerV1,
  accepting_lease_digest: Digest(Arch004LeaseObservationContextV1),
  request_channel_binding_digest: Bytes32,
  replay_deadline: SuspendAwareDeadline,
  owner_unreachability:
    Arch004CapacityOperationRequestOwnerUnreachabilityV1,
  observed_at: MonotonicInstant,
}

Arch004CapacityOperationReplayClosureV1 =
  | Acknowledged {
      acknowledgement:
        Arch004CapacityOperationReplayAcknowledgementV1,
    }
  | Expired {
      expiry: Arch004CapacityOperationReplayExpiryV1,
    }

Arch004CapacityClosedOperationReplayV1 = {
  open_replay_digest: Digest(Arch004CapacityOpenOperationReplayV1),
  replay_request: Arch004CapacityOperationReplayRequestV1,
  replay_request_digest:
    Digest(Arch004CapacityOperationReplayRequestV1),
  operation_id: FreshBytes32,
  publishing_transition_digest:
    Digest(Arch004CapacityLedgerTransitionV1),
  replay_response_root: Digest,
  closure: Arch004CapacityOperationReplayClosureV1,
  closed_at: MonotonicInstant,
  resulting_watermark: Arch004CapacityOperationReplayWatermarkV1,
  resulting_watermark_digest:
    Digest(Arch004CapacityOperationReplayWatermarkV1),
}

Arch004CapacityPostCasSidecarBodyV1 =
  | Receipt {
      receipt: Arch004CapacityPostCasCommitReceiptV1,
      receipt_digest: Digest(Arch004CapacityPostCasCommitReceiptV1),
    }
  | OpenOperationReplay {
      open_replay: Arch004CapacityOpenOperationReplayV1,
      open_replay_digest: Digest(Arch004CapacityOpenOperationReplayV1),
    }
  | ClosedOperationReplay {
      closed: Arch004CapacityClosedOperationReplayV1,
      closed_digest: Digest(Arch004CapacityClosedOperationReplayV1),
    }

Arch004CapacityPostCasSidecarV1 = {
  head_slot: Arch004CapacityDurableHeadSlotV1,
  head_slot_generation: PositiveU64,
  durable_commit_record_digest:
    Digest(Arch004CapacityDurableCommitRecordV1),
  body: Arch004CapacityPostCasSidecarBodyV1,
}

Arch004CapacityPostCasSidecarStorePayloadV1 =
  | Vacant {
      retired_through_sequence: U64,
    }
  | Present {
      sidecar: Arch004CapacityPostCasSidecarV1,
      sidecar_digest: Digest(Arch004CapacityPostCasSidecarV1),
    }

Arch004CapacityPostCasSidecarStoreSlotV1 =
  | EmptyTarget {
      installation_id: InstallationId,
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      store_slot: Exact(Arch004CapacityDurableHeadSlotV1::Slot1),
      store_slot_generation: ExactU64(0),
      next_store_slot_generation: ExactU64(1),
    }
  | Occupied {
      installation_id: InstallationId,
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      store_slot: Arch004CapacityDurableHeadSlotV1,
      store_slot_generation: PositiveU64,
      storage_revision: U64,
      payload: Arch004CapacityPostCasSidecarStorePayloadV1,
      payload_digest:
        Digest(Arch004CapacityPostCasSidecarStorePayloadV1),
    }

Arch004CapacityPublicationTransactionIdV1 = Bytes32

Arch004CapacityReceiptDestinationV1 =
  | StateResolution {
      state_proof: Arch004CapacityStateProofEntryV1,
      state_proof_digest: Digest(Arch004CapacityStateProofEntryV1),
      consuming_subject: Arch004CapacitySubjectV1,
      storage_location_id: Bytes32,
      accounted_bytes: PositiveU64,
    }
  | RetainedMetadataPublication {
      active: Arch004RetainedMetadataActiveV1,
      active_digest: Digest(Arch004RetainedMetadataActiveV1),
      storage_location_id: Bytes32,
      accounted_bytes: PositiveU64,
    }
  | ResourcePublication {
      owner_subject: Arch004GenerationJournalRetentionSubjectV1,
      proof_bundle: Arch004ResourcePublicationProofBundleV1,
      proof_bundle_digest:
        Digest(Arch004ResourcePublicationProofBundleV1),
      storage_location_id: Bytes32,
      accounted_bytes: PositiveU64,
    }

Arch004CapacityReceiptPublicationBatchV1 = {
  publication_transaction_id: Arch004CapacityPublicationTransactionIdV1,
  head_slot: Arch004CapacityDurableHeadSlotV1,
  head_slot_generation: PositiveU64,
  durable_commit_record_digest:
    Digest(Arch004CapacityDurableCommitRecordV1),
  receipt_digest: Digest(Arch004CapacityPostCasCommitReceiptV1),
  destinations:
    BoundedOrderedVector<
      Arch004CapacityReceiptDestinationV1,
      1..=checked_add(
        UdpDnsLimitSetV1.max_active_capacity_reservations, 2)>,
  destination_count: PositiveU64,
  destination_set_root: Digest,
  staged_copy_set_root: Digest,
  staged_copy_count: PositiveU64,
}

Arch004CapacityReceiptDestinationProjectionV1 =
  | StateResolution {
      state_digest: Digest(Arch004CapacityReservationStateV1),
      state_proof_digest: Digest(Arch004CapacityStateProofEntryV1),
      consuming_subject: Arch004CapacitySubjectV1,
      storage_location_id: Bytes32,
      accounted_bytes: PositiveU64,
    }
  | RetainedMetadataPublication {
      active_digest: Digest(Arch004RetainedMetadataActiveV1),
      subject: Arch004RetainedMetadataSubjectV1,
      reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      semantic_terminal: Arch004SemanticMetadataTerminalRefV1,
      storage_location_id: Bytes32,
      accounted_bytes: PositiveU64,
    }
  | ResourcePublication {
      owner_subject: Arch004GenerationJournalRetentionSubjectV1,
      proof_bundle_digest:
        Digest(Arch004ResourcePublicationProofBundleV1),
      storage_location_id: Bytes32,
      accounted_bytes: PositiveU64,
    }

Arch004CapacityStagedDestinationCopyV1 = {
  publication_transaction_id: Arch004CapacityPublicationTransactionIdV1,
  destination_ordinal: U64,
  staging_object_id: Bytes32,
  destination: Arch004CapacityReceiptDestinationV1,
  destination_digest: Digest(Arch004CapacityReceiptDestinationV1),
  destination_projection: Arch004CapacityReceiptDestinationProjectionV1,
  destination_projection_digest:
    Digest(Arch004CapacityReceiptDestinationProjectionV1),
  staged_at: MonotonicInstant,
}

Arch004CapacityPriorStatePublicationAttestationV1 = {
  predecessor_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  predecessor_state_proof_digest:
    Digest(Arch004CapacityReservedStateProofV1),
  origin_public_indirection_digest:
    Digest(Arch004CapacityPublishedDestinationIndirectionV1),
  origin_publication_certificate_digest:
    Digest(Arch004CapacityDestinationPublicationCertificateV1),
}

Arch004CapacityBatchValidationStateV1 = {
  projection: Arch004CapacityPublishedStateEntryV1,
  state: Arch004CapacityReservationStateV1,
  state_digest: Digest(Arch004CapacityReservationStateV1),
  basis_owner_subject: Arch004CapacitySubjectV1,
  basis_member_root: Digest,
  basis_accounted_bytes: PositiveU64,
  basis_bundle_digest: Digest(Arch004CapacityStateBasisBundleV1),
}

Arch004CapacityBatchValidationCapsuleV1 = {
  receipt: Arch004CapacityPostCasCommitReceiptV1,
  receipt_digest: Digest(Arch004CapacityPostCasCommitReceiptV1),
  candidate_publication_set_digest:
    Digest(Arch004CapacityCandidatePublicationSetV1),
  operation_id: FreshBytes32,
  publishing_transition_digest:
    Digest(Arch004CapacityLedgerTransitionV1),
  common_expected_old_head: Arch004CapacityLedgerHeadV1,
  common_expected_old_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  common_before_snapshot: Arch004CapacityLedgerSnapshotV1,
  common_before_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  common_after_snapshot: Arch004CapacityLedgerSnapshotV1,
  common_after_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  candidate_states:
    BoundedOrderedVector<
      Arch004CapacityBatchValidationStateV1,
      0..=checked_add(
        UdpDnsLimitSetV1.max_active_capacity_reservations, 1)>,
  candidate_state_count: U64,
  candidate_state_projection_root: Digest,
  candidate_predecessor_state_proof_root: Digest,
  predecessor_state_attestations:
    SortedUniqueVector<
      Arch004CapacityPriorStatePublicationAttestationV1,
      0..=4>,
  predecessor_state_attestation_count: U64,
  predecessor_state_attestation_set_root: Digest,
  publication_preimage: Arch004CapacityRecoveryPublicationPreimageV1,
  generic_release_cause_preimage: Exact(None),
  validation_root: Digest,
  accounted_bytes: PositiveU64,
}

Arch004CapacityDestinationPublicationCertificateV1 = {
  observation_context_digest:
    Digest(Arch004ObservationContextV1::CapacityCommit),
  publication_transaction_id: Arch004CapacityPublicationTransactionIdV1,
  activation_wal_revision: Arch004CapacityJointCowWalRevisionV1,
  activation_wal_transaction_id: Arch004CapacityJointCowWalTransactionIdV1,
  head_slot: Arch004CapacityDurableHeadSlotV1,
  head_slot_generation: PositiveU64,
  durable_commit_record_digest:
    Digest(Arch004CapacityDurableCommitRecordV1),
  receipt_digest: Digest(Arch004CapacityPostCasCommitReceiptV1),
  publication_batch_digest:
    Digest(Arch004CapacityReceiptPublicationBatchV1),
  destination_ordinal: U64,
  destination_digest: Digest(Arch004CapacityReceiptDestinationV1),
  staged_copy_digest: Digest(Arch004CapacityStagedDestinationCopyV1),
  destination_projection: Arch004CapacityReceiptDestinationProjectionV1,
  destination_projection_digest:
    Digest(Arch004CapacityReceiptDestinationProjectionV1),
  destination_count: PositiveU64,
  destination_set_root: Digest,
  staged_copy_set_root: Digest,
  validation_capsule: Arch004CapacityBatchValidationCapsuleV1,
  validation_capsule_digest:
    Digest(Arch004CapacityBatchValidationCapsuleV1),
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

Arch004CapacityDestinationActivationReceiptV1 = {
  observation_context_digest:
    Digest(Arch004ObservationContextV1::CapacityCommit),
  activation_wal_revision: Arch004CapacityJointCowWalRevisionV1,
  activation_wal_transaction_id: Arch004CapacityJointCowWalTransactionIdV1,
  activation_committed_checkpoint_digest:
    Digest(Arch004CapacityCommittedJointCowCheckpointV1),
  activation_checkpoint_body_digest:
    Digest(Arch004CapacityJointCowCheckpointBodyV1),
  activation_commit_marker_digest:
    Digest(Arch004CapacityJointCowCommitMarkerV1),
  publication_transaction_id: Arch004CapacityPublicationTransactionIdV1,
  destination_ordinal: U64,
  public_storage_location_id: Bytes32,
  prepared_index_region_digest:
    Digest(Arch004CapacityPublishedDestinationPreparedIndexRegionV1),
  public_indirection_digest:
    Digest(Arch004CapacityPublishedDestinationIndirectionV1),
  publication_certificate_digest:
    Digest(Arch004CapacityDestinationPublicationCertificateV1),
  activated_at: MonotonicInstant,
  authenticator: Arch004ExternalObservationAuthenticatorV1,
}

Arch004CapacityPublishedDestinationIndirectionV1 = {
  publication_transaction_id: Arch004CapacityPublicationTransactionIdV1,
  activation_wal_revision: Arch004CapacityJointCowWalRevisionV1,
  activation_wal_transaction_id: Arch004CapacityJointCowWalTransactionIdV1,
  destination_ordinal: U64,
  public_storage_location_id: Bytes32,
  staging_object_id: Bytes32,
  staged_copy_digest: Digest(Arch004CapacityStagedDestinationCopyV1),
  destination_digest: Digest(Arch004CapacityReceiptDestinationV1),
  publication_certificate:
    Arch004CapacityDestinationPublicationCertificateV1,
  publication_certificate_digest:
    Digest(Arch004CapacityDestinationPublicationCertificateV1),
  activated_at: MonotonicInstant,
}

Arch004CapacityPublishedDestinationPreparedIndexRegionV1 = {
  public_indirection: Arch004CapacityPublishedDestinationIndirectionV1,
  public_indirection_digest:
    Digest(Arch004CapacityPublishedDestinationIndirectionV1),
  reserved_index_accounted_bytes: PositiveU64,
}

Arch004CapacityPublishedDestinationActivationSuffixV1 = {
  activation_receipt: Arch004CapacityDestinationActivationReceiptV1,
  activation_receipt_digest:
    Digest(Arch004CapacityDestinationActivationReceiptV1),
}

Arch004CapacityPublishedDestinationIndexEntryV1 = {
  prepared_region:
    Arch004CapacityPublishedDestinationPreparedIndexRegionV1,
  prepared_region_digest:
    Digest(Arch004CapacityPublishedDestinationPreparedIndexRegionV1),
  activation_suffix?: Arch004CapacityPublishedDestinationActivationSuffixV1,
  activation_suffix_digest?:
    Digest(Arch004CapacityPublishedDestinationActivationSuffixV1),
}

Arch004CapacityReceiptPublicationBatchMarkerV1 = {
  publication_transaction_id: Arch004CapacityPublicationTransactionIdV1,
  head_slot: Arch004CapacityDurableHeadSlotV1,
  head_slot_generation: PositiveU64,
  durable_commit_record_digest:
    Digest(Arch004CapacityDurableCommitRecordV1),
  receipt_digest: Digest(Arch004CapacityPostCasCommitReceiptV1),
  publication_batch: Arch004CapacityReceiptPublicationBatchV1,
  publication_batch_digest:
    Digest(Arch004CapacityReceiptPublicationBatchV1),
  public_indirections:
    BoundedOrderedVector<
      Arch004CapacityPublishedDestinationIndirectionV1,
      1..=checked_add(
        UdpDnsLimitSetV1.max_active_capacity_reservations, 2)>,
  public_indirection_count: PositiveU64,
  public_indirection_set_root: Digest,
  opened_at: MonotonicInstant,
}

Arch004CapacityReceiptPublicationBatchMarkerStorePayloadV1 =
  | Vacant {
      retired_through_sequence: U64,
    }
  | Present {
      marker: Arch004CapacityReceiptPublicationBatchMarkerV1,
      marker_digest:
        Digest(Arch004CapacityReceiptPublicationBatchMarkerV1),
    }

Arch004CapacityReceiptPublicationBatchMarkerStoreSlotV1 =
  | EmptyTarget {
      installation_id: InstallationId,
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      store_slot: Exact(Arch004CapacityDurableHeadSlotV1::Slot1),
      store_slot_generation: ExactU64(0),
      next_store_slot_generation: ExactU64(1),
    }
  | Occupied {
      installation_id: InstallationId,
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      store_slot: Arch004CapacityDurableHeadSlotV1,
      store_slot_generation: PositiveU64,
      storage_revision: U64,
      payload:
        Arch004CapacityReceiptPublicationBatchMarkerStorePayloadV1,
      payload_digest:
        Digest(Arch004CapacityReceiptPublicationBatchMarkerStorePayloadV1),
    }

Arch004CapacityJointCowFixedStoreKindV1 =
  | Head
  | PendingAdmission
  | OwnerEpochState
  | OwnerEpochEventStore
  | TransportClosureHead
  | ChannelKeyStoreClosureHead
  | OperationWatermark
  | PostCasSidecar
  | PublicationBatchMarker

Arch004CapacityJointCowFixedStoreEnvelopeDigestV1 =
  | Head {
      digest: Digest(Arch004CapacityDurableHeadStoreSlotV1),
    }
  | PendingAdmission {
      digest: Digest(Arch004CapacityReplayRecoveryStoreSlotV1),
    }
  | OwnerEpochState {
      digest: Digest(Arch004CapacityReplayRecoveryStoreSlotV1),
    }
  | OwnerEpochEventStore {
      digest: Digest(Arch004CapacityReplayRecoveryStoreSlotV1),
    }
  | TransportClosureHead {
      digest: Digest(Arch004CapacityReplayRecoveryStoreSlotV1),
    }
  | ChannelKeyStoreClosureHead {
      digest: Digest(Arch004CapacityReplayRecoveryStoreSlotV1),
    }
  | OperationWatermark {
      digest: Digest(Arch004CapacityOperationReplayWatermarkStoreSlotV1),
    }
  | PostCasSidecar {
      digest: Digest(Arch004CapacityPostCasSidecarStoreSlotV1),
    }
  | PublicationBatchMarker {
      digest:
        Digest(Arch004CapacityReceiptPublicationBatchMarkerStoreSlotV1),
    }

Arch004CapacityJointCowCurrentEntryV1 = {
  kind: Arch004CapacityJointCowFixedStoreKindV1,
  current_envelope_digest:
    Arch004CapacityJointCowFixedStoreEnvelopeDigestV1,
  current_logical_or_storage_revision: U64,
  current_physical_slot: Arch004CapacityDurableHeadSlotV1,
  current_slot_generation: PositiveU64,
  installed_by_transaction_revision: Arch004CapacityJointCowWalRevisionV1,
  installed_by_transaction_id: Arch004CapacityJointCowWalTransactionIdV1,
}

Arch004CapacityJointCowParticipantV1 =
  | FixedStore {
      kind: Arch004CapacityJointCowFixedStoreKindV1,
      target_physical_slot: Arch004CapacityDurableHeadSlotV1,
      old_current_envelope_digest:
        Arch004CapacityJointCowFixedStoreEnvelopeDigestV1,
      old_target_raw_frame_digest: Bytes32,
      old_target_envelope_digest?:
        Arch004CapacityJointCowFixedStoreEnvelopeDigestV1,
      new_target_envelope_digest:
        Arch004CapacityJointCowFixedStoreEnvelopeDigestV1,
    }
  | PublicIndirection {
      activation_wal_revision: Arch004CapacityJointCowWalRevisionV1,
      activation_wal_transaction_id:
        Arch004CapacityJointCowWalTransactionIdV1,
      publication_transaction_id: Arch004CapacityPublicationTransactionIdV1,
      destination_ordinal: U64,
      public_storage_location_id: Bytes32,
      required_old_index_entry_digest: Exact(None),
      new_prepared_index_region_digest:
        Digest(Arch004CapacityPublishedDestinationPreparedIndexRegionV1),
      new_indirection_digest:
        Digest(Arch004CapacityPublishedDestinationIndirectionV1),
      publication_certificate_digest:
        Digest(Arch004CapacityDestinationPublicationCertificateV1),
    }

Arch004CapacityJointCowCheckpointBodyV1 = {
  installation_id: InstallationId,
  ledger_id: Arch004CapacityLedgerId,
  sequence_domain_id: Bytes32,
  wal_revision: Arch004CapacityJointCowWalRevisionV1,
  wal_slot: Arch004CapacityDurableHeadSlotV1,
  wal_slot_generation: PositiveU64,
  replaced_wal_slot_raw_frame_digest?: Bytes32,
  wal_attempt_nonce?: FreshBytes32,
  transaction_id: Arch004CapacityJointCowWalTransactionIdV1,
  predecessor_committed_checkpoint_digest?:
    Digest(Arch004CapacityCommittedJointCowCheckpointV1),
  participants:
    SortedUniqueVector<
      Arch004CapacityJointCowParticipantV1,
      0..=checked_add(
        UdpDnsLimitSetV1.max_active_capacity_reservations, 11)>,
  participant_count: U64,
  participant_set_root: Digest,
  base_fixed_participant_count: U64,
  base_fixed_participant_root: Digest,
  replay_fixed_participant_count: U64,
  replay_fixed_participant_root: Digest,
  public_indirection_participant_count: U64,
  public_indirection_participant_root: Digest,
  resulting_current_tuple:
    ExactVector<Arch004CapacityJointCowCurrentEntryV1, 9>,
  resulting_current_tuple_root: Digest,
  publications_settled_through_wal_revision:
    Arch004CapacityJointCowWalRevisionV1,
  accounted_bytes: PositiveU64,
}

Arch004CapacityJointCowDecisionV1 =
  | Prepared
  | Aborted
  | Committed

Arch004CapacityJointCowPrepareMarkerV1 = {
  wal_revision: Arch004CapacityJointCowWalRevisionV1,
  transaction_id: Arch004CapacityJointCowWalTransactionIdV1,
  checkpoint_body_digest: Digest(Arch004CapacityJointCowCheckpointBodyV1),
  participant_set_root: Digest,
  resulting_current_tuple_root: Digest,
  decision: Exact(Arch004CapacityJointCowDecisionV1::Prepared),
}

Arch004CapacityJointCowAbortMarkerV1 = {
  wal_revision: Arch004CapacityJointCowWalRevisionV1,
  transaction_id: Arch004CapacityJointCowWalTransactionIdV1,
  checkpoint_body_digest: Digest(Arch004CapacityJointCowCheckpointBodyV1),
  prepare_marker_digest: Digest(Arch004CapacityJointCowPrepareMarkerV1),
  participant_set_root: Digest,
  resulting_current_tuple_root: Digest,
  decision: Exact(Arch004CapacityJointCowDecisionV1::Aborted),
}

Arch004CapacityJointCowCommitMarkerV1 = {
  wal_revision: Arch004CapacityJointCowWalRevisionV1,
  transaction_id: Arch004CapacityJointCowWalTransactionIdV1,
  checkpoint_body_digest: Digest(Arch004CapacityJointCowCheckpointBodyV1),
  prepare_marker_digest: Digest(Arch004CapacityJointCowPrepareMarkerV1),
  participant_set_root: Digest,
  resulting_current_tuple_root: Digest,
  decision: Exact(Arch004CapacityJointCowDecisionV1::Committed),
}

Arch004CapacityJointCowFinalDecisionV1 =
  | Aborted {
      abort_marker: Arch004CapacityJointCowAbortMarkerV1,
      abort_marker_digest: Digest(Arch004CapacityJointCowAbortMarkerV1),
    }
  | Committed {
      commit_marker: Arch004CapacityJointCowCommitMarkerV1,
      commit_marker_digest: Digest(Arch004CapacityJointCowCommitMarkerV1),
    }

Arch004CapacityCommittedJointCowCheckpointV1 = {
  checkpoint_body_digest: Digest(Arch004CapacityJointCowCheckpointBodyV1),
  prepare_marker_digest: Digest(Arch004CapacityJointCowPrepareMarkerV1),
  commit_marker_digest: Digest(Arch004CapacityJointCowCommitMarkerV1),
}

Arch004CapacityJointCowWalStoreSlotV1 =
  | EmptyTarget {
      installation_id: InstallationId,
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      wal_slot: Exact(Arch004CapacityDurableHeadSlotV1::Slot1),
      wal_slot_generation: ExactU64(0),
      next_wal_slot_generation: ExactU64(1),
    }
  | Checkpoint {
      installation_id: InstallationId,
      ledger_id: Arch004CapacityLedgerId,
      sequence_domain_id: Bytes32,
      wal_slot: Arch004CapacityDurableHeadSlotV1,
      wal_slot_generation: PositiveU64,
      body: Arch004CapacityJointCowCheckpointBodyV1,
      body_digest: Digest(Arch004CapacityJointCowCheckpointBodyV1),
      prepare_marker?: Arch004CapacityJointCowPrepareMarkerV1,
      prepare_marker_digest?: Digest(Arch004CapacityJointCowPrepareMarkerV1),
      final_decision?: Arch004CapacityJointCowFinalDecisionV1,
      final_decision_digest?: Digest(Arch004CapacityJointCowFinalDecisionV1),
    }

Arch004CurrentResourcePresentV1 =
  | Active {
      commitment: Arch004CapacityReservationCommitmentV1,
      reserved_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
    }
  | Unresolved {
      commitment: Arch004CapacityReservationCommitmentV1,
      reserved_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
    }

Arch004CurrentResourceCapacityV1 =
  | NoCurrentResource
  | Present(Arch004CurrentResourcePresentV1)

Arch004JournalAppendProjectionV1 = {
  receipt_digest:
    Digest(Arch004ResourceJournalPersistenceReceiptV1),
  predecessor_journal_active_digest?:
    Digest(Arch004GenerationJournalRetentionActiveV1),
  current_journal_active_digest:
    Digest(Arch004GenerationJournalRetentionActiveV1),
}

Arch004JournalPublicationCapacityEffectV1 =
  | InitialSplit {
      source_resource_reserved_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      source_resource_released_state_digest:
        Digest(Arch004CapacityReservationStateV1::Released),
      journal_commitment:
        Arch004CapacityReservationCommitmentV1,
      journal_reserved_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      current_resource_capacity: Arch004CurrentResourceCapacityV1,
      before_snapshot_digest:
        Digest(Arch004CapacityLedgerSnapshotV1),
      after_snapshot_digest:
        Digest(Arch004CapacityLedgerSnapshotV1),
    }
  | AppendKeepCurrentResource {
      current_resource_capacity: Arch004CurrentResourcePresentV1,
      unchanged_journal_commitment:
        Arch004CapacityReservationCommitmentV1,
      unchanged_journal_reserved_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      before_snapshot_digest:
        Digest(Arch004CapacityLedgerSnapshotV1),
      after_snapshot_digest:
        Digest(Arch004CapacityLedgerSnapshotV1),
    }
  | AppendReleaseCurrentResource {
      source_current_resource_commitment:
        Arch004CapacityReservationCommitmentV1,
      source_current_resource_reserved_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      released_current_resource_state_digest:
        Digest(Arch004CapacityReservationStateV1::Released),
      unchanged_journal_commitment:
        Arch004CapacityReservationCommitmentV1,
      unchanged_journal_reserved_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      before_snapshot_digest:
        Digest(Arch004CapacityLedgerSnapshotV1),
      after_snapshot_digest:
        Digest(Arch004CapacityLedgerSnapshotV1),
    }

Arch004JournalPublicationEnvelopeV1 = {
  inner_record: Arch004ResourceJournalInnerRecordRefV1,
  append_projection: Arch004JournalAppendProjectionV1,
  capacity_effect: Arch004JournalPublicationCapacityEffectV1,
}

Arch004JournalAppendPublicationV1 = {
  persistence_receipt_digest:
    Digest(Arch004ResourceJournalPersistenceReceiptV1),
  predecessor_active_digest:
    Digest(Arch004GenerationJournalRetentionActiveV1),
  successor_active_digest:
    Digest(Arch004GenerationJournalRetentionActiveV1),
  publication_envelope_digest:
    Digest(Arch004JournalPublicationEnvelopeV1),
}

Arch004CapacityReservedStateProofV1 = {
  state: Arch004CapacityReservationStateV1::Reserved,
  state_digest: Digest(Arch004CapacityReservationStateV1::Reserved),
  basis_bundle: Arch004CapacityStateBasisBundleV1,
  basis_bundle_digest: Digest(Arch004CapacityStateBasisBundleV1),
  post_cas_receipt:
    Arch004CapacityPostCasCommitReceiptRefV1 {
      use: Arch004CapacityPostCasReceiptUseV1::StateResolution,
    },
  origin_public_indirection:
    Arch004CapacityPublishedDestinationIndirectionV1,
  origin_public_indirection_digest:
    Digest(Arch004CapacityPublishedDestinationIndirectionV1),
  publishing_transition: Arch004CapacityLedgerTransitionV1,
  publishing_transition_digest:
    Digest(Arch004CapacityLedgerTransitionV1),
  resulting_head: Arch004CapacityLedgerHeadV1,
  resulting_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  resulting_snapshot: Arch004CapacityLedgerSnapshotV1,
  resulting_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  creation_role:
    Arch004CapacityPublishedStateRoleV1::AdmitReserved |
    Arch004CapacityPublishedStateRoleV1::TransferTargetReserved,
  proof_root: Digest,
  accounted_bytes: PositiveU64,
}

Arch004CapacityStateProofEntryV1 = {
  state: Arch004CapacityReservationStateV1,
  state_digest: Digest(Arch004CapacityReservationStateV1),
  basis_bundle: Arch004CapacityStateBasisBundleV1,
  basis_bundle_digest: Digest(Arch004CapacityStateBasisBundleV1),
  post_cas_receipt:
    Arch004CapacityPostCasCommitReceiptRefV1 {
      use: Arch004CapacityPostCasReceiptUseV1::StateResolution,
    },
  predecessor_reserved_proof?: Arch004CapacityReservedStateProofV1,
  publishing_transition: Arch004CapacityLedgerTransitionV1,
  publishing_transition_digest:
    Digest(Arch004CapacityLedgerTransitionV1),
  resulting_head: Arch004CapacityLedgerHeadV1,
  resulting_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  resulting_snapshot: Arch004CapacityLedgerSnapshotV1,
  resulting_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  creation_role: Arch004CapacityPublishedStateRoleV1,
  proof_root: Digest,
  accounted_bytes: PositiveU64,
}

Arch004ResourcePublicationProofBundleV1 = {
  owner_subject: Arch004GenerationJournalRetentionSubjectV1,
  persistence_receipt: Arch004ResourceJournalPersistenceReceiptV1,
  persistence_receipt_digest:
    Digest(Arch004ResourceJournalPersistenceReceiptV1),
  current_journal_active: Arch004GenerationJournalRetentionActiveV1,
  current_journal_active_digest:
    Digest(Arch004GenerationJournalRetentionActiveV1),
  publication_envelope: Arch004JournalPublicationEnvelopeV1,
  publication_envelope_digest:
    Digest(Arch004JournalPublicationEnvelopeV1),
  publishing_transition: Arch004CapacityLedgerTransitionV1,
  publishing_transition_digest:
    Digest(Arch004CapacityLedgerTransitionV1),
  publishing_post_cas_receipt:
    Arch004CapacityPostCasCommitReceiptRefV1 {
      use: Arch004CapacityPostCasReceiptUseV1::ResourcePublication,
    },
  resulting_head: Arch004CapacityLedgerHeadV1,
  resulting_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  resulting_snapshot: Arch004CapacityLedgerSnapshotV1,
  resulting_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  capacity_state_entries:
    SortedUniqueNonEmptyVector<Arch004CapacityStateProofEntryV1, 1..=4>,
  proof_root: Digest,
  accounted_bytes: PositiveU64,
}

Arch004PublishedResourceEnvelopeRefV1 = {
  proof_bundle_digest:
    Digest(Arch004ResourcePublicationProofBundleV1),
  publication_indirection_digest:
    Digest(Arch004CapacityPublishedDestinationIndirectionV1),
}

Arch004CapacityTransferAuthorityV1 =
  | DatagramFlowRetention {
      terminal_flow: DatagramFlowClosedRefV1,
      retained_active_digest: Digest(Arch004RetainedMetadataActiveV1),
    }
  | DnsTransactionRetention {
      terminal_transaction: DnsTransactionTerminalRefV1,
      retained_active_digest: Digest(Arch004RetainedMetadataActiveV1),
    }
  | ResourceJournalPersisted {
      persistence_receipt_digest:
        Digest(Arch004ResourceJournalPersistenceReceiptV1),
      journal_active_digest:
        Digest(Arch004GenerationJournalRetentionActiveV1),
      publication_envelope_digest:
        Digest(Arch004JournalPublicationEnvelopeV1),
    }

Arch004CapacityTransferTargetV1 = {
  target_ordinal: U64,
  added_commitment: Arch004CapacityReservationCommitmentV1,
  published_reserved_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
}

Arch004CapacityLedgerOperationV1 =
  | Admit {
      added_commitment: Arch004CapacityReservationCommitmentV1,
      published_reserved_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
    }
  | Release {
      removed_commitment: Arch004CapacityReservationCommitmentV1,
      predecessor_reserved_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      release_cause_digest: Digest(Arch004CapacityReleaseCauseV1),
      published_released_state_digest:
        Digest(Arch004CapacityReservationStateV1::Released),
    }
  | Transfer {
      authority: Arch004CapacityTransferAuthorityV1,
      removed_commitment: Arch004CapacityReservationCommitmentV1,
      predecessor_reserved_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      targets:
        BoundedOrderedVector<
          Arch004CapacityTransferTargetV1,
          1..=UdpDnsLimitSetV1.max_active_capacity_reservations>,
      target_count: PositiveU64,
      published_source_released_state_digest:
        Digest(Arch004CapacityReservationStateV1::Released),
    }
  | PublishJournalAppend {
      publication: Arch004JournalAppendPublicationV1,
    }
  | ReleaseCurrentResourceAndPublishJournalAppend {
      removed_resource_commitment:
        Arch004CapacityReservationCommitmentV1,
      predecessor_reserved_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      published_released_state_digest:
        Digest(Arch004CapacityReservationStateV1::Released),
      release_cause:
        Arch004CapacityReleaseCauseV1::NonJournalResourceCompensated |
        Arch004CapacityReleaseCauseV1::NonJournalResourceRecovered,
      publication: Arch004JournalAppendPublicationV1,
    }

Arch004CapacityLedgerOperationIntentV1 = {
  operation_id: FreshBytes32,
  ledger_id: Arch004CapacityLedgerId,
  expected_old_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  before_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  after_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  operation: Arch004CapacityLedgerOperationV1,
}

Arch004CapacityLedgerTransitionV1 = {
  operation_intent: Arch004CapacityLedgerOperationIntentV1,
  operation_intent_digest:
    Digest(Arch004CapacityLedgerOperationIntentV1),
  operation_id: FreshBytes32,
  ledger_id: Arch004CapacityLedgerId,
  replay_request: Arch004CapacityOperationReplayRequestV1,
  replay_request_digest:
    Digest(Arch004CapacityOperationReplayRequestV1),
  expected_old_head_digest: Digest(Arch004CapacityLedgerHeadV1),
  before_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  after_snapshot_digest: Digest(Arch004CapacityLedgerSnapshotV1),
  operation: Arch004CapacityLedgerOperationV1,
}

Arch004ObservationRequirementV1 = {
  observation_kind: Exact(Arch004ResourceReadback),
  schema_version: ExactU16(1),
  verifier_identity: Bytes32,
  helper_nonce_binding: FreshBytes32,
  maximum_observation_age: PositiveBoundedDuration,
}

Arch004ApplyDurablePhaseV1 =
  | AppliedDurable
  | NoExternalEffectDurable
  | RecoveryRequiredDurable

Arch004CompensationDurablePhaseV1 =
  | CompensatedDurable
  | AlreadyCompensatedDurable
  | ExternalDriftPreservedDurable
  | RecoveryRequiredDurable

Arch004ResourcePlanBodyV1 =
  | UdpPath {
      dormant_declaration_actor_graph_digest: Digest(EgressActorGraphV1),
      expected_dynamic_binding_schema:
        ExactAscii("Arch004UdpPathBindingV1"),
    }
  | UdpAdmission {
      exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
      limit_outcome_policy_digest: Digest(Arch004LimitOutcomePolicyV1),
    }
  | DnsRoute {
      capability_matrices:
        SortedUniqueNonEmptyVector<DnsCapabilityMatrixV1, 1..=32>,
      resolver_bindings:
        | NoResolverDependencies
        | BindingSets {
            sets: SortedUniqueNonEmptyVector<
              Arch004ResolverPathBindingSetV1, 1..=32>,
          },
    }
  | DnsIntercept
  | DnsObserver {
      decoder_instance_id: DnsDecoderInstanceId,
      decoder_build: BoundedBuildIdentity,
      plaintext_producer_registry_spec:
        DnsPlaintextProducerRegistrySpecV1,
      exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
      limit_outcome_policy_digest: Digest(Arch004LimitOutcomePolicyV1),
      ambient_network: Prohibited,
    }

Arch004ResourcePlanV1 = {
  step_id: StepId,
  resource_schema_version: ExactU16(1),
  backend_schema_version: PositiveBoundedU16,
  platform_subject: Arch004PlatformSubjectV1,
  identity: Arch004ResourceIdentityV1,
  owner_marker: OwnerMarker,
  executor: Arch004ResourceExecutorV1,
  backend: Arch004ResourceBackendV1,
  body: Arch004ResourcePlanBodyV1,
  before_image: Arch004ResourceImageV1,
  intended_postcondition: Arch004IntendedPostconditionV1,
  mutation_condition: Arch004MutationConditionV1,
  compensation_algorithm: Arch004CompensationAlgorithmV1,
  conflict_key: Arch004ConflictKeyV1,
  dependency_step_ids: SortedUniqueVector<StepId>,
  resource_journal_allocation:
    Arch004ResourceJournalAllocationIdentityV1,
  capacity_requirement_digest: Digest(Arch004CapacityRequirementV1),
  limit_outcome_policy_digest: Digest(Arch004LimitOutcomePolicyV1),
  idempotency_key: IdempotencyKey,
  success_predicate: Arch004SuccessPredicateV1,
  observation_requirement: Arch004ObservationRequirementV1,
  deadline: SuspendAwareDeadline,
  expected_apply_result_schema: ExactAscii("Arch004ResourceResultV1"),
  expected_compensation_result_schema:
    ExactAscii("Arch004ResourceCompensationResultV1"),
}

Arch004ResourceResultV1 =
  | Applied {
      durable_phase: ExactAppliedDurable,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      resource_plan_digest: Digest(Arch004ResourcePlanV1),
      identity: Arch004ResourceIdentityV1,
      observed_after_image: Arch004ResourceImageV1,
      consumed_condition_evidence_ref: ResourceReadbackEvidenceRefV1,
      source_resource_reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
    }
  | AlreadyApplied {
      durable_phase: ExactAppliedDurable,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      resource_plan_digest: Digest(Arch004ResourcePlanV1),
      identity: Arch004ResourceIdentityV1,
      observed_after_image: Arch004ResourceImageV1,
      consumed_condition_evidence_ref: ResourceReadbackEvidenceRefV1,
      source_resource_reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
    }
  | Unapplied {
      durable_phase: ExactNoExternalEffectDurable,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      resource_plan_digest: Digest(Arch004ResourcePlanV1),
      identity: Arch004ResourceIdentityV1,
      observed_before_image: Arch004ResourceImageV1,
      no_owned_effect_evidence_ref: ResourceReadbackEvidenceRefV1,
      reason: Arch004ResourceFailureReasonV1,
      source_resource_reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
    }
  | AmbiguousRecoveryRequired {
      durable_phase: ExactRecoveryRequiredDurable,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      resource_plan_digest: Digest(Arch004ResourcePlanV1),
      identity: Arch004ResourceIdentityV1,
      reason: Arch004ResourceFailureReasonV1,
      last_observed_image_digest?: Digest(Arch004ResourceImageV1),
      last_observation_refs:
        SortedUniqueNonEmptyVector<ResourceReadbackEvidenceRefV1, 1..=8>,
      source_resource_reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
    }

Arch004InitialAppliedOutcomeV1 = Applied | AlreadyApplied

Arch004InitialAppliedResultRefV1 = {
  publication: Arch004PublishedResourceEnvelopeRefV1,
  required_inner_variant: Arch004InitialAppliedOutcomeV1,
  required_current_capacity: Exact(Active),
}

Arch004RecoveryAppliedRefV1 = {
  publication: Arch004PublishedResourceEnvelopeRefV1,
  required_inner_outcome: Exact(Applied),
  required_current_capacity: Exact(Active),
}

Arch004ActiveResourceEvidenceV1 =
  | InitialApply(Arch004InitialAppliedResultRefV1)
  | RecoveryApply(Arch004RecoveryAppliedRefV1)

Arch004ResourceCompensationResultV1 =
  | RestoredBefore {
      durable_phase: ExactCompensatedDurable,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      active_state_source: Arch004ActiveResourceEvidenceV1,
      source_resource_reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      observed_before_image: Arch004ResourceImageV1,
      consumed_condition_evidence_ref: ResourceReadbackEvidenceRefV1,
    }
  | AlreadyBefore {
      durable_phase: ExactAlreadyCompensatedDurable,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      active_state_source: Arch004ActiveResourceEvidenceV1,
      source_resource_reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      observed_before_image: Arch004ResourceImageV1,
      consumed_condition_evidence_ref: ResourceReadbackEvidenceRefV1,
    }
  | CreatedOwnedObjectAbsent {
      durable_phase: ExactCompensatedDurable,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      active_state_source: Arch004ActiveResourceEvidenceV1,
      source_resource_reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      absence_proof_ref: ResourceReadbackEvidenceRefV1,
    }
  | ExternalDriftPreserved {
      durable_phase: ExactExternalDriftPreservedDurable,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      active_state_source: Arch004ActiveResourceEvidenceV1,
      source_resource_reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      current_image_digest: Digest(Arch004ResourceImageV1),
      current_image_evidence_ref: ResourceReadbackEvidenceRefV1,
      bounded_diff_codes:
        SortedUniqueNonEmptyVector<Arch004ResourceDiffCodeV1>,
    }
  | AmbiguousRecoveryRequired {
      durable_phase: ExactRecoveryRequiredDurable,
      observation_context_digest: Digest(Arch004ObservationContextV1),
      active_state_source: Arch004ActiveResourceEvidenceV1,
      source_resource_reserved_capacity_state_digest:
        Digest(Arch004CapacityReservationStateV1::Reserved),
      reason: Arch004ResourceFailureReasonV1,
      last_observation_refs:
        SortedUniqueNonEmptyVector<ResourceReadbackEvidenceRefV1, 1..=8>,
    }

Arch004AmbiguousApplyResultRefV1 = {
  publication: Arch004PublishedResourceEnvelopeRefV1,
  required_inner_variant: Exact(AmbiguousRecoveryRequired),
  required_current_capacity: Exact(Unresolved),
}

Arch004AmbiguousCompensationResultRefV1 = {
  publication: Arch004PublishedResourceEnvelopeRefV1,
  required_inner_variant: Exact(AmbiguousRecoveryRequired),
  required_current_capacity: Exact(Unresolved),
}

Arch004CompensationDriftResultRefV1 = {
  publication: Arch004PublishedResourceEnvelopeRefV1,
  required_inner_variant: Exact(ExternalDriftPreserved),
  required_current_capacity: Exact(Unresolved),
}

Arch004ResourceRecoveryOriginV1 =
  | ApplyAmbiguity(Arch004AmbiguousApplyResultRefV1)
  | CompensationAmbiguity(Arch004AmbiguousCompensationResultRefV1)
  | CompensationDrift(Arch004CompensationDriftResultRefV1)

Arch004RecoveredCompensationOutcomeV1 =
  | RestoredBefore {
      observed_before_image: Arch004ResourceImageV1,
      consumed_condition_evidence_ref: ResourceReadbackEvidenceRefV1,
    }
  | AlreadyBefore {
      observed_before_image: Arch004ResourceImageV1,
      consumed_condition_evidence_ref: ResourceReadbackEvidenceRefV1,
    }
  | CreatedOwnedObjectAbsent {
      absence_proof_ref: ResourceReadbackEvidenceRefV1,
    }

Arch004ResourceRecoveryOutcomeV1 =
  | Applied {
      observed_after_image: Arch004ResourceImageV1,
      consumed_condition_evidence_ref: ResourceReadbackEvidenceRefV1,
    }
  | Unapplied {
      observed_before_image: Arch004ResourceImageV1,
      no_owned_effect_evidence_ref: ResourceReadbackEvidenceRefV1,
    }
  | Compensated {
      outcome: Arch004RecoveredCompensationOutcomeV1,
    }
  | ExternalDriftPreserved {
      current_image: Arch004ResourceImageV1,
      current_image_evidence_ref: ResourceReadbackEvidenceRefV1,
      bounded_diff_codes:
        SortedUniqueNonEmptyVector<Arch004ResourceDiffCodeV1>,
    }
  | OwnershipAbandoned {
      preserved_external_image: Arch004ResourceImageV1,
      ownership_absence_evidence_ref: OwnershipAbsenceEvidenceRefV1,
      all_flowprobe_owner_markers_and_dependent_effects_unreachable: true,
    }
  | StillRecoveryRequired {
      reason: Arch004ResourceFailureReasonV1,
      last_observation_refs:
        SortedUniqueNonEmptyVector<ResourceReadbackEvidenceRefV1, 1..=8>,
      retry_deadline: SuspendAwareDeadline,
    }

Arch004RecoverySuccessorPredecessorRefV1 =
  | StillRecoveryRequired {
      publication: Arch004PublishedResourceEnvelopeRefV1,
      required_inner_outcome: Exact(StillRecoveryRequired),
      required_current_capacity: Exact(Unresolved),
    }
  | ExternalDriftPreserved {
      publication: Arch004PublishedResourceEnvelopeRefV1,
      required_inner_outcome: Exact(ExternalDriftPreserved),
      required_current_capacity: Exact(Unresolved),
    }

Arch004ResourceRecoveryResolutionV1 = {
  origin: Arch004ResourceRecoveryOriginV1,
  identity: Arch004ResourceIdentityV1,
  resource_plan_digest: Digest(Arch004ResourcePlanV1),
  observation_context_digest: Digest(Arch004ObservationContextV1),
  source_resource_reserved_capacity_state_digest:
    Digest(Arch004CapacityReservationStateV1::Reserved),
  revision: U64,
  predecessor_resolution_envelope_ref?:
    Arch004RecoverySuccessorPredecessorRefV1,
  expected_journal_head_before_digest: Digest,
  expected_journal_ordinal_before: MonotonicSequence,
  outcome: Arch004ResourceRecoveryOutcomeV1,
  resolved_at: MonotonicInstant,
}

Arch004ResourceHealthObservationV1 = {
  observation_context_digest: Digest(Arch004ObservationContextV1),
  identity: Arch004ResourceIdentityV1,
  active_state_source: Arch004ActiveResourceEvidenceV1,
  observed_image: Arch004ResourceImageV1,
  health_predicate: Arch004SuccessPredicateV1,
  readback_refs:
    SortedUniqueNonEmptyVector<ResourceReadbackEvidenceRefV1, 1..=8>,
  observed_at: MonotonicInstant,
  expires_at: SuspendAwareDeadline,
}
```

Identity, backend, executor, images, condition, conflict key, result, and
compensation variants must all name the same resource kind. The only executor
mapping is: UDP path/admission to `ActorSocketFactoryOwner`; observer to
`CaptureCore`; runtime resolver/intercept to `NetworkRuntimeAdapter`; and
Windows/Linux system resolver mutations to `PrivilegedHelper`. A generic
executor, opaque backend, unknown image, or read-then-unconditional-write
condition has no encoding.

`Arch004IntendedPostconditionV1` is receipt/result-free and contains only values
known before `PlanDigest` exists. In particular, the UDP-path branch may name
the dormant declaration, stable resource identity, binding schema, closed latch,
and success predicate, but never an `Arch004UdpPathBindingV1`, observation
context, socket-child observation, result, or lease digest. The post-seal
`OperationalBindingReady` image appears only in an applied result. DNS route,
intercept, admission, and observer branches likewise encode a typed desired
state or predicate without a future observation. A plan-to-intended-state-to-
context-to-plan cycle is invalid.

The per-kind plan tuple is closed:

| Kind | Exact executor / backend / body / before / postcondition / condition / compensation / conflict / predicate |
| --- | --- |
| `transport.udp.path.v1` | `ActorSocketFactoryOwner / UdpPathFactory / UdpPath / UdpPath / UdpPath / NoExternalMutation / CloseExactUdpPathBinding / UdpPath / UdpPathBindingAcceptedAndLatched` |
| `transport.udp.admission.v1` | `ActorSocketFactoryOwner / UdpAdmissionOwner / UdpAdmission / UdpAdmission / UdpAdmission / NoExternalMutation / ReleaseExactUdpAdmission / UdpAdmission / UdpAdmissionCounterOpen` |
| `dns.route.v1` runtime | `NetworkRuntimeAdapter / RuntimeProtectedResolverV1 / DnsRoute / RuntimeResolver / RuntimeResolverPresent / RuntimeOwnedInstance / RestoreTypedBeforeImageIfExactAfter or RemoveExactExclusivelyOwnedCreatedObject / RuntimeResolver / RuntimeResolverConfigAndPathReadback` |
| `dns.route.v1` Windows | `PrivilegedHelper / WindowsInterfaceDnsSettingsV1 / DnsRoute / WindowsInterfaceDns / WindowsInterfaceDnsExact / ExactExclusiveOwnedObject / RestoreTypedBeforeImageIfExactAfter / WindowsInterfaceDns / WindowsInterfaceDnsExactManagedImage` |
| `dns.route.v1` resolved | `PrivilegedHelper / LinuxSystemdResolvedOwnedLinkFieldV1 / DnsRoute / LinuxResolvedLinkField / LinuxResolvedExactField / ExactExclusiveOwnedObject / RestoreTypedBeforeImageIfExactAfter / LinuxResolvedField / LinuxResolvedExactFieldImage` |
| `dns.route.v1` NetworkManager | `PrivilegedHelper / LinuxNetworkManagerAppliedConnectionV1 / DnsRoute / LinuxNetworkManagerAppliedConnection / LinuxNetworkManagerDnsProjection / NetworkManagerAppliedVersionCas / RestoreTypedBeforeImageIfExactAfter / LinuxNetworkManagerConnection / NetworkManagerExactAppliedConnectionImage` |
| `dns.intercept.v1` | `NetworkRuntimeAdapter / RuntimeProtectedPort53HijackV1 / DnsIntercept / DnsIntercept / DnsIntercept / RuntimeRuleOwnedInstance / RemoveRuntimeRuleAfterConsumersStop / RuntimePort53Rule / RuntimePort53RuleAndHandlerReadback` |
| `dns.observer.v1` | `CaptureCore / DnsObserverCaptureCore / DnsObserver / DnsObserver / DnsObserver / NoExternalMutation / StopExactObserverInstance / DnsObserver / ObserverRunningWithinBoundsNoAmbientNetwork` |

Within a row, every repeated platform subject, identity, actor, runtime, decoder/build, family,
egress, factory, limit, rule, field, owner, version/CAS, conflict, desired-state,
and predicate value is byte-identical. Before/observed images use that row's
variant, the applied result identity equals the plan identity, and its observed
image satisfies the intended postcondition under the exact success predicate.
Every read-back repeats that identity/image/context. Compensation, recovery,
health, and capacity subjects point back to the same row and plan. A same-kind
backend/body/image from another actor, build, resource, field, rule, limit,
version, or conflict key is a substitution attack and rejects the plan/result.
`ResourceExecution.platform_subject` is byte-identical to the plan field and to
the capability cell/UDP capability consuming its active-state evidence.
Every row also uses the displayed closed `Arch004ObservationRequirementV1`:
its only legal kind/body is `Arch004ResourceReadback`, and its verifier, nonce,
maximum age, plan lease and executor resolve to the exact registered
authenticator for that row. A helper-journal, DNS, host-association, capacity,
retention, or other inline observation kind cannot satisfy a resource plan.

The inner image transition is also fixed. UDP path is
`DormantDeclarationReady -> OperationalBindingReady ->
DormantDeclarationReady`; admission is `Closed -> Open(count=0) -> Closed`;
runtime port-53 intercept is `Absent -> Present -> Absent`; and observer is
`Inert|Stopped -> Running ->` the exact original inert/stopped tag. A preexisting
operational path, nonzero/open admission, present intercept, or running observer
cannot be adopted by these create/open algorithms. `AlreadyApplied` is legal
only when the exact intended state is already owned by this same plan and the
corresponding before/compensation lineage is preserved.

A runtime resolver uses `Absent -> Present -> Absent` only with
`RemoveExactExclusivelyOwnedCreatedObject`; `Present(before) -> Present(desired)
-> Present(before)` uses `RestoreTypedBeforeImageIfExactAfter`. Windows and
resolved route mutation always restores the exact typed before image.
NetworkManager preserves UUID/device and every non-DNS setting, applies the
desired DNS projection at a new CAS version, then restores the before DNS
projection at another new CAS version; semantic settings/digest equal the before
image while the OS-issued version monotonically advances. Result, recovery,
AlreadyApplied, and successful compensation branches obey the same transition;
an incompatible preexisting state is conflict/drift, not an adoptable before
image.

A `DnsRoute` plan body is the only location that may embed resolver binding
sets and their capability matrix bodies. `capability_matrices` is sorted
uniquely by deterministic CBOR of `DnsCapabilityResolverScopeV1` and contains
exactly one matrix for each reachable descriptor/use-site pair in
`BindingSets`; every binding set's `capability_matrix_spec_digest` resolves the
same in-plan body whose ten cells all carry that pair's exact
`PlannedResolverDependency` scope and the route's network scope. No matrix may
name another pair or be shared across two use sites. With
`NoResolverDependencies`, the vector contains exactly one route/platform
matrix and every cell uses the backend-derived `ExactNativeResolverScope` or
`NoResolverScope`; `PlannedResolverDependency` is forbidden in that branch.
Thus a candidate-plan matrix is always enumerable from the closed plan body,
not a dangling digest or post-seal object. Missing, duplicate, orphan, extra,
cross-scope, or digest-mismatched matrices reject preparation.

`NoResolverDependencies` is exact for zero reachable pairs; otherwise the
`BindingSets.sets` vector is sorted by `(descriptor digest,
deterministic_cbor(use_site))`, contains exactly one set for each reachable
descriptor/use-site pair assigned to that route node, and has no duplicate
pair/path ID. Every set's `plan_node_identity` is byte-identical to the
enclosing `DnsRouteResourceIdentityV1`; its members may name only route
identities reachable through declared dependency steps. The set points to the
stable resource identity and never to `Digest(Arch004ResourcePlanV1)`, while the
plan owns the set body, so the edge is encodable and acyclic.

Recovery is one compare-and-append chain rooted in exactly one ambiguous apply,
ambiguous compensation, or compensation `ExternalDriftPreserved` publication
envelope. Revision zero has no predecessor; every
later revision is exactly one greater, names the exact published envelope of
the current `StillRecoveryRequired` or `ExternalDriftPreserved` resolution, and preserves origin, identity,
resource plan, lease context, allocation, and the same current ResourceNode
`Reserved` digest byte-for-byte. `StillRecoveryRequired` and
`ExternalDriftPreserved` may have a bounded successor, and that successor is one
of the displayed outcomes; `Applied`, `Unapplied`, `Compensated`, and
`OwnershipAbandoned` are absorbing. A compensation drift publication may start
revision zero. `OwnershipAbandoned` preserves the foreign image and releases
only after typed read-back proves every FlowProbe owner marker and dependent
effect unreachable; it never overwrites or adopts drift. The
displayed journal head digest/ordinal are the values immediately before the
inner append; the receipt, active successor, publication envelope and capacity
head then advance under the protocol below. A stale head, fork, skipped
revision, cross-resource splice, sibling resolution, or post-terminal append is
invalid. Health and compensation consume the closed published
`Arch004ActiveResourceEvidenceV1`, so a recovered `Applied` state cannot be
confused with an unrelated or merely durable-but-unpublished inner record.

Ownership-absence read-back is complete per resource kind: UDP path enumerates
the binding, socket child and factory-owned effects; UDP admission enumerates
the admission/counter owner; DNS route enumerates its exact backend object and
declared dependency closure; DNS intercept enumerates the protected rule and
handler closure; DNS observer enumerates the instance, buffers and registered
indexes. The plan deterministically derives both universe roots/counts, and the
authenticated read-back reports zero observed FlowProbe markers and zero
reachable dependent effects over those complete universes. An ordinary success
predicate, omitted marker/effect, mismatched foreign image, or wrong-kind
universe cannot authorize abandonment.

Every plan's limit-policy digest resolves to the exact limit-set digest named
by its capacity requirement and resource body. UDP admission and DNS observer
bodies repeat it byte-for-byte. Each dimension appears once in fixed order.
`DecodeOpaqueAndContinueSelectedPath` is accepted only when the sealed policy
proves that dimension is not needed by forwarding, routing, exclusion, health,
or leak prevention; otherwise the entry is block, refuse, close, or fence. A
missing dimension, producer-selected default, or policy digest from another
limit set rejects preparation.

Every ARCH-004 prepared-plan package registers exactly one
`Arch004CapacityLedgerManifestV1`. Its digest is the byte-identical
`capacity_ledger_manifest_digest` in every lease/fence binding under that plan;
the manifest itself contains no plan digest or post-seal gate and therefore
cannot form a plan cycle. Its commit and replay-registry authority specs are
each unique by component, build, public key and their distinct gate
registration digest. Its replay-epoch recovery budget body/digest are exact and
are recomputed from the same sealed limit set. Each replay-epoch
`max_*_store_slot_*` value is the larger canonical encoded length of the
complete kind-correct EmptyTarget arm or the complete Occupied arm carrying
that kind's largest legal payload.
That containing-slot maximum includes the union tag, installation/ledger/domain
and kind, physical slot/generation, storage revision, the complete payload body
and digest, and per-slot framing/checksum. In particular, the event-store
payload reaches the 64-stream/32-record bound; the owner-state payload includes
the full 64-leaf signed census/terminal and both closure heads with their exact
largest branch latch. Every checked multiply/add in
`max_total_accounted_bytes` must succeed. Every registry snapshot repeats
`event_store_store_slot_max_accounted_bytes = manifest.
replay_epoch_recovery_budget.max_event_store_store_slot_accounted_bytes`;
an operation-selected smaller charge or a manifest under the canonical maximum
is invalid. The base ledger budget body/digest are likewise exact and every
base `max_*_store_slot_*` value has the same complete containing-slot meaning.
The head maximum is the largest of its complete EmptyTarget, Genesis and
Committed arms; its Committed arm includes the largest candidate set, transition,
resulting head and sole embedded resulting snapshot. Let
`N = max_active_capacity_reservations`, `C = checked_add(N, 1)` and
`D = checked_add(N, 2)`. The marker maximum uses exactly the `D`-destination
maximum and includes the full batch, `D` public indirections/certificates, and
one complete maximum flat validation capsule physically embedded in every
certificate; the sidecar maximum includes the largest Open or Closed replay
embedding that marker.

The capsule maximum stores one common expected-old-head body and one common
before/after snapshot pair, with all three digests, exactly once. It then stores
at most `C` flat `Arch004CapacityBatchValidationStateV1` members. Each flat
member carries only the current projection/state bodies plus the owner, member
root, accounted bytes and digest needed to reconstruct its original
`Arch004CapacityStateBasisBundleV1` from those common bodies. It also includes
the signed receipt, four fixed predecessor attestations and the larger retained-
metadata or journal publication preimage; it includes no prior full batch,
certificate or indirection. Because each common snapshot and the flat vector are
both linear in `N`, one capsule is `Theta(N)`. Physically duplicating it in the
`D` certificates makes the marker/Open certificate portion `Theta(N^2)`, never
`Theta(N^3)`. A maximum StateResolution destination also charges its complete
current proof and, when Released, one complete predecessor Reserved proof with
that predecessor's one public indirection/certificate/flat capsule. Every `C`,
`D`, multiply and add is checked; overflow rejects the limit set. Canonical
durable accounting charges every physical capsule copy and MUST NOT assume
deduplication or shared in-memory representation. These bounds remain fixed-
depth across operation history. Each destination maximum additionally includes
the complete public-index entry with its maximum activation suffix. The
immutable Prepared region's `reserved_index_accounted_bytes` reserves that
entire framed maximum, including its tag-`0x400D` receipt suffix, so suffix
append adds no unreserved byte and does not double-charge the one index
location. The ledger-budget total is exactly

```text
ledger_recovery_budget.max_total_accounted_bytes = checked_add(
  checked_mul(2,
    ledger_recovery_budget.max_head_store_slot_accounted_bytes),
  checked_mul(2,
    ledger_recovery_budget.max_post_cas_sidecar_store_slot_accounted_bytes),
  checked_mul(2,
    ledger_recovery_budget.
      max_publication_batch_marker_store_slot_accounted_bytes),
  checked_mul(2,
    ledger_recovery_budget.max_operation_watermark_store_slot_accounted_bytes),
  checked_mul(2,
    ledger_recovery_budget.max_joint_cow_wal_store_slot_accounted_bytes))
```

Its five count fields equal the schema constants. The replay-epoch total is the
separate checked equation and does not contain another WAL charge:

```text
replay_epoch_recovery_budget.max_total_accounted_bytes = checked_add(
  checked_mul(2,
    replay_epoch_recovery_budget.
      max_pending_admission_store_slot_accounted_bytes),
  checked_mul(2,
    replay_epoch_recovery_budget.
      max_owner_epoch_state_store_slot_accounted_bytes),
  checked_mul(2,
    replay_epoch_recovery_budget.max_event_store_store_slot_accounted_bytes),
  checked_mul(2,
    replay_epoch_recovery_budget.
      max_transport_closure_head_store_slot_accounted_bytes),
  checked_mul(2,
    replay_epoch_recovery_budget.
      max_channel_key_store_closure_head_store_slot_accounted_bytes))
```

The five exact slot counts in the replay-epoch budget must all be two. There is
one global pair of `Arch004CapacityJointCowWalStoreSlotV1` slots for both the
four base stores and five replay stores, and those two slots are charged exactly
once by the ledger recovery budget. The maximum joint-WAL slot is the larger
canonical encoded length of its complete EmptyTarget arm or its complete
Checkpoint arm carrying the maximum body, Prepare marker, final-decision union
and independently checksummed framing; the atomic final-decision region is
sized for the larger complete Aborted or Committed union arm including its
variant tag, inner marker/digest, outer final-decision digest and framing, never
both arms. The maximum body
contains at most `N + 11` digest-only
participants, the exact nine-entry resulting-current tuple, every count/root,
the settlement scalar and accounted bytes. It never embeds a target envelope or
payload; those bytes are charged only by the corresponding two-slot store
maxima. A redo WAL containing payload bytes is not the canonical V1 encoding.
The allocator reserves both `ledger_recovery_budget.max_total_accounted_bytes`
and `replay_epoch_recovery_budget.max_total_accounted_bytes`; no WAL byte is
omitted or charged in both totals.

After canonical genesis initialization, every creation, transition, cleanup
replacement or logical selection change of any of the nine fixed-store
envelopes, including an otherwise single-store write, MUST be a FixedStore
participant of this global checkpoint protocol.
Later references to an “atomic store transaction”, “joint transaction”, “CAS”
or “copy-on-write append” are semantic shorthand for the compare, target write
and one global Commit-marker sequence defined here. They do not authorize a
second WAL, a direct current-pointer change or any per-store commit primitive.

The global WAL has one commit decision and no base/replay fragment decisions. Fixed
participants are ordered first in
`Arch004CapacityJointCowFixedStoreKindV1` declaration order; public-indirection
participants follow, ordered uniquely by `(publication_transaction_id,
destination_ordinal, public_storage_location_id)`. The union count/root cover
that complete vector. Each base/replay/public subcount and subroot is the exact
stable filter of the union vector, preserving union order. The base kinds are
Head, OperationWatermark, PostCasSidecar and PublicationBatchMarker; the replay
kinds are the other five. Every fixed participant's three typed envelope
digests use the arm matching its `kind`.

There is exactly one FixedStore participant iff that kind's resulting tuple
entry differs from the predecessor tuple. Its `old_current_envelope_digest`
equals `predecessor_tuple[kind].current_envelope_digest` and the matching typed
digest arm of the complete currently selected kind-correct envelope.
`target_physical_slot` is the other physical slot. Its
raw-frame digest covers that exact bounded slot before overwrite and is the
linearizable compare-and-replace precondition. `old_target_envelope_digest` is
present iff the raw frame decodes as one complete valid kind/ledger/domain/slot
envelope, in which case its typed digest is exact; it is absent iff no complete
kind-correct envelope can be decoded at that location. A wrong kind, invalid
framing or torn body is never represented as a typed digest. The new target
must be a complete kind-correct envelope at that same physical slot and its
typed digest equals `resulting_current_tuple[kind].current_envelope_digest`.
That resulting entry separately binds kind, physical slot, generation,
logical/storage revision and installing WAL revision/transaction. A missing,
extra, duplicate, reordered,
wrong-kind or root/count-mismatched member invalidates the checkpoint.

Every PublicIndirection participant has activation revision and transaction ID
equal to the enclosing body, `required_old_index_entry_digest = None`, and a
currently canonically absent index location. That absence is either an unused
location or absence read back after exact Aborted-attempt cleanup; “fresh” never
means a same-operation retry must invent a different consumer location. Its
Prepared index-region digest has indirection/certificate bodies equal to the
participant fields. The certificate and indirection repeat that same activation
tuple, publication transaction, ordinal and location. Public participants never
enter the fixed current tuple.

At genesis, WAL Slot0 contains revision zero/generation one with a valid
Checkpoint body, Prepare marker and Committed final decision; Slot1 is the exact
EmptyTarget at physical generation zero with next generation one. The genesis
body has no predecessor, attempt nonce or replaced-slot raw-frame digest because
canonical provisioning creates Slot0 rather than replacing an earlier frame. It
has an empty participant union and canonical empty subroots, and its exact
nine-entry tuple names the complete genesis current envelope for every fixed
store. Every tuple entry records install revision zero and the genesis
transaction ID. `publications_settled_through_wal_revision` is zero, and no
revision-zero public participant or certificate is legal.

For every non-genesis WAL revision `n`, `wal_slot = Slot(n mod 2)` and
`wal_slot_generation = floor(n / 2) + 1`; its predecessor digest names exactly
the committed revision `n - 1` checkpoint. `wal_attempt_nonce` is present,
nonzero and fresh across every attempt in the ledger, including retries of the
same revision; the transaction ID is recomputed by the displayed target-
independent formula from the ledger identity, revision, predecessor and nonce.
The replaced-WAL-slot raw-frame digest is present and is the exact compare-and-replace
precondition for the alternate WAL frame, so two writers based on the same
predecessor cannot both install a Prepared body. The resulting-current tuple has exactly one entry for each of
the nine kinds in declaration order. An unchanged entry is copied byte-for-byte
from the predecessor tuple. A changed entry names the participant's exact new
target envelope and records `installed_by_transaction_revision = n` and the
current transaction ID. Its physical slot, generation and logical/storage
revision equal the typed envelope. No envelope chooses itself as current; the
committed tuple is the sole installation authority.

Only one revision may be Prepared. A new attempt computes all target bodies/
digests and the complete checkpoint body, atomically compare-and-replaces the
alternate WAL raw frame, fsyncs and reads back the body, then appends/fsyncs/
readbacks the bounded Prepare marker. That Prepare append is one atomic CAS over
the exact enclosing body/body digest, an absent Prepare region and an absent
final-decision region; a stale coordinator whose body was replaced cannot write
its marker into another attempt. No participant target may be written
before that marker is valid. It then compare-and-replaces every named fixed-
store raw target frame and writes every Prepared public-index target, fsyncing
and digest-checking each one. Every such target write atomically rechecks that
the WAL slot still contains this exact body plus valid Prepare marker and an
absent final-decision region, and presents the non-reusable target-write capability
derived from those two digests. Replacing the WAL frame or atomically installing
either final-decision arm revokes that capability, so a paused writer from an older nonce
cannot write either a fixed slot or a different public location. Last, it
atomically compare-and-installs the Committed arm, containing the Commit marker,
by comparing the exact enclosing body/body digest, exact valid Prepare body/
digest and empty final-decision region,
fsyncs and reads it back. That marker is the sole commit decision and
linearization point for the entire participant union. Independent per-store
decisions, “highest valid store” selection, or a second base/replay commit
marker have no V1 encoding.

A body without a Prepare marker is not Prepared and, by construction, cannot
have participant targets; it may be discarded after its frame is verified to
contain no valid prepare region. A valid Prepare marker with an empty final-
decision region is an in-flight uncommitted attempt. Recovery may finish its
exact body, or atomically install the bounded Aborted arm into that empty region.
Aborted and Committed are the two arms of one typed final-decision union and use
the same region/CAS. Each final CAS compares the exact enclosing body/body
digest, exact valid Prepare body/digest and absent final decision before writing
the complete chosen arm/body/digest; a stale or competing attempt cannot poison
the slot, and both arms can never be encoded. The durable Abort marker
immediately revokes every target-write capability and
never changes the predecessor current tuple. Cleanup then presents the distinct
abort-cleanup capability derived from body/Prepare/Abort digests, atomically
rechecks that exact Aborted WAL slot, removes every Prepared public-index target
and reads back absence. A crash during cleanup resumes that same bounded delete;
a stale target writer cannot recreate an entry after Abort. Fixed targets remain
non-current. Only after all public absences read back may the aborted WAL frame
be replaced. A retry uses the same WAL
revision with a fresh nonce and transaction ID; each fixed participant compares
the actual alternate raw frame, using a present old-target digest for a complete
aborted target or absence for a torn/non-envelope frame, then overwrites that
one non-current location. This is the only legal replacement of an uncommitted
same-logical-revision target. The prior attempt never had a Commit marker, all
of its public targets are absent, and after the new target readback only one
complete envelope remains in that physical slot. An unlisted stale fixed target
may remain non-current until that kind next changes; it can never enter the
tuple and its then-current raw frame becomes that future participant's exact
old-target precondition.

The WAL slot uses separately framed and checksummed header/body, atomic Prepare-
marker and atomic final-decision regions. The Prepare body/digest pair and the
final-decision body/digest pair are each either both absent or both present and
valid. A present final decision is exactly one typed Aborted or Committed arm;
each arm contains exactly one valid marker/body-digest pair, requires a valid
Prepare marker and repeats its exact digest. Prepare and both final variants repeat the body's revision,
transaction ID, body digest, participant root and resulting tuple root; any
unequal field is corruption. A canonically absent Prepare
region proves targets were never authorized. A nonempty invalid marker region,
a valid Prepare marker with an invalid body, an unknown/multiply encoded final
decision, or a final marker with an invalid Prepare marker is fail-closed
corruption rather than an older decision.
A valid Commit-marker region proves the committed body/roots independently.
For the selected current checkpoint, any missing or corrupt named target is
committed corruption. A noncurrent fallback's settled historical public target
may instead have been collected under the typed consumer-unreachability rule
below; fallback validation never makes such a target selectable again.

Recovery validates slot identity, revision continuity, parity/generation,
predecessor checkpoint digest, attempt nonce, transaction ID and the recorded
raw-frame precondition values. The trusted compare-and-replace primitive enforces
those preconditions before overwrite; recovery does not pretend to recompute an
old raw digest from bytes already replaced. A body-only alternate with a canonically absent Prepare region is
discarded and the other committed checkpoint remains current; protocol ordering
proves it has no participant targets. A valid body+Prepare marker with an absent
final decision is likewise noncurrent and may resume or choose Abort. Resume
handles each target independently but deterministically. A fixed target equal
to its exact new envelope is accepted by readback; one equal to its recorded old
raw frame is compare-and-replaced with the exact new envelope; any other, torn
or undecodable value forbids Commit and requires Abort. A public target that is
canonically absent is installed with the exact Prepared region; one already
equal to that region is accepted by readback; any other, torn or digest-
mismatched entry likewise requires Abort. The Committed-arm CAS is legal only
after every participant reads back as its exact new target. A valid Abort
marker remains noncurrent and its exact participant vector drives the bounded,
idempotent cleanup before retry. If either body's Prepare/Abort chain cannot be
validated, recovery fails closed because target cleanup can no longer be
enumerated safely.

Once the higher Committed final decision and Commit marker are valid, that
checkpoint is current. Every fixed
current entry's typed digest, physical slot, generation and logical/storage
revision must equal its complete kind-correct target envelope; its install
revision/transaction ID remain bound by the entry itself. Every public participant target must
contain either the exact immutable Prepared region with an absent activation
suffix or that same region plus its unique valid tag-`0x400D` suffix bound to
this checkpoint/participant. Any other missing, torn, corrupt or digest-
mismatched target fails closed and MUST NOT fall back. Recovery loads fixed-
store current values only from the exact nine-entry tuple. Complete but unlisted
targets, individually higher store revisions, two selectable same-revision
siblings, store-family mixing, skips and rollback are never selectable. Only
two WAL slots are retained and no historical chain traversal is required. The
complete legal recovery table is:

- genesis `{Committed(0), EmptyTarget}` validates the genesis body, markers and
  targets and selects revision zero;
- stable `{Committed(n), Committed(n - 1)}` for `n > 0` validates both complete
  WAL checkpoint bodies/Prepare/Committed decisions, requires `n.predecessor =
  Digest(n - 1)`, selects `n`, and keeps `n - 1` only as the digest predecessor
  and fixed-store fallback. All selected-current targets are exact. Historical
  public targets of `n - 1` are not re-required or reselected after settlement
  and typed consumer-unreachability permits their collection;
- in-flight `{BodyOnly(n + 1) | Prepared(n + 1) | Aborted(n + 1),
  Committed(n)}` validates the candidate's predecessor directly against the
  complete committed `n` checkpoint and keeps `n` current. The committed `n`
  body/Prepare/Commit/targets validate on their own; its recorded predecessor
  digest is not dereferenced because `n - 1` has already been overwritten. A
  BodyOnly candidate has no authorized targets, Prepared follows the exact
  resume table above, and Aborted follows exact cleanup before replacement.

A BodyOnly candidate must be one complete valid `n + 1` checkpoint body with
an absent Prepare region and predecessor equal to committed `n`; a torn or
noncanonical Checkpoint frame is fail-closed and is never reclassified as
BodyOnly or an ignorable fallback. Any other two-slot combination, revision
gap, mismatched candidate predecessor, two Committed
siblings at one revision, two in-flight candidates, or invalid marker/body is
fail-closed. When `n + 1` commits, committed `n` becomes its immediate fallback.

After an activation checkpoint commits, the tag-`0x400D` gate validates the
complete current checkpoint and each exact PublicIndirection participant, then
signs that participant's deterministic activation receipt. The receipt repeats
the participant's immutable indirection activation time; it never samples a
post-commit, suffix-append or recovery time. A public index is
physically one immutable Prepared region plus a separately framed bounded
atomic activation-receipt suffix; logical Active is reconstructed only when the
suffix body/digest and signature are valid. Suffix absence remains Prepared and
is idempotently completable from the current checkpoint. A nonempty invalid
suffix is corruption. Promotion never rewrites or duplicates the large
indirection/certificate/capsule region, and the Prepared region's reserved byte
count equals the maximum complete region-plus-suffix framing.
Each suffix installation atomically compares the still-selected exact activation
checkpoint and participant, the exact Prepared-region raw/body digest and a
canonically absent suffix region before writing the complete suffix body/digest
pair. An already byte-identical valid suffix is an idempotent readback success;
any other suffix, changed/reused Prepared region, rotated checkpoint or stale
participant fails without mutation. A paused signer from an older activation
therefore cannot poison a consumer location later reused by another attempt.

While its activation checkpoint is the recovered current checkpoint, a
destination is resolver-visible from either the exact Prepared region or its
unique Active successor because the one committed participant union proves all
destinations together. Thus incremental suffix completion cannot expose only a
subset: every target already read back before the global marker and each is
selected by that same checkpoint. Before any successor revision `n > 0` may
commit, every public participant introduced by predecessor `n - 1` must instead
be Active with a valid tag-`0x400D` receipt durably appended/read back at the
exact charged stable consumer location. Every public target from any aborted
attempt must also be removed and its absence read back. The successor body then
sets `publications_settled_through_wal_revision = n - 1`; the value is zero at
genesis and revision one, is monotonic, and never covers the body currently
being committed. Before a WAL slot rotates out, its committed destinations are
therefore self-authenticating Active index entries and every aborted target is
absent.

After the activation checkpoint is no longer current, resolution requires an
Active index entry whose tag-`0x400D` receipt signature and every bound field
are exact: committed-checkpoint/body/Commit-marker digests, nonzero activation
revision/ID, location, Prepared-region, indirection and certificate digests and
activation time. The receipt time must equal the Prepared region's
`public_indirection.activated_at` and the marker/Open/event publication time.
That revision must be at most the recovered current
checkpoint's settlement scalar. A bare certificate, Prepared-only entry,
uncommitted attempt, stale index value, raw location, mismatched receipt or
activation tuple is unavailable even if it shares a revision with a later
retry. Stable-index deletion still requires the contract's typed consumer-
unreachability proof, an activation revision at or below the current settlement
scalar, and an activation checkpoint that is no longer current. Settlement is
not permission to collect a live destination. Recovery validates every public
target of the selected current checkpoint, but never re-requires a settled,
noncurrent fallback's already collected historical public target.
Collection is an atomic compare-delete of the exact Active index raw frame/
digest and tag-`0x400D` receipt while rechecking that settlement, noncurrent and
typed-unreachability evidence. If the location now contains any different or
reused entry, the stale collector performs no deletion.

After plan seal, the gate registry resolves each
registration to exactly one non-interchangeable `ExternalExecutorGate` and
permit. Every `CapacityAccounting` context satisfies the first five equations;
every ledger-level `CapacityCommit` context satisfies the first two plus the
commit-authority equations, and every `CapacityReplayRegistry` context
satisfies the first two plus the replay-registry equations:

```text
context.ledger_manifest_digest =
  context.lease.binding.capacity_ledger_manifest_digest
context.ledger_id = manifest.ledger_id
context.exact_limit_set_digest = manifest.exact_limit_set_digest
context.accounting_function_build = manifest.accounting_function_build
context.accounting_function_version = manifest.accounting_function_version

// CapacityCommit only:
context.commit_authority_spec_digest =
  manifest.commit_authority_spec_digest
context.commit_authority_gate.prepared_plan_digest =
  context.lease.binding.plan_digest
context.commit_authority_gate.runtime_or_component_instance_id =
  manifest.commit_authority_spec.component_instance_id
context.commit_authority_gate.gate_channel_binding_digest = SHA-256(
  "FlowProbe.Arch004.CapacityPostCasGateChannel.v1\0" ||
  context.ledger_manifest_digest ||
  manifest.commit_authority_spec.post_cas_gate_registration_digest ||
  context.lease.binding.plan_digest ||
  context.lease.binding.activation_lease_id ||
  context.lease.binding.lease_epoch ||
  Digest(context.lease.binding.fence))

// CapacityReplayRegistry only:
context.replay_registry_authority_spec_digest =
  manifest.replay_registry_authority_spec_digest
context.owner_epoch_key_digest = Digest(owner_epoch_key)
context.replay_registry_authority_gate.prepared_plan_digest =
  context.lease.binding.plan_digest
context.replay_registry_authority_gate.runtime_or_component_instance_id =
  manifest.replay_registry_authority_spec.component_instance_id
context.replay_registry_authority_gate.gate_channel_binding_digest = SHA-256(
  "FlowProbe.Arch004.CapacityReplayRegistryGateChannel.v1\0" ||
  context.ledger_manifest_digest ||
  manifest.replay_registry_authority_spec.
    registry_gate_registration_digest ||
  context.owner_epoch_key_digest || deterministic_cbor(context.mode) ||
  context.lease.binding.plan_digest ||
  context.lease.binding.activation_lease_id ||
  context.lease.binding.lease_epoch ||
  Digest(context.lease.binding.fence))
```

The gate registry additionally requires the displayed component build and
public-key digest and returns the sole permit ID registered for that gate
channel. A missing/duplicate registry row, another valid Capture Core key,
ordinary observation-gate channel, changed build/permit/channel, or a context
whose manifest is not the plan-bound manifest is invalid. The commit-authority
component exposes this gate only to the durable-head executor after successful
CAS plus alternate-slot fsync/readback; its ordinary observation API has no
operation that signs tag `0x400A`.
The replay-registry component likewise exposes tag `0x400B` only on the exact
mode-specific gate channel. Its historical-close surface verifies the frozen
snapshot, barrier prefixes and expired lease itself; a caller-selected mode,
owner epoch, prefix root or current live permit is insufficient.

V1 has exactly one ARCH-004 capacity ledger per installation. It cannot be
partitioned by owner, session, generation, plan, or process, because doing so
would multiply aggregate limits. A new limit-set digest can become current only
when the ledger is empty or through an atomic checked rebase whose complete
usage remains within every new ceiling.

Every snapshot contains exactly sixteen ceiling and usage cells in
`Arch004CapacityKindV1` order, including explicit zeroes. The sealed accounting
function derives them from the exact 23-field limit set and package equations;
`ResourceJournalBytes.maximum_worst_case_bytes` is exactly
`max_aggregate_resource_journal_bytes`, and the active commitment vector length
is at most `max_active_capacity_reservations`. `checked_usage` is recomputed
from every active commitment's resolved requirement using checked addition; an
increment submitted by a producer is never trusted. A missing requirement,
duplicate/missing kind, wrong order, overflow, ceiling excess, or vector/root
mismatch rejects the entire operation.
Active commitments are sorted uniquely by `(reservation_ordinal,
reservation_id)`; both fields, the commitment digest, requirement, subject,
owner and context must agree. Head revision equals its resolved snapshot
revision. `last_transition_digest` is absent exactly at genesis and otherwise
resolves the transition that produced that snapshot.

A fresh ledger persists exactly two typed head-store slots: Slot0 contains
`Genesis` at generation one with the complete canonical revision-zero head and
snapshot, and Slot1 contains `EmptyTarget` at physical generation zero with
`next_slot_generation = 1`. Both bodies bind the same installation/ledger and
their digests are read back before the ledger is usable. EmptyTarget is never a
selectable head. Recovery selects Genesis until the first CAS atomically
targets that exact EmptyTarget with `Committed { revision 1, Slot1,
generation 1 }` and the global Commit marker makes the resulting tuple current;
before that marker Genesis remains current, and afterward Genesis is fallback.
Every later selected head is a
Committed store-slot body and follows the parity/generation formula below. A
bare head, zero-filled file, committed image without a transition, or first CAS
against any other target has no V1 encoding.

The selected full head-store slot is the sole current head/snapshot truth. A
selected Genesis projects its byte-identical `genesis_head` and
`genesis_snapshot`; a selected Committed image projects its byte-identical
`resulting_head` and `resulting_snapshot`. Recovery first selects the one global
committed joint-WAL checkpoint and then loads the Head entry from that
checkpoint's exact nine-entry current tuple. The entry's Head-arm envelope
digest, logical revision, physical slot and generation must equal the complete
selected head-store slot. A higher non-Committed BodyOnly, Prepared or Aborted
candidate is noncurrent and handled only by the global recovery table, so the
preceding committed tuple remains current; once its higher Committed
final decision and Commit marker are
valid, a missing or corrupt Head target fails closed. The other physical head
slot is the immediate COW fallback in stable committed state and never an
independently selectable “highest” head. During an uncommitted attempt it may
instead hold that attempt's complete or torn next-revision target; a fresh retry
may replace it only through the exact raw-frame/optional-envelope precondition
above. Two committed/selectable same-revision siblings, or a replacement that
did not consume an aborted attempt this way, are invalid, as are skip or
rollback.
There is no independent current-snapshot singleton, pointer, wrapper, revision
or write path. Historical snapshot copies inside charged publication proofs do
not participate in admission. Every admission and head CAS reads the snapshot
embedded in this selected slot, so a new head and its snapshot cannot disagree
or become visible separately.

The canonical hashes are:

```text
Digest(Arch004CapacityReservationCommitmentV1) =
  SHA-256("FlowProbe.Arch004.CapacityReservationCommitment.v1\0" ||
    deterministic_cbor(commitment))
Digest(Arch004ResourceJournalPersistenceReceiptV1) =
  SHA-256("FlowProbe.Arch004.ResourceJournalPersistenceReceipt.v1\0" ||
    deterministic_cbor(receipt))
Digest(Arch004GenerationJournalRetentionActiveV1) =
  SHA-256("FlowProbe.Arch004.GenerationJournalRetentionActive.v1\0" ||
    deterministic_cbor(active))
Digest(Arch004JournalPublicationEnvelopeV1) =
  SHA-256("FlowProbe.Arch004.JournalPublicationEnvelope.v1\0" ||
    deterministic_cbor(envelope))
Digest(Arch004CapacityStateBasisBundleV1) =
  SHA-256("FlowProbe.Arch004.CapacityStateBasisBundle.v1\0" ||
    deterministic_cbor(bundle))
Digest(Arch004ResourcePublicationProofBundleV1) =
  SHA-256("FlowProbe.Arch004.ResourcePublicationProofBundle.v1\0" ||
    deterministic_cbor(bundle))
Arch004CapacityStateBasisBundleV1.member_root =
  SHA-256("FlowProbe.Arch004.CapacityStateBasisMembers.v1\0" ||
    deterministic_cbor({ owner_subject, expected_old_head,
      expected_old_head_digest, before_snapshot, before_snapshot_digest,
      after_snapshot, after_snapshot_digest }))
Arch004ResourcePublicationProofBundleV1.proof_root =
  SHA-256("FlowProbe.Arch004.ResourcePublicationProofMembers.v1\0" ||
    deterministic_cbor({ owner_subject, persistence_receipt,
      persistence_receipt_digest, current_journal_active,
      current_journal_active_digest, publication_envelope,
      publication_envelope_digest, publishing_transition,
      publishing_transition_digest, publishing_post_cas_receipt,
      resulting_head, resulting_head_digest,
      resulting_snapshot, resulting_snapshot_digest,
      capacity_state_entries }))
active_reservations_root =
  SHA-256("FlowProbe.Arch004.CapacityActiveReservations.v1\0" ||
    deterministic_cbor(active_reservations))
checked_usage_root =
  SHA-256("FlowProbe.Arch004.CapacityCheckedUsage.v1\0" ||
    deterministic_cbor(checked_usage))
Digest(Arch004CapacityLedgerSnapshotV1) =
  SHA-256("FlowProbe.Arch004.CapacityLedgerSnapshot.v1\0" ||
    deterministic_cbor(snapshot))
Digest(Arch004CapacityLedgerOperationIntentV1) =
  SHA-256("FlowProbe.Arch004.CapacityLedgerOperationIntent.v1\0" ||
    deterministic_cbor(operation_intent))
Digest(Arch004CapacityLedgerTransitionV1) =
  SHA-256("FlowProbe.Arch004.CapacityLedgerTransition.v1\0" ||
    deterministic_cbor(transition))
Digest(Arch004CapacityLedgerHeadV1) =
  SHA-256("FlowProbe.Arch004.CapacityLedgerHead.v1\0" ||
    deterministic_cbor(head))
```

Genesis has revision/next ordinal zero, an empty active vector, sixteen ordered
zero usage cells, no last transition, and:

```text
transition_accumulator_root = SHA-256(
  "FlowProbe.Arch004.CapacityLedgerTransitionSeed.v1\0" ||
  ledger_id || installation_id || limit_set_digest)
```

Each successor uses
`SHA-256("FlowProbe.Arch004.CapacityLedgerTransitionRoot.v1\0" ||
old_root || uint64_be(new_revision) || Digest(transition))`. The snapshot roots
are recomputed from the displayed vectors; no opaque producer accumulator is
accepted.

An operation compares `expected_old_head_digest` with the sole durable head;
`before_snapshot_digest` must be that selected head image's embedded snapshot,
and after revision is
exactly before revision plus one. `Admit` inserts exactly one commitment;
`Release` removes exactly its current commitment; `Transfer` atomically removes
one source and inserts the complete `targets` vector. `target_count` equals its
bounded vector length and is in `1..=max_active_capacity_reservations`. Entries
are ordered by strictly increasing `target_ordinal`; each ordinal equals its
embedded commitment's reservation ordinal, the ordinals are the consecutive
range beginning at the before snapshot's `next_reservation_ordinal`, and each
entry's state digest is the exact Reserved publication of that same embedded
commitment. Duplicate commitment/state digest, ordinal gap, reordered pair,
cross-paired digest or independently sorted projection is invalid.
`PublishJournalAppend`
changes no commitment or usage cell but still publishes a successor snapshot
whose revision is incremented and whose next ordinal, ceilings, active vector,
active root, usage vector and usage root equal the predecessor byte-for-byte.
`ReleaseCurrentResourceAndPublishJournalAppend` removes exactly one current
non-journal ResourceNode commitment while publishing the same append. Release,
publish, and release-plus-publish keep `next_reservation_ordinal`;
admit/transfer assign consecutive ordinals to every target and advance it by
`target_count`. A reservation ID is domain-separated from ledger ID, ordinal,
and operation ID and is never reused.

Every transition carries one operation-wide replay request; no operation
variant has a private retry namespace. The manifest value is installation- and
ledger-stable rather than plan-fresh:

```text
operation_replay_sequence_domain_id = SHA-256(
  "FlowProbe.Arch004.CapacityReplayDomain.v1\0" ||
  installation_id || ledger_id)
```

Every accepted manifest for the same installation/ledger repeats that exact
value across plan, lease, limit and build changes. Changing it requires a new
ledger ID; resetting or rebasing a live ledger's replay domain has no V1
encoding. The request owner is the added commitment owner for `Admit`, the
removed source owner for `Release`, `Transfer`, and release-plus-append, and the
current generation-journal commitment owner for `PublishJournalAppend`.
`accepting_lease` is the current authenticated request lease and is byte-equal
to the durable commit context lease. Its deadline satisfies
`cas_linearized_at <= replay_deadline <= accepting_lease.expires_at`.
The request embeds the complete registry snapshot and exact digest and commits
to one `Arch004CapacityLedgerOperationIntentV1` digest. Its explicit ledger ID
equals the manifest, registry snapshot and operation intent. The transition embeds
that intent body/digest, and its repeated operation ID, ledger, old head,
before/after snapshots and operation are byte-identical to the intent. The
request digest and its `RequestAccepted` event are durable and read back before
head CAS. Therefore a failed/pre-CAS attempt cannot reuse the same sequence and
owner epoch for another operation payload; changing any intent byte requires a
different request, which conflicts with the already accepted epoch.

The ledger/domain has exactly one fixed pending-admission store. Genesis is
`Idle { last_admission_revision: 0 }`; that scalar is installation/ledger-
stable, checked-monotonic across plan replacement and never reset while the
ledger ID exists. Preflight first requires no Open/incomplete commit, an `Idle`
admission, the current head and watermark, and the next replay sequence. It computes checked
`admission_revision = last_admission_revision + 1`, the intent, derived owner-
epoch key/snapshot and request, then atomically compare-and-installs the complete
`Accepted` body, the owner-epoch Open head, and event-store revision one in one
joint all-old/all-new transaction. Event-store genesis is computed but never
left as an accepted durable intermediate; revision one contains exactly the
request channel's `RequestAccepted` record at global installed revision one.
That record's `observed_at = Accepted.accepted_at`, and Accepted's event-store/
record digests equal the installed bodies. Its head/watermark, intent/request,
owner-epoch Open head and event-store ID all match byte-for-byte. Only after
joint fsync/readback may `LiveRegistry` sign the record; if that wrapper is lost,
`HistoricalFinalizeInstalledRecord` can sign the exact installed revision after
lease expiry. A concurrent losing snapshot/request remains volatile and has no
accepted epoch. The exact Accepted request and RequestAccepted record are
recovered together after a crash and are the only bodies permitted to enter
head CAS.

When a committed head ultimately reaches its durable Open replay, the Open
activation transaction also changes admission back to `Idle` while preserving
the last admission revision and atomically appends the exact
`OperationReplayOpened` record. If an accepted request reaches typed owner
expiry before head CAS, `HistoricalCloseOnly` first performs a special joint
compare-and-install whose compare-set is exactly the head-CAS input tuple:
the exact selected head accepted as `H0`, current watermark, Pending Accepted,
owner Open and
event-store revision one containing only `RequestAccepted`. Its only write is
event-store revision two containing the exact
`RequestTransportRetired { PreCasAccepted }` latch; its basis repeats the
Accepted body digest and accepted head/watermark digests. Only after this latch
fsync/readback may it retire deterministic suffix tokens, install closure heads,
close every channel with `HistoricalExpired`, seal the exact event store, and
install the exact owner-epoch `Closing { terminal candidate }` through the
common terminal-candidate transaction. No unproved caller cancellation may
clear Accepted. After that candidate reads back and the unique terminal is
signed, one later atomic store transaction consumes the exact Pending Accepted,
owner Closing, Sealed event-store, both branch-bound closure heads, unchanged
capacity head/watermark and Vacant artifact-store envelopes. It installs
`Idle { last_admission_revision: accepted.admission_revision }` and the exact
`Closed { signed terminal }` owner state together; that Idle scalar is the
pre-CAS retirement tombstone. After fsync/readback it collects the epoch's bounded event store,
without changing capacity head or
operation watermark. A subsequent attempt keeps the same
next operation sequence but uses the next admission revision and therefore a
different derived epoch ID. No head CAS accepts event-store revision two or any
other PreOpen prefix, so a winning expiry latch permanently defeats every stale
or reloaded head writer. This single slot prevents an unbounded set of pre-CAS
accepted losers.

Pending admission, owner state, event store and the two closure-head stores each
use one independent pair of
`Arch004CapacityReplayRecoveryStoreSlotV1` envelopes. At ledger genesis, each
pair has an Occupied Slot0 at storage revision zero/generation one and a typed
Slot1 EmptyTarget at physical generation zero. Pending's genesis payload is
`Idle(last_admission_revision = 0)`; the other four genesis payloads are
`Vacant`. Pending never uses Vacant. The other store kinds use only their
same-named payload or Vacant; a kind/payload mismatch is invalid.

Every logical store transition checked-increments `storage_revision`, writes
`slot = Slot(storage_revision mod 2)` and
`slot_generation = floor(storage_revision / 2) + 1`, then fsyncs/readbacks the
complete envelope. Recovery first selects the one global committed joint-WAL
checkpoint and then loads each replay kind solely from its matching exact
current-tuple entry. The typed envelope digest, storage revision, physical slot
and generation must all equal that entry. A higher non-Committed BodyOnly,
Prepared or Aborted candidate is noncurrent under the global table and all of
its targets are ignored together; after its Commit marker is valid, corruption of
any named target fails closed. Every participant of one union transaction is
therefore all-old or all-new, and independently mixing individually complete
store revisions is forbidden. For the first transition, Slot1 EmptyTarget is
replaced by revision one. In stable committed history a later alternate contains
revision `n - 2`; after an aborted Prepared attempt it may instead contain a
complete uncommitted next-revision envelope or no valid envelope, and the fresh-
nonce retry consumes that exact raw state as specified above. Duplicate
generation is invalid only within the same physical slot, because Slot0/revision
zero and Slot1/revision one legitimately both have generation one. Two
committed/selectable same-revision siblings, skips, rollback, kind/domain splice
or a Vacant owner/event store while Pending is Accepted are invalid. Multi-store
operations name the exact old-current digest, raw target-frame precondition,
optional valid old-target digest and new-target digest in the one bounded joint
WAL. This storage revision, rather than admission revision or event-store
logical revision, distinguishes `Accepted(r)` from the later `Idle(last=r)` and
each Open/Closing/Closed/Vacant transition.

Each operation uses a fresh, single-operation owner epoch. Before request
acceptance, the tag-`0x400B` replay-registry authority signs exactly one
`Arch004CapacityOperationOwnerEpochRegistrySnapshotV1` under `LiveRegistry`.
The owner-epoch key equals request owner, sequence domain/sequence and the
accepting lease's installation/session/generation; its epoch ID equals the
canonical formula above. The request repeats all those values. Thus the global
watermark permanently tombstones a collected epoch, and a caller cannot reuse
the same epoch ID at a later sequence. Registrations are the complete bounded
channel universe, sorted by canonical bytes with `registry_ordinal` equal to
the zero-based index; each repeats the exact lease, digest, mutually
authenticated channel binding, transport-handle identity and channel-key
identity. The snapshot's transport/key-store identities equal the plan-sealed
replay-registry authority spec. Registration count and root are recomputed from
the full vector. The request's registry digest resolves
that complete snapshot and its channel binding occurs exactly once. At
`frozen_at` registration closes permanently for that epoch; no late, dormant,
duplicate, omitted or replacement channel is accepted.

The snapshot also fixes one event-store ID and maximum accounted bytes. The
store has exactly one stream per registration in registry order, and
`stream_count = registration_count`. Genesis is `Open`, revision zero, with
every stream empty. Each append is a serialized copy-on-write compare-and-
install of one next unsigned event record followed by fsync/readback. The
record's `predecessor_event_store_digest` is the exact selected Open body,
`installed_revision = predecessor.revision + 1`, and deterministic
`ApplyOne(predecessor, record)` inserts it into exactly its registered stream
and produces the next Open body/digest. Across all streams the installed
revisions are a unique contiguous `1..=N`; per-stream `event_ordinal` is a
unique contiguous `0..event_count-1`, `event_count = event_records.len`, and
`N` is the checked sum of all stream counts. Sealing is the sole next store
transition and sets `revision = N + 1` without adding a record.

Two request-channel records use stricter cross-store installation than an
ordinary append. Pre-CAS `RequestTransportRetired { PreCasAccepted }` is
installed only by the H0/E1 joint race transaction described below.
`OperationReplayOpened` is installed only by the post-head Open activation
union transaction that also publishes the exact Open sidecar and clears
Accepted. Neither `LiveRegistry` nor a historical replay mode can append either
record through its ordinary event API. They may sign the exact installed record
after readback under the otherwise applicable live or
`HistoricalFinalizeInstalledRecord` mode; this remains possible when committed-
head recovery activates Open after the accepting lease expires. No commit-
recovery surface can append any other event or change the E1 request prefix.

After an append, tag `0x400B` may sign the matching observation. Its resulting
revision is the record's installed revision and its resulting digest is the
exact Open body produced by `ApplyOne`; it need not remain the latest body after
later valid appends. Every historical Open result is reconstructed uniquely by
replaying the final durable record set in installed-revision order. Thus a
crash after record fsync but before signature does not strand the epoch:
`LiveRegistry` may finish it while live, and after lease expiry
`HistoricalFinalizeInstalledRecord` may sign only that exact installed record
and reconstructed predecessor/result. A losing sibling, gap, duplicate global
revision, altered record/time, non-prefix result or torn store cannot obtain a
valid observation. `RequestAccepted` is durable in this store before capacity
head CAS. `event_store_store_slot_max_accounted_bytes` is the checked encoding
of the largest complete Occupied containing-slot envelope carrying 64 streams
by 32 unsigned records plus in-body indexes, including its outer tag, ledger/
epoch identity, physical slot/generation, storage revision, payload digest,
framing and checksum. Its two physical slot copies and digest-only WAL are
not one combined charge: the two event-store slots are counted by the replay-
epoch recovery budget, while the one global two-slot digest-only WAL is counted
once by the ledger recovery budget. Signed observation wrappers are instead
included in the bounded owner-state/census maximum. A
different store ID, undercharge, partial append or volatile-only event is
invalid.

Each registration owns one signed ordinal stream. Stream ID and every event
digest use the canonical formulas above; ordinals start at zero, advance by one
and cannot fork. The bounded streams together contain only this operation's
request, Open, retry-token, branch and close events and are replayed in global
`installed_revision` order. Revision one is exactly `RequestAccepted` at
request-channel ordinal zero; other registered channels contain no request
event. The one later branch-latch record on that request channel is either
`ResponseAcknowledged` with the exact Open digest and nonce or
`RequestTransportRetired` with its exact pre-CAS or Open-retirement basis, never
both. If the request commits, the preceding request-channel record is exactly
one `OperationReplayOpened` carrying that same Open digest; if pre-CAS expiry
wins, no Open record has an encoding. Every issued retry token is followed
exactly once by its retirement, and
the final per-channel event is `ChannelClosed` for that same channel key. On
acknowledged closure the request channel uses `AcknowledgedRequest` with the
exact request key and nonce and every other channel uses
`AcknowledgedUnusedSibling`; its closure basis repeats the exact Open digest.
On expiry every channel uses `HistoricalExpired`
with the full signed readback: registration, channel key, lease expiry and
expected transport/key identities match. The request-channel branch record is
durable before either closure head. Both heads embed the same byte-identical
`Arch004CapacityOperationOwnerEpochClosureBranchLatchV1`, whose record is that
one exact branch event from the durable event-store prefix and whose lease,
deadline, request and digest equal the accepted replay request. Before any close
event, the singleton authority atomically installs the transport-registry and
key-store closure heads under the common barrier after closing the exact
registered handles and zeroizing the exact registered keys. Each head
names the plan-sealed store identity, epoch, monotonic revision, barrier,
complete empty vector/count/root and a prohibited successor, is fsynced/read
back, and cannot reopen. Historical readback embeds those byte-identical heads
at or after lease expiry. A naked boolean, arbitrary head/revision, unrelated
store identity or omitted handle/key universe is not a closure basis. An epoch permits
at most eight issued retry tokens and 32 total events per channel; reaching the
bound closes the channel rather than creating an unbounded census.
`ResponseAcknowledged.observed_at` is within the accepting lease and not after
the replay deadline. `RequestTransportRetired.observed_at` is not earlier than
both replay deadline and lease expiry. Once either record is installed, that
branch is chosen durably: no live or historical mode may append the sibling
branch. If the live acknowledged suffix is interrupted,
`HistoricalFinalizeInstalledRecord` supplies exact observations for any
installed-but-unsigned prefix records. `HistoricalCompleteAcknowledgedClosure`
then starts from that exact reconstructed record result and appends/signs only
the missing deterministic token retirements and the two acknowledged closure-
basis variants above. It can resume at every installed-revision boundary, and
cannot issue a token, change the acknowledgement or switch to expiry.
For every leaf, `channel_key = { registration.registry_ordinal,
registration.channel_binding_digest }`, `barrier_next_ordinal =
sealed_event_prefix_count = sealed_event_prefix.len`, and event `i` has ordinal
`i` and the leaf's snapshot/registration/derived stream. Across the union of
all records, `observed_at` is nondecreasing in `installed_revision`; per-stream
time order follows from that global rule.
`closed_event` is byte-identical to the prefix's last member and its digest is
exact. All leaves use one barrier. Registration time is not after snapshot
freeze; live request/token events occur from `frozen_at` through lease expiry;
historical readback and its deterministic suffix occur at or after lease expiry.
The ordering is branch-first and global. On acknowledgement,
`ResponseAcknowledged.observed_at` is not after either closure-head
`observed_at`, and neither head is after any acknowledged `ChannelClosed`
record. On expiry,
`max(replay_deadline, accepting_lease.expires_at)` is not after
`RequestTransportRetired.observed_at`, which is not after either closure-head
time; neither head is after the historical readback, and that readback is not
after its leaf's expired `ChannelClosed` record. The two heads must carry the
same latch variant/body/digest. A head created before its branch record, an Ack
head predating Ack, an expiry head predating either deadline, a readback-first
expiry, or heads from different branches invalidates the census.
The last event is not after `barrier_acknowledged_at`, which is not after census
finalization/terminal close. A count, ordinal, stream, duplicate close, detached
close copy or time reversal invalidates the census.

The census also performs one global single-operation state-machine fold over
installed revisions. It starts `AwaitRequest`; revision one alone consumes the
exact `RequestAccepted` and enters `PreOpen`. PreOpen permits no acknowledgement,
retry-token or channel-close event. Its only legal next record is either the
request channel's exact `OperationReplayOpened`, which enters `OpenActive`, or
its exact `RequestTransportRetired { retirement_basis: PreCasAccepted }`, which
enters `ExpiredClosing`. `OperationReplayOpened.open_replay_digest` is the exact
atomically installed Open body, and its record time equals `open.opened_at`.
In OpenActive, a retry-token issue requires absence and a retirement requires
presence; at most eight issues occur globally. The exact request-channel
acknowledgement carrying that same Open digest enters `AckClosing`, while exact
`RequestTransportRetired { retirement_basis: OpenReplay }` carrying that digest
enters `ExpiredClosing`. Entering either closing
phase snapshots the then-outstanding token set. No later issue, request or
Open/branch event is legal; only retirement of a token in that snapshot and one
branch-correct `ChannelClosed` per still-open registered channel may follow. A
channel may close only after its own token set is empty. When all registered
channels are closed and the global token set is empty, the fold enters absorbing
`Closed`; no later record is legal. Token bodies/digests resolve to the exact
epoch/snapshot/registration/request and fresh nonce. Thus an Ack before Open, a
second Open, a close before its future acknowledgement, an issue before Open or
after branch selection, a second request, or an issue/retire-balanced foreign
token is rejected even when final counts and roots happen to be zero.
The closure census embeds every signed prefix body, not merely counts or roots.
Leaves are in registry order and are a one-to-one projection of registrations;
their common barrier is the event store's sole `Open -> Sealed` transition.
That transition and owner-head `Open -> Closing { exact terminal candidate }`
are one atomic copy-on-write transaction: a crash leaves both Open, or the exact
Sealed store plus Closing candidate. That transaction samples one
`closure_linearized_at`; the Sealed state's `sealed_at`, census `finalized_at`
and terminal-candidate `closed_at` are all byte-identical to it. Ack repeats it
as `acknowledgement.closed_at`, while expiry repeats it as
`expiry.observed_at`. Every record time, transport/key closure-head
`observed_at` and leaf `barrier_acknowledged_at` is not later than that instant.
It seals the exact next ordinal and
prevents backdated append. Replaying each prefix derives the displayed empty
request/token vectors.
The census embeds that exact Sealed event-store body/digest. Store ID,
owner-epoch key, snapshot digest, stream count/root and barrier equal the
snapshot/census. It also embeds the exact transport/key-store closure heads and
digests; their identities equal snapshot/manifest, their owner epoch and common
barrier equal the census, and historical readbacks repeat them. Each leaf's signed observations project byte-for-byte to the
matching sealed-store stream's complete record vector; counts and both signed-
observation/record-prefix roots recompute, and each observation's resulting
store revision/digest pair is the unique `ApplyOne` result at its record's
installed revision. The union of all observations is a one-to-one cover of
global installed revisions `1..=N`; the Sealed store has revision `N + 1`.
The terminal-candidate transaction compares the exact reconstructed revision-N
Open digest and installs this exact revision-(N+1) Sealed digest.
An otherwise signed losing close, an Open or longer store, or a census assembled
from a sibling prefix is invalid.
Their counts are zero and their roots equal the two independently
domain-separated empty-vector roots. Registered and closed channel counts are
equal, and their key-set roots use the same registered-key domain and are
byte-identical. A literal zero, arbitrary equal roots, a naked snapshot digest
or an unsigned channel-close assertion proves nothing.

A successful head compare-and-install is one global joint-WAL transaction
executed while the plan lease/fence and exact post-CAS permit are live. It
compares the recovered committed checkpoint digest, its exact nine-entry tuple,
the selected full Head entry/wrapper/digest, the alternate physical Head target,
the current watermark, Pending/owner/event entries and their exact
Accepted/Open/event-store-revision-one bodies, plus current sidecar/marker
Vacant entries. Revision one contains only the signed `RequestAccepted` record;
a token, Open, Ack, retirement or later event makes the transaction ineligible.

The coordinator samples the declared `cas_linearized_at` once before encoding
the immutable target and Prepared checkpoint. That time has no semantic effect
unless the global commit marker becomes durable. The transaction's only changed
fixed-store participant is Head; all other current-tuple entries are copied
byte-for-byte. It writes/readbacks the Prepared WAL body and prepare marker,
writes/readbacks the complete alternate
`Arch004CapacityDurableHeadStoreSlotV1::Committed` target containing one
`Arch004CapacityDurableHeadSlotImageV1`, then appends/readbacks the single global
commit marker. Only that marker makes the new tuple-selected Head the sole
current head/snapshot and makes the sampled time the logical CAS instant. A
complete Head target without the marker is uncommitted garbage and never wins
the CAS. The slot image contains the full commit context/record, bounded
candidate publication set, transition, resulting head and snapshot, so the
lease window, authority spec, permit, gate channel, declared CAS time,
state/basis bodies, release-cause preimages and semantic/journal publication
preimages are durable before receipt creation. No separate current-snapshot
write, pointer or recovery decision exists.

The first pre-CAS-expiry latch is a competing global joint-WAL transaction. It
compares the same committed checkpoint/tuple, including exact H0, watermark,
Vacant artifact entries, Pending Accepted, owner Open and event-store revision
one, and changes only the event-store entry to revision-two
`RequestTransportRetired { PreCasAccepted }`. The coordinator admits only one
Prepared successor for that checkpoint, and the winner is the transaction whose
single commit marker becomes durable. If expiry commits first, a head attempt no
longer sees E1; if Head commits first, expiry no longer sees the accepted H0
tuple. Target writes or a prepare marker without the commit marker win neither
branch and are resolved before the other contender may retry. The winning head
keeps Accepted and E1 recoverable only as its typed incomplete-commit state
until canonical Open activation clears admission. A stale or reloaded writer
cannot resume after committed pre-CAS retirement, and a tuple-selected H1 cannot
coexist with the selected pre-CAS branch latch.
The gate signs exactly one canonical `Arch004CapacityPostCasCommitReceiptV1`
body only after recovery reselects and readbacks that exact committed checkpoint
and Head target. For every operation except generic `Release`, a second global
joint-WAL transaction installs the next
`Arch004CapacityPostCasSidecarStoreSlotV1::Occupied` Present `Receipt` envelope
as its only changed fixed-store entry. Its global commit marker, not the sidecar
target write, makes that invisible recovery intermediate current before private
staging. The Receipt is never the caller result.

For generic `Release`, the first committed sidecar Present body is instead
`OpenOperationReplay { GenericRelease }`; that activation checkpoint also
installs Pending Idle and the exact `OperationReplayOpened` event while carrying
the marker-store entry forward Vacant. A receipt-only generic-release sidecar
has no encoding. For every other operation, private staged copies, signed
certificates, Prepared public-index entries, a marker-store Present body and an
`OpenOperationReplay { PublishedBatch }` sidecar are installed by the one
all-old/all-new global activation checkpoint described below. A losing or stale
Head attempt emits no receipt and cannot expose a candidate state, transition,
head or result. If a crash occurs after the Head checkpoint commits but before
Open activation commits, recovery recognizes that exact incomplete durable
commit, keeps every candidate and staged copy non-resolver-visible, and blocks
the next ledger operation while the same commit gate and publication procedure
finishes the one canonical Open replay. No caller can receive a result before
the complete activation checkpoint is durable and read back.
Both Open installation paths also compare-and-install the exact pending
admission from `Accepted` to `Idle` and append event-store revision two as the
exact `OperationReplayOpened` record. Its Open digest is byte-identical and its
record time equals `open.opened_at`. Open and Accepted cannot coexist after a
completed publication, and an incomplete commit keeps Accepted plus revision
one recoverable.
`receipt.committed_at` equals the already persisted
`durable_commit_record.cas_linearized_at`; it is never chosen during recovery.
If recovery occurs after the original lease/permit expiry, the commit authority
retains a narrowly scoped historical-completion gate for the tag-`0x400A`
receipt and, after complete staged readback, the deterministic tag-`0x400C`
destination certificates. The same narrow surface may issue missing tag-
`0x400D` activation receipts only for exact PublicIndirection participants of
the recovered current committed checkpoint. Tag-`0x400A`/`0x400C` historical
completion requires the exact valid Head image current, sidecar/marker Vacant or
the exact Receipt/incomplete intermediates for that body, no Open/Closed replay
or public indirection for another body, its recorded CAS instant within the
recorded lease/fence, and no next operation. Tag-`0x400D` instead requires the
exact current activation checkpoint, its PublishedBatch Open and marker bodies,
the matching complete PublicIndirection participant and immutable Prepared
index region, no higher Committed final decision, and either an absent suffix or
the same already-valid receipt. A body-only, Prepared or Aborted `n + 1`
candidate does not change current `n` and does not block this completion; its
Committed arm remains forbidden until every `n` suffix is durable. Those two
prerequisite sets are not interchangeable.
That exception completes this already committed body and cannot authorize,
alter or replay any new head or WAL transaction. The matching authority key
remains recoverable until Open readback and every current checkpoint public
participant has a valid tag-`0x400D` suffix fsynced/read back. After receipt
creation its time/body/signature are immutable; after the staged-copy root and
activation attempt are fixed, each certificate body/signature is likewise
immutable. Each activation receipt is immutable and can bind only the exact
current committed checkpoint/body/Commit-marker and participant; a rotated,
Prepared-only, aborted or sibling attempt is outside the historical gate.
The durable record's ledger/old-head/transition/resulting-head/snapshot digests
equal the committed bodies, `durable_commit_index = resulting_head.revision`,
`head_slot = Slot(resulting_head.revision mod 2)`, and
`head_slot_generation = floor(resulting_head.revision / 2) + 1`. The resulting
generation is unique within its physical slot; Slot0/revision zero and
Slot1/revision one both legitimately use generation one. The resulting
head names the transition and snapshot, and the transition names the old head
and before/after snapshots exactly. The slot image's slot/generation and all
five body/digest pairs, including the candidate publication set, equal the
record fields. `commit_observation_context` and its digest are byte-identical to
the context later named by the receipt; its lease-binding digest, authority-
spec digest, permit and gate-channel digest equal that `CapacityCommit` context
and authenticator gate byte-for-byte. `cas_linearized_at` lies within the
persisted context lease's `observed_at..expires_at` window. Recovery may only
reuse this context body and cannot choose a wider or newer window.

The candidate set's operation ID and transition digest equal the slot
transition. Its state count and projection root equal the durable record's
candidate count/root, and its state count also equals the receipt's
published-state count. The candidate projection vector is the exact full-body
counterpart of `receipt.published_states`: each projection, state digest,
commitment digest, subject and role match byte-for-byte. The candidate
`state_projection_root` and receipt `published_state_set_root` are then
recomputed independently under their distinct displayed domains; they are not
required to equal. The candidate
entry additionally retains the raw state and basis bodies.
`predecessor_state_proofs` is also closed: `Admit` has none; generic `Release`
and `Transfer` contain the source `Reserved` proof; journal append contains the
unchanged journal/current-resource proofs required by its publication bundle;
and release-plus-append contains the released resource predecessor plus the
unchanged journal proof. Every proof is complete, previously post-CAS refined,
sorted by state digest and bound by `predecessor_state_proof_root`; a naked
digest or proof made unreachable by the same operation is invalid. A generic `Release`
requires exactly one matching typed terminal/cause preimage; other operations
omit it. A retention transfer requires exactly its retained Active preimage; a
resource transfer or journal append requires exactly its persistence receipt,
optional predecessor Active, successor Active and envelope; operations with no
semantic publication use `None`. Missing, extra, wrong-variant or digest-
mismatched preimages invalidate the slot image. The bounded candidate set is
fixed recovery material, not a committed-state proof by itself. It remains an
integral part of that immutable slot image until the image is no longer the
current head or required fallback and is overwritten by the normal two-slot
rotation; no independent early deletion has an encoding.

For every non-generic operation, the commit gate also derives one flat
`Arch004CapacityBatchValidationCapsuleV1` from that exact slot image and signed
receipt. Its receipt/body digest, operation ID, transition digest, candidate-set
digest, candidate-state count/projection root and publication preimage equal
those committed bodies. Its generic-release cause field is exactly `None`.

The capsule stores the common basis bodies once. Its
`common_expected_old_head` is the exact predecessor current head selected when
the CAS began, its `common_before_snapshot` is that head's sole snapshot, and
its `common_after_snapshot` is the committed slot's resulting snapshot. Their
digests equal the transition's expected-old/before/after digests. For a nonempty
candidate vector, those six common body/digest fields are byte-identical across
every original candidate basis bundle. For the zero-state
`PublishJournalAppend` case, the exact predecessor head slot and committed
resulting slot still supply the same three common bodies.

At index `i`, `candidate_states[i]` is the lossless flat projection of the
committed `candidate_set.states[i]`: projection, state and state digest are
byte-identical, while `basis_owner_subject`, `basis_member_root`,
`basis_accounted_bytes` and `basis_bundle_digest` equal the corresponding fields
of its original basis. The validator reconstructs exactly one
`Arch004CapacityStateBasisBundleV1` from those four per-state fields plus the
capsule's common expected-old-head and before/after snapshot bodies/digests,
recomputes its member root and basis digest, and requires byte equality with the
original candidate basis. It also recomputes every state digest, candidate count
and ordered projection root. Thus no snapshot or old-head body is repeated per
state, while no original basis field is lost.

All three common body digests are recomputed;
`common_before_snapshot_digest = common_expected_old_head.snapshot_digest`.
The receipt durable record, transition and capsule agree on expected-old-head,
before/after snapshot, resulting snapshot, candidate-set, state-count and
projection-root digests. For each flat member,
`Digest(state) = state_digest = projection.state_digest`, the state's
commitment digest/subject equal the projection, `basis_owner_subject` equals the
state commitment subject, and `state.state_basis_bundle_digest` equals the flat
`basis_bundle_digest`. The reconstructed member root, full basis digest and
semantic `accounted_bytes` equal the flat fields. That per-basis accounted value
is preserved for semantic validation but is not interpreted as `C` physical
snapshot copies and is not summed again into capsule storage. Before tag-
`0x400C` signing, expanding every flat member by this unique reconstruction must
produce a vector byte-identical to the selected current candidate set's
`states`.

The flat vector deliberately omits predecessor proof bodies.
`predecessor_state_attestations` is instead the sorted one-to-one projection of
the candidate set's predecessor proofs: each entry repeats only the predecessor
state/proof digest and the origin indirection/certificate digests that the gate
validated before signing. Count/root are recomputed exactly. Zero to four
attestations are legal; five, a duplicate, wrong order, missing proof projection
or unequal root is invalid.

`candidate_predecessor_state_proof_root` is byte-identical to the selected
candidate set's root and is verified against the full proof vector while that
current slot remains available to the tag-`0x400C` gate. It cannot and MUST NOT
be recomputed from digest-only attestations by a long-term resolver. After the
gate signs, its capsule signature is the trust boundary for that root; validation
never loads a retired candidate set, predecessor proof, sibling batch or prior
certificate to recreate it.

The capsule is a signed, fixed-depth current-operation validation base, not a
resolver or a publication by itself. It contains no staged copy, destination
batch, marker, Open result, full public indirection/certificate, or recursively
resolvable predecessor body. A prior certificate digest in an attestation is
never dereferenced by the long-term capsule validator; tag `0x400C` attests that
the full predecessor proof and its then-live public indirection passed the
ordinary resolver during activation. Thus each new certificate may duplicate
the bounded capsule without nesting an earlier batch or growing with operation
history. The capsule maximum and every duplicate are included in the
destination, marker and sidecar charges.

`published_state_count = published_states.len` and
`published_state_set_root` is the canonical formula above. The vector is the
complete operation projection: `Admit` has its one `AdmitReserved`; `Release`
has its one `ReleaseReleased`; `Transfer` has `TransferSourceReleased` followed
by one `TransferTargetReserved { target_ordinal }` for every operation target
pair in target-vector order; `PublishJournalAppend` has none; and release-plus-append
has its one `ReleaseCurrentResourceReleased`. Every entry's state digest is the
exact operation field, while commitment digest and subject resolve from that
state and the corresponding added/removed commitment. A missing, extra,
duplicate, reordered, wrong-role or partial target entry invalidates every
receipt for the operation. Its checked upper bound is
`max_active_capacity_reservations + 1`: the extra member is the released source
of a transfer whose target vector may itself reach the active-reservation
maximum. Overflow of that derived plus-one bound invalidates the limit set.

The signed receipt has no consumer-specific use. Every
`Arch004CapacityPostCasCommitReceiptRefV1` repeats that one byte-identical body
and digest and adds only a verifier projection. `StateResolution` uses a
zero-based `published_state_ordinal` selecting exactly one in-range entry; its
selected state's commitment resolves its own `CapacityAccounting` context whose
subject/owner/requirement equal that state, while the receipt's
`CapacityCommit` context has the byte-identical ledger manifest and ledger ID.
A `TransferTargetReserved.target_ordinal` equals its target pair's embedded
commitment reservation ordinal rather than its vector index, and its state
digest is the Reserved digest from that same pair. A
`ResourcePublication` ref is legal only for an operation carrying
the byte-identical journal publication; the publication bundle and its journal
state, rather than the ledger-level receipt context, supply and validate the
generation-journal owner. The receipt time equals the durable record's CAS
linearization instant and lies within the original commit lease; signature
generation occurs only after successful slot readback, or through the narrowly
scoped historical-completion rule above. Its historical signature remains
verifiable after that lease expires, but never authorizes a new operation.
While the operation's `OpenOperationReplay` is current, exact response-loss
replay returns the byte-identical complete result, including this receipt and
every ref. A ref with changed core, state set, selected ordinal, owner, role,
time or signature is invalid. After replay closure, the receipt remains usable
only through its charged consumer proof; the transport operation itself is
retired and does not promise an historical bundle.

`ResolveCommittedCapacityState(publication_indirection_digest,
expected_state_digest)` is the non-serialized refinement shown above. The
consumer supplies the exact indirection digest from its sealed storage
location/ref; `expected_state_digest` is only a result-binding assertion and is
never a locator or index key. Resolution begins by loading the complete
`Arch004CapacityPublishedDestinationIndexEntryV1` at that sealed location and
validating one of the two activation branches above: exact PublicIndirection
membership in the recovered current committed checkpoint, or an exact Active
suffix/receipt covered by the current checkpoint's settlement scalar. Its
immutable Prepared region must contain the expected indirection digest. Direct
lookup by raw state, proof digest, private staging ID or an arbitrary public
location is forbidden. The indirection then loads its exact
`Arch004CapacityStagedDestinationCopyV1`, whose StateResolution destination
contains the charged `Arch004CapacityStateProofEntryV1`, state/basis bundle,
selecting receipt ref, creation transition, resulting head and snapshot. The
resolver checks indirection/staging IDs and digests, destination ordinal and
projection, the tag-`0x400C` certificate signature, complete batch roots and
exact `validation_capsule` body/digest/root. It then checks the capsule's
tag-`0x400A` receipt, common basis bodies, reconstructed basis bundles, flat
candidate-state vector, predecessor attestations and typed publication preimage
before checking the selected proof's canonical digest/root, accounted bytes,
every body/digest equality and operation-specific creation role. Only after
publication activation, tag-`0x400A`/`0x400C` signatures and the applicable
current-checkpoint or tag-`0x400D` branch verify may it return the refined state.
A Reserved proof has no predecessor and its role is `AdmitReserved` or the
exact target ordinal. A Released proof embeds one complete
`Arch004CapacityReservedStateProofV1` whose state digest equals
`predecessor_reserved_digest`; that predecessor has no nested predecessor and
its `origin_public_indirection` authenticates the earlier Reserved publication.
A naked receipt/state/basis tuple, raw staged destination or certificate without
its public index/indirection is not a publication proof. Each long-lived
consumer's existing charge retains its exact Active index entry and tag-`0x400D`
receipt, public indirection, raw staged payload, certificate and complete flat
validation capsule after the marker, sibling destinations and head slots rotate
out. The certificate-backed base
case is deliberately non-recursive: it raw-decodes the capsule's complete
current candidate-state projection and typed current publication preimage,
without invoking `ResolveCommittedCapacityState` on those members or loading a
sibling destination. It first validates target `Reserved` states, then the
retained-metadata Active or journal publication preimage, and only then the
source `Released` state whose cause names that semantic output. Each selected
raw member must equal its capsule candidate; each predecessor proof digest must
equal the matching flat attestation. Prior indirection/certificate digests in
those attestations are not dereferenced. Only after the complete flat DAG and
selected destination succeed does the selected raw member become refined.

This certificate-backed base case is unavailable to ordinary callers. The only
other raw-validation base is the selected-current generic-release capsule rule
below; it produces no long-lived state refinement. Except while building the
winning CAS's invisible candidate set or executing exactly one of those two
closed validators, every use of a `Reserved` or `Released` digest anywhere in
this contract MUST use the resolver. A locally self-
consistent state/basis/transition/would-be-head from a losing CAS is therefore
not a state. The serialized state and all consumers retain only the pre-CAS
state digest: embedding a receipt/refinement back into a state, live object,
terminal, cause or transition is forbidden because it would create a release-
chain digest cycle.

For every operation other than generic `Release`, after Receipt-sidecar
readback the ledger derives one
`Arch004CapacityReceiptPublicationBatchV1`. Its deterministic
`publication_transaction_id` uses the canonical formula above. Slot,
generation, durable-record and receipt digests equal the selected head and
sidecar payload. Destinations are ordered first by every published-state
ordinal, each with the selecting `StateResolution` ref, then by exactly one
auxiliary destination iff the candidate publication preimage is non-`None`:
`RetainedMetadataPublication` for a retention Transfer or
`ResourcePublication` for a journal publication. `destination_count` is exactly
state count plus zero or one. Every state destination's digest equals its
selected receipt entry, and consuming subject/location is the exact charged
object that retains that proof. A retained-metadata destination's Active body/
digest is byte-identical to `RetainedMetadataTransfer.active`; its subject,
requirement, Reserved target state and semantic terminal equal the sole
retention target/authority, and its location is the sealed retained-subject
index that stores the resulting public indirection. A resource destination's
owner, proof bundle and location equal the journal publication bundle. Missing,
extra, duplicate, reordered, uncharged, wrong-auxiliary-variant or cross-location
destinations invalidate the batch.
Destination ordinals are the zero-based vector indexes. The marker's
`public_indirection_count`, batch `destination_count` and `staged_copy_count`
are equal, every vector has that exact length, and marker
`public_indirection_set_root` recomputes from the ordered indirection vector.
Each indirection/certificate/staged copy repeats its index as
`destination_ordinal`; duplicate or skipped ordinal, projection mismatch, or
indirection order different from the batch is invalid.
Only this PublishedBatch activation checkpoint may contain PublicIndirection
participants. Its checkpoint-body public stable-filter count equals those three
counts. For each ordinal, the matching marker indirection, batch destination and
sealed destination-kind index-maximum accounting function construct the unique
Prepared region: its indirection/body digest is exact and its
`reserved_index_accounted_bytes` is the exact charged maximum. The body public
stable-filter vector is byte-for-byte the deterministic projection of those
ordered regions: each participant carries the same activation tuple,
publication transaction, ordinal, location, exact Prepared-region/indirection/
certificate digests and `required_old_index_entry_digest = None`, and its target
readback equals that constructed region. Missing, extra, duplicate, reordered or cross-batch public participants
invalidate the checkpoint. Generic Release and every non-activation checkpoint
have public-indirection participant count zero and the canonical empty public
subroot.

The `RetainedMetadataPublication` destination is the only publication of
`Arch004RetainedMetadataActiveV1`. Before activation its candidate preimage and
staged body are private and non-state; after activation the retained-subject
index resolves it only through the exact current-checkpoint Prepared region or
settled Active suffix, public indirection and certificate.
`ResolvePublishedRetainedMetadataActive(publication_indirection_digest,
expected_active_digest)` follows that indirection, staged destination and flat
validation capsule, then proves the target Reserved state, semantic terminal,
retention requirement, source Released cause and Active body in target-before-
Active-before-source order. It also proves that `active.opened_at` equals the
Transfer receipt's persisted `committed_at`/CAS instant and is not earlier than
the referenced flow/DNS semantic-terminal time. The expected digest is a result binding, never a
locator. `MetadataRetentionReadback.predecessor_active_publication_indirection_digest`
equals the indirection in that exact retained-subject index entry and resolves
the same Active digest through the applicable activation branch; a digest-only
Active, Prepared entry from a noncurrent checkpoint, wrong destination variant,
or early staged body cannot authorize its terminal or later capacity release.

For a published `Reserved` state, `predecessor_reserved_proof` is absent. For a
published `Released` state it is mandatory, byte-identical to the candidate
set's source proof, and its state digest equals
`Released.predecessor_reserved_digest`; the destination charge covers that
complete predecessor proof as well as the new receipt ref. The generic-release
capsule carries the same mandatory source proof inside its fixed sidecar budget.

For destination ordinal `i`, the ledger writes exactly one
`Arch004CapacityStagedDestinationCopyV1` under its deterministic
`staging_object_id`. Its destination and digest equal batch member `i`; its
projection is the unique displayed projection of that member. The private
staging namespace accepts lookup only through the unforgeable transaction
capability held by the in-progress publication executor. A state digest, proof
digest, consumer location or staging ID supplied by a caller does not confer
that capability, and ordinary resolver APIs cannot address or enumerate the
namespace. `staged_copy_count = destination_count`, and `staged_copy_set_root` is the
canonical ordered root of the complete staged-copy bodies after every copy has
fsynced and read back. A source proof written first, including a Transfer source
Released proof, therefore remains non-state.

Only after the complete staged vector reads back may the tag-`0x400C` gate sign
one `Arch004CapacityDestinationPublicationCertificateV1` per ordinal. Every
certificate repeats the receipt context, deterministic publication transaction,
selected head slot/generation/record, batch digest/count/roots and that ordinal's
exact staged-copy, destination and projection digests/bodies. Before signing,
the single WAL coordinator reserves the next revision with a fresh attempt nonce
and derives its target-independent transaction ID; every certificate repeats
that exact activation revision/ID. It also embeds the same complete flat
`validation_capsule` body/digest in every certificate. It contains no activation
time, batch body, indirection, marker or Open body, and the capsule contains no
prior full certificate. Recovery of the same Prepared attempt therefore
recreates byte-identical fixed-depth input. An aborted retry uses a fresh nonce,
transaction ID and certificates; the earlier signatures remain unreachable. A
different ledger, operation, activation tuple, slot, ordinal, location, proof,
projection, capsule or batch cannot reuse a certificate.

The ledger then builds one ordered public indirection per staged copy. Each
indirection binds the public consumer location to the deterministic private
object and its exact certificate. Its public location equals the destination
projection's storage location; transaction/ordinal/staging/destination digests
equal the staged copy; `staging_object_id` recomputes from those values; and the
certificate repeats the same activation tuple, projection, batch roots and
validation capsule. At each previously absent public location it constructs the
immutable Prepared index region with an empty activation-suffix frame and the
reserved maximum byte charge. The corresponding PublicIndirection participant
binds that region digest, indirection/certificate digests, location, activation
tuple, publication transaction and ordinal.

Under that one global-WAL attempt the ledger samples one
`publication_linearized_at` and includes every Prepared index region plus the
fixed targets that install the next marker-store Present payload containing the
full `Arch004CapacityReceiptPublicationBatchMarkerV1`, replace the sidecar-store
Receipt payload with `OpenOperationReplay { PublishedBatch }`, change Pending
Accepted to Idle, and append the exact `OperationReplayOpened` record. All fixed
and public targets fsync/read back before the one Commit marker; its checkpoint
revision/transaction ID equal every certificate, indirection and participant.
The transaction exposes all-old or all-new state. The equalities are strict:

```text
marker.opened_at = open.opened_at = OperationReplayOpened.observed_at =
  every public_indirection.activated_at =
  every activation_receipt.activated_at = publication_linearized_at
```

Before the global Commit marker, no ordinary resolver or caller can observe an
unlisted Prepared region, marker, Open result, raw proof or partial destination.
After it, the current checkpoint makes all participants reachable together and
the caller sees the same byte-identical marker/Open. The tag-`0x400D` gate then
signs one activation receipt per exact current participant, copying the sealed
`publication_linearized_at` rather than sampling a new time, and atomically appends
each bounded suffix; all suffixes must read back before any successor checkpoint
may commit. Recovery deterministically reconstructs the same attempt, staged
roots and certificates from the selected head, Receipt sidecar and WAL body; it
can finish missing suffixes but cannot publish a source-only, target-only or
journal-only prefix. A certificate or Prepared region from an uncommitted or
aborted attempt remains unavailable and is removed before retry.

Each destination's fixed worst-case charge includes its raw staged body, public
indirection, certificate with one complete flat validation capsule, immutable
Prepared index region, maximum activation-receipt suffix, framing and recovery
overhead; private staging is the same charged payload copy, not an unaccounted
second raw body. Marker and Open maxima include up to
`max_active_capacity_reservations + 2` certificates and therefore charge the
bounded quadratic worst case of duplicating that flat capsule once per
destination. No maximum may assume shared or deduplicated capsule storage. After
activation, each consumer retains that self-contained Active index entry,
receipt, indirection and certificate at its public location. Marker rotation is
forbidden until every suffix and copy has fsynced/read back, the Open replay has
closed and the successor watermark covers the request sequence. The marker may
then become Vacant without invalidating a consumer activation receipt. Typed
consumer unreachability is required to collect the raw body and index entry. No
destination may be collected while Open is current, and the next head CAS is
blocked until replay closure. Thus marker or sidecar rotation cannot resurrect
a partial batch or create an unbounded marker journal.

For destination `d`, `prepared_region.reserved_index_accounted_bytes` equals
the sealed accounting function's canonical maximum encoded byte length of that
exact destination kind's immutable Prepared region plus one maximum framed tag-
`0x400D` suffix, checksum and location-index overhead. The destination's
`accounted_bytes` includes that value exactly once; the actual one-region/one-
suffix physical length must not exceed it. It is not a producer-selected
estimate, cannot be reduced because the suffix is absent initially, and cannot
be added a second time on promotion. A smaller or larger supplied value, an
extra suffix copy, or one byte beyond the sealed maximum invalidates the
destination and its batch.

A generic `Release` has no long-lived subject-owned receipt destination: it is
legal only after typed unreachability proves that no live semantic payload,
business object, revision/index/lineage entry, queue/staging item or future
contract consumer still uses the source reservation. The exact typed terminal/
cause preimage, its required signed readback and prior publication proof are
release authority rather than continued semantic use: they MUST remain
reachable through validation, are copied into the operation's bounded candidate
or capsule as specified, and may be collected only after Open closure. The
predicate also excludes the operation's new candidate, durable slot image and
replay capsule, which do not exist before the CAS and cannot escape afterward.
Its `GenericRelease` replay result carries one
`Arch004CapacityReleaseReplayCapsuleV1` containing the complete raw `Released`
state, basis bundle, selecting receipt ref, transition, resulting head and
snapshot plus every digest required for the capsule-only raw released-state
validator. It is not a consumer publication and therefore does not fabricate a
public destination indirection; retaining only a receipt/state digest is
invalid. The capsule request equals the transition-wide request. Its
root is the canonical formula above and its accounted bytes cover the checked
maximum encoded capsule, indexes and recovery overhead. A release whose proof
must remain reachable instead uses `Transfer` to a charged retained subject or
the journal-publication operation.

The internal, non-serialized
`ValidateSelectedGenericReleaseCapsule(selected_sidecar_store_slot_digest,
expected_open_replay_digest)` operation is the second and only other raw-
validation base named above. COW/WAL recovery MUST first select the exact current
sidecar `Occupied/Present/OpenOperationReplay { GenericRelease }`; the supplied
slot and Open digests are assertions over that selected body, never locators. The
same recovery tuple must contain the exact current Committed head/slot image,
current watermark one revision behind that head, Pending Idle, revision-two
`OperationReplayOpened` event naming the same Open, and marker Vacant. An older
fallback, Receipt, PublishedBatch, Closing/Closed replay, copied capsule, naked
capsule digest or caller-provided body cannot invoke this operation.

The validator recomputes the Open/result/capsule roots and requires byte equality
among the Open request/operation/transition, capsule request, signed tag-`0x400A`
receipt and the current head-slot candidate. That candidate has exactly one
`ReleaseReleased` state, exactly one matching predecessor Reserved proof, exactly
one matching typed terminal/cause preimage, and publication preimage `None`.
The capsule's complete Released proof, basis, receipt selection, predecessor,
cause, transition, resulting head/snapshot and accounted bytes must equal those
current bodies. Its embedded predecessor proof and origin certificate/
indirection are checked as raw inputs inside this call; they are not resolved or
returned as a new long-lived publication.

Success returns only a stack-local valid-result decision to replay processing;
it creates no refined `Reserved`/`Released` value, reference, index, destination,
indirection, certificate or storage write. No capsule or proof copy may escape
the selected current Open sidecar. Once closure selects Closing/Closed or the
successor watermark retires the sequence, replay selection returns the closed or
retired result before raw validation and this operation is unavailable. Thus a
generic-release capsule has no valid copy or refinement outside the selected
Open payload and cannot become a third raw-validation base.

Every committed operation, including generic `Release`, reaches exactly one
`Arch004CapacityOpenOperationReplayV1`. Its request/digest and operation ID are
byte-identical to the transition, its transition digest is exact, and its
result is `PublishedBatch` for every non-generic operation or `GenericRelease`
for generic release. The published variant embeds the complete receipt and
marker bodies/digests, including the batch, public indirections and destination
certificates, not a set of independently reloadable target refs. The open replay
root covers the complete result and `opened_at`; `accounted_bytes` covers its
maximum body, indexes and crash-recovery overhead. While it is open, the ledger
admits no next head CAS and none of its destination proofs may be collected. An
initial successful call returns
`Arch004CapacityOperationOutcomeV1::Committed { exact open body/digest }`; an
exact response-loss retry returns
`AlreadyCommitted { the same byte-identical open body/digest }`. No error/body
pairing or out-of-band result channel is used;
same-sequence bytes that differ in request, transition, result selector or any
digest are a no-mutation replay conflict.

A durable acknowledgement is accepted only over the open replay's exact
request channel and encodes
`Arch004CapacityOperationReplayAcknowledgementV1`. Open digest, operation ID,
owner, lease-context digest, channel binding and nonce match byte-for-byte.
`acknowledged_at` is ledger-sampled at authenticated channel acceptance, is not
caller supplied, and satisfies
`Arch004CapacityOperationReplayResultReceipt(open).committed_at <=
open.opened_at <= acknowledged_at <= replay_deadline`; it equals the exact
durable `ResponseAcknowledged` record's `observed_at`. That record repeats the
Open digest. Its copy-on-write append CAS compares the selected sidecar-store
Present payload and exact Open body/digest as well as the current OpenActive
event-store prefix; an Accepted/Receipt/Closed/fallback sidecar or another Open
cannot authorize Ack. Before ledger closure, the live registry authority appends
the exact `ResponseAcknowledged`/token-retirement/`ChannelClosed` suffixes,
seals the complete census and signs the unique owner-epoch terminal under
`LiveRegistry`. If the durable acknowledgement chose the success branch but
that sequence was interrupted, `HistoricalCompleteAcknowledgedClosure` finishes
only its exact missing suffix and candidate after lease expiry; a later crash in
Closing is finished only by `HistoricalFinalizeInstalledRecord`. The
acknowledgement embeds that selected terminal and digest, and its terminal time
equals `acknowledgement.closed_at`, which is selected only by the terminal-
candidate CAS and is not earlier than the acknowledged event, every suffix
event, barrier acknowledgement or census finalization. Historical completion
may therefore close after lease expiry without backdating any event. This makes the per-operation epoch absorbing on the
success path as well as expiry. A different caller, channel, lease, nonce,
operation, epoch terminal or late acknowledgement cannot close the replay.

Typed deadline expiry instead requires the complete
`Arch004CapacityOperationRequestOwnerUnreachabilityV1`. Its first
`RequestTransportRetired { retirement_basis: OpenReplay }` append CAS compares
the selected sidecar-store Present payload and exact Open body/digest, the
OpenActive event-store prefix, and both expired deadlines. It cannot run from
Accepted/Receipt/PreOpen/Closed/fallback state, and its basis Open digest is
byte-identical to the eventual expiry/Closed replay. Its registry snapshot,
census and terminal bodies hash to their displayed digests and are byte-equal
where repeated. Snapshot, every registration, request, census, terminal and
authority context carry the same ledger, sequence domain, owner-epoch key,
installation/session/generation and plan binding; the request channel occurs
exactly once. The census barrier, leaves, stream prefixes, counts and canonical
roots satisfy the complete replay rules above. `leaf_count =
registration_count`, both registered/closed key-set roots are equal, every
pending vector is the exact empty vector, and checked total pending counts are
zero. The terminal is the sole compare-and-install successor of the exact
revision-0 frozen registry snapshot: revision is one, predecessor digest equals
that snapshot, closure-census digest is exact, and state is `Closed`.

Terminal signing is post-CAS. The replay-registry authority first constructs
the unique `Arch004CapacityOperationOwnerEpochTerminalCandidateV1` and
atomically compare-and-installs both the event store from Open to its exact
Sealed census body and the owner-epoch head from `Open { exact snapshot }` to
`Closing { exact candidate }`. Only after fsync and byte-for-byte readback can
the tag-`0x400B` terminal gate sign that candidate. A losing sibling candidate
cannot obtain a signature. A crash in `Closing` leaves the same candidate for
historical completion; it cannot choose another census, time, mode or terminal.
The final combined closure below replaces that exact Closing head with
`Closed { signed terminal }`.

The tag-`0x400B` terminal and unreachability signatures use the plan-sealed
singleton replay-registry authority. `HistoricalCloseOnly` is reachable only
after the live lease expires and may use only the exact already frozen snapshot
plus every channel's durable last live prefix. It may append the uniquely
derived terminal retirement/key-destruction/close suffix and then seal the
barrier; it cannot register a channel, accept another request, issue a token,
rewrite a prior event, change a deadline, or authorize a ledger CAS.
`HistoricalCompleteAcknowledgedClosure` is reachable only when the exact
durable prefix already contains one valid in-deadline `ResponseAcknowledged`
and no retirement branch. It may finish only that acknowledged fold and install
its exact census/candidate. `HistoricalFinalizeInstalledRecord` may sign an
exact installed unsigned event record or the exact candidate already persisted
in Closing and its byte-identical unreachability envelope; it cannot append or
change any of them. The terminal's signing context
and digest equal the Ack or
unreachability context where repeated; the authenticator header identity/key/
gate equal that context and the manifest authority spec. Time equality is
strict. For committed-Open expiry,
`owner_unreachability.observed_at = expiry.observed_at =
terminal.candidate.closed_at = closure_census.finalized_at`. For pre-CAS
retirement there is no Open digest, replay-expiry body or Closed replay, and
`owner_unreachability.observed_at = terminal.candidate.closed_at =
closure_census.finalized_at`. In both cases that instant is no earlier than the
replay deadline, accepting-lease expiry, branch latch, both closure heads and
every close event. The terminal is
absorbing: the owner-state head advances only through the two irreversible
steps `Open { frozen snapshot } -> Closing { exact candidate } -> Closed {
signed terminal }`, and no registration, request, token, lease or
successor state under the same epoch ID is thereafter valid. A new operation
uses a fresh epoch and binds all channel AAD, nonces, retry tokens and sequence
to it.

Acknowledgement and expiry share one closure primitive. There is no standalone
durable Ack or Expiry state: one storage compare-and-install consumes the exact
selected sidecar-store Occupied/Present `OpenOperationReplay`, its exact
`Closing { terminal candidate }` owner-epoch state, current watermark-store
slot and current marker-store slot, and installs the unique signed owner-epoch
terminal, the next sidecar-store Occupied/Present
`ClosedOperationReplay { Acknowledged | Expired }` and the successor watermark
together. The non-generic marker remains byte-identical Present; the generic
marker remains byte-identical Vacant. The Ack-embedded or Expiry-embedded
terminal is the exact terminal installed by that transaction. The closed body's replay request/digest,
operation ID, publishing-transition digest and replay-response root are byte-
identical to the consumed open body; Ack/Expiry `open_replay_digest =
Digest(open)`. Its resulting-watermark body/digest are byte-identical to the
body/digest installed in the selected watermark-store slot.
For acknowledged closure, `closed_at = acknowledgement.closed_at`; for
expiry it equals `expiry.observed_at`. The successor watermark has revision and
highest closed sequence each advanced by exactly one, its non-resolving
`last_closed_replay_commitment` equal to
`Arch004CapacityRetiredReplayCommitmentV1(open)`, and predecessor digest equal
to the request's expected-old watermark. That commitment is scalar tombstone
material, never a typed `Digest(Open)` reference and never passed to a resolver.
Owner-epoch state, complete sidecar-store slot, marker-store current and
watermark-store slot are fsynced and read back before the ledger unlocks; a
crash exposes all-old or all-new values, never a closed epoch/sidecar with the
old watermark. After closure the bounded
registry/event store may be collected because the epoch ID is a deterministic
projection of the now-retired sequence. Once the successor watermark is
durable, every operation-result or closure-command retry for that sequence,
including an exact retry while the selected Closed sidecar is still physically
retained, returns `LedgerOperationReplayRetired` with no bundle or mutation.
The Closed body is recovery/audit material, not a second API replay horizon; a
closed marker is never absence and cannot reopen the historical commit gate.

The operation watermark has exactly two durable store slots. Genesis is an
Occupied revision-zero/sequence-zero `Slot0`, generation one, with no
predecessor or last replay; Slot1 is the typed ledger/domain-bound EmptyTarget
at physical generation zero with `next_slot_generation = 1`. EmptyTarget is not
selectable. For every successor `n`, `slot = Slot(n mod 2)` and
`slot_generation = floor(n / 2) + 1`. Recovery loads the watermark only from
the OperationWatermark entry of the recovered global checkpoint's exact current
tuple. The entry's typed envelope digest, revision, physical slot and generation
must equal the complete watermark slot. A higher non-Committed BodyOnly,
Prepared or Aborted candidate is noncurrent under the global table and ignored
as a whole; after its Commit marker is valid, corruption of the named watermark
target fails closed. The watermark participates in the same union decision as
owner/sidecar closure and cannot select its new revision independently. A
closure compares
the exact current digest and atomically copy-on-write replaces the alternate
slot with an Occupied revision `n`. For `n = 1`, target Slot1 is that exact
typed EmptyTarget and Slot0/revision zero becomes fallback. For `n >= 2`, the target
normally held committed revision `n - 2`; an aborted Prepared attempt may have
replaced it with a complete or torn uncommitted revision-`n` target, which only
the fresh-nonce raw-frame retry rule may consume. Before a normal attempt the
complete old fallback is readable, and after commit the old current becomes the
new fallback; no uncommitted target is ever selectable. The predecessor digest
resolves only that immediate new fallback; validators never require an
unbounded watermark chain. A duplicate generation within one physical slot,
two committed/selectable same-revision siblings, skipped revision, rollback or
target-slot mismatch is invalid.

The post-CAS sidecar and publication-batch marker are two independent typed COW
stores, each with exactly two physical slots and its own storage revision. At
ledger genesis each store has Slot0 Occupied at storage revision zero/store-slot
generation one with `Vacant { retired_through_sequence: 0 }`, plus the exact
ledger/domain-bound Slot1 EmptyTarget at physical generation zero with next
generation one. Every logical write checked-increments its storage revision,
uses `store_slot = Slot(storage_revision mod 2)` and
`store_slot_generation = floor(storage_revision / 2) + 1`, and writes/readbacks
the complete containing-slot envelope. The first write replaces only the exact
EmptyTarget. In stable committed history each later target contains revision
`n - 2` and old current revision `n - 1` becomes the sole fallback; an aborted
Prepared attempt may leave a complete or torn uncommitted revision-`n` target
only for the bounded fresh-nonce replacement rule above.

Recovery loads PostCasSidecar and PublicationBatchMarker only from their two
matching entries in the recovered global checkpoint's exact current tuple. Each
entry's typed envelope digest, storage revision, physical slot and generation
must equal its complete artifact-store slot. A higher non-Committed BodyOnly,
Prepared or Aborted candidate is noncurrent under the global table and both
artifact targets are invisible; after its Commit marker is valid, corruption of
either named target fails closed rather than resurrecting a fallback.
Two committed/selectable same-revision different-digest siblings, skips,
rollback, wrong parity/
generation/domain/payload, an unlisted complete target or a non-immediate COW
target are invalid. Once the tuple selects a Vacant/Present payload, every older
payload is suppressed for business selection.

Artifact-store slot/generation is independent from the payload's
`sidecar.head_slot/head_slot_generation` or marker head tuple. A current Present
payload is usable only when that inner tuple and durable-record digest match the
selected head image; otherwise it is an incomplete/corrupt cross-store tuple,
never an alternate current. A newly committed head with current Vacant artifact
stores is the one recoverable post-head/pre-publication state. Non-generic
publication advances sidecar Vacant to Receipt and then, in the activation union
transaction, Receipt to Open while marker Vacant becomes Present. Generic
release advances sidecar Vacant directly to Open and leaves marker Vacant.
Closure advances sidecar Open to Closed without changing the marker payload.

Present-to-Vacant reuse is legal only after the successor watermark covers that
request. Marker reuse additionally requires every destination's self-contained
public indirection/certificate/raw payload to be durable and resolver-readable;
sidecar reuse additionally requires no incomplete historical gate. The new
Vacant `retired_through_sequence` is monotonic and not above the selected
watermark. An old Present fallback, even if byte-valid, cannot reopen a Receipt,
Open, Closed replay or marker after current Vacant is selected. Every artifact
transition lists the exact old-current digest, raw target-frame precondition,
optional complete old-target digest and new-target digest in the bounded union
WAL, so a torn write, crash at decision, current/fallback mix or pre-watermark
overwrite has no V1 success encoding.

Head, selected sidecar/marker store payloads and watermark are cross-checked
before recovery or a new request. In idle Closed or safely Vacant state,
`head.revision = watermark.revision = highest_closed_sequence`. With an Open or
post-head/pre-open incomplete commit,
`head.revision = watermark.revision + 1 = replay_request.request_sequence`.
The selected sidecar Present payload's inner head slot, generation and durable-
commit-record digest equal the selected head-slot image, and its open/closed
transition digest equals that image's transition. A non-generic Open requires
the exact matching marker Present payload; generic Open requires marker Vacant.
The artifact wrappers obey their own storage-revision parity/generation, while
the watermark slot for a closed revision obeys its separate revision formula.
Individually valid bodies from different revisions, slots, generations, commit
records, storage revisions or marker transactions cannot be spliced into a
recoverable ledger state.

Replay selection precedes operation-ID and ordinary head handling. A bounded
parser first extracts only `Arch004CapacityReplaySelectorEnvelopeV1`, the exact
projection of the four same-named request fields. Ledger ID and sequence domain
must equal the current installation-wide manifest; this stable check requires no
collected owner epoch, historical key or channel. It then reads only the
recovery-consistent current `(watermark, pending admission)` tuple and applies
the retirement/sequence cases below. Only a non-retired live horizon loads the
selected head-store slot, sidecar and owner-epoch state and validates the full
request authenticator, registry, owner epoch and channel. Invalid live-horizon
authentication or history is non-retryable. The following order is total:

1. `request_sequence <= highest_closed_sequence` returns
   `LedgerOperationReplayRetired` with no mutation, regardless of a retained
   Closed sidecar or admission revision. `AlreadyCommitted` is unavailable
   after this boundary.
   At exactly the next sequence, `Idle(last)` with
   `admission_revision <= last`, or `Accepted(r)` with an incoming admission
   revision below `r`, likewise returns Retired before historical validation.
2. `request_sequence > highest_closed_sequence + 1`, checked overflow, or an
   impossible cross-store revision tuple returns `LedgerReplaySequenceInvalid`.
3. At exactly the next sequence, a selected head image already committed at
   that revision is handled before fresh admission. If its complete Open or
   Closing replay is present, byte-identical request/intent/transition bytes
   return `Arch004CapacityOperationOutcomeV1::AlreadyCommitted` with the
   complete byte-identical Open body; any
   different bytes return `LedgerOperationReplayConflict`. If the head image is
   durable but receipt/batch/Open publication is incomplete, the exact
   `Accepted` request/intent and slot image deterministically finish that same
   canonical Open, atomically clear admission to Idle, and then return
   `Arch004CapacityOperationOutcomeV1::AlreadyCommitted`; a different request,
   intent or image is conflict. This state never enters another head CAS or returns ordinary head
   mismatch.
4. With no committed next head, `Accepted(r)` is authoritative. An incoming
   admission revision below `r` was retired in case 1; revision `r` resumes only when the
   complete request, intent, accepted head/watermark and owner epoch are byte-
   identical, while different bytes at `r` conflict; a revision above `r` is
   sequence-invalid.
5. With no committed next head and `Idle(last)`, a request with
   `admission_revision <= last` was retired without a bundle in case 1. Only checked
   `admission_revision = last + 1`, an exact current expected-watermark digest,
   and the current head may compare-and-install a fresh Accepted body. A larger
   admission revision or stale expected-watermark digest is sequence-invalid.

Operation-ID and operation-specific head validation run only after case 5 has
selected that fresh Accepted body. A pre-CAS-retired request is therefore
tombstoned by `Idle.last_admission_revision` even though the operation
watermark intentionally did not advance; an incomplete committed request is
completed rather than mistaken for a fresh CAS. Fixed-space retirement never
pretends to reconstruct a collected Transfer target or journal bundle.

There are exactly two fixed slots in each independent sidecar, marker and
watermark store. The selected sidecar Present payload contains the complete
Open/Closed replay and the selected marker Present payload contains the complete
non-generic batch/indirection certificate set. COW reuse may overwrite old
artifact payloads only under the retirement rules above; artifact-store parity
is never inferred from head parity. The current watermark survives head,
sidecar, marker and consumer-proof retirement. The fixed recovery budget
therefore holds at most two complete maximum-size containing-slot envelopes per
store regardless of operation count.

An inner journal record and receipt may already be durable before the capacity
head CAS because the complete allocation was reserved in advance; they are not
the current semantic outcome until publication. The head CAS durably installs
the candidate bodies, transition, new head and its sole embedded after snapshot
as invisible recovery material; it does not publish a consumer-visible state,
journal Active, envelope or raw proof. Only the later activation union
transaction atomically publishes every charged destination through its exact
public indirection/certificate while installing the marker, Open replay,
Accepted-to-Idle transition and `OperationReplayOpened`. Before that activation
every candidate and private staged copy is unreachable to ordinary consumers;
after it every destination resolves from its public indirection. There is no
partial publication and transfer never frees the source semantically before all
targets activate. While the common open replay is current, response-loss replay with
the same request, operation ID and allocation revision returns the byte-
identical bundle. After acknowledgement or typed owner-epoch expiry, operation
replay is retired even though independently charged publication proofs remain
valid for their consumers. A stale head, missing member, second release,
duplicate/forked append revision, counter overflow, or partial vector has no
state change.

`Arch004PublishedResourceEnvelopeRefV1` first resolves the exact public
indirection named by `publication_indirection_digest`, verifies its tag-`0x400C`
certificate and ResourcePublication projection, and loads the matching staged
destination. Only then does it resolve one immutable, fully charged publication
proof bundle, not independent historical digests. In that bundle,
the envelope is exactly the envelope named by the publishing operation; the
resulting head's `last_transition_digest` is exactly that transition; its
snapshot digest/revision equal the transition's after snapshot; receipt and
current Active equal the envelope projection; and the complete state-entry set
contains every `Reserved`/`Released` named by the envelope/operation together
with each state's byte-equal basis bundle. Required inner variant/outcome and
current `Active`/`Unresolved` tag are projected from the bundle and cannot be
supplied independently. The bundle proof root covers every displayed member and
its accounted bytes fit inside the same journal allocation. A missing member or
cross-envelope/transition/head/state splice is invalid even when each object is
otherwise valid.
The `publishing_post_cas_receipt` has `use = ResourcePublication` with the
bundle's exact owner subject; its canonical receipt durable record names this
same transition, resulting head and snapshot. Its ledger-level context resolves
only the same ledger manifest and commit authority; the publication bundle's
journal `Reserved` state and requirement independently validate the exact
journal owner, subject and charge. Every capacity-state
entry's receipt ref instead has `use = StateResolution`, selects the zero-based
receipt member whose state/commitment/subject/creation role equal that entry,
and resolves the same canonical receipt core when those states were published
by this operation. A `PublishJournalAppend` receipt has an empty state vector
but still requires the `ResourcePublication` ref; absence of newly created
states never makes the post-CAS publication proof optional.
State entries are sorted uniquely by `(state_digest, commitment_digest)` and
their exact set is closed: initial split has source Reserved, source Released,
journal target Reserved, plus current ResourceNode Reserved iff present (three
or four); append-keep has current ResourceNode and unchanged journal Reserved
(two); append-release has source ResourceNode Reserved/Released plus unchanged
journal Reserved (three). Duplicate, missing, or extra state entries are
invalid.

Operation/cause mapping is exact. Flow and DNS retention transfers require the
matching typed semantic terminal, retained-active body and
`CapacityTransferredToRetention` source cause. Initial resource persistence
uses `Transfer` with `ResourceJournalPersisted` and the exact revision-zero
receipt, journal Active and outer envelope. A later keep-current or health
append uses only `PublishJournalAppend`; a successful compensation or releasing
recovery uses only `ReleaseCurrentResourceAndPublishJournalAppend` with the
matching `NonJournalResourceCompensated` or `NonJournalResourceRecovered`
cause. Those causes are invalid in generic `Release`. A deleted generation
journal terminal uses generic `Release`. V1 exposes no compaction disposition
or authority: attempting to compact a live ARCH-004 journal allocation is a
typed `ResourceJournalCompactionUnsupported` refusal with no state change.
Retained-metadata, raw-fragment and dynamic terminal causes remain release-only.
Cross-kind authority, wrong terminal disposition, target-set mismatch, or using
a terminal digest as its own evidence is invalid.
Each flow/DNS retention Transfer has exactly one target. Its target commitment
subject is the matching retained subject; target requirement digest equals
`RetainedMetadataTransfer.active.retention_requirement_digest`; target Reserved
state digest equals that Active's `reserved_capacity_state_digest`; and the
Active subject/semantic terminal equal the Transfer authority and source
semantic terminal. The candidate publication preimage is exactly
`RetainedMetadataTransfer { active }`, the source Released cause is exactly
`CapacityTransferredToRetention { retained_active_digest: Digest(active) }`, and
`active.opened_at` equals the durable commit record's `cas_linearized_at` and
signed receipt's `committed_at`; the resolved semantic-terminal time is not
later than that instant. The batch has exactly the source/target StateResolution destinations followed by
one `RetainedMetadataPublication` auxiliary destination. That destination
contains the byte-identical Active body/digest; its projection repeats the
derived subject/Reserved digest/terminal, location and charge; the flat capsule
contains that same Active as its publication preimage; and the public
indirection binds that projection/capsule certificate to the same retained-
subject index location. A multi-target retention Transfer, missing or extra
Active destination, Active published at a different location, or any authority/
cause/candidate/capsule/destination substitution is invalid.
Every operation and published `Released` state also share one cause preimage.
Generic `Release.release_cause_digest` equals the digest of that state's
`release_cause`; release-plus-append's inline cause equals it byte-for-byte.
For `Transfer`, Datagram/DNS retention authority maps only to
`CapacityTransferredToRetention` with the same retained Active, and
`ResourceJournalPersisted` maps only to `ResourceJournalTransferred` with the
same revision-zero journal Active. Authority/cause substitution is invalid.
For release-plus-append, the release cause's narrowed inner record, the
publication envelope's `inner_record`, and the receipt body's `inner_record`
are byte-identical, and the cause variant equals that body's closed outcome.
A durable but unpublished success record cannot be paired with another
Still/health envelope to release a ResourceNode.
For every initial, keep, and release append, envelope `inner_record` equals the
receipt body's inner record; append-projection receipt/predecessor/current
Active values equal the publication and resolved receipt/Active chain; and the
capacity-effect before/after snapshots equal the publishing transition's
before/after snapshots. Initial transfer authority repeats the same receipt,
revision-zero Active and envelope. A cross-receipt, inner-record, Active,
projection, or snapshot splice is invalid.
For compensation, recovery and health, the resolved predecessor publication's
resource identity, plan, context, current commitment and current `Reserved`
state are byte-identical to the inner body and to this envelope's keep/release
capacity-effect fields. Compensation/recovery
`source_resource_reserved_capacity_state_digest` equals that exact current
replacement, never the initial released source or another same-kind reservation.
A same-plan/different-reservation splice is invalid.

`Reserved` and `Released` use only `CapacityAccounting`. Its ledger, subject,
owner, requirement, limit set, and accounting build/version equal commitment
and requirement byte-for-byte. Owner mapping is closed: `ResourceNode` uses
`ResourceExecutor` with the exact identity/executor; live flow/raw-fragment use
`CaptureCore`; live DNS transaction uses `CorrelationPrivacyOwner`; retained
flow/DNS and generation journal use `StoragePrivacyOwner`; DNS stream/DoH
dynamic subjects use `CaptureCore`; queue/staging uses `StoragePrivacyOwner`;
and `BufferGrowth.owner_identity` equals the deterministic identity of its
`CaptureCore`, `CorrelationPrivacyOwner`, or `StoragePrivacyOwner`. No other
subject/owner pair is valid.
The sole reservation time is
`Arch004CapacityReservationCommitmentV1.reserved_at`; `Reserved` does not repeat
or override it. `Released.released_at` is not earlier than that commitment time.

A semantic flow close or DNS terminal never releases capacity directly. It
executes one `Transfer` from `DatagramFlow`/`DnsTransaction` to the matching
retained subject. The target requirement includes every still-reachable
revision, metadata/name commitment, occurrence/question index, lineage edge,
queue/staging and persisted copy; only active-flow/outstanding/correlation
charges proven unreachable disappear in the checked difference. Even when no
representation remains, the transfer publishes a zero-usage retained
reservation followed by a typed terminal so the unreachability proof is not
replaced by `Closed`, `MatchedResponse`, or `QueryTimedOut`. Only
`Arch004RetainedMetadataTerminalV1`, with matching
`MetadataRetentionReadback`, permits its later release.
The retained-subject index stores only the exact activated publication
indirection. `MetadataRetentionReadback` MUST start from that index value and
successfully call `ResolvePublishedRetainedMetadataActive`; its predecessor
digest, subject and semantic terminal equal the resolved Active, and the
terminal's predecessor digest, subject, Reserved digest, reason and evidence ref
equal that readback. `terminal.ended_at = readback.ended_at >= active.opened_at`,
and the later generic-Release state's `released_at >= terminal.ended_at`. The
resolved Active's retention requirement equals the current retained commitment.
The Active indirection/certificate/raw destination remains reachable
through terminal construction and generic-Release Open readback; only after that
Open closes and the successor watermark retires the sequence may the proof copy
be collected. A terminal/readback built from a digest alone, another Active,
private staging, a sibling destination or an already collected indirection
cannot authorize release.

Every resource plan seals a cycle-free journal allocation before its digest is
computed. The allocation identifies the ticket, step, resource and stream but
contains no plan/result/record/root, receipt, capacity state, snapshot,
transition or head digest. Its `maximum_inner_record_count` and
`maximum_accounted_journal_bytes` are the checked sums of the four ordered role
budgets. Accounted bytes include the inner body, complete ARCH-001 envelope,
partition/index entry and the sealed accounting function's fixed per-record
overhead; allocator or compression savings never reduce the charge. The initial
ResourceNode requirement contains exactly `maximum_accounted_journal_bytes` as
its `ResourceJournalBytes` charge. Exceeding a per-role count/byte budget or
either aggregate maximum refuses the append without changing the current
journal Active or capacity head.

Both `role_budgets` and every `role_usage` vector are in the exact displayed
schema order `InitialResult, CompensationResult, RecoveryResolution,
HealthObservation`; each schema occurs once. A usage cell's schema equals the
same-ordinal budget, used count/bytes do not exceed its maximums, and mandatory
terminal reserves do not exceed the remaining count/bytes. Duplicate, missing,
reordered, or cross-role cells are invalid even when aggregate totals fit.
At allocation revision zero, `InitialResult` usage is exactly count one and
`reserved_append_accounted_bytes`; all other usage cells are zero, aggregate
count is one, and aggregate accounted bytes equal that same value. At every
successor, only the cell matching `inner_record` increases: count by one and
bytes by `reserved_append_accounted_bytes`; all other cells are byte-identical
to the predecessor Active. The checked sum of role counts equals
`cumulative_inner_record_count`, and the checked sum of role bytes equals
`cumulative_accounted_journal_bytes`. Decrement, unchanged matching cell,
wrong-cell charging, or under-reporting bytes is invalid.

Role budgets are also liveness reserves. `InitialResult` admits exactly one
record. Compensation and recovery budgets each reserve their displayed
mandatory-terminal count/bytes, `StillRecoveryRequired` is bounded, and health
has a sealed maximum. Any append that leaves a resource Active or Unresolved is
admissible only if the unused role budgets still cover the exact worst-case
mandatory suffix: at least the remaining compensation record and, whenever an
ambiguity exists or can be produced, one absorbing recovery resolution. A
health or retry append cannot consume those bytes. The ordered `role_usage`
vector in every receipt/Active makes this check replayable; all four cells,
including zero usage, are required.

The inner `Arch004ResourceResultV1` is sealed first and contains only values
available before its persistence: in particular it names the preexisting source
ResourceNode `Reserved` state and never a receipt, journal Active, target
Reserved, Released state, outer envelope, transition or resulting head. The
revision-zero receipt then identifies that exact typed inner body and journal
location. Revision zero has no predecessor receipt/Active, count one, and this
seed:

```text
prior_record_accumulator_root = SHA-256(
  "FlowProbe.Arch004.ResourceJournalAllocationSeed.v1\0" ||
  deterministic_cbor(allocation_identity))
```

Every successor receipt names the current Active and latest receipt, increments
the allocation revision and count by one with checked arithmetic, and computes:

```text
record_accumulator_root = SHA-256(
  "FlowProbe.Arch004.ResourceJournalAllocationAppend.v1\0" ||
  prior_record_accumulator_root ||
  uint64_be(allocation_revision) ||
  Digest(inner_record) ||
  uint64_be(inner_record_encoded_bytes) ||
  uint64_be(reserved_append_accounted_bytes) ||
  deterministic_cbor(role_usage_after))
```

`reserved_append_accounted_bytes` is the sealed worst-case total for the inner
body, ARCH-001 envelope, successor Active, outer envelope, retained historical
snapshot/transition/head proof bundle, partition/index entries and fixed record
overhead; the eventual encoded publication must not exceed it. The two cumulative byte counters are
checked predecessor-plus-inner and predecessor-plus-accounted values
respectively; the latter, not the former, is compared with the capacity charge.
Receipt and read-back repeat the complete body; they never name the
successor Active or any outer/capacity publication object. The successor Active
preserves allocation subject, journal `Reserved`, retained charge and maxima,
increments revision by one, and copies the receipt's role usage, cumulative
counts/bytes, accumulator and journal-after root exactly. Only the unique highest published
revision is current, and only it may be terminalized.

The revision-zero outer envelope maps initial outcome exactly: `Applied` and
`AlreadyApplied` use `InitialSplit + Present(Active)`;
`AmbiguousRecoveryRequired` uses `InitialSplit + Present(Unresolved)`; and
`Unapplied` uses `InitialSplit + NoCurrentResource`. The split removes the
source commitment, creates one generation-journal commitment containing exactly
the full preallocated `ResourceJournalBytes` charge, and creates a replacement
ResourceNode commitment containing every and only non-journal active charge when
the outcome keeps a resource. The inner result's source digest, receipt,
revision-zero Active, envelope, transfer targets and released source must all
agree. `Arch004ActiveResourceEvidenceV1` resolves the published envelope and
current replacement, never a naked inner result or released source.

Later compensation, recovery and health inner bodies append inside the same
allocation and advance its Active chain without adding another journal
commitment. Successful compensation outcomes and recovery `Unapplied` or
`Compensated`/`OwnershipAbandoned` use `AppendReleaseCurrentResource`; compensation drift/ambiguity,
recovery `ExternalDriftPreserved`/`StillRecoveryRequired`, recovery `Applied`,
and health use `AppendKeepCurrentResource`. Recovery `Applied` changes the outer
semantic tag from `Unresolved` to `Active` while preserving the same non-journal
commitment and `Reserved` state. Every outer effect has exactly one legal ledger
operation as specified above. The journal commitment remains active
independently until its latest Active reaches the displayed deletion terminal;
an active, ambiguous, drifted, `StillRecoveryRequired`, retained, or
journal-live object is never a terminal release cause.

Keep-current tags are outcome-exact. Compensation
`ExternalDriftPreserved`/`AmbiguousRecoveryRequired` consume an `Active`
predecessor and publish `Unresolved`; recovery
`ExternalDriftPreserved`/`StillRecoveryRequired` preserve `Unresolved`;
recovery `Applied` consumes `Unresolved` and publishes `Active`; and health
consumes and publishes `Active`. Successful compensation consumes `Active` and
releases it; recovery `Unapplied`/`Compensated` consume `Unresolved` and release
it, as does recovery `OwnershipAbandoned` after its ownership-absence proof.
The opposite tag or predecessor cannot be encoded as a valid publication.

The digest dependency order is strict: allocation/source Reserved, inner body,
receipt, target or unchanged commitments and after snapshot, journal/current
Reserved, successor journal Active, optional source Released, outer envelope,
transition, then resulting head. A receipt cannot name its successor Active; an
inner body cannot name any object to its right; a snapshot cannot contain a
state/receipt/Active/envelope; an envelope cannot name its publishing transition
or resulting head; and a transition cannot name its resulting head. The inner
record accumulator never covers the receipt, Active, outer envelope or capacity
objects. These forbidden reverse edges are conformance failures, not
implementation choices.

Before publishing `RawDatagramFragmentMetadataV1`, Capture Core atomically
reserves the `RawFragmentMetadata(fragment_observation_id)` subject for one
metadata-rate slot, the exact worst-case UDP metadata bytes, and any enabled
queue/staging representation. Reservation failure publishes no metadata,
retention state, index, or evidence leaf. The retention chain is only
`Live -> {Terminal | QueuedOrStaged -> Terminal}` with the displayed exact
revisions; every successor preserves fragment ID, metadata digest, subject,
context, and `Reserved` digest. Queue/staging transfer removes the live
representation and installs the queued representation atomically under one
charge; it is not a release. Transition refs resolve only
`RawFragmentRetentionReadback` with byte-equal predecessor and transition.
Only the absorbing terminal, after all live, queue/staging, persisted partition,
record, and index references are unreachable, permits
`RawFragmentRetentionTerminal` release. Committing a persisted record while it
remains reachable is not a terminal and cannot release the reservation. Fork,
second queue, partial transfer, early/double release, or cross-fragment
substitution is invalid.

`applicable_kinds` is the exact deterministic projection of resource body and
limit set. `charges` contains exactly one entry for each applicable kind and no
other kind, in the same order. The sealed accounting build/version computes
each count and worst-case byte charge including occurrence indexes, lineage,
correlation tables, queues, staging, and journal overhead; no representation is
omitted or charged twice. The manifest provides golden equations for every
resource/body variant and max/max-plus-one arithmetic.

Requirement, reserved state, live object, terminal record, and released state
repeat the same capacity subject byte-for-byte. Flow/transaction revision chains
preserve the source `Reserved` digest until the semantic-terminal transfer; the
retained chain then preserves its target `Reserved` digest. A dynamic release
requires the exact absorbing stream/DoH/buffer/queue terminal and matching typed
read-back. Pending, active, reachable, ambiguous, or mismatched-subject objects
retain their charge.

All displayed resource/requirement/reservation/result digests use deterministic
CBOR and distinct domains `FlowProbe.Arch004.<TypeName>.v1\0`. The schema
package publishes golden vectors and rejects unknown fields/tags, kind mismatch,
digest-domain substitution, an active result whose `current_resource` state is
released (the separately named source must have the exact transfer successor), double release,
release before terminality, under-reserved worst-case bytes, and overflow. The
dependency order is fixed: requirement/allocation/resource-persistence receipt/
semantic terminal,
commitments, after snapshot, target `Reserved`, retention active/terminal,
source `Released`, transition, new head, canonical post-CAS receipt, then its
atomic destination batch. Snapshot roots cannot contain a
state/terminal/transition/head; commitments contain no snapshot/head/state/
result/record digest; transitions contain no resulting head. A post-CAS receipt
contains the canonical source/target state projections and the transition/head/
snapshot digests but no state, basis, transition, head or snapshot body; none of
those pre-receipt bodies contains a receipt/refinement digest. The durable slot
candidate set may contain their complete bounded bodies but contains no receipt.
This one-way edge is the no-cycle rule. Allocation identity
contains no journal record/root digest. The two typed head-store slots
(Genesis/EmptyTarget or full committed images with bounded candidate sets),
whose selected full image is the sole current head/snapshot, the two complete
global joint-WAL slots including body, Prepare and final-decision
`max(Aborted, Committed)` regions, two
maximum-size post-CAS sidecar store slots (each able to hold a complete operation replay,
generic-release capsule, owner-epoch expiry proof, or closed body), two complete
publication-batch marker store slots, and the two-slot scalar
operation-replay watermark store use exactly
`manifest.ledger_recovery_budget.max_total_accounted_bytes`
derived from both checked maxima: `max_active_capacity_reservations + 1` for a
head candidate state set and `max_active_capacity_reservations + 2` for a
receipt destination batch (all state destinations plus the one journal
publication destination). The canonical maximum encoding of each containing
EmptyTarget/Occupied store-slot envelope, including the largest marker's full
staged-root/public-indirection/certificate set and the largest Open sidecar that
embeds it, is charged rather than the smaller inner vector alone.

The manifest's additional
`replay_epoch_recovery_budget.max_total_accounted_bytes` simultaneously covers
the two complete COW containing-slot envelopes for the singleton pending-
admission, owner-epoch state, unsigned event store, transport-registry closure
head and channel-key-store closure head. It contains no WAL term; the same one
global WAL above commits these replay stores as participants. The
owner-state slot maximum
includes the complete largest signed-observation census/terminal, so no hidden
attestation store exists. At most one operation epoch is resident: before head
publication it may have `Accepted` plus that same epoch's Open owner/event
state; after Open publication admission is Idle and the same epoch alone may be
Open or Closing; after committed closure the successor watermark permits its
collection; after pre-CAS retirement the advanced admission tombstone permits
its collection. Recovery validates both budgets before any body allocation and
refuses the operation on checked overflow or insufficient reserved bytes. No
third slot, second resident epoch, unbounded prefix/history, or storage charged
outside these two equations has a V1 encoding. Charging ordinary subject
objects to either fixed budget is forbidden recursive accounting. Any historical snapshot/transition/head needed
by a long-lived `Reserved`, `Released`, outer envelope, or published reference
is copied into a typed `Arch004CapacityStateBasisBundleV1` or
`Arch004ResourcePublicationProofBundleV1`. A state-basis member root covers the
complete old head and before/after snapshot bodies plus their byte-equal digests;
its owner subject equals the commitment subject and its digest equals the field
inside that state, but it proves only pre-CAS arithmetic and is never sufficient
without that state's post-CAS receipt ref. A resource-publication proof root
covers the complete canonical publishing receipt/ref, current Active, envelope,
transition, resulting head/snapshot and every named state with its matching
basis bundle and selecting `StateResolution` ref. Missing, extra, digest-
mismatched, wrong-selection or cross-subject members invalidate the bundle. Its exact worst-case bytes are
included in that subject's UDP/DNS metadata, dynamic-object, retained-metadata,
or resource-journal charge and remain reachable only as long as the referencing
object. Transfer includes every still-reachable predecessor proof in the target
requirement; terminal unreachability permits garbage collection.
Thus fixed current-ledger storage does not prune a resolving digest, while
unbounded historical ledger storage has no encoding.

Windows DNS mutation is legal only for the OS-observed `InterfaceGuid` and the
same exact exclusively FlowProbe-owned adapter/object proof. `IfIndex` and a
requested GUID are locators/inputs and never stable identity or rollback
authority. The V1 image normalizes every field selected by the closed mask;
`derived_flags` is the unique projection of family plus that mask, and unknown
version/flag bits reject the node. Apply and compensation compare the same GUID,
owner closure, and full managed image. Foreign after-image drift is preserved
as `ExternalDriftPreserved`, never overwritten.

A systemd-resolved node owns exactly one displayed field. Every operation
rediscovers the link by network namespace, installation/generation
`IFLA_IFALIAS` marker, and device kind, then proves the complete link is
exclusively FlowProbe-owned. Ifindex and D-Bus object path are live locators
only. Apply/compensation calls only the corresponding typed per-link setter and
reads back that field; whole-link `RevertLink` is forbidden. Selecting resolved
and NetworkManager for the same host/session or overlapping conflict keys
rejects before seal.

NetworkManager apply first obtains the exact applied connection, requires UUID,
stable device, nonzero version, and complete-settings digest, copies the OS-
returned complete settings, changes only `NetworkManagerDnsProjectionV1`, and
calls `Reapply(..., before_version_id, 0)`. The result records the new nonzero
version, full digest, and projection. Compensation requires current version and
full image to equal the applied result, then reapplies the current complete
settings with only the before DNS projection using the after version and flags
zero. Version race, manager restart, UUID/device mismatch, or foreign setting
change preserves current state and enters `RecoveryRequired`; the persistent
settings profile is never edited by this backend.

There is deliberately no macOS/Darwin mutating route or intercept backend.
`SCPreferencesLock`, `SCPreferencesGetSignature`, commit/apply, and later
read-back are neither a mutation-consumed CAS token nor proof of atomic active-
state application/restoration. Current macOS preflight therefore returns
`Unsupported/MacOsConditionalDnsMutationUnavailable` before creating a node or
performing any mutation. A future tagged backend requires a separate
architecture change; an opaque token field cannot enable it.

`DnsInterceptBackendV1` registers only the protected runtime port-53 rule. Its
exact owned runtime instance, config, rule, families, UDP/TCP scope, handler,
exclusion root, and authenticated rule/handler read-back must all succeed.
Config text or runtime startup alone is not `Applied` or `Port53Hijacked`.
Windows WFP, Linux netfilter/nftables, and macOS System Configuration intercept
operations are unregistered and return their closed preflight `Unsupported`
reason with zero mutation; no generic native backend can encode them.

Each plan node MUST define:

- schema and backend version;
- stable identity or deterministic discovery recipe;
- installation/generation owner marker;
- complete normalized before image and intended postcondition;
- exact managed and passthrough fields;
- typed executor and dependencies;
- idempotency key and observable success predicate;
- finite deadline and typed result;
- observed after image and provenance; and
- conditional compensation or exclusive-owned deletion proof.

`dns.route.v1` may configure a protected runtime resolver without OS mutation.
If it mutates system resolver state, only the helper executes the registered
platform operation. `dns.intercept.v1` is present only for an accepted port-53
steering mechanism. `dns.observer.v1` is an unprivileged process node whose
exact runtime instance, decoder build, bounds, and no-ambient-network policy are
sealed.

Shared resolver settings with no atomic conditional update, accepted revision
token, or exact exclusive ownership are unsupported. FlowProbe MUST NOT restore
a stale whole-system DNS baseline over DHCP, VPN, administrator, or resolver-
manager changes.

## 17. Activation, health, stop, and recovery

The ARCH-001 graph order is:

1. discover baseline resolver, route, interface, and ordinary-connectivity
   state;
2. resolve capability cells and the exact UDP/DNS policy;
3. compile only pinned protected runtime options;
4. seal all UDP/DNS actors, resources, bounds, and ARCH-002 exclusion entries;
5. start unprivileged actors inert through the ARCH-001 gate;
6. install/read back preventive exclusion and socket-factory policy;
7. apply accepted system DNS/intercept resources transactionally;
8. open the first-packet resume barrier only after all mandatory predicates;
9. prove selected UDP pass-through and each claimed DNS matrix cell; and
10. commit `Active` only after durable results and baseline-relative health.

The mandatory health predicate includes:

- current UDP path and upstream disposition;
- current DNS routing/interception/decoding/leak-prevention claims;
- complete ARCH-002 actor, socket, and exclusion evidence;
- resolver/relay/interface/default-route epoch equality;
- decoder/resource-limit health;
- no policy-incompatible DNS/UDP direct path; and
- ARCH-001 ordinary connectivity.

Stop preserves required data-plane actors until DNS steering, routes/rules, TUN,
and other consumers no longer depend on them, then closes the barrier and actors
in reverse dependency order. Crash, lease loss, association loss, exclusion
loss, resolver drift, or ambiguous ownership fences the path and uses the same
ARCH-001 rollback. A later recovery never restarts or silently edits the old
plan.

## 18. Capability and support

Every UDP capability binds:

```text
UdpCapableEgressV1 =
  | Direct
  | ExternalSocks5RequireAssociate

Arch004UdpPathKindV1 =
  | RuntimeDestinationUdp
  | Socks5UdpRelay

UdpSupportDimensionV1 =
  | OriginalDestination
  | ProcessProvenance
  | FragmentObservation
  | SocketAdmission
  | LoopExclusion

UdpSupportClaimV1 =
  | Proven {
      dimension: UdpSupportDimensionV1,
      evidence_refs:
        SortedUniqueNonEmptyVector<EvidenceRefV1, 1..=16>,
      reason: ExactUdpNoBlockingReason,
    }
  | NotProven {
      dimension: UdpSupportDimensionV1,
      disposition: ClaimNotProvenDispositionV1,
      evidence_refs: SortedUniqueVector<EvidenceRefV1, 0..=16>,
      reason: UdpBlockingReasonV1,
    }

UdpCapabilitySupportClaimsV1 = {
  original_destination:
    UdpSupportClaimV1 { dimension: OriginalDestination },
  process_provenance:
    UdpSupportClaimV1 { dimension: ProcessProvenance },
  fragment_observation:
    UdpSupportClaimV1 { dimension: FragmentObservation },
  socket_admission:
    UdpSupportClaimV1 { dimension: SocketAdmission },
  loop_exclusion:
    UdpSupportClaimV1 { dimension: LoopExclusion },
}

UdpImplementationBuildsV1 = {
  capture_core_build: BoundedBuildIdentity,
  runtime_adapter_build: BoundedBuildIdentity,
  socket_factory_build: BoundedBuildIdentity,
  privileged_helper_build?: BoundedBuildIdentity,
}

UdpCapabilityResourceEvidenceV1 =
  | Ready {
      udp_path_resource_identity: UdpPathResourceIdentityV1,
      udp_path_binding_digest: Digest(Arch004UdpPathBindingV1),
      udp_path_active_state: Arch004ActiveResourceEvidenceV1,
      udp_admission_active_state: Arch004ActiveResourceEvidenceV1,
    }
  | Unavailable {
      reason: UdpBlockingReasonV1,
      preflight_evidence_refs:
        SortedUniqueNonEmptyVector<EvidenceRefV1, 1..=8>,
    }

UdpCapabilityV1 = {
  platform_subject: Arch004PlatformSubjectV1,
  network_scope: NetworkScope,
  selected_egress: UdpCapableEgressV1,
  egress_selection_safe_digest: Digest(SafeEgressSelectionV1),
  family: AddressFamilyV1,
  path_kind: Arch004UdpPathKindV1,
  resource_evidence: UdpCapabilityResourceEvidenceV1,
  support: UdpCapabilitySupportClaimsV1,
  static_support: StaticSupport,
  readiness: Readiness,
  evidence: Evidence,
  implementation_builds: UdpImplementationBuildsV1,
  exact_limit_set_digest: Digest(UdpDnsLimitSetV1),
  limit_outcome_policy_digest: Digest(Arch004LimitOutcomePolicyV1),
  evidence_refs: SortedUniqueNonEmptyVector<EvidenceRefV1, 1..=16>,
  expires_at: SuspendAwareDeadline,
  reason: UdpCapabilityReasonV1,
}
```

ADR-0004 dimensions are mandatory. `Supported` release activation requires
`SupportedByDesign`, `Ready`, and `RealHostVerified` for the exact packaged
matrix. Fake tests and source inspection are not real-host evidence.

The egress/path pairing is closed: `Direct` iff
`RuntimeDestinationUdp`, and `ExternalSocks5RequireAssociate` iff
`Socks5UdpRelay`. `resource_evidence=Ready` is legal only with
`SupportedByDesign + Ready` and path/admission active states that resolve to those
exact resource kinds, identities, platform subject, and byte-equal lease
projection; the path binding, child/association, egress digest, family, and
capability all agree. A non-ready/static-unsupported capability uses
`Unavailable`, carries no fabricated path identity/binding/result, and cites
only current preflight evidence.
Each support claim's dimension tag matches its field, and every `Proven` claim
has its own nonempty typed evidence rather than borrowing the record-level
vector.

`UdpCapabilityV1.reason=NoBlockingReason` is legal only when path/resource
evidence is `Ready`, all five support claims are `Proven`, the requested
static/readiness/evidence tuple is satisfied, and every reference is current.
Otherwise the capability uses `Blocking(UdpBlockingReasonV1)` with the first
applicable reason in displayed order. Support `NotProven` and resource
`Unavailable` accept only `UdpBlockingReasonV1`; a ready path cannot carry a
blocking resource reason. Contradictory dimension/reason pairs are invalid.

At acceptance time no Windows, macOS, or Linux full-tunnel matrix is supported:
ADR-0004's independent runtime attachment/resume-gate blockers and ADR-0005's
complete exclusion/admission blockers remain. This contract MUST NOT convert
its design into a support claim.

## 19. Pinned sing-box 1.13.19 mapping

The only runtime source baseline is sing-box 1.13.19 revision
`b5ebaa1fc0f2b94256180b95468e73ef53caa27d`.

The exact source defines:

- DNS transport tags `udp`, `tcp`, `tls`, `https`, `quic`, and `h3` in
  `constant/dns.go` and their option variants in `option/dns.go`;
- UDP/TCP/TLS/HTTPS/QUIC DNS transport implementations under `dns/transport`;
- HTTP/3 transport implementation in `dns/transport/quic/http3.go`;
- `include/quic.go`, whose `with_quic` build constraint registers both QUIC and
  HTTP/3 transports, and `include/quic_stub.go`, whose inverse constraint
  registers the same schema tags but returns `ErrQUICNotIncluded`;
- the route action tag `hijack-dns` in `option/rule_action.go`;
- packet and stream DNS query classification in `common/sniff/dns.go`; and
- the TUN `udp_timeout` option in `option/tun.go`.

The protected compiler may emit one of those fields only when the exact pinned
option schema accepts it and the versioned adapter implements this contract's
required evidence. Unknown fields and fields first documented after the pin are
rejected. Rolling documentation is discovery material, not capability evidence.
The capability record binds the exact build tags. Schema acceptance of `quic`
or `h3` without `with_quic`, including registration through the stub, is an
explicit `Unsupported/PinnedQuicBuildTagUnavailable` result rather than runtime
readiness.

The pinned `h3` tag maps to the `Https` semantic cell with `Http3`; the pinned
`quic` tag maps to the DoQ `Quic` cell. They are not interchangeable merely
because both use QUIC.

The pinned query sniffer sets a DNS protocol classification after a bounded
query parse; it does not emit response correlation, names/types/classes/rcode,
privacy state, or this contract's evidence. Pinned DNS transport code can open
network paths but does not prove FlowProbe exclusion completeness, original
destination, policy-safe fallback, transaction rollback, or platform support.

At this revision, `dns/transport/https.go` and
`dns/transport/quic/http3.go` allocate a response buffer directly from a
positive HTTP `Content-Length` and otherwise use unbounded `io.ReadAll`; neither
enforces this contract's `max_dns_message_bytes` before allocation/read. The
native pinned `https` and `h3` implementations therefore remain
`UnsupportedPendingArchitecture/PinnedDnsResponseBoundUnavailable` for a
positive FlowProbe capability. They may become eligible only after a versioned
bounded wrapper is accepted and packaged or after a separately audited pin
change. Config validation, a small successful response, or `with_quic` does not
remove this blocker.

Consequently none of these is sufficient by itself:

- accepting a JSON config;
- `hijack-dns` or `udp_timeout` being present;
- the runtime process being healthy;
- DNS transport source existing; or
- an upstream sing-box unit test passing.

The Config Compiler binds the runtime version, revision, binary digest,
protected config digest, and adapter build. A mismatch is
`BackendVersionMismatch`/`PinnedRuntimeMismatch` before mutation.

## 20. Additive normalized-flow extension

The host registers two new tagged extension payloads:

```text
Arch004RecordStorageLocatorV1 =
  | LiveAppendOnlyRecordStream {
      stream_id: Bytes32,
      record_ordinal: MonotonicSequence,
    }
  | PersistedMetadataPartition {
      store_instance_id: Bytes32,
      partition_id: Bytes32,
      record_key: Bytes32,
    }

Arch004RecordRefV1 =
  | DatagramFlowRecord {
      flow_id: DatagramFlowId,
      revision: U64,
      record_digest: Digest(DatagramFlowV1),
      storage_locator: Arch004RecordStorageLocatorV1,
    }
  | DnsTransactionRecord {
      transaction_id: DnsTransactionId,
      revision: U64,
      record_digest: Digest(DnsTransactionV1),
      storage_locator: Arch004RecordStorageLocatorV1,
    }

NormalizedFlowExtensionV1 =
  | FlowProbeDatagramV1 {
      datagram_record_digest: Digest(DatagramFlowV1),
      datagram_record_ref: Arch004RecordRefV1::DatagramFlowRecord,
    }
  | FlowProbeDnsTransactionV1 {
      dns_transaction_digest: Digest(DnsTransactionV1),
      dns_transaction_ref: Arch004RecordRefV1::DnsTransactionRecord,
    }
```

They extend, and do not edit, the accepted `Normalized Flow v0` contract.
The two extension bodies contain only an exact typed digest and its resolving
registered record reference. They have no `flow_id`, `connection_id`,
`capture_session_id`, transport, destination, process, or host timing member.
The exact named source record supplies the additional UDP/DNS data, while the
enclosing `NormalizedFlow` supplies those common fields. The reference's typed
digest and resolved canonical body must match; a dangling or wrong-type
reference is invalid.

`Arch004RecordRefV1` is a one-way high-level record locator, separate from leaf
`EvidenceRefV1`. Its variant, identity, revision, digest, and resolved canonical
body must agree. The referenced record and storage-locator body MUST NOT contain
the enclosing normalized extension digest or a descendant reference, so the
locator cannot form a digest cycle. A filesystem path, SQL statement, database
rowid without partition identity, opaque producer handle, or dangling locator
is invalid.

For a datagram extension, `DatagramFlowV1.identity.flow_id` is byte-for-byte the
enclosing host `flow_id`, not a second allocated ID. Capture-session ID,
transport=`UDP`, destination metadata, process attribution/provenance,
`started_at`/first-byte observation, optional terminal `ended_at`, and any host
connection/observation epoch are the exact registered projections from the
same datagram record and must equal the enclosing values. For a UDP DNS
extension, `DnsHostAssociationV1::UdpDatagramFlow.flow_id` is that same
enclosing host flow ID. TCP, DoT, DoH, and DoQ instead bind the enclosing
registered host connection or HTTP/QUIC transaction through their exact closed
host-association variant and discriminator. A missing
projection rule or any mismatch makes the extension invalid; neither side wins
by last-write or consumer preference.

A native-runtime DNS request that has no independently registered enclosing host
flow/connection is still a valid standalone DNS transaction record but MUST NOT
be attached as a `NormalizedFlowExtensionV1`. Resolver-token possession does
not invent a host flow.

An extension reference may advance only from a valid current record to its
exact successor. Storage compares revision and predecessor digest atomically;
an ancestor, fork, or post-terminal reference cannot replace the current
extension.

Existing identity/timing/transport fields remain authoritative at their layer.
The extension carries only additional optional metadata and uses a versioned
tag. Unknown tags are not reinterpreted as opaque DNS; consumers either preserve
them according to their host contract or return typed unsupported.

A DNS extension never changes raw data or analyzer-derived data into the source
of truth.

## 21. Error model

```text
WindowsInterfaceGuid = Bytes16
NetworkManagerConnectionUuid = Bytes16

WindowsOwnedAdapterIdentityV1 = {
  interface_guid: WindowsInterfaceGuid,
  device_instance_identity_digest: Digest,
  owner_marker: OwnerMarker,
  adapter_kind: ExactFlowProbeOwnedTunnelAdapter,
}

LinuxNetworkNamespaceIdentityV1 = {
  boot_epoch: BootEpoch,
  namespace_handle_identity_digest: Digest,
}

ExactSupportedLinkKind = Tun

LinuxStableDeviceIdentityV1 = {
  network_namespace_identity_digest:
    Digest(LinuxNetworkNamespaceIdentityV1),
  installation_generation_ifalias_owner_marker: OwnerMarker,
  device_kind: ExactSupportedLinkKind,
}

BoundedDnsSuffix = {
  canonical_wire_name: BoundedDnsName,
  terminal_root_present: true,
}

BoundedDnsOptionV1 =
  | SingleRequest
  | SingleRequestReopen
  | Rotate
  | UseVc
  | TrustAd
  | TimeoutSeconds(Integer<1..=30>)
  | Attempts(Integer<1..=10>)

ClosedOperatingSystemV1 = Windows | Linux | MacOs
ClosedArchitectureV1 = X86_64 | Aarch64

BoundedReleaseIdentity = {
  product_name: BoundedAscii,
  exact_version: BoundedVersion,
  exact_build?: BoundedAscii,
  kernel_or_os_build: BoundedAscii,
}

ClosedOriginalDestinationMechanism =
  | TunAuthenticatedMetadata
  | RuntimeAuthenticatedMetadata
  | PlatformOriginalDestinationApi

ClosedConfidence = Arch004ConfidenceV1

ClosedCounterObservationSource =
  | CaptureCoreDatagramBoundary
  | NetworkRuntimeDatagramBoundary
  | ActorSocketFactoryBoundary

ClosedPlatformProcessIdentity =
  | Windows {
      process_object_boot_identity: Bytes32,
      executable_file_identity_digest: Digest,
      service_or_user_sid_digest: Digest,
    }
  | Linux {
      pid_namespace_identity_digest: Digest,
      process_start_identity: Bytes32,
      executable_file_identity_digest: Digest,
      uid: U32,
    }
  | MacOs {
      audit_token_digest: Digest,
      process_start_identity: Bytes32,
      code_identity_digest: Digest,
    }

ClosedProcessObservationMechanism =
  | ExactSocketOwnerAtBoundary
  | ExactActorOwnedSocketChild
  | AuthenticatedRuntimeProcessMetadata

UdpUnavailableReasonV1 =
  | PlatformFactUnavailable
  | PermissionUnavailable
  | OriginalDestinationUnavailable
  | ProcessIdentityUnavailable
  | DirectionUnavailable
  | CounterBoundaryUnavailable
  | InterfaceScopeUnavailable
  | ObservationExpired
  | ObservationLost

UdpOpaqueReasonV1 =
  | MetadataOnlyPolicy
  | FragmentedDatagram
  | UnsupportedPayloadDecoder
  | ResourceLimit
  | EncryptedOrUnknownApplicationPayload

ClosedFragmentReasonV1 =
  | RawIpFragmentWithoutCompleteUdpDatagram
  | FragmentMetadataIncomplete
  | JumbogramUnsupported

ClosedDnsDecodeOpaqueReasonV1 =
  | BoundedDecoderResultUnavailable

ClosedDnsMalformedReasonV1 =
  | AuthenticatedParserRejectedInput

ClosedUnmatchedResponseReasonV1 =
  | NoMatchingPendingQuery

ClosedSystemResolverBackend =
  | WindowsInterfaceDnsSettingsV1
  | LinuxSystemdResolvedOwnedLinkFieldV1
  | LinuxNetworkManagerAppliedConnectionV1

BoundedResolverScope =
  | WindowsInterface { interface_guid: WindowsInterfaceGuid }
  | LinuxOwnedLink {
      network_namespace_identity_digest: Digest,
      owner_marker: OwnerMarker,
      device_kind: ExactSupportedLinkKind,
    }
  | LinuxNetworkManagerConnection {
      connection_uuid: NetworkManagerConnectionUuid,
      device_stable_identity_digest: Digest,
    }

DnsCapabilityResolverScopeV1 =
  | PlannedResolverDependency {
      resolver_dependency_descriptor_digest:
        Digest(ResolverDependencyDescriptorV1),
      resolver_path_id: ResolverDependencyDescriptorV1.resolver_path_id,
      use_site: Arch004ResolverUseSiteV1,
    }
  | ExactNativeResolverScope(BoundedResolverScope)
  | NoResolverScope

ResolverOpaqueReasonV1 = ResolverIdentityNotObservable

ResolverUnavailableReasonV1 =
  | BindingSetUnavailable
  | BindingSetObservationExpired
  | BootstrapUnavailable
  | NativeScopeUnavailable
  | BackendUnsupported

DnsBlockingReasonV1 =
  | InheritedArch001Blocker {
      inherited_disposition: ClaimNotProvenDispositionV1,
    }
  | InheritedArch002Blocker {
      inherited_disposition: ClaimNotProvenDispositionV1,
    }
  | RuntimeAttachmentMissing
  | ResumeGateMissing
  | LoopExclusionIncomplete
  | SocketAdmissionUnavailable
  | UseSiteFamilyPolicyUnavailable
  | RealHostUnverified
  | PinnedRuntimeMismatch
  | PinnedQuicBuildTagUnavailable
  | PinnedDnsResponseBoundUnavailable
  | WindowsDnsInterfaceNotExclusivelyOwned
  | LinuxReleaseTupleUnselected
  | LinuxResolverManagerUnknownOrMixed
  | LinuxResolvedLinkNotExclusivelyOwned
  | NetworkManagerCasUnavailable
  | MacOsConditionalDnsMutationUnavailable
  | MacOsActiveApplyCompletionUnproven
  | WindowsNativeInterceptBackendUnregistered
  | LinuxNativeInterceptBackendUnregistered
  | MacOsNativeInterceptBackendUnregistered
  | CapabilityEvidenceExpired
  | OriginalDestinationUnavailable
  | ProcessProvenanceUnavailable
  | ResolverBindingSetUnavailable
  | ResolverBootstrapUnavailable
  | ResolverNativeScopeUnavailable
  | ResolverBackendUnsupported
  | MechanismDoesNotProveRouting
  | MechanismDoesNotProveInterception
  | MechanismDoesNotProveDecoding
  | MechanismDoesNotProveLeakPrevention
  | DecoderUnavailable

DnsCapabilityReasonV1 =
  | NoBlockingReason
  | Blocking(DnsBlockingReasonV1)

ExactNoBlockingReason = DnsCapabilityReasonV1::NoBlockingReason

UdpBlockingReasonV1 =
  | InheritedArch001Blocker {
      inherited_disposition: ClaimNotProvenDispositionV1,
    }
  | InheritedArch002Blocker {
      inherited_disposition: ClaimNotProvenDispositionV1,
    }
  | RuntimeAttachmentMissing
  | ResumeGateMissing
  | RuntimeDestinationUdpBindingUnavailable
  | LoopExclusionIncomplete
  | SocketAdmissionUnavailable
  | OriginalDestinationUnavailable
  | ProcessProvenanceUnavailable
  | Socks5AssociationUnavailable
  | PlatformPathUnverified
  | RealHostUnverified
  | CapabilityEvidenceExpired

UdpCapabilityReasonV1 =
  | NoBlockingReason
  | Blocking(UdpBlockingReasonV1)

ExactUdpNoBlockingReason = UdpCapabilityReasonV1::NoBlockingReason

The claim-reason mapping is exact. A DNS `NotProven` claim accepts a reason
only in the following row and fixes its disposition as shown:

| DNS reason group | Allowed claim kind | Required disposition |
| --- | --- | --- |
| `InheritedArch001Blocker`, `InheritedArch002Blocker` | Routing, Interception, Decoding, LeakPrevention | exact embedded inherited disposition |
| `RuntimeAttachmentMissing`, `ResumeGateMissing`, `CapabilityEvidenceExpired` | Routing, Interception, Decoding, LeakPrevention | `TemporarilyUnavailable` |
| `LoopExclusionIncomplete` | Routing, Interception, LeakPrevention | `PolicyProhibited` |
| `SocketAdmissionUnavailable` | Routing, Interception, Decoding, LeakPrevention | `TemporarilyUnavailable` |
| `RealHostUnverified` | Routing, Interception, Decoding, LeakPrevention | `Degraded` |
| `PinnedRuntimeMismatch` | Routing, Interception, Decoding, LeakPrevention | `Unsupported` |
| `PinnedQuicBuildTagUnavailable`, `PinnedDnsResponseBoundUnavailable`, `DecoderUnavailable` | Decoding | `Unsupported` |
| `WindowsDnsInterfaceNotExclusivelyOwned` | Routing, LeakPrevention | `PolicyProhibited` |
| `LinuxReleaseTupleUnselected`, `LinuxResolverManagerUnknownOrMixed`, `NetworkManagerCasUnavailable` | Routing, LeakPrevention | `Unsupported` |
| `LinuxResolvedLinkNotExclusivelyOwned` | Routing, LeakPrevention | `PolicyProhibited` |
| `MacOsConditionalDnsMutationUnavailable`, `MacOsActiveApplyCompletionUnproven` | Routing, LeakPrevention | `Unsupported` |
| `WindowsNativeInterceptBackendUnregistered`, `LinuxNativeInterceptBackendUnregistered`, `MacOsNativeInterceptBackendUnregistered` | Interception, LeakPrevention | `Unsupported` |
| `ResolverBindingSetUnavailable`, `ResolverBootstrapUnavailable` | Routing, LeakPrevention | `TemporarilyUnavailable` |
| `ResolverNativeScopeUnavailable`, `ResolverBackendUnsupported` | Routing, LeakPrevention | `Unsupported` |
| `MechanismDoesNotProveRouting` | Routing | `Unsupported` |
| `MechanismDoesNotProveInterception` | Interception | `Unsupported` |
| `MechanismDoesNotProveDecoding` | Decoding | `Unsupported` |
| `MechanismDoesNotProveLeakPrevention` | LeakPrevention | `Unsupported` |

The two ancillary capability claims use narrower reason types. Their mapping is
also total and exact:

| Ancillary claim | Allowed reason | Required disposition |
| --- | --- | --- |
| original destination | `OriginalDestinationUnavailable` | `Unsupported` |
| original destination | `CapabilityEvidenceExpired` | `TemporarilyUnavailable` |
| original destination | `RealHostUnverified` | `Degraded` |
| process provenance | `ProcessProvenanceUnavailable` | `Unsupported` |
| process provenance | `CapabilityEvidenceExpired` | `TemporarilyUnavailable` |
| process provenance | `RealHostUnverified` | `Degraded` |

Each ancillary `NotProven` outcome carries exactly one complete signed local
tag-`0x4005` observation, never a broad tag-2/tag-53 capability root. Its
`cell_spec_digest`, `scope`, `platform_subject`, and
`observation_context_digest` resolve the enclosing matrix cell and its exact
`CapabilityEvaluation` context byte-for-byte; `evaluated_at` is inside that
context's observation window and is the matrix evaluation time. The outcome
variant selects the same-dimension reason tag exactly. An expired reason carries
the complete nonempty prior positive evidence vector, the exact prior evidence
deadline, and requires `evaluated_at > expired_at`; non-expiry reasons carry no
prior vector or deadline. The tag-`0x4005` authenticator and digest validate the
formula above. Another cell, planned-resolver scope, platform, dimension,
reason, deadline, evaluator, or unsigned/digest-only negative result is invalid.

When an ancillary claim is the first failed cell condition, the cell-level
`Blocking` reason is the byte-identical same-named `DnsBlockingReasonV1`
variant. The typed outcome also fixes the exact witness shape described above.
`OriginalDestinationUnavailable`
cannot block process provenance or any standard claim kind, and
`ProcessProvenanceUnavailable` cannot block original destination or any
standard claim kind. A broad decoder, runtime, intercept, or resolver blocker
cannot be stored in either ancillary claim merely because the whole cell is
blocked.

A UDP `NotProven` claim accepts only:

| UDP reason group | Allowed support dimension | Required disposition |
| --- | --- | --- |
| `InheritedArch001Blocker`, `InheritedArch002Blocker` | all five dimensions | exact embedded inherited disposition |
| `RuntimeAttachmentMissing`, `CapabilityEvidenceExpired` | all five dimensions | `TemporarilyUnavailable` |
| `ResumeGateMissing` | SocketAdmission, LoopExclusion | `TemporarilyUnavailable` |
| `RuntimeDestinationUdpBindingUnavailable` | SocketAdmission, LoopExclusion | `TemporarilyUnavailable` |
| `LoopExclusionIncomplete` | LoopExclusion | `PolicyProhibited` |
| `SocketAdmissionUnavailable` | SocketAdmission | `TemporarilyUnavailable` |
| `OriginalDestinationUnavailable` | OriginalDestination | `Unsupported` |
| `ProcessProvenanceUnavailable` | ProcessProvenance | `Unsupported` |
| `Socks5AssociationUnavailable` | SocketAdmission, LoopExclusion | `TemporarilyUnavailable` |
| `PlatformPathUnverified` | FragmentObservation, SocketAdmission, LoopExclusion | `Unsupported` |
| `RealHostUnverified` | all five dimensions | `Degraded` |

There is no fallback row. A reason outside the named kind/dimension, a
different disposition, a `Blocking` reason on `Proven`, or `NoBlockingReason`
on `NotProven` is structurally invalid. Cell-level blocking reason selection
for DNS uses the explicit claim/condition order stated above, not enum
declaration order. UDP aggregate selection uses the displayed support-dimension
order `OriginalDestination, ProcessProvenance, FragmentObservation,
SocketAdmission, LoopExclusion`, followed by resource/freshness conditions.
Both algorithms apply only after this mapping is satisfied.

Arch004ResourceFailureReasonV1 =
  | BackendVersionMismatch
  | IdentityMismatch
  | OwnerProofUnavailable
  | ConditionMismatch
  | ExternalDrift
  | ConflictKeyOverlap
  | CapacityReservationFailed
  | DeadlineExceeded
  | ReadbackMismatch
  | RuntimeInstanceLost
  | AmbiguousExternalResult
  | RecoveryEvidenceUnavailable

Arch004ResourceDiffCodeV1 =
  | ManagedFieldChanged
  | PassthroughFieldChanged
  | OwnerChanged
  | VersionChanged
  | DependentClosureChanged
  | RuntimeInstanceChanged
  | ResourceMissing
  | UnexpectedResourcePresent

ClosedDynamicCapacityTerminalReasonV1 =
  | NormalClose
  | Timeout
  | Cancelled
  | ResourceLimit
  | SessionStopping
  | SessionRollback
  | PolicyBlocked
  | ObservationLost

Arch004ErrorOperationV1 =
  | Prepare
  | Reserve
  | Release
  | Transfer
  | JournalAppend
  | Apply
  | Observe
  | Decode
  | Forward
  | Renew
  | Compensate
  | Recover

Arch004SafePhaseV1 =
  | Preflight
  | Prepared
  | Applying
  | AppliedUncommitted
  | Active
  | Stopping
  | Recovering
  | Inactive

Arch004RetryabilityV1 = Never | ExactIdempotentReplay | AfterExternalChange

ExactAppliedDurable = Arch004ApplyDurablePhaseV1::AppliedDurable
ExactNoExternalEffectDurable =
  Arch004ApplyDurablePhaseV1::NoExternalEffectDurable
ExactRecoveryRequiredDurable =
  Arch004ApplyDurablePhaseV1::RecoveryRequiredDurable
ExactCompensatedDurable =
  Arch004CompensationDurablePhaseV1::CompensatedDurable
ExactAlreadyCompensatedDurable =
  Arch004CompensationDurablePhaseV1::AlreadyCompensatedDurable
ExactExternalDriftPreservedDurable =
  Arch004CompensationDurablePhaseV1::ExternalDriftPreservedDurable

UdpErrorCodeV1 =
  | UdpUnsupported
  | UdpPolicyProhibited
  | UdpPermissionRequired
  | UdpTemporarilyUnavailable
  | DirectUdpPathUnproven
  | HttpProxyUdpUnsupported
  | HttpsProxyUdpUnsupported
  | Socks5UdpDisabled
  | Socks5AssociationUnavailable
  | Socks5RelayLost
  | DirectFallbackAuthorizationInvalid
  | OriginalDestinationUnavailable
  | ProcessProvenanceUnavailable
  | DatagramAdmissionDenied
  | DatagramResourceLimit
  | FragmentationOpaque
  | PathInvalidated
  | LoopExclusionIncomplete
  | SocketAdmissionUnavailable
  | DatagramRevisionInvalid
  | DatagramCounterBoundaryInvalid
  | PinnedRuntimeMismatch

DnsErrorCodeV1 =
  | DnsUnsupported
  | DnsPolicyProhibited
  | DnsPermissionRequired
  | DnsTemporarilyUnavailable
  | DnsRoutingUnproven
  | DnsInterceptionUnproven
  | DnsDecodeUnavailable
  | DnsLeakPreventionUnproven
  | DnsBootstrapCycle
  | DnsResolverIdentityUnavailable
  | DnsMalformed
  | DnsCorrelationLimit
  | DnsTransactionRevisionInvalid
  | DnsLineageInvalid
  | DnsQueryTimedOut
  | DnsResponseUnmatched
  | DnsPrivacyPolicyInvalid
  | DnsExactNameAuthorizationInvalid
  | DnsResolverPathBindingInvalid
  | DnsResourceLimit
  | PinnedQuicBuildTagUnavailable
  | PinnedDnsResponseBoundUnavailable
  | DnsBackendVersionMismatch

Arch004CapacityErrorCodeV1 =
  | LedgerHeadMismatch
  | LedgerSnapshotRootMismatch
  | ReservationCommitmentMismatch
  | ReservationSubjectMismatch
  | CapacityRequirementMismatch
  | TerminalReleaseCauseInvalid
  | ReservationAlreadyReleased
  | LedgerOperationReplayRetired
  | LedgerOperationReplayConflict
  | LedgerReplaySequenceInvalid
  | CapacityCounterOverflow
  | PartialChargeVectorRejected
  | TransferAtomicityInvalid
  | JournalRetentionTerminalInvalid
  | JournalAppendRevisionInvalid
  | JournalAllocationExhausted
  | JournalReceiptActiveMismatch
  | JournalPublicationEnvelopeMismatch
  | ResourceJournalCompactionUnsupported

Arch004ErrorCodeV1 =
  | Udp(UdpErrorCodeV1)
  | Dns(DnsErrorCodeV1)
  | Resource(Arch004ResourceFailureReasonV1)
  | Capacity(Arch004CapacityErrorCodeV1)

Arch004ErrorV1 = {
  operation: Arch004ErrorOperationV1,
  safe_phase: Arch004SafePhaseV1,
  resource_kind?: Arch004ResourceKindV1,
  resource_identity?: Arch004ResourceIdentityV1,
  capacity_subject?: Arch004CapacitySubjectV1,
  family?: AddressFamilyV1,
  transport?: DnsTransportV1 | ExactUdp,
  retryability: Arch004RetryabilityV1,
  code: Arch004ErrorCodeV1,
}
```

Every error is exactly `Arch004ErrorV1`. `Udp` and `Dns` omit both identity and
capacity subject. `Resource(code)` requires `resource_identity` and
`resource_kind`, omits capacity subject, and the kind is the identity tag.
`Capacity(code)` requires `capacity_subject`, omits resource identity, and
carries `resource_kind` if and only if that subject is `ResourceNode`; the kind
then equals its identity tag. Reserve/release, resource-kind, identity, subject,
and code substitution is invalid. Errors
exclude raw messages, names, payloads, arbitrary
parser text, secrets, credentials, and unbounded platform output.

The remaining error fields are validated by these closed tables; there is no
operation, phase, retry, or context default. Every UDP row requires `family`
and `transport=ExactUdp` and omits `resource_kind`; every DNS row requires
`family` and its exact `DnsTransportV1` and omits `resource_kind`.

| UDP code group | Allowed operation | Allowed safe phase | Required retryability |
| --- | --- | --- | --- |
| `UdpUnsupported`, `HttpProxyUdpUnsupported`, `HttpsProxyUdpUnsupported`, `Socks5UdpDisabled`, `PinnedRuntimeMismatch` | Prepare | Preflight | Never |
| `UdpPolicyProhibited`, `DirectFallbackAuthorizationInvalid` | Prepare | Preflight | Never |
| `UdpPermissionRequired`, `UdpTemporarilyUnavailable`, `DirectUdpPathUnproven` | Prepare | Preflight | AfterExternalChange |
| `Socks5AssociationUnavailable` | Prepare or Renew | Preflight or Active respectively | AfterExternalChange |
| `Socks5RelayLost`, `PathInvalidated` | Renew or Forward | Active | AfterExternalChange |
| `OriginalDestinationUnavailable`, `ProcessProvenanceUnavailable`, `FragmentationOpaque` | Observe | Active | AfterExternalChange |
| `DatagramAdmissionDenied`, `DatagramResourceLimit`, `SocketAdmissionUnavailable` | Forward | Prepared or Active | AfterExternalChange |
| `LoopExclusionIncomplete` | Prepare or Renew | Preflight or Active respectively | AfterExternalChange |
| `DatagramRevisionInvalid`, `DatagramCounterBoundaryInvalid` | Observe | Active | Never |

| DNS code group | Allowed operation | Allowed safe phase | Required retryability |
| --- | --- | --- | --- |
| `DnsUnsupported`, `DnsPolicyProhibited`, `DnsBootstrapCycle`, `PinnedQuicBuildTagUnavailable`, `PinnedDnsResponseBoundUnavailable`, `DnsBackendVersionMismatch` | Prepare | Preflight | Never |
| `DnsPermissionRequired`, `DnsTemporarilyUnavailable` | Prepare | Preflight or Prepared | AfterExternalChange |
| `DnsResolverIdentityUnavailable` | Prepare, Renew, Forward, or Observe | Preflight or Prepared for Prepare; Active otherwise | AfterExternalChange |
| `DnsResolverPathBindingInvalid` | Prepare, Renew, Forward, or Observe | Preflight or Prepared for Prepare; Active otherwise | Never |
| `DnsRoutingUnproven`, `DnsInterceptionUnproven`, `DnsLeakPreventionUnproven` | Prepare or Observe | Preflight or Active respectively | AfterExternalChange |
| `DnsDecodeUnavailable` | Prepare or Decode | Preflight or Active respectively | AfterExternalChange |
| `DnsMalformed` | Decode | Active | Never |
| `DnsResourceLimit`, `DnsCorrelationLimit` | Decode or Observe respectively | Active | AfterExternalChange |
| `DnsTransactionRevisionInvalid`, `DnsLineageInvalid` | Observe | Active | Never |
| `DnsQueryTimedOut`, `DnsResponseUnmatched` | Observe | Active | ExactIdempotentReplay |
| `DnsPrivacyPolicyInvalid` | Prepare | Preflight | Never |
| `DnsExactNameAuthorizationInvalid` | Prepare or Decode | Preflight or Active respectively | Never |

Resolver error selection is total. A syntactically and cryptographically valid
set whose typed outcome is `AllUnavailable` or `RequireBothUnavailable`, a
native unavailable outcome, or a previously ready member that becomes
unavailable/expired maps to `DnsResolverIdentityUnavailable` and retains the
typed cause evidence. A digest/body/signature mismatch, invalid outcome/ordinal,
cross-member field projection, endpoint not present in its source result, stale
context presented as current, or any other binding-set structural violation
maps to `DnsResolverPathBindingInvalid`. During Prepare those codes use the
Prepare phase row; discovery by health renewal, forwarding, or observation in
an active plan uses the matching Active operation row. A producer cannot recode
a structural invalidity as a retryable unavailable result or suppress an
Active resolver failure because the plan was valid at Prepare time.

A resource error's operation/phase is exactly `Apply/Applying`,
`Compensate/Stopping`, or `Recover/Recovering`; no other pairing is valid. Its
retryability is `Never` for `BackendVersionMismatch`, `IdentityMismatch`, or
`ConflictKeyOverlap`; `ExactIdempotentReplay` for `DeadlineExceeded` or
`AmbiguousExternalResult`; and `AfterExternalChange` for
`OwnerProofUnavailable`, `ConditionMismatch`, `ExternalDrift`,
`CapacityReservationFailed`, `ReadbackMismatch`, `RuntimeInstanceLost`, or
`RecoveryEvidenceUnavailable`.

A capacity error uses only `Reserve` in `Prepared|Applying|Active`, `Release`
in `Active|Stopping|Recovering`, `Transfer` in
`Applying|Active|Stopping|Recovering`, or `JournalAppend` in
`Applying|Active|Stopping|Recovering`. The release-plus-append operation reports
publication/receipt/allocation failures as `JournalAppend` and removal/cause
failures as `Release`; it never hides one under `Transfer`.
`TerminalReleaseCauseInvalid` and `ReservationAlreadyReleased` are release-only;
`LedgerOperationReplayRetired`, `LedgerOperationReplayConflict`, and
`LedgerReplaySequenceInvalid` apply to every capacity operation before its
operation-specific row. Their operation/subject projection is closed: `Admit`
uses `Reserve` plus its sole added subject; `Release` uses `Release` plus its
removed source subject; `Transfer` uses `Transfer` plus its removed source
subject; `PublishJournalAppend` uses `JournalAppend` plus the current generation-
journal subject; and `ReleaseCurrentResourceAndPublishJournalAppend` uses
`Release` plus its removed ResourceNode subject. No replay-wide Failed outcome
for the composite operation may select its journal target instead.
`TransferAtomicityInvalid` and `ResourceJournalCompactionUnsupported` are
transfer-only; `JournalRetentionTerminalInvalid` is release-only;
`JournalAppendRevisionInvalid`, `JournalAllocationExhausted`,
`JournalReceiptActiveMismatch`, and `JournalPublicationEnvelopeMismatch` are
journal-append-only. `CapacityCounterOverflow` and
`PartialChargeVectorRejected` are reserve/transfer/journal-append only;
head/snapshot/commitment/subject/requirement mismatches are valid for all four
operations. `AlreadyCommitted` is a success outcome rather than an error: it
returns the byte-identical durable Open body only while that replay horizon is
current. Fresh completion returns `Committed`; all failures use the `Failed`
outcome and exactly one typed capacity error.
`LedgerOperationReplayRetired`, `LedgerOperationReplayConflict`, and
`LedgerReplaySequenceInvalid` require `Never`; the watermark/admission replay
selector takes precedence over operation-ID/head lookup. Retired committed
sequences and retired pre-CAS admission revisions both return no historical
bundle.
`LedgerHeadMismatch` means the attempted operation was not committed and
requires `AfterExternalChange`: the caller reads the current head and rebuilds
a fresh operation without reusing the stale envelope/transition bytes.
Snapshot-root mismatch, compaction unsupported, and every other capacity code
require `Never`.
Family/transport are present only when deterministically carried by the exact
resource identity or capacity subject and then are byte-equal; otherwise both
are absent. A cross-row code, extra context field, omitted required field, or
different retryability is invalid.

## 22. Deterministic conformance tests

Deterministic tests MUST cover:

- every tagged-union variant, unknown tag/field, narrowed scalar edge, and
  deterministic-CBOR golden digest, including QR/opcode `0..=15`, extended RCODE
  4095/4096, QUIC stream-ID maximum/max-plus-one, and cross-domain substitution;
- random flow-ID uniqueness, tuple reuse, NAT rebinding, runtime/plan/lease/
  interface/egress epoch changes, and exact host-flow-ID projection;
- outbound-first and inbound-first flow creation, empty observed opposite-
  direction counters, empty-to-first-occurrence transition, independent
  contiguous `direction_ordinal`, contiguous all-flow `flow_ordinal`, accumulator
  hashes, counter overflow, duplicate/reordered occurrence, and terminal races;
- IPv4, IPv6, IPv4-mapped IPv6, link-local zone, zero source port, empty UDP
  payload, max-size metadata, mixed fragment provenance, raw-fragment direction
  unavailable, and cross-fragment evidence substitution;
- raw-fragment flood admission, exact reservation charges, reservation-failure
  zero-record behavior, live-to-queue atomic transfer, retention terminal,
  early/double release, and queue/staging fanout refusal;
- exact normalized-flow common-field equality, typed `Arch004RecordRefV1`
  resolution/current-revision rules, native standalone DNS non-attachment,
  locator/body/descendant-cycle rejection, and unknown extension tags;
- every egress/policy row, HTTP/HTTPS UDP refusal, SOCKS disabled/association
  loss/relay change, and proof of zero silent direct fallback;
- direct-fallback issuer/signature/domain/challenge/nonce/scope/deadline
  negatives, receipt-free subject/final-direct byte equality, one-use durable
  consumption, exact response-loss replay, and cross-plan/ticket/session/
  generation/boot/suspend refusal;
- direct `RuntimeDestinationUdp` dormant-declaration equality, tentative-child
  validation, no-send latch, atomic child/binding publication, first-byte
  consume, expiry, every ARCH-005 terminal race, and zero-byte failure;
- exact 23-field limit-set bytes/order/types/units/clock-domain/hash and every
  limit at zero/max/max-plus-one configuration and live occupancy, with the
  fixed dimension-to-outcome mapping and no producer default;
- every capacity subject/owner and charge/ceiling equation, singleton global
  ledger genesis, complete ordered snapshot/usage roots, checked recomputation,
  concurrent admit/release/transfer/journal-publication head CAS, common
  operation replay request on every variant, response-loss replay, stale head,
  requirement/commitment/subject/context mismatch, partial vector and overflow;
- flat validation-capsule boundaries with `N =
  max_active_capacity_reservations`, `C = checked_add(N, 1)` and `D =
  checked_add(N, 2)`: candidate-state counts zero/one/`C` accepted and `C + 1`
  rejected, destination count `D` accepted and `D + 1` rejected, and overflow in
  either checked add rejected; byte-identical expansion of every flat member
  into its original basis bundle, including the zero-state
  `PublishJournalAppend` common-basis case; rejection after substituting any
  common body/digest, flat owner/subject/member-root/accounted-bytes/basis digest,
  state/projection/commitment field, count/root/order, or a legacy per-state
  `basis_bundle` unknown field; predecessor-attestation counts zero/four accepted
  and five rejected, with duplicate/order/root/origin substitution negatives and
  proof that long-term validation never dereferences retired predecessor or
  sibling history; exact `D` physical capsule copies at the maximum, one-byte-
  underprovision rejection, no deduplication assumption, no summing semantic
  per-basis bytes as physical common-snapshot copies, and fixed-depth repeated-
  Transfer history;
- global joint-COW WAL golden encodings and recovery: genesis has an absent
  replaced-frame digest, absent attempt nonce/predecessor, exact nine-entry
  tuple, empty participant/subroots, valid Prepare and Committed final decision;
  every non-genesis body has a fresh nonce, required raw-frame digest, exact
  predecessor/revision/parity/generation/transaction ID, ordered typed nine-
  entry tuple and stable-filter counts/roots; fixed participants are present iff
  the tuple arm changes and bind exact old-current, target slot, raw old target,
  optional typed old target and new target, while PublishedBatch public
  participants are the exact marker/batch/charged-Prepared-region projection and
  all other transactions have none; zero and `N + 11` participants accepted and
  `N + 12`, missing/extra/duplicate/reordered/wrong-kind/cross-batch members
  rejected;
- global-WAL crash/recovery at complete body install, Prepare append, before and
  after every fixed/public target, Aborted-arm CAS, every public-target cleanup
  delete, retry-frame replacement and Committed-arm CAS; idempotent resume when
  a fixed target is exact old or exact new and a public target is absent or exact
  Prepared, with any other/torn value forcing Abort; stale body writer, stale
  Prepare append and stale Abort/Commit final-CAS rejection after a fresh body
  replaces the slot, Abort-versus-Commit races, final-decision variant/digest/marker substitution,
  invalid or multiply encoded final regions, nonce reuse, exact fresh-nonce
  retry over complete or torn aborted fixed targets, and rejection of two
  committed/selectable same-revision siblings while permitting only that
  Aborted-attempt replacement; exact legal two-slot states
  `{Committed(0), EmptyTarget}`, `{Committed(n), Committed(n-1)}` and
  `{BodyOnly|Prepared|Aborted(n+1), Committed(n)}`, including current-only
  validation after the fallback is overwritten, plus fail-closed gaps,
  rollback, mix-and-match, Prepared selection and committed-corrupt targets;
- tag-`0x400D` golden receipt/signature and current-versus-settled activation:
  current checkpoint membership makes its complete exact Prepared targets
  visible together, while rotated checkpoints require the immutable Active
  suffix, exact receipt and settlement bound; suffix absence/torn/corruption,
  missing/extra/reordered public participants, wrong checkpoint/body/Commit
  marker/activation tuple/location/ordinal/Prepared-region/indirection/
  certificate digest, and activation-time substitution are rejected; the
  receipt time equals indirection/marker/Open/event publication time rather than
  suffix or recovery time; every current public suffix blocks a successor until
  durable, while a body-only/Prepared/Aborted successor candidate leaves the
  current checkpoint's missing suffix historically completable and only its
  Committed arm is blocked; aborted targets are absent before retry/rotation, rotated Prepared is
  unavailable, settled Active survives marker/sibling GC, stale suffix writers
  and stale compare-delete collectors fail after checkpoint rotation or
  consumer-location reuse, and settlement never
  authorizes early collection;
- capacity recovery-budget equations charge exactly two complete global WAL
  slots once in the ledger total and zero WAL slots in the replay total; the WAL
  maximum covers the largest body, Prepare region and complete larger Aborted or
  Committed final-decision wrapper/digests/framing but no target payload, with
  exact-maximum acceptance, one-byte-underprovision rejection and no second or
  redo-payload WAL encoding;
- tag-`0x400A` domain and golden signature; plan-manifest/component/build/key/
  permit/gate-channel and persisted `CapacityCommit` context/window
  substitutions; a losing CAS's otherwise self-consistent
  state/basis/transition/head bundle; successful post-activation state
  resolution beginning from the exact public indirection, and rejection of
  head-CAS-only raw-proof resolution; byte-identical candidate-projection and
  receipt-published-state vectors with independently recomputed domain-separated
  roots, plus rejection when either root is copied into the other domain;
  selected-full-head-slot sole-current-view recovery, with no independent
  current-snapshot singleton, pointer, wrapper or write path; complete `H1`
  fsync/readback selecting the only current snapshot projection, torn or
  uncommitted `H1` falling back to `H0`, committed-corrupt `H1` failing closed,
  an attempted `H1`/separate-`S0` split-brain having no valid encoding, and a
  historical snapshot carried inside a charged proof being refused as an
  admission or current-snapshot source;
  CAS immediately before lease expiry, crash before sidecar and exact historical
  completion after expiry without new-operation authority; receipt durable-
  record/slot/generation/candidate-set/head/snapshot/time/signature
  substitutions; zero-based selection and wrong state role; max-active one with
  a source-plus-one-target transfer and source-plus-max-target publication,
  Transfer `target_count != targets.len`, first target ordinal different from
  `before_snapshot.next_reservation_ordinal`, target/embedded-commitment ordinal
  mismatch, duplicate/gapped/reordered ordinal, duplicate commitment/state
  digest, max-plus-one target and paired projection rejection;
  `c1 < c2` with `Digest(state(c1)) > Digest(state(c2))` encoded as the valid
  ordered pairs `[(c1,d1),(c2,d2)]`, plus swapped digest, duplicate/nonconsecutive
  ordinal, wrong Reserved body and legacy dual-vector-field rejection;
  missing state/basis/cause/retained-Active/journal preimage in the durable
  candidate set; golden digests for retained Active/terminal, prior-state
  attestation and flat validation capsule plus capsule validation-root and
  tag-`0x400C` signature; candidate-state, preimage, attestation, count/root and
  capsule-digest single-field substitutions; non-recursive receipt-local validation in target-before-source
  DAG order; partial multi-target copy, wrong destination count/root/location/
  charge/readback root; tag-`0x400C` domain and golden signature; private-staging
  crash after every destination copy, including a Transfer source copied first,
  with zero resolver/caller visibility; certificate generated but activation
  transaction uncommitted; and atomic all-old/all-new publication of every
  public indirection, marker, Open sidecar, Accepted-to-Idle transition and
  `OperationReplayOpened`; destination/certificate/indirection substitution
  across ledger, operation, head slot/generation, ordinal, location and payload;
  certificate signing before the complete staged vector reads back;
  deterministic publication-transaction/staging-object-ID recomputation and
  transaction-ID/staging-object substitution;
  exact staged-copy and certificate tamper/missing rejection; marker, Closed
  sidecar and every sibling destination retirement followed by successful
  long-term resolution of the sole survivor from its exact Active index entry,
  tag-`0x400D` receipt, Prepared region, public indirection, certificate, flat
  capsule and recovered settlement bound, without loading a sibling or prior batch; prior-
  attestation digest substitution and attempted prior-certificate dereference;
  repeated Transfer history retaining fixed validation depth and rejecting any
  certificate-to-prior-batch recursive body; retained Active private before
  activation, exact source/target-plus-one-Active all-old/all-new publication,
  single-target enforcement, wrong/missing/extra Active destination and early
  digest/staging resolution rejection; marker/sibling GC followed by Active
  resolution from its own exact Active index, tag-`0x400D` receipt, Prepared
  region, indirection and current settlement; exact terminal/readback/predecessor/
  subject/Reserved/semantic-terminal equality, semantic-terminal `<=` Active
  opened/CAS time `<=` equal readback/terminal ended time `<=` Released time,
  every reversed/equal-field-substitution negative, and collection only after generic-
  Release Open closure; refusal when the selected certificate is absent;
  stale/cross-operation
  core or changed-use ref; empty-state `PublishJournalAppend` publication; and
  generic-release receipt-only-sidecar rejection and complete capsule; selected-
  current GenericRelease raw-validator success, rejection from fallback/copied/
  PublishedBatch/Closing/Closed/retired state, exact candidate/cause/predecessor/
  receipt equality, and proof that success returns no escapable refined state;
  atomic
  non-generic batch-marker plus `OpenOperationReplay` publication; exact
  `OperationReplayOpened.open_replay_digest`, Open `opened_at`, event time and
  sidecar-store payload equality; Ack after E1 but before Open, Ack timestamp
  before Open despite a completed head CAS, and Ack/Open-digest substitution
  rejection; generic-Release all-old/all-new activation of the Open sidecar,
  Accepted-to-Idle transition and `OperationReplayOpened` while the marker
  remains exact Vacant, plus rejection of ordinary-event-API insertion of
  `OperationReplayOpened`; exact open-
  horizon `Committed` versus `AlreadyCommitted` outcome encoding for Admit/
  Release/Transfer/both journal variants, generic-release versus published-batch
  result-receipt projection, and Failed-without-result encoding; partial target
  collection refusal while open; owner/channel/nonce/open-result-bound
  acknowledgement; ledger-stamped early/exact/late ack; acknowledged-versus-
  expired closure race/fork and exact `closed_at`; concurrent pending-admission
  winners/losers, intent substitution, Accepted recovery, pre-CAS retirement,
  atomic Accepted/Open/E1-RequestAccepted install, crash immediately after that
  transaction but before record signature and no Accepted-with-empty-store
  state; pre-CAS expiry candidate sealing followed by atomic
  Accepted/Closing/Sealed-to-Idle/Closed retirement with both-old-or-both-new
  crash recovery, plus rejection from owner Open or an unsealed event store;
  monotonic admission tombstone and same-sequence fresh successor;
  head-CAS/pre-CAS-expiry-latch races paused on both sides with exactly one
  winner; an E2 retirement defeating both stale and freshly reloaded head
  writers; a head-CAS winner making E2 fail specifically on the old-head tuple;
  rejection of an E2 transaction that writes anything except the event-store
  latch; and rejection of every attempted `H1` plus pre-CAS-expiry-latch
  combination; committed-
  head/pre-Open crash completion without a second CAS; the complete selector
  precedence matrix over watermark, Idle/Accepted, incomplete head, Open,
  Closing and Closed; Ack and Expiry crash at every
  combined sidecar/watermark boundary with both-old-or-both-new recovery; stable
  installation/ledger replay domain across plan changes; genesis/current/
  fallback watermark selection, revision-to-slot/generation mapping, rollback,
  sibling, skipped revision and immediate-predecessor checks; retired-sequence
  precedence immediately after watermark readback and after sidecar/consumer
  GC using only the stable selector envelope, plus admission-retired after
  owner/key/event GC; same-sequence/admission conflict, skipped/
  overflow/stale-watermark rejection, and no historical-gate reopening;
  tag-`0x400B` owner-epoch registry/event/terminal/unreachability domains and
  golden signatures; omitted/duplicate/late channel registration; wrong owner/
  epoch/session/generation/lease/channel; per-stream ordinal and global installed-
  revision fork/gap/backfill, predecessor-store splice and reordered cross-
  stream append; global fold rejection of close-before-Ack, Ack-after-close,
  issue-after-branch and branch switch; crash after every record CAS but before its signature, exact
  installed-record historical finalization, and changed record/time/resulting-
  store rejection; crash after acknowledged record and every missing-suffix
  boundary followed by exact historical acknowledged completion, plus attempted
  acknowledgement mutation or expiry-branch switch;
  request/token issue without retirement; arbitrary zero counts/roots; omitted
  live channel; registered-versus-closed key-set mismatch; unsigned close/key-
  destruction claim; HistoricalCloseOnly attempting registration, nonterminal
  event, acknowledgement or ledger CAS; historical-finalize attempting append
  or sibling candidate; terminal predecessor/revision/time mismatch and same-
  epoch successor; transport/key closure-head identity/barrier/branch-latch
  splice or reopen; acknowledged closure head before its exact Ack latch, expiry
  closure head before both deadline/lease and its exact retirement latch,
  readback before an expiry head, either head after `ChannelClosed`, and branch/
  deadline/lease/request-key mismatch; byte-identical latch body/digest in both
  heads and the exact inequalities Ack latch `<=` both heads `<=` every
  acknowledged `ChannelClosed`, and max(deadline, lease expiry) `<=` retirement
  latch `<=` both heads `<=` readback `<=` every expired `ChannelClosed`;
  signed-census versus sealed-store prefix mismatch; Sealed/census/candidate/
  Ack-or-Expiry close-time inequality and closure-head/readback/event reversal;
  HistoricalFinalize exact-unreachability-envelope mutation; typed head Genesis/
  EmptyTarget first CAS and watermark EmptyTarget first closure; all five replay-
  recovery store kinds' Occupied/EmptyTarget parity, generation, current/fallback
  and same-admission Accepted-to-Idle storage revision; independent sidecar,
  marker and watermark store genesis, including sidecar/marker Slot0 Occupied at
  storage revision zero/generation one with Vacant(0) and Slot1 EmptyTarget at
  generation zero/next one; first EmptyTarget replacement, alternating target,
  storage-revision/slot-generation progression and current/fallback
  selection; every per-store envelope case exercised through the global-WAL
  body/Prepare/each-target/Aborted-or-Committed matrix above; torn,
  complete-uncommitted and committed-corrupt target handling; committed/
  selectable same-revision sibling, skipped revision, rollback, parity,
  generation, ledger/domain/payload
  splice rejection; current-slot suppression of an older valid fallback;
  artifact-store slot/generation independence from its embedded head slot/
  generation; sidecar and marker inner head/record tuple splice and absent-marker
  versus retired-old-marker distinction; legal sidecar Vacant-to-Receipt-to-
  Open-to-Closed-to-Vacant and marker Vacant-to-Present-to-unchanged-through-
  closure-to-Vacant lifecycles, with the generic marker remaining Vacant;
  pre-watermark overwrite/GC refusal, post-watermark safe reuse and
  proof that an older fallback cannot resurrect a retired replay; every
  base-ledger and replay-recovery-budget max/max-plus-one equation over every
  full kind-correct containing-slot arm—head EmptyTarget/Genesis/Committed and
  every other store EmptyTarget/Occupied—including tags, identity,
  physical slot/generation/revision, complete payload/digest, framing and
  checksum; kind-correct largest-arm maxima, exact-maximum acceptance and
  one-byte-underprovision rejection; head maximum containing the largest
  candidate set plus sole embedded snapshot, marker maximum at
  `max_active_capacity_reservations + 2` with one complete maximum flat capsule
  duplicated in every certificate and no deduplication assumption, exact-max and
  max-plus-one capsule member/attestation/destination cases, fixed-depth repeated-
  Transfer history and bounded quadratic marker/Open charge, sidecar maximum
  containing the largest Open/Closed replay, event maximum containing 64 streams by 32 events and owner
  maximum containing the largest branch latch; simultaneous Accepted/epoch
  state, the exact two-slot global-WAL matrix and maxima above with no omitted
  or double-counted body/header/decision wrapper and no redo-payload or second
  WAL encoding, forbidden second epoch,
  fixed-byte accounting and safe two-slot garbage collection;
- flow/DNS semantic-terminal retention transfer, zero-retained typed proof,
  active/index/lineage early-release refusal, journal preallocation and initial
  split, multi-append receipt/Active chain, complete envelope/index/partition
  byte accounting, many-small-record max/max-plus-one, per-role quota and
  mandatory terminal-reserve preservation, digest-DAG topological order,
  published envelope/transition/head triple-splice rejection, deletion release,
  typed no-mutation compaction refusal, recursive-ledger-accounting refusal,
  double release, and unbounded stream/DoH/buffer/journal fanout;
- all five resource kinds' exact identity/backend/body/before/postcondition/
  condition/compensation/conflict/predicate tuple, with actor/build/limit/rule/
  field/version/CAS/result/readback single-field substitution negatives;
- UDP-path intended-postcondition plan-cycle negatives and proof that bindings,
  contexts, child observations, and results appear only post-seal;
- Windows OS-observed InterfaceGuid/IfIndex substitution, flag/version/managed-
  field closure and foreign drift; resolved link rediscovery, one-field setters,
  link churn and forbidden `RevertLink`; NetworkManager complete-settings/version
  CAS, flags zero, restart/race and unchanged persistent profile;
- macOS route/intercept and Windows/Linux native-intercept zero-mutation typed
  refusals, plus runtime port-53 config-only, wrong-rule, wrong-handler, and
  missing authenticated read-back negatives;
- apply/compensation ambiguity, recovery rev0/successor/current-head CAS,
  origin/identity/plan/reservation preservation, fork/sibling/skip/splice and
  post-terminal rejection, plus recovered applied health/compensation sources;
- evidence kind/body/context equality, ARCH-001 journal role/body mapping,
  ARCH-002 root tag/schema/location mapping, inline ordinal/authenticator,
  source/use-site/signer/message-key equality, valid-but-wrong-kind refs,
  cross-subject/context substitution and self/ancestor/descendant cycles;
- DNS header and framing truncation at every byte, every label/compression
  pointer edge, loops, work/depth limits, invalid label types, root/max/overlong
  names, zero/one/max/max-plus-one questions, section counts, EDNS extended RCODE,
  and arbitrary bytes without panic;
- QR values crossed with every bounded opcode `0..=15`, query/response role
  inversion, opcode mismatch unmatched response, response-before-query, and
  unknown role tag;
- every transport's pending-to-matched query/response identity split, reused wire
  IDs, concurrent identical questions, question mismatch, retransmission, late/
  duplicate response, response/timeout CAS race, TC plus TCP retry, and expiry;
  duplicate query evidence under another transaction ID/creation ordinal,
  same boundary with a different otherwise valid semantic digest,
  same lease/association/message key under another producer stream/ordinal,
  decoded versus decode-opaque versus malformed outcome equivocation,
  response evidence consumed by both matched and unmatched outcomes, unique-
  consumption-index conflict, exact response-loss replay before lookup, matched
  response-loss retry after its pending query has left the table, and post-retention
  replay while the source evidence/lease remains reachable; every unmatched-
  response-context owned field and every boundary-supplied missing-field
  substitution; timeout at deadline-minus-one versus exactly deadline; query-
  bound limit-set preservation across plan change; and every successor-
  preserved field substitution;
- tag-`0x4009` decoded-semantic domain/golden signature; Query omission versus
  Response presence of `response_summary`; exact boundary/context, role,
  family/transport, wire ID/opcode, question commitment, projected-question
  digest, response summary and observed-time single-field substitutions;
  top-level versus response-summary opcode mismatch; and response times at
  query-time-minus-one, exactly query time, deadline-minus-one and exactly
  deadline;
- DNS revision/predecessor/fork/current-state rules, terminal absorption, lineage
  self/forward/cycle/depth rejection, exact resolver/question/scope equality,
  and invalid non-TC or non-UDP retry roots;
- every host-association transport, carrier, hook, occurrence/frame/stream/token
  equality, plaintext-hook versus encrypted-outer-only variants, native request-
  token versus unmatched response-token substitution, absent association zero-
  transaction behavior, and cross-host/flow/connection/HTTP transaction/stream
  association negatives;
- every valid and invalid mechanism/payload/observation-class combination,
  proving decode-opaque/malformed transaction variants and encrypted-opaque/
  unavailable capability statuses cannot encode names, qtype/qclass, wire ID,
  RCODE, latency, or correlation, and that the latter two create no transaction;
- every plaintext decoder reservation/work/message/buffer/aggregate limit,
  zero partial parse products, atomic rollback, same-selected-path continuation,
  and block/close/fence when missing metadata is a policy dependency;
- DoT/DoH/DoQ with and without authenticated plaintext hooks, false positives
  from port/SNI/ALPN/path/resolver IP/QUIC, DoH method/media/base64/body bounds,
  exact HTTP carrier versus native carrier-unavailable, and encrypted-opaque
  selected-path plus complete plan-sealed zero-plaintext-census replay: missing/
  extra/reordered producer entries, wrong derived stream ID, ordinal gaps,
  prefix-root/count mismatch, late backfill, cross-lease/outer substitution,
  matching `Decoded`/`DecodeOpaque`/`Malformed` leaf, unresolved selected-path
  candidate, `NativeNoBinding`/`ObservedNoBinding`/`Opaque` non-selected branch,
  ambiguous selected-path refusal, runtime/native sibling-selection substitution, illegal exact-outer
  attribution, sibling/stopped/prior-lease observer active-state substitution,
  both checked zero sums, and no transaction or names/types/classes/RCODE;
- DoQ exact `doq` ALPN, authenticated resolver/path, client-bidirectional stream,
  one-query/one-response, exact query/response refs, typed server-FIN read-back,
  zero IDs, same-stream, length/FIN rules, plus generic
  QUIC/datagram/unidirectional/server/cross-stream/extra-message/trailing-frame
  negatives;
- every retention mode, transient-before-projection HMAC, key rotation/deletion,
  cross-installation unlinkability, receipt scope/one-use/expiry, first/middle/
  last out-of-scope mixed-question fallback, complete-vector atomic publication,
  no exact prefix, logs/errors, and analyzer permission denial;
- exact ten-cell family-major capability spec/observation, HTTPS carrier set
  exact spec-to-observation equality, all 5x5 mechanism substitutions, HTTPS
  carrier add/remove/order/membership, missing/duplicate/reordered/extra cells,
  platform/resource/lease/freshness substitution, all blocking-reason versus
  NoBlockingReason cross-products, and no claim-dimension implication;
- resolver binding-set/member digests keyed by descriptor plus every use site,
  same-descriptor/different-policy reuse, all five family policies, Prefer first-
  ready selection, `RequireBoth` two-ready obligation,
  `RequireBothUnavailable` preservation/first-cause projection,
  outcome/ordinal equality, derived `AllUnavailable` reason,
  literal/prior closed endpoint-source DAG and
  depth, predecessor observation/result membership, and binding observation order;
- zero-dependency versus nonempty binding branch, missing/extra/duplicate/
  unreachable resolver sets, omitted predecessor source/result, ambient/pending-
  TUN recursion, selected endpoint/carrier/cell mismatch, and fresh-OCSP
  `UseSiteFamilyPolicyUnavailable` zero-network refusal;
- dependency-cycle rejection, actor/exclusion omission, socket admission loss,
  resolver/interface/relay drift, health renewal, and reverse stop ordering;
- error resource-kind omission/substitution, UDP/DNS/resource/capacity code and
  operation mismatch, claim kind/dimension-reason-disposition cross-products,
  Reserve/Release/Transfer confusion, family/transport optionality,
  retryability, and bounded secret-free serialization;
- failure injection before/after each ARCH-001 intent, reservation, OS/runtime
  action, observed-result fsync, response, commit, stop, compensation, recovery,
  retention transfer, and release boundary;
- pinned 1.13.19 positive schema checks plus rejection of newer-only fields,
  wrong revision/binary digest, config-success-as-capability, and native HTTPS/H3
  until response bytes are bounded before allocation/read; and
- `with_quic` versus stub registration and exact `ErrQUICNotIncluded` behavior.

All parser tests use deterministic synthetic messages and include fuzz targets
for DNS framing, labels/compression, correlation keys, and extension decoding.
Tests MUST NOT weaken expected results to accommodate unsafe implementation.

## 23. Real-host release gates

For every exact OS/architecture/release/package/backend/network-scope/egress/
family/UDP-path/DNS-transport/visibility cell claimed supported, the shipped
artifacts MUST pass privileged clean-host tests with an out-of-band control
path.

The suite proves at minimum:

1. IPv4 and IPv6 UDP pass-through for each claimed selected egress, plus exact
   unsupported/block behavior for every other egress;
2. original destination and process provenance at the exact claimed evidence
   grade;
3. DNS query/response metadata for each claimed native, hijacked, or passive
   plaintext mechanism and explicit `EncryptedOpaque` capability statuses for
   DoT/DoH/DoQ without a supported plaintext hook, proving they emit zero DNS
   transactions;
4. no query-name claim from QUIC, TLS, SNI, ALPN, resolver IP, or port alone;
5. exact loop-exclusion and factory admission for runtime, Capture Core,
   resolver, bootstrap, health, helper/watchdog, proof, direct, proxy, and relay
   paths;
6. zero policy-incompatible direct DNS or UDP path, including external upstream
   failure and association loss;
7. malformed traffic and exhaustion without process panic, unbounded growth,
   policy leak, or unnecessary loss of otherwise safe ordinary connectivity;
8. before/during/after ordinary-connectivity oracles and complete route, rule,
   resolver, TUN, socket, process, runtime, helper, and journal enumeration;
9. normal stop, application/Supervisor/runtime/helper/watchdog crash, lease and
   owner loss, response loss, interface/default-route/resolver drift, suspend/
   resume, boot, and every mutation/compensation crash window; and
10. exact package, runtime revision/digest, adapter/decoder build, plan, limits,
    capability, evidence, journal, and baseline-equivalence artifacts sufficient
    to reproduce the claim.

Tests use synthetic private names and payloads. A loopback-only fixture, fake
runtime, source inspection, config check, DNS server response, remote-only proxy,
or one platform API observation cannot establish support.

A failed cell removes `Supported` only from that exact cell, but no broader
status may imply it. Missing mandatory cells refuse the requested mode rather
than publishing a degraded active session.

## 24. Primary references

- [RFC 768](https://datatracker.ietf.org/doc/html/rfc768)
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html)
- [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html)
- [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html)
- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html)
- [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html)
- [RFC 8085](https://www.rfc-editor.org/rfc/rfc8085.html)
- pinned sing-box 1.13.19 revision
  [`b5ebaa1fc0f2b94256180b95468e73ef53caa27d`](https://github.com/SagerNet/sing-box/tree/b5ebaa1fc0f2b94256180b95468e73ef53caa27d),
  including [DNS types](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/constant/dns.go),
  [DNS options](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/dns.go),
  [UDP DNS transport](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/udp.go),
  [TCP DNS transport](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/tcp.go),
  [TLS DNS transport](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/tls.go),
  [HTTPS DNS transport](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/https.go),
  [QUIC DNS transport](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/quic/quic.go),
  [HTTP/3 DNS transport](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/quic/http3.go),
  [`with_quic` registration](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/include/quic.go),
  [non-QUIC stub registration](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/include/quic_stub.go),
  [DNS sniffer](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/sniff/dns.go),
  [route actions](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/rule_action.go),
  and [TUN options](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/tun.go).

These sources define protocol or candidate runtime primitives. They do not
prove FlowProbe support, transactionality, privacy, loop exclusion, or truth.

## 25. Compatibility and migration

FlowProbe is unreleased. This contract replaces incomplete v0.x assumptions
directly. It defines no compatibility shim, legacy flow key, default fallback,
old visibility alias, or migration. Any production compatibility or migration
requires separate authorization.
