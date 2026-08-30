# ADR-0008: Runtime destination UDP path purpose

Status: Accepted

Task: ARCH-005

## Context

ADR-0005 and the accepted egress contract define `PathPurpose` as a closed,
versioned union. Its existing tags 0 through 13 include runtime-destination TCP,
DNS, SOCKS5 UDP relay, verification, recovery, certificate, and telemetry paths,
but no purpose for a FlowProbe-owned socket that sends UDP directly to the
selected destination.

ARCH-004 needs such a socket for its direct UDP path. Reusing
`RuntimeDestinationTcp`, a DNS purpose, or the SOCKS role-C
`Socks5UdpRelay` purpose would assert the wrong protocol and authority. Treating
the purpose as an unknown extension is also invalid because the accepted union
rejects every unrecognized tag. Therefore ARCH-004 cannot make direct UDP Ready
without an explicit upstream amendment.

## Decision

Append one member to `PathPurpose`:

```text
RuntimeDestinationUdp // tag 14
```

Existing tags 0 through 13 keep their encodings. Tag 14 is valid only under the
rules below; tag 15 and every other unknown tag remain invalid.

`RuntimeDestinationUdp` is an operational, non-verification child of the exact
FlowProbe-owned actor that opens the UDP socket. It is legal only when all of
the following are true:

- the transport is UDP;
- the sealed egress selection is the exact existing `Direct` selection;
- the actor, declared family, socket-factory policy, exclusion entry, route and
  interface observation all agree;
- an accepted ARCH-004 `transport.udp.path.v1` binding names the same declaration,
  socket child, selected destination endpoint, and observation context; and
- the child passes the existing ordinary admission, first-byte, checkpoint,
  census, renewal, closure, and recovery predicates.

Until that exact ARCH-004 binding exists, the path is unsupported and releases
zero protocol bytes.

The preflight actor graph seals only a dormant static declaration: the exact
actor, factory, families, UDP transport, and `Direct` selection. It contains no
future socket child or ARCH-004 binding and grants no endpoint or send
authority. At child creation time the factory constructs the child first,
validates the one-way ARCH-004 binding that references that child, and atomically
publishes the child, accepts the binding, commits accounting, and hands off the
still-latched socket. The existing first-byte guard opens the latch only after
that transaction succeeds. Any race or failure leaves no partial publication
and sends zero bytes; pre-publication binding failure uses the dedicated closed
`RuntimeDestinationUdpBindingInvalid` terminal reason. The dynamic binding never
feeds back into the sealed plan. A non-expiry failure to consume the already
accepted binding after publication instead uses
`RuntimeDestinationUdpBindingConsumeFailed`; the committed child, binding, and
accounting remain append-only while the zero-byte close is recorded by the
existing closure ledger and both censuses.

## Authority boundary

The purpose reuses `OwnedActorAllExternalEndpoints` only as the preventive
loop-exclusion scope for the same actor's exact socket-factory policy. That
broad scope never supplies a destination, route, egress policy, protocol, or
send authority. The operational peer comes only from the accepted ARCH-004
per-flow binding.

This amendment does not add a `ResolutionPurpose`. Any runtime-destination
resolution used by ARCH-004 remains in ARCH-004's own signed context and cannot
pretend to have been part of the earlier activation plan. Ambient lookup,
ambient direct fallback, or endpoint substitution remains forbidden.

## Preserved lifecycle and ownership

The new purpose reuses the existing ARCH-001 and ADR-0005 model without adding
a root, actor class, factory, checkpoint, evidence type, or quota:

- the current owner actor and exact tag-14 socket-factory policy create the
  child;
- the existing tag-31 child observation validates preventive mechanism
  read-back, path identity, and the first-byte gate;
- every creation and closure enters the existing chronological tag-34 chain,
  current-open provenance, both exact censuses, and lease-renewal evidence;
- the existing ordinary admission, open-socket and per-lease creation bounds
  apply exactly once per socket; and
- close, release, owner death, unsafe drift, lease loss, boot/suspend change,
  and crash recovery follow the existing fail-closed rules.

## Unchanged protocol and support boundaries

External HTTP and HTTPS remain TCP CONNECT mechanisms and cannot carry this
UDP path. No MASQUE or CONNECT-UDP mechanism is introduced. SOCKS5 UDP continues
to use only its existing role-C `Socks5UdpRelay` path and cannot substitute the
new direct purpose. DNS, probes, verification sockets, local proxy paths, and
user-authorized fallback keep their existing purposes and authority.

This amendment changes no platform capability tuple, `StaticSupport`,
`Readiness`, or `Evidence` value. Recognizing tag 14 is not capability evidence
and by itself makes no Windows, Linux, or macOS mode Ready or supported.

## Consequences

ARCH-004 may now define the exact `transport.udp.path.v1` binding needed to
realize direct destination UDP through the already accepted preventive actor,
factory, exclusion, checkpoint, and evidence model. Implementations still have
to satisfy ARCH-004 and every existing real-host release gate before claiming
support.

The normative encoding, validation predicates, negative cases, and unchanged
support matrix are defined in
[`egress-and-loop-prevention.md`](../contracts/egress-and-loop-prevention.md).
