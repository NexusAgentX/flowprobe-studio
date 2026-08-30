# ADR-0007: UDP and DNS visibility baseline

Status: Accepted

Task: ARCH-004

## Decision scope

FlowProbe will expose bounded generic UDP flow metadata and bounded DNS
transaction metadata without making payload decoding, datagram reassembly, or
universal encrypted-DNS visibility part of the v0.2 baseline. UDP forwarding is
an explicit policy outcome on the selected ARCH-002 egress; DNS routing,
interception, decoding visibility, and leak prevention are four independent
claims.

This decision defines the `transport.udp.*` and `dns.*` namespaces reserved by
ADR-0004. It defines flow identity, lifecycle, visibility states, DNS
correlation, privacy, resource limits, policy failure, transactional resources,
loop integration, capability reporting, and verification obligations. It does
not implement those mechanisms or claim that any release platform is currently
supported.

The normative types and predicates are in
[`udp-dns-baseline.md`](../contracts/udp-dns-baseline.md).

## Preserved architecture

This decision preserves all accepted boundaries:

- sing-box remains an independent managed Network Runtime process;
- Capture Core remains FlowProbe-owned, protocol-oriented, and independent of
  sing-box internals;
- the Config Compiler owns protected `__flowprobe_*` objects and users cannot
  redefine them;
- the privileged helper remains the only authority for journaled operating-
  system network mutations;
- third-party analyzers continue to use versioned host contracts; and
- raw and normalized capture data remain source material while semantic output
  remains derived and rebuildable.

The helper never parses user DNS payloads and never becomes a resolver or UDP
proxy. The Network Runtime owns forwarding and resolver transports. Capture
Core owns generic observation and protocol decoding. The Supervisor binds the
requested policy, capabilities, and evidence into the ARCH-001 plan.

## Observed baseline and support truth

The v0.1 normalized-flow contract allows opaque UDP connection metadata but
does not define a datagram-flow key, original-destination provenance, packet
counts, idle closure, DNS correlation, encrypted-DNS truth, or resource bounds.
The current runtime API has no UDP/DNS capability matrix. Existing sing-box
configuration support and a loopback fixture prove neither system DNS capture
nor policy-safe UDP pass-through.

ADR-0004 currently leaves every full-tunnel platform
`UnsupportedPendingArchitecture` because the accepted independent runtime
attachment and first-packet resume gate do not exist. ADR-0005 additionally
requires a complete preventive exclusion set and durable socket admission. This
ADR does not remove those blockers. It makes zero `Supported` platform claims.

## Four separate DNS claims

Every reported DNS capability has separate dimensions for:

1. **routing**: which configured resolver path a request is intended to use;
2. **interception**: whether an accepted steering mechanism actually captured
   the request;
3. **decoding visibility**: whether FlowProbe actually observed and decoded a
   DNS message at a supported plaintext boundary; and
4. **leak prevention**: whether every other policy-incompatible DNS path is
   preventively blocked or excluded from capture recursion.

Success in one dimension does not imply any of the other three. A protected
runtime DNS server can be configured while application DNS bypasses it. A
passive port-53 decoder can see a packet without controlling its route. A
firewall rule can prevent leakage while no DNS name is visible.

Each IPv4/IPv6 and UDP/TCP/DoT/DoH/DoQ matrix entry reports one visibility
mechanism:

- `NativeConfigured`: a FlowProbe-protected runtime resolver or registered
  platform-native resolver route is current; decoding is proven only when that
  branch's exact closed plaintext hook/pair exists;
- `Port53Hijacked`: an accepted transaction routed matching port-53 traffic to
  the registered DNS handler and read-back proved the rule;
- `MetadataObserved`: a supported passive plaintext decoder observed the
  message without claiming routing authority;
- `EncryptedOpaque`: the exact selected planned resolver transport was observed
  and a closed census proved no matching authenticated plaintext DNS boundary;
  or
- `Unavailable`: neither a supported message observation nor a defensible
  encrypted-transport classification exists.

`NativeConfigured` and `Port53Hijacked` are mechanism claims, not universal
coverage claims. Their capability records carry exact scope and evidence.

## Generic UDP flow decision

A `DatagramFlowId` is the exact existing `NormalizedFlow.flow_id`: a random,
never-reused identifier allocated when the first accepted datagram is observed
for one capture-session/runtime generation. ARCH-004 creates no parallel flow-
ID alias. It is not derived solely from a reusable five-tuple. The flow record
binds:

- capture session, plan, generation, and observation epoch;
- per-occurrence direction relative to the captured application, with separate
  outbound and inbound counters;
- address family and transport;
- observed local/remote endpoints;
- original destination and its provenance, or an explicit unavailable reason;
- selected egress and any SOCKS5 relay identity;
- per-direction packet and byte counts;
- first, last, and optional end times from one declared clock domain;
- idle timeout and terminal close reason;
- process provenance as observed, inferred, or unavailable; and
- an explicit content state of metadata-only, opaque, or unavailable.

Tuple reuse after idle closure creates a new ID. NAT rebinding, interface epoch
change, selected egress change, or original-destination ambiguity closes the old
flow rather than editing its identity in place.

Flow state is an immutable revision/predecessor chain with monotonic counters
and times and a closed `Active | Closed` state. A terminal revision is absorbing;
a delayed older snapshot cannot lower counts or resurrect it. The sealed plan
selects one authoritative complete-datagram counter boundary per direction and
gives each occurrence one identity, so observing the same datagram in TUN,
runtime, and decoder planes cannot count it more than once.

A datagram flow is bidirectional; direction is not frozen into its identity.
Every accepted complete-datagram occurrence has a known direction. A raw
incomplete IP fragment receives no guessed flow ID, port, or original
destination and may instead emit bounded raw-fragment metadata with explicit
`DirectionUnavailable`. Fragment state is folded per occurrence rather than
stored as one immutable flow scalar.

The baseline stores no UDP payload bytes, performs no IP-fragment reassembly,
and promises no application decoder beyond the separately defined DNS decoder.
Packet lengths and bounded transport facts are metadata. An unsupported
fragment, jumbogram, malformed packet, reordered datagram, or missing platform
fact is represented explicitly and must not panic the host.

## UDP forwarding and no silent fallback

For each requested flow, the sealed policy selects exactly one outcome:

- pass through the selected ARCH-002 egress;
- block with a typed reason; or
- use a separately requested and explicitly authorized direct-fallback policy.

Direct fallback is a different prepared request and plan. It is never inferred
from timeout, external proxy failure, resolver failure, or missing UDP support.
`ExternalHttp` and `ExternalHttps` cannot carry UDP. `ExternalSocks5` carries
UDP only with the exact accepted `RequireAssociate` path, live association, and
operational socket admission. Direct UDP requires a proven direct UDP path.

A ready `Direct` path is encoded only as
`Arch004UdpPathBindingV1::DirectRuntimeDestination`. It resolves the dormant
`RuntimeDestinationUdp` declaration, validates one tentative socket child while
the no-send latch stays closed, and atomically publishes the child and accepted
binding before the first-byte guard may open that latch.
`ExternalSocks5(RequireAssociate)` uses `Socks5UdpRelay`. A purpose declaration
or child observation alone is not readiness and changes no platform support
claim.

Direct fallback uses a receipt-free normalized authorization subject followed
by an installation-bound Ed25519 policy-broker receipt. The subject fixes the
ticket/session/generation, exact accepted `NetworkScope` and original
`Digest(SafeEgressSelectionV1)`, destination/family/process scope, and the
complete new `Direct` selection without a digest cycle. The receipt has a fresh
challenge, receipt ID, decision nonce, boot/suspend binding, and a decision
expiry no later than five minutes. `PreparePlan` durably consumes it once and
binds it to one candidate and resulting `PreparedPlanId + PlanDigest`; only an
exact response-loss replay returns the same result.

If the selected upstream cannot carry the requested UDP, activation or the
individual operation returns a closed unsupported/block result. It never emits
the datagram through ambient direct routing and never reports a drop as success.

Every DNS and UDP socket joins ADR-0005's actor graph, exclusion set, factory
admission, physical-path proof, and sustained-health predicates. A resolver or
decoder may not open an unregistered socket. Proof traffic, bootstrap DNS,
certificate-status traffic, and DNS-over-encrypted-transport connections are
included in the same completeness check.

## DNS transaction decision

Plaintext DNS messages are decoded only at registered bounded boundaries. A
`DnsTransactionId` is allocated independently of the reusable 16-bit wire ID.
Correlation uses an immutable `DnsCorrelationDiscriminatorV1` containing only
the QR=0 query identity and exact four-bit opcode:

- UDP carries the query occurrence, flow ID, wire ID, and opcode; endpoint
  identity remains in the registered datagram flow and resolver evidence rather
  than being duplicated in the correlation key;
- TCP or DoT carries the connection epoch, query frame sequence, wire ID, and
  opcode;
- DoH carries the exact host HTTP transaction and opcode;
- DoQ carries the QUIC connection epoch, stream identity, and opcode; and
- a protected runtime hook carries runtime/resolver IDs, its path-bound
  selection, authenticated query token, semantic transport, and opcode; while
  a registered platform-native hook carries backend, stable scope, route
  identity, family, selection, token, transport, and opcode.

A matched response adds the transport-matching
`DnsResponseCompletionEvidenceV1`; a response occurrence, frame, stream
evidence, HTTP response ordinal, or response token never enters or rewrites the
query discriminator. Only QR=1 with an equal opcode may match. An opcode
mismatch is a new terminal `UnmatchedResponse`, and response/timeout races use
one compare-and-append successor.

The completion evidence owns the canonical response boundary reference. The
tag-`0x4009` signed decoded-semantic response observation repeats that exact
reference and binds the parsed opcode, projected questions, response summary
and time; it does not create a second response identity. Query semantic
observations omit a response summary, response observations require one, and a
single-field substitution invalidates the signature/equality proof.

Transaction storage also owns one atomic message-consumption index keyed by the
current plan/lease binding, host association, and transport message key. The key
does not include producer stream, boundary ref, classification, semantic digest
or transaction ID. Consequently one canonical message can produce exactly one
query chain, matched response, unmatched response, decode-opaque terminal, or
malformed terminal; alternate signed boundaries and response-loss retries
cannot duplicate or equivocate the outcome. That index is checked before
allocation, pending lookup or mutation: an exact retry returns the stored
transaction/revision immediately, including a matched response whose pending
query has already left the table, while any changed evidence under the same key
is a no-mutation conflict.

The metadata record contains the bounded canonical DNS wire-name
representation, query
type and class, response code, transport, resolver identity, query/response
times, latency when comparable, truncation flag, correlation state, and
observation provenance. It does not retain resource-record payloads in the v0.2
baseline.

Every transaction carries a mandatory transport-typed `DnsHostAssociationV1`.
For a query transaction, its key matches the query discriminator and registered
query host read-back byte-for-byte. A matched runtime or platform-native
completion carries a distinct response association: request/response role tags
and authenticated tokens differ, while their runtime/resolver or
backend/scope/route, family, transport, and resolver-selection core is exact.
The response association also repeats the exact authenticated query-token
digest used by the closed response lookup key.
An unmatched response uses that response association as the transaction
association. Private, cross-flow, cross-connection, cross-transaction,
cross-stream, or cross-token associations are invalid. A runtime or registered
platform-native resolver transaction without an enclosing host flow remains a
standalone DNS record and cannot be attached to a normalized-flow extension.

Plaintext DoT/DoH/DoQ associations carry the exact authenticated hook (and the
HTTP carrier/transaction or QUIC stream where applicable). Encrypted outer
capability read-backs use outer-connection-only variants and never become DNS
transactions or invent a hook, HTTP transaction, carrier, or stream. DoQ response completion binds both the
typed response-message read-back and a separate typed server-FIN read-back.

The record uses the closed payload union `Decoded | DecodeOpaque | Malformed`.
`Decoded` alone can contain
questions, responses, and correlation. `DecodeOpaque` represents an
authenticated plaintext decoder attempt that cannot complete within its sealed
admission, memory, work, method/media, cancellation, or deadline bound. The
decoded V1 projection requires between one and the sealed maximum number of
complete questions; a grammar-valid zero-question message is `DecodeOpaque`,
not producer-selected as malformed, and an over-bound message is never partially
decoded. The
other branches cannot encode names,
types, classes, wire IDs, response codes, or fabricated correlation.
An `Unavailable` capability or resolver-path status creates no DNS transaction;
it remains explicit in the signed matrix/member observation and bounded status
surface, avoiding a pseudo-transaction for bytes that were never observed.
Transaction state is an immutable revision/predecessor chain: a correlatable
query begins only as revision-zero pending and may become exactly one
revision-one matched or timed-out successor; unmatched, malformed and
decode-opaque records are revision-zero terminals. Every terminal state is
absorbing. A delayed pending record cannot overwrite a terminal result.

An unmatched response remains unmatched. A retransmission is a new observation
linked to the earlier transaction rather than silently overwriting it. A UDP
response with `TC=1` and a later TCP retry are two linked transactions. A
grammar-invalid message produces bounded malformed metadata; an over-bound or
resource-exhausted decoder produces bounded `DecodeOpaque`. Neither invents a
name, type, response code, or correlation.

Retransmission and truncated-retry lineage is an acyclic, bounded predecessor
graph over strictly earlier transaction ordinals. It preserves exact transient
questions, resolver authority, family, network scope, and selected egress. A truncated
retry additionally requires a terminal matched UDP response with `TC=1` and a
new TCP transaction. Its closed authority core preserves either the exact
runtime instance/resolver/config or the exact native backend/scope/stable route
identity while allowing only transport-specific member/socket evidence to
change; self, forward, cyclic, cross-kind/cross-authority, and over-depth links
are invalid.

## Encrypted DNS and QUIC truth

Port number, SNI, ALPN, process name, destination address, a configured server,
or QUIC detection alone does not prove visible DNS. A registered decoder must
observe the plaintext DNS message at an authenticated supported boundary before
FlowProbe emits a DNS transaction. Generic QUIC remains generic QUIC. Unknown
HTTPS traffic remains HTTPS metadata, not DoH.

For an exact selected planned resolver path, FlowProbe may report bounded outer
transport, timing, and byte metadata as an `EncryptedOpaque` capability status,
subject to the same privacy policy. It first signs a complete census barrier
showing zero matching authenticated plaintext boundaries for that outer
association/epoch/window. Endpoint data remains in the registered host
connection. The status is not a DNS transaction and cannot report query names,
types, classes, response codes, or answers as observed.

The `DnsObserver` plan seals the complete finite plaintext-producer registry.
Each lease/fence derives one dedicated contiguous observation stream per
producer partition; the encrypted-outer census embeds the exact registry
snapshot and a replayable prefix barrier for every stream. Every plaintext leaf
binds its registry entry, stream ordinal and outer attribution. Classification
requires both zero matching exact-outer leaves and zero unresolved candidates
for the same selected encrypted path. A missing producer, ordinal gap, late
backfill, registry drift, or runtime/native hook that cannot bind an exact outer
therefore yields `Unavailable`, not `EncryptedOpaque`.

Only host-bound DoT/DoH/DoQ plaintext associations can project an
`ExactOuter`. Runtime/native request and response hooks have no host-connection
identity in V1, so encrypted transports are always unresolved candidates bound
to their exact authenticated resolver selection; they cannot claim or fabricate
an exact outer association.
Plaintext boundaries proven to use `NativeNoBinding`, `ObservedNoBinding`, or an
opaque non-selected resolver branch remain in the complete producer stream but
are outside a selected-path census. Any ambiguity about whether a boundary is
on the selected path makes the capability unavailable.

Every encrypted-outer capability read-back carries an acyclic selected-path
projection binding the stream path's socket/tag-13 roots, sealed cell spec and
pure outer-association key. The evidence direction is plan registry to
plaintext leaves to prefix roots to outer census/read-back to capability cell;
the outer body contains no nested ARCH-004 evidence reference. Passive
`NoResolverScope` TLS/HTTPS/QUIC never receives an encrypted-DNS classification.
The read-back has no resolver identity and no DNS transaction projection.

Decoded DoQ additionally requires the full RFC 9250 predicate: either an
authenticated configured-resolver QUIC path or an authenticated passive
hook-bearing DoQ association with `ObservedResolverEndpoint`, negotiated ALPN
exactly `doq`, a client-initiated bidirectional stream, one length-prefixed
query and at most one response on that same stream, DNS IDs zero, and the
required message/FIN ordering. QUIC
datagrams, unidirectional/server streams, generic QUIC, cross-stream pairing,
extra messages, nonzero IDs, or missing path authentication are never decoded
DoQ.

## Privacy and retention

Full DNS names are sensitive. The plan selects one explicit name-retention
mode:

- `EphemeralExact`: exact normalized names may exist only in bounded live
  memory and are not persisted;
- `PersistKeyedDigest`: the default persisted form is an installation-scoped
  keyed digest plus label count;
- `PersistExactAuthorized`: each transient question is evaluated independently
  against the signed family, transport, domain, qtype, and qclass scope; an in-
  scope member becomes exact, an out-of-scope member uses the one signed
  `PersistKeyedDigest` or `Redacted` fallback, and the complete ordered vector
  is reserved and published atomically or not published at all; or
- `Redacted`: no name or stable name digest is exposed to the consumer.

Keys, exact names, resolver addresses, and process identity are exposed only to
authorized host consumers. Ordinary logs and errors contain bounded reason
codes, never raw DNS messages, HTTP headers, TLS secrets, captured payloads, or
full names. Retention follows capture-session boundaries and independently
deletes exact names and keyed indexes when their policy expires.

Exact correlation is completed transiently before retention projection. A
session-scoped secret authenticates an HMAC commitment over the ordered exact
canonical question tuples, allowing redacted persisted records to retain
verifiable same-session lineage without storing names; the key is never exposed
and is deleted with the capture session. A commitment match never replaces the
exact transient equality check while plaintext exists.

Exact-name persistence uses its own receipt-free subject and installation-bound
Ed25519 policy-broker receipt. It fixes the capture session, permitted consumer
and DNS question scope, network scope, and maximum retention deadline. The
decision receipt is valid for at most five minutes and is durably consumed once
for one prepared plan; a copied reference, renderer flag, expired receipt, or
cross-session/consumer reuse grants nothing.

## Bounds and failure behavior

Every release defines finite positive limits for active flows, outstanding DNS
transactions, per-message bytes, question count, name bytes, decoder work,
per-connection buffered bytes, active DNS stream connections, active DoH HTTP
transactions, aggregate DNS stream buffers, idle time, correlation time,
active capacity reservations, aggregate resource-journal bytes, and separate
aggregate UDP/DNS metadata memory. The exact 23 limits and their
implementation build are part of capability and plan evidence. Admission and
release reserve per-object and aggregate counters atomically before allocation,
so opening unlimited TCP/DoT/DoH/DoQ connections cannot multiply a nominal
per-connection limit into unbounded memory.

One installation-wide ledger publishes a complete sorted commitment snapshot,
all sixteen checked usage cells, a durable head, and an append-only transition
accumulator. The selected full image from the typed two-slot head store is the
sole current head/snapshot truth; no separate current-snapshot singleton or
pointer exists. Admit, release, and transfer compare that image and atomically
prepare the new full image containing the candidate state bodies, transition,
snapshot, and head as invisible recovery material. One global WAL checkpoint
with an exact nine-store current tuple selects that image only at its single
Commit marker; a target-slot write alone never changes current state. Consumer-visible state and
resource publication occurs only in the later certified Open-activation
transaction. Usage is recomputed from every resolved requirement rather than
trusting producer increments; partitioning the ledger by plan/session/owner is
forbidden.

The prepared plan also seals the singleton ledger manifest and the exact
Capture Core commit-authority component/build/key registration. A successful
head CAS must survive alternate-slot fsync/readback and the global WAL Commit
marker before that authority's dedicated gate can sign tag `0x400A`; another
accepted Capture Core key, a Prepared-only transaction or a losing self-
consistent candidate is insufficient. Each operation has one
canonical signed receipt core with the complete state-role projection. Consumer
refs select a state or journal publication without changing that core. Raw
proofs first enter a private, non-addressable staging namespace. After every
bounded copy reads back, the same authority signs tag `0x400C` destination
certificates bound to the fresh activation-WAL attempt. One global transaction
installs the complete Prepared public-index vector, typed marker, Open replay,
admission update, and exact Open event together. While that checkpoint is
current its participant union proves activation. The authority then signs tag
`0x400D` receipts into separately framed index suffixes; each receipt repeats
the already sealed Open/publication time rather than suffix-append or recovery
time, and every suffix must be
durable before a successor checkpoint can rotate membership into the settled
long-term branch. A pre-commit certificate or stale Prepared index is never
activation proof.
Retention Transfer adds one dedicated Active destination after its source and
sole target state destinations; its indirection is the only semantic visibility
gate for that Active and remains the terminal/readback release authority.
Long-lived consumers retain their Active index/receipt/indirection/certificate after marker
rotation, so a half-written Transfer source or target is never independently
resolvable. The validator has one non-recursive raw-projection base case behind
that certificate. Every certificate signs and carries the same flat current-
operation validation capsule. The common old head and before/after snapshots
occur once; constant-size per-state members reconstruct the original basis
bundles exactly. Current state bodies and semantic output remain complete, while
predecessor history is represented only by at most four fixed-size attestations
and is never recursively dereferenced. Tag `0x400C` deliberately migrates trust:
the current commit authority re-attests that each historical proof and its then-
live publication passed the ordinary resolver, so a long-term verifier trusts
that current signature and digest set rather than following an unbounded prior-
certificate chain. A single surviving
destination therefore validates after marker and sibling collection without
embedding a prior batch or growing with operation history. Generic final Release
has the only second raw base, scoped to the exact selected current Open capsule;
it returns no refined state and is unavailable after closure. The durable head-slot image also
carries the exact commit context/window and a bounded full candidate set, so a
crash before receipt creation can finish the same historical commit even after
lease expiry without authorizing a new one. Every capacity operation then enters
through one fixed pending-admission slot whose monotonic revision tombstones a
pre-CAS-retired request without advancing the committed-operation watermark.
Admission, owner Open and the first durable `RequestAccepted` record appear in
one all-old/all-new transaction. Head commit accepts only that exact revision-
one event store. The first pre-CAS expiry latch atomically appends revision-two
`RequestTransportRetired` while comparing the same head/watermark/admission/
owner/event tuple, so exactly one path can win and a committed head cannot
coexist with the expiry branch.

All nine fixed COW stores share one typed two-slot WAL; no base/replay half may
commit independently. Each checkpoint contains one ordered participant union,
base/replay/public subroots and an exact nine-entry resulting-current tuple.
The body and atomic Prepare marker authorize attempt-bound target writes; one
atomic final-decision region then accepts exactly one Aborted or Committed arm.
Commit is the sole current-state linearization; Abort changes no current tuple,
revokes attempt-bound target writes and authorizes bounded cleanup. Complete higher store revisions
are ignored unless selected by that tuple, while any tuple target corrupt after
Commit fails closed. Stable slots retain current plus immediate committed
fallback; an in-flight Prepared successor may temporarily replace the fallback.
Aborted attempts are cleaned through their complete participant body after the
durable Abort decision and retried at the same WAL revision only with a fresh
nonce, exact raw-frame compare and a revocable attempt capability. Recovery has
an exact two-slot table for genesis, stable committed current/fallback and a
body-only/Prepared/Aborted successor plus committed current. This makes
body-only, Prepared, Aborted, committed and committed-corrupt recovery
mechanically distinguishable without an unbounded WAL chain.

An already durable head image is completed, never admitted as a second CAS.
Every committed operation then enters one common bounded open-replay state before its result is visible: non-generic
operations retain the complete certified marker and publication batch, while a generic final
release retains a complete capsule rather than a receipt-only intermediate.
Open installation atomically appends `OperationReplayOpened` and records one
`opened_at`; acknowledgement binds that exact Open and cannot precede it. The
open state occupies the current value of an independent typed two-slot sidecar
COW store, blocks the next ledger CAS, and returns the byte-identical result
until an owner/channel/nonce-bound durable acknowledgement or typed deadline/
lease/request-owner unreachability. Both closure paths atomically replace that
sidecar-store value and advance the same fixed two-slot monotonic operation
watermark before unlocking. The replay domain is
stable for the installation/ledger, so retired sidecars or collected Transfer
targets cannot make an old sequence executable or require an unbounded result
history. Expiry embeds a signed, replayable channel-event census for the exact
fresh owner epoch: the frozen registry and all closed streams have identical
key sets, request/token pending sets replay to empty, and the authenticated
Open-to-Closed epoch terminal is absorbing. Event records carry one global
installed order and predecessor store digest, so a lost signature can be
recreated only for the exact durable prefix. A durable in-deadline
acknowledgement selects the success branch; a narrow historical gate may finish
only its deterministic missing close suffix after lease expiry. Both transport
and key-store closure heads repeat the exact Ack/expiry branch latch and are
installed after that latch but before every channel-close event; they cannot
destroy the request handle or key before authenticated Ack or before both
expiry deadlines. The manifest seals separate checked fixed-space budgets for
the complete typed head `EmptyTarget|Genesis|Committed` store-slot encodings,
for the complete `EmptyTarget|Occupied` sidecar, marker and watermark slots,
and for the complete two-copy pending, owner-state,
event-store and transport/key closure-head slot encodings. Exactly two global
WAL slots are charged once in the ledger budget; the replay budget contains no
second WAL. Each WAL maximum includes its body, Prepare marker and the larger
complete Aborted-or-Committed final-decision union wrapper with its inner/outer
digests and framing, never both arms, but only target digests; every target
payload remains charged in its own two-slot maximum. Snapshot bytes are counted once inside head images.
No unbounded Transfer vector, second resident
epoch or hidden attestation log is encodable. Long-lived semantic proof and its
Active index/receipt/indirection/certificate remain independently charged in
retained or journal subjects. Let `N` be the active-reservation limit,
`C = N + 1` the checked flat-state maximum and `D = N + 2` the checked
destination maximum. One capsule stores the common basis once plus `C` flat
members and is linear in `N`; Marker and Open charge `D` physical certificate/
capsule copies, without a deduplication assumption, so their worst case is
quadratic rather than cubic. Every checked add/multiply and every Prepared-
region plus maximum tag-`0x400D` suffix is included in the sealed byte maximum.
The one-level predecessor proof is explicit while repeated history remains
fixed-depth. Thus post-CAS
proof neither creates a digest cycle nor an unaccounted operation-history log.

Every live charge is represented by exactly one current commitment and
`Reserved` state. Transfer uses one bounded vector of ordinal-ordered
`{ commitment, Reserved-state digest }` pairs, so separately sorted vectors
cannot cross-pair a target. Typed transfer may replace the source state
atomically: a resource's
initial state splits into a generation-journal target and, when still active or
unresolved, a non-journal ResourceNode target. A semantic flow/DNS
terminal transfers its charge to a retained-metadata subject; only a later
typed proof that revisions, indexes, lineage, queues, staging, and persisted
copies are unreachable permits release. That Transfer has exactly one retained
target plus one atomically activated retained-Active destination; terminal
readback resolves that Active through its exact public indirection, not a raw
digest or staging ID. Resource journal bytes transfer to a
generation-journal subject preallocated for the complete bounded result,
compensation, recovery and health chain. Revisioned receipts/Active states append
inside that fixed allocation without charging twice. Deletion releases it; V1
returns a typed no-mutation refusal for compaction. Merely closing, matching, timing out,
unapplying, compensating, journaling, or moving an object never releases still-
reachable bytes. Ledger metadata uses a fixed nonrecursive durable budget.

Limit exhaustion fails in a policy-safe direction:

- a new flow that cannot be admitted is blocked or the requested mode is
  refused; it is never sent outside the selected path;
- an already admitted pass-through flow continues only while the exact selected
  path, exclusion proof, and bounded forwarding resources remain valid;
- authenticated plaintext decoder admission, work, memory, cancellation, or
  deadline exhaustion becomes `DecodeOpaque(BoundedDecoderResultUnavailable)` without changing
  an independently policy-safe forwarding path; and
- any state that cannot distinguish safe pass-through from a policy leak closes
  the data-plane gate and triggers ARCH-001 rollback.

Malformed DNS, IP fragments, reordering, loss, timeout, unmatched responses,
and unsupported payloads do not panic. Parser failure cannot unnecessarily tear
down a separately healthy pass-through flow, but it also cannot manufacture a
visibility claim.

## Transaction and resource ownership

System resolver changes, port-53 capture rules, and any privileged DNS/UDP
resource are session-scoped ARCH-001 nodes. Each has a schema, stable identity,
normalized before/after image, owner proof, success predicate, idempotency rule,
conditional compensation, deadline, and typed failure. Shared resolver state
without an accepted conditional mutation or exclusive ownership is unsupported.

The namespace is a closed `Arch004ResourcePlanV1`/result/compensation/recovery
union with five resources:

- `transport.udp.path.v1`: selected UDP path and loop-exclusion dependencies;
- `transport.udp.admission.v1`: bounded operational datagram admission;
- `dns.route.v1`: protected resolver selection without claiming observation;
- `dns.intercept.v1`: accepted port-53 steering/read-back when present; and
- `dns.observer.v1`: unprivileged bounded decoder instance and evidence.

They reuse the single ARCH-001 journal, lease, fence, recovery, and resume
barrier and the single ARCH-002 actor/exclusion/factory model. They do not create
a second helper, lease, loop gate, fallback router, or sidecar journal.

Windows DNS mutation uses only the OS-observed `InterfaceGuid` plus exact
exclusive ownership. systemd-resolved mutates one owned link field per journal
node and never calls whole-link `RevertLink`. NetworkManager uses the applied-
connection version as a CAS token for apply and restore and preserves every
non-DNS setting. No macOS/Darwin mutating route or intercept backend is
registered. `dns.intercept.v1` currently registers only the exact protected-
runtime port-53 rule; native WFP, netfilter/nftables, and System Configuration
intercepts are typed unsupported with zero mutation.

Ambiguous apply/compensation or preserved compensation drift enters one
append-only recovery-resolution chain. `StillRecoveryRequired` and preserved
drift may advance within sealed retry bounds; applied, unapplied, compensated,
and ownership-abandoned outcomes are absorbing. Capacity remains reserved
through ambiguity and drift. Ownership abandonment preserves the foreign image
and requires typed proof that no FlowProbe owner marker or dependent effect is
reachable. A typed unapplied/compensated/ownership-abandoned result may
remove nonpersistent resource charges, but its durable journal bytes are first
atomically transferred to generation-journal retention and cannot be released
until typed deletion proves them unreachable. Inner result bodies are sealed
before persistence and never reference the receipt, successor Active, outer
publication envelope, ledger transition, or resulting head; deterministic
tests enforce this one-way digest DAG.

`Arch004ResolverPathBindingSetV1` is the sole ARCH-004 realization of ARCH-002's
`RequiresAcceptedArch004Binding` marker. It is keyed by both the exact
`ResolverDependencyDescriptorV1` and its closed consuming use site, so one
descriptor may preserve different family policies at direct-destination,
external-proxy, external-destination, or activation-probe fields. The set has
one or two ordered, receipt/result-free members derived from that exact use-site
`IpFamilyPolicy`: `RequireBoth` is `[Ipv4, Ipv6]` and requires both independently
ready, while `Prefer*` selects the first ready member without erasing sibling
observations. Bootstrap is an acyclic graph rooted at a literal endpoint or an
earlier accepted member; ambient DNS and pending-TUN recursion are prohibited.
Only the post-seal `Arch004ResolverPathBindingSetObservationV1` carries selected
endpoints, socket children, matrix observation, and current evidence, so future
results do not feed back into the plan digest. ARCH-002 supplies no family
policy for fresh-OCSP responder resolution; that use site is therefore typed
unsupported before seal and emits no ambient lookup.

A route with zero reachable resolver dependencies uses an explicit zero branch;
otherwise the binding-set count equals the exact reachable descriptor/use-site
pair count. A ready literal endpoint and a previously resolved endpoint use
different closed source variants. The latter must name the exact predecessor
set/member observation and a complete local tag-`0x4008` RuntimeAdapter-signed
bootstrap result. That result binds the current member, predecessor Ready path,
descriptor/use site, exact DNS-name input and port, required family, canonical
sorted-unique bounded candidates, and freshness; it does not borrow an
ARCH-002 tag-4 purpose that cannot encode resolver bootstrap. The Ready member
selects the first canonical positive candidate. `AllUnavailable` is limited to `Only`/`Prefer` policies;
`RequireBothUnavailable` preserves both required member observations and derives
its display reason from the first unavailable member in `[Ipv4, Ipv6]` order.
Neither outcome stores a second producer-selected reason.

A path-bound success resolves one current route plan, Active state, and fresh
health/read-back observation. Runtime and Windows/resolved/NetworkManager
stable identities are mutually exclusive, with no generic network-resolver
alias. The no-binding native branch is restricted to a platform-native
backend/scope and `NativeConfigured + NativeSystemPath` cell in the same route
plan; runtime values and sibling route digests cannot be recoded into it.
Platform-native DoH/DoQ may prove configured routing/leak state, but V1 has no
native plaintext pair for decoding them and reports decoding `NotProven`
instead of fabricating a generic hook or DoQ FIN.

## Pinned sing-box decision

The compiler mapping is restricted to sing-box 1.13.19 revision
`b5ebaa1fc0f2b94256180b95468e73ef53caa27d`. At that revision the source defines
DNS transport tags `udp`, `tcp`, `tls`, `https`, `quic`, and `h3`, a route
`hijack-dns` action, a DNS packet/stream sniffer, and TUN `udp_timeout`. Those
are candidate runtime primitives only.

The source's DNS sniffer validates only enough structure to classify a query;
it does not emit this contract's query/response transaction metadata. Runtime
DNS transports do not establish FlowProbe's original-destination provenance,
cross-plane correlation, privacy policy, loop completeness, transaction
read-back, or real-host support. `hijack-dns`, `udp_timeout`, and newer rolling
documentation fields cannot be compiled into a capability unless the exact
pinned option schema, runtime behavior, and packaged adapter evidence all
match.

QUIC and HTTP/3 transport registration is build-conditional: `include/quic.go`
registers them only with `with_quic`, while `include/quic_stub.go` registers the
same tags but returns `ErrQUICNotIncluded` without it. Capabilities bind the
build tags; accepting the schema is not readiness.

The pinned HTTPS and HTTP/3 DNS response paths allocate from positive
`Content-Length` and otherwise use unbounded `io.ReadAll`, without enforcing
this ADR's pre-allocation `max_dns_message_bytes`. Native pinned DoH/H3 therefore
remain `UnsupportedPendingArchitecture/PinnedDnsResponseBoundUnavailable` until
a versioned bounded wrapper is accepted and packaged or a new pin is separately
audited.

Fields or semantics introduced after the pin are rejected. Updating the pin is
a separate architecture and dependency change, not a documentation shortcut.

## Platform capability decision

Capability is reported for the exact OS, architecture, release, package,
backend, network scope, address family, UDP path, DNS transport, observation
mechanism, and decoder build. It carries ADR-0004 `StaticSupport`, `Readiness`,
and `Evidence`, plus routing, interception, decoding, leak-prevention, process-
provenance, and original-destination dimensions.

A candidate plan contains only the exact ten-cell family-major capability
specification: IPv4 then IPv6, each ordered as UDP, TCP, DoT, DoH, and DoQ.
Post-seal `DnsCapabilityMatrixObservationV1` separately binds the current
observation context, exact platform subject, typed resource-result evidence,
freshness, and closed claim reasons without feeding future results into the plan
digest. Its mechanism is exactly the selected spec mechanism; observation
cannot switch mechanisms after seal. An HTTPS observation repeats the spec's
carrier coverage byte-for-byte. An HTTPS cell carries either a non-empty sorted set of observed
HTTP/1.1, HTTP/2, or HTTP/3 carriers or explicit carrier unavailability;
non-HTTPS cells carry no HTTPS coverage. `NoBlockingReason` is valid only when
all six claims are `Proven`, all positive support/readiness/evidence values and
typed resources are current; every failure uses the
first applicable closed blocking reason.

Evidence references are typed at their use sites. Datagram/original-
destination/process, DNS plaintext/encrypted/message/FIN/host association,
resolver path, resource read-back, metadata retention, journal retention, and
capacity terminal fields each accept only their registered body/context/signer
mapping. A cryptographically valid reference of another kind is invalid, not
generic evidence.

Windows, Linux, and macOS candidates may expose different original-destination,
process, resolver, and packet-flow evidence. API availability is not support.
Each claimed matrix cell requires packaged real-host proof for IPv4 and IPv6
where claimed, UDP pass-through, DNS observation, loop exclusion, rollback,
crash recovery, ordinary connectivity, resource exhaustion, and negative
encrypted-DNS visibility.

Until those gates and ADR-0004/0005 blockers are resolved, every cell remains
`UnsupportedPendingArchitecture` or otherwise non-ready with `DesignOnly`
evidence.

The inherited platform snapshot is deliberately non-supporting:

| Candidate | UDP/DNS evidence that remains necessary | Current result |
| --- | --- | --- |
| Windows 10 build 19041+/Windows 11 x86_64 | Exact adapter/compartment and original-destination provenance, process evidence distinct from endpoint-owner lookup, per-interface resolver ownership, preventive IPv4/IPv6 UDP path proof, packaged rollback and real-host visibility matrix | `UnsupportedPendingArchitecture` / `Unsafe` / `DesignOnly` |
| Selected Linux release tuple | Exact namespace/TUN/original-destination evidence, one accepted resolver manager, preventive socket/mark/bind proof, complete UDP census, packaged rollback and real-host visibility matrix | `UnsupportedPendingArchitecture` / `Unsafe` / `DesignOnly`; release tuple remains unselected |
| macOS 26+ direct-distribution candidate | Accepted native packet authority/identity and independent-runtime handoff, public original-destination/process evidence for the chosen path, preventive UDP exclusion, conditional DNS ownership, packaged rollback and real-host visibility matrix | `UnsupportedPendingArchitecture` / `Unsafe` / `DesignOnly` |

Endpoint-owner tables, socket diagnostics, `NEFlowMetaData`, a resolver API, or
one observed packet are candidate facts only. None alone proves the complete
row.

## Normalized-flow extension

UDP and DNS metadata extend the existing additive/tagged normalized-flow model.
They do not change the accepted `NormalizedFlow v0` artifact. Unknown extension
tags are preserved or rejected according to the consumer's version contract;
no consumer may reinterpret opaque UDP as decoded DNS.

The extension carries only UDP/DNS-specific projection fields and a closed
`Arch004RecordRefV1` to the immutable source record. The typed locator binds
partition, key, revision, canonical digest, and schema but never embeds the
source body or a descendant reference, preventing a digest cycle. It does not duplicate host flow/session/transport,
destination, process, or timing fields. The source
`DatagramFlowV1.identity.flow_id` is byte-for-byte the enclosing host flow ID,
and every unavoidable common projection must equal the host value. Mismatch is
invalid rather than resolved by precedence, preventing storage and analyzer
association from diverging.

## Rejected alternatives

### Treat every port-53 packet as visible DNS

Rejected because ports can carry malformed or non-DNS data, encrypted transports
can use other ports, and routing/interception does not prove successful decode.

### Infer DoH, DoT, or DoQ from endpoint, SNI, ALPN, or QUIC

Rejected because those are outer-transport observations and can produce false
visibility claims without a supported plaintext decoder.

### Fall back to direct UDP when a proxy lacks support

Rejected because it leaks policy-incompatible traffic and misreports the
selected egress. Direct fallback must be separately requested and sealed.

### Use the UDP five-tuple as permanent identity

Rejected because NAT rebinding, tuple reuse, idle expiration, interface change,
and runtime restart make it ambiguous.

### Persist full DNS packets or names by default

Rejected because DNS reveals browsing and application intent. The baseline is
metadata-only and exact-name persistence is explicit.

### Let parser failure break all connectivity

Rejected because visibility is subordinate to connectivity when forwarding is
otherwise policy-safe. Decode failure becomes opaque; path or leak-proof failure
still fails closed.

## Verification obligations

Deterministic tests cover the complete tagged unions, tuple reuse, both
directions, IPv4/IPv6, counter overflow, idle and hard closure, loss, reorder,
fragmentation, malformed DNS framing and compression, multi-question bounds,
correlation collision, unmatched/retransmitted/truncated responses, encrypted-
opaque truth, privacy modes, every resource limit, every upstream policy, stale
capability evidence, and all crash/rollback boundaries.

They also cover flow/transaction revision forks and terminal absorption,
cross-plane duplicate counting, aggregate connection/buffer exhaustion,
receipt signature/scope/one-use replay, resolver-binding equality and bootstrap
cycles, all invalid payload/mechanism pairs, redacted correlation commitments,
the full RFC 9250 DoQ predicate and negatives, normalized-host-field mismatch,
`with_quic`/stub behavior, and the pinned native DoH/H3 response-bound blocker.

Coverage also includes independent per-direction and all-flow occurrence
ordinals, QR/opcode mismatch, query/response completion-evidence separation,
every hook-bearing/outer-only host-association transport, typed DoQ response/FIN
evidence and native request/response token, mixed-scope
atomic question projection, resolver use-site keying and `RequireBoth`, exact
zero/nonzero resolver branch and predecessor source, ten-cell sealed-mechanism/
HTTPS-carrier equality, evidence use-site/kind/body/context/signer/journal-role
mapping and cycle rejection, direct-path no-send publication, all five resource tuple
substitutions, Windows/resolved/NetworkManager CAS and rollback races, macOS and
native-intercept zero-mutation refusals, recovery forks, raw-fragment flood/
retention transfer, global capacity snapshot/head CAS, semantic retention,
journal preallocation/revisioned append/deletion, typed compaction refusal,
digest-DAG and recursive-accounting refusal,
claim reason/disposition mapping, and capacity early/double-release failures.

Capacity conformance also covers the exact global-WAL genesis and nine-entry
tuple/participant projections, fresh-nonce same-revision retry, body/Prepare/
each-target/Abort/cleanup/Commit crash matrix and the complete legal two-slot
recovery table. It expands every flat validation-capsule member byte-for-byte,
checks `C = N + 1` and `D = N + 2` boundaries and proves non-recursive
long-term validation. Tag `0x400D` tests exercise current-Prepared and settled-
Active branches, exact publication-time binding, suffix completion, Abort
cleanup and successor settlement. Budget vectors charge exactly two complete
global WAL slots once in the ledger total, zero WAL in the replay total, every
physical capsule copy and the larger final-decision arm, with exact-max,
one-byte-under and checked-overflow negatives.

Real-host release gates prove the exact claimed matrix using synthetic names and
payloads. They enumerate OS resolver, route/rule, TUN, socket, process, runtime,
helper, and journal state before, during, and after start/stop/crash/recovery;
prove zero unintended direct DNS/UDP path; and compare ordinary connectivity to
the ARCH-001 baseline.

## Primary references

- [RFC 768](https://datatracker.ietf.org/doc/html/rfc768) defines UDP framing.
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html) defines DNS message,
  name, UDP, TCP, truncation, and transaction-ID basics.
- [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html) defines DNS over TCP.
- [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html) defines DNS over TLS.
- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) defines DNS over HTTPS.
- [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) defines DNS over QUIC.
- [RFC 8085](https://www.rfc-editor.org/rfc/rfc8085.html) supplies UDP usage and
  source-validation guidance.
- Pinned sing-box 1.13.19 revision
  [`b5ebaa1fc0f2b94256180b95468e73ef53caa27d`](https://github.com/SagerNet/sing-box/tree/b5ebaa1fc0f2b94256180b95468e73ef53caa27d),
  especially its [DNS option schema](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/dns.go),
  [DNS transport tags](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/constant/dns.go),
  [HTTPS DNS transport](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/https.go),
  [HTTP/3 DNS transport](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/dns/transport/quic/http3.go),
  [`with_quic` registration](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/include/quic.go),
  [non-QUIC stub registration](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/include/quic_stub.go),
  [DNS sniffer](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/sniff/dns.go),
  [route actions](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/rule_action.go),
  and [TUN option schema](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/tun.go).

These sources define protocol or candidate runtime primitives. They do not by
themselves prove FlowProbe transaction, visibility, loop, privacy, or support.

## Compatibility and migration

FlowProbe is unreleased. This decision directly replaces incomplete v0.x UDP
metadata assumptions and adds no compatibility shim, alias, or migration.
Production compatibility requires a separate explicitly authorized task.
