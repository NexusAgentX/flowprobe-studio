# ADR-0005: Egress selection and loop prevention

Status: Accepted

Task: ARCH-002

## Decision scope

FlowProbe will represent product-owned egress as one explicit tagged selection,
prove that exact selection before system-network activation, and maintain a
fail-closed exclusion set for every FlowProbe-owned network path. External HTTP,
HTTPS, and SOCKS5 proxies are protocol choices rather than aliases for direct
egress. Full-tunnel and proxy-only capture are separately reported network
scopes; neither is an implicit fallback for the other.

This decision defines the `egress.*` extension reserved by ADR-0004. It defines
selection, protocol behavior, local-listener identity, capability reporting,
pre-activation proof, loop-exclusion resources, commit predicates, sustained
health, and verification obligations. It does not implement those mechanisms,
change an existing accepted artifact, or claim that any release platform is
currently supported.

The normative types and predicates are in
[`egress-and-loop-prevention.md`](../contracts/egress-and-loop-prevention.md).

## Preserved architecture

This ADR preserves the frozen decomposition:

- sing-box remains an independent managed Network Runtime process and the
  functional Network Plane owner;
- Capture Core remains protocol-oriented and independent from sing-box
  internals;
- the Config Compiler, not user configuration, owns protected
  `__flowprobe_*` routes, outbounds, marks, and loop rules;
- the privileged helper remains the only authority for journaled operating-
  system mutations and recovery; and
- raw or normalized traffic remains source material while semantic analyzer
  output remains derived and rebuildable.

Selection does not move proxy protocol code into Capture Core. Capture Core may
request an already-defined egress connector through a versioned boundary; the
Network Runtime owns direct and proxy dialing. The helper may apply typed
exclusion resources and verify OS evidence, but it never becomes a proxy client
or receives captured traffic.

## Observed baseline and support truth

The current runtime API exposes only `probe_direct_egress`. Its capability set
is boolean, the fake probe can return only `Ready` after process start, and the
real sing-box adapter advertises direct egress while returning typed unsupported
for that probe. Current real-runtime proof uses loopback-only HTTP proxying,
forbids TUN and system route changes, and intentionally proves no direct-egress
probe. Runtime survival and configuration validation therefore prove neither a
selected egress path nor loop prevention.

The current Capture Core accepts an already-connected upstream stream. Its
optional normalized-flow process attribution is observation metadata, not
listener ownership or exclusion authority. No production compiler currently
turns a typed exclusion plan into OS enforcement.

ADR-0004 independently leaves every full-tunnel platform unsupported because
the accepted independent external-TUN attachment and first-packet
`ResumeBarrier` are absent. This ADR does not remove those blockers. A host can
implement every decision below and still remain
`UnsupportedPendingArchitecture`/`Unsafe`/`DesignOnly` for full-tunnel use.

## Product request is a pair, not one mode

Each activation request binds both:

1. a `NetworkScope`: `FullTunnel` or `ProxyOnly`; and
2. one `EgressSelection`: `Direct`, `ExternalHttp`, `ExternalHttps`, or
   `ExternalSocks5`.

`FullTunnel` means the accepted system-network transaction steers the requested
host traffic into FlowProbe. `ProxyOnly` means only applications explicitly
configured to use the FlowProbe listener enter the capture path and no claim is
made about system-wide traffic.

The prepared plan, active status, journal, lease evidence, and diagnostics bind
both values. A failure to support full-tunnel exclusion cannot be reported as a
degraded full-tunnel session. Proxy-only operation is permitted only when it
was requested initially or the user explicitly accepted a newly prepared
`ProxyOnly` request after the full-tunnel request was refused. The resulting
active mode is always reported as `ProxyOnly`, with the refused request retained
only as bounded diagnostic context.

## Closed tagged egress model

The accepted selection union is closed:

```text
Direct {
  destination_resolution,
  timeout_budget,
}

ExternalHttp {
  proxy_endpoint_policy,
  authentication_ref?,              // Supervisor/runtime boundary only
  cleartext_credential_policy,
  destination_resolution,
  timeout_budget,
}

ExternalHttps {
  proxy_endpoint_policy,
  authentication_ref?,              // Supervisor/runtime boundary only
  proxy_tls_policy_ref,
  destination_resolution,
  timeout_budget,
}

ExternalSocks5 {
  proxy_endpoint_policy,
  authentication_ref?,              // Supervisor/runtime boundary only
  cleartext_credential_policy,
  destination_resolution,
  udp_policy,
  timeout_budget,
}
```

`proxy_endpoint_policy` independently binds the outer proxy endpoint resolver
and IP-family policy. `destination_resolution=LocalAddress` carries its own
resolver and destination-family policy. `ProxyName` deliberately reports the
proxy-resolved destination family as `ProxyOpaque`; FlowProbe cannot promise a
client-enforced IPv4/IPv6 outcome it cannot observe. SOCKS5 UDP inherits that
single destination policy and has no second conflicting resolution/family knob.

Unknown tags and fields are rejected. SOCKS4, SOCKS4a, HTTP forward-proxy
absolute-form requests, opportunistic proxy TLS, generic sing-box selectors,
user-defined outbounds, and UDP-over-TCP extensions do not satisfy these tags.
They require a later explicit architecture decision.

Selection is exact. The runtime MUST NOT silently replace:

- an external proxy with direct egress or another proxy protocol;
- HTTPS proxy transport with plaintext HTTP;
- proxy-side destination resolution with local resolution, or the reverse;
- an outer proxy or locally resolved destination family outside its exact
  policy, or any concrete destination-family claim for `ProxyOpaque`;
- SOCKS5 UDP association with direct UDP, UDP-over-TCP, or a drop reported as
  success; or
- full-tunnel scope with proxy-only scope.

A caller may explicitly request a different selection after a typed refusal.
That produces a new plan and generation; it is not runtime fallback.

## Ownership of the egress path

| Responsibility | Owner |
| --- | --- |
| Render bounded selection/status UI under a preventive no-external-socket sandbox | Renderer; never an authority source |
| Turn authenticated user/admin policy into signed, exact risk and probe-target authorization receipts | Trusted product-policy broker; never renderer |
| Validate typed user intent and publish exact requested/active state | Supervisor |
| Resolve opaque credential/trust-material handles and perform one plan-bound delivery to the private config materializer for the exact sealed runtime instance | Supervisor-side secret/trust brokers; never renderer or helper |
| Compile protected egress tags, connector graph, and runtime loop rules | Config Compiler |
| Materialize/delete the fixed private runtime artifact and start the independent process through the ARCH-001 gate | Network Runtime adapter |
| Direct dial, HTTP CONNECT, TLS-to-proxy, SOCKS5 negotiation, destination transport, and runtime socket creation | Network Runtime |
| Capture protocol streams and hand them to the versioned egress connector without knowing sing-box internals | Capture Core |
| Sign immutable, exact-tuple TLS and non-TLS capability real-host release evidence under a compile-time trusted release-key registry | Release Verifier; plan-independent and unable to sign live/runtime observations |
| Discover baseline/interface state, local listeners, and live capability/readiness evidence | Typed platform backend under Supervisor/helper orchestration |
| Apply, read back, lease, compensate, and recover privileged `egress.*` resources | Privileged helper authority |
| Keep the loop gate closed on owner death, unsafe drift, boot, or suspend epoch change | Helper/watchdog fence domain |

Every live trust-boundary component is registered in the plan before activation,
including Renderer, policy broker, Supervisor, secret/trust brokers, Config Compiler, runtime
adapter/runtime, Capture Core, platform backend, helper/watchdog, and each
accepted local external proxy. Each either declares all external network paths
or supplies preventive `NoExternalNetworkPath` evidence. Proof and health are
purposes on the component that really opens the socket, not fictional actors.
DNS or UDP actors registered later by ARCH-004 join the same exclusion set when
they use the selected egress.
The Release Verifier is deliberately not a live actor: its Ed25519 identity is
accepted only through the compile-time release-key registry and only for the
immutable registered TLS-verifier and non-TLS capability-evidence roots (tags
49 and 53). It cannot sign a capability
report, runtime readiness, plan observation, TLS handshake, or health result.
A TLS capability becomes `RealHostVerified` only when the live backend report,
the release-signed exact OS/package/backend/adapter evidence root, the package
manifest build identity, and the runtime handshake stack identity all
cross-bind byte-for-byte.
Every other `RealHostVerified` capability likewise requires a release-signed
tag-53 root whose key, mechanism/version, backend/package/platform, covered
scope/enforcement, implementation build, and passed real-host suite match the
live report and package manifest exactly. Live capability, endpoint-resolution,
local-proxy-identity, and baseline-anchor roots are instead signed by the typed
platform backend under a helper-issued pre-plan ticket/session/generation/
nonce/boot/suspend/channel binding before their digests enter the one-way
candidate-plan DAG. Tag 54 is the unsigned closed isolation policy descriptor
and binds an exact release-verified `ActorNetworkIsolation` capability report.
An already-live networkless actor may additionally carry a pre-plan tag-55
readback in the graph; a newly allocated actor carries only the instruction to
start inert with tag 54 attached, never a future readback digest. Regardless of
that initialization branch, every networkless actor must have a fresh dual-
signed preactivation tag-55 checkpoint accepted before it executes, sends local
IPC, emits a protocol byte, or precedes a shared OS mutation. Fresh tag-55
postactivation/renewal readbacks are likewise jointly signed by the platform
backend and helper and do not feed back into the sealed graph.

### Pinned sing-box mapping

The protected compiler mapping targets the repository's pinned sing-box
1.13.19 revision, not a rolling documentation default. These are structural
targets only, not capability claims:

| Product tag | Protected runtime mapping |
| --- | --- |
| `Direct` | `type=direct` with an explicit accepted bind/protect policy |
| `ExternalHttp` | `type=http`, TLS disabled, HTTP CONNECT only |
| `ExternalHttps` | `type=http`, TLS enabled with the sealed proxy identity/trust policy, HTTP CONNECT only |
| `ExternalSocks5` | `type=socks`, explicit `version=5`; `udp_policy=Disable` emits only `network=tcp`, while `RequireAssociate` emits only `network=tcp,udp`; UDP-over-TCP disabled |

The compiler emits protected `__flowprobe_*` tags and rejects user redefinition.
It MUST NOT use a generic detour that causes sing-box to ignore the outbound's
binding/mark fields, depend on SOCKS default version or network values, or treat
`auto_detect_interface`, `find_process`, a process/path route matcher, or a
successful config check as FlowProbe exclusion evidence. Rolling sing-box
documentation is discovery-only, not a normative source here; fields added
after the pin do not enter this contract until the runtime pin and architecture
are deliberately updated.

The pinned built-in HTTP client does not implement the contract's complete-2xx,
sealed Basic exchange, bounded 407, and safe-error semantics. Its public-key-pin
TLS option enables insecure verification rather than the required AND condition.
Its pinned Go 1.24.7 public TLS state does not expose the negotiated group or
server-authentication signature scheme, and its defaults offer values outside
the contract's closed ClientHello policy; it therefore cannot manufacture the
required TLS observation from public state.
Its SOCKS UDP path does not provide the required literal-relay locality/source/RSV/FRAG
checks. The current compiler/runtime and Go clients also do not prove the
specified credential containment and zeroization lifecycle. Therefore emitting
the table above cannot make the affected path Ready: a separate versioned,
packaged adapter plus the contract's fake and real-host gates is required.

## Protocol decisions

### Direct

`Direct` opens the destination transport through the sealed baseline egress
anchor, not through the pending FlowProbe TUN or a user-defined selector. Each
socket uses an explicit interface binding, route mark plus owned policy rule,
platform protect operation, or another accepted mechanism with equivalent
read-back evidence. Merely omitting an outbound tag is not direct-path proof.

If a hostname must be resolved locally, its resolver path is an explicit
dependency supplied by the ARCH-004 contract. Absence or policy incompatibility
is a typed refusal; it never triggers an ambient system lookup hidden from the
plan.

### External HTTP

`ExternalHttp` establishes a plaintext TCP connection to the configured proxy
endpoint through the baseline egress anchor, then uses HTTP CONNECT with an
authority target. Only a complete 2xx response establishes the tunnel. Bounds
apply to status/header bytes, field count, authentication rounds, and total
handshake time. A non-2xx response, malformed framing, excess data, or timeout
is a typed failure. Proxy credentials are injected from a secret reference only
at the exact unprivileged protocol-consumer boundary and are never journaled or
returned in diagnostics. The
helper-visible plan binds only a non-authorizing credential descriptor digest;
the credential handle itself is excluded because it may be a bearer capability.
HTTP Basic over plaintext requires a separately recorded explicit risk
acceptance. That acceptance is a signed, installation/preparation-ticket/
session/generation/proxy/credential/policy-bound receipt from the trusted policy
broker. It signs a receipt-free authorization scope, so profile construction has
no digest cycle; the helper one-use record binds first consumption to one
candidate plan and permits only its exact idempotent replay. Renderer input or a
copied digest cannot mint it. Without a valid receipt the request is
`PolicyProhibited` before any socket or mutation.

FlowProbe does not implement HTTP absolute-form forwarding under this tag.
HTTP CONNECT is a byte-stream tunnel and does not carry UDP. Any selected policy
that requires UDP through `ExternalHttp` is unsupported before mutation.

### External HTTPS

`ExternalHttps` first authenticates a TLS connection to the proxy endpoint,
then performs the same bounded HTTP CONNECT exchange inside that connection.
The configured proxy hostname or literal IP is the TLS reference identity; DNS
aliases and resolved addresses do not replace it. SNI, certificate path,
hostname or IP matching, validity, the fixed algorithm/key-size policy, TLS
minimum/maximum, HTTP/1.1-or-absent ALPN, leaf-SPKI pins as an additional AND
condition, and explicit revocation policy are sealed by
`proxy_tls_policy_ref`. A DNS identity sends its exact A-label as SNI; an IP
identity sends no SNI. TLS 1.2/1.3 cipher suites, groups, certificate algorithms,
TLS 1.2 `ServerKeyExchange` signature/hash pairs, and TLS 1.3 server
`CertificateVerify` signature schemes are closed lists; early data,
renegotiation, and resumption are disabled in v1. A TLS 1.2 ECDSA signature pair
does not encode or prove a certificate curve. Exactly one ClientHello is
allowed: TLS 1.2 legacy session ID/ticket, TLS 1.3 PSK/PSK-mode/early-data, and
all unknown extensions are absent, the complete extension order is observed,
and a HelloRetryRequest is rejected without sending a second ClientHello.
When a mixed TLS 1.2/1.3 offer negotiates TLS 1.2, the client also rejects both
RFC 8446 ServerHello downgrade sentinels and records only the closed successful
check, never the raw random value.
When TLS 1.2 is offered the fixed cipher list ends with the empty-renegotiation
SCSV and a successful TLS 1.2 server must acknowledge empty secure
renegotiation. The ClientHello also carries the empty extended-master-secret
extension, and successful TLS 1.2 requires server echo plus EMS derivation; TLS
1.3 records both checks as not applicable.
Passed evidence carries closed reference-identity, path, time/usage, every
validated path-key/signature algorithm, revocation, and pin results and proves
they correspond to the offered/negotiated ClientHello values.
For TLS 1.2, an ECDHE_ECDSA suite accepts only an ECDSA/Ed25519 leaf and a
matching ECDSA/Ed25519 `ServerKeyExchange`; an ECDHE_RSA suite accepts only an
RSA leaf and matching RSA-PSS-RSAE or RSA-PKCS1 `ServerKeyExchange`. Every
cross-family combination is rejected. TLS 1.3 cipher suites remain independent
of authentication, with the leaf/signature relationship still checked exactly.
The fixed TLS 1.2 supported-group image permits only P-256/P-384 ECDSA leaf
keys; P-521 is therefore rejected in TLS 1.2 while remaining available through
the exact P-521/SHA-512 TLS 1.3 signature scheme.
The recorded selected anchor is the actual terminal anchor of the validated
path and must be a member of the exact context-bound system snapshot or private
anchor descriptor and of the exact loaded set; a substituted or filtered-out
FlowProbe anchor cannot produce `Passed`.
Certificate validity uses one OS UTC wall-clock sample whose corresponding
helper-domain monotonic tick and boot/suspend epochs are carried inside the
runtime-signed handshake root. The sample is not described as independently
authenticated time. Every certificate in the path uses that same value, and a
read failure, epoch mismatch, or detected wall-clock discontinuity fails closed;
a runtime implementation unable to detect discontinuity keeps `ExternalHttps`
unsupported.

An untrusted certificate, identity mismatch, unavailable required revocation
evidence, or TLS downgrade is a refusal. There is no opportunistic plaintext
retry and no global trust-all switch. Upstream-proxy TLS trust is independent of
ARCH-003's local interception CA; installing or trusting FlowProbe's local CA
must not cause an external proxy certificate to be accepted.

System trust is a short-lived, revision-bound filtered snapshot, not an ambient
runtime default. Before sealing, request-only anchor/pin handles resolve to
non-authorizing content descriptors and expected observation schemas; the plan
never binds a future result. After each phase challenge exists, the trust broker
also signs a plan/generation/context-bound effective-trust observation over the
fresh snapshot. Preactivation binds the sealed snapshot; postactivation and
renewal permit only a newly observed snapshot with identical security fields
apart from its bounded time window. After `Prepared`, the trust broker signs one
plan/node/slot/channel-bound delivery record, the Network Runtime signs the
exact loaded state with ambient reads/reload disabled, and the Runtime Adapter
independently signs the exact materialization and post-load artifact absence.
The Runtime copies bounded material into private non-file-backed memory and
proves zero remaining artifact handles and file-backed mappings before the
adapter removes the pathname; current-state evidence repeats both zero counts,
and adapter evidence is explicitly limited to adapter-owned handles/mappings.
The artifact is removed before proxy TLS begins. Each proxy connection then
produces a context-bound runtime-signed handshake root with the actual
ClientHello policy image, server-authentication scheme, negotiated values, and
bounded outcome. Preactivation, postactivation, and renewal use distinct
nonce/marker/lease/fence contexts; later checkpoints re-sign current loaded
state and current artifact absence without redelivery or reload. System-root
mode also revalidates the exact store revision and filtered anchor set. The
plan/journal retain only registered descriptors, signed safe roots, and digests,
never handles, raw anchors, certificates, or transcripts.
The runtime load root repeats its authenticated external-gate channel binding
in its signed body, and the adapter artifact root must repeat that same value.
This load-ack/control channel is domain-separated from the broker-to-materializer
delivery channel; signer-header, load-root, runtime, or artifact substitutions
fail closed.

The pinned sing-box 1.13.19 TLS options expose no revocation-status enforcement
surface. `RequireFreshOcsp` is therefore explicitly unsupported in contract v1;
enabling it needs a later accepted contract that also closes responder egress and
SSRF authorization, not only a runtime adapter.
`NoOnlineCheck` is reported honestly and never renamed “platform default”. A
future ARCH-003 identity-set digest is an input only for filtering FlowProbe-
owned anchors; this ADR does not predefine CA/store semantics.

Like `ExternalHttp`, this tag carries TCP tunnels only. It does not imply
CONNECT-UDP or any other datagram extension.

### External SOCKS5

`ExternalSocks5` implements only SOCKS version 5. It negotiates either no
authentication or an explicitly configured supported method. Username/password
credentials, when selected, are secret-referenced and are never logged. A
server-selected method not offered by the request is unsupported.
Username/password over plaintext SOCKS5 also requires the same explicit
cleartext-credential risk acceptance.

TCP uses SOCKS5 `CONNECT`. Destination resolution is explicit: `ProxyName`
sends a domain-name address to the proxy, while `LocalAddress` uses only an
address returned by the sealed resolver dependency. A failed or incompatible
choice never falls back to the other.

UDP is disabled unless `udp_policy=RequireAssociate` and every required
capability and probe succeeds. That policy uses three distinct socket roles.
Role A is the ordinary SOCKS5 TCP connection that performs method/authentication,
one `CONNECT`, the target NonceEcho, and its required peer close. Once CONNECT
succeeds, A is tunnel data and may never carry another SOCKS greeting or command.
Role B is a new TCP connection to the byte-identical sealed proxy candidate. It
starts a fresh greeting at byte zero, repeats method negotiation and the RFC
1929 wire exchange when configured, sends the sole RFC 1928 `UDP ASSOCIATE`, and
remains open for the association lifetime. The same exact runtime may reuse the
credential already held in protected memory, but creates no second broker
delivery or artifact. Role C is the UDP relay child. A/B have distinct epochs,
tag-31 roots, platform identities, socket sequences, route observations and,
for HostLocal, independent connected-peer proofs; their ordering is A < B < C.
Using A as B or sending `UDP ASSOCIATE` in the CONNECT tunnel is invalid rather
than a typed protocol failure.

The policy honors B's returned relay endpoint and accepts only a public-global-
unicast literal IPv4 or unscoped IPv6 relay. A domain-form relay is a typed
terminal unsupported result and starts
neither a resolver nor UDP child. v0.2 does not claim SOCKS5 UDP fragmentation: nonzero `FRAG` is
first dropped and then makes association health fail as unsupported; it cannot
be reported as delivered. The exact runtime may establish a bounded association
during preactivation proof but must close it before the factory's one-way phase
transition. Because v1 defines no authenticated transfer of that socket into the
ResumeBarrier-protected phase, `RequireAssociate` remains
`UnsupportedPendingArchitecture/PreactivationSocketPhaseTransitionUnavailable`;
it cannot retain or silently recreate the association through commit.
Full-tunnel UDP requires an endpoint-independent preventive socket/actor
exclusion; a proxy-selected relay can never create an unsealed privileged route
or rule. `Disable` rejects a request
that requires UDP; `RequireAssociate` rejects lack or loss of the association.
UDP-over-TCP is a different protocol and is not substituted.

The request address is exact: IPv4 role-B control uses `0.0.0.0:0`, IPv6 role-B control uses
`[::]:0`, and neither uses a domain/destination value. Relay datagrams require
zero RSV and FRAG before delivery. The pinned built-in SOCKS UDP client does not
meet these relay and header rules, so `RequireAssociate` remains explicitly
unsupported until a conforming packaged adapter exists.

`RequireAssociate` also requires the sole signed probe-target authorization to
name `NonceEcho` and explicitly authorize the additional SOCKS5 UDP canary
transport; a TCP-only receipt is not widened implicitly. After plan sealing and
exact A target-tunnel, B dedicated-control, and C UDP-relay child plus literal-
relay selection, the helper generates a
fresh association-bound nonce and distinct UDP commitment, durably appends and
fsyncs the helper-signed one-use consumption record, and only then releases the
nonce once to the exact runtime/channel. It is never a plan commitment and is
never reused across TCP/UDP, phase, target, attempt, candidate, either TCP epoch
or child, UDP child, relay, or destination. Record/fsync/delivery ambiguity,
crash, timeout, or response loss
fails closed without redelivery; helper cleanup remains a helper-verified fact,
not a Network Runtime self-assertion.

After A's target challenge passes and closes, B is opened by one bounded atomic
factory operation covering queue/capacity, creation, mechanism/readback, TCP
connect, HostLocal peer proof, signing, sequence/epoch allocation, and
publication. A normal route semantic mismatch or connect refusal/timeout is an
unpublished role-B protocol terminal; a factory-invariant failure publishes no
B phase/child and uses the dedicated control-release abort. A terminal latched
during the operation is drained: success publishes B and immediately terminates
the zero-byte method phase, while factory failure keeps abort priority. An
ordinary route/connect negative completion and a latched cancellation or
deadline instead compete by gate ordinal: completion-first retains the ordinary
unpublished role-B outcome, terminal-first retains `Cancelled`/`TimedOut` on
the active role-B phase, and neither ordering publishes B, retries, or permits a
later event to overwrite the winner. If the
one-shot first-byte guard fails after B publication, a separate guard-abort
binds B, emits zero greeting/authentication/ASSOCIATE bytes, closes B, and keeps
A+B in the permanent creation chain. None of these prefixes retries or changes
candidate after A has consumed the authorized target challenge.

UDP-child creation and guarded release occur after literal-relay classification
and before the canary-send phase. If any factory-local creation, mechanism,
readback, latch, signing, queue-append, sequence, or release invariant fails
before that child is released, tag 50 records the dedicated pre-send abort with
zero nonce/tag-48/datagram material. The attempt's first fresh socket
checkpoint carries the exact `TerminalFailed` latch that uniquely projects the
outer `SocketFactoryInvariantUnproven` failure. Because that factory defect is
the first defect, the cleanup checkpoint must carry the actual residual state
with both censuses Complete and equal; a simultaneous or later negative census
cannot independently replace or wrap the creation failure. If actual state
cannot be proved, no tag-50 or outer wrapper is valid. The runtime
cannot relabel it as a relay or canary protocol failure, retry, or consume
another privileged permit.
Positive relay classification remains pending until the serialized event gate
can atomically commit the passed classification together with either the exact
factory release result or its typed terminal failure. Cancellation, deadline,
or control loss before the full bounded factory operation starts leaves the
relay unselected and the UDP child unpublished. Once that operation has
started, a later terminal event is instead latched without allowing nonce or
payload bytes while the operation drains. A successful drain publishes the
child and projects that latch as the immediate send-phase terminal; a factory-
step failure owns the higher-priority typed pre-send abort. Unprovable drain or
cleanup invalidates the wrapper, and there is no signed gap after a passed
classification.
If C publication succeeds but its one-shot first-datagram guard fails, C remains
in the signed chain, the already-durable tag-48/constructed request is retained
with zero datagrams and no response, and the tag-46 factory failure outranks the
nested canary failure. A pre-publication abort may never hide that released C.

The synthetic request and response each carry the fixed 40-byte FPEG v1
NonceEcho payload inside one exact RFC 1928 UDP envelope. IPv4, IPv6, and domain
destination datagrams are exactly 50, 62, and `47 + name_length` bytes. Passed
tag-50 evidence signs the sole target, attempt, family tuple, candidate,
role-A target-tunnel epoch/child, role-B dedicated-control epoch/child, role-C
UDP child, first-following socket census, literal relay, exact authorized
destination, B control-exchange frame digests, fresh
commitment/consumption record, whole request/response datagram digests, exact
relay source, zero RSV/FRAG, and byte counts. A wrong source, destination,
envelope, or echo nonce/type/length selects one closed typed negative result.
Even a valid consumed echo remains a pending validation result until one final
zero-network gate operation atomically rechecks control/association liveness,
commits both validation and `AssociationReady`, and freezes an immutable
terminal snapshot. A terminal event whose ordinal wins retains the echo evidence
and terminates validation. The winning positive snapshot is not yet the signed
root. A was already closed by the target challenge. Preactivation then closes B
and C so all three roots are chain-present/current-absent; postactivation and
renewal retain this attempt's B and C, leaving its A chain-present/current-
absent. The factory-wide current-open set at a later active-group checkpoint
also retains the B+C pair from every earlier successful group. In quiescent
postactivation that verification projection is the whole set; at renewal it is
disjoint from, and added to, every unrelated live child of the same actor-wide
factory reported by the exact dual census. Any non-success attempt, including one in the first group, controlled-
closes its published children and every B+C pair retained by an earlier group in
the same verification sequence before the terminal attempt's first-following
checkpoint. The cumulative chain remains, but an ordinary negative, timeout, or
cancellation contributes no verification child current-open; unrelated renewal
children remain governed by the same lifecycle/census rules. Required closes
run one child at a time in decreasing socket-sequence order, so C precedes B in
each retained pair. A close failure identifies the first child and whether its
request failed or bounded completion was unproven; cleanup failure instead lets
the factory/census negative take priority when the actual residual state is
authenticated; only unprovable cleanup state yields no valid outer root. The exact
context-required first-following tag-34 census is produced before tag 50 is
signed.

These A/B/C children are verification-only and are never promoted into the
generic UDP data plane. Preactivation closes every published child as part of
the attempt; tag 13's final clean attempt checkpoint is also its sequence-
finalization root. For tag 28 or 29, a failed/timed-out/cancelled protocol
attempt closes its own children and every retained prior B+C pair before that
attempt's first-following checkpoint, so no extra success-side root is added.
After a clean protocol-successful final attempt, however, the traversal and
tag-51/tag-52 predicates are frozen first. Both a positive result and every
structurally valid predicate-negative result then require one later fresh
`Empty` tag-34 finalization checkpoint. `RequireAssociate` marks every retained
B+C pair cleanup-owned and closes it there; other selections create no socket
but still execute the fresh dual census. The checkpoint preserves the
cumulative chain, proves no verification child current-open, and is the probe
factory's top-level outer root. At renewal it retains the exact unrelated
operational set, less only independently serialized ordinary closes; it never
assumes the actor-wide factory itself is empty. A provable close/bookkeeping/
census failure takes priority as a dual-signed factory negative. Failure to
construct, authenticate, or sign the required finalization or outer root yields
no valid wrapper. The next renewal can never inherit a prior verification pair;
operational UDP associations remain a separate ARCH-004 responsibility.

Later loss is durably queued under the same plan-generation acceptance-event
order as outer publication, commit/renewal disposition, factory release, and
completion. Every tag-13 negative has no Open release. A passed tag 13 alone
authorizes one clean tag-34 transition from `FinalizedHeld` to
`Open(VerificationOnly)` for its probe factory; it still cannot authorize an
Ordinary socket. Tags 28 and 29 instead carry factory-ID-ordered predecessor
checkpoints for every applicable actor-wide factory and hold every creation gate.
The probe member proposes `FinalizedHeld -> Open(OrdinaryAndVerification)`;
tag-28 non-probe members propose the sole VerificationOnly scope upgrade, while
tag-29 non-probe members propose only a same-scope authority refresh. A completed
pre-lock ordinary close changes only the factory-local ledger, counter, and
provenance until its release member first dual-authenticates it; it does not
append an independent helper record or advance the disposition tip. An
unresolved close, an independent post-receipt helper append, or a terminal before
completion aborts and fences.

The release authority is a target closed
`FactoryAdmissionReleaseCurrentIndexV1` extension of the installation's sole
ARCH-001 protected index—not a sidecar, second slot set, or second selector. A
pristine installation has `Unset { index_epoch=0 }` only once. A future
registered extension of `PreparePlan` must bind `Unset`, or a fully closed
prior-generation `GenerationClosed`, to non-authorizing `BoundClosed` with the
next epoch and exact plan, generation, complete factory list, and parent journal
tip. Tag 13 leaves it unchanged. The durable tag-28 commit result must change
`BoundClosed` to non-authorizing `ReleasePending(Postactivation)`; the durable
tag-29 `LeaseRenewed` result must change the exact old `Committed` to
non-authorizing `ReleasePending(Renewal)`. Each pending value fixes one batch ID,
the exact outer/ordinals/receipt, disposition tip, suspend-aware observation
time and earliest deadline; Renewal also fixes the prior tag-56 digest and its
paired batch tip. Old tag 56 loses authority as soon as pending is selected.
Only the complete matching tag-56 batch changes pending to `Committed`.
Preparation rollback, stop finalization, fence/recovery, or generation
retirement changes `BoundClosed`, `ReleasePending`, or `Committed` to
`GenerationClosed` only with the core barrier closed and actors stopped/revoked;
a new generation binds only from that selected closed state.

The current accepted ARCH-001 contract has neither these composite transitions
nor a typed authenticated proof query that can return the current extension and
bounded tag-56 record proof to both Supervisor and guards. Its closed `Status`
returns only the safe summary and common head/revision, and callers may not read
the protected journal/index directly or invent an extension field, cache,
sidecar, or second selector. Therefore every current profile remains
`UnsupportedPendingArchitecture` with both
`DurableAdmissionReleaseCommitUnavailable` and
`AdmissionReleaseProofReadUnavailable`. A separate ARCH-001 architecture task
must register the state transitions, authorization/idempotency/recovery, and
proof-read request/result/reconnect rules. The model here constrains that future
work; it does not authorize an ARCH-002 implementation to bypass the frozen
helper boundary.

In that target model, a release batch consumes the exact selected pending
disposition tip as its CAS base, stages every factory-ID-ordered tag-34 member
and the helper/watchdog-signed tag-56 completion, and advances one transaction-
local head/revision per record. The helper persists the vector and inactive slot
of the one copy-on-write composite index, then uses its sole durable selector.
Until that selector, `ReleasePending` remains authoritative and neither the old
release nor candidates authorize a child. Selector commit publishes the entire
vector, changes pending to `Committed`, and advances the outer revision to
`R + member_count + 1`; there is no partial prefix or per-factory
acknowledgement. A pre-selector crash or batch failure is unresumable: candidate
tails are ignored/quarantined and pending fences through cleanup to
`GenerationClosed`, without a replacement batch ID. A post-selector crash reads
the whole new value or fences; no request replay repeats an index transition.

The coordinator holds the acceptance-event gate and every factory lock while it
reserves tag-56 time/ordinal, signs, persists, and checks an uncached helper
clock immediately before selector write. After durable selector acknowledgement
it checks that clock again before any return, product acceptance, or guard
release. Crossing any bound keeps the gates closed and fences the historical
Committed value. Even after a successful post-check, the same gate is atomically
handed to the health/fence consumer, which drains every terminal ordered after
completion but before handoff. A nonempty drain fences without opening; only an
empty drain releases all factory locks and the global gate. Every later Ordinary
publication acquires that exact gate, drains earlier events, and revalidates
proof/freshness before its atomic child publication, so terminal-first blocks
the child and admission-first makes the terminal the next health event. There is
no unowned selector-to-first-byte interval. A missing proof query, stale census,
unprovable cleanup, undrained event, clock failure, or signing timeout yields no
Active/healthy acceptance or Ordinary release.

Replay, a second datagram, or cross-context substitution instead invalidates the
evidence and forces the enclosing transaction to fail closed; it cannot be
converted into a valid outer `Failed` or generic success.

ARCH-004 owns generic datagram identity, DNS routing and visibility, and
detailed UDP/DNS policy. It must reuse this selection and exclusion contract;
it cannot weaken the no-leak rule.

The compiler counts A and B as independent occurrences under the same 60-second
overall and 256-KiB protocol ceilings: B repeats connect, method negotiation and
wire authentication without resetting either budget. C's full child-factory
operation through the final association-ready gate—and, for the last successful
active group, through the close-only checkpoint—is one additional
`target_challenge` occurrence under that same overall deadline and does not
reset between its steps. The compiler also sums both-direction maximum
conforming bytes for every legal A+B+C decision-tree path, including both TCP
sessions and the full UDP envelopes; insufficient normal-path capacity rejects
sealing, while hostile over-bound input uses only the phase's closed failure.
Socket planning likewise counts three new children for every reached
association attempt, the exact in-sequence peak of retained B+C pairs across
required family groups, and the complete serial-tree new-child total. Static
sealing rejects a policy whose configured maxima cannot fit that tree even from
an otherwise empty factory. Live occupancy is resolved separately: before every
verification sequence and before any attempt child or protocol byte, one
sequence-scoped admission transaction drains any earlier Ordinary operation,
takes complete/equal factory and independent OS censuses, and requests an exact
reservation for the current actor-wide open count plus incremental peak and the
current lease-new count plus complete-tree total. Existing non-verification
children and earlier lease-epoch creations count. A fitting request transitions
`Open -> Exclusive(Running)` and reserves one contiguous child-sequence interval;
a dynamic open or cumulative limit failure transitions directly to a typed
terminal admission root, with open-limit priority when both fail. New Ordinary
creation is held while Exclusive; existing sockets may continue and close, with
every close serialized into the next checkpoint. Reserved A/B/C children alone
consume the reservation in exact role/order, so an ordinary close cannot lend
capacity and no limit can first be discovered after A sends bytes. Finalization
consumes no further reservation; only the later authorized Open release returns
the unused suffix, and it allocates no skipped sequence. Successful
cleanup leaves no verification child current-open for the next sequence while
preserving all historical chain roots.

## IPv4, IPv6, DNS, and time bounds

Each FlowProbe-resolved object has its own address-family policy:
`Ipv4Only`, `Ipv6Only`, `PreferIpv4`, `PreferIpv6`, or `RequireBoth`. The outer
proxy endpoint and a locally resolved tunneled destination are never conflated.
Preference permits a bounded, ordered attempt over an already sealed candidate
set; it does not permit an unbounded resolver race. `RequireBoth` requires
independent path proof and loop evidence for both families. A `ProxyName`
destination is `ProxyOpaque` and cannot satisfy a client-enforced family claim.
Future per-flow results are observed under a sealed resolver policy rather than
invented in the activation plan.

V1 seals exactly one probe target and executes its derived connector/destination
family tuples and candidate pairs serially. A later attempt is permitted only
after the prior socket is closed and a fresh complete/equal factory-versus-OS
census checkpoint is accepted. Only an early bounded connect timeout,
`ConnectionRefused`, `NetworkUnreachable`, or `HostUnreachable`, before any TLS,
authentication, credential, challenge, or other application-protocol byte, may
retry the same candidate or advance the sealed candidate sequence. A mechanism,
route/read-back, connected-local-peer, release-guard, queue, signing, or
sequence failure is fail-closed and cannot be converted into candidate fallback.

The proxy endpoint and probe targets are normalized as host plus port, with
literal IPv6 scoped where required. Endpoint resolution records the resolver
dependency, normalized result set, TTL/expiry or equivalent freshness limit,
family, route decision, and digest. A hostname-to-address change invalidates
the prepared observation. Immediately before commit the exact chosen endpoint
is re-resolved or freshness-checked and reclassified as local or remote.

Every connect, TLS, authentication, CONNECT/SOCKS negotiation, target challenge,
and total proof has a positive finite deadline. Counts and byte limits are also
finite: resolver candidates, HTTP head, TLS chain, OCSP material, target data,
per-connection work, and aggregate proof bytes all have contract caps. No API
accepts an infinite timeout. `TimedOut` is itself the closed reason variant; its
bounded phase is inline, while family and endpoint digest come from the
enclosing attempt. It is never encoded as `Failed { error_code=TimedOut }`.

## Pre-activation proof of the actual selection

Configuration parsing and process startup are necessary but insufficient.
During ARCH-001 `Preflighting`, the Supervisor uses the read-only preparation
ticket only to validate and place a bounded `EgressProofSpecification` plus its
expected observation in the candidate graph. It starts no new session-scoped
Network Runtime, Capture Core, or data-plane service; already-running helper,
broker, and discovery components may perform only their typed preflight work,
and the Supervisor does not claim the future proof result already exists. After
the helper seals the exact plan, the runtime adapter uses the ARCH-001 external
gate to start the exact sing-box instance inert. That same authenticated runtime then executes
`EgressPathProof` before any FlowProbe route, DNS, firewall, TUN, or other shared
OS-network mutation. The result is Ed25519-signed under the runtime key bound by
the ARCH-001 gate, using the contract's root-tag/version/role signing domain. It
binds a public 32-byte helper nonce, plan/controller/channel/runtime/package/
config identity, is independently checked, and is durably journaled before the
first privileged mutation. The plan binds the specification/predicate, never its
future result.

The proof:

1. binds to the discovered baseline egress anchor or uses an equivalent
   accepted protect mechanism;
2. proves every serial connection attempt from the sealed actor-wide socket-
   factory invariant, that attempt's exact child observation when a connector
   was released, its first-following accumulator and complete factory/OS census,
   and route/interface evidence; a pre-connector-release `BeforeConnector`
   attempt has no connector child but still
   requires its fresh cleanup census, and merely running before later FlowProbe
   TUN/steering exists is not proof against recapture;
3. resolves the proxy endpoint and target only through sealed resolver
   dependencies;
4. executes the selected direct, HTTP CONNECT, HTTPS-plus-CONNECT, or SOCKS5
   handshake rather than only validating JSON;
5. reaches the exactly one explicitly configured v1 probe target and completes
   its bounded protocol challenge for every required family-success group;
6. records the selected connector tag, family, endpoint/target digests,
   baseline anchor, applied bypass mechanism, route observation, timing, and
   typed outcome; and
7. returns no response body, captured payload, raw certificate, proxy
   authorization field, username, password, secret reference value, or
   unbounded platform text.

There is no mandatory FlowProbe cloud endpoint. A probe target must carry a
signed exact target/port/address-class/challenge/bounds receipt and may be
administrator-hosted, a test-lab fixture, a local-network canary reachable
through the baseline path, or another explicitly trusted target profile. If no
target capable of proving the requested selection exists, the result is
`InteractionRequired`, not a syntactic success.

The target receipt signs a receipt-free target authorization scope bound to the
preparation ticket, session, generation, and policy-broker context; the helper
consumes it for one candidate plan with exact idempotent replay only. V1 rejects
multiple targets or concurrent attempts pending a separate aggregation contract.
`NonceEcho` uses the fixed 40-byte v1 frame and a helper-generated 32-byte target
nonce. Preactivation seals a distinct commitment for every target-family tuple;
the commitment binds the preparation ticket/session/generation, helper nonce,
target, and tuple and is then sealed into the final plan. The selected attempt,
candidate, connection epoch, and child are bound later by its consumption record
and registered challenge-result root. Only the commitment, helper-signed
consumption record, and registered challenge-result root/digest are durable. The record carries a fresh delivery ID and
`ConsumedBeforeWrite` but never the raw nonce. It is journaled and fsynced before
the raw target nonce leaves the helper. The nonce is delivered once per exact
closed phase context in its authenticated plan/runtime/channel/target/tuple/
attempt/candidate/connection/child/commitment/record-bound transient frame and
then zeroized. That frame is the only raw-nonce IPC representation, and it is
never redelivered on response loss or after an ambiguous/crashed write.
Postactivation and every renewal receive a different fresh nonce after their
phase context and exact socket child exist. The helper durably consumes delivery
before sending its first nonce byte. The preactivation commitment deliberately
does not hash the not-yet-computable final plan digest; its one-way inclusion in
that final plan prevents a digest cycle, while the later record/result bind the
final plan and exact attempt.
Postactivation/renewal commitments additionally bind the phase context and
child. Every signed phase result binds the first-following helper/watchdog
accumulator. A partial write or lost
acknowledgement never permits redelivery. V1 probe challenges are only
`TcpConnect` and `NonceEcho`; target TLS probing remains
`UnsupportedPendingArchitecture` pending a separate closed contract.
Every deterministic failed challenge uses the single signed code
`ProbeFailed`; timeout and cancellation remain their own outcome classes.
`ProbePathUnproven` is reserved for the fail-closed orchestration case in which
no valid signed path result exists and never appears inside a runtime phase or
probe outcome.

Proof sockets, endpoint DNS, certificate-status traffic when policy requires
it, and challenge traffic are themselves required loop-excluded paths. Probe
data is a fixed bounded challenge, never a captured request or user credential.
The sealed proof expires on deadline, interface/route epoch change, endpoint
identity change, listener identity change, helper fence change, boot/suspend,
or plan change.

## Separate capability dimensions

Process attribution, local-listener ownership detection, loop exclusion,
physical-path binding, socket-creation enforcement, and independent full socket
census are distinct capabilities. A platform can observe a PID without proving
listener ownership, prove ownership without an enforceable bypass, bind one
factory socket without proving every actor entrypoint is constrained, or inspect
the installed policy without completely enumerating the live socket scope. No
capability is inferred from another.

Every capability report contains:

- `Disposition`: `Supported`, `Unsupported`, `PolicyProhibited`,
  `PermissionRequired`, `InteractionRequired`, `TemporarilyUnavailable`, or
  `Degraded`;
- ADR-0004 `StaticSupport`, `Readiness`, and `Evidence` dimensions;
- mechanism and mechanism version;
- platform/backend/package version scope;
- network scope, address families, transports, actor classes, and endpoint
  locality covered;
- enforcement strength: `Preventive`, `Detective`, or `None`;
- observation freshness and evidence digest; and
- one stable bounded reason code.

`Supported` as a release activation disposition requires
`SupportedByDesign`, `Ready`, and `RealHostVerified` for the exact packaged
platform/mode matrix. Socket-creation and path-binding reports must be
`Preventive`; the independent census report is intentionally `Detective` and is
mandatory in addition to them. Detective evidence alone cannot authorize full-tunnel
activation. Service, helper, or runtime restart is availability evidence only;
it cannot establish exclusion, listener ownership, journal recovery, or path
readiness.

## Local external proxy classification and identity

An external proxy endpoint is `HostLocal` only if its selected address is
loopback, currently assigned to this host in the relevant namespace/
compartment, or delivered by the OS's explicit host-local route class. An
ordinary on-link route, private address, same-LAN host, VPN peer, or gateway is
`Remote`, not local. A backend with no reliable host-local/on-link distinction
reports `Ambiguous`; it cannot invent an open-ended platform-local class. V1
accepts `HostLocal` only for a literal proxy endpoint represented by exactly one
`LiteralNoResolution` candidate. A DNS proxy candidate set containing any
`HostLocal` address, or mixing `HostLocal` and `Remote`, is
`UnsupportedPendingArchitecture/LocalProxyCandidateIdentityMapUnavailable`;
multi-candidate DNS proxy plans are eligible only when every candidate is
`Remote`. The exact selected address is pinned and revalidated before use.

A local endpoint requires `LocalProxyIdentity`. A PID, process name, executable
path string, listener port, socket inode, service name, package name, or one
table snapshot is never sufficient alone. The identity binds:

- address family, normalized local address, port, protocol, namespace or
  compartment, and listener creation observation;
- the OS listener-owner observation and its provenance/version;
- a live process object such as a retained handle or pidfd where available,
  plus boot/process-creation evidence;
- stable executable or platform identity where public APIs provide it, such as
  file identity plus verified signer/package/service identity;
- the policy identity used by the exclusion mechanism, such as an application
  identifier or controlled cgroup identity;
- endpoint-resolution and route epochs; and
- a complete typed platform-backend signature and short expiry, with no opaque
  listener, process, route, or evidence digest.

Discovery is followed by revalidation while holding the same helper/session
serialization boundary used to seal the plan. Immediately before the first
privileged egress mutation and again before commit, the backend re-queries the
listener, proves the retained live process and stable identity still match,
and proves the enforcement policy still targets that identity. Replacement,
PID reuse, executable replacement, namespace move, dual-stack mismatch, closed
handle, or ambiguous multiple owner is `ListenerIdentityChanged` or
`ListenerOwnerAmbiguous` and fails before commit.

Every connection or reconnection adds a second race-closure point after
`connect` and before any TLS, SOCKS, CONNECT, application, or credential byte.
V1 accepts only kernel-established-connection owner evidence. In-band TLS-first attestation is
`UnsupportedPendingArchitecture/ConnectedLocalPeerPreTlsAttestationUnavailable`;
out-of-band cooperation is also unsupported because no fresh socket-bound
attestation root/key/domain is registered. Supporting cooperation needs a
future accepted socket-bound contract and, for in-band TLS, a two-stage pre-TLS
permit and application-byte release contract. Ordinary HTTPS identity alone is insufficient. The socket factory
holds the socket in a no-send state while the backend binds the
established kernel peer to the sealed listener/process/executable/policy
identity. A fresh signed `ConnectedLocalPeerObservation` carries the exact
kernel query mechanism/scope, established connection identity, unique retained
owner, listener, namespace, executable/platform identity, policy identity, and
observation time inline; no unregistered owner hash can release the socket. A platform
without kernel-established-connection ownership must refuse the local path; a
pre-connect port/PID recheck is not a
substitute.

Remote proxy endpoints do not require a local process identity, but they still
require pinned endpoint/route evidence and every FlowProbe-owned actor remains
in the exclusion set. DNS rebinding to a local address changes the requirement
and invalidates the plan.

## Fail-closed loop-exclusion set

The `EgressExclusionSet` is a closed, digested part of the prepared session
plan. It contains one entry for every required actor/path/family/transport and
names both the preventive mechanism and its read-back predicate. The minimum
set is:

- the Renderer, trusted policy broker, Supervisor, secret/trust brokers, Config Compiler,
  runtime adapter, and typed platform backend, each with every path or
  preventive `NoExternalNetworkPath` reference to an unsigned tag-54 actor-
  network-isolation policy plus either an existing signed pre-plan tag-55
  complete readback or an explicit start-inert initialization branch, followed
  in both cases by a fresh dual-signed preactivation tag-55 checkpoint before
  actor execution/IPC/first byte/shared mutation, with complete denied external
  capabilities and bounded allowed local IPC;
- all Network Runtime direct, proxy-control, tunnel, DNS, and UDP sockets used
  by the selection;
- every Capture Core egress connector socket;
- helper, watchdog, and recovery traffic, including any health or certificate-
  status request;
- every preactivation, activation, sustained-health, and recovery purpose on
  the actual actor that opens it; and
- every selected local external proxy process and its TCP/UDP/DNS paths.

For a `HostLocal` selection the graph and both exclusion roots carry the exact
`LocalProxyIdentity` digest and contain exactly one matching
`ExternalLocalProxy` actor; its applicable TCP, UDP, and DNS declarations are
complete under dedicated upstream path purposes. Direct selections and remote
external-proxy selections omit both the digest and actor. Identity or locality
is never inferred from absence.
Because an independently owned local proxy may reach arbitrary upstreams, its
entries use a dedicated all-external-endpoints scope bound to that identity and
preventively cover every external-network-capable socket of its complete stable
worker set. Selected-endpoint enumeration, an extra worker, unsupported
family/transport, or process ownership/compensation by FlowProbe is invalid.

Each entry must bypass the captured path through the sealed baseline egress
anchor using explicit per-socket interface binding, an owned route mark and
policy rule, an OS protect operation, an enforceable process/cgroup/application
identity rule, or another platform mechanism with equivalent preventive and
read-back guarantees. A route observation or process attribution event without
preventive enforcement is `Detective`, not sufficient.

Actor identities are closed inline values: owned components repeat their exact
component/runtime instances, while the sole local-external-proxy variant names
the registered `LocalProxyIdentity` root. Exclusion entries resolve identity
through the actor graph rather than carrying a second arbitrary identity hash.
Endpoint resolution carries its complete bounded alias chain and per-candidate
route/locality facts inline; baseline and local identity roots do the same and
are pre-plan signed. The contract's schema inventory rejects every digest field
that does not resolve to a registered root, an exact ARCH-001 field/domain, or
an explicitly defined content-byte hash.

FlowProbe installs the runtime's actor-wide socket-factory policy once through
one ARCH-001 external permit. The sealed proof specification binds the exact
actor graph, probe Network Runtime actor, runtime instance, component, and probe
factory policy ID. Tag 13, tag 28, and tag 29 project that same tuple; their
NetworkRuntime signatures use its exact `ExternalExecutorGate`, and every
sequence tag-15/tag-31/tag-34 root belongs to that factory and epoch. Another
valid runtime, actor, component, factory, or plan-component signer channel is
not substitutable.

Every later socket is exactly an `Ordinary` bounded data-plane operation or a
`Reserved` verification operation under the installed invariant. Both get one
gap-free sequence and signed child observation before first protocol bytes and
are synchronously enqueued on the pre-sealed bounded append-only multi-reader
observation channel before release. Ordinary creation requires an effective
`Open(OrdinaryAndVerification)` authority plus the current complete tag-56
shared-index batch. Reserved creation instead requires the byte-identical
authenticated `Exclusive(Running)` sequence reservation, contiguous reserved
ordinal, and exact A/B/C role. `FinalizedHeld`, `TerminalHeld`,
`VerificationOnly` for Ordinary use, a staged batch member, or a stale index
releases nothing.
The plan carries separate release-verified capability reports for socket-
creation enforcement, full OS census, and each physical-path mechanism. The
policy and installation root carry the complete factory build identity,
preventive socket-entrypoint policy, policy-root digest, alternate-path census,
release-guard state, and census-barrier state as closed fields rather than
opaque evidence/readback hashes. `SO_MARK` embeds the complete pre-existing
rule priority/table/higher-priority set/resulting baseline route expectation;
every child and checkpoint re-reads that exact tuple.
Helper and watchdog have independent cursors and both receive every child;
capacity follows the slower cursor, and neither performs a per-child release
decision. Preactivation children bind the redeemed external gate, sealed
factory, while the helper independently proves from its journal that no shared
steering intent/resource exists. Before steering, all preactivation sockets are
closed and a factory/OS census proves none remain; an irreversible factory latch
then binds the closed ARCH-001 `ResumeBarrier`. The latch counter increments for
every accepted lease/fence tuple and protected children bind the current open
barrier read-back. Cross-phase socket reuse is unsupported. Socket creation
limits are cumulative within a lease epoch. Queue loss, full,
timeout, or any bind/read-back failure closes the no-send socket, terminally
fails the factory epoch, and sends zero protocol or credential bytes. No child
reuses the consumed permit. At proof, pre-commit, and renewal checkpoints the factory and
platform backend independently construct the same canonical open-socket set
under one helper challenge and linearization barrier. Factory, platform backend,
and helper co-sign the installed policy observation; every later platform census
also freshly re-reads the exact enforcement instance and complete alternate-
entrypoint surface. The platform receives no
expected digest/list; equal signed roots, stable lifecycle counters, exact child
provenance, and the gap-free accumulator are all mandatory. Missing/duplicate
sequences, alternate raw dialers, an unmatched OS socket, factory restart, or
observation-channel loss closes the gate. A platform that cannot enforce this
local factory invariant remains `UnsupportedPendingArchitecture`.

The compiler and helper must prove set completeness against the selected mode's
registered actor graph. Omitting one actor, family, transport, endpoint, DNS
path, or helper/probe path is a pre-commit failure. No path is allowed to
use the future/pending TUN during proof. Unsupported UDP or DNS is
blocked or refuses activation according to the explicit policy; it never
escapes through direct egress.

## Platform mechanism decision

The following mechanisms are architecture candidates, not support claims:

| Platform | FlowProbe-owned socket candidate | Local external proxy candidate | Current result |
| --- | --- | --- | --- |
| Windows 10 build 19041+/Windows 11 x86_64 | Per-socket `IP_UNICAST_IF`/`IPV6_UNICAST_IF` or an accepted WFP/route equivalent, bound to an observed stable interface/compartment; family-specific values, IPv4 wire order, both call results, option read-back, and route read-back are exact. WFP application identity may be an enforcement input but path strings are not stable ownership | Owner-PID/module listener tables locate a candidate; bind-creation observation, retained process handle, process creation, file/signer or package evidence and an enforceable WFP/cooperative interface-binding policy must all agree. Owner PID or `ALE_APP_ID` alone is insufficient | `UnsupportedPendingArchitecture`/`Unsafe`/`DesignOnly`; no reviewed implementation proves the complete full-tunnel exclusion set, conforming pinned bind adapter, external runtime attachment, resume gate, or real-host canaries |
| Linux release-tuple candidate | One sealed no-fallback `SO_BINDTOIFINDEX` or `SO_BINDTODEVICE` branch and/or exact `SO_MARK` plus helper-owned policy rule/table, all with full option/route read-back; any mark and table are generation-scoped resources | `sock_diag` tuple/cookie/inode evidence locates the socket; pidfd, process-start/executable identity, namespace, optional permission-gated duplicated listener FD, and a helper-controlled cgroup or cooperative socket mark/binding must be revalidated. PID, socket inode, UID, unit, or cgroup name alone is insufficient | `UnsupportedPendingArchitecture`/`Unsafe`/`DesignOnly`; release tuple, minimum kernel/permission policy, exact no-fallback bind/cgroup/mark enforcement, external runtime attachment, resume gate, and real-host canaries are unselected or absent |
| macOS 26+ direct-distribution candidate | Network.framework `requiredInterface` can bind only connections created through that framework; BSD `IP_BOUND_IF`/`IPV6_BOUND_IF` are candidates for other FlowProbe-owned sockets. The pinned sing-box/Go path must prove its own binding/read-back; interface identity and route epoch must still be observed | No accepted public mechanism in the reviewed design proves stable arbitrary local-listener ownership and forces that process's complete egress outside a native full-tunnel route. Cooperation cannot be assumed | `UnsupportedPendingArchitecture`/`Unsafe`/`DesignOnly`; local external-proxy full-tunnel activation is explicitly unsupported until a public, packaged, real-host-verified mechanism is accepted, in addition to ADR-0004 blockers |

On Windows, only a TCP owner row in `MIB_TCP_STATE_LISTEN` is a listener;
`GetExtendedUdpTable` is a bound-endpoint snapshot. Interface evidence uses the
GUID/LUID, fresh `MIB_IF_ROW2`, compartment, and live index conversion. Process
identity adds a retained handle/creation time, open-file `FILE_ID_INFO`, and
verified signer/package evidence. WFP `ALE_APP_ID` is a path filtering identity,
not immutable executable identity, and an ALE permit/block does not force a
next hop. IPv4 `IP_UNICAST_IF` set bytes use the documented network order while
read-back is normalized to host order; IPv6 uses host order. A dual-family path
must check both operations. The pinned sing Windows helper ignores one IPv6 bind
error in its unspecified-address path and is therefore not conforming evidence.

On Linux, `sock_diag` tuple/state/cookie/inode evidence is correlated with a
bounded `/proc/<pid>/fd` scan, retained pidfd, process start time, opened
`/proc/<pid>/exe` plus `statx`/package identity, namespace, and fresh
`RTM_GETLINK` evidence. FD transfer, ptrace-denied `pidfd_getfd`, and identity
change remain explicit failures. `SO_MARK` and `SO_BINDTODEVICE` operate on
sockets, while policy routing and cgroup classification are separate privileged
resources that v1 has not registered. `SO_BINDTOIFINDEX` and
`SO_BINDTODEVICE` are distinct sealed variants: a call failure cannot flip the
process into the other branch. The pinned sing Linux helper does exactly that
process-global fallback on selected errors, so it is nonconforming. `SO_MARK`
requires complete-value read-back, a nonzero masked result, and proof that no
higher-priority rule recaptures the socket.

Apple documents explicit interface binding for sockets created through the
relevant API, but Network.framework evidence does not apply to sing-box's Go
sockets. Public Endpoint Security and Security.framework can add event-time
process/signing provenance; neither provides an atomic current listener-owner
snapshot or route enforcement. The reviewed XNU `libproc` listener/process
interfaces are private, and Network Extension flow metadata belongs to another
provider topology. These limitations are why candidate APIs do not become
optimistic capability booleans.

## Integration with the ARCH-001 transaction

This ADR registers session-scoped observation predicates, the exact external
`egress.actor-socket-policy.v1` actor-wide factory node, and an egress predicate contribution to
the existing ARCH-001 `ResumeBarrier`. It does not create another gate. The
privileged stems for endpoint-bypass routes, policy routes, and actor-identity
policies are reserved but deliberately not registered: a tuple that needs one
remains `UnsupportedPendingArchitecture` until a later accepted contract adds
the exact typed fields, one-OS-call operation, read-back, CAS, compensation,
canonical vectors, and real-host gates required by the helper contract.

Registered egress nodes inherit the same authenticated helper,
generation, plan digest, activation lease, fence, conditional state revision,
journal phase, dependency graph, compensation, recovery, and terminal receipt
rules.

The sealed plan binds at least:

- requested `NetworkScope` and exact `EgressSelection` digest;
- secret-reference, signed receipt-free risk/target authorization scopes and
  receipts, TLS policy/effective-trust/material descriptors, exact live TLS
  capability report plus release-signed real-host evidence/build identity,
  non-TLS capability reports plus their tag-53 release roots when
  `RealHostVerified`, and expected
  delivery/effective-trust-observation/load/artifact/handshake schemas, signer roles, and freshness
  predicates, never future observation digests, secret values, or raw anchors;
- runtime package/build, exact runtime instance, secret-free config template,
  derived private-artifact identity/cleanup predicate, endpoint, resolver,
  probe-target, baseline-anchor, and interface/route epoch digests;
- pre-plan-signed capability snapshot, endpoint resolution, baseline anchor,
  local proxy identity when required, and platform/package/backend versions;
- complete actor graph, each referenced tag-54 isolation policy/release-
  verified capability report, any `ExistingPreplanReadback` tag-55 root, every
  `StartInertThenPreactivationReadback` declaration, and the expected mandatory
  dual-signed preactivation tag-55 checkpoint schema, and
  `EgressExclusionSet` digest;
- socket-factory implementation/enforcement identity, bounds, epoch, sequence,
  child-observation accumulator, and OS-census predicates;
- preactivation proof specification, helper nonce slot, the complete bounded
  expected observation schema/role/freshness list, and result freshness bound,
  never a future result or an opaque schema-table hash;
- typed `egress.*` resource graph, apply/read-back/compensation predicates; and
- mandatory sustained-health predicates.

After `Prepared`, the trust broker, Runtime Adapter, Network Runtime, socket
factory, and platform backend produce the applicable delivery, load, artifact-
absence, effective-trust-observation, TLS-handshake, child, accumulator,
SOCKS association, exclusion-readback, ordinary-connectivity, factory-census,
OS-census, path-proof, Nonce consumption, and phase-bound challenge roots under the
pre-sealed schemas. The exact runtime starts inert through
its ARCH-001 permit and returns a helper-nonce/controller/channel/runtime-bound
result. The helper independently checks safety-critical OS state and durably
records the signed roots as terminal outcomes of their already sealed
observation nodes before any shared network mutation. Journaled results never
rewrite `PlanDigest`.

`egress.*` operations cannot execute from raw renderer data or user sing-box
JSON. Only registered compile-time schemas are accepted; a reserved operation
name fails closed. Before any OS mutation the helper verifies all mandatory
capabilities and proof evidence. Before commit it revalidates endpoint locality,
local listener identity, baseline anchor, exclusion completeness, and each
preventive read-back.

Normal stop first refuses new product work but keeps healthy mandatory actors
available while traffic steering, DNS/rules/routes, and TUN ownership are
removed. Only after system traffic no longer depends on FlowProbe does it close
the single ARCH-001 barrier, stop actors, verify private-artifact absence, and
remove remaining exclusions. Failed activation, actor loss, unsafe drift,
suspend/boot, or lease/owner loss instead closes/fences that barrier first and
performs emergency steering rollback. Recovery derives identity and
compensation only from the sealed secret-free journal. Ambiguous ownership or
external drift enters `RecoveryRequired`; the helper never deletes or rewrites
an unproven foreign rule, mark, route, filter, or process policy.

The accepted helper protocol currently has only recovery-authority
`AcknowledgeRecovery`, while its terminal predicate also requires a Supervisor
final-revision acknowledgement after a healthy ordinary stop. It defines no
typed normal-stop acknowledgement or durable transition into recovery
finalization. This ADR does not invent one: every mode remains
`UnsupportedPendingArchitecture/NormalStopFinalizationProtocolUnavailable`
until a separate ARCH-001 architecture task adds the exact request, authority,
state transition, idempotency, and response. Disconnect or reuse of recovery
acknowledgement cannot publish terminal `Inactive`.

## Sustained health and change behavior

The active lease requires fresh evidence for every mandatory egress predicate.
Health is an active bounded observation, not process liveness. It covers:

- selected protocol and endpoint identity;
- interface, default-route, resolver, namespace/compartment, boot/suspend, and
  backend epochs;
- applied exclusion resources and their complete actor/family/transport set;
- local listener and stable process/policy identity where required;
- direct or proxy path proof on the actual selected connector;
- each factory's gap-free child accumulator plus challenge/barrier-bound,
  counter-stable, independently signed factory and full OS socket censuses;
- for HTTPS proxying, fresh context-bound runtime trust-state, adapter artifact-
  absence, and handshake roots, plus a TrustMaterialBroker-signed context-bound
  observation of an unchanged freshly observed filtered system-store snapshot
  when that trust mode is selected;
- a NetworkRuntime-signed phase-bound target result tying the authorized target,
  current canary/renewal nonce, exact connector child, and following
  helper/watchdog accumulator together;
- the distinct SOCKS5 A target-tunnel history plus the immutable tag-50 snapshot
  that observed live B control/C UDP association when selected, followed by the
  mandatory close-only census with no verification child and an exact unchanged-
  or-ordinarily-closed unrelated operational set; and
- baseline-relative ordinary connectivity according to ADR-0004.

An interface/default-route change immediately invalidates old route and probe
evidence. The data-plane gate closes or remains closed while a new preparation
is evaluated; the old plan is never edited in place. Listener replacement,
executable or policy identity change, missing exclusion, proxy TLS identity
change, uncommanded SOCKS5 UDP association loss before the winning terminal/
teardown gate position, or any possible recursion denies lease renewal and
triggers fenced rollback. The protocol-required A close and the controlled B/C
verification teardown after their respective winning gate positions are not
association loss. V1 defines no tolerated-transient renewal disposition: any
tag-29 `Failed`, `TimedOut`, or `Cancelled` result denies renewal and fences the
old lease even when preventive exclusion and ordinary connectivity remain
proven. A plan requesting consecutive-failure or elapsed-time tolerance is
`UnsupportedPendingArchitecture/TransientHealthToleranceDispositionUnavailable`
before execution. A future accepted architecture must define its own sealed
plan fields, exact disposition, persistence, priority, and recovery semantics;
v1 cannot infer a threshold.

The runtime never switches to direct, another proxy, another DNS mode, another
family outside policy, or proxy-only scope to preserve apparent availability.

## Security and privacy decision

- Proxy passwords, tokens, authorization fields, private trust material, and
  full user configuration never enter the plan, helper journal, health report,
  error, or ordinary log. References and keyed digests are allowed. Because the
  pinned runtime has no secret callback, the broker performs one delivery to a
  fixed owner-only/no-follow config materializer after `Prepared`; the exact
  runtime may retain the credential in protected memory for repeated connections
  only during that `RuntimeInstanceId`. The artifact is removed after the
  authenticated load handshake and must be absent after crash/stop/recovery.
  Reload, rotation, endpoint change, or restart requires a new generation.
  Missing dump/swap/inheritance containment or cleanup proof makes authenticated
  proxy modes unsupported.
- Cleartext risk and probe-target permissions are signed, nonce/expiry-bound
  receipts over receipt-free scopes from a trusted product-policy broker and are
  included in the helper authorization-grant digest. They bind preparation
  ticket/session/generation/context and are consumed for one candidate plan with
  exact idempotent replay. The renderer cannot mint or replay them.
- Authentication failure is reported by bounded scheme/status/reason metadata,
  never an echoed challenge containing secrets or arbitrary proxy text.
- HTTPS proxy trust uses its own narrow, revision-bound material snapshot. It
  cannot inherit the local interception CA, reread ambient roots after load,
  turn leaf pins into skip-verify, or disable service-identity verification.
- Probe input is generated bounded data. Probe output contains no response body
  or captured application payload.
- Hostnames, addresses, executable paths, certificate subjects, and platform
  messages are normalized, bounded, and redacted or digested when not required
  for operator action.
- A local proxy is an untrusted external process. Detection grants no control
  or kill authority. FlowProbe does not attach debuggers, inject code, scrape
  memory, or obtain its credentials.
- Fail-open is forbidden whenever missing proof could recurse, leak DNS/UDP,
  misreport the requested path, or strand system networking.

## Verification and release claims

Deterministic fake tests must cover the closed union, unknown variants/fields,
all capability state combinations, every protocol success/error/timeout,
IPv4/IPv6 policies, resolver choices, listener and executable replacement
races, exclusion-set omissions, route/interface drift, lease loss, and
fail-closed rollback. The contract specifies the complete matrix.

They also cover all 57 canonical root tags, receipt-free authorization DAG and
replay boundaries, the mechanically closed digest-domain inventory, Ed25519
signer header/role/key/channel/domain including the pre-plan discovery binding,
release-only tag-49/tag-53 authorities, the closed
serial family-tuple/candidate attempt sequence and continuation rules, unique
socket child/connection epochs and first-following checkpoints, per-tuple
NonceEcho consumption-root/delivery-frame exception and crash windows,
HostLocal literal-only classification and DNS-local/mixed rejection,
inline endpoint route/locality, baseline, local-listener and connected-kernel-
peer replacement races, tag-54 isolation policy/capability plus optional
existing pre-plan and mandatory preactivation/postactivation/renewal tag-55
complete readbacks,
socket-factory pre-byte queue/sequence/accumulator plus anti-echo factory/OS
census completeness and closed policy/readback fields (including empty and
close-only checkpoints), phase-specific
external-gate/ResumeBarrier release evidence, cumulative lease socket bounds,
trust broker/runtime/adapter separation and time/context/handle ordering, exact
one-ClientHello/no-HRR/no-resumption evidence, TLS 1.2/1.3 server-
authentication observations and pinned-adapter refusals, and the missing ARCH-
001 normal-stop finalization protocol.

Every platform/mode claimed supported by a release additionally requires real
privileged direct and local-external proxy loop canaries on the exact packaged
OS/architecture/backend tuple. Canary evidence must prove the intended path,
exactly one capture traversal for intended non-FlowProbe harness traffic, zero
capture traversal for every released FlowProbe egress A connector, B SOCKS5 UDP
control, C UDP relay child, and
other excluded registered actor, ordinary connectivity before/during/after, interface-change handling,
and stop/crash/watchdog/boot recovery. Remote-only tests cannot establish local
listener exclusion. Fake tests and upstream sing-box features cannot establish
platform support.

The repository currently has no such v0.2 implementation or real-host evidence.
Accordingly this ADR makes zero `Supported` platform claims.

## Rejected alternatives

### Treat sing-box configuration success as egress proof

Rejected because parsing and process survival do not demonstrate the selected
protocol, actual route, interface exclusion, DNS behavior, or remote path.

### Use a single optimistic `loop_prevention=true` capability

Rejected because process attribution, listener ownership, preventive
enforcement, current readiness, version scope, and evidence grade can fail
independently.

### Exclude by PID, name, path string, or port

Rejected because PID and port reuse, listener replacement, executable
replacement, namespaces/compartments, dual-stack listeners, and path aliasing
make those observations racy and non-durable.

### Allow best-effort direct fallback

Rejected because it leaks policy-incompatible destination, DNS, or UDP traffic
and misreports the requested egress.

### Keep full-tunnel active when one exclusion is unavailable

Rejected because a single recursive actor can amplify traffic indefinitely or
make rollback and health evidence untrustworthy. Proxy-only is a separate
request, not an implicit degraded full-tunnel.

### Let the helper dial proxies or inspect probe payloads

Rejected because it expands the privileged attack surface and violates the
functional Network Plane boundary. The helper applies and verifies typed OS
resources only.

### Reuse the local interception CA for HTTPS proxy trust

Rejected because it couples a local traffic-decryption authority to remote
server authentication and would broaden trust unexpectedly.

## Primary references

Protocol decisions use:

- [RFC 9110 CONNECT semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6),
  including the authority target, 2xx tunnel transition, proxy authentication,
  and response-framing rules;
- [RFC 9110 proxy authorization](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7)
  and [RFC 7617 Basic authentication](https://www.rfc-editor.org/rfc/rfc7617.html);
- [RFC 9112 HTTP/1.1 request-target forms](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2),
  distinguishing CONNECT authority-form from forward-proxy absolute-form;
- [RFC 1928 SOCKS5](https://www.rfc-editor.org/rfc/rfc1928.html), including
  CONNECT, domain/IPv4/IPv6 address forms, UDP ASSOCIATE lifetime, relay
  endpoint, and optional fragmentation;
- [RFC 768 UDP](https://datatracker.ietf.org/doc/html/rfc768), whose source port
  is optional/zero when unused and whose minimum UDP length of eight permits an
  empty application datagram, plus
  [RFC 8085 section 5.1](https://www.rfc-editor.org/rfc/rfc8085.html#section-5.1)
  for source-port/address validation and the non-prohibitive `SHOULD NOT` on a
  zero source port;
- [RFC 1929 username/password authentication](https://www.rfc-editor.org/rfc/rfc1929.html);
- [RFC 5246 TLS 1.2 server key exchange](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.3)
  and [client CertificateVerify](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.8),
  [TLS 1.2 ClientHello](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.2),
  [RFC 8446 ClientHello/HelloRetryRequest](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2),
  [ServerHello downgrade protection](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.3),
  [supported versions](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.1),
  [signature algorithms](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3),
  [supported groups](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.7),
  [key share](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8),
  [early data](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.10),
  [PSK key exchange](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11),
  plus [RFC 8446 TLS 1.3 server CertificateVerify](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3),
  [RFC 6066 SNI](https://www.rfc-editor.org/rfc/rfc6066.html#section-3),
  [RFC 5280 path validation](https://www.rfc-editor.org/rfc/rfc5280.html#section-6),
  [RFC 8422 ECDHE_ECDSA/EdDSA and ECDHE_RSA](https://www.rfc-editor.org/rfc/rfc8422.html#section-2.1),
  [RFC 9325 TLS deployment recommendations](https://www.rfc-editor.org/rfc/rfc9325.html),
  [RFC 5077 session tickets](https://www.rfc-editor.org/rfc/rfc5077.html#section-3.2),
  [RFC 4055 RSA-PSS parameters](https://www.rfc-editor.org/rfc/rfc4055.html#section-3.1),
  [RFC 5746 secure renegotiation](https://www.rfc-editor.org/rfc/rfc5746.html#section-3.3),
  [RFC 7627 extended master secret](https://www.rfc-editor.org/rfc/rfc7627.html#section-4),
  and [RFC 6960 OCSP](https://www.rfc-editor.org/rfc/rfc6960.html);
- [RFC 9525 service identity](https://www.rfc-editor.org/rfc/rfc9525.html),
  including configured reference identity and exact IP identity matching; and
- the byte-pinned [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv)
  and [IPv6 special-purpose registries](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv)
  for the v1 probe-address classifier snapshot.

The repository's pinned sing-box 1.13.19 revision
`b5ebaa1fc0f2b94256180b95468e73ef53caa27d` exposes direct, HTTP CONNECT, and
SOCKS outbounds, TLS wrapping for HTTP proxy transport, common dial options,
interface binding on Linux/macOS/Windows, and Linux routing marks. These are
runtime primitives, not FlowProbe transaction or support proof:

- [direct outbound](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/protocol/direct/outbound.go),
  [HTTP outbound](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/protocol/http/outbound.go#L29-L66),
  and [SOCKS outbound](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/protocol/socks/outbound.go#L38-L116);
- [dial options](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/outbound.go#L65-L94),
  [outbound TLS options](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/option/tls.go#L97-L120),
  [standard TLS pin behavior](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/tls/std_client.go#L114-L121),
  [pin callback](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/tls/std_client.go#L223-L239),
  and [dialer application](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/common/dialer/default.go#L52-L135);
- its [`go.mod`-pinned sing v0.8.13](https://github.com/SagerNet/sing-box/blob/b5ebaa1fc0f2b94256180b95468e73ef53caa27d/go.mod#L37),
  specifically the [HTTP client state machine](https://github.com/SagerNet/sing/blob/v0.8.13/protocol/http/client.go#L115-L150),
  [SOCKS UDP association](https://github.com/SagerNet/sing/blob/v0.8.13/protocol/socks/client.go#L136-L150),
  [SOCKS packet decoder](https://github.com/SagerNet/sing/blob/v0.8.13/protocol/socks/packet.go#L39-L99),
  [Windows bind behavior](https://github.com/SagerNet/sing/blob/v0.8.13/common/control/bind_windows.go#L25-L56),
  [Linux bind fallback](https://github.com/SagerNet/sing/blob/v0.8.13/common/control/bind_linux.go#L13-L40),
  and [Linux mark behavior](https://github.com/SagerNet/sing/blob/v0.8.13/common/control/mark_linux.go#L7-L11);
- pinned Go 1.24.7
  [`crypto/tls.ConnectionState`](https://github.com/golang/go/blob/go1.24.7/src/crypto/tls/common.go#L235-L311)
  and [default groups/signature schemes](https://github.com/golang/go/blob/go1.24.7/src/crypto/tls/defaults.go#L18-L44),
  which delimit what the public pinned runtime can observe and configure.

Platform candidates use:

- Microsoft [extended TCP owner tables](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable),
  [extended UDP owner tables](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable),
  [process handles](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights),
  [process handle lifetime](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers),
  [`GetIfEntry2`/`MIB_IF_ROW2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2),
  [GUID/LUID mapping](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceguidtoluid),
  [`FILE_ID_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info),
  and [`WinVerifyTrust`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust),
  [WFP application identity](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers),
  [WFP object and dynamic-session lifetime](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management),
  [`IP_UNICAST_IF`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options),
  and [`IPV6_UNICAST_IF`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options);
- pinned Linux man-pages
  [`sock_diag`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man7/sock_diag.7?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`SO_MARK` and `SO_BINDTODEVICE`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man7/socket.7?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  Linux v6.6 [`SO_BINDTOIFINDEX` UAPI](https://github.com/torvalds/linux/blob/v6.6/include/uapi/asm-generic/socket.h#L106-L110),
  [set path](https://github.com/torvalds/linux/blob/v6.6/net/core/sock.c#L1505-L1507),
  and [get path](https://github.com/torvalds/linux/blob/v6.6/net/core/sock.c#L1972-L1974),
  [policy routing rules](https://docs.kernel.org/netlink/specs/rt-rule.html),
  [route netlink](https://docs.kernel.org/netlink/specs/rt-route.html), and
  [`pidfd_open`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man2/pidfd_open.2?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c) plus
  permission-gated [`pidfd_getfd`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man2/pidfd_getfd.2?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`proc_pid_fd`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man5/proc_pid_fd.5?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`proc_pid_stat`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man5/proc_pid_stat.5?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`proc_pid_exe`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man5/proc_pid_exe.5?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`statx`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man2/statx.2?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  [`rtnetlink`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man7/rtnetlink.7?id=ad4e4b8acef4d1b0b48037b34e5aa1720d18115c),
  kernel [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html), and
  [cgroup socket-address BPF program types](https://docs.kernel.org/6.9/bpf/libbpf/program_types.html); and
- Apple Network.framework
  [`requiredInterface`](https://developer.apple.com/documentation/network/nwparameters/requiredinterface)
  plus pinned XNU's public
  [`IP_BOUND_IF`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/in.h#L443)
  and [`IPV6_BOUND_IF`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet6/in6.h#L642),
  public Endpoint Security
  [`es_process_t`](https://developer.apple.com/documentation/endpointsecurity/es_process_t),
  and Security.framework
  [`SecCodeCopySigningInformation`](https://developer.apple.com/documentation/security/seccodecopysigninginformation%28_%3A_%3A_%3A%29),
  contrasted with XNU's explicitly private
  [`libproc` interfaces](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.h#L38-L42)
  and provider-scoped Network Extension
  [`NEFlowMetaData`](https://developer.apple.com/documentation/networkextension/neflowmetadata).

These sources establish candidate API semantics only. FlowProbe support remains
conditioned on the accepted transaction, packaged implementation, and exact
real-host evidence.

## Compatibility and migration

FlowProbe is unreleased. This architecture directly replaces the incomplete
v0.x egress scaffolding. It defines no compatibility shim, legacy mode alias,
or migration path. A later production compatibility or migration requirement
needs a separate authorized task.
