# ADR-0004: Transactional system-network lifecycle

Status: Accepted

Task: ARCH-001

## Decision scope

FlowProbe will introduce a generation-fenced transactional network-session
layer above Network Runtime Control. One unprivileged Supervisor controller
orchestrates each session. One authenticated privileged helper authority owns
the durable system-network journal, allowlisted operating-system mutations,
watchdog fencing, and crash/boot recovery.

This decision defines shared ownership, lifecycle, recovery, capability, and
platform authority. It does not implement the helper or claim that a platform
is currently supported.

## Observed v0.1 baseline

The v0.1 runtime API controls an independent process with `Stopped`, `Running`,
and `Crashed` state plus process-local generation and boolean capabilities. The
Supervisor forwards those runtime operations. The sing-box adapter manages its
child process and compiled configuration; it does not implement a privileged
network journal, lease fencing, stable resource ownership, or system rollback.

Those types remain valid for runtime-process lifecycle only. They MUST NOT be
reused as evidence that TUN, route, DNS, firewall, or trust resources are active
or recovered. Process-group cleanup and object destruction are not network
rollback.

## Frozen architecture preserved

This ADR does not change the accepted system decomposition:

- sing-box remains an independent managed Network Runtime process and the
  functional Network Plane owner;
- Capture Core remains protocol-oriented, uses only versioned boundaries, and
  does not import sing-box internals;
- user configuration remains compiled with protected system/runtime overlays
  and cannot redefine `__flowprobe_*` objects;
- analyzers remain third-party WASM components behind versioned capabilities;
  and
- raw/normalized traffic remains source material while semantic output remains
  derived and rebuildable.

Functional Network Plane ownership is distinct from privileged mutation
authority. The helper applies journaled OS mutations on behalf of a sealed
session plan; it does not become a proxy engine, inspect traffic, or replace
sing-box. Conversely, sing-box cannot independently mutate a resource owned by
the helper.

## Actors and trust boundaries

| Actor | Decision |
| --- | --- |
| Renderer | Sends only typed product intent through desktop IPC; has no helper transport, OS network API, raw operation, path, or fencing access |
| Supervisor | Sole unprivileged session orchestrator; validates, sequences, holds the live lease, and reports truth |
| Config Compiler | Produces the protected runtime configuration and digest before activation |
| Network Runtime adapter | Controls the independent sing-box process through the versioned runtime contract |
| Capture Core | Starts protocol/capture services but owns no route, DNS, TUN, or helper operation |
| Privileged helper authority | Sole privileged mutation and durable journal writer for an installation/namespace |
| Watchdog/reconciler | Part of the helper fence domain; may take over only after durably fencing the previous lease |
| Platform backend | Implements compile-time registered, typed, versioned operations and stable discovery |

The helper transport authenticates installation and peer identity. It rejects
unknown operations and schemas. It never accepts shell, executable, arguments,
environment, arbitrary path, raw OS request, dynamic privileged plugin,
renderer-controlled payload, user sing-box configuration, or captured data.

## Transaction decision

The normative session states are:

```text
Inactive
  -> Preflighting
  -> Prepared
  -> Applying
  -> Verifying
  -> Active
  -> Stopping
  -> RollingBack
  -> Inactive

Any journaled state -> Recovering -> RollingBack
Unsafe ambiguity or external drift -> RecoveryRequired
```

Only `Inactive` accepts a new start. `Active` is published only after the
prepared plan, all mandatory observed after images, the exact requested mode's
actor/health predicates, baseline-relative connectivity evidence, and the
commit record are durable. `RecoveryRequired` refuses new activation and cannot
be displayed as active, stopped, or recovered.

The start order is:

1. acquire the controller/helper authority and advance a durable generation;
2. resolve static support, current readiness, permission, and unresolved
   recovery state;
3. discover and normalize the network baseline;
4. compile configuration and run registered egress/loop preconditions;
5. build the resource graph and exact mode-specific mandatory actor/health set;
6. have the helper durably seal that graph and atomically issue its plan-bound
   activation lease/fence before any service starts;
7. journal a one-use external intent and redeem ticket, then use a helper-held
   online gate to start each internal unprivileged service inert, authenticate
   its exact `RuntimeInstanceId`, and durably observe it before the gate completes
   and before changing system networking;
8. fsync all known before images and intended postconditions, then activate
   registered TUN, route/rule, DNS, firewall, and later extension
   resources in dependency order;
9. independently verify every mandatory postcondition and mode-specific end-to-
   end/baseline-relative health predicate; and
10. fsync commit, then publish `Active`.

Stop, failed activation, expired owner, runtime loss that makes the path unsafe,
and crash/boot reconciliation compensate resources in reverse dependency
order. During normal stop, every mandatory data-plane actor in the sealed mode
remains available until traffic-steering, DNS/rule/route, and TUN resources no
longer direct system traffic to it; only then are those internal actors stopped.
If a mandatory data-plane actor already crashed, the helper performs bounded
emergency rollback without waiting for it.

## Generation, lease, and fencing

Every attempt receives a never-reused durable `Generation`. Preflight uses only
a non-mutating preparation ticket. When the exact graph is durably sealed, the
helper atomically issues an activation lease and ordered fence bound to
installation, session, helper-assigned random `ControllerId`, connection-binding
epoch, backend, boot/suspend epoch, and plan digest. The controller ID is bound
to proof of possession of an ephemeral Supervisor-instance key; another process
cannot choose or claim it under the same OS service identity. The preparation
ticket and plan have the same controller binding. Mutating commands also carry
an idempotency key and expected durable state revision.

Concurrent starts return `Busy`. Repeated stops join the same current operation.
A stale generation, lease, fence, or revision has no side effect. A mutation
holds the same cross-process helper lock from durable fence reread through
intent, OS call/read-back, and direction-specific `AppliedDurable` or
`CompensatedDurable` fsync. Takeover acquires that lock, then durably advances
the fence, rejects the old owner, and reconciles. PID, service restart, login
session, current boot, or IPC disconnect is observation, not ownership proof.

Lease renewal uses that same lock and conditional state revision as watchdog
takeover. It binds the controller, connection, plan, activation lease/epoch/
fence, a helper challenge, and fresh mandatory actor/resource/connectivity
evidence. Immediately before fsync, renewal must reread the suspend-aware clock
and prove the old deadline, request, challenge, and evidence are all still live;
crossing the old deadline is irreversible even while renewal holds the lock.
The same transition consumes the challenge, issues the next one, and either
durably commits a later deadline or advances the recovery fence with no renewal.

After owner loss, boot, or suspend fencing, the old activation lease is never
reused. The helper owns a recovery epoch/fence, immutable base journal root, and
helper-derived recovery plan for internal reconciliation. A typed claim response
separately issues a bounded delegate lease/epoch/fence to one controller,
connection, and recovery-node subset. Delegate expiry/loss fences only that
delegate and its permits; it never transfers or stops helper-internal authority.
Both can only observe and reverse-compensate the sealed old plan, never apply or
commit it.

Recovery completion is a separate idempotent acknowledgement, not a recovery
step or commit alias. Under the same lock the helper revalidates the live
delegate, exact current pre-finalization head/revision, all privileged results,
exact runtime-absence observations, and `BaselineEquivalent`, then fsyncs
`RecoveryFinalizedDurable`. The response distinguishes that acknowledged tip
from the resulting post-finalization tip. The owning Supervisor may publish
`Inactive` from that typed response or its durable replay. The helper also keeps
the latest non-authorizing terminal receipt in the protected installation index
without a time-based expiry while it remains the current terminal generation,
so a newly authenticated Supervisor can publish `Inactive` even if the original
process and ephemeral key were permanently lost after the final fsync. Durable
allocation of a later generation retires that older receipt as publication
proof.

External process/service apply and compensation use a helper-authoritative
online gate. Issue itself holds the takeover lock through authority/fence/head
reread and atomic intent/permit/revision fsync, sealing and returning the parent
and issued journal heads, so an old controller cannot append an intent after the
recovery plan is sealed. Issuing a ticket does not authorize action. Redemption
submits only the permit ID, live gate, and current head/revision; the helper
loads sealed authority and verifies the issued head remains an unsuperseded
ancestor. It again holds the lock through bounded inert launch or exact-instance
stop, protected handshake/read-back, durable presence or absence observation,
and permit consumption. Recovery compensation has its own delegate-fenced
durable intent. An executor that can act from an offline ticket, start non-inert,
or escape on gate loss is unsupported.

Lease time uses a suspend-aware monotonic clock plus durable boot/suspend epoch.
Boot, suspend/resume, or clock-domain discontinuity invalidates an old plan and
lease, advances the fence, and forces reconciliation; v0.2 does not silently
resume the session.

A supported data path additionally requires a first-packet `ResumeBarrier`: an
OS/kernel gate installed before activation must close automatically on cold
boot, suspend/hibernate epoch change, and helper/watchdog/gate-channel death.
A pre-suspend inhibitor/removal sequence counts only if holder death or forced
suspend is OS-atomically ordered with that closure/removal. Eventual userspace
scheduling or an ordinary inhibitor released by helper crash is insufficient.
The old generation is rolled back and never reopens its gate; a platform/mode
without this proof is `Unsupported` with reason `ResumeGateMissing`.

## Durable journal and mutation protocol

The privileged helper owns an authenticated, checksummed, versioned, secret-
free journal in platform-protected persistent storage. Before each mutation it
fsyncs:

- installation, session, attempt, generation, lease, fence, and state revision;
- backend kind/version and step dependencies;
- resource kind, owner, stable identity/discovery recipe, and managed fields;
- normalized before image and provenance;
- intended postcondition, idempotency rule, deadline, and compensation; and
- the `IntentDurable` mutation phase.

The backend then issues one typed mutation, queries the OS, verifies owner and
postcondition, and fsyncs the normalized observed after image before any
dependent mutation or commit. A successful return code alone is insufficient.

A crash after mutation but before after-image persistence is explicitly
ambiguous. Recovery rediscovers by stable identity:

- intended state plus proven owner: persist the observed after image, then
  compensate normally;
- proven unchanged before state or absent create target: record unapplied;
- partial state, multiple candidates, missing owner proof, or other mismatch:
  preserve state and enter `RecoveryRequired`.

Rollback is conditional compare-before-restore. It changes only normalized
managed fields that still equal the recorded after image and only through an OS
atomic condition/revision token or an exact exclusively owned resource
instance. Read/compare followed by an unconditional setter is forbidden because
it can overwrite a racing administrator change. Passthrough fields remain
current. Any external change or missing conditional primitive is preserved and
reported as `ExternalDrift`/`RecoveryRequired`; FlowProbe never overwrites it
with a stale whole-system baseline.

For whole-object deletion, exclusive ownership covers the complete object and
every dependent that the OS would delete transitively. The current normalized
object/dependent closure must equal the recorded owned after-image graph under a
condition covering deletion, or the backend must have prevented foreign
attachments. Any added address, route, rule, attachment, child, or passthrough
field blocks deletion even when managed fields and the owner marker still match.

The journal is retained until all session resources are verified absent/
restored, exact runtime instances are stopped, and the baseline-relative
`BaselineEquivalent` predicate proves no FlowProbe-caused degradation. An
offline baseline can therefore terminate safely. Unknown or corrupt journal
versions fail closed.

The complete normative behavior is in
[`network-session-lifecycle.md`](../contracts/network-session-lifecycle.md) and
[`privileged-helper.md`](../contracts/privileged-helper.md).

## Capability and support decision

Capabilities are multi-dimensional:

- static support: `SupportedByDesign`, `UnsupportedPendingArchitecture`, or
  `UnsupportedByPlatform`;
- current readiness, including `Ready`, `Degraded`, `PermissionMissing`,
  `UserActionRequired`, `PolicyProhibited`, `TemporarilyUnavailable`,
  `BackendVersionMismatch`, `Unsafe`, `RecoveryRequired`, and `NotInstalled`;
- safety/recovery state;
- backend/version scope; and
- evidence grade: design, deterministic fake, or real privileged host.

Static API availability is not readiness. Fake tests are not platform support.
A platform/mode is supported only after its exact release package and version
matrix passes real privileged start, stop, crash-window, stale-journal, drift,
sleep/logout, and boot-recovery tests with ordinary-connectivity oracles.

The architecture snapshot is:

| Platform candidate | Candidate authority | Durable resource identity / live process observation | Current typed result |
| --- | --- | --- | --- |
| Windows 10 build 19041+/Windows 11 x86_64 | Dedicated non-admin Supervisor service identity plus signed privileged helper; official Wintun; typed IP Helper DNS/route and WFP operations; independent sing-box packet runtime | Observed `InterfaceGuid` plus device/owner evidence, complete normalized route tuples, and generation-derived WFP provider/sublayer/filter GUIDs; durable `RuntimeInstanceId` plus protected handshake; handle/creation/file data are live corroboration only; never `IfIndex` or PID | `StaticSupport=UnsupportedPendingArchitecture`; `Readiness=Unsafe`; `Evidence=DesignOnly`; reasons include `ExternalRuntimeAttachmentMissing`, `PeerBindingImplementationMissing`, `ResumeGateMissing`, and `RealHostUnverified` |
| Linux candidate prerequisites: x86_64, systemd, one resolver backend, and kernel/package floor selected by an as-yet-unselected release tuple | Dedicated non-root Supervisor service UID plus restricted privileged helper; non-persistent kernel TUN; typed rtnetlink; one explicit resolved or NetworkManager adapter; independent sing-box packet runtime | Installation/generation `IFLA_IFALIAS`, namespace/device kind, full route/rule tuples, connection UUID/version where applicable; durable `RuntimeInstanceId` plus protected handshake; pidfd/start/file data are live corroboration only; never interface name/index or PID | `StaticSupport=UnsupportedPendingArchitecture`; `Readiness=Unsafe`; `Evidence=DesignOnly`; reasons include `ReleaseTupleUnselected`, `ExternalRuntimeAttachmentMissing`, `PeerBindingImplementationMissing`, `ResumeGateMissing`, and `RealHostUnverified` |
| macOS 26+ direct-distribution candidate; older releases unselected | Notarized Developer ID helper is the only compatible candidate authority; native TUN authority/identity and independent handoff are not selected | System Configuration may use returned service ID plus protocol while holding `SCPreferencesLock` across synchronize/reread/change/commit, then request apply and independently read back effective active state; the lock/signature are not a CAS or apply-completion proof; durable `RuntimeInstanceId` plus protected handshake; no accepted TUN identity; `utun` name/PID are locators only | `StaticSupport=UnsupportedPendingArchitecture`; `Readiness=Unsafe`; `Evidence=DesignOnly`; reasons include `NativeTunAuthorityUnproven`, `ExternalRuntimeAttachmentMissing`, `ResumeGateMissing`, and `RealHostUnverified` |

The complete cross-platform authority matrix is deliberately explicit about
unresolved downstream contracts:

| Concern | Windows candidate | macOS candidate | Linux candidate |
| --- | --- | --- | --- |
| Authority and package | Dedicated non-admin Supervisor service SID plus signed privileged own-process service, restricted named pipe/service SID, release installer | macOS 26+ signed/notarized Developer ID app plus `SMAppService` LaunchDaemon and XPC peer code-signing requirement; Network/System Extension alternatives remain distinct | Dedicated non-root Supervisor service UID plus a release-tuple-specific distribution/repository-authenticated package and restricted privileged systemd service/Unix socket; authenticity mechanism and tuple remain unselected, so no `.deb`/`.rpm` package is supported |
| TUN/data path | Official Wintun candidate owned by the helper; independent runtime attachment and first-packet resume gate are missing | Packet Tunnel flow, transparent-proxy flow, and native TUN are separate choices; the reviewed Apple sources do not establish a supported native TUN authority/identity, independent attachment, or first-packet resume gate | Non-persistent kernel TUN candidate owned by the helper; independent runtime attachment and first-packet resume gate are missing |
| Route/rule mutation | Typed IP Helper rows, complete identity and field-scoped read-back | A future native backend would require typed route operations with captured before/after images; current path is unsupported | Typed rtnetlink with exclusive create, explicit owned table/markers, and complete tuples |
| DNS mutation authority | Per-interface API bound to the owned `InterfaceGuid`, but only with an exact exclusive object or conditional mutation; shared unconditional replacement is unsupported; detailed behavior remains ARCH-004-owned | A future backend would need returned System Configuration service ID plus protocol, hold `SCPreferencesLock` across synchronize/reread/change/commit, request apply, and independently read back effective active state; the lock/signature are neither CAS nor apply-completion proof, and a conditional design remains unproven; Packet/transparent provider semantics are not interchangeable; detailed behavior remains ARCH-004-owned | Exactly one declared adapter; resolved is limited to an exact exclusively owned link, NetworkManager may use applied version CAS, and unknown/mixed ownership is unsupported; detailed behavior remains ARCH-004-owned |
| Process identity | Durable `RuntimeInstanceId` plus protected runtime handshake; handle/creation/file observations are live only; PID is display/lookup only | Durable `RuntimeInstanceId` plus protected runtime handshake/package identity; live process observation is not durable; PID is display/lookup only | Durable `RuntimeInstanceId` plus protected runtime handshake; pidfd/start/file observations are live only; PID/unit/restart is not durable ownership |
| Loop exclusion | Only the `egress.*` extension envelope and candidate helper/runtime authorities exist; mechanism, identity policy, and support are exclusively ARCH-002 | Same; Packet Tunnel, transparent flow, and native path cannot inherit one another's conclusion | Same; no cgroup, mark, process, or route mechanism is selected here |
| Trust store | Only persistent `trust.ca.*` helper primitives are reserved; ARCH-003 owns its separate generation/lifecycle and network stop never implies trust removal | Same; native helper versus user/system trust authority is not selected here | Same; no distro trust-store mechanism is selected here |
| Watchdog and boot | Service starts automatically, reconciles journal, then becomes ready; SCM restart is availability only | LaunchDaemon candidate reconciles before readiness; launchd/System Extension restart is availability only | systemd service reconciles before `READY=1`; restart/watchdog/`ExecStopPost` are availability or best-effort cleanup only |
| Typed unsupported cases | Old OS/API, missing isolated peer/package, wrong architecture, runtime attachment or resume gate absent, unsafe conditional mutation, permission denial, unresolved journal, or failed real-host gate | Every current requested mode is unsupported pending architecture; pre-macOS-26 peer design, native TUN authority/identity, runtime attachment/resume gate, extension denial/disable, and private-API-only paths are explicit failures | Release tuple unselected, unknown resolver/manager, non-systemd/unlisted distro, missing isolated peer/capability/device, runtime attachment/resume gate absent, unsafe conditional mutation, unresolved journal, or failed real-host gate |

Wintun availability, a Linux TUN device, or sing-box successfully starting does
not change these results.

## Required independent-runtime attachment

The selected architecture requires a versioned, supported, out-of-process
attachment/control contract through which the helper-owned TUN and protected
network plan are consumed by the independent sing-box process without sing-box
also changing the same route/DNS resources.

Current public sing-box CLI configuration and Runtime Control do not expose the
required prepare/observe/reconcile semantics or a stable external TUN handoff.
Internal `sing-tun` file-descriptor options and the embedded libbox platform
interface are library implementation surfaces, not this contract
([generic options](https://github.com/SagerNet/sing-tun/blob/ab72f02181f593b91a2128534613d457ea759a70/tun.go#L69-L118),
[Darwin implementation](https://github.com/SagerNet/sing-tun/blob/ab72f02181f593b91a2128534613d457ea759a70/tun_darwin.go#L94-L125)).
Until a separate architecture task authorizes and versions a compatible
independent-process surface, system-wide activation MUST return
`UnsupportedPendingArchitecture` with a bounded reason and perform no OS
mutation.

The alternative—letting current sing-box `auto_route`, `auto_redirect`, or DNS
management run alongside helper mutations—is forbidden dual ownership. Letting
root sing-box own them alone is also insufficient because the helper cannot
durably bracket each internal mutation, observe its after image, or perform
field-scoped recovery.

The sing-box TUN documentation describes these runtime features but does not
specify FlowProbe's transaction guarantees: [TUN inbound
options](https://sing-box.sagernet.org/configuration/inbound/tun/). The
independent CLI option schema reviewed at sing-box commit
`066a5b1d3a16379561f0ca8d578b13cff9e3985e` has no FlowProbe external-attachment
or transactional resource fields
([source](https://github.com/SagerNet/sing-box/blob/066a5b1d3a16379561f0ca8d578b13cff9e3985e/option/tun.go#L14-L54)).
In the reviewed sing-tun commit
`ab72f02181f593b91a2128534613d457ea759a70`, Linux cleanup uses rule ranges and
whole-link resolver cleanup, while Windows setup owns adapter/DNS/route/WFP
operations internally; neither exposes FlowProbe journal/CAS recovery
([Linux source](https://github.com/SagerNet/sing-tun/blob/ab72f02181f593b91a2128534613d457ea759a70/tun_linux.go#L1136-L1231),
[Windows source](https://github.com/SagerNet/sing-tun/blob/ab72f02181f593b91a2128534613d457ea759a70/tun_windows.go#L39-L256)).

## Windows platform rationale

The Windows candidate uses a dedicated non-administrator Supervisor service
identity and a separate signed privileged own-process helper. The helper pipe
grants only SYSTEM and the Supervisor service SID; the interactive desktop
never receives helper credentials. SCM automatic start and failure actions
improve availability but are not recovery or commit evidence. The helper
reconciles before it accepts sessions and never automatically reactivates a
previous session. Microsoft documents [service
SIDs](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
and [named-pipe
ACLs](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

The official Wintun DLL is a fixed audited candidate backend dependency, not a
dynamic plugin. It is installed at one administrator-owned path, loaded only by
absolute hardened lookup, and verified against the allowed Authenticode
publisher/version and signed-manifest hash before mutation; mismatch is
`BackendVersionMismatch`/`Unsafe`. The helper records the actual OS interface
GUID and owner/device evidence. Microsoft notes
that interface indexes can change after disable/enable, so `IfIndex` is only a
locator ([MSFT_NetAdapter](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter)).
Wintun's requested GUID creation input does not replace observed OS identity
([Wintun API](https://git.zx2c4.com/wintun/tree/api/wintun.h?h=0.14.1)).

IP Helper supplies typed route creation and OS read-back
([CreateIpForwardEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2),
[GetIpForwardEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardentry2)).
Those APIs alone do not establish an atomic compare-and-swap. Update/deletion
of an externally mutable row remains unsupported until an exact conditional or
exclusive-owned resource design is separately proven.
Per-interface DNS uses `GetInterfaceDnsSettings`/`SetInterfaceDnsSettings`,
whose documented client floor is Windows 10 build 19041
([GetInterfaceDnsSettings](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getinterfacednssettings)).
Because those references do not provide a shared-object CAS guarantee, a DNS
mutation is permitted only on an exact exclusively FlowProbe-owned adapter/
object or after a separately proven conditional design; otherwise it is
unsupported.
Dynamic WFP sessions may provide automatic filter cleanup, but do not cover
TUN, route, DNS, or journal recovery
([FwpmEngineOpen0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0)).
Generation-derived keys use the documented GUID fields in
[`FWPM_PROVIDER0`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0),
[`FWPM_SUBLAYER0`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0), and
[`FWPM_FILTER0`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0).

PID reuse is possible after process-object release. Durable ownership is the
pre-sealed `RuntimeInstanceId` plus protected runtime handshake/package/launch
evidence; a retained handle and creation/file observations corroborate only the
live process ([process handles and
identifiers](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers)).
ARCH-002 owns the eventual loop-exclusion mechanism and support conclusion.

## Linux platform rationale

The Linux candidate uses a dedicated non-root Supervisor service UID plus a
separate privileged systemd helper with a typed Unix socket, `StateDirectory=`,
minimal justified capabilities, `NoNewPrivileges`, and other service
sandboxing. Only the Supervisor UID reaches the helper socket; the interactive
desktop uses a narrower product IPC endpoint. polkit may authorize the product
action but is not a generic root-command launcher or confinement boundary.
The socket verifies
[`SO_PEERCRED`](https://man7.org/linux/man-pages/man7/unix.7.html) peer UID/PID
and a separate installation-bound authenticated handshake. PID-only polkit
identity is racy, so it cannot be the helper authentication or durable owner
identity
([PolkitUnixProcess](https://polkit.pages.freedesktop.org/polkit/PolkitUnixProcess.html)).

The initial candidate uses a non-persistent kernel TUN. Closing its descriptor
may remove the device and routes, but that is cleanup assistance, not complete
transactional proof ([Linux TUN/TAP](https://docs.kernel.org/networking/tuntap.html)).
The helper writes an installation/generation owner marker to `IFLA_IFALIAS` and
rediscovers it with network-namespace and device-kind evidence
([rt-link](https://docs.kernel.org/netlink/specs/rt-link.html)). Name and ifindex
remain locators.

Route/rule operations use typed rtnetlink, exclusive creation, explicit owned
tables/markers, and complete normalized tuples
([rt-route](https://docs.kernel.org/netlink/specs/rt-route.html),
[rt-rule](https://docs.kernel.org/netlink/specs/rt-rule.html)). Deleting by
priority range is forbidden.

DNS authority is explicit per supported release tuple. A systemd-resolved
backend uses the per-link D-Bus API and field-scoped images; it does not blindly
call whole-link `RevertLink`. Because this ADR has no conditional shared-link
setter proof, that candidate is limited to an exact exclusively FlowProbe-owned
link; other resolved mutations are unsupported
([resolve1](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html)).
A separate NetworkManager backend uses connection UUID plus applied-connection
version for compare-before-restore
([NetworkManager device API](https://www.networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Device.html)).
Foreign `/etc/resolv.conf`, unknown/multiple resolver ownership, and unsupported
managers fail before mutation.

Durable process ownership uses the pre-sealed `RuntimeInstanceId` and protected
runtime handshake. pidfd, boot/start, and executable observations corroborate a
live instance only. ARCH-001 selects no release distribution, systemd,
kernel floor, resolver, NetworkManager, or package/authenticity tuple, so no
`.deb` or `.rpm` packaging is supported and Linux remains
`StaticSupport=UnsupportedPendingArchitecture` with reason
`ReleaseTupleUnselected`.

systemd restart/watchdog directives do not survive every failure and cannot
replace the persistent journal. `READY=1` is emitted only after reconciliation;
journal data lives under `/var/lib`, not `/run`
([systemd service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html),
[systemd execution environment](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)).

## macOS platform decision

macOS has three distinct authority/data-path families. They MUST NOT share one
generic “macOS TUN” capability.

| Path | Public data path and deployment | Decision |
| --- | --- | --- |
| Mac App Store Packet Tunnel app extension | OS-owned virtual interface exposed as `NEPacketTunnelFlow`; sandboxed app extension; App Store distribution | Unsupported for the requested local system-network design. Apple frames packet tunnels as remote-VPN data paths and does not publish an external packet-flow/fd handoff to an independent sing-box CLI |
| Developer ID Packet Tunnel system extension | The same `NEPacketTunnelFlow` model in an OS-managed system extension; Developer ID entitlements, embedding, user/admin activation, hardened signing, and notarization | Unsupported under the frozen independent-process boundary. Stronger deployment/lifetime does not create a public packet-flow handoff |
| App/transparent proxy extension | `NEAppProxyFlow` TCP connections and UDP flows rather than raw IP packets/TUN; system DNS/proxy behavior differs | Requires a separate architecture change; it cannot be represented as the current packet/TUN Capture path |
| Developer ID native helper plus public System Configuration candidate | A root LaunchDaemon could preserve an independent runtime process, but reviewed Apple sources do not establish a supported native TUN/route authority, cross-process handoff, or stable TUN identity | Only compatible authority direction, but `UnsupportedPendingArchitecture` until native TUN authority/identity, independent attachment, conditional recovery, and real-host gates are separately accepted |

Apple distinguishes App Store app extensions from Developer ID system
extensions and their user/global lifecycle in
[TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).
Packet Tunnel providers own an
[`NEPacketTunnelFlow`](https://developer.apple.com/documentation/networkextension/nepackettunnelflow),
and [TN3120](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers)
limits packet-tunnel use to supported VPN-style paths rather than local packet
filter/reinjection designs. Transparent proxy providers expose TCP/UDP flows,
not a raw packet TUN
([handling flow copying](https://developer.apple.com/documentation/networkextension/handling-flow-copying)).

Developer ID Network/System Extension packaging requires the corresponding
entitlements, system-extension activation, signing, hardened runtime, and
notarization
([Network Extension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension),
[System Extension installation](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers),
[notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)).
These controls do not replace FlowProbe's journal, lease, or CAS rollback.

The macOS 26+ native-helper authority candidate uses a fixed `SMAppService`
LaunchDaemon and narrow XPC peer code-signing requirement. `SMAppService` starts
at macOS 13, but the selected peer requirement starts at macOS 26; older
releases have no accepted peer-authentication design here. Administrator denial
is a typed preflight result with ordinary connectivity unchanged
([SMAppService registration](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29),
[XPC peer requirement](https://developer.apple.com/documentation/xpc/xpc_connection_set_peer_requirement)).
Managed preference candidates use the identifier returned by
`SCNetworkServiceGetServiceID()` plus protocol type while holding
`SCPreferencesLock` across synchronize/reread, change, and
`SCPreferencesCommitChanges`; they then request `SCPreferencesApplyChanges` and
independently read back the effective active configuration. The lock protects
preferences access only. `SCPreferencesGetSignature` supplies saved-preferences
change-detection evidence, not an atomic CAS token or proof that active-state
application completed; a revision-token/conditional design remains separately
unproven
([service ID](https://developer.apple.com/documentation/systemconfiguration/scnetworkservicegetserviceid%28_%3A%29),
[protocol lookup](https://developer.apple.com/documentation/systemconfiguration/scnetworkservicecopyprotocol%28_%3A_%3A%29),
[preferences lock](https://developer.apple.com/documentation/systemconfiguration/scpreferenceslock%28_%3A_%3A%29),
[synchronize](https://developer.apple.com/documentation/systemconfiguration/scpreferencessynchronize%28_%3A%29),
[signature](https://developer.apple.com/documentation/systemconfiguration/scpreferencesgetsignature%28_%3A%29),
[commit](https://developer.apple.com/documentation/systemconfiguration/scpreferencescommitchanges%28_%3A%29),
[apply](https://developer.apple.com/documentation/systemconfiguration/scpreferencesapplychanges%28_%3A%29)).

An upstream Apple client does not prove this architecture. The reviewed client
embeds Libbox inside `NEPacketTunnelProvider`
([source](https://github.com/SagerNet/sing-box-for-apple/blob/52352677fa2892d4e66055d2f78aff454c45e654/Library/Network/ExtensionProvider.swift#L1-L218))
and obtains an internal packet-flow socket descriptor through undocumented KVC
([source](https://github.com/SagerNet/sing-box-for-apple/blob/52352677fa2892d4e66055d2f78aff454c45e654/Library/Network/ExtensionPlatformInterface.swift#L194-L207)).
FlowProbe MUST NOT embed libbox to call that an independent process, use private
API/KVC, reflect or `dlsym` private selectors, or treat those techniques as
support evidence. Source and final-binary negative scans are release gates.

Native `sing-tun` accepts an internal file descriptor/external-configuration
option, but it is not a stable public independent-CLI contract. At the same
reviewed sing-tun commit `ab72f02181f593b91a2128534613d457ea759a70`, its
macOS route implementation can delete an existing conflicting route and later
delete only its derived route rather than restore a captured before image
([source](https://github.com/SagerNet/sing-tun/blob/ab72f02181f593b91a2128534613d457ea759a70/tun_darwin.go#L445-L524)).
That behavior cannot satisfy transactional rollback.

## Downstream architecture ownership

ARCH-001 freezes only the common envelopes:

- `core.session.*`, `core.resource.*`, and `core.helper.*` here;
- `egress.*` belongs exclusively to ARCH-002;
- `trust.ca.*` belongs exclusively to ARCH-003; and
- `transport.udp.*` and `dns.*` belong exclusively to ARCH-004.

`trust.ca.*` may reuse helper authentication, journal, fencing, and conditional-
restore primitives only through an ARCH-003-defined persistent transaction and
generation. It is not part of the ephemeral network-session graph, and network
stop or lease loss MUST NOT imply CA/trust removal.

The helper serializes actual privileged mutations globally but maintains
separate transaction-class generations, journals, fences, and declared resource
conflict sets. A future unresolved trust transaction blocks a network session
only if ARCH-003 defines that interaction, their resource sets conflict, or
shared helper/journal integrity is unsafe.

This ADR's platform matrix identifies authority and extension availability. It
does not decide HTTP/HTTPS/SOCKS5 semantics, egress validation details, process
loop-exclusion mechanisms, CA state/fingerprint/store scope, UDP flow keys, DNS
metadata, encrypted-DNS visibility, or those domains' support claims. Later
contracts register exact resource schemas through the common journal/fencing
envelope.

## Rejected alternatives

### Let renderer or desktop host elevate for each mutation

Rejected because untrusted web content or compromised unprivileged code would
gain an ambient privilege path, and no boot authority would remain to reconcile
the journal.

### Let helper accept arbitrary commands, paths, or raw OS requests

Rejected because it is equivalent to a local root/admin execution service. Only
compile-time typed operations are permitted.

### Treat sing-box startup/cleanup as the transaction

Rejected because current runtime status and cleanup do not expose per-resource
before/after images, fencing, CAS rollback, external drift, or boot recovery.

### Let helper and sing-box both manage route or DNS state

Rejected because ownership and compensation become ambiguous. Every resource
has exactly one mutation authority.

### Embed libbox to obtain a convenient TUN surface

Rejected for this architecture because it breaks the accepted independent
sing-box managed-process boundary. Internal library interfaces are also not a
versioned external contract.

### Restore the complete baseline after failure

Rejected because it overwrites post-baseline administrator, DHCP, VPN,
resolver, or other application changes. Rollback is field-scoped and
compare-before-restore.

### Use service restart, TUN descriptor close, or ephemeral identifiers as recovery

Rejected because none proves which durable resource belongs to which fenced
generation or whether ordinary connectivity was restored.

## Security and operational consequences

- A broken or unavailable helper fails closed before activation.
- Ambiguity deliberately leaves a diagnosable `RecoveryRequired` state rather
  than risking destructive cleanup.
- The helper becomes a small high-assurance component requiring strict IPC,
  journal, package-signing, and platform API review.
- The independent runtime needs a separately accepted external attachment/
  ownership contract before system-wide mode can be enabled.
- Platform support is narrower than “API exists” and is tied to named release
  package/version tuples and real privileged evidence.
- No existing v0.1 runtime type or fake test is silently promoted into a system
  network claim.

## Verification obligations

Deterministic conformance tests inject failure before and after every durable
boundary, exhaust the state machine, race two controllers, replay stale
requests, corrupt journals, and introduce external drift. Fake backends prove
protocol behavior only.

Every claimed supported host also requires release-packaged, privileged tests
with an out-of-band management path. The suite enumerates actual TUN,
route/rule, firewall, DNS, process, and journal state and checks IPv4, IPv6 when
baselined, resolver operation, route selection, the intended FlowProbe egress,
and a non-FlowProbe ordinary-connectivity control path:

- before start;
- while active;
- after normal stop;
- after UI, Supervisor, runtime, helper, and watchdog crashes;
- after every mutation and direction-specific durable-result crash window;
- after external drift, interface/index/PID reuse, resolver/manager restart,
  sleep/resume or logout; and
- after boot with active, pre-commit, rollback-interrupted, and stale journals.

No support claim is valid if the suite leaves an owned resource, deletes an
unproven resource, overwrites external drift, cannot restore ordinary
connectivity, or terminates an unresolved session as `Inactive` or `Active`.

FlowProbe is unreleased. This architecture directly replaces internal v0
scaffolding; it adds no compatibility shim or migration. Any later production
compatibility or migration requires explicit authorization and a separate
task.
