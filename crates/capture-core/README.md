# FlowProbe Capture Core

`flowprobe-capture-core` consumes generic directional connection bytes and
emits `flowprobe-model`'s `NormalizedFlowV0`. It does not import sing-box or
encode product-specific hosts, paths, or routing behavior.

The v0 decoder recognizes plaintext HTTP/1, the HTTP/2 client preface and
bounded frames, and TLS records carrying a bounded ClientHello, including a
ClientHello split across consecutive handshake records. TLS wire
bytes are kept separate from application bytes supplied by an explicit
successful interception boundary. A passed-through TLS connection therefore
emits connection and TLS metadata without pretending that encrypted bytes are
HTTP. HPACK supports the static table and non-Huffman literal forms needed by
the minimum v0 path; unsupported dynamic references, Huffman strings, and
continued header blocks return structured errors. This path also requires an
initial non-acknowledgement SETTINGS frame from each participating peer, an odd
client stream identifier, ordinary request pseudo-headers, consistent body
semantics, valid field and pseudo-header URI values, no connection-specific
fields, valid SETTINGS/control-frame structure, and a complete END_STREAM
transition. Server push is explicitly unsupported. Text protocols without a
structural HTTP/1.0 or HTTP/1.1 request line remain opaque connections.
HTTP/1 CONNECT tunnels and informational response sequences are explicitly
unsupported in the minimum v0 path rather than being decoded as ordinary
message bodies.
ClientHello metadata parsing enforces bounded session identifiers, unique
extension types, non-empty ALPN lists, and valid SNI list structure.

The minimum TLS interception boundary generates a path-length-zero CA in
memory, issues a short-lived end-entity certificate for one exact expected SNI,
and terminates downstream TLS with an explicit rustls ring provider. It
authenticates the upstream server against a separately supplied root store
before reading or forwarding the downstream HTTP request.
The expected downstream DNS identity is normalized to lowercase without an
optional absolute-name trailing dot, matching DNS case semantics and rustls's
RFC 6066 wire SNI form; invalid DNS names still fail closed. The v0 relay handles
one bounded HTTP/1.1 transaction with `Content-Length` framing; unsupported
ALPNs, transfer encoding, pipelining, malformed framing, trust failures,
progress or transcript-limit failures fail closed with typed errors. Socket I/O
has a per-operation idle timeout, while one shared monotonic transaction
deadline covers ClientHello intake, both TLS handshakes, and the HTTP relay; a
peer cannot extend that deadline by trickling bytes before the idle timeout.
TLS handshakes also have an explicit read/write-operation ceiling. The host
supplies already-connected downstream and upstream TCP streams, so Capture Core
remains independent from routing/runtime internals.
CA installation, persistence/rotation, HTTP/2 relay, fallback policy, and
multi-transaction connection handling remain outside this minimum proof.

Every session has per-direction pending-byte backpressure. Header bytes,
header count, body bytes, HTTP/2 frame payload/count, HPACK strings/table size,
and TLS record/extension counts also have explicit configurable limits with
hard ceilings. Limit failures and recognized malformed/truncated inputs return
`CaptureError`; unrecognized application data produces an opaque connection
flow. Public input Debug output reports byte counts only and never renders
captured bytes.
