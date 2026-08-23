# FlowProbe Capture Core

`flowprobe-capture-core` consumes generic directional connection bytes and
emits `flowprobe-model`'s `NormalizedFlowV0`. It does not import sing-box or
encode product-specific hosts, paths, or routing behavior.

The v0 decoder recognizes plaintext HTTP/1, the HTTP/2 client preface and
bounded frames, and TLS records carrying an in-record ClientHello. TLS wire
bytes are kept separate from application bytes supplied by an explicit
successful interception boundary. A passed-through TLS connection therefore
emits connection and TLS metadata without pretending that encrypted bytes are
HTTP. HPACK supports the static table and non-Huffman literal forms needed by
the minimum v0 path; unsupported dynamic references, Huffman strings, and
continued header blocks return structured errors. This path also requires an
initial non-acknowledgement SETTINGS frame from each participating peer, an odd
client stream identifier, ordinary request pseudo-headers, consistent body
semantics, and a complete END_STREAM transition. Text protocols without a
structural HTTP/1.0 or HTTP/1.1 request line remain opaque connections.

Every session has per-direction pending-byte backpressure. Header bytes,
header count, body bytes, HTTP/2 frame payload/count, HPACK strings/table size,
and TLS record/extension counts also have explicit configurable limits with
hard ceilings. Limit failures and recognized malformed/truncated inputs return
`CaptureError`; unrecognized application data produces an opaque connection
flow. Public input Debug output reports byte counts only and never renders
captured bytes.
