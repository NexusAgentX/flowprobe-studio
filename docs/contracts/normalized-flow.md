# Contract: Normalized Flow v0

Status: Draft for v0.1

NormalizedFlow is the stable boundary between capture/protocol decoding, storage/UI and analyzers.

Minimum identity/timing fields:
- flow_id
- connection_id
- capture_session_id (optional outside explicit session)
- process attribution with confidence/source where available
- started_at / first_byte_at / ended_at
- transport and destination metadata

Protocol representation is additive/tagged. Initial forms include:
- opaque TCP/UDP connection metadata;
- TLS metadata (SNI, ALPN, negotiated version, interception state);
- HTTP request/response transaction metadata;
- streaming events/chunks with relative timing.

HTTP normalized fields include method, scheme, authority/host, path, status, version, content type, request/response byte counts and body references rather than requiring bodies inline.

Payloads are referenced through opaque BodyRef/BlobRef values. Consumers may not assume the storage filesystem layout.

Compatibility rule: additive optional fields are preferred. Breaking representation changes require a new contract version and migration strategy.
