# FlowProbe model

`flowprobe-model` owns the NormalizedFlow v0 JSON boundary shared by capture,
storage, desktop queries, and analyzers. It contains data contracts and
validation only; it does not capture traffic or resolve payload references.

Use `NormalizedFlowV0::from_json` and `NormalizedFlowV0::to_canonical_json` at
trust boundaries. These methods validate identity, timing, destination, HTTP,
and opaque-reference invariants. Additive fields are retained in sorted
extension maps, and an unknown protocol kind is retained as opaque JSON so a
v0 consumer can forward records produced by a newer decoder.

`BodyRef` and `BlobRef` are deliberately restricted opaque identifiers. Their
serialized values cannot contain filesystem separators or URI syntax, and the
model exposes no storage lookup path.
