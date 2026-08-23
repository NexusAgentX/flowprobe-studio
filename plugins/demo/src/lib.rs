//! Deterministic demo implementation of the Analyzer v0.1 WIT world.

wit_bindgen::generate!({
    path: "../../docs/contracts",
    world: "analyzer",
});

use flowprobe::analyzer::{host, types::SemanticEvent};

struct DemoAnalyzer;

impl Guest for DemoAnalyzer {
    fn info() -> AnalyzerInfo {
        AnalyzerInfo {
            id: "flowprobe.demo".into(),
            version: "0.1.0".into(),
        }
    }

    fn analyze(event: EventRef) -> Result<(), String> {
        let event_json = host::get_event_json(&event)?;
        let event_value: serde_json::Value =
            serde_json::from_str(&event_json).map_err(|_| "invalid normalized event".to_owned())?;
        let timestamp_ns = event_value
            .get("timing")
            .and_then(|timing| timing.get("started_at"))
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "missing timing.started_at".to_owned())?;
        let attributes = serde_json::json!({
            "event_id": event.id,
            "event_kind": event.kind,
            "source": "deterministic-fixture",
        });

        host::emit_semantic(&SemanticEvent {
            namespace: "flowprobe.demo".into(),
            kind: "fixture-observed".into(),
            timestamp_ns,
            json_attributes: attributes.to_string(),
        })
    }
}

export!(DemoAnalyzer);
