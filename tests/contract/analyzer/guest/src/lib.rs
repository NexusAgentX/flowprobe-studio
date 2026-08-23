//! Deliberately hostile Analyzer v0.1 component used only by sandbox tests.

wit_bindgen::generate!({
    path: "../../../../docs/contracts",
    world: "analyzer",
});

use flowprobe::analyzer::{host, types::SemanticEvent};

struct AdversarialAnalyzer;

impl Guest for AdversarialAnalyzer {
    fn info() -> AnalyzerInfo {
        if cfg!(feature = "hostile-info") {
            let _ = emit(r#"{"from":"info"}"#.into());
            host::log("info", "metadata function attempted a side effect");
        }
        AnalyzerInfo {
            id: "flowprobe.test.adversarial".into(),
            version: if cfg!(feature = "invalid-info") {
                "not-a-semantic-version"
            } else {
                "0.1.0"
            }
            .into(),
        }
    }

    fn analyze(event: EventRef) -> Result<(), String> {
        match event.kind.as_str() {
            "fixture.loop" => {
                let mut value = 0_u64;
                loop {
                    value = std::hint::black_box(value.wrapping_add(1));
                }
            }
            "fixture.memory" => {
                let bytes = vec![1_u8; 64 * 1024 * 1024];
                std::hint::black_box(bytes);
                Ok(())
            }
            "fixture.logs" => {
                for _ in 0..16 {
                    host::log("info", "bounded fixture log");
                }
                Ok(())
            }
            "fixture.outputs" => {
                for sequence in 0..16 {
                    emit(format!(r#"{{"sequence":{sequence}}}"#))?;
                }
                Ok(())
            }
            "fixture.oversized-output" => emit(format!(
                r#"{{"payload":"{}"}}"#,
                "x".repeat(300 * 1024)
            )),
            "fixture.invalid-output" => emit("not-json".into()),
            "fixture.unsorted-output" => {
                emit(r#"{"z":1,"a":{"y":2,"x":3}}"#.into())
            }
            "fixture.unauthorized-event" => {
                let other = EventRef {
                    id: "different-flow".into(),
                    kind: event.kind,
                };
                host::get_event_json(&other).map(|_| ())
            }
            "fixture.event-reads" => {
                for _ in 0..16 {
                    host::get_event_json(&event)?;
                }
                Ok(())
            }
            "fixture.trap" => panic!("deliberate sandbox test trap"),
            "fixture.guest-error" => Err("deliberate guest rejection".into()),
            "fixture.host-log-error" => {
                host::log("info", "host rejects this test log");
                Ok(())
            }
            "fixture.host-emit-error" => emit(r#"{"fixture":true}"#.into()),
            _ => host::get_event_json(&event).map(|_| ()),
        }
    }
}

fn emit(json_attributes: String) -> Result<(), String> {
    host::emit_semantic(&SemanticEvent {
        namespace: "flowprobe.test".into(),
        kind: "adversarial-fixture".into(),
        timestamp_ns: 1,
        json_attributes,
    })
}

export!(AdversarialAnalyzer);
