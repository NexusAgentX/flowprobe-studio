use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use flowprobe_model::{
    BlobRef, CaptureSessionId, ConnectionId, FlowId, NormalizedFlowV0, TimestampNs,
};
use flowprobe_storage::{
    BlobLimits, DeterministicMemoryBlobStore, FlowQuery, LATEST_SCHEMA_VERSION, MAX_PAGE_SIZE,
    OpaquePayloadStore, PageSize, SemanticEventId, SemanticEventInput, SemanticQuery,
    SemanticSource, SettingValue, SqliteMetadataStore, StorageError, TimeRange,
};
use serde_json::{Value, json};

const GOLDEN_FLOW: &str = include_str!("../../../tests/fixtures/normalized-flow-v0.json");
const PAYLOAD_MARKER: &str = "do-not-persist-payload-marker-8d20ec";

static NEXT_TEMP_PATH: AtomicU64 = AtomicU64::new(0);

struct TempDatabase {
    path: PathBuf,
}

impl TempDatabase {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "flowprobe-storage-{label}-{}-{sequence}.sqlite3",
            std::process::id()
        ));
        let _stale_cleanup = fs::remove_file(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-journal", "-shm", "-wal"] {
            let candidate = PathBuf::from(format!("{}{suffix}", self.path.display()));
            let _cleanup_result = fs::remove_file(candidate);
        }
    }
}

fn session_id(value: &str) -> CaptureSessionId {
    CaptureSessionId::new(value).expect("test session id must be valid")
}

fn flow_id(value: &str) -> FlowId {
    FlowId::new(value).expect("test flow id must be valid")
}

fn fixture_value() -> Value {
    serde_json::from_str(GOLDEN_FLOW).expect("checked-in flow fixture must be valid JSON")
}

fn fixture_flow(session: &str, id: &str, started_at: u64, host: &str) -> NormalizedFlowV0 {
    let mut value = fixture_value();
    value["capture_session_id"] = json!(session);
    value["flow_id"] = json!(id);
    value["connection_id"] = json!(format!("connection_{id}"));
    value["timing"]["started_at"] = json!(started_at);
    value["timing"]["first_byte_at"] = json!(started_at);
    value["timing"]["ended_at"] = json!(started_at);
    value["destination"]["host"] = json!(host);
    NormalizedFlowV0::from_json(
        &serde_json::to_string(&value).expect("test flow value must serialize"),
    )
    .expect("synthetic test flow must satisfy the model contract")
}

fn insert_session(store: &SqliteMetadataStore, id: &CaptureSessionId, started_at: u64) {
    store
        .create_capture_session(id, TimestampNs(started_at), None)
        .expect("test session must insert");
}

fn semantic_event(id: &str, source: SemanticSource, timestamp: u64) -> SemanticEventInput {
    SemanticEventInput {
        event_id: SemanticEventId::new(id).expect("test event id must be valid"),
        source,
        analyzer_id: "contract-analyzer".to_owned(),
        analyzer_version: "1.0.0".to_owned(),
        namespace: "security".to_owned(),
        kind: "finding".to_owned(),
        timestamp: TimestampNs(timestamp),
        attributes: json!({"severity": "info", "credential": PAYLOAD_MARKER}),
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn fresh_schema_and_parameterized_settings_are_bounded_and_redacted() {
    let store = SqliteMetadataStore::open_in_memory().expect("fresh schema must initialize");
    assert_eq!(
        store.schema_version().expect("schema version"),
        LATEST_SCHEMA_VERSION
    );

    let injection_shaped_key = "theme'); DELETE FROM settings; --";
    let secret = SettingValue::new("secret-setting-value").expect("bounded setting");
    store
        .set_setting(injection_shaped_key, &secret)
        .expect("parameterized setting insert");
    store
        .set_setting("ordinary", &SettingValue::new("kept").expect("setting"))
        .expect("ordinary setting insert");

    assert_eq!(
        store
            .get_setting(injection_shaped_key)
            .expect("setting lookup")
            .expect("setting exists")
            .expose(),
        "secret-setting-value"
    );
    assert_eq!(
        store
            .get_setting("ordinary")
            .expect("setting lookup")
            .expect("setting exists")
            .expose(),
        "kept"
    );
    assert!(!format!("{secret:?}").contains("secret-setting-value"));
    assert!(PageSize::new(0).is_err());
    assert!(PageSize::new(MAX_PAGE_SIZE + 1).is_err());
    assert!(TimeRange::new(Some(TimestampNs(2)), Some(TimestampNs(1))).is_err());
}

#[test]
fn opening_an_unmarked_nonempty_database_fails_without_overwriting_it() {
    let database = TempDatabase::new("foreign-database");
    {
        let connection = rusqlite::Connection::open(database.path()).expect("foreign DB opens");
        connection
            .execute("CREATE TABLE user_owned(value TEXT NOT NULL)", [])
            .expect("foreign table creates");
        connection
            .execute("INSERT INTO user_owned(value) VALUES ('kept')", [])
            .expect("foreign data inserts");
    }

    assert!(matches!(
        SqliteMetadataStore::open(database.path()),
        Err(StorageError::NotFlowProbeDatabase)
    ));
    let connection = rusqlite::Connection::open(database.path()).expect("foreign DB reopens");
    let value: String = connection
        .query_row("SELECT value FROM user_owned", [], |row| row.get(0))
        .expect("foreign data remains");
    assert_eq!(value, "kept");
}

#[test]
fn metadata_only_flow_write_does_not_persist_full_or_protocol_payload_material() {
    let database = TempDatabase::new("metadata-only");
    let session = session_id("session_metadata_only");
    let mut value = fixture_value();
    value["capture_session_id"] = json!(session.as_str());
    value["flow_id"] = json!("flow_metadata_only");
    value["connection_id"] = json!("connection_metadata_only");
    value["protocols"][2]["metadata"]["request"]["path"] =
        json!(format!("/sensitive/{PAYLOAD_MARKER}"));
    value["protocols"][2]["metadata"]["request"]["authorization"] = json!(PAYLOAD_MARKER);
    value["protocols"][4]["metadata"]["opaque_payload"] = json!(PAYLOAD_MARKER);
    value["captured_full_payload"] = json!(PAYLOAD_MARKER);
    let flow = NormalizedFlowV0::from_json(
        &serde_json::to_string(&value).expect("sensitive synthetic flow must serialize"),
    )
    .expect("sensitive synthetic flow must remain a valid normalized flow");
    assert!(
        flow.to_canonical_json()
            .expect("flow canonical JSON")
            .contains(PAYLOAD_MARKER)
    );

    {
        let mut store = SqliteMetadataStore::open(database.path()).expect("file store opens");
        insert_session(&store, &session, flow.timing.started_at.0);
        store
            .upsert_flow_metadata(&flow)
            .expect("metadata projection must insert");
        let indexed = store
            .get_flow_index(&flow.flow_id)
            .expect("flow lookup")
            .expect("flow index exists");
        assert_eq!(indexed.http_method.as_deref(), Some("POST"));
        assert_eq!(indexed.http_status, Some(200));
        assert_eq!(indexed.destination_host.as_deref(), Some("fixture.example"));
        assert!(indexed.normalized_source_ref.is_none());
    }

    let database_bytes = fs::read(database.path()).expect("SQLite file must be readable");
    for forbidden in [
        PAYLOAD_MARKER,
        "/v1/fixture",
        "body_fixture_request_001",
        "body_fixture_response_001",
        "blob_fixture_stream_001",
    ] {
        assert!(
            !contains_bytes(&database_bytes, forbidden.as_bytes()),
            "metadata-only SQLite file unexpectedly contains {forbidden:?}"
        );
    }
    assert!(contains_bytes(&database_bytes, b"fixture.example"));
}

#[test]
fn flow_query_filters_and_keyset_pagination_are_stable_for_full_u64_time() {
    let mut store = SqliteMetadataStore::open_in_memory().expect("store opens");
    let session = session_id("session_query");
    insert_session(&store, &session, 1);
    for flow in [
        fixture_flow(session.as_str(), "flow_a", 20, "Example.COM"),
        fixture_flow(session.as_str(), "flow_b", 20, "example.com"),
        fixture_flow(session.as_str(), "flow_c", 10, "other.example"),
        fixture_flow(session.as_str(), "flow_max", u64::MAX, "example.com"),
    ] {
        store
            .upsert_flow_metadata(&flow)
            .expect("flow metadata inserts");
    }

    let range =
        TimeRange::new(Some(TimestampNs(20)), Some(TimestampNs(20))).expect("valid time range");
    let first = store
        .query_flows(
            &FlowQuery::new(PageSize::new(1).expect("page size"))
                .with_time_range(range)
                .with_host("EXAMPLE.com")
                .with_protocol("http")
                .for_capture_session(session.clone()),
        )
        .expect("first flow page");
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].flow_id.as_str(), "flow_a");
    let cursor = first.next_cursor.expect("first page has cursor");
    assert_eq!(cursor.started_at(), TimestampNs(20));
    assert_eq!(cursor.flow_id(), "flow_a");

    let second = store
        .query_flows(
            &FlowQuery::new(PageSize::new(1).expect("page size"))
                .with_time_range(range)
                .with_host("example.com")
                .with_protocol("http")
                .for_capture_session(session.clone())
                .after(cursor),
        )
        .expect("second flow page");
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].flow_id.as_str(), "flow_b");
    assert!(second.next_cursor.is_none());

    let all = store
        .query_flows(&FlowQuery::new(PageSize::new(10).expect("page size")))
        .expect("all flow page");
    assert_eq!(all.items[0].flow_id.as_str(), "flow_max");
    assert_eq!(all.items[0].started_at, TimestampNs(u64::MAX));
    assert_eq!(
        store
            .query_flows(
                &FlowQuery::new(PageSize::new(10).expect("page size")).with_protocol("tcp"),
            )
            .expect("transport protocol query")
            .items
            .len(),
        4
    );

    let missing_session_flow = fixture_flow("session_missing", "flow_missing", 30, "missing.test");
    assert!(matches!(
        store.upsert_flow_metadata(&missing_session_flow),
        Err(StorageError::MissingCaptureSession)
    ));
}

#[test]
fn flow_upsert_preserves_stable_identity_and_accepts_metadata_progress() {
    let session = session_id("session_upsert");
    let mut store = SqliteMetadataStore::open_in_memory().expect("store opens");
    insert_session(&store, &session, 1);
    let mut flow = fixture_flow(session.as_str(), "flow_upsert", 2, "before.example");
    store
        .upsert_flow_metadata(&flow)
        .expect("initial flow metadata insert");

    flow.destination.host = Some("after.example".to_owned());
    store
        .upsert_flow_metadata(&flow)
        .expect("ordinary metadata update");
    assert_eq!(
        store
            .get_flow_index(&flow.flow_id)
            .expect("flow lookup")
            .expect("flow exists")
            .destination_host
            .as_deref(),
        Some("after.example")
    );

    flow.connection_id = ConnectionId::new("connection_changed").expect("valid connection id");
    assert!(matches!(
        store.upsert_flow_metadata(&flow),
        Err(StorageError::ImmutableFlowIdentity)
    ));
}

#[test]
fn opaque_blob_backend_is_deterministic_bounded_and_session_deletable() {
    let owner = session_id("session_blob_owner");
    let limits = BlobLimits::new(5, 8, 3).expect("valid limits");
    let mut blobs = DeterministicMemoryBlobStore::new(limits);

    let body = blobs
        .put_body(Some(&owner), b"abc")
        .expect("owned body inserts");
    let blob = blobs
        .put_blob(Some(&owner), b"de")
        .expect("owned blob inserts");
    let global = blobs.put_blob(None, b"f").expect("global blob inserts");
    assert_eq!(body.as_str(), "body_0000000000000000");
    assert_eq!(blob.as_str(), "blob_0000000000000001");
    assert_eq!(global.as_str(), "blob_0000000000000002");
    assert_eq!(
        blobs.read_body(&body).expect("body read"),
        Some(b"abc".to_vec())
    );
    assert!(!format!("{blobs:?}").contains("abc"));
    assert!(blobs.put_blob(None, b"x").is_err());

    let deleted = blobs
        .delete_capture_session(&owner)
        .expect("session payload delete");
    assert_eq!(deleted.bodies, 1);
    assert_eq!(deleted.blobs, 1);
    assert_eq!(deleted.bytes, 5);
    assert_eq!(blobs.read_body(&body).expect("body read"), None);
    assert_eq!(
        blobs.read_blob(&global).expect("global read"),
        Some(b"f".to_vec())
    );
    assert!(blobs.delete_blob(&global).expect("global blob delete"));
    assert!(!blobs.delete_blob(&global).expect("idempotent blob delete"));

    let mut byte_limited =
        DeterministicMemoryBlobStore::new(BlobLimits::new(5, 5, 10).expect("valid byte limits"));
    byte_limited.put_blob(None, b"1234").expect("first blob");
    assert!(byte_limited.put_blob(None, b"12").is_err());
    assert!(byte_limited.put_blob(None, b"123456").is_err());
}

#[test]
fn explicit_opaque_source_link_is_separate_from_metadata_projection() {
    let session = session_id("session_source_link");
    let mut store = SqliteMetadataStore::open_in_memory().expect("store opens");
    insert_session(&store, &session, 1);
    let flow = fixture_flow(session.as_str(), "flow_source_link", 2, "source.example");
    store.upsert_flow_metadata(&flow).expect("metadata insert");

    let mut blobs = DeterministicMemoryBlobStore::default();
    let reference = blobs
        .put_blob(
            Some(&session),
            flow.to_canonical_json().expect("canonical flow").as_bytes(),
        )
        .expect("explicit normalized source write");
    store
        .set_normalized_source_ref(&flow.flow_id, Some(&reference))
        .expect("opaque source link");
    let mut updated_flow = flow.clone();
    updated_flow.destination.host = Some("source-updated.example".to_owned());
    store
        .upsert_flow_metadata(&updated_flow)
        .expect("metadata update preserves source link");
    let indexed = store
        .get_flow_index(&flow.flow_id)
        .expect("flow lookup")
        .expect("flow index");
    assert_eq!(indexed.normalized_source_ref, Some(reference.clone()));
    assert!(blobs.read_blob(&reference).expect("source read").is_some());

    store
        .set_normalized_source_ref(&flow.flow_id, None)
        .expect("source unlink");
    assert!(
        store
            .get_flow_index(&flow.flow_id)
            .expect("flow lookup")
            .expect("flow index")
            .normalized_source_ref
            .is_none()
    );
    assert!(matches!(
        store.set_normalized_source_ref(
            &flow_id("flow_absent"),
            Some(&BlobRef::new("blob_absent").expect("valid blob ref"))
        ),
        Err(StorageError::MissingSourceFlow)
    ));
}

#[test]
fn semantic_output_is_queryable_rebuildable_and_debug_redacted() {
    let session = session_id("session_semantic");
    let mut store = SqliteMetadataStore::open_in_memory().expect("store opens");
    insert_session(&store, &session, 1);
    let flow = fixture_flow(session.as_str(), "flow_semantic", 10, "semantic.example");
    store
        .upsert_flow_metadata(&flow)
        .expect("flow metadata insert");

    let first = semantic_event("event_a", SemanticSource::Flow(flow.flow_id.clone()), 20);
    let second = semantic_event(
        "event_b",
        SemanticSource::CaptureSession(session.clone()),
        20,
    );
    assert!(!format!("{first:?}").contains(PAYLOAD_MARKER));
    store
        .upsert_semantic_event(&first)
        .expect("flow semantic insert");
    store
        .upsert_semantic_event(&second)
        .expect("session semantic insert");

    let first_page = store
        .query_semantic_events(
            &SemanticQuery::new(PageSize::new(1).expect("page size"))
                .with_namespace("security")
                .with_kind("finding")
                .for_capture_session(session.clone()),
        )
        .expect("semantic first page");
    assert_eq!(first_page.items[0].event_id.as_str(), "event_a");
    assert!(!format!("{:?}", first_page.items[0]).contains(PAYLOAD_MARKER));
    let cursor = first_page.next_cursor.expect("semantic cursor");
    assert_eq!(cursor.timestamp(), TimestampNs(20));
    assert_eq!(cursor.event_id(), "event_a");

    let second_page = store
        .query_semantic_events(
            &SemanticQuery::new(PageSize::new(1).expect("page size"))
                .for_capture_session(session.clone())
                .after(cursor),
        )
        .expect("semantic second page");
    assert_eq!(second_page.items[0].event_id.as_str(), "event_b");
    assert!(second_page.next_cursor.is_none());

    assert_eq!(store.clear_semantic_events().expect("clear semantic"), 2);
    assert!(
        store
            .query_semantic_events(&SemanticQuery::new(PageSize::new(10).expect("page size")))
            .expect("semantic query after clear")
            .items
            .is_empty()
    );
    assert!(
        store
            .get_flow_index(&flow.flow_id)
            .expect("flow lookup")
            .is_some()
    );

    let invalid = SemanticEventInput {
        attributes: json!("not an object"),
        ..semantic_event("event_invalid", SemanticSource::Global, 30)
    };
    assert!(matches!(
        store.upsert_semantic_event(&invalid),
        Err(StorageError::InvalidSemanticAttributes)
    ));
    let missing = semantic_event(
        "event_missing",
        SemanticSource::Flow(flow_id("flow_missing")),
        30,
    );
    assert!(matches!(
        store.upsert_semantic_event(&missing),
        Err(StorageError::MissingSourceFlow)
    ));
}

#[test]
fn session_retention_is_bounded_and_cascades_metadata_only() {
    let mut store = SqliteMetadataStore::open_in_memory().expect("store opens");
    let old = session_id("session_old");
    let newer = session_id("session_newer");
    let active = session_id("session_active");
    for (session, started) in [(&old, 1), (&newer, 2), (&active, 3)] {
        insert_session(&store, session, started);
    }
    store
        .finish_capture_session(&old, TimestampNs(10))
        .expect("old session finish");
    store
        .finish_capture_session(&newer, TimestampNs(20))
        .expect("newer session finish");
    let old_flow = fixture_flow(old.as_str(), "flow_old", 5, "old.example");
    let newer_flow = fixture_flow(newer.as_str(), "flow_newer", 6, "newer.example");
    let active_flow = fixture_flow(active.as_str(), "flow_active", 7, "active.example");
    for flow in [&old_flow, &newer_flow, &active_flow] {
        store
            .upsert_flow_metadata(flow)
            .expect("session flow metadata insert");
    }
    store
        .upsert_semantic_event(&semantic_event(
            "event_old",
            SemanticSource::Flow(old_flow.flow_id.clone()),
            8,
        ))
        .expect("old semantic event");
    store
        .upsert_semantic_event(&semantic_event(
            "event_newer",
            SemanticSource::Flow(newer_flow.flow_id.clone()),
            9,
        ))
        .expect("newer semantic event");

    let candidates = store
        .retention_candidates(TimestampNs(20), PageSize::new(1).expect("candidate page"))
        .expect("bounded retention candidates");
    assert_eq!(candidates.as_slice().len(), 1);
    assert_eq!(candidates.as_slice()[0].as_str(), old.as_str());
    assert!(!format!("{candidates:?}").contains(old.as_str()));

    let pruned = store
        .prune_capture_sessions(
            TimestampNs(20),
            PageSize::new(1).expect("bounded retention page"),
        )
        .expect("bounded retention pass");
    assert_eq!(pruned.sessions, 1);
    assert_eq!(pruned.flows, 1);
    assert_eq!(pruned.semantic_events, 1);
    assert!(
        store
            .get_capture_session(&old)
            .expect("old lookup")
            .is_none()
    );
    assert!(
        store
            .get_capture_session(&newer)
            .expect("newer lookup")
            .is_some()
    );
    assert!(
        store
            .get_capture_session(&active)
            .expect("active lookup")
            .is_some()
    );

    let deleted = store
        .delete_capture_session(&newer)
        .expect("explicit session delete");
    assert_eq!(deleted.sessions, 1);
    assert_eq!(deleted.flows, 1);
    assert_eq!(deleted.semantic_events, 1);
    assert!(
        store
            .get_flow_index(&newer_flow.flow_id)
            .expect("flow lookup")
            .is_none()
    );
    assert_eq!(
        store
            .delete_capture_session(&newer)
            .expect("idempotent absent delete"),
        Default::default()
    );

    let second_retention = store
        .prune_capture_sessions(
            TimestampNs(u64::MAX),
            PageSize::new(10).expect("retention page"),
        )
        .expect("retention skips active sessions");
    assert_eq!(second_retention, Default::default());
    assert!(
        store
            .get_capture_session(&active)
            .expect("active lookup")
            .is_some()
    );
}

#[test]
fn errors_and_store_debug_do_not_echo_secret_values() {
    let store = SqliteMetadataStore::open_in_memory().expect("store opens");
    let debug = format!("{store:?}");
    assert!(!debug.contains("sqlite"));

    let secret_key = format!("{}\n", PAYLOAD_MARKER);
    let error = store
        .get_setting(&secret_key)
        .expect_err("control character key must fail");
    let rendered = format!("{error:?}");
    assert!(!rendered.contains(PAYLOAD_MARKER));
    assert!(rendered.contains("setting.key"));

    let sensitive_source = SemanticSource::CaptureSession(session_id(PAYLOAD_MARKER));
    assert!(!format!("{sensitive_source:?}").contains(PAYLOAD_MARKER));
}
