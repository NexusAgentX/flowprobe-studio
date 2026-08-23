use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::{Mutex, MutexGuard},
};

use flowprobe_ipc::{
    IpcError, IpcErrorCode, SemanticOutputItem, SemanticOutputPage, SemanticPageRequest,
    TrafficDetail, TrafficDetailRequest, TrafficListItem, TrafficPage, TrafficPageRequest,
};
use flowprobe_model::FlowId;
use flowprobe_storage::{
    FlowCursor, FlowIndexRecord, FlowQuery, PageSize, SemanticCursor, SemanticEventRecord,
    SemanticQuery, SqliteMetadataStore,
};

const MAX_OUTSTANDING_CURSORS: usize = 256;
const MAX_CURSOR_TOKEN_BYTES: usize = 64;
const MAX_FLOW_ID_BYTES: usize = 1024;

/// Host-side Traffic query boundary backed by the real metadata store.
///
/// The renderer receives bounded DTO pages and opaque one-shot cursor tokens;
/// it never receives a database handle, SQL text, or payload reference.
pub struct TrafficService {
    state: Mutex<TrafficState>,
}

impl TrafficService {
    #[must_use]
    pub fn new(store: SqliteMetadataStore) -> Self {
        Self {
            state: Mutex::new(TrafficState {
                store,
                flow_cursors: CursorRegistry::new("flow"),
                semantic_cursors: CursorRegistry::new("semantic"),
            }),
        }
    }

    pub fn query_traffic(&self, request: TrafficPageRequest) -> Result<TrafficPage, IpcError> {
        let page_size = validate_page_size(request.page_size)?;
        let mut state = self.lock_state()?;
        let mut query = FlowQuery::new(page_size);
        if let Some(token) = request.cursor {
            if token.len() > MAX_CURSOR_TOKEN_BYTES {
                return Err(invalid_flow_cursor());
            }
            let cursor = state
                .flow_cursors
                .take(&token)
                .ok_or_else(invalid_flow_cursor)?;
            query = query.after(cursor);
        }

        let page = state
            .store
            .query_flows(&query)
            .map_err(|_| storage_unavailable())?;
        let items = page.items.into_iter().map(flow_summary).collect();
        let next_cursor = page
            .next_cursor
            .map(|cursor| state.flow_cursors.insert(cursor));

        Ok(TrafficPage { items, next_cursor })
    }

    pub fn get_traffic_detail(
        &self,
        request: TrafficDetailRequest,
    ) -> Result<TrafficDetail, IpcError> {
        if request.flow_id.len() > MAX_FLOW_ID_BYTES {
            return Err(invalid_flow_id());
        }
        let flow_id = FlowId::new(request.flow_id).map_err(|_| invalid_flow_id())?;
        let state = self.lock_state()?;
        let record = state
            .store
            .get_flow_index(&flow_id)
            .map_err(|_| storage_unavailable())?
            .ok_or_else(flow_not_found)?;

        Ok(flow_detail(&record))
    }

    pub fn query_semantic_output(
        &self,
        request: SemanticPageRequest,
    ) -> Result<SemanticOutputPage, IpcError> {
        let page_size = validate_page_size(request.page_size)?;
        let mut state = self.lock_state()?;
        let mut query = SemanticQuery::new(page_size);
        if let Some(token) = request.cursor {
            if token.len() > MAX_CURSOR_TOKEN_BYTES {
                return Err(invalid_semantic_cursor());
            }
            let cursor = state
                .semantic_cursors
                .take(&token)
                .ok_or_else(invalid_semantic_cursor)?;
            query = query.after(cursor);
        }

        let page = state
            .store
            .query_semantic_events(&query)
            .map_err(|_| storage_unavailable())?;
        let items = page
            .items
            .into_iter()
            .map(semantic_output)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = page
            .next_cursor
            .map(|cursor| state.semantic_cursors.insert(cursor));

        Ok(SemanticOutputPage { items, next_cursor })
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, TrafficState>, IpcError> {
        self.state.lock().map_err(|_| {
            IpcError::new(
                IpcErrorCode::Internal,
                "traffic supervisor state is unavailable",
            )
        })
    }
}

impl fmt::Debug for TrafficService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrafficService")
            .finish_non_exhaustive()
    }
}

struct TrafficState {
    store: SqliteMetadataStore,
    flow_cursors: CursorRegistry<FlowCursor>,
    semantic_cursors: CursorRegistry<SemanticCursor>,
}

struct CursorRegistry<T> {
    prefix: &'static str,
    next_sequence: u64,
    entries: BTreeMap<String, T>,
    insertion_order: VecDeque<String>,
}

impl<T> CursorRegistry<T> {
    fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            next_sequence: 0,
            entries: BTreeMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    fn insert(&mut self, cursor: T) -> String {
        while self.entries.len() >= MAX_OUTSTANDING_CURSORS {
            let Some(expired) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&expired);
        }

        let token = format!("{}-{:016x}", self.prefix, self.next_sequence);
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.entries.insert(token.clone(), cursor);
        self.insertion_order.push_back(token.clone());
        token
    }

    fn take(&mut self, token: &str) -> Option<T> {
        let cursor = self.entries.remove(token)?;
        self.insertion_order.retain(|candidate| candidate != token);
        Some(cursor)
    }
}

fn validate_page_size(value: u16) -> Result<PageSize, IpcError> {
    PageSize::new(value).map_err(|_| {
        IpcError::new(
            IpcErrorCode::InvalidRequest,
            "page size is outside the supported range",
        )
    })
}

fn flow_summary(record: FlowIndexRecord) -> TrafficListItem {
    TrafficListItem {
        flow_id: record.flow_id.as_str().to_owned(),
        started_at_ns: record.started_at.0.to_string(),
        transport_protocol: record.transport_protocol,
        destination_host: record.destination_host,
        destination_ip: record.destination_ip.map(|address| address.to_string()),
        destination_port: record.destination_port,
        protocols: record.protocols,
        http_method: record.http_method,
        http_status: record.http_status,
    }
}

fn flow_detail(record: &FlowIndexRecord) -> TrafficDetail {
    TrafficDetail {
        summary: TrafficListItem {
            flow_id: record.flow_id.as_str().to_owned(),
            started_at_ns: record.started_at.0.to_string(),
            transport_protocol: record.transport_protocol.clone(),
            destination_host: record.destination_host.clone(),
            destination_ip: record.destination_ip.map(|address| address.to_string()),
            destination_port: record.destination_port,
            protocols: record.protocols.clone(),
            http_method: record.http_method.clone(),
            http_status: record.http_status,
        },
        connection_id: record.connection_id.as_str().to_owned(),
        capture_session_id: record
            .capture_session_id
            .as_ref()
            .map(|identifier| identifier.as_str().to_owned()),
        first_byte_at_ns: record
            .first_byte_at
            .map(|timestamp| timestamp.0.to_string()),
        ended_at_ns: record.ended_at.map(|timestamp| timestamp.0.to_string()),
        normalized_source_available: record.normalized_source_ref.is_some(),
    }
}

fn semantic_output(record: SemanticEventRecord) -> Result<SemanticOutputItem, IpcError> {
    let attributes_json = serde_json::to_string_pretty(&record.attributes).map_err(|_| {
        IpcError::new(
            IpcErrorCode::StorageUnavailable,
            "semantic metadata could not be encoded",
        )
    })?;

    Ok(SemanticOutputItem {
        event_id: record.event_id.as_str().to_owned(),
        capture_session_id: record
            .capture_session_id
            .as_ref()
            .map(|identifier| identifier.as_str().to_owned()),
        source_flow_id: record
            .source_flow_id
            .as_ref()
            .map(|identifier| identifier.as_str().to_owned()),
        analyzer_id: record.analyzer_id,
        analyzer_version: record.analyzer_version,
        namespace: record.namespace,
        kind: record.kind,
        timestamp_ns: record.timestamp.0.to_string(),
        attributes_json,
    })
}

fn invalid_flow_cursor() -> IpcError {
    IpcError::new(
        IpcErrorCode::InvalidCursor,
        "traffic cursor is invalid or expired",
    )
}

fn invalid_semantic_cursor() -> IpcError {
    IpcError::new(
        IpcErrorCode::InvalidCursor,
        "semantic cursor is invalid or expired",
    )
}

fn invalid_flow_id() -> IpcError {
    IpcError::new(IpcErrorCode::InvalidRequest, "flow identity is invalid")
}

fn flow_not_found() -> IpcError {
    IpcError::new(IpcErrorCode::NotFound, "traffic flow was not found")
}

fn storage_unavailable() -> IpcError {
    IpcError::new(
        IpcErrorCode::StorageUnavailable,
        "traffic metadata store is unavailable",
    )
}

#[cfg(test)]
mod tests {
    use flowprobe_ipc::{
        IpcErrorCode, SemanticPageRequest, TrafficDetailRequest, TrafficPageRequest,
    };
    use flowprobe_model::{FlowId, NormalizedFlowV0, TimestampNs};
    use flowprobe_storage::{
        SemanticEventId, SemanticEventInput, SemanticSource, SqliteMetadataStore,
    };
    use serde_json::{Value, json};

    use super::TrafficService;

    const GOLDEN_FLOW: &str = include_str!("../../../tests/fixtures/normalized-flow-v0.json");

    fn flow(id: &str, started_at: u64, host: &str) -> NormalizedFlowV0 {
        let mut value: Value = serde_json::from_str(GOLDEN_FLOW).expect("golden flow is valid");
        value
            .as_object_mut()
            .expect("golden flow is an object")
            .remove("capture_session_id");
        value["flow_id"] = json!(id);
        value["connection_id"] = json!(format!("connection_{id}"));
        value["timing"]["started_at"] = json!(started_at);
        value["timing"]["first_byte_at"] = json!(started_at + 1);
        value["timing"]["ended_at"] = json!(started_at + 2);
        value["destination"]["host"] = json!(host);
        NormalizedFlowV0::from_json(&serde_json::to_string(&value).expect("flow encodes"))
            .expect("synthetic flow validates")
    }

    fn populated_service() -> TrafficService {
        let mut store = SqliteMetadataStore::open_in_memory().expect("store opens");
        for (id, started_at, host) in [
            ("flow_old", 10, "old.example"),
            ("flow_middle", 20, "middle.example"),
            ("flow_new", 30, "new.example"),
        ] {
            store
                .upsert_flow_metadata(&flow(id, started_at, host))
                .expect("flow inserts");
        }
        store
            .upsert_semantic_event(&SemanticEventInput {
                event_id: SemanticEventId::new("semantic_new").expect("event id"),
                source: SemanticSource::Flow(FlowId::new("flow_new").expect("flow id")),
                analyzer_id: "demo-analyzer".to_owned(),
                analyzer_version: "0.1.0".to_owned(),
                namespace: "flowprobe.demo".to_owned(),
                kind: "request-summary".to_owned(),
                timestamp: TimestampNs(40),
                attributes: json!({"summary": "fixture analyzed", "requestCount": 1}),
            })
            .expect("semantic event inserts");
        store
            .upsert_semantic_event(&SemanticEventInput {
                event_id: SemanticEventId::new("semantic_old").expect("event id"),
                source: SemanticSource::Global,
                analyzer_id: "demo-analyzer".to_owned(),
                analyzer_version: "0.1.0".to_owned(),
                namespace: "flowprobe.demo".to_owned(),
                kind: "session-summary".to_owned(),
                timestamp: TimestampNs(5),
                attributes: json!({"summary": "older output"}),
            })
            .expect("semantic event inserts");
        TrafficService::new(store)
    }

    #[test]
    fn traffic_query_uses_bounded_keyset_pagination() {
        let service = populated_service();
        let first = service
            .query_traffic(TrafficPageRequest {
                page_size: 2,
                cursor: None,
            })
            .expect("first page");
        assert_eq!(
            first
                .items
                .iter()
                .map(|item| item.flow_id.as_str())
                .collect::<Vec<_>>(),
            ["flow_new", "flow_middle"]
        );
        let cursor = first.next_cursor.expect("second page cursor");

        let second = service
            .query_traffic(TrafficPageRequest {
                page_size: 2,
                cursor: Some(cursor.clone()),
            })
            .expect("second page");
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0].flow_id, "flow_old");
        assert!(second.next_cursor.is_none());

        let reused = service
            .query_traffic(TrafficPageRequest {
                page_size: 2,
                cursor: Some(cursor),
            })
            .expect_err("cursor is one-shot");
        assert_eq!(reused.code, IpcErrorCode::InvalidCursor);
    }

    #[test]
    fn consumed_pagination_cursors_do_not_accumulate_registry_state() {
        let mut store = SqliteMetadataStore::open_in_memory().expect("store opens");
        for sequence in 0..300_u64 {
            let id = format!("flow_page_{sequence:03}");
            store
                .upsert_flow_metadata(&flow(&id, sequence * 10, "bounded.example"))
                .expect("flow inserts");
        }
        let service = TrafficService::new(store);
        let mut cursor = None;
        let mut seen = 0;

        loop {
            let page = service
                .query_traffic(TrafficPageRequest {
                    page_size: 1,
                    cursor,
                })
                .expect("page query succeeds");
            seen += page.items.len();
            let Some(next_cursor) = page.next_cursor else {
                break;
            };
            cursor = Some(next_cursor);
        }

        assert_eq!(seen, 300);
        let state = service.state.lock().expect("state lock remains healthy");
        assert!(state.flow_cursors.entries.is_empty());
        assert!(state.flow_cursors.insertion_order.is_empty());
    }

    #[test]
    fn detail_exposes_normalized_metadata_without_payload_references() {
        let service = populated_service();
        let detail = service
            .get_traffic_detail(TrafficDetailRequest {
                flow_id: "flow_new".to_owned(),
            })
            .expect("detail exists");

        assert_eq!(detail.connection_id, "connection_flow_new");
        assert_eq!(
            detail.summary.destination_host.as_deref(),
            Some("new.example")
        );
        assert_eq!(detail.summary.http_method.as_deref(), Some("POST"));
        assert_eq!(detail.summary.http_status, Some(200));
        assert!(!detail.normalized_source_available);

        let missing = service
            .get_traffic_detail(TrafficDetailRequest {
                flow_id: "flow_missing".to_owned(),
            })
            .expect_err("missing detail");
        assert_eq!(missing.code, IpcErrorCode::NotFound);
    }

    #[test]
    fn semantic_output_queries_real_derived_index_with_pagination() {
        let service = populated_service();
        let first = service
            .query_semantic_output(SemanticPageRequest {
                page_size: 1,
                cursor: None,
            })
            .expect("semantic page");
        assert_eq!(first.items[0].event_id, "semantic_new");
        assert_eq!(first.items[0].source_flow_id.as_deref(), Some("flow_new"));
        assert!(first.items[0].attributes_json.contains("fixture analyzed"));

        let second = service
            .query_semantic_output(SemanticPageRequest {
                page_size: 1,
                cursor: first.next_cursor,
            })
            .expect("semantic second page");
        assert_eq!(second.items[0].event_id, "semantic_old");
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn invalid_requests_return_stable_typed_errors_without_echoing_values() {
        let service = populated_service();
        let page_error = service
            .query_traffic(TrafficPageRequest {
                page_size: 0,
                cursor: None,
            })
            .expect_err("zero page size is invalid");
        assert_eq!(page_error.code, IpcErrorCode::InvalidRequest);

        let invalid_id = " invalid-flow ";
        let detail_error = service
            .get_traffic_detail(TrafficDetailRequest {
                flow_id: invalid_id.to_owned(),
            })
            .expect_err("invalid flow id");
        assert_eq!(detail_error.code, IpcErrorCode::InvalidRequest);
        assert!(!detail_error.message.contains(invalid_id));

        let cursor_error = service
            .query_semantic_output(SemanticPageRequest {
                page_size: 10,
                cursor: Some("attacker-controlled-cursor".to_owned()),
            })
            .expect_err("unknown cursor");
        assert_eq!(cursor_error.code, IpcErrorCode::InvalidCursor);
        assert!(!cursor_error.message.contains("attacker-controlled-cursor"));

        let oversized_cursor = service
            .query_traffic(TrafficPageRequest {
                page_size: 10,
                cursor: Some("x".repeat(65)),
            })
            .expect_err("oversized cursor");
        assert_eq!(oversized_cursor.code, IpcErrorCode::InvalidCursor);

        let oversized_flow = service
            .get_traffic_detail(TrafficDetailRequest {
                flow_id: "x".repeat(1025),
            })
            .expect_err("oversized flow identity");
        assert_eq!(oversized_flow.code, IpcErrorCode::InvalidRequest);
    }
}
