use std::{collections::BTreeSet, error::Error, fmt, net::IpAddr, path::Path, str::FromStr};

#[cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt};

use flowprobe_model::{
    BlobRef, CaptureSessionId, ConnectionId, FlowId, NormalizedFlowV0, ProtocolMetadata,
    TimestampNs,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Row, Transaction, TransactionBehavior, params,
};
use serde_json::Value;

pub const LATEST_SCHEMA_VERSION: u32 = 2;
pub const MAX_PAGE_SIZE: u16 = 200;

const APPLICATION_ID: i64 = 1_179_669_297;
const MAX_IDENTIFIER_BYTES: usize = 1024;
const MAX_HOST_BYTES: usize = 1024;
const MAX_PROTOCOL_BYTES: usize = 128;
const MAX_LABEL_BYTES: usize = 1024;
const MAX_SETTING_KEY_BYTES: usize = 256;
const MAX_SETTING_VALUE_BYTES: usize = 64 * 1024;
const MAX_SEMANTIC_TEXT_BYTES: usize = 512;
const MAX_SEMANTIC_ATTRIBUTES_BYTES: usize = 256 * 1024;
const MAX_PROTOCOL_EVENTS: usize = 4096;
const MAX_PROTOCOLS_JSON_BYTES: usize = MAX_PROTOCOL_EVENTS * (MAX_PROTOCOL_BYTES + 3) + 2;

const SCHEMA_V1: &str = r#"
CREATE TABLE settings (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE capture_sessions (
    session_id TEXT PRIMARY KEY NOT NULL,
    started_at_ns TEXT NOT NULL,
    ended_at_ns TEXT,
    label TEXT
) STRICT;

CREATE TABLE normalized_flows (
    flow_id TEXT PRIMARY KEY NOT NULL,
    connection_id TEXT NOT NULL,
    capture_session_id TEXT REFERENCES capture_sessions(session_id) ON DELETE CASCADE,
    started_at_ns TEXT NOT NULL,
    first_byte_at_ns TEXT,
    ended_at_ns TEXT,
    transport_protocol TEXT NOT NULL,
    destination_host TEXT,
    destination_ip TEXT,
    destination_port INTEGER NOT NULL CHECK(destination_port BETWEEN 1 AND 65535),
    protocols_json TEXT NOT NULL,
    http_method TEXT,
    http_status INTEGER CHECK(http_status BETWEEN 100 AND 599),
    normalized_source_ref TEXT
) STRICT;

CREATE TABLE flow_protocols (
    flow_id TEXT NOT NULL REFERENCES normalized_flows(flow_id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    PRIMARY KEY (flow_id, protocol)
) STRICT;

CREATE TABLE semantic_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    capture_session_id TEXT REFERENCES capture_sessions(session_id) ON DELETE CASCADE,
    source_flow_id TEXT REFERENCES normalized_flows(flow_id) ON DELETE CASCADE,
    analyzer_id TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    timestamp_ns TEXT NOT NULL,
    attributes_json TEXT NOT NULL
) STRICT;
"#;

const MIGRATION_V1_TO_V2: &str = r#"
ALTER TABLE normalized_flows ADD COLUMN host_normalized TEXT;
UPDATE normalized_flows
SET host_normalized = lower(destination_host)
WHERE destination_host IS NOT NULL;

CREATE INDEX capture_sessions_retention_idx
ON capture_sessions(ended_at_ns, session_id)
WHERE ended_at_ns IS NOT NULL;

CREATE INDEX normalized_flows_time_idx
ON normalized_flows(started_at_ns DESC, flow_id ASC);

CREATE INDEX normalized_flows_host_time_idx
ON normalized_flows(host_normalized, started_at_ns DESC, flow_id ASC);

CREATE INDEX normalized_flows_session_time_idx
ON normalized_flows(capture_session_id, started_at_ns DESC, flow_id ASC);

CREATE INDEX flow_protocols_protocol_flow_idx
ON flow_protocols(protocol, flow_id);

CREATE INDEX semantic_events_time_idx
ON semantic_events(timestamp_ns DESC, event_id ASC);

CREATE INDEX semantic_events_session_time_idx
ON semantic_events(capture_session_id, timestamp_ns DESC, event_id ASC);

CREATE INDEX semantic_events_namespace_kind_time_idx
ON semantic_events(namespace, kind, timestamp_ns DESC, event_id ASC);
"#;

/// Typed storage failure that avoids echoing user values or SQL parameters.
pub enum StorageError {
    Database,
    InvalidNormalizedFlow,
    InvalidField {
        field: &'static str,
    },
    FieldTooLong {
        field: &'static str,
        max_bytes: usize,
    },
    TooManyItems {
        field: &'static str,
        max_items: usize,
    },
    InvalidPageSize,
    InvalidTimeRange,
    InvalidSessionTiming,
    SessionAlreadyExists,
    SessionNotFound,
    MissingCaptureSession,
    MissingSourceFlow,
    ImmutableFlowIdentity,
    ImmutableSemanticSource,
    InvalidSemanticAttributes,
    UnsupportedSchemaVersion(i64),
    NotFlowProbeDatabase,
    CorruptData {
        field: &'static str,
    },
    IntegerOutOfRange {
        field: &'static str,
    },
}

impl fmt::Debug for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database => formatter.write_str("SQLite metadata operation failed"),
            Self::InvalidNormalizedFlow => {
                formatter.write_str("normalized flow failed contract validation")
            }
            Self::InvalidField { field } => write!(formatter, "invalid storage field {field}"),
            Self::FieldTooLong { field, max_bytes } => {
                write!(formatter, "storage field {field} exceeds {max_bytes} bytes")
            }
            Self::TooManyItems { field, max_items } => {
                write!(formatter, "storage field {field} exceeds {max_items} items")
            }
            Self::InvalidPageSize => {
                write!(formatter, "page size must be between 1 and {MAX_PAGE_SIZE}")
            }
            Self::InvalidTimeRange => formatter.write_str("invalid storage time range"),
            Self::InvalidSessionTiming => {
                formatter.write_str("capture session end precedes its start")
            }
            Self::SessionAlreadyExists => formatter.write_str("capture session already exists"),
            Self::SessionNotFound => formatter.write_str("capture session was not found"),
            Self::MissingCaptureSession => {
                formatter.write_str("referenced capture session was not found")
            }
            Self::MissingSourceFlow => {
                formatter.write_str("referenced normalized flow was not found")
            }
            Self::ImmutableFlowIdentity => {
                formatter.write_str("normalized flow immutable identity fields changed")
            }
            Self::ImmutableSemanticSource => {
                formatter.write_str("semantic event source boundary changed")
            }
            Self::InvalidSemanticAttributes => {
                formatter.write_str("semantic attributes must be a bounded JSON object")
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "unsupported local storage schema version {version}"
                )
            }
            Self::NotFlowProbeDatabase => {
                formatter.write_str("database is not an initialized FlowProbe storage file")
            }
            Self::CorruptData { field } => {
                write!(formatter, "stored metadata field {field} is corrupt")
            }
            Self::IntegerOutOfRange { field } => {
                write!(formatter, "integer field {field} is out of range")
            }
        }
    }
}

impl Error for StorageError {}

impl From<rusqlite::Error> for StorageError {
    fn from(_error: rusqlite::Error) -> Self {
        Self::Database
    }
}

/// A validated, bounded query page size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSize(u16);

impl PageSize {
    pub fn new(value: u16) -> Result<Self, StorageError> {
        if value == 0 || value > MAX_PAGE_SIZE {
            Err(StorageError::InvalidPageSize)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Inclusive started-at bounds for stable flow queries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeRange {
    pub start_inclusive: Option<TimestampNs>,
    pub end_inclusive: Option<TimestampNs>,
}

impl TimeRange {
    pub fn new(
        start_inclusive: Option<TimestampNs>,
        end_inclusive: Option<TimestampNs>,
    ) -> Result<Self, StorageError> {
        if start_inclusive
            .zip(end_inclusive)
            .is_some_and(|(start, end)| start > end)
        {
            return Err(StorageError::InvalidTimeRange);
        }
        Ok(Self {
            start_inclusive,
            end_inclusive,
        })
    }
}

/// Opaque keyset position returned by a flow page.
#[derive(Clone, PartialEq, Eq)]
pub struct FlowCursor {
    started_at: TimestampNs,
    flow_id: String,
}

impl FlowCursor {
    #[must_use]
    pub const fn started_at(&self) -> TimestampNs {
        self.started_at
    }

    #[must_use]
    pub fn flow_id(&self) -> &str {
        &self.flow_id
    }
}

impl fmt::Debug for FlowCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowCursor")
            .field("started_at", &self.started_at)
            .field("flow_id", &"[OPAQUE]")
            .finish()
    }
}

/// Fixed-shape filters for the Traffic UI flow index.
#[derive(Clone, PartialEq, Eq)]
pub struct FlowQuery {
    page_size: PageSize,
    time_range: TimeRange,
    host: Option<String>,
    protocol: Option<String>,
    capture_session_id: Option<CaptureSessionId>,
    after: Option<FlowCursor>,
}

impl FlowQuery {
    #[must_use]
    pub fn new(page_size: PageSize) -> Self {
        Self {
            page_size,
            time_range: TimeRange::default(),
            host: None,
            protocol: None,
            capture_session_id: None,
            after: None,
        }
    }

    #[must_use]
    pub const fn with_time_range(mut self, time_range: TimeRange) -> Self {
        self.time_range = time_range;
        self
    }

    #[must_use]
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    #[must_use]
    pub fn for_capture_session(mut self, session_id: CaptureSessionId) -> Self {
        self.capture_session_id = Some(session_id);
        self
    }

    #[must_use]
    pub fn after(mut self, cursor: FlowCursor) -> Self {
        self.after = Some(cursor);
        self
    }
}

impl fmt::Debug for FlowQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowQuery")
            .field("page_size", &self.page_size)
            .field("time_range", &self.time_range)
            .field("has_host", &self.host.is_some())
            .field("has_protocol", &self.protocol.is_some())
            .field("has_capture_session", &self.capture_session_id.is_some())
            .field("after", &self.after)
            .finish()
    }
}

/// Metadata/index projection of a NormalizedFlow. No payload or HTTP path is stored.
#[derive(Clone, PartialEq, Eq)]
pub struct FlowIndexRecord {
    pub flow_id: FlowId,
    pub connection_id: ConnectionId,
    pub capture_session_id: Option<CaptureSessionId>,
    pub started_at: TimestampNs,
    pub first_byte_at: Option<TimestampNs>,
    pub ended_at: Option<TimestampNs>,
    pub transport_protocol: String,
    pub destination_host: Option<String>,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: u16,
    pub protocols: Vec<String>,
    pub http_method: Option<String>,
    pub http_status: Option<u16>,
    pub normalized_source_ref: Option<BlobRef>,
}

impl fmt::Debug for FlowIndexRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowIndexRecord")
            .field("flow_id", &"[OPAQUE]")
            .field("connection_id", &"[OPAQUE]")
            .field("has_capture_session", &self.capture_session_id.is_some())
            .field("started_at", &self.started_at)
            .field("first_byte_at", &self.first_byte_at)
            .field("ended_at", &self.ended_at)
            .field("transport_protocol", &self.transport_protocol)
            .field("has_destination_host", &self.destination_host.is_some())
            .field("destination_ip", &self.destination_ip)
            .field("destination_port", &self.destination_port)
            .field("protocols", &self.protocols)
            .field("http_method", &self.http_method)
            .field("http_status", &self.http_status)
            .field(
                "has_normalized_source",
                &self.normalized_source_ref.is_some(),
            )
            .finish()
    }
}

/// One bounded flow query page.
#[derive(Clone, PartialEq, Eq)]
pub struct FlowPage {
    pub items: Vec<FlowIndexRecord>,
    pub next_cursor: Option<FlowCursor>,
}

impl fmt::Debug for FlowPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowPage")
            .field("item_count", &self.items.len())
            .field("next_cursor", &self.next_cursor)
            .finish()
    }
}

/// A capture session boundary used for retention and cascading deletion.
#[derive(Clone, PartialEq, Eq)]
pub struct CaptureSessionRecord {
    pub session_id: CaptureSessionId,
    pub started_at: TimestampNs,
    pub ended_at: Option<TimestampNs>,
    pub label: Option<String>,
}

impl fmt::Debug for CaptureSessionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureSessionRecord")
            .field("session_id", &"[OPAQUE]")
            .field("started_at", &self.started_at)
            .field("ended_at", &self.ended_at)
            .field("has_label", &self.label.is_some())
            .finish()
    }
}

/// Cascaded metadata counts from a session deletion/retention operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeletionSummary {
    pub sessions: u64,
    pub flows: u64,
    pub semantic_events: u64,
}

/// Bounded session identities selected for a coordinated retention pass.
#[derive(Clone, PartialEq, Eq)]
pub struct RetentionCandidates {
    session_ids: Vec<CaptureSessionId>,
}

impl RetentionCandidates {
    #[must_use]
    pub fn as_slice(&self) -> &[CaptureSessionId] {
        &self.session_ids
    }

    #[must_use]
    pub fn into_ids(self) -> Vec<CaptureSessionId> {
        self.session_ids
    }
}

impl fmt::Debug for RetentionCandidates {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetentionCandidates")
            .field("session_count", &self.session_ids.len())
            .finish()
    }
}

/// Setting value whose Debug representation never reveals its contents.
#[derive(Clone, PartialEq, Eq)]
pub struct SettingValue(String);

impl SettingValue {
    pub fn new(value: impl Into<String>) -> Result<Self, StorageError> {
        let value = value.into();
        if value.len() > MAX_SETTING_VALUE_BYTES {
            return Err(StorageError::FieldTooLong {
                field: "setting.value",
                max_bytes: MAX_SETTING_VALUE_BYTES,
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SettingValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SettingValue([REDACTED])")
    }
}

/// Stable identity of one derived semantic event.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticEventId(String);

impl SemanticEventId {
    pub fn new(value: impl Into<String>) -> Result<Self, StorageError> {
        let value = value.into();
        validate_identifier("semantic.event_id", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SemanticEventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SemanticEventId([OPAQUE])")
    }
}

/// Source boundary for rebuildable semantic output.
#[derive(Clone, PartialEq, Eq)]
pub enum SemanticSource {
    Flow(FlowId),
    CaptureSession(CaptureSessionId),
    Global,
}

impl fmt::Debug for SemanticSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flow(_) => formatter.write_str("SemanticSource::Flow([OPAQUE])"),
            Self::CaptureSession(_) => {
                formatter.write_str("SemanticSource::CaptureSession([OPAQUE])")
            }
            Self::Global => formatter.write_str("SemanticSource::Global"),
        }
    }
}

/// Host-owned semantic event input. Attributes are never included in Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct SemanticEventInput {
    pub event_id: SemanticEventId,
    pub source: SemanticSource,
    pub analyzer_id: String,
    pub analyzer_version: String,
    pub namespace: String,
    pub kind: String,
    pub timestamp: TimestampNs,
    pub attributes: Value,
}

impl fmt::Debug for SemanticEventInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticEventInput")
            .field("event_id", &self.event_id)
            .field("source", &self.source)
            .field("analyzer_id", &"[REDACTED]")
            .field("analyzer_version", &"[REDACTED]")
            .field("namespace", &"[REDACTED]")
            .field("kind", &"[REDACTED]")
            .field("timestamp", &self.timestamp)
            .field("attributes", &"[REDACTED]")
            .finish()
    }
}

/// Materialized semantic index row. Attributes remain rebuildable derived data.
#[derive(Clone, PartialEq, Eq)]
pub struct SemanticEventRecord {
    pub event_id: SemanticEventId,
    pub capture_session_id: Option<CaptureSessionId>,
    pub source_flow_id: Option<FlowId>,
    pub analyzer_id: String,
    pub analyzer_version: String,
    pub namespace: String,
    pub kind: String,
    pub timestamp: TimestampNs,
    pub attributes: Value,
}

impl fmt::Debug for SemanticEventRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticEventRecord")
            .field("event_id", &self.event_id)
            .field("has_capture_session", &self.capture_session_id.is_some())
            .field("has_source_flow", &self.source_flow_id.is_some())
            .field("analyzer_id", &"[REDACTED]")
            .field("analyzer_version", &"[REDACTED]")
            .field("namespace", &"[REDACTED]")
            .field("kind", &"[REDACTED]")
            .field("timestamp", &self.timestamp)
            .field("attributes", &"[REDACTED]")
            .finish()
    }
}

/// Opaque keyset position returned by a semantic page.
#[derive(Clone, PartialEq, Eq)]
pub struct SemanticCursor {
    timestamp: TimestampNs,
    event_id: String,
}

impl SemanticCursor {
    #[must_use]
    pub const fn timestamp(&self) -> TimestampNs {
        self.timestamp
    }

    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
}

impl fmt::Debug for SemanticCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticCursor")
            .field("timestamp", &self.timestamp)
            .field("event_id", &"[OPAQUE]")
            .finish()
    }
}

/// Bounded fixed-shape semantic index filters.
#[derive(Clone, PartialEq, Eq)]
pub struct SemanticQuery {
    page_size: PageSize,
    time_range: TimeRange,
    namespace: Option<String>,
    kind: Option<String>,
    capture_session_id: Option<CaptureSessionId>,
    after: Option<SemanticCursor>,
}

impl SemanticQuery {
    #[must_use]
    pub fn new(page_size: PageSize) -> Self {
        Self {
            page_size,
            time_range: TimeRange::default(),
            namespace: None,
            kind: None,
            capture_session_id: None,
            after: None,
        }
    }

    #[must_use]
    pub const fn with_time_range(mut self, time_range: TimeRange) -> Self {
        self.time_range = time_range;
        self
    }

    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    #[must_use]
    pub fn with_kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = Some(kind.into());
        self
    }

    #[must_use]
    pub fn for_capture_session(mut self, session_id: CaptureSessionId) -> Self {
        self.capture_session_id = Some(session_id);
        self
    }

    #[must_use]
    pub fn after(mut self, cursor: SemanticCursor) -> Self {
        self.after = Some(cursor);
        self
    }
}

impl fmt::Debug for SemanticQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticQuery")
            .field("page_size", &self.page_size)
            .field("time_range", &self.time_range)
            .field("has_namespace", &self.namespace.is_some())
            .field("has_kind", &self.kind.is_some())
            .field("has_capture_session", &self.capture_session_id.is_some())
            .field("after", &self.after)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SemanticPage {
    pub items: Vec<SemanticEventRecord>,
    pub next_cursor: Option<SemanticCursor>,
}

impl fmt::Debug for SemanticPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticPage")
            .field("item_count", &self.items.len())
            .field("next_cursor", &self.next_cursor)
            .finish()
    }
}

/// Host-side SQLite metadata store. No connection or SQL handle is exposed.
pub struct SqliteMetadataStore {
    connection: Connection,
}

impl fmt::Debug for SqliteMetadataStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteMetadataStore")
            .finish_non_exhaustive()
    }
}

impl SqliteMetadataStore {
    /// Opens or creates a host-owned SQLite storage file and applies migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        #[cfg(unix)]
        let path = {
            let file_name = path.file_name().ok_or(StorageError::Database)?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            fs::canonicalize(parent)
                .map_err(|_error| StorageError::Database)?
                .join(file_name)
        };
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags)?;
        connection.execute_batch("PRAGMA busy_timeout = 5000;")?;
        #[cfg(unix)]
        {
            if is_flowprobe_or_empty_database(&connection)? {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .map_err(|_error| StorageError::Database)?;
            }
        }
        Self::initialize(connection)
    }

    /// Creates a deterministic in-memory SQLite backend for behavior tests.
    pub fn open_in_memory() -> Result<Self, StorageError> {
        Self::initialize(Connection::open_in_memory()?)
    }

    fn initialize(mut connection: Connection) -> Result<Self, StorageError> {
        connection.execute_batch(
            r#"PRAGMA foreign_keys = ON;
               PRAGMA trusted_schema = OFF;
               PRAGMA secure_delete = ON;
               PRAGMA busy_timeout = 5000;"#,
        )?;

        let application_id: i64 =
            connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let schema_version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;

        if schema_version == 0 {
            if application_id != 0 && application_id != APPLICATION_ID {
                return Err(StorageError::NotFlowProbeDatabase);
            }
            let schema_object_count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            if schema_object_count != 0 {
                return Err(StorageError::NotFlowProbeDatabase);
            }
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(SCHEMA_V1)?;
            transaction
                .execute_batch("PRAGMA application_id = 1179669297; PRAGMA user_version = 1;")?;
            transaction.commit()?;
        } else if application_id != APPLICATION_ID {
            return Err(StorageError::NotFlowProbeDatabase);
        }

        let mut version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 1 {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(MIGRATION_V1_TO_V2)?;
            transaction.execute_batch("PRAGMA user_version = 2;")?;
            transaction.commit()?;
            version = 2;
        }
        if version != i64::from(LATEST_SCHEMA_VERSION) {
            return Err(StorageError::UnsupportedSchemaVersion(version));
        }

        connection.prepare("SELECT flow_id, host_normalized FROM normalized_flows LIMIT 0")?;
        Ok(Self { connection })
    }

    /// Current on-disk schema version after migrations.
    pub fn schema_version(&self) -> Result<u32, StorageError> {
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        u32::try_from(version).map_err(|_| StorageError::IntegerOutOfRange {
            field: "schema_version",
        })
    }

    /// Stores a bounded setting using parameterized SQL.
    pub fn set_setting(&self, key: &str, value: &SettingValue) -> Result<(), StorageError> {
        validate_setting_key(key)?;
        self.connection.execute(
            r#"INSERT INTO settings(key, value) VALUES (?1, ?2)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
            params![key, value.expose()],
        )?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<SettingValue>, StorageError> {
        validate_setting_key(key)?;
        let value: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        value.map(SettingValue::new).transpose()
    }

    pub fn delete_setting(&self, key: &str) -> Result<bool, StorageError> {
        validate_setting_key(key)?;
        Ok(self
            .connection
            .execute("DELETE FROM settings WHERE key = ?1", params![key])?
            != 0)
    }

    /// Starts an explicit capture/retention boundary.
    pub fn create_capture_session(
        &self,
        session_id: &CaptureSessionId,
        started_at: TimestampNs,
        label: Option<&str>,
    ) -> Result<(), StorageError> {
        validate_identifier("capture_session_id", session_id.as_str())?;
        if let Some(label) = label {
            ensure_bounded_text("capture_session.label", label, MAX_LABEL_BYTES, false)?;
        }
        let inserted = self.connection.execute(
            r#"INSERT OR IGNORE INTO capture_sessions(session_id, started_at_ns, label)
               VALUES (?1, ?2, ?3)"#,
            params![session_id.as_str(), timestamp_key(started_at), label],
        )?;
        if inserted == 0 {
            Err(StorageError::SessionAlreadyExists)
        } else {
            Ok(())
        }
    }

    /// Marks a capture session complete without allowing its retention boundary to move.
    pub fn finish_capture_session(
        &self,
        session_id: &CaptureSessionId,
        ended_at: TimestampNs,
    ) -> Result<(), StorageError> {
        validate_identifier("capture_session_id", session_id.as_str())?;
        let existing: Option<(String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT started_at_ns, ended_at_ns FROM capture_sessions WHERE session_id = ?1",
                params![session_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((started_at_key, existing_end)) = existing else {
            return Err(StorageError::SessionNotFound);
        };
        let started_at = parse_timestamp(&started_at_key, "capture_session.started_at")?;
        if ended_at < started_at {
            return Err(StorageError::InvalidSessionTiming);
        }
        let end_key = timestamp_key(ended_at);
        if let Some(existing_end) = existing_end {
            return if existing_end == end_key {
                Ok(())
            } else {
                Err(StorageError::InvalidSessionTiming)
            };
        }
        let changed = self.connection.execute(
            r#"UPDATE capture_sessions SET ended_at_ns = ?2
               WHERE session_id = ?1 AND started_at_ns = ?3 AND ended_at_ns IS NULL"#,
            params![session_id.as_str(), end_key, started_at_key],
        )?;
        if changed == 1 {
            return Ok(());
        }

        let current: Option<(String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT started_at_ns, ended_at_ns FROM capture_sessions WHERE session_id = ?1",
                params![session_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match current {
            None => Err(StorageError::SessionNotFound),
            Some((current_start, Some(current_end)))
                if current_start == started_at_key && current_end == end_key =>
            {
                Ok(())
            }
            Some(_) => Err(StorageError::InvalidSessionTiming),
        }
    }

    pub fn get_capture_session(
        &self,
        session_id: &CaptureSessionId,
    ) -> Result<Option<CaptureSessionRecord>, StorageError> {
        validate_identifier("capture_session_id", session_id.as_str())?;
        let row: Option<(String, Option<String>, Option<String>)> = self
            .connection
            .query_row(
                "SELECT started_at_ns, ended_at_ns, label FROM capture_sessions WHERE session_id = ?1",
                params![session_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(started_at, ended_at, label)| {
            if let Some(label) = label.as_deref() {
                validate_stored_text("capture_session.label", label, MAX_LABEL_BYTES)?;
            }
            Ok(CaptureSessionRecord {
                session_id: session_id.clone(),
                started_at: parse_timestamp(&started_at, "capture_session.started_at")?,
                ended_at: parse_optional_timestamp(
                    ended_at.as_deref(),
                    "capture_session.ended_at",
                )?,
                label,
            })
        })
        .transpose()
    }

    /// Selects a bounded stable set for host-coordinated metadata/payload retention.
    pub fn retention_candidates(
        &self,
        cutoff: TimestampNs,
        limit: PageSize,
    ) -> Result<RetentionCandidates, StorageError> {
        let mut statement = self.connection.prepare(
            r#"SELECT session_id FROM capture_sessions
               WHERE ended_at_ns IS NOT NULL AND ended_at_ns <= ?1
               ORDER BY ended_at_ns ASC, session_id ASC
               LIMIT ?2"#,
        )?;
        let mapped = statement.query_map(
            params![timestamp_key(cutoff), i64::from(limit.get())],
            |row| row.get::<_, String>(0),
        )?;
        let mut session_ids = Vec::new();
        for value in mapped {
            session_ids.push(decode_capture_session_id(
                value?,
                "retention.capture_session_id",
            )?);
        }
        Ok(RetentionCandidates { session_ids })
    }

    /// Inserts or updates only the typed metadata/index projection of a flow.
    ///
    /// This method has no payload parameter and never serializes the full flow.
    pub fn upsert_flow_metadata(&mut self, flow: &NormalizedFlowV0) -> Result<(), StorageError> {
        flow.validate()
            .map_err(|_| StorageError::InvalidNormalizedFlow)?;
        validate_identifier("flow_id", flow.flow_id.as_str())?;
        validate_identifier("connection_id", flow.connection_id.as_str())?;
        if let Some(session_id) = &flow.capture_session_id {
            validate_identifier("capture_session_id", session_id.as_str())?;
        }
        if flow.protocols.len() > MAX_PROTOCOL_EVENTS {
            return Err(StorageError::TooManyItems {
                field: "protocols",
                max_items: MAX_PROTOCOL_EVENTS,
            });
        }

        let transport_protocol = flow.transport.protocol.as_str();
        ensure_bounded_text(
            "transport.protocol",
            transport_protocol,
            MAX_PROTOCOL_BYTES,
            false,
        )?;
        if let Some(host) = flow.destination.host.as_deref() {
            ensure_bounded_text("destination.host", host, MAX_HOST_BYTES, false)?;
        }
        let protocols = protocol_kinds(flow)?;
        let protocols_json = serde_json::to_string(&protocols)
            .map_err(|_| StorageError::CorruptData { field: "protocols" })?;
        let (http_method, http_status) = http_summary(flow);
        if let Some(method) = http_method.as_deref() {
            ensure_bounded_text("http.method", method, MAX_PROTOCOL_BYTES, false)?;
        }

        let flow_id = flow.flow_id.as_str();
        let connection_id = flow.connection_id.as_str();
        let session_id = flow
            .capture_session_id
            .as_ref()
            .map(CaptureSessionId::as_str);
        let started_at = timestamp_key(flow.timing.started_at);
        let first_byte_at = flow.timing.first_byte_at.map(timestamp_key);
        let ended_at = flow.timing.ended_at.map(timestamp_key);
        let destination_host = flow.destination.host.as_deref();
        let host_normalized = destination_host.map(normalize_host);
        let destination_ip = flow.destination.ip.map(|value| value.to_string());
        let destination_port = i64::from(flow.destination.port);
        let http_status = http_status.map(i64::from);

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(session_id) = session_id {
            ensure_session_exists(&transaction, session_id)?;
        }
        let existing: Option<(String, Option<String>, String)> = transaction
            .query_row(
                r#"SELECT connection_id, capture_session_id, started_at_ns
                   FROM normalized_flows WHERE flow_id = ?1"#,
                params![flow_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if existing
            .as_ref()
            .is_some_and(|(stored_connection, stored_session, stored_started)| {
                stored_connection != connection_id
                    || stored_session.as_deref() != session_id
                    || stored_started != &started_at
            })
        {
            return Err(StorageError::ImmutableFlowIdentity);
        }

        transaction.execute(
            r#"INSERT INTO normalized_flows(
                   flow_id, connection_id, capture_session_id, started_at_ns, first_byte_at_ns,
                   ended_at_ns, transport_protocol, destination_host, destination_ip,
                   destination_port, protocols_json, http_method, http_status, host_normalized
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
               ON CONFLICT(flow_id) DO UPDATE SET
                   first_byte_at_ns = excluded.first_byte_at_ns,
                   ended_at_ns = excluded.ended_at_ns,
                   transport_protocol = excluded.transport_protocol,
                   destination_host = excluded.destination_host,
                   destination_ip = excluded.destination_ip,
                   destination_port = excluded.destination_port,
                   protocols_json = excluded.protocols_json,
                   http_method = excluded.http_method,
                   http_status = excluded.http_status,
                   host_normalized = excluded.host_normalized"#,
            params![
                flow_id,
                connection_id,
                session_id,
                started_at,
                first_byte_at,
                ended_at,
                transport_protocol,
                destination_host,
                destination_ip,
                destination_port,
                protocols_json,
                http_method,
                http_status,
                host_normalized,
            ],
        )?;
        transaction.execute(
            "DELETE FROM flow_protocols WHERE flow_id = ?1",
            params![flow_id],
        )?;
        for protocol in protocols {
            transaction.execute(
                "INSERT INTO flow_protocols(flow_id, protocol) VALUES (?1, ?2)",
                params![flow_id, protocol],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Links explicitly retained normalized source material by opaque reference.
    pub fn set_normalized_source_ref(
        &self,
        flow_id: &FlowId,
        reference: Option<&BlobRef>,
    ) -> Result<(), StorageError> {
        validate_identifier("flow_id", flow_id.as_str())?;
        let changed = self.connection.execute(
            "UPDATE normalized_flows SET normalized_source_ref = ?2 WHERE flow_id = ?1",
            params![flow_id.as_str(), reference.map(BlobRef::as_str)],
        )?;
        if changed == 0 {
            Err(StorageError::MissingSourceFlow)
        } else {
            Ok(())
        }
    }

    pub fn get_flow_index(
        &self,
        flow_id: &FlowId,
    ) -> Result<Option<FlowIndexRecord>, StorageError> {
        validate_identifier("flow_id", flow_id.as_str())?;
        let mut statement = self.connection.prepare(
            r#"SELECT flow_id, connection_id, capture_session_id, started_at_ns,
                      first_byte_at_ns, ended_at_ns, transport_protocol, destination_host,
                      destination_ip, destination_port, protocols_json, http_method,
                      http_status, normalized_source_ref
               FROM normalized_flows WHERE flow_id = ?1"#,
        )?;
        let mut rows = statement.query(params![flow_id.as_str()])?;
        rows.next()?.map(decode_flow_row).transpose()
    }

    /// Performs a bounded, parameterized keyset query ordered by time then flow id.
    pub fn query_flows(&self, query: &FlowQuery) -> Result<FlowPage, StorageError> {
        validate_time_range(query.time_range)?;
        let host = query
            .host
            .as_deref()
            .map(|value| {
                ensure_bounded_text("query.host", value, MAX_HOST_BYTES, false)?;
                Ok::<String, StorageError>(normalize_host(value))
            })
            .transpose()?;
        let protocol = query
            .protocol
            .as_deref()
            .map(|value| {
                ensure_bounded_text("query.protocol", value, MAX_PROTOCOL_BYTES, false)?;
                Ok::<String, StorageError>(value.to_owned())
            })
            .transpose()?;
        let start = query.time_range.start_inclusive.map(timestamp_key);
        let end = query.time_range.end_inclusive.map(timestamp_key);
        let session = query
            .capture_session_id
            .as_ref()
            .map(CaptureSessionId::as_str);
        if let Some(session) = session {
            validate_identifier("query.capture_session_id", session)?;
        }
        let cursor_time = query
            .after
            .as_ref()
            .map(|cursor| timestamp_key(cursor.started_at));
        let cursor_id = query.after.as_ref().map(|cursor| cursor.flow_id.as_str());
        let limit = i64::from(query.page_size.get()) + 1;

        let mut statement = self.connection.prepare(
            r#"SELECT f.flow_id, f.connection_id, f.capture_session_id, f.started_at_ns,
                      f.first_byte_at_ns, f.ended_at_ns, f.transport_protocol,
                      f.destination_host, f.destination_ip, f.destination_port,
                      f.protocols_json, f.http_method, f.http_status, f.normalized_source_ref
               FROM normalized_flows AS f
               WHERE (?1 IS NULL OR f.started_at_ns >= ?1)
                 AND (?2 IS NULL OR f.started_at_ns <= ?2)
                 AND (?3 IS NULL OR f.host_normalized = ?3)
                 AND (?4 IS NULL OR f.transport_protocol = ?4 OR EXISTS (
                     SELECT 1 FROM flow_protocols AS p
                     WHERE p.flow_id = f.flow_id AND p.protocol = ?4
                 ))
                 AND (?5 IS NULL OR f.capture_session_id = ?5)
                 AND (?6 IS NULL OR f.started_at_ns < ?6
                      OR (f.started_at_ns = ?6 AND f.flow_id > ?7))
               ORDER BY f.started_at_ns DESC, f.flow_id ASC
               LIMIT ?8"#,
        )?;
        let mut rows = statement.query(params![
            start.as_deref(),
            end.as_deref(),
            host.as_deref(),
            protocol.as_deref(),
            session,
            cursor_time.as_deref(),
            cursor_id,
            limit,
        ])?;
        let mut items = Vec::with_capacity(usize::from(query.page_size.get()) + 1);
        while let Some(row) = rows.next()? {
            items.push(decode_flow_row(row)?);
        }
        let has_more = items.len() > usize::from(query.page_size.get());
        if has_more {
            items.pop();
        }
        let next_cursor = if has_more {
            let Some(last) = items.last() else {
                return Err(StorageError::CorruptData {
                    field: "flow pagination",
                });
            };
            Some(FlowCursor {
                started_at: last.started_at,
                flow_id: last.flow_id.as_str().to_owned(),
            })
        } else {
            None
        };
        Ok(FlowPage { items, next_cursor })
    }

    /// Inserts or replaces one bounded rebuildable semantic event.
    pub fn upsert_semantic_event(
        &mut self,
        event: &SemanticEventInput,
    ) -> Result<(), StorageError> {
        validate_identifier("semantic.event_id", event.event_id.as_str())?;
        for (field, value) in [
            ("semantic.analyzer_id", event.analyzer_id.as_str()),
            ("semantic.analyzer_version", event.analyzer_version.as_str()),
            ("semantic.namespace", event.namespace.as_str()),
            ("semantic.kind", event.kind.as_str()),
        ] {
            ensure_bounded_text(field, value, MAX_SEMANTIC_TEXT_BYTES, false)?;
        }
        if !event.attributes.is_object() {
            return Err(StorageError::InvalidSemanticAttributes);
        }
        let attributes_json = serde_json::to_string(&event.attributes)
            .map_err(|_| StorageError::InvalidSemanticAttributes)?;
        if attributes_json.len() > MAX_SEMANTIC_ATTRIBUTES_BYTES {
            return Err(StorageError::FieldTooLong {
                field: "semantic.attributes",
                max_bytes: MAX_SEMANTIC_ATTRIBUTES_BYTES,
            });
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (capture_session_id, source_flow_id) = match &event.source {
            SemanticSource::Flow(flow_id) => {
                validate_identifier("semantic.source_flow_id", flow_id.as_str())?;
                let capture_session_id: Option<Option<String>> = transaction
                    .query_row(
                        "SELECT capture_session_id FROM normalized_flows WHERE flow_id = ?1",
                        params![flow_id.as_str()],
                        |row| row.get(0),
                    )
                    .optional()?;
                let Some(capture_session_id) = capture_session_id else {
                    return Err(StorageError::MissingSourceFlow);
                };
                if let Some(session_id) = capture_session_id.as_deref() {
                    validate_identifier("semantic.capture_session_id", session_id).map_err(
                        |_| StorageError::CorruptData {
                            field: "semantic.capture_session_id",
                        },
                    )?;
                }
                (capture_session_id, Some(flow_id.as_str()))
            }
            SemanticSource::CaptureSession(session_id) => {
                validate_identifier("semantic.capture_session_id", session_id.as_str())?;
                ensure_session_exists(&transaction, session_id.as_str())?;
                (Some(session_id.as_str().to_owned()), None)
            }
            SemanticSource::Global => (None, None),
        };
        let existing_source: Option<(Option<String>, Option<String>)> = transaction
            .query_row(
                r#"SELECT capture_session_id, source_flow_id
                   FROM semantic_events WHERE event_id = ?1"#,
                params![event.event_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if existing_source.is_some_and(|(existing_session, existing_flow)| {
            existing_session.as_deref() != capture_session_id.as_deref()
                || existing_flow.as_deref() != source_flow_id
        }) {
            return Err(StorageError::ImmutableSemanticSource);
        }

        transaction.execute(
            r#"INSERT INTO semantic_events(
                   event_id, capture_session_id, source_flow_id, analyzer_id, analyzer_version,
                   namespace, kind, timestamp_ns, attributes_json
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
               ON CONFLICT(event_id) DO UPDATE SET
                   capture_session_id = excluded.capture_session_id,
                   source_flow_id = excluded.source_flow_id,
                   analyzer_id = excluded.analyzer_id,
                   analyzer_version = excluded.analyzer_version,
                   namespace = excluded.namespace,
                   kind = excluded.kind,
                   timestamp_ns = excluded.timestamp_ns,
                   attributes_json = excluded.attributes_json"#,
            params![
                event.event_id.as_str(),
                capture_session_id.as_deref(),
                source_flow_id,
                event.analyzer_id,
                event.analyzer_version,
                event.namespace,
                event.kind,
                timestamp_key(event.timestamp),
                attributes_json,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Queries derived events with a bounded stable keyset cursor.
    pub fn query_semantic_events(
        &self,
        query: &SemanticQuery,
    ) -> Result<SemanticPage, StorageError> {
        validate_time_range(query.time_range)?;
        let namespace =
            validate_optional_query_text("semantic.query.namespace", query.namespace.as_deref())?;
        let kind = validate_optional_query_text("semantic.query.kind", query.kind.as_deref())?;
        let start = query.time_range.start_inclusive.map(timestamp_key);
        let end = query.time_range.end_inclusive.map(timestamp_key);
        let session = query
            .capture_session_id
            .as_ref()
            .map(CaptureSessionId::as_str);
        if let Some(session) = session {
            validate_identifier("semantic.query.capture_session_id", session)?;
        }
        let cursor_time = query
            .after
            .as_ref()
            .map(|cursor| timestamp_key(cursor.timestamp));
        let cursor_id = query.after.as_ref().map(|cursor| cursor.event_id.as_str());
        let limit = i64::from(query.page_size.get()) + 1;

        let mut statement = self.connection.prepare(
            r#"SELECT event_id, capture_session_id, source_flow_id, analyzer_id,
                      analyzer_version, namespace, kind, timestamp_ns, attributes_json
               FROM semantic_events
               WHERE (?1 IS NULL OR timestamp_ns >= ?1)
                 AND (?2 IS NULL OR timestamp_ns <= ?2)
                 AND (?3 IS NULL OR namespace = ?3)
                 AND (?4 IS NULL OR kind = ?4)
                 AND (?5 IS NULL OR capture_session_id = ?5)
                 AND (?6 IS NULL OR timestamp_ns < ?6
                      OR (timestamp_ns = ?6 AND event_id > ?7))
               ORDER BY timestamp_ns DESC, event_id ASC
               LIMIT ?8"#,
        )?;
        let mut rows = statement.query(params![
            start.as_deref(),
            end.as_deref(),
            namespace,
            kind,
            session,
            cursor_time.as_deref(),
            cursor_id,
            limit,
        ])?;
        let mut items = Vec::with_capacity(usize::from(query.page_size.get()) + 1);
        while let Some(row) = rows.next()? {
            items.push(decode_semantic_row(row)?);
        }
        let has_more = items.len() > usize::from(query.page_size.get());
        if has_more {
            items.pop();
        }
        let next_cursor = if has_more {
            let Some(last) = items.last() else {
                return Err(StorageError::CorruptData {
                    field: "semantic pagination",
                });
            };
            Some(SemanticCursor {
                timestamp: last.timestamp,
                event_id: last.event_id.as_str().to_owned(),
            })
        } else {
            None
        };
        Ok(SemanticPage { items, next_cursor })
    }

    /// Removes all rebuildable analyzer output without touching normalized source indexes.
    pub fn clear_semantic_events(&self) -> Result<u64, StorageError> {
        count_from_usize(
            self.connection.execute("DELETE FROM semantic_events", [])?,
            "deleted semantic events",
        )
    }

    /// Removes rebuildable output belonging to one capture boundary.
    pub fn delete_semantic_events_for_capture_session(
        &self,
        session_id: &CaptureSessionId,
    ) -> Result<u64, StorageError> {
        validate_identifier("capture_session_id", session_id.as_str())?;
        count_from_usize(
            self.connection.execute(
                r#"DELETE FROM semantic_events
                   WHERE capture_session_id = ?1
                      OR source_flow_id IN (
                          SELECT flow_id FROM normalized_flows WHERE capture_session_id = ?1
                      )"#,
                params![session_id.as_str()],
            )?,
            "deleted semantic events",
        )
    }

    /// Deletes one capture boundary and all of its SQLite flow/semantic metadata.
    ///
    /// Opaque payload backends have an independent matching session-delete API;
    /// a host coordinator invokes both boundaries when payload retention is enabled.
    pub fn delete_capture_session(
        &mut self,
        session_id: &CaptureSessionId,
    ) -> Result<DeletionSummary, StorageError> {
        validate_identifier("capture_session_id", session_id.as_str())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let summary = delete_capture_session_in(&transaction, session_id.as_str())?;
        transaction.commit()?;
        Ok(summary)
    }

    /// Deletes at most `limit` completed metadata sessions ending by `cutoff`.
    ///
    /// When opaque payload retention is enabled, first use
    /// [`Self::retention_candidates`] and coordinate each candidate with the
    /// payload store rather than calling this metadata-only convenience path.
    pub fn prune_capture_sessions(
        &mut self,
        cutoff: TimestampNs,
        limit: PageSize,
    ) -> Result<DeletionSummary, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session_ids = {
            let mut statement = transaction.prepare(
                r#"SELECT session_id FROM capture_sessions
                   WHERE ended_at_ns IS NOT NULL AND ended_at_ns <= ?1
                   ORDER BY ended_at_ns ASC, session_id ASC
                   LIMIT ?2"#,
            )?;
            let mapped = statement.query_map(
                params![timestamp_key(cutoff), i64::from(limit.get())],
                |row| row.get::<_, String>(0),
            )?;
            let mut values = Vec::new();
            for value in mapped {
                values.push(value?);
            }
            values
        };

        let mut total = DeletionSummary::default();
        for session_id in session_ids {
            let summary = delete_capture_session_in(&transaction, &session_id)?;
            total.sessions =
                checked_add_count(total.sessions, summary.sessions, "deleted sessions")?;
            total.flows = checked_add_count(total.flows, summary.flows, "deleted flows")?;
            total.semantic_events = checked_add_count(
                total.semantic_events,
                summary.semantic_events,
                "deleted semantic events",
            )?;
        }
        transaction.commit()?;
        Ok(total)
    }
}

fn validate_setting_key(key: &str) -> Result<(), StorageError> {
    ensure_bounded_text("setting.key", key, MAX_SETTING_KEY_BYTES, false)
}

#[cfg(unix)]
fn is_flowprobe_or_empty_database(connection: &Connection) -> Result<bool, StorageError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let schema_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if schema_version != 0 {
        return Ok(application_id == APPLICATION_ID);
    }
    if application_id != 0 && application_id != APPLICATION_ID {
        return Ok(false);
    }
    let schema_object_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    Ok(schema_object_count == 0)
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), StorageError> {
    ensure_bounded_text(field, value, MAX_IDENTIFIER_BYTES, false)?;
    if value.trim() != value {
        return Err(StorageError::InvalidField { field });
    }
    Ok(())
}

fn ensure_bounded_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), StorageError> {
    if (!allow_empty && value.is_empty()) || value.chars().any(char::is_control) {
        return Err(StorageError::InvalidField { field });
    }
    if value.len() > max_bytes {
        return Err(StorageError::FieldTooLong { field, max_bytes });
    }
    Ok(())
}

fn validate_optional_query_text<'a>(
    field: &'static str,
    value: Option<&'a str>,
) -> Result<Option<&'a str>, StorageError> {
    if let Some(value) = value {
        ensure_bounded_text(field, value, MAX_SEMANTIC_TEXT_BYTES, false)?;
    }
    Ok(value)
}

fn validate_time_range(range: TimeRange) -> Result<(), StorageError> {
    TimeRange::new(range.start_inclusive, range.end_inclusive).map(|_| ())
}

fn timestamp_key(timestamp: TimestampNs) -> String {
    format!("{:020}", timestamp.0)
}

fn parse_timestamp(value: &str, field: &'static str) -> Result<TimestampNs, StorageError> {
    if value.len() != 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(StorageError::CorruptData { field });
    }
    value
        .parse::<u64>()
        .map(TimestampNs)
        .map_err(|_| StorageError::CorruptData { field })
}

fn parse_optional_timestamp(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<TimestampNs>, StorageError> {
    value.map(|value| parse_timestamp(value, field)).transpose()
}

fn normalize_host(host: &str) -> String {
    host.to_ascii_lowercase()
}

fn protocol_kinds(flow: &NormalizedFlowV0) -> Result<Vec<String>, StorageError> {
    let mut protocols = BTreeSet::new();
    for event in &flow.protocols {
        let kind = event.metadata.to_string();
        ensure_bounded_text("protocol.kind", &kind, MAX_PROTOCOL_BYTES, false)?;
        protocols.insert(kind);
    }
    Ok(protocols.into_iter().collect())
}

fn http_summary(flow: &NormalizedFlowV0) -> (Option<String>, Option<u16>) {
    flow.protocols
        .iter()
        .find_map(|event| match &event.metadata {
            ProtocolMetadata::Http(metadata) => Some((
                Some(metadata.request.method.clone()),
                metadata
                    .response
                    .as_ref()
                    .map(|response| response.status.get()),
            )),
            _ => None,
        })
        .unwrap_or((None, None))
}

fn ensure_session_exists(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> Result<(), StorageError> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM capture_sessions WHERE session_id = ?1)",
        params![session_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(StorageError::MissingCaptureSession)
    }
}

fn decode_flow_row(row: &Row<'_>) -> Result<FlowIndexRecord, StorageError> {
    let flow_id = decode_flow_id(row.get(0)?, "flow.flow_id")?;
    let connection_id = decode_connection_id(row.get(1)?, "flow.connection_id")?;
    let capture_session_id = row
        .get::<_, Option<String>>(2)?
        .map(|value| decode_capture_session_id(value, "flow.capture_session_id"))
        .transpose()?;
    let started_at = parse_timestamp(&row.get::<_, String>(3)?, "flow.started_at")?;
    let first_byte_at = parse_optional_timestamp(
        row.get::<_, Option<String>>(4)?.as_deref(),
        "flow.first_byte_at",
    )?;
    let ended_at =
        parse_optional_timestamp(row.get::<_, Option<String>>(5)?.as_deref(), "flow.ended_at")?;
    let transport_protocol: String = row.get(6)?;
    validate_stored_text(
        "flow.transport_protocol",
        &transport_protocol,
        MAX_PROTOCOL_BYTES,
    )?;
    let destination_host: Option<String> = row.get(7)?;
    if let Some(host) = destination_host.as_deref() {
        validate_stored_text("flow.destination_host", host, MAX_HOST_BYTES)?;
    }
    let destination_ip = row
        .get::<_, Option<String>>(8)?
        .map(|value| {
            IpAddr::from_str(&value).map_err(|_| StorageError::CorruptData {
                field: "flow.destination_ip",
            })
        })
        .transpose()?;
    let destination_port = decode_u16(row.get(9)?, "flow.destination_port")?;
    if destination_port == 0 {
        return Err(StorageError::CorruptData {
            field: "flow.destination_port",
        });
    }
    let protocols_json: String = row.get(10)?;
    if protocols_json.len() > MAX_PROTOCOLS_JSON_BYTES {
        return Err(StorageError::CorruptData {
            field: "flow.protocols",
        });
    }
    let protocols: Vec<String> =
        serde_json::from_str(&protocols_json).map_err(|_| StorageError::CorruptData {
            field: "flow.protocols",
        })?;
    validate_stored_protocols(&protocols)?;
    let http_method: Option<String> = row.get(11)?;
    if let Some(method) = http_method.as_deref() {
        validate_stored_text("flow.http_method", method, MAX_PROTOCOL_BYTES)?;
    }
    let http_status = row
        .get::<_, Option<i64>>(12)?
        .map(|value| {
            let value = decode_u16(value, "flow.http_status")?;
            if (100..=599).contains(&value) {
                Ok(value)
            } else {
                Err(StorageError::CorruptData {
                    field: "flow.http_status",
                })
            }
        })
        .transpose()?;
    let normalized_source_ref = row
        .get::<_, Option<String>>(13)?
        .map(|value| {
            BlobRef::new(value).map_err(|_| StorageError::CorruptData {
                field: "flow.normalized_source_ref",
            })
        })
        .transpose()?;

    Ok(FlowIndexRecord {
        flow_id,
        connection_id,
        capture_session_id,
        started_at,
        first_byte_at,
        ended_at,
        transport_protocol,
        destination_host,
        destination_ip,
        destination_port,
        protocols,
        http_method,
        http_status,
        normalized_source_ref,
    })
}

fn decode_semantic_row(row: &Row<'_>) -> Result<SemanticEventRecord, StorageError> {
    let event_id =
        SemanticEventId::new(row.get::<_, String>(0)?).map_err(|_| StorageError::CorruptData {
            field: "semantic.event_id",
        })?;
    let capture_session_id = row
        .get::<_, Option<String>>(1)?
        .map(|value| decode_capture_session_id(value, "semantic.capture_session_id"))
        .transpose()?;
    let source_flow_id = row
        .get::<_, Option<String>>(2)?
        .map(|value| decode_flow_id(value, "semantic.source_flow_id"))
        .transpose()?;
    let analyzer_id: String = row.get(3)?;
    let analyzer_version: String = row.get(4)?;
    let namespace: String = row.get(5)?;
    let kind: String = row.get(6)?;
    for (field, value) in [
        ("semantic.analyzer_id", analyzer_id.as_str()),
        ("semantic.analyzer_version", analyzer_version.as_str()),
        ("semantic.namespace", namespace.as_str()),
        ("semantic.kind", kind.as_str()),
    ] {
        validate_stored_text(field, value, MAX_SEMANTIC_TEXT_BYTES)?;
    }
    let timestamp = parse_timestamp(&row.get::<_, String>(7)?, "semantic.timestamp")?;
    let attributes_json: String = row.get(8)?;
    if attributes_json.len() > MAX_SEMANTIC_ATTRIBUTES_BYTES {
        return Err(StorageError::CorruptData {
            field: "semantic.attributes",
        });
    }
    let attributes: Value =
        serde_json::from_str(&attributes_json).map_err(|_| StorageError::CorruptData {
            field: "semantic.attributes",
        })?;
    if !attributes.is_object() {
        return Err(StorageError::CorruptData {
            field: "semantic.attributes",
        });
    }

    Ok(SemanticEventRecord {
        event_id,
        capture_session_id,
        source_flow_id,
        analyzer_id,
        analyzer_version,
        namespace,
        kind,
        timestamp,
        attributes,
    })
}

fn decode_flow_id(value: String, field: &'static str) -> Result<FlowId, StorageError> {
    validate_identifier(field, &value).map_err(|_| StorageError::CorruptData { field })?;
    FlowId::new(value).map_err(|_| StorageError::CorruptData { field })
}

fn decode_connection_id(value: String, field: &'static str) -> Result<ConnectionId, StorageError> {
    validate_identifier(field, &value).map_err(|_| StorageError::CorruptData { field })?;
    ConnectionId::new(value).map_err(|_| StorageError::CorruptData { field })
}

fn decode_capture_session_id(
    value: String,
    field: &'static str,
) -> Result<CaptureSessionId, StorageError> {
    validate_identifier(field, &value).map_err(|_| StorageError::CorruptData { field })?;
    CaptureSessionId::new(value).map_err(|_| StorageError::CorruptData { field })
}

fn decode_u16(value: i64, field: &'static str) -> Result<u16, StorageError> {
    u16::try_from(value).map_err(|_| StorageError::IntegerOutOfRange { field })
}

fn validate_stored_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), StorageError> {
    ensure_bounded_text(field, value, max_bytes, false)
        .map_err(|_| StorageError::CorruptData { field })
}

fn validate_stored_protocols(protocols: &[String]) -> Result<(), StorageError> {
    if protocols.is_empty() || protocols.len() > MAX_PROTOCOL_EVENTS {
        return Err(StorageError::CorruptData {
            field: "flow.protocols",
        });
    }
    let mut unique = BTreeSet::new();
    for protocol in protocols {
        validate_stored_text("flow.protocols", protocol, MAX_PROTOCOL_BYTES)?;
        if !unique.insert(protocol) {
            return Err(StorageError::CorruptData {
                field: "flow.protocols",
            });
        }
    }
    Ok(())
}

fn delete_capture_session_in(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> Result<DeletionSummary, StorageError> {
    let sessions = query_count(
        transaction,
        "SELECT COUNT(*) FROM capture_sessions WHERE session_id = ?1",
        session_id,
        "deleted sessions",
    )?;
    if sessions == 0 {
        return Ok(DeletionSummary::default());
    }
    let flows = query_count(
        transaction,
        "SELECT COUNT(*) FROM normalized_flows WHERE capture_session_id = ?1",
        session_id,
        "deleted flows",
    )?;
    let semantic_events = query_count(
        transaction,
        r#"SELECT COUNT(*) FROM semantic_events
           WHERE capture_session_id = ?1
              OR source_flow_id IN (
                  SELECT flow_id FROM normalized_flows WHERE capture_session_id = ?1
              )"#,
        session_id,
        "deleted semantic events",
    )?;
    transaction.execute(
        "DELETE FROM capture_sessions WHERE session_id = ?1",
        params![session_id],
    )?;
    Ok(DeletionSummary {
        sessions,
        flows,
        semantic_events,
    })
}

fn query_count(
    transaction: &Transaction<'_>,
    sql: &str,
    parameter: &str,
    field: &'static str,
) -> Result<u64, StorageError> {
    let value: i64 = transaction.query_row(sql, params![parameter], |row| row.get(0))?;
    u64::try_from(value).map_err(|_| StorageError::IntegerOutOfRange { field })
}

fn count_from_usize(value: usize, field: &'static str) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::IntegerOutOfRange { field })
}

fn checked_add_count(left: u64, right: u64, field: &'static str) -> Result<u64, StorageError> {
    left.checked_add(right)
        .ok_or(StorageError::IntegerOutOfRange { field })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    const LEGACY_SCHEMA_V1: &str = include_str!("../tests/fixtures/schema-v1.sql");

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    fn migration_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "flowprobe-storage-migration-{}-{}.sqlite3",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn first_persisted_schema_matches_the_frozen_migration_fixture() {
        assert_eq!(SCHEMA_V1.trim(), LEGACY_SCHEMA_V1.trim());
    }

    #[test]
    fn first_persisted_schema_migrates_to_latest_and_backfills_host_index() {
        let path = migration_path();
        let _stale_cleanup = fs::remove_file(&path);
        {
            let connection = Connection::open(&path).expect("migration fixture database opens");
            connection
                .execute_batch(LEGACY_SCHEMA_V1)
                .expect("v1 schema creates");
            connection
                .execute_batch("PRAGMA application_id = 1179669297; PRAGMA user_version = 1;")
                .expect("v1 schema markers persist");
            connection
                .execute(
                    "INSERT INTO capture_sessions(session_id, started_at_ns) VALUES (?1, ?2)",
                    params!["session_migration", timestamp_key(TimestampNs(1))],
                )
                .expect("v1 session inserts");
            connection
                .execute(
                    r#"INSERT INTO normalized_flows(
                           flow_id, connection_id, capture_session_id, started_at_ns,
                           transport_protocol, destination_host, destination_ip, destination_port,
                           protocols_json
                       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
                    params![
                        "flow_migration",
                        "connection_migration",
                        "session_migration",
                        timestamp_key(TimestampNs(2)),
                        "tcp",
                        "MiXeD.Example",
                        "192.0.2.1",
                        443_i64,
                        "[\"http\"]",
                    ],
                )
                .expect("v1 flow inserts");
        }

        let store = SqliteMetadataStore::open(&path).expect("v1 database migrates");
        assert_eq!(
            store.schema_version().expect("migrated schema version"),
            LATEST_SCHEMA_VERSION
        );
        let page = match store.query_flows(
            &FlowQuery::new(PageSize::new(10).expect("page size")).with_host("mixed.example"),
        ) {
            Ok(page) => page,
            Err(error) => panic!("backfilled host query failure: {error:?}"),
        };
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].flow_id.as_str(), "flow_migration");
        drop(store);
        fs::remove_file(path).expect("migration test database removes");
    }

    #[test]
    fn failed_first_migration_is_atomic_and_can_be_retried() {
        let path = migration_path();
        let _stale_cleanup = fs::remove_file(&path);
        {
            let connection = Connection::open(&path).expect("migration fixture database opens");
            connection
                .execute_batch(LEGACY_SCHEMA_V1)
                .expect("v1 schema creates");
            connection
                .execute_batch(
                    r#"PRAGMA application_id = 1179669297;
                       PRAGMA user_version = 1;
                       CREATE INDEX normalized_flows_time_idx
                       ON normalized_flows(flow_id);"#,
                )
                .expect("conflicting v1 index creates");
        }

        assert!(matches!(
            SqliteMetadataStore::open(&path),
            Err(StorageError::Database)
        ));
        {
            let connection = Connection::open(&path).expect("failed migration database reopens");
            let version: i64 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .expect("schema version reads");
            assert_eq!(version, 1);
            let host_column_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('normalized_flows') WHERE name = 'host_normalized'",
                    [],
                    |row| row.get(0),
                )
                .expect("rolled-back schema reads");
            assert_eq!(host_column_count, 0);
            connection
                .execute("DROP INDEX normalized_flows_time_idx", [])
                .expect("migration conflict removes");
        }

        let store = SqliteMetadataStore::open(&path).expect("clean retry migrates");
        assert_eq!(
            store.schema_version().expect("migrated schema version"),
            LATEST_SCHEMA_VERSION
        );
        drop(store);
        fs::remove_file(path).expect("migration test database removes");
    }
}
