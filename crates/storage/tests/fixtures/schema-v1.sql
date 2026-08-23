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
