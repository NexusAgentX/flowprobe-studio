//! Host-owned Local Storage v0.
//!
//! SQLite remains private to this crate. Public APIs expose bounded metadata
//! queries and opaque payload references rather than connections, SQL, or file
//! layouts. Metadata-only flow writes never accept payload bytes.

mod blob;
mod sqlite;

pub use blob::{
    BlobLimits, BlobStoreError, DeterministicMemoryBlobStore, OpaquePayloadStore,
    PayloadDeletionSummary,
};
pub use sqlite::{
    CaptureSessionRecord, DeletionSummary, FlowCursor, FlowIndexRecord, FlowPage, FlowQuery,
    LATEST_SCHEMA_VERSION, MAX_PAGE_SIZE, PageSize, RetentionCandidates, SemanticCursor,
    SemanticEventId, SemanticEventInput, SemanticEventRecord, SemanticPage, SemanticQuery,
    SemanticSource, SettingValue, SqliteMetadataStore, StorageError, TimeRange,
};
