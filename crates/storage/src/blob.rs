use std::{collections::BTreeMap, error::Error, fmt};

use flowprobe_model::{BlobRef, BodyRef, CaptureSessionId};

const MAX_OWNER_BYTES: usize = 1024;

/// Hard bounds for one deterministic payload backend instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobLimits {
    max_item_bytes: u64,
    max_total_bytes: u64,
    max_entries: u32,
}

impl BlobLimits {
    /// Creates internally consistent non-zero limits.
    pub fn new(
        max_item_bytes: u64,
        max_total_bytes: u64,
        max_entries: u32,
    ) -> Result<Self, BlobStoreError> {
        if max_item_bytes == 0
            || max_total_bytes == 0
            || max_entries == 0
            || max_item_bytes > max_total_bytes
        {
            return Err(BlobStoreError::InvalidLimits);
        }
        Ok(Self {
            max_item_bytes,
            max_total_bytes,
            max_entries,
        })
    }

    #[must_use]
    pub const fn max_item_bytes(self) -> u64 {
        self.max_item_bytes
    }

    #[must_use]
    pub const fn max_total_bytes(self) -> u64 {
        self.max_total_bytes
    }

    #[must_use]
    pub const fn max_entries(self) -> u32 {
        self.max_entries
    }
}

impl Default for BlobLimits {
    fn default() -> Self {
        Self {
            max_item_bytes: 16 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_entries: 4096,
        }
    }
}

/// Counts returned when an explicit session payload retention boundary is removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PayloadDeletionSummary {
    pub bodies: u64,
    pub blobs: u64,
    pub bytes: u64,
}

/// Safe failure from an opaque payload backend.
pub enum BlobStoreError {
    InvalidLimits,
    OwnerTooLong { max_bytes: usize },
    ItemTooLarge { max_bytes: u64 },
    CapacityExceeded,
    EntryLimitExceeded { max_entries: u32 },
    IntegerOverflow,
    ReferenceSpaceExhausted,
    GeneratedReferenceInvalid,
}

impl fmt::Debug for BlobStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for BlobStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid opaque payload limits"),
            Self::OwnerTooLong { max_bytes } => {
                write!(
                    formatter,
                    "opaque payload owner exceeds the {max_bytes}-byte limit"
                )
            }
            Self::ItemTooLarge { max_bytes } => {
                write!(
                    formatter,
                    "opaque payload exceeds the {max_bytes}-byte item limit"
                )
            }
            Self::CapacityExceeded => {
                formatter.write_str("opaque payload store byte capacity exceeded")
            }
            Self::EntryLimitExceeded { max_entries } => write!(
                formatter,
                "opaque payload store exceeds the {max_entries}-entry limit"
            ),
            Self::IntegerOverflow => formatter.write_str("opaque payload size overflow"),
            Self::ReferenceSpaceExhausted => {
                formatter.write_str("opaque payload reference space exhausted")
            }
            Self::GeneratedReferenceInvalid => {
                formatter.write_str("generated opaque payload reference was invalid")
            }
        }
    }
}

impl Error for BlobStoreError {}

/// Host capability for optional payload material.
///
/// Implementations must not expose filesystem paths. Calling `put_*` is an
/// explicit payload-retention action; SQLite metadata writes never call it.
pub trait OpaquePayloadStore {
    fn put_body(
        &mut self,
        owner: Option<&CaptureSessionId>,
        bytes: &[u8],
    ) -> Result<BodyRef, BlobStoreError>;

    fn put_blob(
        &mut self,
        owner: Option<&CaptureSessionId>,
        bytes: &[u8],
    ) -> Result<BlobRef, BlobStoreError>;

    fn read_body(&self, reference: &BodyRef) -> Result<Option<Vec<u8>>, BlobStoreError>;

    fn read_blob(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, BlobStoreError>;

    fn delete_body(&mut self, reference: &BodyRef) -> Result<bool, BlobStoreError>;

    fn delete_blob(&mut self, reference: &BlobRef) -> Result<bool, BlobStoreError>;

    fn delete_capture_session(
        &mut self,
        session_id: &CaptureSessionId,
    ) -> Result<PayloadDeletionSummary, BlobStoreError>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PayloadKind {
    Body,
    Blob,
}

struct MemoryEntry {
    owner: Option<String>,
    kind: PayloadKind,
    bytes: Vec<u8>,
}

/// Bounded, deterministic backend used by contract tests and architecture proofs.
pub struct DeterministicMemoryBlobStore {
    limits: BlobLimits,
    next_reference: u64,
    total_bytes: u64,
    entries: BTreeMap<String, MemoryEntry>,
}

impl DeterministicMemoryBlobStore {
    #[must_use]
    pub fn new(limits: BlobLimits) -> Self {
        Self {
            limits,
            next_reference: 0,
            total_bytes: 0,
            entries: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    fn put(
        &mut self,
        owner: Option<&CaptureSessionId>,
        bytes: &[u8],
        kind: PayloadKind,
    ) -> Result<String, BlobStoreError> {
        validate_owner(owner)?;
        let byte_count = u64::try_from(bytes.len()).map_err(|_| BlobStoreError::IntegerOverflow)?;
        if byte_count > self.limits.max_item_bytes {
            return Err(BlobStoreError::ItemTooLarge {
                max_bytes: self.limits.max_item_bytes,
            });
        }
        let entry_count =
            u64::try_from(self.entries.len()).map_err(|_| BlobStoreError::IntegerOverflow)?;
        if entry_count >= u64::from(self.limits.max_entries) {
            return Err(BlobStoreError::EntryLimitExceeded {
                max_entries: self.limits.max_entries,
            });
        }
        let next_total = self
            .total_bytes
            .checked_add(byte_count)
            .ok_or(BlobStoreError::IntegerOverflow)?;
        if next_total > self.limits.max_total_bytes {
            return Err(BlobStoreError::CapacityExceeded);
        }

        let current = self.next_reference;
        self.next_reference = self
            .next_reference
            .checked_add(1)
            .ok_or(BlobStoreError::ReferenceSpaceExhausted)?;
        let prefix = match kind {
            PayloadKind::Body => "body_",
            PayloadKind::Blob => "blob_",
        };
        let reference = format!("{prefix}{current:016x}");
        if self.entries.contains_key(&reference) {
            return Err(BlobStoreError::ReferenceSpaceExhausted);
        }
        self.entries.insert(
            reference.clone(),
            MemoryEntry {
                owner: owner.map(|value| value.as_str().to_owned()),
                kind,
                bytes: bytes.to_vec(),
            },
        );
        self.total_bytes = next_total;
        Ok(reference)
    }

    fn read(&self, reference: &str, kind: PayloadKind) -> Option<Vec<u8>> {
        self.entries
            .get(reference)
            .filter(|entry| entry.kind == kind)
            .map(|entry| entry.bytes.clone())
    }

    fn delete(&mut self, reference: &str, kind: PayloadKind) -> Result<bool, BlobStoreError> {
        if self
            .entries
            .get(reference)
            .is_some_and(|entry| entry.kind != kind)
        {
            return Ok(false);
        }
        let Some(entry) = self.entries.remove(reference) else {
            return Ok(false);
        };
        let byte_count =
            u64::try_from(entry.bytes.len()).map_err(|_| BlobStoreError::IntegerOverflow)?;
        self.total_bytes = self
            .total_bytes
            .checked_sub(byte_count)
            .ok_or(BlobStoreError::IntegerOverflow)?;
        Ok(true)
    }
}

impl Default for DeterministicMemoryBlobStore {
    fn default() -> Self {
        Self::new(BlobLimits::default())
    }
}

impl fmt::Debug for DeterministicMemoryBlobStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicMemoryBlobStore")
            .field("limits", &self.limits)
            .field("entry_count", &self.entries.len())
            .field("total_bytes", &self.total_bytes)
            .finish_non_exhaustive()
    }
}

impl OpaquePayloadStore for DeterministicMemoryBlobStore {
    fn put_body(
        &mut self,
        owner: Option<&CaptureSessionId>,
        bytes: &[u8],
    ) -> Result<BodyRef, BlobStoreError> {
        BodyRef::new(self.put(owner, bytes, PayloadKind::Body)?)
            .map_err(|_| BlobStoreError::GeneratedReferenceInvalid)
    }

    fn put_blob(
        &mut self,
        owner: Option<&CaptureSessionId>,
        bytes: &[u8],
    ) -> Result<BlobRef, BlobStoreError> {
        BlobRef::new(self.put(owner, bytes, PayloadKind::Blob)?)
            .map_err(|_| BlobStoreError::GeneratedReferenceInvalid)
    }

    fn read_body(&self, reference: &BodyRef) -> Result<Option<Vec<u8>>, BlobStoreError> {
        Ok(self.read(reference.as_str(), PayloadKind::Body))
    }

    fn read_blob(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, BlobStoreError> {
        Ok(self.read(reference.as_str(), PayloadKind::Blob))
    }

    fn delete_body(&mut self, reference: &BodyRef) -> Result<bool, BlobStoreError> {
        self.delete(reference.as_str(), PayloadKind::Body)
    }

    fn delete_blob(&mut self, reference: &BlobRef) -> Result<bool, BlobStoreError> {
        self.delete(reference.as_str(), PayloadKind::Blob)
    }

    fn delete_capture_session(
        &mut self,
        session_id: &CaptureSessionId,
    ) -> Result<PayloadDeletionSummary, BlobStoreError> {
        validate_owner(Some(session_id))?;
        let owned: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.owner.as_deref() == Some(session_id.as_str()))
            .map(|(reference, entry)| (reference.clone(), entry.kind))
            .collect();
        let mut summary = PayloadDeletionSummary::default();
        for (reference, kind) in owned {
            let entry = self
                .entries
                .remove(&reference)
                .ok_or(BlobStoreError::IntegerOverflow)?;
            let byte_count =
                u64::try_from(entry.bytes.len()).map_err(|_| BlobStoreError::IntegerOverflow)?;
            summary.bytes = summary
                .bytes
                .checked_add(byte_count)
                .ok_or(BlobStoreError::IntegerOverflow)?;
            match kind {
                PayloadKind::Body => {
                    summary.bodies = summary
                        .bodies
                        .checked_add(1)
                        .ok_or(BlobStoreError::IntegerOverflow)?;
                }
                PayloadKind::Blob => {
                    summary.blobs = summary
                        .blobs
                        .checked_add(1)
                        .ok_or(BlobStoreError::IntegerOverflow)?;
                }
            }
        }
        self.total_bytes = self
            .total_bytes
            .checked_sub(summary.bytes)
            .ok_or(BlobStoreError::IntegerOverflow)?;
        Ok(summary)
    }
}

fn validate_owner(owner: Option<&CaptureSessionId>) -> Result<(), BlobStoreError> {
    if owner.is_some_and(|value| value.as_str().len() > MAX_OWNER_BYTES) {
        Err(BlobStoreError::OwnerTooLong {
            max_bytes: MAX_OWNER_BYTES,
        })
    } else {
        Ok(())
    }
}
