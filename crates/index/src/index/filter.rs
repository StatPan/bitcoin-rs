//! Versioned immutable compact-filter records in the index metadata family.

use super::{capability::IndexWatermark, error::IndexError};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvSnapshot};

/// Both immutable components share the reserved filter reset namespace.
pub(super) const FILTER_PREFIX: &[u8] = b"F";
// Version 1 was the experimental combined metadata/blob value and is refused.
const FILTER_RECORD_VERSION: u8 = 2;
const FILTER_KEY_LEN: usize = 2 + 4 + 32;
const FILTER_METADATA_LEN: usize = 1 + 3 * 32;
pub(super) const FILTER_RECORD_OVERHEAD: usize = 2 * FILTER_KEY_LEN + FILTER_METADATA_LEN;

/// Fixed-size filter facts for one exact block, without loading the filter blob.
///
/// Metadata is `F\0 || height (BE) || block_hash`; its value is one version
/// byte followed by the parent block hash, filter hash and filter header.
/// The paired `F\1` key holds only the serialized BIP158 bytes. Both components
/// are immutable and published with their watermark in the same atomic batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactFilterMetadata {
    /// Exact height and block hash carried by the record key.
    pub block: IndexWatermark,
    /// Parent block identity, retained for body-free rollback.
    pub parent_hash: [u8; 32],
    /// Double-SHA256 of the serialized filter.
    pub filter_hash: [u8; 32],
    /// Double-SHA256 of `filter_hash || previous_filter_header`.
    pub filter_header: [u8; 32],
}

/// An immutable basic filter for one exact block identity.
///
/// Stored hashes use the same little-endian byte representation as block hashes.
/// A record remains available by identity after its branch is disconnected;
/// only the separate capability watermark describes active-chain coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactFilterRecord {
    /// Exact height and block hash carried by the record key.
    pub block: IndexWatermark,
    /// Parent block identity, retained for body-free rollback.
    pub parent_hash: [u8; 32],
    /// Serialized BIP158 basic filter, checked against its metadata hash on read.
    pub filter: Vec<u8>,
    /// Double-SHA256 of the serialized filter.
    pub filter_hash: [u8; 32],
    /// Double-SHA256 of `filter_hash || previous_filter_header`.
    pub filter_header: [u8; 32],
}

fn record_key(block: IndexWatermark, component: u8) -> [u8; FILTER_KEY_LEN] {
    let mut key = [0; FILTER_KEY_LEN];
    key[0] = FILTER_PREFIX[0];
    key[1] = component;
    key[2..6].copy_from_slice(&block.height.to_be_bytes());
    key[6..].copy_from_slice(&block.hash);
    key
}

fn filter_header(hash: [u8; 32], previous: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&hash);
    bytes[32..].copy_from_slice(&previous);
    double_sha256(&bytes).to_le_bytes()
}

impl CompactFilterMetadata {
    fn encode(self) -> [u8; FILTER_METADATA_LEN] {
        let mut value = [0; FILTER_METADATA_LEN];
        value[0] = FILTER_RECORD_VERSION;
        value[1..33].copy_from_slice(&self.parent_hash);
        value[33..65].copy_from_slice(&self.filter_hash);
        value[65..].copy_from_slice(&self.filter_header);
        value
    }

    fn decode(block: IndexWatermark, value: &[u8]) -> Result<Self, IndexError> {
        let version = *value
            .first()
            .ok_or(IndexError::InvalidCompactFilterRecord)?;
        if version != FILTER_RECORD_VERSION {
            return Err(IndexError::UnsupportedCompactFilterVersion { version });
        }
        if value.len() != FILTER_METADATA_LEN {
            return Err(IndexError::InvalidCompactFilterRecord);
        }
        let mut parent_hash = [0; 32];
        parent_hash.copy_from_slice(&value[1..33]);
        let mut filter_hash = [0; 32];
        filter_hash.copy_from_slice(&value[33..65]);
        let mut filter_header = [0; 32];
        filter_header.copy_from_slice(&value[65..]);
        Ok(Self {
            block,
            parent_hash,
            filter_hash,
            filter_header,
        })
    }

    pub(super) fn read(
        snapshot: &dyn KvSnapshot,
        block: IndexWatermark,
    ) -> Result<Option<Self>, IndexError> {
        snapshot
            .get(ColumnFamily::UtxoMeta, &record_key(block, 0))?
            .as_deref()
            .map(|value| Self::decode(block, value))
            .transpose()
    }

    fn require(snapshot: &dyn KvSnapshot, block: IndexWatermark) -> Result<Self, IndexError> {
        Self::read(snapshot, block)?.ok_or(IndexError::MissingCompactFilter {
            height: block.height,
            hash: block.hash,
        })
    }

    /// Checks local header recurrence without recursively scanning older records.
    fn validate_header(self, snapshot: &dyn KvSnapshot) -> Result<(), IndexError> {
        let previous_header = if let Some(height) = self.block.height.checked_sub(1) {
            Self::require(
                snapshot,
                IndexWatermark {
                    height,
                    hash: self.parent_hash,
                },
            )?
            .filter_header
        } else {
            if self.parent_hash != [0; 32] {
                return Err(IndexError::InvalidCompactFilterRecord);
            }
            [0; 32]
        };
        if self.filter_header != filter_header(self.filter_hash, previous_header) {
            return Err(IndexError::InvalidCompactFilterRecord);
        }
        Ok(())
    }
}

impl CompactFilterRecord {
    pub(super) fn new(
        block: IndexWatermark,
        parent_hash: [u8; 32],
        filter: Vec<u8>,
        previous_header: [u8; 32],
    ) -> Self {
        let filter_hash = double_sha256(&filter).to_le_bytes();
        Self {
            block,
            parent_hash,
            filter,
            filter_hash,
            filter_header: filter_header(filter_hash, previous_header),
        }
    }

    fn metadata(&self) -> CompactFilterMetadata {
        CompactFilterMetadata {
            block: self.block,
            parent_hash: self.parent_hash,
            filter_hash: self.filter_hash,
            filter_header: self.filter_header,
        }
    }

    /// Adds only absent pairs; reconnection must reproduce both immutable components.
    pub(super) fn put_immutable(
        &self,
        snapshot: &dyn KvSnapshot,
        batch: &mut BufferedWriteBatch,
    ) -> Result<(), IndexError> {
        if self.block.height == 0 && self.parent_hash != [0; 32] {
            return Err(IndexError::InvalidCompactFilterRecord);
        }
        match Self::read(snapshot, self.block)? {
            Some(existing) if existing != *self => Err(IndexError::ConflictingCompactFilter {
                height: self.block.height,
                hash: self.block.hash,
            }),
            Some(_) => Ok(()),
            None => {
                batch.put(
                    ColumnFamily::UtxoMeta,
                    &record_key(self.block, 0),
                    &self.metadata().encode(),
                );
                batch.put(
                    ColumnFamily::UtxoMeta,
                    &record_key(self.block, 1),
                    &self.filter,
                );
                Ok(())
            }
        }
    }

    /// Validates the complete current record and its local header recurrence.
    /// Advancing a watermark may not hide a known missing or corrupt anchor blob.
    pub(super) fn require_validated(
        snapshot: &dyn KvSnapshot,
        block: IndexWatermark,
    ) -> Result<Self, IndexError> {
        let record = Self::read(snapshot, block)?.ok_or(IndexError::MissingCompactFilter {
            height: block.height,
            hash: block.hash,
        })?;
        record.metadata().validate_header(snapshot)?;
        Ok(record)
    }

    pub(super) fn read(
        snapshot: &dyn KvSnapshot,
        block: IndexWatermark,
    ) -> Result<Option<Self>, IndexError> {
        let metadata = CompactFilterMetadata::read(snapshot, block)?;
        let blob = snapshot.get(ColumnFamily::UtxoMeta, &record_key(block, 1))?;
        match (metadata, blob) {
            (None, None) => Ok(None),
            (Some(metadata), Some(filter)) => {
                // The empty filter still has a one-byte element count.
                if filter.is_empty() || double_sha256(&filter).to_le_bytes() != metadata.filter_hash
                {
                    return Err(IndexError::InvalidCompactFilterRecord);
                }
                Ok(Some(Self {
                    block,
                    filter,
                    parent_hash: metadata.parent_hash,
                    filter_hash: metadata.filter_hash,
                    filter_header: metadata.filter_header,
                }))
            }
            _ => Err(IndexError::InvalidCompactFilterRecord),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_storage::{KvIter, StorageError};
    use std::sync::Mutex;

    struct MetadataOnlySnapshot {
        metadata: CompactFilterMetadata,
        reads: Mutex<Vec<Vec<u8>>>,
    }

    impl KvSnapshot for MetadataOnlySnapshot {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            assert_eq!(cf, ColumnFamily::UtxoMeta);
            assert_eq!(
                key,
                record_key(self.metadata.block, 0),
                "metadata query must not load blob"
            );
            self.reads
                .lock()
                .map_err(|_| StorageError::Backend("poisoned read log".into()))?
                .push(key.to_vec());
            Ok(Some(self.metadata.encode().to_vec()))
        }

        fn iter_prefix<'a>(
            &'a self,
            _: ColumnFamily,
            _: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            Err(StorageError::Backend("metadata query must not scan".into()))
        }
    }

    #[test]
    fn metadata_read_loads_one_fixed_size_row_and_never_the_blob() -> Result<(), IndexError> {
        let metadata = CompactFilterRecord::new(
            IndexWatermark {
                height: 0,
                hash: [7; 32],
            },
            [0; 32],
            vec![0],
            [0; 32],
        )
        .metadata();
        let snapshot = MetadataOnlySnapshot {
            metadata,
            reads: Mutex::new(Vec::new()),
        };
        assert_eq!(
            CompactFilterMetadata::read(&snapshot, metadata.block)?,
            Some(metadata)
        );
        assert_eq!(metadata.encode().len(), 97);
        assert_eq!(
            snapshot
                .reads
                .lock()
                .map_err(|_| IndexError::InvalidCompactFilterRecord)?
                .len(),
            1
        );
        Ok(())
    }
}
