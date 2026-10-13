//! Storage and fence invariants for the optional immutable basic-filter index.
#[path = "support/common.rs"]
mod common;

use std::sync::{Arc, atomic::Ordering};

use bitcoin::bip158::{BlockFilter, FilterHeader};
use bitcoin::hashes::Hash as _;
use bitcoin_rs_index::{
    ConsumerCursorUpdate, IndexCapabilities, IndexCapability, IndexError, IndexReader,
    IndexWatermark, IndexWriter, PreparedBatch, PreparedBatchLimits, PreparedBlock,
    SpentCoinScripts, compact_filter::CompactFilterError,
};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Network, OutPoint, Tx, TxIn, Txid, consensus_bytes,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore};
use common::MemoryStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const FILTER_WATERMARK: &[u8] = &[0, b'F'];

struct NoScripts;
impl SpentCoinScripts for NoScripts {
    fn script_bytes(&self, _: &[u8; 32], _: u32) -> Option<&[u8]> {
        None
    }
}

struct UnexpectedScripts;
impl SpentCoinScripts for UnexpectedScripts {
    fn script_bytes(&self, _: &[u8; 32], _: u32) -> Option<&[u8]> {
        panic!("disabled filters must not request undo scripts")
    }
}

fn block(parent: [u8; 32], nonce: u32) -> Block {
    let mut block = Network::Regtest.genesis_block();
    block.header.prev_blockhash = BlockHash(Hash256::from_le_bytes(&parent));
    block.header.nonce = nonce;
    block
}

fn point(height: u32, block: &Block) -> IndexWatermark {
    IndexWatermark {
        height,
        hash: *block.block_hash().as_bytes(),
    }
}

fn key(point: IndexWatermark) -> Vec<u8> {
    let mut key = b"F\0".to_vec();
    key.extend_from_slice(&point.height.to_be_bytes());
    key.extend_from_slice(&point.hash);
    key
}

fn prepare<S: KvStore>(
    writer: &IndexWriter<S>,
    height: u32,
    block: &Block,
) -> Result<PreparedBlock, IndexError> {
    writer.prepare_block_with_spent_scripts(
        IndexCapabilities::COMPACT_FILTER,
        height,
        point(height, block).hash,
        &consensus_bytes(block),
        &NoScripts,
    )
}

fn batch(blocks: impl IntoIterator<Item = PreparedBlock>) -> PreparedBatch {
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 10_000,
        max_bytes: 1_000_000,
    });
    for block in blocks {
        assert!(batch.try_push(block).is_ok());
    }
    batch
}

fn setup() -> Result<(Arc<MemoryStore>, IndexWriter<MemoryStore>), IndexError> {
    let store = Arc::new(MemoryStore::default());
    let writer = IndexWriter::open(Arc::clone(&store), 1)?;
    Ok((store, writer))
}

#[test]
fn batch_chains_headers_sequentially_and_publishes_one_exact_snapshot() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let first = block(point(0, &genesis).hash, 1);
    let second = block(point(1, &first).hash, 2);
    let old_reader = bitcoin_rs_index::Indexer::new(Arc::clone(&store));
    let old = old_reader.snapshot()?;
    let prepared = batch([
        prepare(&writer, 0, &genesis)?,
        prepare(&writer, 1, &first)?,
        prepare(&writer, 2, &second)?,
    ]);
    let (fence, _) = writer.fenced_watermarks()?;
    assert_eq!(
        writer.commit_forward_with_cursor(
            fence,
            prepared,
            ConsumerCursorUpdate::Set(b"tip-two")
        )?,
        point(2, &second)
    );
    let snapshot = writer.snapshot()?;
    let mut previous = FilterHeader::all_zeros();
    for (height, block) in [genesis, first, second].iter().enumerate() {
        let at = point(u32::try_from(height)?, block);
        let record = snapshot.compact_filter(at)?.ok_or("missing filter")?;
        let filter = BlockFilter::new(&record.filter);
        assert_eq!(
            record.filter_header,
            filter.filter_header(&previous).to_byte_array()
        );
        assert_eq!(
            record.filter_hash,
            bitcoin_rs_primitives::encode::double_sha256(&record.filter).to_le_bytes()
        );
        assert_eq!(record.block, at);
        previous = FilterHeader::from_byte_array(record.filter_header);
        assert!(old.compact_filter(at)?.is_none());
        assert!(
            snapshot
                .compact_filter(IndexWatermark {
                    height: at.height + 1,
                    ..at
                })?
                .is_none()
        );
    }
    assert_eq!(
        snapshot.capability_watermark(IndexCapability::CompactFilter)?,
        writer.watermarks()?.compact_filter
    );
    assert!(
        snapshot
            .capability_watermark(IndexCapability::TxLookup)?
            .is_none()
    );
    assert_eq!(writer.consumer_cursor()?, Some(b"tip-two".to_vec()));
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
    Ok(())
}

#[test]
fn missing_exact_predecessor_refuses_forward_and_rollback_without_mutation() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let first = block(point(0, &genesis).hash, 1);
    writer.commit_forward(batch([prepare(&writer, 0, &genesis)?]))?;
    let mut deleted = store.new_batch();
    let mut missing_key = key(point(0, &genesis));
    deleted.delete(ColumnFamily::UtxoMeta, &missing_key);
    missing_key[1] = 1;
    deleted.delete(ColumnFamily::UtxoMeta, &missing_key);
    store.write(deleted)?;
    let before = store.rows(ColumnFamily::UtxoMeta);
    let prepared = batch([prepare(&writer, 1, &first)?]);
    assert!(matches!(
        writer.commit_forward(prepared),
        Err(IndexError::MissingCompactFilter { height: 0, .. })
    ));
    assert_eq!(store.rows(ColumnFamily::UtxoMeta), before);
    let (fence, _) = writer.fenced_watermarks()?;
    assert!(matches!(
        writer.commit_compact_filter_rollback_with_cursor(fence, None, ConsumerCursorUpdate::Clear),
        Err(IndexError::MissingCompactFilter { height: 0, .. })
    ));
    assert_eq!(store.rows(ColumnFamily::UtxoMeta), before);
    Ok(())
}

#[test]
fn filter_writes_and_cursor_only_writes_share_all_four_watermark_fences() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let (stale, _) = writer.fenced_watermarks()?;
    let prepared = batch([prepare(&writer, 0, &genesis)?]);
    writer.commit_consumer_cursor(stale.clone(), b"new-revision")?;
    assert!(matches!(
        writer.commit_forward_with_cursor(stale, prepared, ConsumerCursorUpdate::Clear),
        Err(IndexError::StaleIndexState)
    ));
    assert!(writer.watermarks()?.compact_filter.is_none());
    assert!(
        store
            .rows(ColumnFamily::UtxoMeta)
            .iter()
            .all(|(key, _)| !key.starts_with(b"F"))
    );
    let (fence, _) = writer.fenced_watermarks()?;
    // Change only the fourth watermark, without bumping revision, to prove the
    // conditional write explicitly fences that key as well.
    let mut changed = store.new_batch();
    changed.put(
        ColumnFamily::UtxoMeta,
        FILTER_WATERMARK,
        &point(0, &genesis).to_bytes(),
    );
    store.write(changed)?;
    assert!(matches!(
        writer.commit_consumer_cursor(fence, b"stale"),
        Err(IndexError::StaleIndexState)
    ));
    assert_eq!(writer.consumer_cursor()?, Some(b"new-revision".to_vec()));
    Ok(())
}

#[test]
fn rollback_retains_branches_and_reconnecting_reuses_the_immutable_record() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let first = block(point(0, &genesis).hash, 1);
    writer.commit_forward(batch([
        prepare(&writer, 0, &genesis)?,
        prepare(&writer, 1, &first)?,
    ]))?;
    let original = writer
        .snapshot()?
        .compact_filter(point(1, &first))?
        .ok_or("first filter")?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_compact_filter_rollback_with_cursor(
        fence,
        Some(point(0, &genesis)),
        ConsumerCursorUpdate::Set(b"rewound"),
    )?;
    assert_eq!(
        writer.snapshot()?.compact_filter(point(1, &first))?,
        Some(original.clone())
    );
    assert_eq!(writer.consumer_cursor()?, Some(b"rewound".to_vec()));
    let rival = block(point(0, &genesis).hash, 9);
    writer.commit_forward(batch([prepare(&writer, 1, &rival)?]))?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_compact_filter_rollback_with_cursor(
        fence,
        Some(point(0, &genesis)),
        ConsumerCursorUpdate::Keep,
    )?;
    writer.commit_forward(batch([prepare(&writer, 1, &first)?]))?;
    assert_eq!(
        writer.snapshot()?.compact_filter(point(1, &first))?,
        Some(original)
    );
    assert!(
        writer
            .snapshot()?
            .compact_filter(point(1, &rival))?
            .is_some()
    );
    assert_eq!(
        store
            .rows(ColumnFamily::UtxoMeta)
            .iter()
            .filter(|(key, _)| key.starts_with(b"F"))
            .count(),
        6
    );
    assert!(
        IndexCapabilities::NONE
            .leftover(writer.watermarks()?)
            .is_empty()
    );
    Ok(())
}

#[test]
fn unknown_record_version_refuses_filter_operation_and_survives_legacy_reset() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let at = point(0, &genesis);
    writer.commit_forward(batch([prepare(&writer, 0, &genesis)?]))?;
    let mut raw = store
        .get(ColumnFamily::UtxoMeta, &key(at))?
        .ok_or("filter bytes")?;
    raw[0] = 99;
    let mut changed = store.new_batch();
    changed.put(ColumnFamily::UtxoMeta, &key(at), &raw);
    store.write(changed)?;
    assert!(matches!(
        writer.snapshot()?.compact_filter(at),
        Err(IndexError::UnsupportedCompactFilterVersion { version: 99 })
    ));
    let next = block(at.hash, 1);
    assert!(matches!(
        writer.commit_forward(batch([prepare(&writer, 1, &next)?])),
        Err(IndexError::UnsupportedCompactFilterVersion { version: 99 })
    ));
    IndexWriter::reset_index(store.as_ref(), 2)?;
    let reopened = IndexWriter::open(Arc::clone(&store), 3)?;
    assert_eq!(reopened.watermarks()?.compact_filter, Some(at));
    assert_eq!(store.get(ColumnFamily::UtxoMeta, &key(at))?, Some(raw));
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, &[0, b'V'])?,
        Some(vec![5, 0, 0, 0])
    );
    Ok(())
}

#[test]
fn explicit_filter_reset_is_prefix_bounded_and_preserves_sibling_rows_and_metadata() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    writer.commit_block(0, &consensus_bytes(&genesis))?;
    writer.commit_forward(batch([prepare(&writer, 0, &genesis)?]))?;
    let legacy = writer.watermarks()?;
    let headers = store.rows(ColumnFamily::BlockHeaders);
    let transactions = store.rows(ColumnFamily::TxConfirmed);
    let mut extra = store.new_batch();
    extra.put(ColumnFamily::UtxoMeta, b"unrelated-metadata", b"preserve");
    // More than one reset scan, including unrecognized filter record versions.
    for height in 1..1_005 {
        extra.put(
            ColumnFamily::UtxoMeta,
            &key(IndexWatermark {
                height,
                hash: [7; 32],
            }),
            &[99],
        );
    }
    store.write(extra)?;
    writer.reset_capabilities(IndexCapabilities::COMPACT_FILTER)?;
    let watermarks = writer.watermarks()?;
    assert_eq!(watermarks.tx_lookup, legacy.tx_lookup);
    assert_eq!(watermarks.script_history, legacy.script_history);
    assert!(watermarks.compact_filter.is_none());
    assert_eq!(store.rows(ColumnFamily::BlockHeaders), headers);
    assert_eq!(store.rows(ColumnFamily::TxConfirmed), transactions);
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, b"unrelated-metadata")?,
        Some(b"preserve".to_vec())
    );
    assert!(
        store
            .rows(ColumnFamily::UtxoMeta)
            .iter()
            .all(|(key, _)| !key.starts_with(b"F"))
    );
    Ok(())
}

#[test]
fn prepared_budget_counts_filter_bytes_and_entire_record_overhead() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let first = block(point(0, &genesis).hash, 1);
    let prepared = prepare(&writer, 0, &genesis)?;
    let expected_bytes = prepared.encoded_bytes;
    assert_eq!(prepared.row_count, 2);
    let mut bounded = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 10,
        max_bytes: expected_bytes,
    });
    assert!(bounded.try_push(prepared).is_ok());
    assert!(bounded.is_full());
    assert!(bounded.try_push(prepare(&writer, 1, &first)?).is_err());
    writer.commit_forward(bounded)?;
    let record_key = key(point(0, &genesis));
    let record = store
        .get(ColumnFamily::UtxoMeta, &record_key)?
        .ok_or("record")?;
    let mut blob_key = record_key.clone();
    blob_key[1] = 1;
    let blob = store
        .get(ColumnFamily::UtxoMeta, &blob_key)?
        .ok_or("blob")?;
    assert_eq!(
        expected_bytes,
        record_key.len() + record.len() + blob_key.len() + blob.len()
    );
    assert_eq!(record.len(), 97);
    assert_eq!(
        writer
            .snapshot()?
            .compact_filter_metadata(point(0, &genesis))?
            .ok_or("metadata")?
            .filter_hash,
        bitcoin_rs_primitives::encode::double_sha256(&blob).to_le_bytes()
    );
    assert_eq!(record_key.len(), 38);
    assert_eq!(record[0], 2);
    let mut oversized = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 0,
        max_bytes: 0,
    });
    assert!(oversized.try_push(prepare(&writer, 1, &first)?).is_ok());
    assert!(oversized.is_full());
    Ok(())
}

#[test]
fn disabled_filter_preparation_never_loads_spent_scripts_or_writes_filter_rows() -> TestResult {
    let (store, mut writer) = setup()?;
    let mut genesis = block([0; 32], 0);
    let missing = OutPoint::new(Txid(Hash256::from_le_bytes(&[7; 32])), 3);
    genesis.txs.push(Tx {
        inputs: vec![TxIn {
            previous_output: missing,
            ..TxIn::default()
        }],
        ..genesis.txs[0].clone()
    });
    let body = consensus_bytes(&genesis);
    let prepared = writer.prepare_block_with_spent_scripts(
        IndexCapabilities::HISTORICAL,
        0,
        point(0, &genesis).hash,
        &body,
        &UnexpectedScripts,
    )?;
    writer.commit_forward(batch([prepared]))?;
    assert!(
        matches!(prepare(&writer, 0, &genesis), Err(IndexError::CompactFilterBuild(CompactFilterError::MissingPrevout(outpoint))) if outpoint == missing)
    );
    assert!(writer.watermarks()?.compact_filter.is_none());
    assert!(
        store
            .rows(ColumnFamily::UtxoMeta)
            .iter()
            .all(|(key, _)| !key.starts_with(b"F"))
    );
    Ok(())
}

#[test]
fn failed_atomic_commit_exposes_neither_filter_watermark_nor_cursor() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let prepared = batch([prepare(&writer, 0, &genesis)?]);
    let (fence, _) = writer.fenced_watermarks()?;
    store.fail_next_fenced_write.store(true, Ordering::SeqCst);
    assert!(matches!(
        writer.commit_forward_with_cursor(
            fence,
            prepared,
            ConsumerCursorUpdate::Set(b"not-committed")
        ),
        Err(IndexError::Storage(_))
    ));
    assert!(
        writer
            .snapshot()?
            .compact_filter(point(0, &genesis))?
            .is_none()
    );
    assert!(writer.watermarks()?.compact_filter.is_none());
    assert!(writer.consumer_cursor()?.is_none());
    Ok(())
}

#[test]
fn reset_invalidates_prepared_filter_fence_and_rollback_checks_parent_identity() -> TestResult {
    let (_, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let first = block(point(0, &genesis).hash, 1);
    let (fence, _) = writer.fenced_watermarks()?;
    let prepared = batch([prepare(&writer, 0, &genesis)?]);
    writer.reset_capabilities(IndexCapabilities::COMPACT_FILTER)?;
    assert!(matches!(
        writer.commit_forward_with_cursor(fence, prepared, ConsumerCursorUpdate::Keep),
        Err(IndexError::ResetInProgress)
    ));
    writer.commit_forward(batch([
        prepare(&writer, 0, &genesis)?,
        prepare(&writer, 1, &first)?,
    ]))?;
    let (fence, _) = writer.fenced_watermarks()?;
    let wrong_parent = IndexWatermark {
        height: 0,
        hash: [8; 32],
    };
    assert!(matches!(
        writer.commit_compact_filter_rollback_with_cursor(
            fence,
            Some(wrong_parent),
            ConsumerCursorUpdate::Keep
        ),
        Err(IndexError::InvalidCompactFilterRecord)
    ));
    assert_eq!(writer.watermarks()?.compact_filter, Some(point(1, &first)));
    Ok(())
}

#[test]
fn aligned_four_capability_commit_and_rollback_share_one_durable_transition() -> TestResult {
    let (_, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let prepared = writer.prepare_block_with_spent_scripts(
        IndexCapabilities::ALL,
        0,
        point(0, &genesis).hash,
        &consensus_bytes(&genesis),
        &NoScripts,
    )?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_forward_with_cursor(
        fence,
        batch([prepared]),
        ConsumerCursorUpdate::Set(b"all"),
    )?;
    let marks = writer.watermarks()?;
    assert_eq!(marks.tx_lookup, Some(point(0, &genesis)));
    assert_eq!(marks.tx_lookup, marks.script_history);
    assert_eq!(marks.tx_lookup, marks.script_live);
    assert_eq!(marks.tx_lookup, marks.compact_filter);
    let original = writer.snapshot()?.compact_filter(point(0, &genesis))?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
        fence,
        IndexCapabilities::ALL,
        None,
        &consensus_bytes(&genesis),
        ConsumerCursorUpdate::Clear,
        &NoScripts,
    )?;
    assert_eq!(
        writer.watermarks()?,
        bitcoin_rs_index::IndexWatermarks::default()
    );
    assert_eq!(
        writer.snapshot()?.compact_filter(point(0, &genesis))?,
        original
    );
    assert!(writer.consumer_cursor()?.is_none());
    Ok(())
}

#[test]
fn retained_current_record_cannot_rollback_across_a_missing_previous_record() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let first = block(point(0, &genesis).hash, 1);
    writer.commit_forward(batch([
        prepare(&writer, 0, &genesis)?,
        prepare(&writer, 1, &first)?,
    ]))?;
    let mut deletion = store.new_batch();
    deletion.delete(ColumnFamily::UtxoMeta, &key(point(0, &genesis)));
    store.write(deletion)?;
    let before = store.rows(ColumnFamily::UtxoMeta);
    let (fence, _) = writer.fenced_watermarks()?;
    assert!(matches!(
        writer.commit_compact_filter_rollback_with_cursor(
            fence,
            Some(point(0, &genesis)),
            ConsumerCursorUpdate::Clear
        ),
        Err(IndexError::MissingCompactFilter { height: 0, .. })
    ));
    assert_eq!(store.rows(ColumnFamily::UtxoMeta), before);
    Ok(())
}

#[cfg(any(feature = "fjall", feature = "redb"))]
fn persistent_roundtrip<S: KvStore>(
    open: impl Fn() -> Result<S, bitcoin_rs_storage::StorageError>,
) -> TestResult {
    let genesis = block([0; 32], 0);
    let first = block(point(0, &genesis).hash, 1);
    let original = {
        let mut writer = IndexWriter::open(Arc::new(open()?), 1)?;
        writer.commit_forward(batch([
            prepare(&writer, 0, &genesis)?,
            prepare(&writer, 1, &first)?,
        ]))?;
        writer
            .snapshot()?
            .compact_filter(point(1, &first))?
            .ok_or("first filter")?
    };
    {
        let mut writer = IndexWriter::open(Arc::new(open()?), 2)?;
        assert_eq!(writer.watermarks()?.compact_filter, Some(point(1, &first)));
        assert_eq!(
            writer.snapshot()?.compact_filter(point(1, &first))?,
            Some(original.clone())
        );
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_compact_filter_rollback_with_cursor(
            fence,
            Some(point(0, &genesis)),
            ConsumerCursorUpdate::Set(b"rewound"),
        )?;
    }
    let mut writer = IndexWriter::open(Arc::new(open()?), 3)?;
    assert_eq!(
        writer.watermarks()?.compact_filter,
        Some(point(0, &genesis))
    );
    assert_eq!(writer.consumer_cursor()?, Some(b"rewound".to_vec()));
    assert_eq!(
        writer.snapshot()?.compact_filter(point(1, &first))?,
        Some(original.clone())
    );
    writer.commit_forward(batch([prepare(&writer, 1, &first)?]))?;
    assert_eq!(
        writer.snapshot()?.compact_filter(point(1, &first))?,
        Some(original)
    );
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_filter_records_cursor_and_rewind_survive_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    persistent_roundtrip(|| bitcoin_rs_storage::FjallStore::open(dir.path()))
}

#[cfg(feature = "redb")]
#[test]
fn dedicated_redb_filter_records_cursor_and_rewind_survive_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    persistent_roundtrip(|| bitcoin_rs_storage::open_redb_tx_index_store(dir.path()))
}

#[test]
fn corrupt_durable_tip_header_is_refused_before_extension_or_rollback() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let first = block(point(0, &genesis).hash, 1);
    let second = block(point(1, &first).hash, 2);
    writer.commit_forward(batch([
        prepare(&writer, 0, &genesis)?,
        prepare(&writer, 1, &first)?,
    ]))?;
    let tip_key = key(point(1, &first));
    let mut metadata = store
        .get(ColumnFamily::UtxoMeta, &tip_key)?
        .ok_or("metadata")?;
    metadata[65] ^= 1;
    let mut corruption = store.new_batch();
    corruption.put(ColumnFamily::UtxoMeta, &tip_key, &metadata);
    store.write(corruption)?;
    let before = store.rows(ColumnFamily::UtxoMeta);
    assert!(matches!(
        writer.commit_forward(batch([prepare(&writer, 2, &second)?])),
        Err(IndexError::InvalidCompactFilterRecord)
    ));
    let (fence, _) = writer.fenced_watermarks()?;
    assert!(matches!(
        writer.commit_compact_filter_rollback_with_cursor(
            fence,
            Some(point(0, &genesis)),
            ConsumerCursorUpdate::Clear
        ),
        Err(IndexError::InvalidCompactFilterRecord)
    ));
    assert_eq!(store.rows(ColumnFamily::UtxoMeta), before);
    Ok(())
}

#[test]
fn genesis_filter_requires_zero_parent_and_version_one_is_explicitly_refused() -> TestResult {
    let (store, mut writer) = setup()?;
    let non_genesis = block([1; 32], 0);
    assert!(matches!(
        writer.commit_forward(batch([prepare(&writer, 0, &non_genesis)?])),
        Err(IndexError::InvalidCompactFilterRecord)
    ));
    assert_eq!(store.count(ColumnFamily::UtxoMeta), 0);
    let genesis = block([0; 32], 0);
    writer.commit_forward(batch([prepare(&writer, 0, &genesis)?]))?;
    let metadata_key = key(point(0, &genesis));
    let mut metadata = store
        .get(ColumnFamily::UtxoMeta, &metadata_key)?
        .ok_or("metadata")?;
    metadata[0] = 1;
    let mut old_format = store.new_batch();
    old_format.put(ColumnFamily::UtxoMeta, &metadata_key, &metadata);
    store.write(old_format)?;
    assert!(matches!(
        writer
            .snapshot()?
            .compact_filter_metadata(point(0, &genesis)),
        Err(IndexError::UnsupportedCompactFilterVersion { version: 1 })
    ));
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, &metadata_key)?,
        Some(metadata)
    );
    Ok(())
}

#[test]
fn full_reads_and_reconnect_verify_blob_while_metadata_reads_stay_fixed_size() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let first = block(point(0, &genesis).hash, 1);
    writer.commit_forward(batch([
        prepare(&writer, 0, &genesis)?,
        prepare(&writer, 1, &first)?,
    ]))?;
    let metadata = writer
        .snapshot()?
        .compact_filter_metadata(point(1, &first))?
        .ok_or("metadata")?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_compact_filter_rollback_with_cursor(
        fence,
        Some(point(0, &genesis)),
        ConsumerCursorUpdate::Keep,
    )?;
    let mut blob_key = key(point(1, &first));
    blob_key[1] = 1;
    let mut corruption = store.new_batch();
    corruption.put(ColumnFamily::UtxoMeta, &blob_key, &[0]);
    store.write(corruption)?;
    assert_eq!(
        writer
            .snapshot()?
            .compact_filter_metadata(point(1, &first))?,
        Some(metadata)
    );
    assert!(matches!(
        writer.snapshot()?.compact_filter(point(1, &first)),
        Err(IndexError::InvalidCompactFilterRecord)
    ));
    let before = store.rows(ColumnFamily::UtxoMeta);
    assert!(matches!(
        writer.commit_forward(batch([prepare(&writer, 1, &first)?])),
        Err(IndexError::InvalidCompactFilterRecord)
    ));
    assert_eq!(store.rows(ColumnFamily::UtxoMeta), before);
    Ok(())
}

#[test]
fn missing_or_corrupt_current_blob_refuses_forward_and_rollback_atomically() -> TestResult {
    for missing in [true, false] {
        let (store, mut writer) = setup()?;
        let genesis = block([0; 32], 0);
        let first = block(point(0, &genesis).hash, 1);
        let second = block(point(1, &first).hash, 2);
        writer.commit_forward(batch([
            prepare(&writer, 0, &genesis)?,
            prepare(&writer, 1, &first)?,
        ]))?;
        let mut blob_key = key(point(1, &first));
        blob_key[1] = 1;
        let mut damage = store.new_batch();
        if missing {
            damage.delete(ColumnFamily::UtxoMeta, &blob_key);
        } else {
            damage.put(ColumnFamily::UtxoMeta, &blob_key, &[0]);
        }
        store.write(damage)?;
        let before = store.rows(ColumnFamily::UtxoMeta);
        let (fence, _) = writer.fenced_watermarks()?;
        let prepared = batch([prepare(&writer, 2, &second)?]);
        assert!(matches!(
            writer.commit_forward_with_cursor(
                fence.clone(),
                prepared,
                ConsumerCursorUpdate::Set(b"must-not-advance")
            ),
            Err(IndexError::InvalidCompactFilterRecord)
        ));
        assert_eq!(store.rows(ColumnFamily::UtxoMeta), before);
        assert!(matches!(
            writer.commit_compact_filter_rollback_with_cursor(
                fence,
                Some(point(0, &genesis)),
                ConsumerCursorUpdate::Set(b"must-not-rewind")
            ),
            Err(IndexError::InvalidCompactFilterRecord)
        ));
        assert_eq!(store.rows(ColumnFamily::UtxoMeta), before);
    }
    Ok(())
}

#[test]
fn missing_or_corrupt_rollback_target_blob_refuses_rewind_atomically() -> TestResult {
    for missing in [true, false] {
        let (store, mut writer) = setup()?;
        let genesis = block([0; 32], 0);
        let first = block(point(0, &genesis).hash, 1);
        writer.commit_forward(batch([
            prepare(&writer, 0, &genesis)?,
            prepare(&writer, 1, &first)?,
        ]))?;
        let mut blob_key = key(point(0, &genesis));
        blob_key[1] = 1;
        let mut damage = store.new_batch();
        if missing {
            damage.delete(ColumnFamily::UtxoMeta, &blob_key);
        } else {
            damage.put(ColumnFamily::UtxoMeta, &blob_key, &[0]);
        }
        store.write(damage)?;
        let before = store.rows(ColumnFamily::UtxoMeta);
        let (fence, _) = writer.fenced_watermarks()?;
        assert!(matches!(
            writer.commit_compact_filter_rollback_with_cursor(
                fence,
                Some(point(0, &genesis)),
                ConsumerCursorUpdate::Set(b"must-not-rewind")
            ),
            Err(IndexError::InvalidCompactFilterRecord)
        ));
        assert_eq!(store.rows(ColumnFamily::UtxoMeta), before);
    }
    Ok(())
}

#[test]
fn malformed_filter_watermark_preserves_exact_bytes_while_legacy_writes_continue() -> TestResult {
    for malformed in [Vec::new(), vec![7; 35], vec![8; 1024]] {
        let (store, mut writer) = setup()?;
        let genesis = block([0; 32], 0);
        let mut damage = store.new_batch();
        damage.put(ColumnFamily::UtxoMeta, FILTER_WATERMARK, &malformed);
        store.write(damage)?;
        let (fence, watermarks) = writer.fenced_watermarks()?;
        assert!(watermarks.compact_filter.is_none());
        assert!(matches!(
            writer
                .snapshot()?
                .capability_watermark(IndexCapability::CompactFilter),
            Err(IndexError::InvalidCompactFilterWatermark)
        ));
        assert!(matches!(
            writer
                .indexer()
                .capability_watermark(IndexCapability::CompactFilter),
            Err(IndexError::InvalidCompactFilterWatermark)
        ));
        let before = store.rows(ColumnFamily::UtxoMeta);
        assert!(matches!(
            writer.commit_forward_with_cursor(
                fence.clone(),
                batch([prepare(&writer, 0, &genesis)?]),
                ConsumerCursorUpdate::Set(b"must-not-advance")
            ),
            Err(IndexError::InvalidCompactFilterWatermark)
        ));
        assert!(matches!(
            writer.commit_compact_filter_rollback_with_cursor(
                fence,
                None,
                ConsumerCursorUpdate::Clear
            ),
            Err(IndexError::InvalidCompactFilterWatermark)
        ));
        assert_eq!(store.rows(ColumnFamily::UtxoMeta), before);
        writer.commit_block(0, &consensus_bytes(&genesis))?;
        let (fence, watermarks) = writer.fenced_watermarks()?;
        assert_eq!(watermarks.tx_lookup, Some(point(0, &genesis)));
        assert_eq!(watermarks.script_history, Some(point(0, &genesis)));
        writer.commit_consumer_cursor(fence, b"legacy-ready")?;
        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, FILTER_WATERMARK)?,
            Some(malformed.clone())
        );
        assert_eq!(writer.consumer_cursor()?, Some(b"legacy-ready".to_vec()));
        IndexWriter::reset_index(store.as_ref(), 2)?;
        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, FILTER_WATERMARK)?,
            Some(malformed)
        );
        // Only an explicit filter reset removes the opaque malformed cursor.
        writer.reset_capabilities(IndexCapabilities::COMPACT_FILTER)?;
        assert!(
            store
                .get(ColumnFamily::UtxoMeta, FILTER_WATERMARK)?
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn a_changed_malformed_filter_watermark_rejects_legacy_and_cursor_writes() -> TestResult {
    let (store, mut writer) = setup()?;
    let genesis = block([0; 32], 0);
    let mut first = store.new_batch();
    first.put(ColumnFamily::UtxoMeta, FILTER_WATERMARK, &[7; 35]);
    store.write(first)?;
    let (fence, _) = writer.fenced_watermarks()?;
    let mut second = store.new_batch();
    second.put(ColumnFamily::UtxoMeta, FILTER_WATERMARK, &[8; 35]);
    store.write(second)?;
    let before = store.rows(ColumnFamily::UtxoMeta);
    let prepared = writer.prepare_block(0, point(0, &genesis).hash, &consensus_bytes(&genesis))?;
    assert!(matches!(
        writer.commit_forward_with_cursor(
            fence.clone(),
            batch([prepared]),
            ConsumerCursorUpdate::Set(b"stale")
        ),
        Err(IndexError::StaleIndexState)
    ));
    assert!(matches!(
        writer.commit_consumer_cursor(fence, b"stale"),
        Err(IndexError::StaleIndexState)
    ));
    assert_eq!(store.rows(ColumnFamily::UtxoMeta), before);
    Ok(())
}

#[test]
fn malformed_legacy_watermarks_keep_their_original_capture_error() -> TestResult {
    for key in [[0, b'T'], [0, b'S'], [0, b'L']] {
        let (store, mut writer) = setup()?;
        let mut damage = store.new_batch();
        damage.put(ColumnFamily::UtxoMeta, &key, &[7; 35]);
        damage.put(ColumnFamily::UtxoMeta, FILTER_WATERMARK, &[8; 35]);
        store.write(damage)?;
        assert!(matches!(
            writer.fenced_watermarks(),
            Err(IndexError::InvalidWatermark)
        ));
    }
    Ok(())
}
