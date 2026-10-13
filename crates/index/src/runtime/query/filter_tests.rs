//! Query-only fixtures: immutable filter rows, exact ancestry, and read tripwires.
#![expect(clippy::expect_used, reason = "focused query fixture assertions")]

use core::ops::ControlFlow;
use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, BlockTreeReader, NodeStatus, TipReader, TipSnapshot};
use bitcoin_rs_primitives::{BlockHash, Hash256, Network, OutPoint, Txid, encode::double_sha256};
use bitcoin_rs_storage::PrefixScanLimit;
use parking_lot::{Mutex, RwLock};

use super::{DerivedIndexQueryEngine, IndexBlockSource, QueryEngineLive};
use crate::query_api::{CompactFilterQuery, FilterQueryError};
use crate::runtime::{DerivedIndexLifecycle, DerivedIndexQueryAdapter, DerivedIndexRuntime};
use crate::{
    CompactFilterMetadata, CompactFilterRecord, IndexCapabilities, IndexCapability, IndexError,
    IndexReader, IndexWatermark, ScriptHash, ScriptLiveScan, TxIndexScan, TxIndexSnapshot,
};

type Key = (u32, [u8; 32]);
type ReadHook = Arc<Mutex<Option<(Option<Key>, Box<dyn FnOnce() + Send>)>>>;

#[derive(Clone)]
struct Row {
    metadata: CompactFilterMetadata,
    blob: Arc<Vec<u8>>,
}

#[derive(Clone, Default)]
struct Data {
    watermark: Option<IndexWatermark>,
    rows: BTreeMap<Key, Row>,
    unsupported: Option<Key>,
}

#[derive(Default)]
struct Reads {
    metadata: AtomicUsize,
    blobs: AtomicUsize,
}

struct Reader {
    data: RwLock<Data>,
    reads: Arc<Reads>,
    hook: ReadHook,
}
struct Snapshot {
    data: Data,
    reads: Arc<Reads>,
    hook: ReadHook,
}

impl IndexReader for Reader {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        Ok(Box::new(Snapshot {
            data: self.data.read().clone(),
            reads: self.reads.clone(),
            hook: self.hook.clone(),
        }))
    }
}

impl TxIndexSnapshot for Snapshot {
    fn capability_watermark(
        &self,
        _: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        Ok(self.data.watermark)
    }
    fn compact_filter_metadata(
        &self,
        block: IndexWatermark,
    ) -> Result<Option<CompactFilterMetadata>, IndexError> {
        self.reads.metadata.fetch_add(1, Ordering::Relaxed);
        let key = (block.height, block.hash);
        let hook = {
            let mut slot = self.hook.lock();
            if slot
                .as_ref()
                .is_some_and(|(target, _)| target.is_none_or(|target| target == key))
            {
                slot.take()
            } else {
                None
            }
        };
        if let Some((_, hook)) = hook {
            hook();
        }
        if self.data.unsupported == Some(key) {
            return Err(IndexError::UnsupportedCompactFilterVersion { version: 255 });
        }
        Ok(self.data.rows.get(&key).map(|row| row.metadata))
    }
    fn compact_filter(
        &self,
        block: IndexWatermark,
    ) -> Result<Option<CompactFilterRecord>, IndexError> {
        self.reads.blobs.fetch_add(1, Ordering::Relaxed);
        if self
            .data
            .rows
            .get(&(block.height, block.hash))
            .is_some_and(|row| {
                double_sha256(row.blob.as_slice()).to_le_bytes() != row.metadata.filter_hash
            })
        {
            return Err(IndexError::InvalidCompactFilterRecord);
        }
        Ok(self
            .data
            .rows
            .get(&(block.height, block.hash))
            .map(|row| CompactFilterRecord {
                block,
                parent_hash: row.metadata.parent_hash,
                filter: (*row.blob).clone(),
                filter_hash: row.metadata.filter_hash,
                filter_header: row.metadata.filter_header,
            }))
    }
    fn transaction_rows(&self, _: &Txid, _: PrefixScanLimit) -> Result<TxIndexScan, IndexError> {
        panic!("filter query must not read transaction rows")
    }
    fn funding_rows(&self, _: ScriptHash, _: PrefixScanLimit) -> Result<TxIndexScan, IndexError> {
        panic!("filter query must not read funding rows")
    }
    fn spending_rows(&self, _: &OutPoint, _: PrefixScanLimit) -> Result<TxIndexScan, IndexError> {
        panic!("filter query must not read spending rows")
    }
    fn live_rows(&self, _: ScriptHash, _: PrefixScanLimit) -> Result<ScriptLiveScan, IndexError> {
        panic!("filter query must not read live rows")
    }
}

fn header(hash: [u8; 32], previous: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&hash);
    bytes[32..].copy_from_slice(&previous);
    double_sha256(&bytes).to_le_bytes()
}

struct Fixture {
    engine: DerivedIndexQueryEngine,
    runtime: Arc<DerivedIndexRuntime>,
    reader: Arc<Reader>,
    tree: Arc<RwLock<BlockTree>>,
    applied: Arc<ArcSwapOption<TipSnapshot>>,
    tips: Vec<TipSnapshot>,
}

impl Fixture {
    fn new(count: u32) -> Self {
        let mut tree = BlockTree::new();
        let mut parent = None;
        let mut parent_hash = [0; 32];
        let mut previous_header = [0; 32];
        let mut tips = Vec::new();
        let mut data = Data::default();
        let blob = Arc::new(vec![0]);
        let filter_hash = double_sha256(blob.as_slice()).to_le_bytes();
        for height in 0..count {
            let mut block_header = Network::Regtest.genesis_block().header;
            block_header.prev_blockhash = BlockHash::from(Hash256::from_le_bytes(&parent_hash));
            block_header.nonce = height;
            let id = tree
                .insert_node(parent, block_header, NodeStatus::Active)
                .expect("insert header");
            tree.record_applied_tx_count(id, 1)
                .expect("record validated identity");
            let node = tree.node(id).expect("node");
            let tip = TipSnapshot {
                tip_id: id,
                height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            };
            let block = IndexWatermark {
                height,
                hash: node.hash.to_le_bytes(),
            };
            let filter_header = header(filter_hash, previous_header);
            data.rows.insert(
                (height, block.hash),
                Row {
                    metadata: CompactFilterMetadata {
                        block,
                        parent_hash,
                        filter_hash,
                        filter_header,
                    },
                    blob: blob.clone(),
                },
            );
            data.watermark = Some(block);
            parent = Some(id);
            parent_hash = block.hash;
            previous_header = filter_header;
            tips.push(tip);
        }
        let applied = Arc::new(ArcSwapOption::new(tips.last().cloned().map(Arc::new)));
        let tree = Arc::new(RwLock::new(tree));
        let (wake, _) = crossbeam_channel::bounded(1);
        let runtime = Arc::new(DerivedIndexRuntime::new(wake));
        let reader = Arc::new(Reader {
            data: RwLock::new(data),
            reads: Arc::new(Reads::default()),
            hook: Arc::new(Mutex::new(None)),
        });
        let engine = DerivedIndexQueryEngine::new(
            runtime.clone(),
            reader.clone(),
            IndexBlockSource::new(Arc::new(RwLock::new(crate::BlockLog::new()))),
            BlockTreeReader::new(tree.clone()),
            TipReader::new(applied.clone()),
            None,
            QueryEngineLive {
                utxo: None,
                chain_transition: None,
                enabled: IndexCapabilities::COMPACT_FILTER,
            },
        );
        Self {
            engine,
            runtime,
            reader,
            tree,
            applied,
            tips,
        }
    }
    fn hash(&self, height: usize) -> BlockHash {
        BlockHash::from(self.tips[height].hash)
    }
    fn key(&self, height: usize) -> Key {
        (
            self.tips[height].height,
            self.tips[height].hash.to_le_bytes(),
        )
    }
    fn hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.reader.hook.lock() = Some((None, Box::new(hook)));
    }
}

#[test]
fn genesis_and_checkpoint_boundaries_use_metadata_only() {
    let fixture = Fixture::new(2_002);
    assert_eq!(
        fixture
            .engine
            .filter_hashes(0, fixture.hash(0))
            .expect("genesis")
            .previous_header,
        [0; 32]
    );
    assert!(
        fixture
            .engine
            .checkpoint_headers(fixture.hash(999))
            .expect("before checkpoint")
            .is_empty()
    );
    assert_eq!(
        fixture
            .engine
            .checkpoint_headers(fixture.hash(1_000))
            .expect("first checkpoint")
            .len(),
        1
    );
    let expected: Vec<_> = [1_000, 2_000]
        .into_iter()
        .map(|height| {
            fixture.reader.data.read().rows[&fixture.key(height)]
                .metadata
                .filter_header
        })
        .collect();
    assert_eq!(
        fixture
            .engine
            .checkpoint_headers(fixture.hash(2_001))
            .expect("two checkpoints"),
        expected
    );
    assert_eq!(fixture.reader.reads.blobs.load(Ordering::Relaxed), 0);
}

#[test]
fn hash_and_filter_ranges_accept_exact_protocol_limits() {
    let fixture = Fixture::new(2_001);
    assert_eq!(
        fixture
            .engine
            .filter_hashes(0, fixture.hash(1_999))
            .expect("2000 hashes")
            .hashes
            .len(),
        2_000
    );
    assert_eq!(
        fixture.engine.filter_hashes(0, fixture.hash(2_000)),
        Err(FilterQueryError::InvalidRange)
    );
    assert_eq!(
        fixture.engine.filter_hashes(2, fixture.hash(1)),
        Err(FilterQueryError::InvalidRange)
    );
    let mut sent = 0;
    assert_eq!(
        fixture
            .engine
            .stream_filters(0, fixture.hash(999), &|| true, &mut |_| {
                sent += 1;
                ControlFlow::Continue(())
            })
            .expect("1000 filters"),
        ControlFlow::Continue(())
    );
    assert_eq!(sent, 1_000);
    assert_eq!(
        fixture
            .engine
            .stream_filters(0, fixture.hash(1_000), &|| true, &mut |_| panic!(
                "oversized range emits nothing"
            )),
        Err(FilterQueryError::InvalidRange)
    );
}

#[test]
fn retained_filter_works_during_lag_but_ranges_do_not() {
    let fixture = Fixture::new(3);
    fixture.reader.data.write().watermark = Some(IndexWatermark {
        height: 1,
        hash: fixture.key(1).1,
    });
    assert!(!fixture.engine.filter_index_info().expect("progress").synced);
    assert_eq!(
        fixture
            .engine
            .filter(fixture.hash(0))
            .expect("retained filter")
            .block
            .height,
        0
    );
    assert_eq!(
        fixture.engine.filter_hashes(0, fixture.hash(1)),
        Err(FilterQueryError::Indexing)
    );
    fixture.reader.data.write().rows.remove(&fixture.key(2));
    assert_eq!(
        fixture.engine.filter(fixture.hash(2)),
        Err(FilterQueryError::Indexing)
    );
}

#[test]
fn stale_ranges_remain_anchored_to_the_requested_stop_branch() {
    let fixture = Fixture::new(3);
    let genesis = fixture.key(0);
    let mut block_header = Network::Regtest.genesis_block().header;
    block_header.prev_blockhash = fixture.hash(0);
    block_header.nonce = 9_999;
    let mut tree = fixture.tree.write();
    let id = tree
        .insert_node(
            Some(fixture.tips[0].tip_id),
            block_header,
            NodeStatus::Stale,
        )
        .expect("fork header");
    tree.record_applied_tx_count(id, 1).expect("applied fork");
    let node = tree.node(id).expect("fork node");
    let tip = TipSnapshot {
        tip_id: id,
        height: 1,
        chainwork: node.chainwork,
        hash: node.hash,
        chain_tx_count: node.chain_tx_count,
    };
    drop(tree);
    let block = IndexWatermark {
        height: 1,
        hash: tip.hash.to_le_bytes(),
    };
    let blob = Arc::new(vec![42]);
    let filter_hash = double_sha256(blob.as_slice()).to_le_bytes();
    let mut data = fixture.reader.data.write();
    let previous = data.rows[&genesis].metadata.filter_header;
    data.rows.insert(
        (1, block.hash),
        Row {
            metadata: CompactFilterMetadata {
                block,
                parent_hash: genesis.1,
                filter_hash,
                filter_header: header(filter_hash, previous),
            },
            blob,
        },
    );
    data.watermark = Some(block);
    let expected = vec![
        data.rows[&fixture.key(1)].metadata.filter_hash,
        data.rows[&fixture.key(2)].metadata.filter_hash,
    ];
    drop(data);
    fixture.applied.store(Some(Arc::new(tip)));
    fixture.runtime.wake();
    assert_eq!(
        fixture
            .engine
            .filter(fixture.hash(2))
            .expect("retained stale filter")
            .block
            .hash,
        fixture.key(2).1
    );
    assert_eq!(
        fixture
            .engine
            .filter_hashes(1, fixture.hash(2))
            .expect("old branch range")
            .hashes,
        expected
    );
}

#[test]
fn ready_probe_checks_version_blob_and_parent_header() {
    let fixture = Fixture::new(3);
    assert!(fixture.engine.filter_index_info().expect("ready").synced);
    assert_eq!(fixture.reader.reads.blobs.load(Ordering::Relaxed), 1);
    fixture.reader.data.write().unsupported = Some(fixture.key(2));
    assert!(matches!(
        fixture.engine.filter_index_info(),
        Err(FilterQueryError::Corrupt(_))
    ));
    fixture.reader.data.write().unsupported = None;
    fixture
        .reader
        .data
        .write()
        .rows
        .get_mut(&fixture.key(2))
        .expect("tip")
        .blob = Arc::new(vec![1]);
    assert!(matches!(
        fixture.engine.filter_index_info(),
        Err(FilterQueryError::Corrupt(_))
    ));
    fixture
        .reader
        .data
        .write()
        .rows
        .get_mut(&fixture.key(2))
        .expect("tip")
        .blob = Arc::new(vec![0]);
    fixture
        .reader
        .data
        .write()
        .rows
        .get_mut(&fixture.key(1))
        .expect("parent")
        .metadata
        .filter_header = [7; 32];
    assert!(matches!(
        fixture.engine.filter_index_info(),
        Err(FilterQueryError::Corrupt(_))
    ));
}

#[test]
fn unknown_unapplied_and_missing_expected_records_are_distinct() {
    let fixture = Fixture::new(2);
    assert_eq!(
        fixture
            .engine
            .filter(BlockHash::from(Hash256::from_le_bytes(&[99; 32]))),
        Err(FilterQueryError::UnknownBlock)
    );
    let mut new_header = Network::Regtest.genesis_block().header;
    new_header.prev_blockhash = fixture.hash(1);
    new_header.nonce = 100;
    let id = fixture
        .tree
        .write()
        .insert_node(
            Some(fixture.tips[1].tip_id),
            new_header,
            NodeStatus::HeaderValid,
        )
        .expect("header only");
    let hash = fixture.tree.read().node(id).expect("new node").hash;
    assert_eq!(
        fixture.engine.filter(BlockHash::from(hash)),
        Err(FilterQueryError::NotConnected)
    );
    fixture.reader.data.write().rows.remove(&fixture.key(1));
    assert!(matches!(
        fixture.engine.filter(fixture.hash(1)),
        Err(FilterQueryError::Corrupt(_))
    ));
}

#[test]
fn stream_headroom_and_sink_cancellation_stop_before_next_blob() {
    let fixture = Fixture::new(3);
    assert_eq!(
        fixture
            .engine
            .stream_filters(0, fixture.hash(2), &|| false, &mut |_| panic!(
                "no headroom"
            )),
        Ok(ControlFlow::Break(()))
    );
    assert_eq!(fixture.reader.reads.blobs.load(Ordering::Relaxed), 0);
    assert_eq!(
        fixture.engine.stream_filters(
            0,
            fixture.hash(2),
            &|| true,
            &mut |_| ControlFlow::Break(())
        ),
        Ok(ControlFlow::Break(()))
    );
    assert_eq!(fixture.reader.reads.blobs.load(Ordering::Relaxed), 1);
}

#[test]
fn stream_detects_reorg_before_loading_second_blob() {
    let fixture = Fixture::new(3);
    let mut sent = 0;
    let result = fixture
        .engine
        .stream_filters(0, fixture.hash(2), &|| true, &mut |_| {
            sent += 1;
            fixture
                .applied
                .store(Some(Arc::new(fixture.tips[1].clone())));
            fixture.runtime.wake();
            ControlFlow::Continue(())
        });
    assert_eq!(result, Err(FilterQueryError::Retry));
    assert_eq!(sent, 1);
    assert_eq!(fixture.reader.reads.blobs.load(Ordering::Relaxed), 1);
}

#[test]
fn stale_invalidation_without_tip_or_revision_change_refuses_inflight_reads() {
    for mode in 0..3 {
        let fixture = Fixture::new(3);
        fixture
            .applied
            .store(Some(Arc::new(fixture.tips[0].clone())));
        fixture.reader.data.write().watermark = Some(IndexWatermark {
            height: 0,
            hash: fixture.key(0).1,
        });
        let tree = fixture.tree.clone();
        let root = fixture.tips[1].tip_id;
        *fixture.reader.hook.lock() = Some((
            Some(fixture.key(1)),
            Box::new(move || {
                tree.write()
                    .invalidate_subtree(root)
                    .expect("invalidate stale branch");
            }),
        ));
        let revision = fixture.runtime.revision();
        let mut emitted = 0;
        let result = match mode {
            0 => fixture.engine.filter(fixture.hash(1)).map(|_| ()),
            1 => fixture.engine.filter_hashes(1, fixture.hash(2)).map(|_| ()),
            _ => fixture
                .engine
                .stream_filters(0, fixture.hash(2), &|| true, &mut |_| {
                    emitted += 1;
                    ControlFlow::Continue(())
                })
                .map(|_| ()),
        };
        assert_eq!(result, Err(FilterQueryError::NotConnected));
        assert_eq!(fixture.runtime.revision(), revision);
        assert_eq!(
            fixture
                .applied
                .load_full()
                .expect("unchanged applied tip")
                .hash,
            fixture.tips[0].hash
        );
        if mode == 2 {
            assert_eq!(emitted, 1);
            assert_eq!(fixture.reader.reads.blobs.load(Ordering::Relaxed), 1);
        }
    }
}

#[test]
fn snapshot_revision_aba_and_local_blocker_are_revalidated() {
    let fixture = Fixture::new(2);
    let runtime = fixture.runtime.clone();
    fixture.hook(move || runtime.wake());
    assert_eq!(
        fixture.engine.filter_hashes(0, fixture.hash(1)),
        Err(FilterQueryError::Retry)
    );
    let runtime = fixture.runtime.clone();
    fixture.hook(move || runtime.block_compact_filters("unsupported filter version", false));
    assert!(matches!(
        fixture.engine.filter_index_info(),
        Err(FilterQueryError::Unavailable(_))
    ));
    assert!(matches!(
        fixture.engine.filter(fixture.hash(0)),
        Err(FilterQueryError::Unavailable(_))
    ));
}

#[test]
fn disabled_stopped_and_opening_queries_fail_closed() {
    let mut fixture = Fixture::new(1);
    fixture.engine.enabled = IndexCapabilities::TX_LOOKUP;
    assert_eq!(
        fixture.engine.filter_index_info(),
        Err(FilterQueryError::Disabled)
    );
    fixture.engine.enabled = IndexCapabilities::COMPACT_FILTER;
    fixture.runtime.request_shutdown();
    assert!(matches!(
        fixture.engine.filter_index_info(),
        Err(FilterQueryError::Unavailable(_))
    ));
    let adapter = DerivedIndexQueryAdapter::new(Arc::new(arc_swap::ArcSwap::from_pointee(
        DerivedIndexLifecycle::Opening,
    )));
    assert!(matches!(
        adapter.filter_index_info(),
        Err(FilterQueryError::Unavailable(_))
    ));
}

#[test]
fn large_filter_stream_has_no_historical_cumulative_byte_cutoff() {
    let fixture = Fixture::new(1_000);
    // A real, large GCS encoding. Synthetic headers/rows exercise query resource
    // behavior, rather than claiming these fixtures are consensus block bodies.
    let mut encoded = Vec::new();
    let mut writer = bitcoin::bip158::GcsFilterWriter::new(&mut encoded, 0, 0, 784_931, 19);
    for index in 0_u32..30_000 {
        writer.add_element(&index.to_le_bytes());
    }
    writer.finish().expect("large filter encoding");
    let blob = Arc::new(encoded);
    let hash = double_sha256(blob.as_slice()).to_le_bytes();
    let mut previous = [0; 32];
    for row in fixture.reader.data.write().rows.values_mut() {
        row.blob = blob.clone();
        row.metadata.filter_hash = hash;
        row.metadata.filter_header = header(hash, previous);
        previous = row.metadata.filter_header;
    }
    let mut bytes = 0;
    assert_eq!(
        fixture
            .engine
            .stream_filters(0, fixture.hash(999), &|| true, &mut |record| {
                bytes += record.filter.len();
                ControlFlow::Continue(())
            })
            .expect("bounded large stream"),
        ControlFlow::Continue(())
    );
    assert!(bytes > 64 << 20);
}
