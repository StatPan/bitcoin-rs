//! Optional-filter isolation and reconciliation through the existing worker.
#![expect(clippy::expect_used, reason = "focused runtime regression assertions")]

use super::recovery_tests::{ForkFixture, Harness};
use super::*;
use crate::{ConsumerCursorUpdate, NoSpentScripts};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, OutPoint, TxIn, Txid, consensus_bytes, deserialize,
};

fn with_filters() -> IndexCapabilities {
    IndexCapabilities::HISTORICAL.insert(IndexCapability::CompactFilter)
}

fn at(tip: &TipSnapshot) -> IndexWatermark {
    IndexWatermark {
        height: tip.height,
        hash: tip.hash.to_le_bytes(),
    }
}

/// Drives only enough passes to establish sibling readiness, allowing the
/// deliberately unavailable filter capability to remain stalled.
fn settle_siblings(harness: &Harness, target: IndexWatermark) {
    let mut pending = None;
    for _ in 0..32 {
        harness
            .worker
            .reconcile_once(&mut pending)
            .expect("reconcile siblings");
        let marks = harness.watermarks();
        if marks.tx_lookup == Some(target) && marks.script_history == Some(target) {
            return;
        }
    }
    assert_eq!(harness.watermarks().tx_lookup, Some(target));
    assert_eq!(harness.watermarks().script_history, Some(target));
}

#[test]
fn unavailable_filter_inputs_do_not_starve_transaction_or_script_history() {
    let fixture = ForkFixture::new(2);
    let tip = fixture.tip(fixture.a[1]);
    // Give the validated-body fixture an external spend for which the body
    // store has no undo. No consensus-validity claim is made by this test.
    let identity = (1, fixture.a[0].1.to_le_bytes());
    let mut bodies = fixture.bodies.bodies.lock();
    let mut block: Block = deserialize(bodies.get(&identity).expect("body")).expect("decode");
    let mut spend = block.txs[0].clone();
    spend.inputs = vec![TxIn {
        previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0),
        ..TxIn::default()
    }];
    block.txs.push(spend);
    bodies.insert(identity, consensus_bytes(&block));
    drop(bodies);
    let harness = Harness::with_enabled(&fixture, u32::MAX, with_filters());
    harness.set_tip(&tip);
    settle_siblings(&harness, at(&tip));
    assert!(harness.runtime.compact_filter_unavailable().is_some());
    harness.runtime.retry_compact_filters();
    let mut pending = None;
    assert!(matches!(
        harness
            .worker
            .reconcile_once(&mut pending)
            .expect("filter input refusal"),
        ReconcileAction::Progressed
    ));
    assert!(harness.runtime.compact_filter_unavailable().is_some());
    assert!(harness.watermarks().compact_filter.is_none());
    assert_eq!(harness.watermarks().tx_lookup, Some(at(&tip)));
    assert_eq!(harness.watermarks().script_history, Some(at(&tip)));
    assert!(!harness.runtime.failed.load(Ordering::Acquire));
    assert!(pending.is_none());
}

#[test]
fn blocked_filter_is_excluded_from_forward_and_rollback_selection() {
    let fixture = ForkFixture::new(2);
    let tip = fixture.tip(fixture.a[1]);
    let harness = Harness::with_enabled(&fixture, u32::MAX, with_filters());
    harness
        .runtime
        .block_compact_filters("unsupported filter record version", false);
    let selected = harness
        .worker
        .forward_selection(IndexWatermarks::default(), &tip)
        .expect("siblings need forward");
    assert_eq!(selected.0, IndexCapabilities::HISTORICAL);
    let marks = IndexWatermarks {
        compact_filter: Some(IndexWatermark {
            height: 2,
            hash: fixture.b[1].1.to_le_bytes(),
        }),
        ..IndexWatermarks::default()
    };
    assert!(
        harness
            .worker
            .rollback_selection(marks, Some(&tip))
            .is_none()
    );
    harness.runtime.retry_compact_filters();
    assert!(
        harness.runtime.compact_filter_unavailable().is_some(),
        "permanent version refusal cannot be retried automatically"
    );
    harness.set_tip(&tip);
    settle_siblings(&harness, at(&tip));
    let mut pending = None;
    assert!(matches!(
        harness
            .worker
            .reconcile_once(&mut pending)
            .expect("unavailable result"),
        ReconcileAction::Stalled
    ));
    assert!(harness.watermarks().compact_filter.is_none());
}

#[test]
fn filter_rollback_uses_retained_records_when_departed_bodies_and_undo_are_absent() {
    let fixture = ForkFixture::new(3);
    let tip_a = fixture.tip(fixture.a[2]);
    let tip_b = fixture.tip(fixture.b[2]);
    // A zero cutover would reset body-derived indexes; filters must still rewind.
    let harness = Harness::with_enabled(&fixture, 0, IndexCapabilities::COMPACT_FILTER);
    harness.set_tip(&tip_a);
    let mut pending = None;
    harness.settle(&mut pending);
    assert_eq!(harness.watermarks().compact_filter, Some(at(&tip_a)));
    for (offset, (_, hash)) in fixture.a.iter().enumerate() {
        fixture.bodies.bodies.lock().remove(&(
            u32::try_from(offset + 1).expect("height"),
            hash.to_le_bytes(),
        ));
    }
    harness.set_tip(&tip_b);
    harness.settle(&mut pending);
    assert_eq!(harness.watermarks().compact_filter, Some(at(&tip_b)));
    assert!(harness.runtime.compact_filter_unavailable().is_none());
}

#[test]
fn missing_filter_watermark_tree_identity_is_local_to_filters() {
    let fixture = ForkFixture::new(2);
    let tip = fixture.tip(fixture.a[1]);
    let harness = Harness::with_enabled(&fixture, u32::MAX, with_filters());
    // Seed a legitimate immutable index branch that this restored tree does
    // not know, then ask the worker to reconcile to the fixture's active tip.
    let mut genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let genesis_hash = *genesis.block_hash().as_bytes();
    let prepared_genesis = harness
        .writer
        .prepare_block_with_spent_scripts(
            IndexCapabilities::COMPACT_FILTER,
            0,
            genesis_hash,
            &consensus_bytes(&genesis),
            &NoSpentScripts,
        )
        .expect("prepare genesis");
    genesis.header.prev_blockhash = BlockHash(Hash256::from_le_bytes(&genesis_hash));
    genesis.header.nonce = genesis.header.nonce.wrapping_add(1);
    let first_hash = *genesis.block_hash().as_bytes();
    let prepared_first = harness
        .writer
        .prepare_block_with_spent_scripts(
            IndexCapabilities::COMPACT_FILTER,
            1,
            first_hash,
            &consensus_bytes(&genesis),
            &NoSpentScripts,
        )
        .expect("prepare first");
    let mut batch = PreparedBatch::new(DEFAULT_BATCH_LIMITS);
    assert!(batch.try_push(prepared_genesis).is_ok());
    assert!(batch.try_push(prepared_first).is_ok());
    let (fence, _) = harness.writer.fenced_watermarks().expect("fence");
    harness
        .writer
        .commit_forward_with_cursor(fence, batch, ConsumerCursorUpdate::Keep)
        .expect("seed unknown branch");
    harness.set_tip(&tip);
    settle_siblings(&harness, at(&tip));
    assert!(harness.runtime.compact_filter_unavailable().is_some());
    assert_eq!(
        harness.watermarks().compact_filter,
        Some(IndexWatermark {
            height: 1,
            hash: first_hash
        })
    );
    assert!(!harness.runtime.failed.load(Ordering::Acquire));
}

#[test]
fn enabling_filters_backfills_without_resetting_ready_sibling_watermarks() {
    let fixture = ForkFixture::new(2);
    let tip = fixture.tip(fixture.a[1]);
    let mut harness = Harness::with_enabled(&fixture, u32::MAX, IndexCapabilities::HISTORICAL);
    harness.set_tip(&tip);
    let mut pending = None;
    harness.settle(&mut pending);
    let legacy = harness.watermarks();
    harness.worker.enabled = with_filters();
    harness.settle(&mut pending);
    let rebuilt = harness.watermarks();
    assert_eq!(rebuilt.tx_lookup, legacy.tx_lookup);
    assert_eq!(rebuilt.script_history, legacy.script_history);
    assert_eq!(rebuilt.compact_filter, Some(at(&tip)));
    harness.worker.enabled = IndexCapabilities::HISTORICAL;
    harness.settle(&mut pending);
    assert_eq!(
        harness.watermarks(),
        rebuilt,
        "disabling preserves filter rows and cursor"
    );
    harness.worker.enabled = with_filters();
    harness.settle(&mut pending);
    assert_eq!(harness.watermarks(), rebuilt);
}

#[test]
fn malformed_optional_filter_cursor_preserves_healthy_sibling_progress() {
    use bitcoin_rs_storage::{ColumnFamily, KvStore};

    for enabled in [IndexCapabilities::HISTORICAL, with_filters()] {
        let fixture = ForkFixture::new(2);
        let tip = fixture.tip(fixture.a[1]);
        let harness = Harness::with_enabled(&fixture, u32::MAX, enabled);
        let opaque = b"malformed optional cursor";
        harness
            .store
            .put(ColumnFamily::UtxoMeta, &[0, b'F'], opaque)
            .expect("seed malformed cursor");
        harness.set_tip(&tip);
        settle_siblings(&harness, at(&tip));
        assert_eq!(
            harness
                .store
                .get(ColumnFamily::UtxoMeta, &[0, b'F'])
                .expect("read cursor"),
            Some(opaque.to_vec()),
            "sibling reconciliation must preserve opaque filter bytes"
        );
        assert!(!harness.runtime.failed.load(Ordering::Acquire));
        assert_eq!(
            harness.runtime.compact_filter_unavailable().is_some(),
            enabled.contains(IndexCapability::CompactFilter)
        );
        let mut pending = None;
        let action = harness
            .worker
            .reconcile_once(&mut pending)
            .expect("settled siblings");
        assert!(matches!(
            action,
            ReconcileAction::CaughtUp | ReconcileAction::Stalled
        ));
        if enabled == IndexCapabilities::HISTORICAL {
            assert!(matches!(action, ReconcileAction::CaughtUp));
            assert!(matches!(
                harness.worker.persist_chain_cursor().expect("cursor"),
                CursorCommit::Settled
            ));
        }
    }
}

#[test]
fn missing_old_filter_body_does_not_starve_new_legacy_blocks() {
    let fixture = ForkFixture::new(3);
    let old_tip = fixture.tip(fixture.a[1]);
    let new_tip = fixture.tip(fixture.a[2]);
    let mut harness = Harness::with_enabled(&fixture, u32::MAX, IndexCapabilities::HISTORICAL);
    harness.set_tip(&old_tip);
    let mut pending = None;
    harness.settle(&mut pending);
    let (genesis_key, genesis_body) = fixture
        .bodies
        .bodies
        .lock()
        .iter()
        .find(|((height, _), _)| *height == 0)
        .map(|(key, body)| (*key, body.clone()))
        .expect("genesis body");
    fixture.bodies.bodies.lock().remove(&genesis_key);
    harness.worker.enabled = with_filters();
    harness.set_tip(&new_tip);
    settle_siblings(&harness, at(&new_tip));
    assert!(harness.runtime.compact_filter_unavailable().is_some());
    assert!(harness.watermarks().compact_filter.is_none());
    assert!(!harness.runtime.failed.load(Ordering::Acquire));

    fixture
        .bodies
        .bodies
        .lock()
        .insert(genesis_key, genesis_body);
    harness.runtime.retry_compact_filters();
    harness.settle(&mut pending);
    assert_eq!(harness.watermarks().compact_filter, Some(at(&new_tip)));
    assert!(harness.runtime.compact_filter_unavailable().is_none());
}

#[test]
fn missing_filter_body_preserves_committed_records_before_retry() {
    use bitcoin_rs_storage::{ColumnFamily, KvStore};

    let fixture = ForkFixture::new(3);
    let first_tip = fixture.tip(fixture.a[0]);
    let second_tip = fixture.tip(fixture.a[1]);
    let new_tip = fixture.tip(fixture.a[2]);
    let mut harness = Harness::with_enabled(&fixture, u32::MAX, IndexCapabilities::HISTORICAL);
    harness.set_tip(&first_tip);
    let mut pending = None;
    harness.settle(&mut pending);
    // The coinbase-only fixture has no undo store. Backfill filters in their
    // own leg instead of depending on the production quiet-wait retry loop.
    harness.worker.enabled = with_filters();
    harness.settle(&mut pending);
    let first_mark = at(&first_tip);
    let keys: Vec<Vec<u8>> = [0, 1]
        .into_iter()
        .map(|part| {
            let mut key = vec![b'F', part];
            key.extend_from_slice(&first_mark.height.to_be_bytes());
            key.extend_from_slice(&first_mark.hash);
            key
        })
        .collect();
    let records: Vec<_> = keys
        .iter()
        .map(|key| {
            harness
                .store
                .get(ColumnFamily::UtxoMeta, key)
                .expect("filter component")
        })
        .collect();
    assert!(records.iter().all(Option::is_some));
    harness.worker.enabled = IndexCapabilities::HISTORICAL;
    harness.set_tip(&second_tip);
    harness.settle(&mut pending);
    let missing_key = (second_tip.height, second_tip.hash.to_le_bytes());
    let missing_body = fixture
        .bodies
        .bodies
        .lock()
        .remove(&missing_key)
        .expect("second body");
    harness.worker.enabled = with_filters();
    harness.set_tip(&new_tip);
    settle_siblings(&harness, at(&new_tip));
    assert_eq!(harness.watermarks().compact_filter, Some(first_mark));
    assert!(harness.runtime.compact_filter_unavailable().is_some());
    for (key, record) in keys.iter().zip(&records) {
        assert_eq!(
            &harness
                .store
                .get(ColumnFamily::UtxoMeta, key)
                .expect("preserved component"),
            record
        );
    }
    fixture
        .bodies
        .bodies
        .lock()
        .insert(missing_key, missing_body);
    harness.runtime.retry_compact_filters();
    harness.settle(&mut pending);
    assert_eq!(harness.watermarks().compact_filter, Some(at(&new_tip)));
    for (key, record) in keys.iter().zip(&records) {
        assert_eq!(
            &harness
                .store
                .get(ColumnFamily::UtxoMeta, key)
                .expect("immutable component"),
            record
        );
    }
}

#[test]
fn formerly_pruned_history_never_fabricates_a_filter_prefix() {
    use bitcoin_rs_storage::pruning::{
        ExecutedFrontier, HistoryAccess, RetentionBudget, RetentionRegistry,
    };
    use bitcoin_rs_storage::{ColumnFamily, KvStore};

    let fixture = ForkFixture::new(3);
    let old_tip = fixture.tip(fixture.a[1]);
    let new_tip = fixture.tip(fixture.a[2]);
    let mut harness = Harness::with_enabled(&fixture, u32::MAX, IndexCapabilities::HISTORICAL);
    harness.set_tip(&old_tip);
    let mut pending = None;
    harness.settle(&mut pending);
    // Models reopening a previously pruned datadir with pruning now disabled.
    harness.worker.history = HistoryAccess::new(
        Arc::new(RetentionRegistry::seeded(ExecutedFrontier::new(2))),
        RetentionBudget::Unlimited,
    );
    harness.worker.enabled = with_filters();
    harness.set_tip(&new_tip);
    settle_siblings(&harness, at(&new_tip));
    assert!(harness.watermarks().compact_filter.is_none());
    assert!(
        harness
            .store
            .iter_prefix(ColumnFamily::UtxoMeta, b"F")
            .expect("filter rows")
            .next()
            .is_none()
    );
    assert!(
        harness
            .store
            .get(ColumnFamily::UtxoMeta, &[0, b'F'])
            .expect("filter cursor")
            .is_none()
    );
    assert!(!harness.runtime.failed.load(Ordering::Acquire));
    assert!(harness.runtime.compact_filter_unavailable().is_some());
    harness.runtime.retry_compact_filters();
    assert!(harness.runtime.compact_filter_unavailable().is_some());
}
