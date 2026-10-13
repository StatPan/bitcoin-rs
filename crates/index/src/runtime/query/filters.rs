//! Stop-anchored immutable filter reads; storage and runtime state never escape.

use core::ops::ControlFlow;

use bitcoin_rs_chain::{BlockTree, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::{BlockHash, encode::double_sha256};

use super::DerivedIndexQueryEngine;
use crate::query_api::{CompactFilterQuery, DerivedIndexInfo, FilterHashRange, FilterQueryError};
use crate::runtime::DerivedIndexQueryAdapter;
use crate::{
    CompactFilterMetadata, CompactFilterRecord, IndexCapability, IndexError, IndexWatermark,
    TxIndexSnapshot, TxQueryError,
};

const MAX_FILTERS: usize = 1_000;
const MAX_FILTER_HASHES: usize = 2_000;
const CHECKPOINT_INTERVAL: u32 = 1_000;
// Conservative bound already used for serialized block inputs. This is a
// per-record bound, never the historical-query cumulative byte cutoff.
const MAX_FILTER_BYTES: usize = 4_000_000;
const MAX_ANCESTRY_HOPS: usize = 1_000_000;
const MAX_CHECKPOINT_PLAN_BYTES: usize = 64 << 20;
const MAX_CHECKPOINT_REPLY_BYTES: usize = 32 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
struct FilterIdentity {
    block: IndexWatermark,
    parent_hash: [u8; 32],
}

struct FilterRead<'a> {
    engine: &'a DerivedIndexQueryEngine,
    snapshot: &'a dyn TxIndexSnapshot,
    tip: &'a TipSnapshot,
    revision: u64,
    watermark: Option<IndexWatermark>,
}

fn store_error(error: IndexError) -> FilterQueryError {
    match error {
        IndexError::Storage(error) => FilterQueryError::Storage(error.to_string().into()),
        other => FilterQueryError::Corrupt(other.to_string().into()),
    }
}

fn engine_error(error: TxQueryError) -> FilterQueryError {
    match error {
        TxQueryError::Retry => FilterQueryError::Retry,
        TxQueryError::Unavailable(reason) => FilterQueryError::Unavailable(reason),
        TxQueryError::Storage(reason) => FilterQueryError::Storage(reason),
    }
}

fn corrupt(reason: &'static str) -> FilterQueryError {
    FilterQueryError::Corrupt(reason.into())
}

fn ancestry_budget() -> FilterQueryError {
    FilterQueryError::Unavailable("compact filter ancestry budget exceeded".into())
}

fn chained_header(hash: [u8; 32], previous: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&hash);
    bytes[32..].copy_from_slice(&previous);
    double_sha256(&bytes).to_le_bytes()
}

fn identity(tree: &BlockTree, id: NodeId) -> Result<FilterIdentity, FilterQueryError> {
    let node = tree.node(id).map_err(|_| FilterQueryError::Retry)?;
    if node.status == NodeStatus::Invalid {
        return Err(FilterQueryError::NotConnected);
    }
    let parent_hash = node.header.prev_blockhash.0.to_le_bytes();
    if node.height == 0 {
        if node.parent.is_some() || parent_hash != [0; 32] {
            return Err(corrupt("invalid genesis identity"));
        }
    } else {
        let parent = tree
            .node(node.parent.ok_or_else(|| corrupt("missing block parent"))?)
            .map_err(|_| corrupt("missing block parent"))?;
        if parent.height.checked_add(1) != Some(node.height)
            || parent.hash.to_le_bytes() != parent_hash
        {
            return Err(corrupt("inconsistent block ancestry"));
        }
    }
    Ok(FilterIdentity {
        block: IndexWatermark {
            height: node.height,
            hash: node.hash.to_le_bytes(),
        },
        parent_hash,
    })
}

impl DerivedIndexQueryEngine {
    fn filter_health(&self) -> Result<(), FilterQueryError> {
        if !self.enabled.contains(IndexCapability::CompactFilter) {
            return Err(FilterQueryError::Disabled);
        }
        self.query_health().map_err(engine_error)?;
        if let Some(reason) = self.runtime.compact_filter_unavailable() {
            return Err(FilterQueryError::Unavailable(reason));
        }
        Ok(())
    }

    fn filter_current(&self, tip: &TipSnapshot, revision: u64) -> Result<(), FilterQueryError> {
        self.filter_health()?;
        if self.runtime.revision() != revision
            || self
                .applied_tip
                .load_full()
                .as_ref()
                .is_none_or(|current| current.height != tip.height || current.hash != tip.hash)
        {
            return Err(FilterQueryError::Retry);
        }
        Ok(())
    }

    fn with_filter_snapshot<T>(
        &self,
        read: impl FnOnce(&FilterRead<'_>) -> Result<T, FilterQueryError>,
    ) -> Result<T, FilterQueryError> {
        self.filter_health()?;
        let tip = self
            .applied_tip
            .load_full()
            .ok_or(FilterQueryError::Indexing)?;
        let revision = self.runtime.revision();
        let snapshot = self.reader.snapshot().map_err(store_error)?;
        let watermark = snapshot
            .capability_watermark(IndexCapability::CompactFilter)
            .map_err(store_error)?;
        let view = FilterRead {
            engine: self,
            snapshot: snapshot.as_ref(),
            tip: &tip,
            revision,
            watermark,
        };
        self.filter_current(&tip, revision)?;
        let result = read(&view);
        self.filter_current(&tip, revision)?;
        result
    }
}

impl FilterRead<'_> {
    fn synced(&self) -> bool {
        self.watermark
            == Some(IndexWatermark {
                height: self.tip.height,
                hash: self.tip.hash.to_le_bytes(),
            })
    }

    fn current(&self) -> Result<(), FilterQueryError> {
        self.engine.filter_current(self.tip, self.revision)
    }

    fn missing(&self) -> FilterQueryError {
        if self.synced() {
            corrupt("expected filter record is missing")
        } else {
            FilterQueryError::Indexing
        }
    }

    fn block(&self, hash: BlockHash) -> Result<FilterIdentity, FilterQueryError> {
        let tree = self.engine.block_tree.read();
        let id = tree
            .lookup(hash.into())
            .ok_or(FilterQueryError::UnknownBlock)?;
        let node = tree.node(id).map_err(|_| FilterQueryError::UnknownBlock)?;
        let mut remaining = MAX_ANCESTRY_HOPS;
        let on_applied = node.height <= self.tip.height
            && tree
                .node_at_height_from_bounded(self.tip.tip_id, node.height, &mut remaining)
                .map_err(|_| ancestry_budget())?
                == Some(id);
        if !on_applied && node.chain_tx_count.get().is_none() {
            return Err(FilterQueryError::NotConnected);
        }
        identity(&tree, id)
    }

    /// Invalidation of a stale branch need not move the applied tip or wake
    /// the index. Revalidate the captured identity without choosing a new chain.
    fn revalidate_block(&self, block: FilterIdentity) -> Result<(), FilterQueryError> {
        self.current()?;
        let tree = self.engine.block_tree.read();
        let id = tree
            .lookup(bitcoin_rs_primitives::Hash256::from_le_bytes(
                &block.block.hash,
            ))
            .ok_or(FilterQueryError::Retry)?;
        if identity(&tree, id)? != block {
            return Err(FilterQueryError::Retry);
        }
        Ok(())
    }

    fn metadata(&self, block: FilterIdentity) -> Result<CompactFilterMetadata, FilterQueryError> {
        self.current()?;
        let record = self
            .snapshot
            .compact_filter_metadata(block.block)
            .map_err(store_error)?
            .ok_or_else(|| self.missing())?;
        if record.block != block.block || record.parent_hash != block.parent_hash {
            return Err(corrupt("filter metadata does not match block identity"));
        }
        Ok(record)
    }

    fn previous_header(&self, block: FilterIdentity) -> Result<[u8; 32], FilterQueryError> {
        let Some(height) = block.block.height.checked_sub(1) else {
            return Ok([0; 32]);
        };
        let parent = self
            .snapshot
            .compact_filter_metadata(IndexWatermark {
                height,
                hash: block.parent_hash,
            })
            .map_err(store_error)?
            .ok_or_else(|| self.missing())?;
        if parent.block
            != (IndexWatermark {
                height,
                hash: block.parent_hash,
            })
        {
            return Err(corrupt("filter parent metadata identity mismatch"));
        }
        if height == 0
            && (parent.parent_hash != [0; 32]
                || parent.filter_header != chained_header(parent.filter_hash, [0; 32]))
        {
            return Err(corrupt("invalid genesis filter header"));
        }
        Ok(parent.filter_header)
    }

    fn checked_metadata(
        &self,
        block: FilterIdentity,
    ) -> Result<CompactFilterMetadata, FilterQueryError> {
        let metadata = self.metadata(block)?;
        let previous = self.previous_header(block)?;
        if metadata.filter_header != chained_header(metadata.filter_hash, previous) {
            return Err(corrupt("filter header does not match its predecessor"));
        }
        Ok(metadata)
    }

    fn full_record(&self, block: FilterIdentity) -> Result<CompactFilterRecord, FilterQueryError> {
        let metadata = self.checked_metadata(block)?;
        self.revalidate_block(block)?;
        let record = self
            .snapshot
            .compact_filter(block.block)
            .map_err(store_error)?
            .ok_or_else(|| self.missing())?;
        if record.block != metadata.block
            || record.parent_hash != metadata.parent_hash
            || record.filter_hash != metadata.filter_hash
            || record.filter_header != metadata.filter_header
            || record.filter.is_empty()
            || record.filter.len() > MAX_FILTER_BYTES
        {
            return Err(corrupt("filter bytes or metadata are inconsistent"));
        }
        self.revalidate_block(block)?;
        Ok(record)
    }

    fn require_ready(&self) -> Result<(), FilterQueryError> {
        if !self.synced() {
            return Err(FilterQueryError::Indexing);
        }
        let tip = self.block(BlockHash::from(self.tip.hash))?;
        self.checked_metadata(tip)?;
        Ok(())
    }

    fn range(
        &self,
        start: u32,
        stop: BlockHash,
        limit: usize,
    ) -> Result<Vec<FilterIdentity>, FilterQueryError> {
        let last = self.block(stop)?;
        let count = last
            .block
            .height
            .checked_sub(start)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(FilterQueryError::InvalidRange)?;
        if count > limit {
            return Err(FilterQueryError::InvalidRange);
        }
        let tree = self.engine.block_tree.read();
        let mut cursor = tree.lookup(stop.into()).ok_or(FilterQueryError::Retry)?;
        let mut plan = Vec::with_capacity(count);
        for offset in 0..count {
            let block = identity(&tree, cursor)?;
            let expected = last
                .block
                .height
                .checked_sub(u32::try_from(offset).map_err(|_| FilterQueryError::InvalidRange)?)
                .ok_or(FilterQueryError::InvalidRange)?;
            if block.block.height != expected {
                return Err(corrupt("noncontiguous filter range"));
            }
            plan.push(block);
            if offset + 1 < count {
                cursor = tree
                    .node(cursor)
                    .map_err(|_| FilterQueryError::Retry)?
                    .parent
                    .ok_or_else(|| corrupt("missing filter range ancestor"))?;
            }
        }
        plan.reverse();
        Ok(plan)
    }

    fn checkpoints(&self, stop: BlockHash) -> Result<Vec<FilterIdentity>, FilterQueryError> {
        let last = self.block(stop)?;
        let count = usize::try_from(last.block.height / CHECKPOINT_INTERVAL)
            .map_err(|_| ancestry_budget())?;
        let retained_size = core::mem::size_of::<FilterIdentity>() + 32;
        if count
            .checked_mul(retained_size)
            .is_none_or(|bytes| bytes > MAX_CHECKPOINT_PLAN_BYTES)
            || count
                .checked_mul(32)
                .and_then(|bytes| bytes.checked_add(42))
                .is_none_or(|bytes| bytes > MAX_CHECKPOINT_REPLY_BYTES)
        {
            return Err(FilterQueryError::Unavailable(
                "compact filter checkpoint response budget exceeded".into(),
            ));
        }
        let tree = self.engine.block_tree.read();
        let mut cursor = tree.lookup(stop.into()).ok_or(FilterQueryError::Retry)?;
        let mut remaining = MAX_ANCESTRY_HOPS;
        let mut plan = Vec::with_capacity(count);
        for index in (1..=count).rev() {
            let height = u32::try_from(index)
                .ok()
                .and_then(|n| n.checked_mul(CHECKPOINT_INTERVAL))
                .ok_or_else(ancestry_budget)?;
            cursor = tree
                .node_at_height_from_bounded(cursor, height, &mut remaining)
                .map_err(|_| ancestry_budget())?
                .ok_or_else(|| corrupt("missing checkpoint ancestor"))?;
            plan.push(identity(&tree, cursor)?);
        }
        plan.reverse();
        Ok(plan)
    }
}

impl CompactFilterQuery for DerivedIndexQueryEngine {
    fn filter_index_info(&self) -> Result<DerivedIndexInfo, FilterQueryError> {
        self.with_filter_snapshot(|view| {
            let synced = view.synced();
            if synced {
                view.full_record(view.block(BlockHash::from(view.tip.hash))?)?;
            }
            Ok(DerivedIndexInfo {
                synced,
                best_block_height: view.watermark.map_or(0, |mark| mark.height),
            })
        })
    }

    fn filter(&self, block: BlockHash) -> Result<CompactFilterRecord, FilterQueryError> {
        self.with_filter_snapshot(|view| view.full_record(view.block(block)?))
    }

    fn filter_hashes(
        &self,
        start: u32,
        stop: BlockHash,
    ) -> Result<FilterHashRange, FilterQueryError> {
        self.with_filter_snapshot(|view| {
            view.require_ready()?;
            let plan = view.range(start, stop, MAX_FILTER_HASHES)?;
            let first = *plan.first().ok_or(FilterQueryError::InvalidRange)?;
            let last = *plan.last().ok_or(FilterQueryError::InvalidRange)?;
            let previous_header = view.previous_header(first)?;
            let mut previous = previous_header;
            let mut hashes = Vec::with_capacity(plan.len());
            for block in plan {
                let metadata = view.metadata(block)?;
                if metadata.filter_header != chained_header(metadata.filter_hash, previous) {
                    return Err(corrupt("filter range header linkage mismatch"));
                }
                previous = metadata.filter_header;
                hashes.push(metadata.filter_hash);
            }
            view.revalidate_block(last)?;
            Ok(FilterHashRange {
                previous_header,
                hashes,
            })
        })
    }

    fn checkpoint_headers(&self, stop: BlockHash) -> Result<Vec<[u8; 32]>, FilterQueryError> {
        self.with_filter_snapshot(|view| {
            view.require_ready()?;
            let last = view.block(stop)?;
            let headers = view
                .checkpoints(stop)?
                .into_iter()
                .map(|block| {
                    view.checked_metadata(block)
                        .map(|metadata| metadata.filter_header)
                })
                .collect::<Result<Vec<_>, _>>()?;
            view.revalidate_block(last)?;
            Ok(headers)
        })
    }

    fn stream_filters(
        &self,
        start: u32,
        stop: BlockHash,
        headroom: &dyn Fn() -> bool,
        emit: &mut dyn FnMut(CompactFilterRecord) -> ControlFlow<()>,
    ) -> Result<ControlFlow<()>, FilterQueryError> {
        self.with_filter_snapshot(|view| {
            view.require_ready()?;
            let plan = view.range(start, stop, MAX_FILTERS)?;
            let last = *plan.last().ok_or(FilterQueryError::InvalidRange)?;
            for block in plan {
                view.revalidate_block(last)?;
                if !headroom() {
                    return Ok(ControlFlow::Break(()));
                }
                let record = view.full_record(block)?;
                view.revalidate_block(last)?;
                if emit(record).is_break() {
                    return Ok(ControlFlow::Break(()));
                }
            }
            view.revalidate_block(last)?;
            Ok(ControlFlow::Continue(()))
        })
    }
}

impl CompactFilterQuery for DerivedIndexQueryAdapter {
    fn filter_index_info(&self) -> Result<DerivedIndexInfo, FilterQueryError> {
        self.load_engine()
            .map_err(engine_error)?
            .filter_index_info()
    }
    fn filter(&self, block: BlockHash) -> Result<CompactFilterRecord, FilterQueryError> {
        self.load_engine().map_err(engine_error)?.filter(block)
    }
    fn filter_hashes(
        &self,
        start: u32,
        stop: BlockHash,
    ) -> Result<FilterHashRange, FilterQueryError> {
        self.load_engine()
            .map_err(engine_error)?
            .filter_hashes(start, stop)
    }
    fn checkpoint_headers(&self, stop: BlockHash) -> Result<Vec<[u8; 32]>, FilterQueryError> {
        self.load_engine()
            .map_err(engine_error)?
            .checkpoint_headers(stop)
    }
    fn stream_filters(
        &self,
        start: u32,
        stop: BlockHash,
        headroom: &dyn Fn() -> bool,
        emit: &mut dyn FnMut(CompactFilterRecord) -> ControlFlow<()>,
    ) -> Result<ControlFlow<()>, FilterQueryError> {
        self.load_engine()
            .map_err(engine_error)?
            .stream_filters(start, stop, headroom, emit)
    }
}
