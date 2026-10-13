//! BIP157 request policy. The index owns identity, readiness and filter contents;
//! P2P owns request limits, stale-block eligibility and bounded response delivery.

use core::ops::ControlFlow;

use bitcoin::bip158::{FilterHash, FilterHeader};
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::message_filter::{CFCheckpt, CFHeaders, CFilter};
use bitcoin_rs_index::query_api::CompactFilterQuery;
use bitcoin_rs_primitives::{BlockHash, Hash256};

use crate::dispatch::ChainQuery;
use crate::{Message, PeerError};

const BASIC_FILTER: u8 = 0;
const MAX_FILTERS: u32 = 1_000;
const MAX_FILTER_HASHES: u32 = 2_000;
const CHECKPOINT_INTERVAL: u32 = 1_000;

/// Never advertise a configured bit without the index's current readiness proof.
/// Neither base service flags nor a previous successful query establish readiness.
pub(crate) fn local_services(
    base: ServiceFlags,
    filters: Option<&dyn CompactFilterQuery>,
) -> ServiceFlags {
    let base = ServiceFlags::from(base.to_u64() & !ServiceFlags::COMPACT_FILTERS.to_u64());
    if filters.is_some_and(|filters| filters.filter_index_info().is_ok_and(|info| info.synced)) {
        base | ServiceFlags::COMPACT_FILTERS
    } else {
        base
    }
}

/// Disabled serving preserves the native ignore policy (a deliberate deviation
/// from Core's disabled-service disconnect). Enabled invalid requests follow
/// Core 31.1 `PrepareBlockFilterRequest`: disconnect without discouragement.
/// Every query rechecks readiness; an index failure never fabricates a reply.
pub(crate) fn serve(
    message: &Message,
    chain: Option<&dyn ChainQuery>,
    filters: Option<&dyn CompactFilterQuery>,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    let Some(filters) = filters else {
        return Ok(());
    };
    let (filter_type, start, stop, limit) = match message {
        Message::GetCFilters(request) => (
            request.filter_type,
            request.start_height,
            request.stop_hash,
            MAX_FILTERS,
        ),
        Message::GetCFHeaders(request) => (
            request.filter_type,
            request.start_height,
            request.stop_hash,
            MAX_FILTER_HASHES,
        ),
        Message::GetCFCheckpt(request) => (request.filter_type, 0, request.stop_hash, u32::MAX),
        _ => return Ok(()),
    };
    if filter_type != BASIC_FILTER {
        return Err(PeerError::Protocol("unsupported compact filter type"));
    }
    let Some(chain) = chain else {
        return Ok(());
    };
    let native_stop = BlockHash::from(Hash256::from_le_bytes(stop.as_byte_array()));
    let stop_height = chain
        .filter_stop_height(native_stop)
        .ok_or(PeerError::Protocol("ineligible compact filter stop block"))?;
    let count = if matches!(message, Message::GetCFCheckpt(_)) {
        0 // Checkpoints have no start-height range; their budget belongs to index.
    } else {
        stop_height
            .checked_sub(start)
            .filter(|difference| *difference < limit)
            .and_then(|difference| difference.checked_add(1))
            .ok_or(PeerError::Protocol("invalid compact filter range"))?
    };
    match message {
        Message::GetCFilters(_) => stream_filters(
            filters,
            chain,
            start,
            native_stop,
            stop_height,
            headroom,
            send,
        ),
        Message::GetCFHeaders(_) => {
            let Ok(range) = filters.filter_hashes(start, native_stop) else {
                return Ok(());
            };
            if u32::try_from(range.hashes.len()) != Ok(count)
                || (start == 0 && range.previous_header != [0; 32])
                || chain.filter_stop_height(native_stop) != Some(stop_height)
            {
                return Err(PeerError::Protocol(
                    "incomplete compact filter hash response",
                ));
            }
            send(Message::CFHeaders(CFHeaders {
                filter_type: BASIC_FILTER,
                stop_hash: stop,
                previous_filter_header: FilterHeader::from_byte_array(range.previous_header),
                filter_hashes: range
                    .hashes
                    .into_iter()
                    .map(FilterHash::from_byte_array)
                    .collect(),
            }))
        }
        Message::GetCFCheckpt(_) => {
            let Ok(headers) = filters.checkpoint_headers(native_stop) else {
                return Ok(());
            };
            if u32::try_from(headers.len()) != Ok(stop_height / CHECKPOINT_INTERVAL)
                || chain.filter_stop_height(native_stop) != Some(stop_height)
            {
                return Err(PeerError::Protocol(
                    "incomplete compact filter checkpoint response",
                ));
            }
            send(Message::CFCheckpt(CFCheckpt {
                filter_type: BASIC_FILTER,
                stop_hash: stop,
                filter_headers: headers
                    .into_iter()
                    .map(FilterHeader::from_byte_array)
                    .collect(),
            }))
        }
        _ => Ok(()),
    }
}

fn stream_filters(
    filters: &dyn CompactFilterQuery,
    chain: &dyn ChainQuery,
    start: u32,
    stop: BlockHash,
    stop_height: u32,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    let mut next_height = u64::from(start);
    let mut previous_hash = None;
    let mut send_error = None;
    let result = filters.stream_filters(start, stop, headroom, &mut |record| {
        // The provider promises ordered exact identities. Fail closed rather
        // than complete a truncated or misaddressed response if it breaks that
        // contract. Recheck stop eligibility after each unlocked blob read.
        if u64::from(record.block.height) != next_height
            || record.block.height > stop_height
            || previous_hash.is_some_and(|previous| record.parent_hash != previous)
            || (record.block.height == stop_height && record.block.hash != *stop.as_bytes())
            || chain.filter_stop_height(stop) != Some(stop_height)
        {
            send_error = Some(PeerError::Protocol("inconsistent compact filter stream"));
            return ControlFlow::Break(());
        }
        previous_hash = Some(record.block.hash);
        if let Err(error) = send(Message::CFilter(CFilter {
            filter_type: BASIC_FILTER,
            block_hash: bitcoin::BlockHash::from_byte_array(record.block.hash),
            filter: record.filter,
        })) {
            send_error = Some(error);
            return ControlFlow::Break(());
        }
        next_height += 1;
        ControlFlow::Continue(())
    });
    if let Some(error) = send_error {
        return Err(error);
    }
    match result {
        Ok(ControlFlow::Continue(())) if next_height == u64::from(stop_height) + 1 => Ok(()),
        // Core leaves a wholly unavailable request unanswered. Once anything
        // was emitted, close the connection so a missing suffix cannot look
        // like a successful response. Queue saturation always closes, too.
        Err(_) if next_height == u64::from(start) => Ok(()),
        _ => Err(PeerError::Protocol("compact filter stream interrupted")),
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "failed test fixture or assertion")]
pub(crate) mod tests;
