use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bitcoin::bip152::BlockTransactionsRequest;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_filter::{GetCFCheckpt, GetCFHeaders, GetCFilters};
use bitcoin_rs_index::query_api::{DerivedIndexInfo, FilterHashRange, FilterQueryError};
use bitcoin_rs_index::{CompactFilterRecord, IndexWatermark};
use bitcoin_rs_primitives::Header;

use super::*;
use crate::connection::OutboundBudget;
use crate::dispatch::{InventoryServing, dispatch_inbound_full};
use crate::test_support::TestResult;
use crate::{Peer, PeerLease, PeerState};

fn block_hash(height: u32) -> [u8; 32] {
    let mut hash = [0; 32];
    hash[..4].copy_from_slice(&height.to_le_bytes());
    hash[4] = 1;
    hash
}

fn wire_hash(height: u32) -> bitcoin::BlockHash {
    bitcoin::BlockHash::from_byte_array(block_hash(height))
}

pub(crate) struct Filters {
    pub(crate) synced: AtomicBool,
    pub(crate) failed: AtomicBool,
    loads: AtomicUsize,
    truncate: bool,
    fail_after: Option<u32>,
}

impl Default for Filters {
    fn default() -> Self {
        Self {
            synced: AtomicBool::new(true),
            failed: AtomicBool::new(false),
            loads: AtomicUsize::new(0),
            truncate: false,
            fail_after: None,
        }
    }
}

impl Filters {
    fn ready(&self) -> Result<(), FilterQueryError> {
        if self.failed.load(Ordering::Relaxed) {
            return Err(FilterQueryError::Storage("test failure".into()));
        }
        if self.synced.load(Ordering::Relaxed) {
            Ok(())
        } else {
            Err(FilterQueryError::Indexing)
        }
    }
}

impl CompactFilterQuery for Filters {
    fn filter_index_info(&self) -> Result<DerivedIndexInfo, FilterQueryError> {
        if self.failed.load(Ordering::Relaxed) {
            return Err(FilterQueryError::Storage("test failure".into()));
        }
        Ok(DerivedIndexInfo {
            synced: self.synced.load(Ordering::Relaxed),
            best_block_height: 2_000,
        })
    }

    fn filter(&self, _: BlockHash) -> Result<CompactFilterRecord, FilterQueryError> {
        panic!("P2P ranges must use the streaming query")
    }

    fn filter_hashes(
        &self,
        start: u32,
        stop: BlockHash,
    ) -> Result<FilterHashRange, FilterQueryError> {
        self.ready()?;
        let stop = height(stop);
        let hashes = (start..=stop).map(block_hash).collect::<Vec<_>>();
        Ok(FilterHashRange {
            previous_header: if start == 0 {
                [0; 32]
            } else {
                block_hash(start - 1)
            },
            hashes: if self.truncate { Vec::new() } else { hashes },
        })
    }

    fn checkpoint_headers(&self, stop: BlockHash) -> Result<Vec<[u8; 32]>, FilterQueryError> {
        self.ready()?;
        Ok((1..=height(stop) / 1_000)
            .map(|n| block_hash(n * 1_000))
            .collect())
    }

    fn stream_filters(
        &self,
        start: u32,
        stop: BlockHash,
        headroom: &dyn Fn() -> bool,
        emit: &mut dyn FnMut(CompactFilterRecord) -> ControlFlow<()>,
    ) -> Result<ControlFlow<()>, FilterQueryError> {
        self.ready()?;
        for height in start..=height(stop) {
            if self.fail_after == Some(height) {
                return Err(FilterQueryError::Storage("test failure".into()));
            }
            if !headroom() {
                return Ok(ControlFlow::Break(()));
            }
            self.loads.fetch_add(1, Ordering::Relaxed);
            if self.truncate {
                break;
            }
            if emit(CompactFilterRecord {
                block: IndexWatermark {
                    height,
                    hash: block_hash(height),
                },
                parent_hash: height.checked_sub(1).map_or([0; 32], block_hash),
                filter: vec![0],
                filter_hash: block_hash(height),
                filter_header: [7; 32],
            })
            .is_break()
            {
                return Ok(ControlFlow::Break(()));
            }
        }
        Ok(ControlFlow::Continue(()))
    }
}

fn height(hash: BlockHash) -> u32 {
    let bytes = hash.as_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

struct Chain;
impl ChainQuery for Chain {
    fn headers_after(&self, _: &[BlockHash], _: BlockHash, _: usize) -> Vec<Header> {
        Vec::new()
    }
    fn serve_inventory_blocks(
        &self,
        _: &[Inventory],
        _: Option<u64>,
        _: &dyn Fn() -> bool,
        _: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError> {
        Ok(InventoryServing::default())
    }
    fn block_transactions(
        &self,
        _: &BlockTransactionsRequest,
        _: Option<u64>,
        _: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError> {
        Ok(None)
    }
    fn filter_stop_height(&self, hash: BlockHash) -> Option<u32> {
        (hash.as_bytes()[4] == 1).then(|| height(hash))
    }
}

fn request(start: u32, stop: u32) -> Message {
    Message::GetCFilters(GetCFilters {
        filter_type: 0,
        start_height: start,
        stop_hash: wire_hash(stop),
    })
}

fn dispatch(
    message: &Message,
    filters: Option<&dyn CompactFilterQuery>,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
    peer.state = PeerState::Ready;
    dispatch_inbound_full(
        &mut peer,
        message,
        Some(&Chain),
        None,
        filters,
        &|| true,
        headroom,
        send,
        &mut |_| {},
        &mut |_| {},
    )
}

#[test]
fn disabled_and_lagged_filters_stay_silent() -> TestResult {
    let invalid = Message::GetCFilters(GetCFilters {
        filter_type: 255,
        start_height: u32::MAX,
        stop_hash: bitcoin::BlockHash::all_zeros(),
    });
    dispatch(
        &invalid,
        None,
        &|| panic!("disabled request touched headroom"),
        &mut |_| panic!("disabled request answered"),
    )?;
    let filters = Filters::default();
    filters.synced.store(false, Ordering::Relaxed);
    for message in [
        request(0, 1),
        Message::GetCFHeaders(GetCFHeaders {
            filter_type: 0,
            start_height: 0,
            stop_hash: wire_hash(1),
        }),
        Message::GetCFCheckpt(GetCFCheckpt {
            filter_type: 0,
            stop_hash: wire_hash(1),
        }),
    ] {
        dispatch(&message, Some(&filters), &|| true, &mut |_| {
            panic!("lagged request answered")
        })?;
    }
    assert_eq!(filters.loads.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn enabled_invalid_requests_disconnect_without_discouragement() {
    let filters = Filters::default();
    let invalid = [
        Message::GetCFilters(GetCFilters {
            filter_type: 1,
            start_height: 0,
            stop_hash: wire_hash(0),
        }),
        Message::GetCFHeaders(GetCFHeaders {
            filter_type: 1,
            start_height: 0,
            stop_hash: wire_hash(0),
        }),
        Message::GetCFCheckpt(GetCFCheckpt {
            filter_type: 1,
            stop_hash: wire_hash(0),
        }),
        Message::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: 0,
            stop_hash: bitcoin::BlockHash::all_zeros(),
        }),
        request(2, 1),
        request(0, 1_000),
        request(u32::MAX, 1),
        Message::GetCFHeaders(GetCFHeaders {
            filter_type: 0,
            start_height: 0,
            stop_hash: wire_hash(2_000),
        }),
    ];
    for message in invalid {
        let error = dispatch(&message, Some(&filters), &|| true, &mut |_| {
            panic!("invalid reply")
        })
        .expect_err("invalid request accepted");
        assert!(matches!(error, PeerError::Protocol(_)));
        assert!(!error.is_misbehavior());
        assert!(!error.recoverable_for_protected());
    }
    assert_eq!(filters.loads.load(Ordering::Relaxed), 0);
}

#[test]
fn inclusive_limits_and_exact_wire_answers() -> TestResult {
    let filters = Filters::default();
    let mut received = 0;
    dispatch(&request(0, 999), Some(&filters), &|| true, &mut |message| {
        assert_eq!(
            message,
            Message::CFilter(CFilter {
                filter_type: 0,
                block_hash: wire_hash(received),
                filter: vec![0]
            })
        );
        received += 1;
        Ok(())
    })?;
    assert_eq!(received, 1_000);
    assert_eq!(filters.loads.load(Ordering::Relaxed), 1_000);
    for (start, stop) in [(0, 1_999), (17, 17)] {
        dispatch(
            &Message::GetCFHeaders(GetCFHeaders {
                filter_type: 0,
                start_height: start,
                stop_hash: wire_hash(stop),
            }),
            Some(&filters),
            &|| true,
            &mut |message| {
                assert_eq!(
                    message,
                    Message::CFHeaders(CFHeaders {
                        filter_type: 0,
                        stop_hash: wire_hash(stop),
                        previous_filter_header: FilterHeader::from_byte_array(if start == 0 {
                            [0; 32]
                        } else {
                            block_hash(start - 1)
                        }),
                        filter_hashes: (start..=stop)
                            .map(|height| FilterHash::from_byte_array(block_hash(height)))
                            .collect()
                    })
                );
                Ok(())
            },
        )?;
    }
    for stop in [0, 999, 1_000, 1_999, 2_000] {
        dispatch(
            &Message::GetCFCheckpt(GetCFCheckpt {
                filter_type: 0,
                stop_hash: wire_hash(stop),
            }),
            Some(&filters),
            &|| true,
            &mut |message| {
                assert_eq!(
                    message,
                    Message::CFCheckpt(CFCheckpt {
                        filter_type: 0,
                        stop_hash: wire_hash(stop),
                        filter_headers: (1..=stop / 1_000)
                            .map(|n| FilterHeader::from_byte_array(block_hash(n * 1_000)))
                            .collect()
                    })
                );
                Ok(())
            },
        )?;
    }
    Ok(())
}

#[test]
fn headroom_precedes_each_blob_and_partial_failure_closes() {
    let filters = Filters::default();
    let error = dispatch(&request(0, 1), Some(&filters), &|| false, &mut |_| {
        panic!("reply")
    })
    .expect_err("full queue accepted a stream");
    assert!(matches!(error, PeerError::Protocol(_)));
    assert_eq!(filters.loads.load(Ordering::Relaxed), 0);
    let (tx, rx) = crossbeam_channel::unbounded();
    let lease =
        PeerLease::new_with_budget(tx, false, OutboundBudget::with_block_reserve(1, 1_000, 0));
    let budget = lease.budget_handle();
    let error = dispatch(
        &request(0, 1),
        Some(&filters),
        &|| budget.has_filter_production_headroom(),
        &mut |message| {
            lease
                .send(message)
                .map_err(|_| PeerError::Protocol("test queue full"))
        },
    )
    .expect_err("partial stream stayed open");
    assert!(!error.is_misbehavior());
    assert_eq!(filters.loads.load(Ordering::Relaxed), 1);
    assert_eq!(rx.len(), 1);
}

#[test]
fn truncated_and_failed_provider_never_complete_a_partial_response() {
    for filters in [
        Filters {
            truncate: true,
            ..Filters::default()
        },
        Filters {
            fail_after: Some(1),
            ..Filters::default()
        },
    ] {
        let mut sent = 0;
        let error = dispatch(&request(0, 1), Some(&filters), &|| true, &mut |_| {
            sent += 1;
            Ok(())
        })
        .expect_err("incomplete response succeeded");
        assert!(matches!(error, PeerError::Protocol(_)));
        assert!(!error.is_misbehavior());
        assert!(sent <= 1);
    }
    let filters = Filters {
        truncate: true,
        ..Filters::default()
    };
    assert!(
        dispatch(
            &Message::GetCFHeaders(GetCFHeaders {
                filter_type: 0,
                start_height: 0,
                stop_hash: wire_hash(1)
            }),
            Some(&filters),
            &|| true,
            &mut |_| panic!("truncated hashes sent")
        )
        .is_err()
    );
}

#[test]
fn current_readiness_controls_flags_without_disturbing_other_services() {
    let filters = Arc::new(Filters::default());
    let base = ServiceFlags::WITNESS | ServiceFlags::NETWORK_LIMITED | ServiceFlags::P2P_V2;
    assert_eq!(
        local_services(base | ServiceFlags::COMPACT_FILTERS, None),
        base
    );
    let mut shared = crate::listener::test_shared(
        Arc::default(),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    );
    shared.local_services = base;
    shared.compact_filters = Some(filters.clone());
    for (synced, failed) in [(false, false), (true, false), (true, true), (true, false)] {
        filters.synced.store(synced, Ordering::Relaxed);
        filters.failed.store(failed, Ordering::Relaxed);
        assert_eq!(
            shared.advertised_services(),
            if synced && !failed {
                base | ServiceFlags::COMPACT_FILTERS
            } else {
                base
            }
        );
    }
}

#[test]
fn truncated_filter_requests_fail_decoding_before_dispatch() -> TestResult {
    for message in [
        request(0, 1),
        Message::GetCFHeaders(GetCFHeaders {
            filter_type: 0,
            start_height: 0,
            stop_hash: wire_hash(1),
        }),
        Message::GetCFCheckpt(GetCFCheckpt {
            filter_type: 0,
            stop_hash: wire_hash(1),
        }),
    ] {
        let payload = crate::wire::encode_payload(&message)?;
        for end in 0..payload.len() {
            let malformed = Message::Unknown {
                command: message.command(),
                payload: payload[..end].to_vec(),
            };
            let mut bytes = Vec::new();
            crate::wire::write_message(&mut bytes, Magic::REGTEST, &malformed)?;
            assert!(crate::wire::read_message(&mut Cursor::new(bytes), Magic::REGTEST).is_err());
        }
    }
    Ok(())
}
