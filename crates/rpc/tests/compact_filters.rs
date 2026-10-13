//! RPC projection of the optional, typed compact-filter query capability.
// A wrong result is a fixture failure; keep the assertion at the call site.
#![allow(clippy::expect_used)]

use std::ops::ControlFlow;
use std::sync::Arc;

use bitcoin_rs_index::query_api::{CompactFilterQuery, FilterHashRange, FilterQueryError};
use bitcoin_rs_index::{CompactFilterRecord, DerivedIndexInfo, IndexWatermark};
use bitcoin_rs_primitives::{BlockHash, Hash256, OutPoint, Tx, Txid};
use bitcoin_rs_rpc::context::{Context, DerivedIndexQuery, TxQueryError};
use bitcoin_rs_rpc::{Handler, RpcError};
use parking_lot::Mutex;
use sonic_rs::{JsonValueTrait as _, Value, json};

const BASIC_INDEX: &str = "basic block filter index";
const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct FakeFilters {
    record: Result<CompactFilterRecord, FilterQueryError>,
    info: Mutex<Result<DerivedIndexInfo, FilterQueryError>>,
}

impl CompactFilterQuery for FakeFilters {
    fn filter_index_info(&self) -> Result<DerivedIndexInfo, FilterQueryError> {
        self.info.lock().clone()
    }

    fn filter(&self, block: BlockHash) -> Result<CompactFilterRecord, FilterQueryError> {
        if let Ok(record) = &self.record {
            assert_eq!(block.as_bytes(), &record.block.hash);
        }
        self.record.clone()
    }

    fn filter_hashes(&self, _: u32, _: BlockHash) -> Result<FilterHashRange, FilterQueryError> {
        Err(FilterQueryError::Unavailable("unused in RPC".into()))
    }

    fn checkpoint_headers(&self, _: BlockHash) -> Result<Vec<[u8; 32]>, FilterQueryError> {
        Err(FilterQueryError::Unavailable("unused in RPC".into()))
    }

    fn stream_filters(
        &self,
        _: u32,
        _: BlockHash,
        _: &dyn Fn() -> bool,
        _: &mut dyn FnMut(CompactFilterRecord) -> ControlFlow<()>,
    ) -> Result<ControlFlow<()>, FilterQueryError> {
        Err(FilterQueryError::Unavailable("unused in RPC".into()))
    }
}

struct FakeTxIndex;

impl DerivedIndexQuery for FakeTxIndex {
    fn transaction(&self, _: &Txid) -> Result<Option<Tx>, TxQueryError> {
        Ok(None)
    }

    fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        Ok(None)
    }

    fn index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
        Ok(DerivedIndexInfo {
            synced: true,
            best_block_height: 42,
        })
    }
}

fn context(filters: FakeFilters) -> Context {
    let mut context = Context::new();
    context.indexes.compact_filter = Some(Arc::new(filters));
    context
}

fn info(synced: bool) -> DerivedIndexInfo {
    DerivedIndexInfo {
        synced,
        best_block_height: 7,
    }
}

fn failure(error: FilterQueryError) -> FakeFilters {
    FakeFilters {
        record: Err(error.clone()),
        info: Mutex::new(Err(error)),
    }
}

fn assert_error(handler: &Handler, method: &str, params: &Value, code: i64, message: &str) {
    let error = handler.dispatch(method, params).expect_err("must refuse");
    assert_eq!(error.code(), code);
    assert_eq!(error.to_string(), message);
}

#[test]
fn getblockfilter_returns_exact_bytes_and_display_order_header()
-> Result<(), Box<dyn std::error::Error>> {
    let block = IndexWatermark {
        height: 7,
        hash: Hash256::from_str_be(HASH)?.to_le_bytes(),
    };
    let filter_header = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let handler = Handler::new(Arc::new(context(FakeFilters {
        record: Ok(CompactFilterRecord {
            block,
            parent_hash: [0; 32],
            filter: vec![1, 0, 0xab, 0xff, 0x13],
            filter_hash: [0; 32],
            filter_header,
        }),
        // A retained block can be queried while active coverage is catching up.
        info: Mutex::new(Ok(info(false))),
    })));
    let expected = json!({
        "filter": "0100abff13",
        "header": "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
    });
    for params in [
        json!([HASH]),
        json!([HASH, "basic"]),
        json!([HASH, null]),
        json!({"blockhash": HASH}),
        json!({"blockhash": HASH, "filtertype": "basic"}),
        json!({"args": [HASH], "filtertype": "basic"}),
        json!([HASH.to_uppercase()]),
    ] {
        assert_eq!(handler.dispatch("getblockfilter", &params)?, expected);
    }
    Ok(())
}

#[test]
fn disabled_filter_index_is_explicit_and_unknown_type_precedes_it() {
    let handler = Handler::new(Arc::new(Context::new()));
    assert_error(
        &handler,
        "getblockfilter",
        &json!([HASH]),
        -1,
        "Index is not enabled for filtertype basic",
    );
    assert_error(
        &handler,
        "getblockfilter",
        &json!([HASH, "unknown"]),
        -5,
        "Unknown filtertype",
    );
}

#[test]
fn getblockfilter_projects_typed_failures_without_fabricating_results() {
    let cases = [
        (
            FilterQueryError::Disabled,
            -1,
            "Index is not enabled for filtertype basic",
        ),
        (FilterQueryError::UnknownBlock, -5, "Block not found"),
        (
            FilterQueryError::NotConnected,
            -5,
            "Filter not found. Block was not connected to active chain.",
        ),
        (
            FilterQueryError::Indexing,
            -1,
            "Filter not found. Block filters are still in the process of being indexed.",
        ),
        (
            FilterQueryError::Retry,
            -1,
            "compact filter query changed; retry",
        ),
        (
            FilterQueryError::Unavailable("stopped".into()),
            -1,
            "compact filter index unavailable: stopped",
        ),
        (
            FilterQueryError::Corrupt("bad header".into()),
            -32_603,
            "internal error: compact filter index corrupt: bad header",
        ),
        (
            FilterQueryError::Storage("read failed".into()),
            -32_603,
            "internal error: compact filter storage error: read failed",
        ),
    ];
    for (error, code, message) in cases {
        let handler = Handler::new(Arc::new(context(failure(error))));
        assert_error(&handler, "getblockfilter", &json!([HASH]), code, message);
    }
}

#[test]
fn getblockfilter_validates_named_arguments_types_and_hashes() {
    let handler = Handler::new(Arc::new(Context::new()));
    for (params, code) in [
        (json!([]), -32_602),
        (json!([HASH, "basic", 1]), -32_602),
        (json!([false]), -3),
        (json!([HASH, false]), -3),
        (json!({"filtertype": "basic"}), -3),
        (json!(["bad"]), -8),
        (json!(["g".repeat(64)]), -8),
        (json!({"blockhash": HASH, "other": true}), -8),
        (json!({"args": [HASH], "blockhash": HASH}), -8),
    ] {
        let error = handler
            .dispatch("getblockfilter", &params)
            .expect_err("invalid input");
        assert_eq!(error.code(), code, "{params:?}: {error}");
    }
}

#[test]
fn getindexinfo_reports_configured_filter_progress_and_preserves_txindex()
-> Result<(), Box<dyn std::error::Error>> {
    for synced in [false, true] {
        let mut context = context(FakeFilters {
            record: Err(FilterQueryError::UnknownBlock),
            info: Mutex::new(Ok(info(synced))),
        });
        context.indexes.derived_index = Some(Arc::new(FakeTxIndex));
        let handler = Handler::new(Arc::new(context));
        let expected = json!({
            "basic block filter index": {"synced": synced, "best_block_height": 7},
            "txindex": {"synced": true, "best_block_height": 42},
        });
        for params in [
            json!([]),
            json!(null),
            json!([null]),
            json!({}),
            json!([""]),
            json!({"index_name": ""}),
        ] {
            assert_eq!(handler.dispatch("getindexinfo", &params)?, expected);
        }
        for params in [json!([BASIC_INDEX]), json!({"index_name": BASIC_INDEX})] {
            assert_eq!(
                handler.dispatch("getindexinfo", &params)?,
                json!({
                    "basic block filter index": {"synced": synced, "best_block_height": 7},
                })
            );
        }
        assert_eq!(
            handler.dispatch("getindexinfo", &json!(["txindex"]))?,
            json!({
                "txindex": {"synced": true, "best_block_height": 42},
            })
        );
        for name in ["unknown", "basic", "basic block filter"] {
            assert_eq!(handler.dispatch("getindexinfo", &json!([name]))?, json!({}));
        }
    }
    Ok(())
}

#[test]
fn getindexinfo_omits_disabled_filter_index() -> Result<(), RpcError> {
    let handler = Handler::new(Arc::new(Context::new()));
    assert_eq!(handler.dispatch("getindexinfo", &json!([]))?, json!({}));
    assert_eq!(
        handler.dispatch("getindexinfo", &json!([BASIC_INDEX]))?,
        json!({})
    );
    Ok(())
}

#[test]
fn getindexinfo_does_not_hide_filter_query_failures_or_query_unselected_index()
-> Result<(), RpcError> {
    for (error, code) in [
        (FilterQueryError::Retry, -1),
        (FilterQueryError::Unavailable("failed".into()), -1),
        (FilterQueryError::Corrupt("missing tip".into()), -32_603),
        (FilterQueryError::Storage("read failed".into()), -32_603),
    ] {
        let mut context = context(failure(error));
        context.indexes.derived_index = Some(Arc::new(FakeTxIndex));
        let handler = Handler::new(Arc::new(context));
        for params in [json!([]), json!({"index_name": BASIC_INDEX})] {
            assert_eq!(
                handler
                    .dispatch("getindexinfo", &params)
                    .expect_err("must refuse")
                    .code(),
                code
            );
        }
        assert_eq!(
            handler.dispatch("getindexinfo", &json!(["txindex"]))?,
            json!({
                "txindex": {"synced": true, "best_block_height": 42},
            })
        );
        assert_eq!(
            handler.dispatch("getindexinfo", &json!(["unknown"]))?,
            json!({})
        );
    }
    Ok(())
}

#[test]
fn getindexinfo_validates_named_and_positional_parameters() {
    let handler = Handler::new(Arc::new(Context::new()));
    for (params, code) in [
        (json!({"index_name": false}), -3),
        (json!(["txindex", "extra"]), -32_602),
        (json!({"index": "txindex"}), -8),
        (json!({"args": ["txindex"], "index_name": BASIC_INDEX}), -8),
    ] {
        assert_eq!(
            handler
                .dispatch("getindexinfo", &params)
                .expect_err("invalid input")
                .code(),
            code
        );
    }
}

#[test]
fn filter_rpc_is_implemented_without_claiming_external_parity() {
    use bitcoin_rs_rpc::manifest::{Status, SurfaceKind, entries_of_kind};

    let row = entries_of_kind(SurfaceKind::Rpc)
        .find(|entry| entry.name == "getblockfilter")
        .expect("registry row");
    assert_eq!(row.status, Status::ImplementedUnverified);
    assert!(row.shipped());
}

#[test]
fn getnetworkinfo_uses_live_p2p_service_flags_and_preserves_pruning() -> Result<(), RpcError> {
    use bitcoin::p2p::ServiceFlags;
    use bitcoin_rs_p2p::{P2pService, P2pServiceConfig};
    use bitcoin_rs_rpc::context::NetworkHandles;

    let base = ServiceFlags::WITNESS | ServiceFlags::NETWORK_LIMITED | ServiceFlags::P2P_V2;
    let provider = Arc::new(FakeFilters {
        record: Err(FilterQueryError::UnknownBlock),
        info: Mutex::new(Ok(info(false))),
    });
    let p2p = Arc::new(
        P2pService::new(
            P2pServiceConfig {
                // A configured bit is insufficient without a live ready provider.
                local_services: base | ServiceFlags::COMPACT_FILTERS,
                ..P2pServiceConfig::default()
            },
            bitcoin_rs_chain::LatchReader::fixture_never(),
        )
        .with_compact_filters(Some(provider.clone())),
    );
    let mut context = Context::new();
    context.network = NetworkHandles {
        peer_table: p2p.table(),
        p2p,
    };
    let handler = Handler::new(Arc::new(context));
    let result = handler.dispatch("getnetworkinfo", &json!([]))?;
    assert_eq!(
        result.get("localservices"),
        Some(&json!("0000000000000c08"))
    );
    assert_eq!(
        result.get("localservicesnames"),
        Some(&json!(["WITNESS", "NETWORK_LIMITED", "P2P_V2"]))
    );
    *provider.info.lock() = Ok(info(true));
    let result = handler.dispatch("getnetworkinfo", &json!([]))?;
    assert_eq!(
        result.get("localservices"),
        Some(&json!("0000000000000c48"))
    );
    assert_eq!(
        result.get("localservicesnames"),
        Some(&json!([
            "WITNESS",
            "COMPACT_FILTERS",
            "NETWORK_LIMITED",
            "P2P_V2"
        ]))
    );
    *provider.info.lock() = Err(FilterQueryError::Unavailable("stopped".into()));
    let result = handler.dispatch("getnetworkinfo", &json!([]))?;
    assert_eq!(
        result.get("localservices"),
        Some(&json!("0000000000000c08"))
    );
    assert_eq!(
        result.get("localservicesnames"),
        Some(&json!(["WITNESS", "NETWORK_LIMITED", "P2P_V2"]))
    );
    Ok(())
}
