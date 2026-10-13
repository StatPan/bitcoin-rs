//! Basic-filter RPC projection; the index owns block identity and readiness.

use alloc::sync::Arc;

use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_primitives::{BlockHash, Hash256};
use corepc_types::v31;
use sonic_rs::{JsonValueTrait as _, Value};

use crate::context::{Context, FilterQueryError};
use crate::convert::typed_to_sonic;
use crate::error::RpcError;

pub(crate) fn getblockfilter(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let params = super::bind_named_params(params, &["blockhash", "filtertype"])?;
    super::ensure_at_most_params(&params, 2)?;
    let hash = super::required_str(&params, 0, "blockhash is required")?;
    let filter_type = match params.get(1).filter(|value| !value.is_null()) {
        None => "basic",
        Some(value) => value
            .as_str()
            .ok_or_else(|| super::wrong_type(2, "filtertype", value, "string"))?,
    };
    let block = BlockHash::from(super::parse_txid(hash, "blockhash")?.0);
    if filter_type != "basic" {
        return Err(RpcError::InvalidAddressOrKey(
            "Unknown filtertype".to_owned(),
        ));
    }
    let index = ctx
        .indexes
        .compact_filter
        .as_ref()
        .ok_or(FilterQueryError::Disabled)?;
    let record = index.filter(block)?;
    typed_to_sonic(&v31::GetBlockFilter {
        filter: record.filter.to_lower_hex_string(),
        header: Hash256::from_le_bytes(&record.filter_header).to_string_be(),
    })
}
