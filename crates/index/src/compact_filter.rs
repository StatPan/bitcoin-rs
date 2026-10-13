//! Pure BIP158 construction; this module does not enable an index or a service.

use bitcoin::bip158::GcsFilterWriter;
use bitcoin_rs_primitives::{Block, OutPoint};
use hashbrown::HashMap;
use thiserror::Error;

use crate::SpentCoinScripts;

/// Failure to construct a complete basic filter.
#[derive(Debug, Error)]
pub enum CompactFilterError {
    /// An external input has no authoritative spent-output script.
    #[error("compact filter is missing the script for {0:?}")]
    MissingPrevout(OutPoint),
    /// The filter encoder refused the output.
    #[error("compact filter encoding failed: {0}")]
    Encoding(#[from] bitcoin::bip158::Error),
}

/// Builds the serialized BIP158 basic filter of an already validated block.
///
/// `spent` must resolve external inputs against this block's authoritative
/// undo/resolved-prevout facts, not the current UTXO set. Same-block inputs
/// resolve from the block itself. Extra undo restores (for example BIP30
/// overwritten coins) are never included unless an input actually spends them.
///
/// This is a derived-data operation, not a validation path. The caller owns
/// block/undo identity, retained-history access, scheduling and persistence.
/// No partial filter is returned when a prevout is unavailable.
pub fn basic_filter(
    block: &Block,
    spent: &dyn SpentCoinScripts,
) -> Result<Vec<u8>, CompactFilterError> {
    let hash = block.block_hash();
    let bytes = hash.as_bytes();
    let mut key0 = [0_u8; 8];
    let mut key1 = [0_u8; 8];
    key0.copy_from_slice(&bytes[..8]);
    key1.copy_from_slice(&bytes[8..16]);
    let mut encoded = Vec::new();
    // BIP158 basic-filter parameters. The existing library owns GCS encoding,
    // empty-element removal and deduplication.
    let mut writer = GcsFilterWriter::new(
        &mut encoded,
        u64::from_le_bytes(key0),
        u64::from_le_bytes(key1),
        784_931,
        19,
    );
    let mut created = HashMap::new();
    for tx in &block.txs {
        let txid = tx.txid();
        for (vout, output) in (0_u32..).zip(&tx.outputs) {
            let script = output.script_pubkey.as_bytes();
            created.insert(OutPoint::new(txid, vout), script);
            if script.first() != Some(&0x6a) {
                writer.add_element(script);
            }
        }
    }
    for tx in block.txs.iter().skip(1) {
        for input in &tx.inputs {
            let outpoint = input.previous_output;
            let script = created
                .get(&outpoint)
                .copied()
                .or_else(|| spent.script_bytes(outpoint.txid.as_bytes(), outpoint.vout));
            let script = script.ok_or(CompactFilterError::MissingPrevout(outpoint))?;
            writer.add_element(script);
        }
    }
    writer.finish().map_err(bitcoin::bip158::Error::from)?;
    Ok(encoded)
}
