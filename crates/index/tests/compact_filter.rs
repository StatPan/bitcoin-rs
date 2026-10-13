//! BIP158 bytes and headers against independent, pinned public vectors.
#![allow(clippy::expect_used)]

use bitcoin::bip158::{BlockFilter, FilterHeader};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::FromHex as _;
use bitcoin_rs_index::SpentCoinScripts;
use bitcoin_rs_index::compact_filter::{CompactFilterError, basic_filter};
use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
use std::collections::HashMap;

#[derive(Default)]
struct Scripts(HashMap<([u8; 32], u32), Vec<u8>>);

impl SpentCoinScripts for Scripts {
    fn script_bytes(&self, txid: &[u8; 32], vout: u32) -> Option<&[u8]> {
        self.0.get(&(*txid, vout)).map(Vec::as_slice)
    }
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn official_bip158_vectors_match_bytes_and_chained_headers() -> TestResult {
    // CC0 source, retained byte-for-byte:
    // https://github.com/bitcoin/bips/blob/dd3948b4742eaad13872a85691347dc77cce09f0/bip-0158/testnet-19.json
    // Includes genesis, empty/OP_RETURN scripts, duplicate scripts and witness.
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("data/bip158-testnet-19.json"))?;
    assert_eq!(rows.len() - 1, 10);
    for row in rows.iter().skip(1) {
        let height = row[0].as_u64().ok_or("height")?;
        let block: Block =
            bitcoin_rs_primitives::deserialize(&Vec::from_hex(row[2].as_str().ok_or("block")?)?)?;
        assert_eq!(
            block.block_hash().to_string(),
            row[1].as_str().ok_or("hash")?
        );
        let inputs: Vec<_> = block.txs.iter().skip(1).flat_map(|tx| &tx.inputs).collect();
        let prevouts = row[3].as_array().ok_or("prevout scripts")?;
        assert_eq!(inputs.len(), prevouts.len(), "height {height}");
        let mut scripts = Scripts::default();
        for (input, script) in inputs.iter().zip(prevouts) {
            let outpoint = input.previous_output;
            scripts.0.insert(
                (outpoint.txid.0.to_le_bytes(), outpoint.vout),
                Vec::from_hex(script.as_str().ok_or("script hex")?)?,
            );
        }
        let encoded = basic_filter(&block, &scripts)?;
        assert_eq!(
            encoded,
            Vec::from_hex(row[5].as_str().ok_or("expected filter")?)?,
            "filter at height {height}"
        );
        let previous: FilterHeader = row[4].as_str().ok_or("previous header")?.parse()?;
        let expected: FilterHeader = row[6].as_str().ok_or("expected header")?.parse()?;
        assert_eq!(
            BlockFilter::new(&encoded).filter_header(&previous),
            expected
        );
    }
    Ok(())
}

fn output(script: &[u8]) -> TxOut {
    TxOut {
        script_pubkey: script.to_vec().into(),
        ..TxOut::default()
    }
}

fn fixture(outputs: Vec<TxOut>) -> Block {
    // Construction is deliberately pure: these focused element-set fixtures
    // need no PoW or UTXO mutation and make no block-validity claim.
    Block {
        txs: vec![Tx {
            outputs,
            ..Tx::default()
        }],
        ..Block::default()
    }
}

#[test]
fn same_block_spend_needs_no_external_undo_and_keeps_created_script() -> TestResult {
    let mut block = fixture(vec![output(&[0x51])]);
    let parent = Tx {
        outputs: vec![output(&[0x52])],
        ..Tx::default()
    };
    let child = Tx {
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent.txid(), 0),
            ..TxIn::default()
        }],
        outputs: vec![output(&[0x53])],
        ..Tx::default()
    };
    block.txs.extend([parent, child]);
    let encoded = basic_filter(&block, &Scripts::default())?;
    // The header (and therefore filter key) is identical. Repeated scripts
    // are a set: the input must not double-count the parent's output.
    let expected = fixture(vec![output(&[0x51]), output(&[0x52]), output(&[0x53])]);
    assert_eq!(encoded, basic_filter(&expected, &Scripts::default())?);
    Ok(())
}

#[test]
fn absent_external_prevout_fails_and_unrelated_undo_is_ignored() -> TestResult {
    let missing = OutPoint::new(Txid(Hash256::from_le_bytes(&[7; 32])), 3);
    let mut block = fixture(vec![output(&[0x51])]);
    block.txs.push(Tx {
        inputs: vec![TxIn {
            previous_output: missing,
            ..TxIn::default()
        }],
        ..Tx::default()
    });
    assert!(matches!(
        basic_filter(&block, &Scripts::default()),
        Err(CompactFilterError::MissingPrevout(outpoint)) if outpoint == missing
    ));
    let mut scripts = Scripts::default();
    scripts.0.insert(([7; 32], 3), vec![0x52]);
    let expected = basic_filter(&block, &scripts)?;
    // A BIP30 replacement can add an undo restore without any input spending
    // it. Such extra restores must not change the filter.
    scripts.0.insert(([9; 32], 0), vec![0x54]);
    assert_eq!(basic_filter(&block, &scripts)?, expected);
    assert_eq!(
        expected,
        basic_filter(
            &fixture(vec![output(&[0x51]), output(&[0x52])]),
            &Scripts::default()
        )?
    );
    Ok(())
}

#[test]
fn output_rules_are_distinct_from_live_utxo_admission() -> TestResult {
    let oversize = vec![0x51; 10_001];
    let block = fixture(vec![
        output(&[]),
        output(&[0x6a, 0x51]),
        output(&[0x51]),
        output(&[0x51]),
        output(&oversize),
    ]);
    let expected = fixture(vec![output(&[0x51]), output(&oversize)]);
    assert_eq!(
        basic_filter(&block, &Scripts::default())?,
        basic_filter(&expected, &Scripts::default())?
    );
    let hash = bitcoin::BlockHash::from_byte_array(block.block_hash().0.to_le_bytes());
    assert!(
        BlockFilter::new(&basic_filter(&block, &Scripts::default())?)
            .match_all(&hash, [&[0x51][..], oversize.as_slice()].into_iter())?
    );
    assert_eq!(
        basic_filter(
            &fixture(vec![output(&[]), output(&[0x6a])]),
            &Scripts::default()
        )?,
        vec![0]
    );
    Ok(())
}
