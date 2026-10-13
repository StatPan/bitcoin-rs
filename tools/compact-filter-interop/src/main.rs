//! A real, unmodified bdk_kyoto client on one trusted loopback regtest peer.
use bdk_kyoto::{
    ScanType, TrustedPeer,
    builder::{Builder, BuilderExt},
};
use bdk_wallet::{CreateParams, KeychainKind, bitcoin::Network};
use std::{net::IpAddr, path::PathBuf, time::Duration};

// Public test descriptors only. Never use this wallet to receive real funds.
const EXTERNAL: &str = "tr([7d94197e/86'/1'/0']tpubDCyQVJj8KzjiQsFjmb3KwECVXPvMwvAxxZGCP9XmWSopmjW3bCV3wD7TgxrUhiGSueDS1MU5X1Vb1YjYcp8jitXc5fXfdC1z68hDDEyKRNr/0/*)";
const INTERNAL: &str = "tr([7d94197e/86'/1'/0']tpubDCyQVJj8KzjiQsFjmb3KwECVXPvMwvAxxZGCP9XmWSopmjW3bCV3wD7TgxrUhiGSueDS1MU5X1Vb1YjYcp8jitXc5fXfdC1z68hDDEyKRNr/1/*)";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut wallet = CreateParams::new(EXTERNAL, INTERNAL)
        .network(Network::Regtest)
        .create_wallet_no_persist()?;
    if args.len() == 2 && args[1] == "address" {
        println!("{}", wallet.peek_address(KeychainKind::External, 0).address);
        return Ok(());
    }
    if args.len() != 8 || args[1] != "sync" {
        return Err("usage: compact-filter-interop-probe address | sync PORT DATADIR TXID HEIGHT TIP_HASH FUNDING_BLOCK_HASH".into());
    }
    let port: u16 = args[2].parse()?;
    let peer: TrustedPeer = ("127.0.0.1".parse::<IpAddr>()?, Some(port)).into();
    let client = Builder::new(Network::Regtest)
        .add_peer(peer)
        // Do not fall back to Core if the candidate advertises it through gossip.
        .whitelist_only()
        .data_dir(PathBuf::from(&args[3]))
        .required_peers(1)
        .build_with_wallet(&wallet, ScanType::Sync)?;
    let (client, _logging, mut updates) = client.subscribe();
    let client = client.start();
    let requester = client.requester();
    let result = tokio::time::timeout(Duration::from_secs(40), updates.update()).await;
    requester.shutdown()?;
    let update = result??;
    let txids: Vec<_> = update
        .tx_update
        .txs
        .iter()
        .map(|tx| tx.compute_txid().to_string())
        .collect();
    let expected = &args[4];
    let expected_height: u32 = args[5].parse()?;
    let expected_tip = &args[6];
    let funding_block = &args[7];
    assert!(
        txids.contains(expected),
        "expected funded tx absent, found {txids:?}"
    );
    let (anchor, _) = update
        .tx_update
        .anchors
        .iter()
        .find(|(_, txid)| txid.to_string() == *expected)
        .ok_or("expected transaction has no confirmation anchor")?;
    assert_eq!(anchor.block_id.height, 102);
    assert_eq!(anchor.block_id.hash.to_string(), *funding_block);
    wallet.apply_update(update)?;
    assert_eq!(wallet.latest_checkpoint().height(), expected_height);
    assert_eq!(
        wallet.latest_checkpoint().block_id().hash.to_string(),
        *expected_tip
    );
    let balance = wallet.balance();
    assert_eq!(balance.total().to_sat(), 21_000_000);
    assert_eq!(balance.confirmed.to_sat(), 21_000_000);
    println!(
        "RESULT {{\"txid\":\"{}\",\"height\":{},\"tip_hash\":\"{}\",\"confirmed_sat\":{},\"total_sat\":{},\"confirmation_height\":102,\"confirmation_hash\":\"{}\"}}",
        expected,
        expected_height,
        expected_tip,
        balance.confirmed.to_sat(),
        balance.total().to_sat(),
        funding_block
    );
    Ok(())
}
