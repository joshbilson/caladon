//! Dev tool: fetch PCS collateral for the live TDX quote fixture and print it as JSON, so it can
//! be committed as the OFFLINE collateral fixture the attestation tamper tests run against.
//!
//!   cargo run --example fetch_fixture --features std -- <quote.hex> > tests/fixtures/collateral.json
//!
//! Run native only (needs network + the `report` feature). NOT part of the test suite.

use std::env;
use std::fs;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let path = env::args().nth(1).expect("usage: fetch_fixture <quote.hex>");
    let hex_str = fs::read_to_string(&path).expect("read quote hex").trim().to_string();
    let quote = hex::decode(&hex_str).expect("decode quote hex");
    let json = caladon_core::attestation::collateral::fetch_collateral_json(&quote, None)
        .await
        .expect("fetch collateral");
    println!("{json}");
}
