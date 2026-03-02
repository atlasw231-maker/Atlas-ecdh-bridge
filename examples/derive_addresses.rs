// Copyright (c) 2024-2026 Atlas Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Derive Ed25519 addresses for all built-in chains from a simulated ECDH secret.

use atlas_ecdh_bridge::{Chain, derive_public_key_base58, derive_public_key_hex};

fn main() {
    println!("═══ atlas-ecdh-bridge: Address Derivation Demo ═══");
    println!();

    // Simulated 32-byte ECDH shared secret (in production, comes from hardware ECDH)
    let simulated_secret = [0xAB_u8; 32];

    println!("ECDH secret (simulated): {}", hex::encode(&simulated_secret));
    println!();

    // Base58 addresses (Solana-style)
    println!("── Base58 Addresses ──");
    for chain in Chain::all_builtins() {
        let addr = derive_public_key_base58(&simulated_secret, chain).unwrap();
        println!("  {:>10}: {}", chain.name(), addr);
    }
    println!();

    // Hex addresses (Sui/Aptos-style)
    println!("── Hex Addresses ──");
    for chain in Chain::all_builtins() {
        let addr = derive_public_key_hex(&simulated_secret, chain).unwrap();
        println!("  {:>10}: 0x{}", chain.name(), addr);
    }
    println!();

    // Custom chain
    let custom = Chain::Custom("my-game:items:ed25519:v1".into());
    let custom_addr = derive_public_key_base58(&simulated_secret, &custom).unwrap();
    println!("── Custom Chain ──");
    println!("  {}: {}", custom, custom_addr);
}
