// Copyright (c) 2024-2026 Atlas Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sign a message and verify the signature across multiple chains.

use atlas_ecdh_bridge::{Chain, derive_public_key, derive_public_key_base58, sign, verify};

fn main() {
    println!("═══ atlas-ecdh-bridge: Sign & Verify Demo ═══");
    println!();

    let secret = [0xEF_u8; 32];
    let message = b"Transfer 1.5 SOL to Bob";

    println!("Message: {:?}", std::str::from_utf8(message).unwrap());
    println!();

    for chain in &[Chain::Solana, Chain::Sui, Chain::Aptos, Chain::Sei] {
        let pubkey = derive_public_key(&secret, chain).unwrap();
        let addr = derive_public_key_base58(&secret, chain).unwrap();
        let sig = sign(&secret, message, chain).unwrap();

        println!("── {} ──", chain.name());
        println!("  Address:   {}", addr);
        println!("  Signature: {}...{}", hex::encode(&sig[..8]), hex::encode(&sig[56..]));

        match verify(&pubkey, message, &sig) {
            Ok(()) => println!("  Verified:  ✓"),
            Err(e) => println!("  FAILED:    {}", e),
        }
        println!();
    }

    // Demonstrate failure: wrong message
    println!("── Tampered Message Test ──");
    let sig = sign(&secret, message, &Chain::Solana).unwrap();
    let pubkey = derive_public_key(&secret, &Chain::Solana).unwrap();
    match verify(&pubkey, b"Transfer 100 SOL to Eve", &sig) {
        Ok(()) => println!("  ERROR: Should have failed!"),
        Err(_) => println!("  Tampered message correctly rejected ✓"),
    }
}
