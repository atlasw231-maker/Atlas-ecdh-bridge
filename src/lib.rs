// Copyright (c) 2024-2026 Atlas Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # atlas-ecdh-bridge
//!
//! **Derive deterministic Ed25519 signing keys from WebAuthn/Passkey P-256 ECDH —
//! zero persistent secrets, hardware-bound identity.**
//!
//! ## The Problem
//!
//! Passkeys (WebAuthn/FIDO2) use NIST P-256 keys locked inside hardware security
//! modules — Android StrongBox, iOS Secure Enclave, Windows Hello, YubiKeys.
//! You **cannot** export the private key, and you **cannot** sign with Ed25519.
//!
//! Meanwhile, most blockchains (Solana, Sui, Aptos, Stellar, NEAR, Cosmos, etc.)
//! require **Ed25519** signatures. The curves are mathematically incompatible.
//!
//! ## The Solution
//!
//! This crate bridges the gap using **ECDH key agreement** — a standard operation
//! that passkey hardware already supports:
//!
//! ```text
//! passkey_private × FIXED_POINT → 32-byte shared secret (inside TEE)
//!                                        ↓
//!              HKDF(secret, "solana:ed25519:v1") → Ed25519 seed → sign → zeroize
//! ```
//!
//! **One passkey → deterministic Ed25519 keys for every chain → zero secrets stored.**
//!
//! ## Security Properties
//!
//! - **No persistent secrets** — Ed25519 key material exists in RAM only during
//!   [`sign()`], then is zeroized via the `zeroize` crate
//! - **Deterministic** — same passkey × same fixed point = same addresses, every time
//! - **Biometric-gated** — ECDH requires user verification (fingerprint, face, PIN)
//! - **Hardware-bound** — the passkey private key never leaves the secure element
//! - **Domain-separated** — each chain gets an independent key via HKDF with unique salt
//! - **No seed phrase** — the hardware IS the identity
//! - **Auditable** — the fixed point is derived from a public domain string

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use p256::elliptic_curve::ops::{MulByGenerator, Reduce};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Domain string & chain salts
// ─────────────────────────────────────────────────────────────────────────────

/// Domain string for fixed-point scalar derivation.
/// SHA-256(DOMAIN_STRING) mod n → scalar → scalar × G = fixed point.
const DOMAIN_STRING: &[u8] = b"atlas:ecdh:p256:ed25519:derivation:v1";

/// HKDF info field used for all chain derivations.
const HKDF_INFO: &[u8] = b"ed25519-signing-key";

// ─────────────────────────────────────────────────────────────────────────────
// Chain enum
// ─────────────────────────────────────────────────────────────────────────────

/// Supported blockchain chains for Ed25519 key derivation.
///
/// Each variant maps to a unique HKDF salt, ensuring cryptographically
/// independent Ed25519 keys from the same ECDH shared secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Chain {
    Solana,
    Sui,
    Aptos,
    Sei,
    Stellar,
    Near,
    Cosmos,
    Polkadot,
    Cardano,
    Ton,
    /// Custom chain with a user-defined salt string.
    /// Use format: `"your-app:your-chain:ed25519:v1"`
    Custom(String),
}

impl Chain {
    /// Get the HKDF salt bytes for this chain.
    pub fn salt(&self) -> Vec<u8> {
        match self {
            Chain::Solana => b"atlas:ecdh:solana:ed25519:v1".to_vec(),
            Chain::Sui => b"atlas:ecdh:sui:ed25519:v1".to_vec(),
            Chain::Aptos => b"atlas:ecdh:aptos:ed25519:v1".to_vec(),
            Chain::Sei => b"atlas:ecdh:sei:ed25519:v1".to_vec(),
            Chain::Stellar => b"atlas:ecdh:stellar:ed25519:v1".to_vec(),
            Chain::Near => b"atlas:ecdh:near:ed25519:v1".to_vec(),
            Chain::Cosmos => b"atlas:ecdh:cosmos:ed25519:v1".to_vec(),
            Chain::Polkadot => b"atlas:ecdh:polkadot:ed25519:v1".to_vec(),
            Chain::Cardano => b"atlas:ecdh:cardano:ed25519:v1".to_vec(),
            Chain::Ton => b"atlas:ecdh:ton:ed25519:v1".to_vec(),
            Chain::Custom(s) => s.as_bytes().to_vec(),
        }
    }

    /// Display name for this chain.
    pub fn name(&self) -> &str {
        match self {
            Chain::Solana => "Solana",
            Chain::Sui => "Sui",
            Chain::Aptos => "Aptos",
            Chain::Sei => "Sei",
            Chain::Stellar => "Stellar",
            Chain::Near => "NEAR",
            Chain::Cosmos => "Cosmos",
            Chain::Polkadot => "Polkadot",
            Chain::Cardano => "Cardano",
            Chain::Ton => "TON",
            Chain::Custom(s) => s.as_str(),
        }
    }

    /// All built-in chain variants (excludes Custom).
    pub fn all_builtins() -> &'static [Chain] {
        &[
            Chain::Solana,
            Chain::Sui,
            Chain::Aptos,
            Chain::Sei,
            Chain::Stellar,
            Chain::Near,
            Chain::Cosmos,
            Chain::Polkadot,
            Chain::Cardano,
            Chain::Ton,
        ]
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixed Point computation
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the fixed P-256 public key used for ECDH derivation.
///
/// Returns **65 bytes**: `[0x04 || X(32) || Y(32)]` (uncompressed SEC1 format),
/// suitable for Android `KeyAgreement`, iOS `SecKey`, and WebAuthn.
///
/// The point is derived as:
/// ```text
/// scalar = SHA-256("atlas:ecdh:p256:ed25519:derivation:v1") mod n
/// FIXED_POINT = scalar × G  (P-256 generator)
/// ```
///
/// This is a well-known, auditable constant — **not** a secret.
///
/// # Example
/// ```
/// let point = atlas_ecdh_bridge::fixed_point_uncompressed();
/// assert_eq!(point.len(), 65);
/// assert_eq!(point[0], 0x04);
/// ```
pub fn fixed_point_uncompressed() -> Vec<u8> {
    let scalar = domain_scalar();
    let point = p256::ProjectivePoint::mul_by_generator(&scalar);
    let affine = p256::AffinePoint::from(point);
    affine.to_encoded_point(false).as_bytes().to_vec()
}

/// Return the fixed point as raw `X || Y` (64 bytes, no `0x04` prefix).
///
/// Convenience for platforms that take separate X/Y coordinates, e.g.
/// Kotlin's `ECPoint(BigInteger(x), BigInteger(y))`.
///
/// # Example
/// ```
/// let xy = atlas_ecdh_bridge::fixed_point_xy();
/// assert_eq!(xy.len(), 64);
/// ```
pub fn fixed_point_xy() -> Vec<u8> {
    fixed_point_uncompressed()[1..].to_vec()
}

/// Return the fixed point in compressed SEC1 format (33 bytes: `02/03 || X`).
pub fn fixed_point_compressed() -> Vec<u8> {
    let scalar = domain_scalar();
    let point = p256::ProjectivePoint::mul_by_generator(&scalar);
    let affine = p256::AffinePoint::from(point);
    affine.to_encoded_point(true).as_bytes().to_vec()
}

/// Internal: derive the P-256 scalar from the domain string.
fn domain_scalar() -> p256::Scalar {
    let hash = Sha256::digest(DOMAIN_STRING);
    <p256::Scalar as Reduce<p256::U256>>::reduce_bytes(&hash)
}

// ─────────────────────────────────────────────────────────────────────────────
// HKDF-based Ed25519 key derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a 32-byte Ed25519 seed from the ECDH shared secret + chain salt.
///
/// Uses HKDF-SHA256 with:
/// - IKM = 32-byte ECDH shared secret
/// - salt = chain-specific domain string
/// - info = "ed25519-signing-key"
fn derive_seed(ecdh_secret: &[u8], chain: &Chain) -> Result<Zeroizing<[u8; 32]>, String> {
    if ecdh_secret.len() != 32 {
        return Err(format!(
            "ECDH secret must be exactly 32 bytes, got {}",
            ecdh_secret.len()
        ));
    }

    let salt = chain.salt();
    let hk = Hkdf::<Sha256>::new(Some(&salt), ecdh_secret);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut())
        .map_err(|e| format!("HKDF expand failed: {}", e))?;
    Ok(okm)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — Key derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive the raw 32-byte Ed25519 public key for a given chain.
///
/// # Example
/// ```
/// use atlas_ecdh_bridge::Chain;
/// let secret = [0xAB_u8; 32];
/// let pubkey = atlas_ecdh_bridge::derive_public_key(&secret, &Chain::Solana).unwrap();
/// assert_eq!(pubkey.len(), 32);
/// ```
pub fn derive_public_key(ecdh_secret: &[u8], chain: &Chain) -> Result<Vec<u8>, String> {
    let seed = derive_seed(ecdh_secret, chain)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key: VerifyingKey = (&signing_key).into();
    Ok(verifying_key.to_bytes().to_vec())
}

/// Derive the Ed25519 public key as a **base58** string (standard Solana address format).
///
/// # Example
/// ```
/// use atlas_ecdh_bridge::Chain;
/// let secret = [0xAB_u8; 32];
/// let addr = atlas_ecdh_bridge::derive_public_key_base58(&secret, &Chain::Solana).unwrap();
/// assert!(addr.len() >= 32 && addr.len() <= 44);
/// ```
pub fn derive_public_key_base58(ecdh_secret: &[u8], chain: &Chain) -> Result<String, String> {
    let pubkey = derive_public_key(ecdh_secret, chain)?;
    Ok(bs58::encode(&pubkey).into_string())
}

/// Derive the Ed25519 public key as a **hex** string (standard Sui/Aptos address format).
pub fn derive_public_key_hex(ecdh_secret: &[u8], chain: &Chain) -> Result<String, String> {
    let pubkey = derive_public_key(ecdh_secret, chain)?;
    Ok(hex::encode(&pubkey))
}

/// Derive Ed25519 public keys for **all 10 built-in chains** at once.
///
/// Returns a `Vec` of `(Chain, base58_address)` pairs.
///
/// # Example
/// ```
/// let secret = [0xAB_u8; 32];
/// let keys = atlas_ecdh_bridge::derive_all_builtin_keys(&secret).unwrap();
/// assert_eq!(keys.len(), 10);
/// ```
pub fn derive_all_builtin_keys(
    ecdh_secret: &[u8],
) -> Result<Vec<(Chain, String)>, String> {
    Chain::all_builtins()
        .iter()
        .map(|chain| {
            let addr = derive_public_key_base58(ecdh_secret, chain)?;
            Ok((chain.clone(), addr))
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — Signing & Verification
// ─────────────────────────────────────────────────────────────────────────────

/// Sign a message with the ECDH-derived Ed25519 key for a given chain.
///
/// **Security:** The Ed25519 private key exists ONLY during this function call,
/// then is zeroized. No key material persists after return.
///
/// Returns a 64-byte Ed25519 signature.
///
/// # Example
/// ```
/// use atlas_ecdh_bridge::Chain;
/// let secret = [0xAB_u8; 32];
/// let sig = atlas_ecdh_bridge::sign(&secret, b"hello", &Chain::Solana).unwrap();
/// assert_eq!(sig.len(), 64);
/// ```
pub fn sign(ecdh_secret: &[u8], message: &[u8], chain: &Chain) -> Result<Vec<u8>, String> {
    let seed = derive_seed(ecdh_secret, chain)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(message);
    // seed is Zeroizing — auto-zeroed on drop
    Ok(signature.to_bytes().to_vec())
}

/// Verify an Ed25519 signature against a public key.
///
/// `pubkey` must be 32 bytes (raw Ed25519 public key).
/// `signature` must be 64 bytes.
pub fn verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    if pubkey.len() != 32 {
        return Err(format!("Public key must be 32 bytes, got {}", pubkey.len()));
    }
    if signature.len() != 64 {
        return Err(format!("Signature must be 64 bytes, got {}", signature.len()));
    }

    let vk_bytes: [u8; 32] = pubkey.try_into().map_err(|_| "Invalid pubkey length")?;
    let verifying_key =
        VerifyingKey::from_bytes(&vk_bytes).map_err(|e| format!("Invalid public key: {}", e))?;

    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| "Invalid signature length")?;
    let sig = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(message, &sig)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

/// Print the fixed point in all formats — useful for embedding in platform code.
pub fn print_fixed_point_info() {
    let uncompressed = fixed_point_uncompressed();
    let xy = fixed_point_xy();
    let compressed = fixed_point_compressed();

    println!("═══ atlas-ecdh-bridge Fixed Point ═══");
    println!();
    println!("Domain: {}", std::str::from_utf8(DOMAIN_STRING).unwrap());
    println!();
    println!(
        "Uncompressed (65 bytes): {}",
        hex::encode(&uncompressed)
    );
    println!("X (32 bytes): {}", hex::encode(&xy[..32]));
    println!("Y (32 bytes): {}", hex::encode(&xy[32..]));
    println!(
        "Compressed (33 bytes):   {}",
        hex::encode(&compressed)
    );
    println!();
    println!("── Android (Kotlin) ──");
    println!("val fixedPointXY = byteArrayOf(");
    for (i, chunk) in xy.chunks(16).enumerate() {
        let hex_str: Vec<String> = chunk.iter().map(|b| format!("0x{:02X}.toByte()", b)).collect();
        let comma = if i < (xy.len() + 15) / 16 - 1 { "," } else { "" };
        println!("    {}{}", hex_str.join(", "), comma);
    }
    println!(")");
    println!();
    println!("── iOS (Swift) ──");
    println!(
        "let fixedPoint = Data(hex: \"{}\")",
        hex::encode(&uncompressed)
    );
    println!();
    println!("── Web (JavaScript) ──");
    println!(
        "const fixedPoint = new Uint8Array([{}]);",
        uncompressed
            .iter()
            .map(|b| format!("0x{:02X}", b))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_point_is_valid_p256() {
        let point = fixed_point_uncompressed();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);

        // Verify it's a valid P-256 point by parsing it
        let encoded =
            p256::EncodedPoint::from_bytes(&point).expect("Must be valid SEC1 encoding");
        assert!(!encoded.is_identity());
    }

    #[test]
    fn fixed_point_is_deterministic() {
        assert_eq!(fixed_point_uncompressed(), fixed_point_uncompressed());
    }

    #[test]
    fn fixed_point_xy_matches_uncompressed() {
        let full = fixed_point_uncompressed();
        let xy = fixed_point_xy();
        assert_eq!(xy.len(), 64);
        assert_eq!(&full[1..], &xy[..]);
    }

    #[test]
    fn fixed_point_compressed_matches() {
        let compressed = fixed_point_compressed();
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    #[test]
    fn derive_pubkey_is_32_bytes() {
        let secret = [0xAB_u8; 32];
        let pubkey = derive_public_key(&secret, &Chain::Solana).unwrap();
        assert_eq!(pubkey.len(), 32);
    }

    #[test]
    fn derive_pubkey_is_deterministic() {
        let secret = [0xAB_u8; 32];
        let pk1 = derive_public_key(&secret, &Chain::Solana).unwrap();
        let pk2 = derive_public_key(&secret, &Chain::Solana).unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn different_chains_produce_different_keys() {
        let secret = [0xCD_u8; 32];
        let sol = derive_public_key(&secret, &Chain::Solana).unwrap();
        let sui = derive_public_key(&secret, &Chain::Sui).unwrap();
        let apt = derive_public_key(&secret, &Chain::Aptos).unwrap();
        let sei = derive_public_key(&secret, &Chain::Sei).unwrap();
        assert_ne!(sol, sui);
        assert_ne!(sol, apt);
        assert_ne!(sol, sei);
        assert_ne!(sui, apt);
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let pk1 = derive_public_key(&[0xAA_u8; 32], &Chain::Solana).unwrap();
        let pk2 = derive_public_key(&[0xBB_u8; 32], &Chain::Solana).unwrap();
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn base58_address_format() {
        let secret = [0x42_u8; 32];
        let addr = derive_public_key_base58(&secret, &Chain::Solana).unwrap();
        assert!(addr.len() >= 32 && addr.len() <= 44);
    }

    #[test]
    fn hex_address_format() {
        let secret = [0x42_u8; 32];
        let addr = derive_public_key_hex(&secret, &Chain::Sui).unwrap();
        assert_eq!(addr.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn custom_chain_works() {
        let secret = [0xEE_u8; 32];
        let custom = Chain::Custom("my-app:my-chain:ed25519:v1".into());
        let pk = derive_public_key(&secret, &custom).unwrap();
        assert_eq!(pk.len(), 32);

        // Must differ from built-in chains
        let sol = derive_public_key(&secret, &Chain::Solana).unwrap();
        assert_ne!(pk, sol);
    }

    #[test]
    fn derive_all_builtin() {
        let secret = [0xAB_u8; 32];
        let keys = derive_all_builtin_keys(&secret).unwrap();
        assert_eq!(keys.len(), 10);

        // All different
        let addrs: Vec<&String> = keys.iter().map(|(_, a)| a).collect();
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(addrs[i], addrs[j]);
            }
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let secret = [0xEF_u8; 32];
        let message = b"hello solana";

        let sig = sign(&secret, message, &Chain::Solana).unwrap();
        assert_eq!(sig.len(), 64);

        let pubkey = derive_public_key(&secret, &Chain::Solana).unwrap();
        verify(&pubkey, message, &sig).expect("Signature must verify");
    }

    #[test]
    fn wrong_message_fails_verification() {
        let secret = [0xEF_u8; 32];
        let sig = sign(&secret, b"correct", &Chain::Solana).unwrap();
        let pubkey = derive_public_key(&secret, &Chain::Solana).unwrap();
        assert!(verify(&pubkey, b"wrong", &sig).is_err());
    }

    #[test]
    fn wrong_chain_fails_verification() {
        let secret = [0xEF_u8; 32];
        let sig = sign(&secret, b"msg", &Chain::Solana).unwrap();
        let sui_pk = derive_public_key(&secret, &Chain::Sui).unwrap();
        assert!(verify(&sui_pk, b"msg", &sig).is_err());
    }

    #[test]
    fn sign_verify_all_builtin_chains() {
        let secret = [0xDD_u8; 32];
        let msg = b"test all chains";

        for chain in Chain::all_builtins() {
            let sig = sign(&secret, msg, chain).unwrap();
            let pk = derive_public_key(&secret, chain).unwrap();
            verify(&pk, msg, &sig)
                .unwrap_or_else(|e| panic!("Failed for {}: {}", chain.name(), e));
        }
    }

    #[test]
    fn verify_invalid_pubkey() {
        assert!(verify(&[0u8; 16], b"msg", &[0u8; 64]).is_err());
    }

    #[test]
    fn verify_invalid_signature_length() {
        let secret = [0xAA_u8; 32];
        let pk = derive_public_key(&secret, &Chain::Solana).unwrap();
        assert!(verify(&pk, b"msg", &[0u8; 32]).is_err());
    }

    #[test]
    fn invalid_secret_length_0() {
        assert!(derive_public_key(&[], &Chain::Solana).is_err());
    }

    #[test]
    fn invalid_secret_length_16() {
        assert!(derive_public_key(&[0u8; 16], &Chain::Solana).is_err());
    }

    #[test]
    fn invalid_secret_length_48() {
        assert!(sign(&[0u8; 48], b"msg", &Chain::Solana).is_err());
    }
}
