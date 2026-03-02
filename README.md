# atlas-ecdh-bridge

**Derive deterministic Ed25519 signing keys from WebAuthn/Passkey P-256 ECDH — zero persistent secrets, hardware-bound identity.**

[![Crates.io](https://img.shields.io/crates/v/atlas-ecdh-bridge.svg)](https://crates.io/crates/atlas-ecdh-bridge)
[![Docs.rs](https://docs.rs/atlas-ecdh-bridge/badge.svg)](https://docs.rs/atlas-ecdh-bridge)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

---

## The Problem

Passkeys (WebAuthn/FIDO2) use **NIST P-256** (secp256r1) keys locked inside hardware security modules — Android StrongBox, iOS Secure Enclave, Windows Hello, YubiKeys. You **cannot export** the private key. You **cannot** ask the hardware to sign with a different curve.

Meanwhile, most blockchains require **Ed25519** (Curve25519) signatures:

| Chain | Signature Curve |
|-------|----------------|
| Solana | Ed25519 |
| Sui | Ed25519 |
| Aptos | Ed25519 |
| Stellar | Ed25519 |
| NEAR | Ed25519 |
| Cosmos/Tendermint | Ed25519 |
| Polkadot | Ed25519 / Sr25519 |
| Cardano | Ed25519-BIP32 |
| TON | Ed25519 |

**P-256 ≠ Ed25519.** The curves are mathematically incompatible. You can't convert one key to the other.

## The Solution

This crate bridges the gap using **ECDH key agreement** — a standard operation that passkey hardware already supports:

```
┌─────────────────────────────────────────────────────────────────┐
│                    PASSKEY HARDWARE (TEE)                        │
│                                                                 │
│  passkey_private_key  ×  FIXED_POINT  →  32-byte shared secret  │
│  (never leaves TEE)     (public, from    (biometric-gated)      │
│                          this crate)                             │
└───────────────────────────────────┬─────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    THIS CRATE (Rust, in app)                    │
│                                                                 │
│  HKDF-SHA256(shared_secret, "solana:ed25519:v1")                │
│       → 32-byte Ed25519 seed                                    │
│       → sign(message)                                           │
│       → ZEROIZE seed                                            │
│                                                                 │
│  Same secret + different salt → different chain key:            │
│    "sui:ed25519:v1"    → Sui Ed25519 key                       │
│    "aptos:ed25519:v1"  → Aptos Ed25519 key                     │
│    "stellar:ed25519:v1"→ Stellar Ed25519 key                   │
│    ...                                                          │
└─────────────────────────────────────────────────────────────────┘
```

**One passkey → deterministic Ed25519 keys for every chain → zero secrets stored.**

## How It Works

### Step 1: Get the Fixed Point (once, at build time)

```rust
let fixed_point = atlas_ecdh_bridge::fixed_point_uncompressed();
// 65 bytes: [0x04 || X(32) || Y(32)] — embed in your Android/iOS/Web code
```

This point is derived deterministically from `SHA-256("atlas:ecdh:p256:ed25519:derivation:v1") mod n × G`. It's a public constant, not a secret. You can verify the derivation yourself.

### Step 2: Perform ECDH on the Platform (at runtime, biometric-gated)

**Android (Kotlin):**
```kotlin
// Get the passkey's KeyPair from Android Keystore
val keyPair = KeyStore.getInstance("AndroidKeyStore")
    .getEntry("my-passkey-alias", null) as KeyStore.PrivateKeyEntry

// Construct the fixed point as an ECPublicKey
val xy = fixedPointXY // 64 bytes from step 1
val x = BigInteger(1, xy.sliceArray(0 until 32))
val y = BigInteger(1, xy.sliceArray(32 until 64))
val spec = ECPublicKeySpec(ECPoint(x, y), ecP256Params)
val fixedKey = KeyFactory.getInstance("EC").generatePublic(spec)

// ECDH — requires biometric prompt
val agreement = KeyAgreement.getInstance("ECDH")
agreement.init(keyPair.privateKey)  // triggers BiometricPrompt
agreement.doPhase(fixedKey, true)
val sharedSecret: ByteArray = agreement.generateSecret()  // 32 bytes
```

**iOS (Swift):**
```swift
let fixedKeyData = Data(hex: "04...") // 65 bytes from step 1
let fixedKey = try P256.KeyAgreement.PublicKey(x963Representation: fixedKeyData)

// ECDH — requires FaceID/TouchID via LAContext
let sharedSecret = try passkey.sharedSecretFromKeyAgreement(with: fixedKey)
    .withUnsafeBytes { Data($0) } // 32 bytes
```

**Web (JavaScript with WebAuthn PRF extension):**
```javascript
// Using the PRF extension (WebAuthn Level 3)
const assertion = await navigator.credentials.get({
    publicKey: {
        challenge: new Uint8Array(32),
        extensions: {
            prf: {
                eval: {
                    first: new TextEncoder().encode(
                        "atlas:ecdh:p256:ed25519:derivation:v1"
                    )
                }
            }
        }
    }
});
const sharedSecret = new Uint8Array(
    assertion.getClientExtensionResults().prf.results.first
); // 32 bytes
```

### Step 3: Derive Keys & Sign (this crate)

```rust
use atlas_ecdh_bridge::{Chain, derive_public_key, sign, verify};

// The 32-byte shared secret from platform ECDH
let ecdh_secret: &[u8] = &shared_secret_from_platform;

// Derive the Solana address (base58 Ed25519 public key)
let solana_addr = atlas_ecdh_bridge::derive_public_key_base58(
    ecdh_secret, &Chain::Solana
).unwrap();
println!("Solana address: {}", solana_addr);

// Sign a Solana transaction
let signature = sign(ecdh_secret, &serialized_transaction, &Chain::Solana).unwrap();
// signature is 64 bytes — Ed25519

// The Ed25519 private key has already been zeroized at this point
```

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **No persistent secrets** | Ed25519 key material exists in RAM only during `sign()`, then is zeroized via the `zeroize` crate |
| **Deterministic** | Same passkey × same fixed point = same Ed25519 addresses, every time, on every platform |
| **Biometric-gated** | The ECDH step requires user verification (fingerprint, face, PIN) — enforced by platform hardware |
| **Hardware-bound** | The passkey private key never leaves the secure element — ECDH is computed inside the TEE |
| **Domain-separated** | Each chain gets a cryptographically independent Ed25519 key via HKDF with a unique salt |
| **No seed phrase** | No mnemonic, no encrypted blob, no cloud backup of secrets. The hardware IS the identity |
| **Auditable derivation** | The fixed point is derived from a public domain string — anyone can verify the math |
| **Forward-compatible** | `Chain::Custom("your-salt")` supports any future Ed25519 chain without a crate update |

## Security Considerations

> **⚠️ IMPORTANT: Read before using in production.**

1. **Device loss = key loss (by design).** If the user loses their device and the passkey
   cannot be recovered (e.g., no iCloud Keychain sync, no Google Password Manager backup),
   the derived Ed25519 keys are lost forever. Implement social recovery or guardian
   mechanisms at the application layer.

2. **The ECDH shared secret is sensitive.** While it exists in your application's memory
   between the platform ECDH call and this crate's `sign()`, it could be read by a
   memory dump. Keep the secret in a `Zeroizing<[u8; 32]>` wrapper and pass it to this
   crate immediately.

3. **Passkey sync behavior varies.** Apple syncs passkeys via iCloud Keychain. Google syncs
   via Google Password Manager. This means the same passkey (and therefore the same ECDH
   secret → same addresses) can exist on multiple devices. This is a feature for UX but
   affects your threat model.

4. **This crate does NOT handle the ECDH step itself.** The platform-specific ECDH call
   (Android KeyAgreement, iOS SecKeyCreateSharedSecret, WebAuthn PRF) is your responsibility.
   This crate takes the 32-byte output and derives Ed25519 keys from it.

5. **Not yet audited by a third-party security firm.** While the cryptographic primitives
   used (HKDF-SHA256, Ed25519, P-256 ECDH) are well-established standards implemented by
   widely-audited crates (`ed25519-dalek`, `p256`, `hkdf`), the composition and protocol
   design of this crate has not been independently reviewed.

## API Reference

### Fixed Point

| Function | Returns | Description |
|----------|---------|-------------|
| `fixed_point_uncompressed()` | `Vec<u8>` (65 bytes) | `04 \|\| X \|\| Y` — for Android `KeyAgreement`, iOS `SecKey` |
| `fixed_point_xy()` | `Vec<u8>` (64 bytes) | `X \|\| Y` — for APIs taking separate coordinates |
| `fixed_point_compressed()` | `Vec<u8>` (33 bytes) | `02/03 \|\| X` — compressed SEC1 format |

### Key Derivation

| Function | Returns | Description |
|----------|---------|-------------|
| `derive_public_key(secret, chain)` | `Vec<u8>` (32 bytes) | Raw Ed25519 public key |
| `derive_public_key_base58(secret, chain)` | `String` | Base58 — standard Solana address format |
| `derive_public_key_hex(secret, chain)` | `String` | Hex — standard Sui/Aptos format |
| `derive_all_builtin_keys(secret)` | `Vec<(Chain, String)>` | All 10 built-in chains at once |

### Signing

| Function | Returns | Description |
|----------|---------|-------------|
| `sign(secret, message, chain)` | `Vec<u8>` (64 bytes) | Ed25519 signature (key is zeroized after) |
| `verify(pubkey, message, signature)` | `Result<()>` | Verify an Ed25519 signature |

### Chains

Built-in: `Solana`, `Sui`, `Aptos`, `Sei`, `Stellar`, `Near`, `Cosmos`, `Polkadot`, `Cardano`, `Ton`

Custom: `Chain::Custom("your-app:your-chain:ed25519:v1".into())`

## Examples

```bash
# Print the fixed point in all formats + platform code snippets
cargo run --example fixed_point

# Derive addresses for all chains from a simulated ECDH secret
cargo run --example derive_addresses

# Sign a message and verify the signature
cargo run --example sign_and_verify
```

## Installation

```toml
[dependencies]
atlas-ecdh-bridge = "0.1"
```

Minimum Rust version: **1.70**

## How to Verify the Fixed Point Derivation

The fixed point is **not a random value** — it's derived deterministically so anyone can audit it:

```python
# Python verification (requires `ecdsa` package)
import hashlib
from ecdsa import NIST256p, numbertheory

domain = b"atlas:ecdh:p256:ed25519:derivation:v1"
h = hashlib.sha256(domain).digest()
scalar = int.from_bytes(h, 'big') % NIST256p.order
point = scalar * NIST256p.generator
print(f"X: {point.x():064x}")
print(f"Y: {point.y():064x}")
```

```javascript
// JavaScript verification (Node.js with `elliptic`)
const { ec: EC } = require('elliptic');
const crypto = require('crypto');
const curve = new EC('p256');
const hash = crypto.createHash('sha256')
    .update('atlas:ecdh:p256:ed25519:derivation:v1')
    .digest('hex');
const point = curve.g.mul(hash);
console.log('X:', point.getX().toString(16).padStart(64, '0'));
console.log('Y:', point.getY().toString(16).padStart(64, '0'));
```

Both should produce the same X/Y coordinates as `cargo run --example fixed_point`.

## Comparison to Alternatives

| Approach | Persistent Secret? | Hardware-Bound? | Multi-Chain? | Seed Phrase? |
|----------|-------------------|-----------------|-------------|-------------|
| BIP-39 mnemonic | Yes (seed on disk) | No | Yes | Yes |
| Atlas ECDH bridge (this crate) | **No** | **Yes** | **Yes** | **No** |
| MPC (Fireblocks, Lit, etc.) | Shares on servers | Partial | Yes | No |
| Social recovery (Argent) | Encrypted blob | No | Limited | Optional |
| Hardware wallet (Ledger) | On device chip | Yes | Yes | Yes (recovery) |

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE) 
- [MIT License](LICENSE-MIT)

at your option.

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

**This is cryptographic software.** While it uses well-established primitives
(HKDF-SHA256, Ed25519, P-256 ECDH) from widely-audited Rust crates, the
protocol composition — deriving Ed25519 keys from P-256 ECDH shared secrets —
is a novel construction that has **not been independently audited by a
third-party security firm**.

**Do not use this in production without a professional security audit.**

Loss of the passkey (and its sync credentials) means permanent loss of all
derived Ed25519 keys. There is no recovery mechanism at the cryptographic
layer — implement application-level recovery (social recovery, guardians,
multi-sig) before deploying to real users with real funds.

## Contributing

Contributions are welcome. Please open an issue first to discuss significant changes.

All contributions are dual-licensed under MIT/Apache-2.0 unless explicitly stated otherwise.
