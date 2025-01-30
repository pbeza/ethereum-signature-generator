// SPDX-License-Identifier: MIT
// Author: GitHub Copilot (prompted by Patrick)

use ethereum_types::{H160, H256};
use hex::encode;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use tiny_keccak::{Hasher, Keccak};

/// A struct that represents the components of a secp256k1 signature.
pub struct Signature {
    /// V component in Electrum format with chain-id replay protection.
    pub v: u8,
    /// R component of the signature.
    pub r: H256,
    /// S component of the signature.
    pub s: H256,
}

/// Signature encoded as RSV components
#[repr(C)]
pub struct EncodedSignature([u8; 65]);

/// Converts a `Signature` struct to an `EncodedSignature`.
pub fn from_rsv(signature: &Signature) -> EncodedSignature {
    let mut bytes = [0u8; 65];
    bytes[..32].copy_from_slice(signature.r.as_bytes());
    bytes[32..64].copy_from_slice(signature.s.as_bytes());
    bytes[64] = signature.v;
    EncodedSignature(bytes)
}

fn sign_ecdsa_recoverable(secret_key: &SecretKey, message: &H256) -> Signature {
    let secp = Secp256k1::new();
    let msg = Message::from_slice(message.as_bytes()).expect("32 bytes");
    let sig = secp.sign_ecdsa_recoverable(&msg, secret_key);
    let (rec_id, sig_bytes) = sig.serialize_compact();
    let r = H256::from_slice(&sig_bytes[0..32]);
    let s = H256::from_slice(&sig_bytes[32..64]);
    Signature {
        v: rec_id.to_i32() as u8 + 27, // Convert to 'Electrum' notation
        r,
        s,
    }
}

/// Derives the Ethereum address from the public key.
fn public_key_to_address(public_key: &PublicKey) -> H160 {
    let public_key = public_key.serialize_uncompressed();
    let hash = keccak256(&public_key[1..]); // Skip the first byte (0x04)
    H160::from_slice(&hash[12..]) // Take the last 20 bytes
}

/// Computes the Keccak-256 hash of the input bytes.
fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

fn main() {
    // Example secret key (do not use this in production)
    let secret_key = SecretKey::from_slice(
        &hex::decode("c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3").unwrap(),
    )
    .unwrap();
    let message = H256::from_low_u64_be(12345);

    // Sign the message
    let signature = sign_ecdsa_recoverable(&secret_key, &message);

    // Convert to EncodedSignature
    let encoded_signature = from_rsv(&signature);

    // Derive the public key from the secret key
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Derive the Ethereum address from the public key
    let address = public_key_to_address(&public_key);

    // Print the Ethereum address, message, v, r, s, and encoded signature in hex
    println!("Signer (Ethereum address): {:?}", address);
    println!("Message: {:?}", message);
    println!("v: {}", signature.v);
    println!("r: {:?}", signature.r);
    println!("s: {:?}", signature.s);
    println!("Encoded Signature: {}", encode(encoded_signature.0));
}
