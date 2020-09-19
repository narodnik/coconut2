use bls12_381 as bls;
use sha2::{Digest, Sha256};

use crate::aes::AesKey;

pub type ScanCode = [u8; 4];

pub fn derive_shared_secret(public_a: &bls::G1Projective, secret_b: &bls::Scalar) -> AesKey {
    let derived_key = public_a * secret_b;

    let mut hasher = Sha256::new();
    let data = bls::G1Affine::from(derived_key).to_compressed();
    hasher.input(&data[0..32]);
    hasher.input(&data[32..]);
    let shared_secret_result = hasher.result();

    // Rust is dumb. Sha256 and AesGcm libraries have incompatible classes called 'GenericArray'
    // We just store the intermediate values in fixed length arrays
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_secret_result[0..32]);
    shared_secret
}

pub fn create_scancode(shared_secret: &AesKey) -> ScanCode {
    let secret_hash = Sha256::digest(&shared_secret[..]);
    let mut scancode = [0u8; 4];
    scancode.copy_from_slice(&secret_hash[0..4]);
    scancode
}
