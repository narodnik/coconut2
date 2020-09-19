use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use bls12_381 as bls;

pub type AesKey = [u8; 32];
pub type Plaintext = Vec<u8>;
pub type Ciphertext = Vec<u8>;

pub fn aes_encrypt(
    shared_secret: &AesKey,
    ephem_public: &bls::G1Projective,
    plaintext: &[u8],
) -> Option<Ciphertext> {
    // Rust is gay, I need to convert to 'GenericArray' whatever the fuck that is...
    let key = GenericArray::from_slice(&shared_secret[..]);
    let cipher = Aes256Gcm::new(key);

    // 96-bits = 12 bytes; unique per message
    let ephem_public_bytes = bls::G1Affine::from(ephem_public).to_compressed();
    let nonce = GenericArray::from_slice(&ephem_public_bytes[..12]);

    let ciphertext = cipher.encrypt(nonce, plaintext);
    ciphertext.ok()
}

pub fn aes_decrypt(
    shared_secret: &AesKey,
    ephem_public: &bls::G1Projective,
    ciphertext: &Ciphertext,
) -> Option<Plaintext> {
    // Rust is gay, I need to convert to 'GenericArray' whatever the fuck that is...
    let key = GenericArray::from_slice(&shared_secret[..]);
    let cipher = Aes256Gcm::new(key);

    // 96-bits = 12 bytes; unique per message
    let ephem_public_bytes = bls::G1Affine::from(ephem_public).to_compressed();
    let nonce = GenericArray::from_slice(&ephem_public_bytes[..12]);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref());
    plaintext.ok()
}

#[test]
fn test_aes() {
    use crate::bls_extensions::BlsStringConversion;
    use crate::stealth::derive_shared_secret;

    let g1 = bls::G1Affine::generator();

    let titan_public = bls::G1Projective::from_string(
        "96ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7");

    let ephem_secret = bls::Scalar::from_string(
        "d8a053e0527b7197bd004086d5894b79ac6ed199153a269ae199b8c21762565d",
    );
    let ephem_public = g1 * ephem_secret;

    // Sender creates derived secret key
    let shared_secret = derive_shared_secret(&titan_public, &ephem_secret);

    let ciphertext = aes_encrypt(&shared_secret, &ephem_public, b"plaintext message").unwrap();

    let plaintext = aes_decrypt(&shared_secret, &ephem_public, &ciphertext).unwrap();
    // OK it works!
    assert_eq!(&plaintext, b"plaintext message");
}
