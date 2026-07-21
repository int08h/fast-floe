use fast_floe::{Key, Parameters, Provider, Result, decrypt, encrypt};

const KEY_BYTES: [u8; Key::LEN] = [0x6a; Key::LEN];
const AAD: &[u8] = b"provider-unification";

pub fn encrypt_message(plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = Key::from_bytes_with_provider(KEY_BYTES, Provider::RING);
    encrypt(&key, AAD, Parameters::SEGMENT_4_KIB, plaintext)
}

pub fn decrypt_message(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key = Key::from_bytes_with_provider(KEY_BYTES, Provider::RING);
    decrypt(&key, AAD, ciphertext)
}
