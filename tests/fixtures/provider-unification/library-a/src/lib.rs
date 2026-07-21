use fast_floe::{Key, Parameters, Provider, Result, decrypt, encrypt};

const KEY_BYTES: [u8; Key::LEN] = [0x6a; Key::LEN];
const AAD: &[u8] = b"provider-unification";

pub fn encrypt_message(plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = Key::from_bytes_with_provider(KEY_BYTES, Provider::AWS_LC_RS);
    encrypt(&key, AAD, Parameters::SEGMENT_4_KIB, plaintext)
}

pub fn decrypt_message(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key = Key::from_bytes_with_provider(KEY_BYTES, Provider::AWS_LC_RS);
    decrypt(&key, AAD, ciphertext)
}
