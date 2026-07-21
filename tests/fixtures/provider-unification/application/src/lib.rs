pub fn verify() {
    let plaintext = b"features unify; provider choices do not";

    let aws_ciphertext = provider_library_a::encrypt_message(plaintext).unwrap();
    assert_eq!(
        provider_library_b::decrypt_message(&aws_ciphertext).unwrap(),
        plaintext
    );

    let ring_ciphertext = provider_library_b::encrypt_message(plaintext).unwrap();
    assert_eq!(
        provider_library_a::decrypt_message(&ring_ciphertext).unwrap(),
        plaintext
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn both_libraries_keep_explicit_provider() {
        super::verify();
    }
}
