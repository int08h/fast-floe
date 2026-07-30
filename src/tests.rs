//! Cross-cutting test suites that exercise the crate's whole surface at
//! once and therefore belong to no single module: provider identity and
//! interoperability, provider-selection failures from every entry layer,
//! and KAT/specification conformance.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::crate_error;
use crate::key::test_key;
use crate::low_level::{start_decryption, start_encryption};
use crate::online::{Decryptor, Encryptor};
use crate::{Error, Header, Key, Parameters, Provider, decrypt, decrypt_with_parameters, encrypt};

const KAT_AAD: &[u8] = b"This is AAD";

#[test]
fn explicit_provider_preserved_by_keys_and_states() {
    // Given a key explicitly bound to each compiled provider
    for &provider in Provider::COMPILED {
        let key = Key::from_bytes_with_provider([0x32; Key::LEN], provider);

        // Then the key, its clones, and generated keys keep that binding
        assert_eq!(key.provider(), Ok(provider));
        assert_eq!(key.clone().provider(), Ok(provider));
        assert_eq!(
            Key::generate_with_provider(provider).unwrap().provider(),
            Ok(provider)
        );

        // When every state type is constructed from the key
        // Then each reports the same provider, including through shared
        // contexts and their forks
        let parameters = Parameters::SEGMENT_4_KIB;
        let encryptor = Encryptor::new(&key, b"provider identity", parameters).unwrap();
        assert_eq!(encryptor.provider(), provider);
        let header = *encryptor.header();

        let decryptor = Decryptor::new(&key, b"provider identity", &header).unwrap();
        assert_eq!(decryptor.provider(), provider);

        let (encryption, header) =
            start_encryption(&key, b"provider identity", parameters).unwrap();
        assert_eq!(encryption.provider(), provider);
        let encryption = encryption.into_shared();
        assert_eq!(encryption.provider(), provider);
        assert_eq!(encryption.fork().provider(), provider);

        let decryption = start_decryption(&key, b"provider identity", parameters, &header).unwrap();
        assert_eq!(decryption.provider(), provider);
        let decryption = decryption.into_shared();
        assert_eq!(decryption.provider(), provider);
        assert_eq!(decryption.fork().provider(), provider);
    }
}

#[test]
fn verify_providers_interoperate() {
    // Given a message encrypted by each compiled provider
    let plaintext = b"provider-independent FLOE ciphertext";
    for &encrypt_provider in Provider::COMPILED {
        let encrypt_key = Key::from_bytes_with_provider([0x43; Key::LEN], encrypt_provider);
        let ciphertext = encrypt(
            &encrypt_key,
            b"cross-provider",
            Parameters::SEGMENT_4_KIB,
            plaintext,
        )
        .unwrap();

        // When every compiled provider decrypts the same ciphertext
        for &decrypt_provider in Provider::COMPILED {
            let decrypt_key = Key::from_bytes_with_provider([0x43; Key::LEN], decrypt_provider);

            // Then each recovers the plaintext
            assert_eq!(
                decrypt(&decrypt_key, b"cross-provider", &ciphertext).unwrap(),
                plaintext,
                "{} encryption did not interoperate with {} decryption",
                encrypt_provider.name(),
                decrypt_provider.name()
            );
        }
    }
}

#[test]
fn ambiguous_keys_fail_from_every_entry_layer() {
    // Given a multi-provider build and a key with no explicit provider
    if Provider::build_default().is_some() {
        return;
    }
    let key = Key::from_bytes([0; Key::LEN]);
    let parameters = Parameters::SEGMENT_4_KIB;
    let aad = b"ambiguous provider";

    // When each encryption entry point uses the ambiguous key
    // Then each demands an explicit provider selection
    assert_eq!(key.provider(), Err(Error::ProviderSelectionRequired));
    assert!(matches!(
        encrypt(&key, aad, parameters, b"message"),
        Err(Error::ProviderSelectionRequired)
    ));
    assert!(matches!(
        Encryptor::new(&key, aad, parameters),
        Err(Error::ProviderSelectionRequired)
    ));
    assert!(matches!(
        start_encryption(&key, aad, parameters),
        Err(Error::ProviderSelectionRequired)
    ));

    // When each decryption entry point uses the ambiguous key on a valid
    // ciphertext, then each demands an explicit provider selection
    let ciphertext = encrypt(&test_key(), aad, parameters, b"message").unwrap();
    let header = Header::try_from(&ciphertext[..Header::LEN]).unwrap();
    assert_eq!(
        decrypt(&key, aad, &ciphertext),
        Err(Error::ProviderSelectionRequired)
    );
    assert!(matches!(
        Decryptor::new(&key, aad, &header),
        Err(Error::ProviderSelectionRequired)
    ));
    assert!(matches!(
        start_decryption(&key, aad, parameters, &header),
        Err(Error::ProviderSelectionRequired)
    ));

    // When the io and random-access layers use the ambiguous key
    // Then each wraps the same selection error in its io::Error
    let encryption_error =
        crate::io::EncryptWriter::new(Vec::new(), &key, aad, parameters).unwrap_err();
    assert_eq!(encryption_error.kind(), std::io::ErrorKind::Other);
    assert!(matches!(
        crate_error(&encryption_error),
        Some(Error::ProviderSelectionRequired)
    ));

    let decryption_error =
        crate::io::DecryptReader::new(std::io::Cursor::new(ciphertext.clone()), &key, aad)
            .unwrap_err();
    assert_eq!(decryption_error.kind(), std::io::ErrorKind::InvalidData);
    assert!(matches!(
        crate_error(&decryption_error),
        Some(Error::ProviderSelectionRequired)
    ));

    let random_access_error =
        crate::random_access::Reader::new(std::io::Cursor::new(ciphertext), &key, aad).unwrap_err();
    assert_eq!(random_access_error.kind(), std::io::ErrorKind::InvalidData);
    assert!(matches!(
        crate_error(&random_access_error),
        Some(Error::ProviderSelectionRequired)
    ));

    // Then the error message names every compiled provider and the
    // constructors that resolve the ambiguity
    let message = Error::ProviderSelectionRequired.to_string();
    for provider in Provider::COMPILED {
        assert!(message.contains(provider.name()));
    }
    assert!(message.contains("Key::from_bytes_with_provider"));
    assert!(message.contains("Key::generate_with_provider"));
}

#[test]
fn every_kat_decrypts() {
    // Given the vendored known-answer vectors; a published crate omits
    // them, which is tolerated only outside a repository checkout
    let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let kat_directory = manifest_directory.join("kats");
    if !kat_directory.exists() {
        assert!(
            manifest_directory.join(".cargo_vcs_info.json").is_file(),
            "KAT directory missing from repository checkout"
        );
        return;
    }

    let mut kat_names: Vec<String> = fs::read_dir(&kat_directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", kat_directory.display()))
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter_map(|file_name| {
            file_name
                .strip_suffix("_ct.txt")
                .filter(|name| {
                    name.ends_with("GCM256_IV256_1M")
                        || name.ends_with("GCM256_IV256_4K")
                        || name.ends_with("GCM256_IV256_64")
                        || name.ends_with("rotation")
                })
                .map(str::to_owned)
        })
        .collect();
    kat_names.sort();

    // Then every supported vector is present
    assert!(
        !kat_names.is_empty(),
        "no KATs found in {}",
        kat_directory.display()
    );
    assert_eq!(
        kat_names.len(),
        20,
        "expected every supported KAT in {}",
        kat_directory.display()
    );

    // When each vector's ciphertext is decrypted with its parameter set
    // Then the specified plaintext is recovered
    for name in kat_names {
        let parameters = if name.ends_with("GCM256_IV256_1M") {
            Parameters::SEGMENT_1_MIB
        } else if name.ends_with("GCM256_IV256_4K") {
            Parameters::SEGMENT_4_KIB
        } else if name.ends_with("GCM256_IV256_64") {
            Parameters::SEGMENT_64_B
        } else if name.ends_with("rotation") {
            Parameters::with_rotation_mask_for_test(40, !3).unwrap()
        } else {
            panic!("unrecognized KAT {name}");
        };

        let ciphertext = read_hex(&kat_directory.join(format!("{name}_ct.txt")));
        let expected_plaintext = read_hex(&kat_directory.join(format!("{name}_pt.txt")));
        let actual_plaintext =
            decrypt_with_parameters(&test_key(), KAT_AAD, parameters, &ciphertext)
                .unwrap_or_else(|error| panic!("KAT {name} failed: {error}"));

        assert_eq!(actual_plaintext, expected_plaintext, "KAT {name} mismatch");
    }
}

fn read_hex(path: &Path) -> Vec<u8> {
    let encoded = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    hex::decode(encoded.trim())
        .unwrap_or_else(|error| panic!("cannot decode {}: {error}", path.display()))
}
