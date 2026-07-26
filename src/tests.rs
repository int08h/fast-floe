use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use crate::backends::ProviderRng;
use crate::low_level::{
    DecryptionState, EncryptionState, SharedDecryptionContext, SharedEncryptionContext,
    start_decryption, start_decryption_inferred, start_encryption,
};
use crate::online::{Decryptor, Encryptor};
use crate::{
    Error, HEADER_LENGTH, Header, Key, LengthRequirement, Parameters, Provider, SEGMENT_OVERHEAD,
    SegmentBuffer, SegmentFraming, SegmentKind, decrypt, decrypt_with_parameters, encrypt,
};

static KEY: Key = Key::from_bytes_with_provider([0; Key::LEN], Provider::COMPILED[0]);
const KAT_AAD: &[u8] = b"This is AAD";

#[test]
fn compiled_providers_match_features() {
    let expected = &[
        #[cfg(feature = "aws-lc-rs")]
        Provider::AWS_LC_RS,
        #[cfg(feature = "boring")]
        Provider::BORING,
        #[cfg(feature = "ring")]
        Provider::RING,
        #[cfg(feature = "rustcrypto")]
        Provider::RUSTCRYPTO,
    ];
    assert_eq!(Provider::COMPILED, expected);
    assert_eq!(
        Provider::COMPILED
            .iter()
            .map(|provider| provider.name())
            .collect::<Vec<_>>(),
        [
            #[cfg(feature = "aws-lc-rs")]
            "aws-lc-rs",
            #[cfg(feature = "boring")]
            "boring",
            #[cfg(feature = "ring")]
            "ring",
            #[cfg(feature = "rustcrypto")]
            "rustcrypto",
        ]
    );
    assert_eq!(
        Provider::build_default(),
        (Provider::COMPILED.len() == 1).then_some(Provider::COMPILED[0])
    );
}

#[test]
fn providers_construct_only_fixed_rng() {
    for &provider in Provider::COMPILED {
        let rng = ProviderRng::new(provider);
        let expected = if provider.name() == "rustcrypto" {
            "chacha12"
        } else {
            provider.name()
        };
        assert_eq!(rng.name(), expected);
    }
}

#[test]
fn implicit_keys_resolve_only_for_single_provider_builds() {
    let key = Key::from_bytes([0x21; Key::LEN]);
    if let Some(provider) = Provider::build_default() {
        assert_eq!(key.provider(), Ok(provider));
        assert_eq!(Key::generate().unwrap().provider(), Ok(provider));
        let ciphertext = encrypt(
            &key,
            b"implicit provider",
            Parameters::SEGMENT_4_KIB,
            b"message",
        )
        .unwrap();
        assert_eq!(
            decrypt(&key, b"implicit provider", &ciphertext).unwrap(),
            b"message"
        );
    } else {
        assert_eq!(key.provider(), Err(Error::ProviderSelectionRequired));
        assert!(matches!(
            Key::generate(),
            Err(Error::ProviderSelectionRequired)
        ));
    }
}

#[test]
fn explicit_provider_preserved_by_keys_and_states() {
    for &provider in Provider::COMPILED {
        let key = Key::from_bytes_with_provider([0x32; Key::LEN], provider);
        assert_eq!(key.provider(), Ok(provider));
        assert_eq!(key.clone().provider(), Ok(provider));
        assert_eq!(
            Key::generate_with_provider(provider).unwrap().provider(),
            Ok(provider)
        );

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

        for &decrypt_provider in Provider::COMPILED {
            let decrypt_key = Key::from_bytes_with_provider([0x43; Key::LEN], decrypt_provider);
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
    if Provider::build_default().is_some() {
        return;
    }

    let key = Key::from_bytes([0; Key::LEN]);
    let parameters = Parameters::SEGMENT_4_KIB;
    let aad = b"ambiguous provider";
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

    let ciphertext = encrypt(&KEY, aad, parameters, b"message").unwrap();
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

    let encryption_error =
        crate::io::EncryptWriter::new(Vec::new(), &key, aad, parameters).unwrap_err();
    assert_eq!(encryption_error.kind(), std::io::ErrorKind::Other);
    assert!(matches!(
        encryption_error
            .get_ref()
            .and_then(|source| source.downcast_ref::<Error>()),
        Some(Error::ProviderSelectionRequired)
    ));

    let decryption_error =
        crate::io::DecryptReader::new(std::io::Cursor::new(ciphertext.clone()), &key, aad)
            .unwrap_err();
    assert_eq!(decryption_error.kind(), std::io::ErrorKind::InvalidData);
    assert!(matches!(
        decryption_error
            .get_ref()
            .and_then(|source| source.downcast_ref::<Error>()),
        Some(Error::ProviderSelectionRequired)
    ));

    let random_access_error =
        crate::random_access::Reader::new(std::io::Cursor::new(ciphertext), &key, aad).unwrap_err();
    assert_eq!(random_access_error.kind(), std::io::ErrorKind::InvalidData);
    assert!(matches!(
        random_access_error
            .get_ref()
            .and_then(|source| source.downcast_ref::<Error>()),
        Some(Error::ProviderSelectionRequired)
    ));

    let message = Error::ProviderSelectionRequired.to_string();
    for provider in Provider::COMPILED {
        assert!(message.contains(provider.name()));
    }
    assert!(message.contains("Key::from_bytes_with_provider"));
    assert!(message.contains("Key::generate_with_provider"));
}

#[test]
fn parameter_encoding_matches_specification() {
    assert_eq!(
        Parameters::SEGMENT_4_KIB.encode(),
        hex::decode("00000000100000000020").unwrap().as_slice()
    );
    assert_eq!(
        Parameters::SEGMENT_1_MIB.encode(),
        hex::decode("00000010000000000020").unwrap().as_slice()
    );
    assert_eq!(
        Parameters::SEGMENT_4_KIB.ciphertext_segment_length(),
        4 * 1024
    );
    assert_eq!(
        Parameters::SEGMENT_1_MIB.ciphertext_segment_length(),
        1024 * 1024
    );
}

#[test]
fn parameters_accept_exactly_valid_segment_lengths() {
    let valid_range = Parameters::VALID_SEGMENT_LENGTHS;
    let first_valid = valid_range.start;
    let last_valid = valid_range.end - 1;

    for segment_length in [
        first_valid,
        first_valid + 1,
        4 * 1024,
        64 * 1024,
        1_000_000,
        1024 * 1024,
        last_valid,
    ] {
        assert!(valid_range.contains(&segment_length));

        let parameters = Parameters::from_segment_length(segment_length).unwrap();
        assert_eq!(
            parameters.ciphertext_segment_length(),
            usize::try_from(segment_length).unwrap()
        );
        assert_eq!(Parameters::decode(parameters.encode()), Ok(parameters));
    }

    for segment_length in [0, first_valid - 1, valid_range.end, u32::MAX] {
        assert!(!valid_range.contains(&segment_length));
        assert_eq!(
            Parameters::from_segment_length(segment_length),
            Err(Error::InvalidParameters)
        );

        let mut encoded = Parameters::SEGMENT_4_KIB.encode();
        encoded[2..6].copy_from_slice(&segment_length.to_be_bytes());
        assert!(Parameters::decode(encoded).is_err());
    }
}

#[test]
fn typed_headers_support_strict_and_inferred_decryption() {
    let plaintext = b"header-selected parameters";
    let ciphertext = encrypt(
        &KEY,
        b"header inference",
        Parameters::SEGMENT_1_MIB,
        plaintext,
    )
    .unwrap();
    let header = Header::try_from(&ciphertext[..Header::LEN]).unwrap();

    assert_eq!(Header::LEN, HEADER_LENGTH);
    assert_eq!(
        header.unverified_parameters().unwrap(),
        Parameters::SEGMENT_1_MIB
    );
    assert_eq!(
        start_decryption_inferred(&KEY, b"header inference", &header)
            .unwrap()
            .parameters(),
        Parameters::SEGMENT_1_MIB
    );
    assert_eq!(
        decrypt(&KEY, b"header inference", &ciphertext).unwrap(),
        plaintext
    );

    let mut changed_parameters = ciphertext.clone();
    changed_parameters[..crate::ENCODED_PARAMETERS_LENGTH]
        .copy_from_slice(&Parameters::SEGMENT_4_KIB.encode());
    let changed_header = Header::try_from(&changed_parameters[..Header::LEN]).unwrap();
    assert_eq!(
        changed_header.unverified_parameters().unwrap(),
        Parameters::SEGMENT_4_KIB
    );
    assert_eq!(
        decrypt(&KEY, b"header inference", &changed_parameters),
        Err(Error::InvalidHeaderTag)
    );

    let mut unsupported = <[u8; Header::LEN]>::from(header);
    unsupported[0] = 1;
    let unsupported = Header::from(unsupported);
    assert_eq!(
        unsupported.unverified_parameters(),
        Err(Error::InvalidHeaderParameters)
    );
    assert!(matches!(
        start_decryption_inferred(&KEY, b"header inference", &unsupported),
        Err(Error::InvalidHeaderParameters)
    ));
}

#[test]
fn message_layouts_cover_plaintext_boundaries() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let plaintext_segment_length = u64::try_from(parameters.plaintext_segment_length()).unwrap();
    let ciphertext_segment_length = u64::try_from(parameters.ciphertext_segment_length()).unwrap();
    let header_length = u64::try_from(HEADER_LENGTH).unwrap();
    let overhead = u64::try_from(SEGMENT_OVERHEAD).unwrap();

    for plaintext_length in [
        0,
        1,
        plaintext_segment_length - 1,
        plaintext_segment_length,
        plaintext_segment_length + 1,
        2 * plaintext_segment_length,
        2 * plaintext_segment_length + 7,
    ] {
        let layout = parameters.plaintext_layout(plaintext_length).unwrap();
        let expected_count = if plaintext_length == 0 {
            1
        } else {
            (plaintext_length - 1) / plaintext_segment_length + 1
        };
        assert_eq!(layout.parameters(), parameters);
        assert_eq!(layout.plaintext_length(), plaintext_length);
        assert_eq!(layout.segment_count(), expected_count);
        assert_eq!(
            layout.ciphertext_length(),
            header_length + plaintext_length + expected_count * overhead
        );
        assert_eq!(
            parameters
                .ciphertext_layout(layout.ciphertext_length())
                .unwrap(),
            layout
        );

        let segments: Vec<_> = layout.segments().collect();
        assert_eq!(u64::try_from(segments.len()).unwrap(), expected_count);
        assert_eq!(layout.into_iter().collect::<Vec<_>>(), segments);
        assert_eq!(
            layout.segments().next_back(),
            layout.segment_for_position(expected_count - 1)
        );

        for segment in segments {
            let position = segment.position();
            assert_eq!(Some(segment), layout.segment_for_position(position));
            assert_eq!(segment.position(), position);
            assert_eq!(
                segment.plaintext_offset(),
                position * plaintext_segment_length
            );
            assert_eq!(
                segment.ciphertext_offset(),
                header_length + position * ciphertext_segment_length
            );
            assert_eq!(
                u64::try_from(segment.ciphertext_length()).unwrap(),
                u64::try_from(segment.plaintext_length()).unwrap() + overhead
            );
            assert_eq!(segment.is_final(), position + 1 == expected_count);
            assert_eq!(
                segment.kind(),
                if segment.is_final() {
                    SegmentKind::Final
                } else {
                    SegmentKind::NonFinal
                }
            );
        }
        assert_eq!(layout.segment_for_position(layout.segment_count()), None);
    }
}

#[test]
fn message_layouts_enforce_length_and_segment_limits() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let plaintext_segment_length = u64::try_from(parameters.plaintext_segment_length()).unwrap();
    let maximum_plaintext_length = crate::AEAD_MAX_SEGMENTS * plaintext_segment_length;
    let maximum = parameters
        .plaintext_layout(maximum_plaintext_length)
        .unwrap();
    assert_eq!(maximum.segment_count(), crate::AEAD_MAX_SEGMENTS);
    assert!(
        maximum
            .segment_for_position(crate::AEAD_MAX_SEGMENTS - 1)
            .unwrap()
            .is_final()
    );
    assert_eq!(
        parameters.plaintext_layout(maximum_plaintext_length + 1),
        Err(Error::SegmentLimit)
    );
    assert_eq!(
        parameters.ciphertext_layout(maximum.ciphertext_length() + 1),
        Err(Error::SegmentLimit)
    );

    let header_length = u64::try_from(HEADER_LENGTH).unwrap();
    let overhead = u64::try_from(SEGMENT_OVERHEAD).unwrap();
    assert!(matches!(
        parameters.ciphertext_layout(header_length - 1),
        Err(Error::InvalidHeaderLength { .. })
    ));
    assert_eq!(
        parameters.ciphertext_layout(header_length),
        Err(Error::Truncated)
    );
    assert!(matches!(
        parameters.ciphertext_layout(header_length + overhead - 1),
        Err(Error::InvalidCiphertextLength { .. })
    ));
    assert_eq!(
        parameters
            .ciphertext_layout(header_length + overhead)
            .unwrap(),
        parameters.plaintext_layout(0).unwrap()
    );
}

#[test]
fn ciphertext_layout_accepts_length_valid_empty_final_segment() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let header_length = u64::try_from(HEADER_LENGTH).unwrap();
    let ciphertext_segment_length = u64::try_from(parameters.ciphertext_segment_length()).unwrap();
    let overhead = u64::try_from(SEGMENT_OVERHEAD).unwrap();
    let ciphertext_length = header_length + ciphertext_segment_length + overhead;

    let layout = parameters.ciphertext_layout(ciphertext_length).unwrap();
    assert_eq!(layout.segment_count(), 2);
    assert_eq!(
        layout.plaintext_length(),
        u64::try_from(parameters.plaintext_segment_length()).unwrap()
    );

    let first = layout.segment_for_position(0).unwrap();
    assert!(!first.is_final());
    assert_eq!(
        first.ciphertext_length(),
        parameters.ciphertext_segment_length()
    );
    assert_eq!(
        first.plaintext_length(),
        parameters.plaintext_segment_length()
    );

    let final_segment = layout.segment_for_position(1).unwrap();
    assert!(final_segment.is_final());
    assert_eq!(final_segment.plaintext_length(), 0);
    assert_eq!(final_segment.ciphertext_length(), SEGMENT_OVERHEAD);

    let canonical = parameters
        .plaintext_layout(layout.plaintext_length())
        .unwrap();
    assert_eq!(canonical.segment_count(), 1);
    assert_ne!(canonical.ciphertext_length(), ciphertext_length);
}

#[test]
fn segment_prefix_classification_exposes_valid_framing() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let non_final = SegmentFraming::decode(parameters, u32::MAX.to_be_bytes()).unwrap();
    assert_eq!(non_final.kind(), SegmentKind::NonFinal);
    assert!(!non_final.is_final());
    assert_eq!(
        non_final.ciphertext_length(),
        parameters.ciphertext_segment_length()
    );
    assert_eq!(
        non_final.plaintext_length(),
        parameters.plaintext_segment_length()
    );

    for encrypted_length in [
        SEGMENT_OVERHEAD,
        SEGMENT_OVERHEAD + 7,
        parameters.ciphertext_segment_length(),
    ] {
        let prefix = u32::try_from(encrypted_length).unwrap().to_be_bytes();
        let final_segment = SegmentFraming::decode(parameters, prefix).unwrap();
        assert_eq!(final_segment.kind(), SegmentKind::Final);
        assert!(final_segment.is_final());
        assert_eq!(final_segment.ciphertext_length(), encrypted_length);
        assert_eq!(
            final_segment.plaintext_length(),
            encrypted_length - SEGMENT_OVERHEAD
        );
    }

    for invalid in [
        SEGMENT_OVERHEAD - 1,
        parameters.ciphertext_segment_length() + 1,
    ] {
        let prefix = u32::try_from(invalid).unwrap().to_be_bytes();
        assert!(matches!(
            SegmentFraming::decode(parameters, prefix),
            Err(Error::InvalidCiphertextLength { .. })
        ));
    }
    assert_eq!(
        crate::SEGMENT_PAYLOAD_OFFSET,
        crate::SEGMENT_PREFIX_LENGTH + crate::AEAD_IV_LENGTH
    );
}

#[test]
fn segment_framing_rejects_prefix_whose_low_bits_look_valid() {
    let parameters = Parameters::SEGMENT_4_KIB;
    for forged in [69_632_u32, 1_048_576 + 4_096] {
        assert!(matches!(
            SegmentFraming::decode(parameters, forged.to_be_bytes()),
            Err(Error::InvalidCiphertextLength { .. })
        ));
    }
}

#[test]
fn final_segment_prefix_must_equal_actual_segment_length() {
    // This drives `decrypt_segment_at` directly because
    // `SegmentFraming::decode` would reject the prefix before
    // `validate_segment` is exercised on the online path.
    let parameters = Parameters::SEGMENT_4_KIB;
    let (mut encryption, header) =
        start_encryption(&KEY, b"forged final prefix", parameters).unwrap();
    let layout = parameters.plaintext_layout(4).unwrap();
    let mut segment = encryption
        .encrypt_segment(b"last", layout.final_segment())
        .unwrap();
    let true_length = u32::try_from(segment.len()).unwrap();
    let forged = true_length | 0x0001_0000;
    segment[..crate::SEGMENT_PREFIX_LENGTH].copy_from_slice(&forged.to_be_bytes());

    let mut decryption =
        start_decryption(&KEY, b"forged final prefix", parameters, &header).unwrap();
    let error = decryption
        .decrypt_segment_at(&segment, 0, SegmentKind::Final)
        .unwrap_err();

    assert!(matches!(
        error,
        Error::InvalidCiphertextLength {
            actual,
            required: LengthRequirement::Exactly(required),
        } if actual == segment.len() && required == segment.len() + 0x1_0000
    ));
}

#[test]
fn complete_message_round_trips_boundaries() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let segment_length = parameters.plaintext_segment_length();
    for length in [
        0,
        1,
        segment_length - 1,
        segment_length,
        segment_length + 1,
        2 * segment_length,
        2 * segment_length + 3,
    ] {
        let plaintext: Vec<u8> = (0..length)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        let ciphertext = encrypt(&KEY, b"aad", parameters, &plaintext).unwrap();
        assert_eq!(
            decrypt(&KEY, b"aad", &ciphertext).unwrap(),
            plaintext,
            "round trip failed at length {length}"
        );
    }
}

#[test]
fn complete_message_decrypts_full_non_final_and_empty_final_segments() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let plaintext = vec![0x5a; parameters.plaintext_segment_length()];
    let mut encryption = Encryptor::new(&KEY, b"alternate framing", parameters).unwrap();
    let header = *encryption.header();
    let non_final = encryption.encrypt_non_final_segment(&plaintext).unwrap();
    let final_segment = encryption.encrypt_final_segment(b"").unwrap();

    let mut ciphertext = Vec::with_capacity(Header::LEN + non_final.len() + final_segment.len());
    ciphertext.extend_from_slice(header.as_ref());
    ciphertext.extend_from_slice(&non_final);
    ciphertext.extend_from_slice(&final_segment);

    let layout = parameters
        .ciphertext_layout(u64::try_from(ciphertext.len()).unwrap())
        .unwrap();
    assert_eq!(layout.segment_count(), 2);
    assert_eq!(
        decrypt(&KEY, b"alternate framing", &ciphertext).unwrap(),
        plaintext
    );
}

#[test]
fn random_access_segments_decrypt_out_of_order() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let full = vec![0x5a; parameters.plaintext_segment_length()];
    let final_plaintext = b"final";
    let layout = parameters
        .plaintext_layout(u64::try_from(full.len() + final_plaintext.len()).unwrap())
        .unwrap();
    let segment_zero_layout = layout.segment_for_position(0).unwrap();
    let segment_one_layout = layout.segment_for_position(1).unwrap();
    let (mut encryption, header) = start_encryption(&KEY, b"random access", parameters).unwrap();
    let segment_zero = encryption
        .encrypt_segment(&full, segment_zero_layout)
        .unwrap();
    let segment_one = encryption
        .encrypt_segment(final_plaintext, segment_one_layout)
        .unwrap();

    let mut decryption = start_decryption(&KEY, b"random access", parameters, &header).unwrap();
    assert_eq!(
        decryption
            .decrypt_segment(&segment_one, segment_one_layout)
            .unwrap(),
        final_plaintext
    );
    assert_eq!(
        decryption
            .decrypt_segment(&segment_zero, segment_zero_layout)
            .unwrap(),
        full
    );
}

#[test]
fn parallel_contexts_create_independent_states() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<EncryptionState>();
    assert_send::<DecryptionState>();
    assert_send::<SharedEncryptionContext>();
    assert_sync::<SharedEncryptionContext>();
    assert_send::<SharedDecryptionContext>();
    assert_sync::<SharedDecryptionContext>();

    let parameters = Parameters::SEGMENT_4_KIB;
    let segment_length = parameters.plaintext_segment_length();
    let plaintext_segments: Vec<Vec<u8>> = (0..8)
        .map(|position| {
            let length = if position == 7 { 17 } else { segment_length };
            vec![u8::try_from(position).unwrap(); length]
        })
        .collect();
    let layout = parameters
        .plaintext_layout(
            plaintext_segments
                .iter()
                .map(|segment| u64::try_from(segment.len()).unwrap())
                .sum(),
        )
        .unwrap();

    let (encryption, header) = start_encryption(&KEY, b"parallel states", parameters).unwrap();
    let encryption = encryption.into_shared();
    assert_eq!(encryption.parameters(), parameters);
    let encrypted_segments: Vec<Vec<u8>> = plaintext_segments
        .par_iter()
        .enumerate()
        .map_init(
            || encryption.fork(),
            |state, (position, plaintext)| {
                assert_eq!(state.parameters(), parameters);
                let segment = layout
                    .segment_for_position(u64::try_from(position).unwrap())
                    .unwrap();
                state.encrypt_segment(plaintext, segment)
            },
        )
        .collect::<crate::Result<_>>()
        .unwrap();

    let decryption = start_decryption(&KEY, b"parallel states", parameters, &header).unwrap();
    let decryption = decryption.into_shared();
    assert_eq!(decryption.parameters(), parameters);
    let decrypted_segments: Vec<Vec<u8>> = encrypted_segments
        .par_iter()
        .enumerate()
        .map_init(
            || decryption.fork(),
            |state, (position, encrypted)| {
                assert_eq!(state.parameters(), parameters);
                let segment = layout
                    .segment_for_position(u64::try_from(position).unwrap())
                    .unwrap();
                state.decrypt_segment(encrypted, segment)
            },
        )
        .collect::<crate::Result<_>>()
        .unwrap();

    assert_eq!(decrypted_segments, plaintext_segments);
}

#[test]
fn rotation_and_position_boundaries_match_specification() {
    const ROTATION_INTERVAL: u64 = 1 << 20;

    let parameters = Parameters::SEGMENT_4_KIB;
    assert_eq!(parameters.masked_position(ROTATION_INTERVAL - 1), 0);
    assert_eq!(
        parameters.masked_position(ROTATION_INTERVAL),
        ROTATION_INTERVAL
    );
    assert_eq!(
        parameters.masked_position(crate::AEAD_MAX_SEGMENTS - 1),
        crate::AEAD_MAX_SEGMENTS - ROTATION_INTERVAL
    );

    let (mut encryption, header) =
        start_encryption(&KEY, b"position boundaries", parameters).unwrap();
    let before_rotation = encryption
        .encrypt_segment_at(b"before", ROTATION_INTERVAL - 1, SegmentKind::Final)
        .unwrap();
    let after_rotation = encryption
        .encrypt_segment_at(b"after", ROTATION_INTERVAL, SegmentKind::Final)
        .unwrap();
    let last_position = encryption
        .encrypt_segment_at(b"last", crate::AEAD_MAX_SEGMENTS - 1, SegmentKind::Final)
        .unwrap();
    assert_eq!(
        encryption.encrypt_segment_at(b"past", crate::AEAD_MAX_SEGMENTS, SegmentKind::Final),
        Err(Error::SegmentLimit)
    );

    let mut decryption =
        start_decryption(&KEY, b"position boundaries", parameters, &header).unwrap();
    assert_eq!(
        decryption
            .decrypt_segment_at(&before_rotation, ROTATION_INTERVAL - 1, SegmentKind::Final,)
            .unwrap(),
        b"before"
    );
    assert_eq!(
        decryption
            .decrypt_segment_at(&after_rotation, ROTATION_INTERVAL, SegmentKind::Final)
            .unwrap(),
        b"after"
    );
    assert_eq!(
        decryption
            .decrypt_segment_at(
                &last_position,
                crate::AEAD_MAX_SEGMENTS - 1,
                SegmentKind::Final,
            )
            .unwrap(),
        b"last"
    );
    assert_eq!(
        decryption
            .decrypt_segment_at(&last_position, crate::AEAD_MAX_SEGMENTS, SegmentKind::Final,),
        Err(Error::SegmentLimit)
    );
}

#[test]
fn batched_nonces_remain_unique_across_refills() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let plaintext = vec![0x5a; parameters.plaintext_segment_length()];
    let mut encrypted = vec![0u8; parameters.ciphertext_segment_length()];
    let (mut encryption, _) = start_encryption(&KEY, b"nonce batches", parameters).unwrap();
    let mut nonces = HashSet::new();

    for position in 0..130 {
        encryption
            .encrypt_segment_into_at(&plaintext, position, SegmentKind::NonFinal, &mut encrypted)
            .unwrap();
        let nonce: [u8; crate::AEAD_IV_LENGTH] = encrypted
            [crate::SEGMENT_PREFIX_LENGTH..crate::SEGMENT_PREFIX_LENGTH + crate::AEAD_IV_LENGTH]
            .try_into()
            .unwrap();
        assert!(
            nonces.insert(nonce),
            "nonce repeated at position {position}"
        );
    }
}

#[test]
fn online_state_enforces_finalization() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let encryption = Encryptor::new(&KEY, b"aad", parameters).unwrap();
    assert_eq!(encryption.next_position(), 0);
    let header = *encryption.header();
    let final_segment = encryption.encrypt_final_segment(b"done").unwrap();

    let decryption = Decryptor::new(&KEY, b"aad", &header).unwrap();
    assert_eq!(decryption.finish(), Err(Error::Truncated));

    let mut decryption = Decryptor::new(&KEY, b"aad", &header).unwrap();
    assert_eq!(decryption.decrypt_segment(&final_segment).unwrap(), b"done");
    assert!(decryption.is_finished());
    assert_eq!(
        decryption.decrypt_segment(&final_segment),
        Err(Error::Closed)
    );
    assert!(decryption.finish().is_ok());

    let mut decryption = Decryptor::new(&KEY, b"aad", &header).unwrap();
    assert_eq!(decryption.next_position(), 0);
    let mut too_small = [0u8; 3];
    assert!(matches!(
        decryption.decrypt_segment_into(&final_segment, &mut too_small),
        Err(Error::OutputTooSmall { .. })
    ));
    let mut output = [0u8; 4];
    assert_eq!(
        decryption
            .decrypt_segment_into(&final_segment, &mut output)
            .unwrap(),
        output.len()
    );
    assert_eq!(&output, b"done");
    assert!(decryption.finish().is_ok());

    let mut invalid_prefix = [0u8; SEGMENT_OVERHEAD];
    invalid_prefix[..crate::SEGMENT_PREFIX_LENGTH]
        .copy_from_slice(&u32::try_from(SEGMENT_OVERHEAD - 1).unwrap().to_be_bytes());
    let mut decryption = Decryptor::new(&KEY, b"aad", &header).unwrap();
    assert!(matches!(
        decryption.decrypt_segment(&invalid_prefix),
        Err(Error::InvalidCiphertextLength {
            actual,
            required: LengthRequirement::Between {..},
        }) if actual == SEGMENT_OVERHEAD - 1
    ));

    let encryption = Encryptor::new(&KEY, b"aad", parameters).unwrap();
    let header = *encryption.header();
    let mut in_place = SegmentBuffer::new(parameters);
    in_place
        .prepare_plaintext(4)
        .unwrap()
        .copy_from_slice(b"done");
    encryption
        .encrypt_final_segment_in_place(&mut in_place)
        .unwrap();
    let mut decryption = Decryptor::new(&KEY, b"aad", &header).unwrap();
    assert_eq!(
        decryption.decrypt_segment_in_place(&mut in_place).unwrap(),
        b"done"
    );
    assert!(decryption.finish().is_ok());
}

#[test]
fn failed_final_encryption_returns_reusable_state() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let encryption = Encryptor::new(&KEY, b"recover final", parameters).unwrap();
    let header = *encryption.header();
    let mut too_small = [0u8; SEGMENT_OVERHEAD];

    let failure = encryption
        .encrypt_final_segment_into(b"retry", &mut too_small)
        .unwrap_err();
    assert!(matches!(failure.error(), Error::OutputTooSmall { .. }));
    assert!(!format!("{failure:?}").contains("Encryptor"));

    let encryption = failure.into_encryptor();
    assert_eq!(encryption.header(), &header);
    assert_eq!(encryption.next_position(), 0);
    let encrypted = encryption.encrypt_final_segment(b"retry").unwrap();

    let mut decryption = Decryptor::new(&KEY, b"recover final", &header).unwrap();
    assert_eq!(decryption.decrypt_segment(&encrypted).unwrap(), b"retry");
    decryption.finish().unwrap();
}

#[test]
fn into_apis_validate_buffers_and_write_exact_lengths() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let segment = parameters
        .plaintext_layout(3)
        .unwrap()
        .segment_for_position(0)
        .unwrap();
    let (mut encryption, header) = start_encryption(&KEY, b"", parameters).unwrap();
    let wrong_profile_segment = Parameters::SEGMENT_1_MIB
        .plaintext_layout(3)
        .unwrap()
        .segment_for_position(0)
        .unwrap();
    assert_eq!(
        encryption.encrypt_segment(b"abc", wrong_profile_segment),
        Err(Error::InvalidParameters)
    );
    assert_eq!(
        encryption.encrypt_segment(b"ab", segment),
        Err(Error::InvalidPlaintextLength {
            actual: 2,
            required: LengthRequirement::Exactly(3),
        })
    );
    let mut too_small = [0u8; SEGMENT_OVERHEAD + 2];
    assert!(matches!(
        encryption.encrypt_segment_into(b"abc", segment, &mut too_small[..SEGMENT_OVERHEAD + 2]),
        Err(Error::OutputTooSmall { .. })
    ));

    let mut encrypted = [0u8; SEGMENT_OVERHEAD + 3];
    let encrypted_length = encryption
        .encrypt_segment_into(b"abc", segment, &mut encrypted)
        .unwrap();
    assert_eq!(encrypted_length, SEGMENT_OVERHEAD + 3);

    let mut decryption = start_decryption(&KEY, b"", parameters, &header).unwrap();
    let mut plaintext = [0u8; 3];
    assert_eq!(
        decryption
            .decrypt_segment_into(&encrypted[..encrypted_length], segment, &mut plaintext,)
            .unwrap(),
        3
    );
    assert_eq!(&plaintext, b"abc");

    let (mut encryption, header) = start_encryption(&KEY, b"", parameters).unwrap();
    let mut in_place = SegmentBuffer::new(parameters);
    in_place
        .prepare_plaintext(3)
        .unwrap()
        .copy_from_slice(b"abc");
    assert_eq!(
        encryption
            .encrypt_segment_in_place(&mut in_place, segment)
            .unwrap()
            .len(),
        SEGMENT_OVERHEAD + 3
    );
    let mut tampered = SegmentBuffer::new(parameters);
    tampered
        .prepare_ciphertext(SEGMENT_OVERHEAD + 3)
        .unwrap()
        .copy_from_slice(in_place.ciphertext().unwrap());
    *tampered
        .prepare_ciphertext(SEGMENT_OVERHEAD + 3)
        .unwrap()
        .last_mut()
        .unwrap() ^= 1;
    let mut rejecting_decryption = start_decryption(&KEY, b"", parameters, &header).unwrap();
    assert_eq!(
        rejecting_decryption.decrypt_segment_in_place(&mut tampered, segment),
        Err(Error::AuthenticationFailed)
    );
    let mut decryption = start_decryption(&KEY, b"", parameters, &header).unwrap();
    assert_eq!(
        decryption
            .decrypt_segment_in_place(&mut in_place, segment)
            .unwrap(),
        b"abc"
    );
}

#[test]
fn authentication_and_framing_fail_closed() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let ciphertext = encrypt(&KEY, b"correct aad", parameters, b"plaintext").unwrap();

    assert_eq!(
        decrypt(&KEY, b"wrong aad", &ciphertext),
        Err(Error::InvalidHeaderTag)
    );
    assert!(matches!(
        Header::try_from(&ciphertext[..HEADER_LENGTH - 1]),
        Err(Error::InvalidHeaderLength { .. })
    ));
    assert!(matches!(
        Header::try_from(&ciphertext[..=HEADER_LENGTH]),
        Err(Error::InvalidHeaderLength { .. })
    ));

    let mut bad_header = ciphertext.clone();
    bad_header[HEADER_LENGTH - 1] ^= 1;
    assert_eq!(
        decrypt(&KEY, b"correct aad", &bad_header),
        Err(Error::InvalidHeaderTag)
    );

    let mut bad_segment = ciphertext.clone();
    *bad_segment.last_mut().unwrap() ^= 1;
    assert_eq!(
        decrypt(&KEY, b"correct aad", &bad_segment),
        Err(Error::AuthenticationFailed)
    );

    let header_only = &ciphertext[..HEADER_LENGTH];
    assert_eq!(
        decrypt(&KEY, b"correct aad", header_only),
        Err(Error::Truncated)
    );

    let truncated = &ciphertext[..ciphertext.len() - 1];
    assert_eq!(
        decrypt(&KEY, b"correct aad", truncated),
        Err(Error::InvalidCiphertextLength {
            actual: truncated.len() - HEADER_LENGTH,
            required: LengthRequirement::AtLeast(ciphertext.len() - HEADER_LENGTH)
        })
    );

    let mut undersized_final = header_only.to_vec();
    undersized_final.extend_from_slice(&4_u32.to_be_bytes());
    assert!(matches!(
        decrypt(&KEY, b"correct aad", &undersized_final),
        Err(Error::InvalidCiphertextLength { .. })
    ));
}

#[test]
fn every_truncation_of_valid_ciphertext_rejected() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let plaintext = vec![0x3c; 3 * parameters.plaintext_segment_length() + 7];
    let ciphertext = encrypt(&KEY, b"aad", parameters, &plaintext).unwrap();

    for end in 0..ciphertext.len() {
        assert!(
            decrypt(&KEY, b"aad", &ciphertext[..end]).is_err(),
            "accepted ciphertext truncated to {end} bytes"
        );
    }

    assert_eq!(
        decrypt_with_parameters(&KEY, b"aad", Parameters::SEGMENT_1_MIB, &ciphertext,),
        Err(Error::InvalidHeaderParameters)
    );
}

#[test]
fn position_and_final_indicator_authenticated() {
    let parameters = Parameters::SEGMENT_4_KIB;
    let (mut encryption, header) = start_encryption(&KEY, b"", parameters).unwrap();
    let segment_bytes = encryption
        .encrypt_segment_at(b"data", 5, SegmentKind::Final)
        .unwrap();

    let mut decryption = start_decryption(&KEY, b"", parameters, &header).unwrap();
    assert_eq!(
        decryption.decrypt_segment_at(&segment_bytes, 6, SegmentKind::Final),
        Err(Error::AuthenticationFailed)
    );

    let mut decryption = start_decryption(&KEY, b"", parameters, &header).unwrap();
    let mut forged_non_final = vec![0u8; parameters.ciphertext_segment_length()];
    forged_non_final[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    forged_non_final[4..4 + segment_bytes.len() - 4].copy_from_slice(&segment_bytes[4..]);
    assert_eq!(
        decryption.decrypt_segment_at(&forged_non_final, 5, SegmentKind::NonFinal),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn generated_keys_have_required_size() {
    for &provider in Provider::COMPILED {
        assert_eq!(
            Key::generate_with_provider(provider)
                .unwrap()
                .as_bytes()
                .len(),
            Key::LEN
        );
    }
}

#[test]
fn every_kat_decrypts() {
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
        let actual_plaintext = decrypt_with_parameters(&KEY, KAT_AAD, parameters, &ciphertext)
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
