#[cfg(not(any(
    feature = "rustcrypto",
    feature = "aws-lc-rs",
    feature = "boring",
    feature = "ring"
)))]
compile_error!("enable at least one FLOE provider: aws-lc-rs, boring, ring, or rustcrypto");

use crate::provider::ProviderKind;
use crate::{Provider, Result};

const KDF_MAX_OUTPUT_LENGTH: usize = 48;

fn validate_kdf_output_length<const N: usize>() -> crate::Result<()> {
    if N <= KDF_MAX_OUTPUT_LENGTH {
        Ok(())
    } else {
        Err(crate::Error::CryptoFailure)
    }
}

#[cfg(feature = "rustcrypto")]
mod aead_rustcrypto {
    use aes_gcm::Aes256Gcm;
    use aes_gcm::aead::inout::InOutBuf;
    use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
    use hmac::{Hmac, Mac};
    use sha2::Sha384;
    use zeroize::Zeroize;

    use crate::backends::validate_kdf_output_length;
    use crate::{AEAD_TAG_LENGTH, Error, Result};

    type HmacSha384 = Hmac<Sha384>;

    pub(crate) struct AeadKey(Aes256Gcm);

    impl AeadKey {
        #[inline]
        pub(crate) fn new(key: &[u8; 32]) -> Result<Self> {
            Aes256Gcm::new_from_slice(key)
                .map(Self)
                .map_err(|_| Error::CryptoFailure)
        }

        #[inline]
        pub(crate) fn seal(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            in_out: &mut [u8],
            tag: &mut [u8; AEAD_TAG_LENGTH],
        ) -> Result<()> {
            let generated_tag = self
                .0
                .encrypt_inout_detached(&Nonce::<Aes256Gcm>::from(*nonce), aad, in_out.into())
                .map_err(|_| Error::CryptoFailure)?;
            tag.copy_from_slice(&generated_tag);
            Ok(())
        }

        #[inline]
        pub(crate) fn open(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8; AEAD_TAG_LENGTH],
            output: &mut [u8],
        ) -> Result<()> {
            let in_out = InOutBuf::new(ciphertext, output).map_err(|_| Error::CryptoFailure)?;
            self.0
                .decrypt_inout_detached(
                    &Nonce::<Aes256Gcm>::from(*nonce),
                    aad,
                    in_out,
                    &Tag::<Aes256Gcm>::from(*tag),
                )
                .map_err(|_| Error::AuthenticationFailed)
        }

        #[inline]
        pub(crate) fn open_in_place(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            tag: &[u8; AEAD_TAG_LENGTH],
            in_out: &mut [u8],
        ) -> Result<()> {
            self.0
                .decrypt_inout_detached(
                    &Nonce::<Aes256Gcm>::from(*nonce),
                    aad,
                    in_out.into(),
                    &Tag::<Aes256Gcm>::from(*tag),
                )
                .map_err(|_| Error::AuthenticationFailed)
        }
    }

    pub(crate) fn kdf_expand<const N: usize>(key: &[u8], info: &[&[u8]]) -> Result<[u8; N]> {
        validate_kdf_output_length::<N>()?;

        let mut hmac =
            <HmacSha384 as KeyInit>::new_from_slice(key).map_err(|_| Error::CryptoFailure)?;
        for part in info {
            hmac.update(part);
        }
        hmac.update(&[1]);

        let mut block = hmac.finalize().into_bytes();
        let mut output = [0u8; N];
        output.copy_from_slice(&block[..N]);
        block.as_mut_slice().zeroize();
        Ok(output)
    }
}

#[cfg(feature = "aws-lc-rs")]
mod aead_aws_lc_rs {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use aws_lc_rs::hkdf::{HKDF_SHA384, KeyType, Prk};

    use crate::backends::validate_kdf_output_length;
    use crate::{AEAD_TAG_LENGTH, Error, Result};

    pub(crate) struct AeadKey(LessSafeKey);

    struct OutputLength(usize);

    impl KeyType for OutputLength {
        fn len(&self) -> usize {
            self.0
        }
    }

    impl AeadKey {
        #[inline]
        pub(crate) fn new(key: &[u8; 32]) -> Result<Self> {
            let key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| Error::CryptoFailure)?;
            Ok(Self(LessSafeKey::new(key)))
        }

        #[inline]
        pub(crate) fn seal(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            in_out: &mut [u8],
            tag: &mut [u8; AEAD_TAG_LENGTH],
        ) -> Result<()> {
            let generated_tag = self
                .0
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(*nonce),
                    Aad::from(aad),
                    in_out,
                )
                .map_err(|_| Error::CryptoFailure)?;
            tag.copy_from_slice(generated_tag.as_ref());
            Ok(())
        }

        #[inline]
        pub(crate) fn open(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8; AEAD_TAG_LENGTH],
            output: &mut [u8],
        ) -> Result<()> {
            self.0
                .open_separate_gather(
                    Nonce::assume_unique_for_key(*nonce),
                    Aad::from(aad),
                    ciphertext,
                    tag,
                    output,
                )
                .map_err(|_| Error::AuthenticationFailed)
        }

        #[inline]
        pub(crate) fn open_in_place(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            tag: &[u8; AEAD_TAG_LENGTH],
            in_out: &mut [u8],
        ) -> Result<()> {
            self.0
                .open_in_place_separate_tag(
                    Nonce::assume_unique_for_key(*nonce),
                    Aad::from(aad),
                    tag,
                    in_out,
                )
                .map(|_| ())
                .map_err(|_| Error::AuthenticationFailed)
        }
    }

    pub(crate) fn kdf_expand<const N: usize>(key: &[u8], info: &[&[u8]]) -> Result<[u8; N]> {
        validate_kdf_output_length::<N>()?;

        let prk = Prk::new_less_safe(HKDF_SHA384, key);
        let okm = prk
            .expand(info, OutputLength(N))
            .map_err(|_| Error::CryptoFailure)?;
        let mut output = [0u8; N];
        okm.fill(&mut output).map_err(|_| Error::CryptoFailure)?;
        Ok(output)
    }
}

#[cfg(feature = "boring")]
mod aead_boring {
    use boring::aead::{AeadCtx, Algorithm};
    use boring::hash::MessageDigest;
    use boring::hmac::Hmac;
    use zeroize::Zeroize;

    use crate::backends::validate_kdf_output_length;
    use crate::{AEAD_TAG_LENGTH, Error, Result};

    pub(crate) struct AeadKey(AeadCtx);

    impl AeadKey {
        #[inline]
        pub(crate) fn new(key: &[u8; 32]) -> Result<Self> {
            let algorithm = Algorithm::aes_256_gcm();
            AeadCtx::new(&algorithm, key, AEAD_TAG_LENGTH)
                .map(Self)
                .map_err(|_| Error::CryptoFailure)
        }

        #[inline]
        pub(crate) fn seal(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            in_out: &mut [u8],
            tag: &mut [u8; AEAD_TAG_LENGTH],
        ) -> Result<()> {
            let written = self
                .0
                .seal_in_place(nonce, in_out, tag, aad)
                .map_err(|_| Error::CryptoFailure)?;
            if written.len() != AEAD_TAG_LENGTH {
                return Err(Error::CryptoFailure);
            }
            Ok(())
        }

        #[inline]
        pub(crate) fn open(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8; AEAD_TAG_LENGTH],
            output: &mut [u8],
        ) -> Result<()> {
            output.copy_from_slice(ciphertext);
            self.0
                .open_in_place(nonce, output, tag, aad)
                .map_err(|_| Error::AuthenticationFailed)
        }

        #[inline]
        pub(crate) fn open_in_place(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            tag: &[u8; AEAD_TAG_LENGTH],
            in_out: &mut [u8],
        ) -> Result<()> {
            self.0
                .open_in_place(nonce, in_out, tag, aad)
                .map_err(|_| Error::AuthenticationFailed)
        }
    }

    pub(crate) fn kdf_expand<const N: usize>(key: &[u8], info: &[&[u8]]) -> Result<[u8; N]> {
        validate_kdf_output_length::<N>()?;

        let mut hmac =
            Hmac::init(key, &MessageDigest::sha384()).map_err(|_| Error::CryptoFailure)?;
        for part in info {
            hmac.update(part).map_err(|_| Error::CryptoFailure)?;
        }
        hmac.update(&[1]).map_err(|_| Error::CryptoFailure)?;

        let mut block = hmac.finalize().map_err(|_| Error::CryptoFailure)?;
        if block.len() != 48 {
            block.zeroize();
            return Err(Error::CryptoFailure);
        }
        let mut output = [0u8; N];
        output.copy_from_slice(&block[..N]);
        block.zeroize();
        Ok(output)
    }
}

#[cfg(feature = "ring")]
mod aead_ring {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, Tag, UnboundKey};
    use ring::hkdf::{HKDF_SHA384, KeyType, Prk};

    use crate::backends::validate_kdf_output_length;
    use crate::{AEAD_TAG_LENGTH, Error, Result};

    pub(crate) struct AeadKey(LessSafeKey);

    struct OutputLength(usize);

    impl KeyType for OutputLength {
        fn len(&self) -> usize {
            self.0
        }
    }

    impl AeadKey {
        #[inline]
        pub(crate) fn new(key: &[u8; 32]) -> Result<Self> {
            let key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| Error::CryptoFailure)?;
            Ok(Self(LessSafeKey::new(key)))
        }

        #[inline]
        pub(crate) fn seal(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            in_out: &mut [u8],
            tag: &mut [u8; AEAD_TAG_LENGTH],
        ) -> Result<()> {
            let generated_tag = self
                .0
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(*nonce),
                    Aad::from(aad),
                    in_out,
                )
                .map_err(|_| Error::CryptoFailure)?;
            tag.copy_from_slice(generated_tag.as_ref());
            Ok(())
        }

        #[inline]
        pub(crate) fn open(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8; AEAD_TAG_LENGTH],
            output: &mut [u8],
        ) -> Result<()> {
            output.copy_from_slice(ciphertext);
            self.0
                .open_in_place_separate_tag(
                    Nonce::assume_unique_for_key(*nonce),
                    Aad::from(aad),
                    Tag::from(*tag),
                    output,
                    0..,
                )
                .map(|_| ())
                .map_err(|_| Error::AuthenticationFailed)
        }

        #[inline]
        pub(crate) fn open_in_place(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            tag: &[u8; AEAD_TAG_LENGTH],
            in_out: &mut [u8],
        ) -> Result<()> {
            self.0
                .open_in_place_separate_tag(
                    Nonce::assume_unique_for_key(*nonce),
                    Aad::from(aad),
                    Tag::from(*tag),
                    in_out,
                    0..,
                )
                .map(|_| ())
                .map_err(|_| Error::AuthenticationFailed)
        }
    }

    pub(crate) fn kdf_expand<const N: usize>(key: &[u8], info: &[&[u8]]) -> Result<[u8; N]> {
        validate_kdf_output_length::<N>()?;

        let prk = Prk::new_less_safe(HKDF_SHA384, key);
        let okm = prk
            .expand(info, OutputLength(N))
            .map_err(|_| Error::CryptoFailure)?;
        let mut output = [0u8; N];
        okm.fill(&mut output).map_err(|_| Error::CryptoFailure)?;
        Ok(output)
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum AeadKey {
    #[cfg(feature = "aws-lc-rs")]
    AwsLcRs(aead_aws_lc_rs::AeadKey),
    #[cfg(feature = "boring")]
    Boring(aead_boring::AeadKey),
    #[cfg(feature = "ring")]
    Ring(aead_ring::AeadKey),
    #[cfg(feature = "rustcrypto")]
    RustCrypto(aead_rustcrypto::AeadKey),
}

impl AeadKey {
    pub(crate) fn new(provider: Provider, key: &[u8; 32]) -> Result<Self> {
        match provider.kind() {
            #[cfg(feature = "aws-lc-rs")]
            ProviderKind::AwsLcRs => aead_aws_lc_rs::AeadKey::new(key).map(Self::AwsLcRs),
            #[cfg(feature = "boring")]
            ProviderKind::Boring => aead_boring::AeadKey::new(key).map(Self::Boring),
            #[cfg(feature = "ring")]
            ProviderKind::Ring => aead_ring::AeadKey::new(key).map(Self::Ring),
            #[cfg(feature = "rustcrypto")]
            ProviderKind::RustCrypto => aead_rustcrypto::AeadKey::new(key).map(Self::RustCrypto),
        }
    }

    pub(crate) fn seal(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; crate::AEAD_TAG_LENGTH],
    ) -> Result<()> {
        match self {
            #[cfg(feature = "aws-lc-rs")]
            Self::AwsLcRs(key) => key.seal(nonce, aad, in_out, tag),
            #[cfg(feature = "boring")]
            Self::Boring(key) => key.seal(nonce, aad, in_out, tag),
            #[cfg(feature = "ring")]
            Self::Ring(key) => key.seal(nonce, aad, in_out, tag),
            #[cfg(feature = "rustcrypto")]
            Self::RustCrypto(key) => key.seal(nonce, aad, in_out, tag),
        }
    }

    pub(crate) fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; crate::AEAD_TAG_LENGTH],
        output: &mut [u8],
    ) -> Result<()> {
        match self {
            #[cfg(feature = "aws-lc-rs")]
            Self::AwsLcRs(key) => key.open(nonce, aad, ciphertext, tag, output),
            #[cfg(feature = "boring")]
            Self::Boring(key) => key.open(nonce, aad, ciphertext, tag, output),
            #[cfg(feature = "ring")]
            Self::Ring(key) => key.open(nonce, aad, ciphertext, tag, output),
            #[cfg(feature = "rustcrypto")]
            Self::RustCrypto(key) => key.open(nonce, aad, ciphertext, tag, output),
        }
    }

    pub(crate) fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        tag: &[u8; crate::AEAD_TAG_LENGTH],
        in_out: &mut [u8],
    ) -> Result<()> {
        match self {
            #[cfg(feature = "aws-lc-rs")]
            Self::AwsLcRs(key) => key.open_in_place(nonce, aad, tag, in_out),
            #[cfg(feature = "boring")]
            Self::Boring(key) => key.open_in_place(nonce, aad, tag, in_out),
            #[cfg(feature = "ring")]
            Self::Ring(key) => key.open_in_place(nonce, aad, tag, in_out),
            #[cfg(feature = "rustcrypto")]
            Self::RustCrypto(key) => key.open_in_place(nonce, aad, tag, in_out),
        }
    }
}

impl Provider {
    pub(crate) fn kdf_expand<const N: usize>(self, key: &[u8], info: &[&[u8]]) -> Result<[u8; N]> {
        match self.kind() {
            #[cfg(feature = "aws-lc-rs")]
            ProviderKind::AwsLcRs => aead_aws_lc_rs::kdf_expand(key, info),
            #[cfg(feature = "boring")]
            ProviderKind::Boring => aead_boring::kdf_expand(key, info),
            #[cfg(feature = "ring")]
            ProviderKind::Ring => aead_ring::kdf_expand(key, info),
            #[cfg(feature = "rustcrypto")]
            ProviderKind::RustCrypto => aead_rustcrypto::kdf_expand(key, info),
        }
    }
}

#[cfg(feature = "rustcrypto")]
mod rng_rustcrypto {
    use rand_chacha::ChaCha12Rng;
    use rand_chacha::rand_core::{Rng as _, SeedableRng};
    use zeroize::Zeroize;

    use crate::{Error, Result};

    #[derive(Debug)]
    pub(crate) struct Rng(Option<ChaCha12Rng>);

    impl Rng {
        pub(crate) fn new() -> Self {
            Self(None)
        }

        pub(crate) fn fill(&mut self, output: &mut [u8]) -> Result<()> {
            let rng = match &mut self.0 {
                Some(rng) => rng,
                slot @ None => {
                    let mut seed = [0u8; 32];
                    getrandom::fill(&mut seed).map_err(|_| Error::RngFailure)?;
                    let rng = ChaCha12Rng::from_seed(seed);
                    seed.zeroize();
                    slot.insert(rng)
                }
            };
            rng.fill_bytes(output);
            Ok(())
        }
    }
}

#[cfg(feature = "aws-lc-rs")]
mod rng_aws_lc_rs {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    use crate::{Error, Result};

    #[derive(Debug)]
    pub(crate) struct Rng(SystemRandom);

    impl Rng {
        pub(crate) fn new() -> Self {
            Self(SystemRandom::new())
        }

        pub(crate) fn fill(&mut self, output: &mut [u8]) -> Result<()> {
            self.0.fill(output).map_err(|_| Error::RngFailure)
        }
    }
}

#[cfg(feature = "boring")]
mod rng_boring {
    use crate::{Error, Result};

    #[derive(Debug)]
    pub(crate) struct Rng;

    impl Rng {
        pub(crate) fn new() -> Self {
            Self
        }

        // BoringSSL exposes process-global random generation, so there is no
        // provider object for this backend to retain between calls.
        #[allow(clippy::unused_self)]
        pub(crate) fn fill(&mut self, output: &mut [u8]) -> Result<()> {
            boring::rand::rand_bytes(output).map_err(|_| Error::RngFailure)
        }
    }
}

#[cfg(feature = "ring")]
mod rng_ring {
    use ring::rand::{SecureRandom, SystemRandom};

    use crate::{Error, Result};

    #[derive(Debug)]
    pub(crate) struct Rng(SystemRandom);

    impl Rng {
        pub(crate) fn new() -> Self {
            Self(SystemRandom::new())
        }

        pub(crate) fn fill(&mut self, output: &mut [u8]) -> Result<()> {
            self.0.fill(output).map_err(|_| Error::RngFailure)
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum ProviderRng {
    #[cfg(feature = "aws-lc-rs")]
    AwsLcRs(rng_aws_lc_rs::Rng),
    #[cfg(feature = "boring")]
    Boring(rng_boring::Rng),
    #[cfg(feature = "ring")]
    Ring(rng_ring::Rng),
    #[cfg(feature = "rustcrypto")]
    RustCrypto(rng_rustcrypto::Rng),
}

impl ProviderRng {
    pub(crate) fn new(provider: Provider) -> Self {
        match provider.kind() {
            #[cfg(feature = "aws-lc-rs")]
            ProviderKind::AwsLcRs => Self::AwsLcRs(rng_aws_lc_rs::Rng::new()),
            #[cfg(feature = "boring")]
            ProviderKind::Boring => Self::Boring(rng_boring::Rng::new()),
            #[cfg(feature = "ring")]
            ProviderKind::Ring => Self::Ring(rng_ring::Rng::new()),
            #[cfg(feature = "rustcrypto")]
            ProviderKind::RustCrypto => Self::RustCrypto(rng_rustcrypto::Rng::new()),
        }
    }

    pub(crate) fn fill(&mut self, output: &mut [u8]) -> Result<()> {
        match self {
            #[cfg(feature = "aws-lc-rs")]
            Self::AwsLcRs(rng) => rng.fill(output),
            #[cfg(feature = "boring")]
            Self::Boring(rng) => rng.fill(output),
            #[cfg(feature = "ring")]
            Self::Ring(rng) => rng.fill(output),
            #[cfg(feature = "rustcrypto")]
            Self::RustCrypto(rng) => rng.fill(output),
        }
    }

    #[cfg(test)]
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "aws-lc-rs")]
            Self::AwsLcRs(_) => "aws-lc-rs",
            #[cfg(feature = "boring")]
            Self::Boring(_) => "boring",
            #[cfg(feature = "ring")]
            Self::Ring(_) => "ring",
            #[cfg(feature = "rustcrypto")]
            Self::RustCrypto(_) => "chacha12",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_construct_only_fixed_rng() {
        // Given every provider compiled into this build
        for &provider in Provider::COMPILED {
            // When the provider constructs its random generator
            let rng = ProviderRng::new(provider);

            // Then it is the provider's single fixed generator; the
            // rustcrypto provider always uses ChaCha12
            let expected = if provider.name() == "rustcrypto" {
                "chacha12"
            } else {
                provider.name()
            };
            assert_eq!(rng.name(), expected);
        }
    }
}
