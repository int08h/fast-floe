use core::fmt;

use zeroize::Zeroize;

use crate::backends::ProviderRng;
use crate::{Error, Provider, Result};

/// A 256-bit FLOE key that zeroizes its owned bytes on drop.
///
/// Use [`Key::generate`] for a fresh random key or [`Key::from_bytes`] when
/// importing existing key material.
pub struct Key {
    bytes: [u8; Self::LEN],
    provider: Option<Provider>,
}

impl Key {
    /// Required FLOE key length in bytes.
    pub const LEN: usize = 32;

    /// Generates a new 256-bit FLOE key with the build default provider.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderSelectionRequired`] when multiple providers
    /// are compiled, or [`Error::RngFailure`] if the provider cannot obtain
    /// secure randomness.
    pub fn generate() -> Result<Self> {
        let provider = Provider::build_default().ok_or(Error::ProviderSelectionRequired)?;
        Self::generate_with_provider(provider)
    }

    /// Generates a new 256-bit FLOE key bound to `provider`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RngFailure`] if the provider cannot obtain secure
    /// randomness.
    pub fn generate_with_provider(provider: Provider) -> Result<Self> {
        let mut rng = ProviderRng::new(provider);
        let mut key = [0u8; Self::LEN];
        rng.fill(&mut key)?;
        Ok(Self {
            bytes: key,
            provider: Some(provider),
        })
    }

    /// Imports an existing 256-bit key using the build default provider.
    ///
    /// Provider resolution is deferred until [`Self::provider`] or the first
    /// cryptographic operation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self {
            bytes,
            provider: None,
        }
    }

    /// Imports an existing 256-bit key bound to `provider`.
    #[must_use]
    pub const fn from_bytes_with_provider(bytes: [u8; Self::LEN], provider: Provider) -> Self {
        Self {
            bytes,
            provider: Some(provider),
        }
    }

    /// Returns the raw secret key bytes. Handle with care.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.bytes
    }

    /// Returns the concrete provider this key will use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderSelectionRequired`] when this key has no
    /// explicit provider and multiple providers are compiled.
    pub const fn provider(&self) -> Result<Provider> {
        match self.provider {
            Some(provider) => Ok(provider),
            None => match Provider::build_default() {
                Some(provider) => Ok(provider),
                None => Err(Error::ProviderSelectionRequired),
            },
        }
    }
}

impl Clone for Key {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            provider: self.provider,
        }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Key").field(&"[REDACTED]").finish()
    }
}

impl From<[u8; Key::LEN]> for Key {
    fn from(bytes: [u8; Key::LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let actual = bytes.len();
        let bytes = bytes
            .try_into()
            .map_err(|_| Error::InvalidKeyLength { actual })?;
        Ok(Self::from_bytes(bytes))
    }
}

// The all-zero key every KAT is generated with, bound to the build's first
// compiled provider so multi-provider test builds stay deterministic.
#[cfg(test)]
pub(crate) fn test_key() -> Key {
    Key::from_bytes_with_provider([0; Key::LEN], Provider::COMPILED[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Parameters, decrypt, encrypt};

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
}
