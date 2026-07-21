/// A compiled-in cryptographic backend: an AEAD, KDF, and RNG bundle.
///
/// When exactly one backend is compiled in, everything "just works" transparently.
///
/// When a build contains multiple providers, bind one explicitly to
/// a [`crate::Key`] with [`crate::Key::from_bytes_with_provider`] or
/// [`crate::Key::generate_with_provider`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Provider(ProviderKind);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderKind {
    #[cfg(feature = "aws-lc-rs")]
    AwsLcRs,
    #[cfg(feature = "boring")]
    Boring,
    #[cfg(feature = "ring")]
    Ring,
    #[cfg(feature = "rustcrypto")]
    RustCrypto,
}

impl Provider {
    /// The aws-lc-rs provider.
    #[cfg(feature = "aws-lc-rs")]
    pub const AWS_LC_RS: Self = Self(ProviderKind::AwsLcRs);

    /// The `BoringSSL` provider.
    #[cfg(feature = "boring")]
    pub const BORING: Self = Self(ProviderKind::Boring);

    /// The Ring provider.
    #[cfg(feature = "ring")]
    pub const RING: Self = Self(ProviderKind::Ring);

    /// The `RustCrypto` provider.
    #[cfg(feature = "rustcrypto")]
    pub const RUSTCRYPTO: Self = Self(ProviderKind::RustCrypto);

    /// Every provider compiled into this build.
    pub const COMPILED: &'static [Self] = &[
        #[cfg(feature = "aws-lc-rs")]
        Self::AWS_LC_RS,
        #[cfg(feature = "boring")]
        Self::BORING,
        #[cfg(feature = "ring")]
        Self::RING,
        #[cfg(feature = "rustcrypto")]
        Self::RUSTCRYPTO,
    ];

    /// Returns the build's default provider when exactly one provider was compiled.
    ///
    /// Multi-provider builds deliberately have no default.
    #[must_use]
    pub const fn build_default() -> Option<Self> {
        if Self::COMPILED.len() == 1 {
            Some(Self::COMPILED[0])
        } else {
            None
        }
    }

    /// Returns this provider's stable identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            #[cfg(feature = "aws-lc-rs")]
            ProviderKind::AwsLcRs => "aws-lc-rs",
            #[cfg(feature = "boring")]
            ProviderKind::Boring => "boring",
            #[cfg(feature = "ring")]
            ProviderKind::Ring => "ring",
            #[cfg(feature = "rustcrypto")]
            ProviderKind::RustCrypto => "rustcrypto",
        }
    }

    pub(crate) const fn kind(self) -> ProviderKind {
        self.0
    }
}
