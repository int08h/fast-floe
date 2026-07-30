use core::fmt;

/// Result type used by this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A length bound that a plaintext or ciphertext input failed to meet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthRequirement {
    /// Exactly this many bytes are required.
    Exactly(usize),
    /// At least this many bytes are required.
    AtLeast(usize),
    /// At most this many bytes are permitted.
    AtMost(usize),
    /// A length in this inclusive range is required.
    Between { minimum: usize, maximum: usize },
}

impl fmt::Display for LengthRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exactly(length) => write!(f, "exactly {length}"),
            Self::AtLeast(length) => write!(f, "at least {length}"),
            Self::AtMost(length) => write!(f, "at most {length}"),
            Self::Between { minimum, maximum } => {
                write!(f, "between {minimum} and {maximum}")
            }
        }
    }
}

/// Errors returned by FLOE operations.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A key did not have the required 32-byte length.
    InvalidKeyLength { actual: usize },
    /// An operation combined values from different FLOE parameter sets.
    InvalidParameters,
    /// A plaintext segment did not meet its required length.
    InvalidPlaintextLength {
        actual: usize,
        required: LengthRequirement,
    },
    /// A header did not have the length required by [`crate::Header`].
    InvalidHeaderLength { actual: usize },
    /// The encoded parameters in a header do not match the selected parameters.
    InvalidHeaderParameters,
    /// Header authentication failed.
    InvalidHeaderTag,
    /// A ciphertext segment did not meet its required length, or its encoded
    /// final-length prefix contradicted its actual length.
    InvalidCiphertextLength {
        actual: usize,
        required: LengthRequirement,
    },
    /// An internal segment did not begin with `0xffff_ffff`.
    InvalidSegmentPrefix,
    /// AES-GCM authentication failed.
    AuthenticationFailed,
    /// An online encryptor or decryptor was used after its final segment.
    Closed,
    /// A message or online operation ended without producing or authenticating
    /// a final segment.
    Truncated,
    /// A segment position exceeded the AES-GCM FLOE limit.
    SegmentLimit,
    /// A caller-provided output buffer was too small.
    OutputTooSmall { actual: usize, required: usize },
    /// A segment buffer was used in the wrong preparation state.
    InvalidBufferState,
    /// An operation omitted its provider while multiple providers were compiled.
    ProviderSelectionRequired,
    /// A length calculation overflowed.
    LengthOverflow,
    /// The selected provider could not obtain cryptographically secure bytes.
    RngFailure,
    /// The selected cryptographic backend rejected an otherwise valid operation.
    CryptoFailure,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { actual } => {
                write!(f, "FLOE keys must be 32 bytes, got {actual}")
            }
            Self::InvalidParameters => f.write_str("FLOE parameter sets do not match"),
            Self::InvalidPlaintextLength { actual, required } => write!(
                f,
                "invalid plaintext segment length {actual}; required {required}"
            ),
            Self::InvalidHeaderLength { actual } => write!(
                f,
                "FLOE headers must be {} bytes, got {actual}",
                crate::HEADER_LENGTH
            ),
            Self::InvalidHeaderParameters => {
                f.write_str("header parameters do not match the selected FLOE parameters")
            }
            Self::InvalidHeaderTag => f.write_str("invalid FLOE header tag"),
            Self::InvalidCiphertextLength { actual, required } => write!(
                f,
                "invalid ciphertext segment length {actual}; required {required}"
            ),
            Self::InvalidSegmentPrefix => {
                f.write_str("non-final FLOE segment has an invalid prefix")
            }
            Self::AuthenticationFailed => f.write_str("FLOE segment authentication failed"),
            Self::Closed => f.write_str("FLOE online state is already closed"),
            Self::Truncated => f.write_str("FLOE input has no authenticated final segment"),
            Self::SegmentLimit => f.write_str("FLOE segment limit exceeded"),
            Self::OutputTooSmall { actual, required } => {
                write!(
                    f,
                    "output buffer is {actual} bytes; {required} bytes are required"
                )
            }
            Self::InvalidBufferState => {
                f.write_str("segment buffer is not prepared for this operation")
            }
            Self::ProviderSelectionRequired => {
                f.write_str("multiple FLOE providers are compiled (")?;
                for (index, provider) in crate::Provider::COMPILED.iter().enumerate() {
                    if index != 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(provider.name())?;
                }
                f.write_str(
                    ") and none was named; construct keys with \
                     Key::from_bytes_with_provider or Key::generate_with_provider",
                )
            }
            Self::LengthOverflow => f.write_str("FLOE length calculation overflowed"),
            Self::RngFailure => f.write_str("random backend generation failed"),
            Self::CryptoFailure => f.write_str("cryptographic backend operation failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Returns the crate error carried as a wrapped `io::Error` source.
#[cfg(test)]
pub(crate) fn crate_error(error: &std::io::Error) -> Option<&Error> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<Error>())
}
