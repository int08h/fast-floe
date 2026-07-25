#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod backends;
mod buffer;
mod error;
pub mod io;
mod key;
pub mod online;
mod parameters;
mod provider;
pub mod random_access;
mod state;
mod wire;

pub use error::{Error, LengthRequirement, Result};
pub use key::Key;
pub use online::{decrypt, decrypt_with_parameters, encrypt};
pub use parameters::{Parameters, SEGMENT_PREFIX_LENGTH, SegmentFraming, SegmentKind};
pub use provider::Provider;
pub use state::Header;

/// Framing, backend, and raw random-access primitives for experts. These
/// APIs expose more of the FLOE state machine and require callers to preserve
/// message-level invariants (and to know those invariants exist).
///
/// In particular, callers processing segments themselves must uphold the
/// obligations that higher-level APIs abstract away:
///
///   - Encrypt each position at most once
///   - Produce exactly one final segment
///   - Leave no gaps
///   - Never process positions beyond the final segment.
///
/// Prefer the higher-level APIs unless manual segment processing or parallel
/// access is required.
pub mod low_level {
    pub use crate::buffer::SegmentBuffer;
    pub use crate::parameters::SEGMENT_PAYLOAD_OFFSET;
    pub use crate::state::{
        DecryptionState, EncryptionState, SharedDecryptionContext, SharedEncryptionContext,
        start_decryption, start_decryption_inferred, start_encryption,
    };
}

pub(crate) use buffer::SegmentBuffer;
pub(crate) use parameters::{
    AEAD_IV_LENGTH, AEAD_MAX_SEGMENTS, AEAD_TAG_LENGTH, ENCODED_PARAMETERS_LENGTH, FLOE_IV_LENGTH,
    HEADER_LENGTH, HEADER_TAG_LENGTH, SEGMENT_OVERHEAD, SEGMENT_PAYLOAD_OFFSET, SegmentLayout,
    length_u32_to_usize, length_usize_to_u64,
};
pub(crate) use state::{
    DecryptionState, EncryptionState, start_decryption, start_decryption_inferred, start_encryption,
};

#[cfg(test)]
mod tests;
