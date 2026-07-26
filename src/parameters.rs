use core::iter::FusedIterator;
use core::ops::Range;

use crate::{Error, LengthRequirement, Result};

pub(crate) const AEAD_IV_LENGTH: usize = 12;
pub(crate) const AEAD_TAG_LENGTH: usize = 16;
pub(crate) const AEAD_MAX_SEGMENTS: u64 = 1 << 40;

pub(crate) const FLOE_IV_LENGTH: usize = 32;
pub(crate) const ENCODED_PARAMETERS_LENGTH: usize = 10;
pub(crate) const HEADER_TAG_LENGTH: usize = 32;
pub(crate) const HEADER_LENGTH: usize =
    ENCODED_PARAMETERS_LENGTH + FLOE_IV_LENGTH + HEADER_TAG_LENGTH;

const _: () = assert!(HEADER_LENGTH == 74, "unexpected size of HEADER");

const _: () = assert!(
    usize::BITS == 32 || usize::BITS == 64,
    "fast-floe supports only 32-bit and 64-bit targets"
);

/// Segment length prefix size in bytes.
pub const SEGMENT_PREFIX_LENGTH: usize = 4;

/// Offset at which plaintext or ciphertext payload bytes begin in a segment.
///
/// Safe APIs encapsulate this detail in [`crate::SegmentBuffer`].
pub const SEGMENT_PAYLOAD_OFFSET: usize = SEGMENT_PREFIX_LENGTH + AEAD_IV_LENGTH;

pub(crate) const SEGMENT_OVERHEAD: usize = SEGMENT_PAYLOAD_OFFSET + AEAD_TAG_LENGTH;

const ROTATION_BITS: u8 = 20;
const ROTATION_MASK: u64 = !((1_u64 << ROTATION_BITS) - 1);
const FLOE_IV_LENGTH_U32: u32 = 32;
const _: () = assert!(length_u32_to_usize(FLOE_IV_LENGTH_U32) == FLOE_IV_LENGTH);

pub(crate) const SEGMENT_OVERHEAD_U32: u32 = 32;
const _: () = assert!(length_u32_to_usize(SEGMENT_OVERHEAD_U32) == SEGMENT_OVERHEAD);

/// Converts a wire-format length to the crate's in-memory length type.
#[inline]
pub(crate) const fn length_u32_to_usize(value: u32) -> usize {
    value as usize
}

/// Converts an in-memory length to the crate's message-arithmetic type.
/// `std` has no `From<usize> for u64`, so this documents the assumption once.
#[inline]
pub(crate) const fn length_usize_to_u64(value: usize) -> u64 {
    value as u64
}

pub(crate) const HEADER_LENGTH_U64: u64 = length_usize_to_u64(HEADER_LENGTH);
pub(crate) const SEGMENT_OVERHEAD_U64: u64 = length_usize_to_u64(SEGMENT_OVERHEAD);

/// The segment length is the only varying parameter in the current
/// specification; AES-256-GCM, HKDF-Expand-SHA-384, and the 32-byte FLOE
/// IV are fixed.
///
/// Use [`Parameters::from_segment_length`] to construct a [`Parameters`] instance with
/// your desired segment length, or use one of the pre-made [`Parameters`] constants
/// like [`Parameters::SEGMENT_4_KIB`] or [`Parameters::SEGMENT_1_MIB`] if convenient.
///
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    ciphertext_segment_length: u32,
    #[cfg(test)]
    rotation_mask: u64,
}

/// Whether a segment is an internal or final segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentKind {
    /// A full-sized segment followed by another segment.
    NonFinal,
    /// The authenticated final segment of a message.
    Final,
}

impl SegmentKind {
    /// Returns whether this identifies the message's final segment.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Final)
    }

    pub(crate) const fn indicator(self) -> u8 {
        match self {
            Self::NonFinal => 0,
            Self::Final => 1,
        }
    }
}

/// Complete length and segment layout for one FLOE message.
///
/// Construct this with [`Parameters::plaintext_layout`] when the plaintext
/// length is known, or [`Parameters::ciphertext_layout`] when the complete
/// ciphertext length is known.
///
/// Each [`SegmentLayout`] supplies the offsets, lengths, position,
/// and [`SegmentKind`] needed by the random-access encryption and
/// decryption APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageLayout {
    parameters: Parameters,
    plaintext_length: u64,
    ciphertext_length: u64,
    segment_count: u64,
}

impl MessageLayout {
    /// Returns the layout of this message's final segment.
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // a valid layout always contains a final segment
    pub fn final_segment(self) -> SegmentLayout {
        self.segment_for_position(self.segment_count - 1)
            .expect("every FLOE message layout contains one final segment")
    }

    /// Returns the parameter set used by this layout.
    #[must_use]
    pub const fn parameters(self) -> Parameters {
        self.parameters
    }

    /// Returns the complete plaintext length.
    #[must_use]
    pub const fn plaintext_length(self) -> u64 {
        self.plaintext_length
    }

    /// Returns the complete ciphertext length, including the FLOE header.
    #[must_use]
    pub const fn ciphertext_length(self) -> u64 {
        self.ciphertext_length
    }

    /// Returns the number of segments, including exactly one final segment.
    #[must_use]
    pub const fn segment_count(self) -> u64 {
        self.segment_count
    }

    /// Iterates over every segment in position order.
    ///
    /// See [`Self::segment_for_position`] when accessing an individual
    /// segment by position.
    #[must_use]
    pub fn segments(self) -> Segments {
        Segments {
            layout: self,
            positions: 0..self.segment_count,
        }
    }

    /// Returns the [`SegmentLayout`] of `position`, or `None` if it is outside this message.
    ///
    /// The returned values can be passed directly to the corresponding
    /// random-access segment operation.
    #[must_use]
    pub fn segment_for_position(self, position: u64) -> Option<SegmentLayout> {
        if position >= self.segment_count {
            return None;
        }

        let plaintext_segment_length = self.parameters.plaintext_segment_length();
        let plaintext_segment_length_u64 =
            u64::from(self.parameters.plaintext_segment_length_u32());
        let ciphertext_segment_length = self.parameters.ciphertext_segment_length();
        let ciphertext_segment_length_u64 =
            u64::from(self.parameters.ciphertext_segment_length_u32());
        let plaintext_offset = position * plaintext_segment_length_u64;
        let kind = if position + 1 == self.segment_count {
            SegmentKind::Final
        } else {
            SegmentKind::NonFinal
        };

        let (plaintext_length, ciphertext_length) = match kind {
            SegmentKind::NonFinal => (plaintext_segment_length, ciphertext_segment_length),
            SegmentKind::Final => {
                let plaintext_length =
                    usize::try_from(self.plaintext_length - plaintext_offset).ok()?;
                (plaintext_length, SEGMENT_OVERHEAD + plaintext_length)
            }
        };

        let ciphertext_offset = HEADER_LENGTH_U64 + position * ciphertext_segment_length_u64;

        Some(SegmentLayout {
            parameters: self.parameters,
            position,
            plaintext_offset,
            plaintext_length,
            ciphertext_offset,
            ciphertext_length,
            kind,
        })
    }
}

impl IntoIterator for MessageLayout {
    type Item = SegmentLayout;
    type IntoIter = Segments;

    fn into_iter(self) -> Self::IntoIter {
        self.segments()
    }
}

/// Iterator over the segments in a [`MessageLayout`].
///
/// Obtain this with [`MessageLayout::segments`] or by iterating over a
/// [`MessageLayout`] directly.
#[derive(Clone, Debug)]
pub struct Segments {
    layout: MessageLayout,
    positions: Range<u64>,
}

impl Iterator for Segments {
    type Item = SegmentLayout;

    fn next(&mut self) -> Option<Self::Item> {
        let position = self.positions.next()?;
        match self.layout.segment_for_position(position) {
            Some(segment) => Some(segment),
            None => unreachable!("a layout iterator only produces valid segment positions"),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.positions.size_hint()
    }
}

impl DoubleEndedIterator for Segments {
    fn next_back(&mut self) -> Option<Self::Item> {
        let position = self.positions.next_back()?;
        match self.layout.segment_for_position(position) {
            Some(segment) => Some(segment),
            None => unreachable!("a layout iterator only produces valid segment positions"),
        }
    }
}

impl FusedIterator for Segments {}

/// Offsets and lengths for one segment in a [`MessageLayout`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentLayout {
    parameters: Parameters,
    position: u64,
    plaintext_offset: u64,
    plaintext_length: usize,
    ciphertext_offset: u64,
    ciphertext_length: usize,
    kind: SegmentKind,
}

impl SegmentLayout {
    /// Returns this segment's zero-based position.
    #[must_use]
    pub const fn position(self) -> u64 {
        self.position
    }

    /// Returns this segment's byte offset in the complete plaintext.
    #[must_use]
    pub const fn plaintext_offset(self) -> u64 {
        self.plaintext_offset
    }

    /// Returns this segment's plaintext length.
    #[must_use]
    pub const fn plaintext_length(self) -> usize {
        self.plaintext_length
    }

    /// Returns this segment's byte offset in the complete ciphertext,
    /// including the FLOE header.
    #[must_use]
    pub const fn ciphertext_offset(self) -> u64 {
        self.ciphertext_offset
    }

    /// Returns this segment's ciphertext length.
    #[must_use]
    pub const fn ciphertext_length(self) -> usize {
        self.ciphertext_length
    }

    /// Returns whether this is the message's final segment.
    #[must_use]
    pub const fn is_final(self) -> bool {
        self.kind.is_final()
    }

    /// Returns whether this is an internal or final segment.
    #[must_use]
    pub const fn kind(self) -> SegmentKind {
        self.kind
    }

    pub(crate) const fn parameters(self) -> Parameters {
        self.parameters
    }
}

/// Segment framing information decoded from a FLOE segment prefix.
///
/// Construct this with [`Self::decode`]. A streaming
/// decryptor can use [`Self::ciphertext_length`] to read the remainder of the
/// segment and [`Self::plaintext_length`] to size an output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentFraming {
    ciphertext_length: usize,
    plaintext_length: usize,
    kind: SegmentKind,
}

impl SegmentFraming {
    /// Decodes the **unauthenticated** framing declared by a segment prefix.
    ///
    /// This **does not authenticate** the prefix or the rest of the segment.
    /// You must successfully decrypt the segment before trusting it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCiphertextLength`] when a final prefix encodes
    /// a length outside the supported range.
    pub fn decode(parameters: Parameters, prefix: [u8; SEGMENT_PREFIX_LENGTH]) -> Result<Self> {
        let encoded = u32::from_be_bytes(prefix);

        let ciphertext_length = if encoded == u32::MAX {
            parameters.ciphertext_segment_length()
        } else {
            // Validated in u32 space: the range check must not depend on the
            // width of usize, because `encoded` is attacker-controlled and
            // unauthenticated.
            let maximum = parameters.ciphertext_segment_length_u32();
            if !(SEGMENT_OVERHEAD_U32..=maximum).contains(&encoded) {
                return Err(Error::InvalidCiphertextLength {
                    actual: length_u32_to_usize(encoded),
                    required: LengthRequirement::Between {
                        minimum: SEGMENT_OVERHEAD,
                        maximum: parameters.ciphertext_segment_length(),
                    },
                });
            }
            length_u32_to_usize(encoded)
        };

        Ok(Self {
            ciphertext_length,
            plaintext_length: ciphertext_length - SEGMENT_OVERHEAD,
            kind: if encoded == u32::MAX {
                SegmentKind::NonFinal
            } else {
                SegmentKind::Final
            },
        })
    }

    /// Returns the complete ciphertext segment length.
    #[must_use]
    pub const fn ciphertext_length(self) -> usize {
        self.ciphertext_length
    }

    /// Returns the segment's plaintext payload length.
    #[must_use]
    pub const fn plaintext_length(self) -> usize {
        self.plaintext_length
    }

    /// Returns whether the prefix identifies a final segment.
    #[must_use]
    pub const fn is_final(self) -> bool {
        self.kind.is_final()
    }

    /// Returns whether the prefix identifies an internal or final segment.
    #[must_use]
    pub const fn kind(self) -> SegmentKind {
        self.kind
    }
}

impl Parameters {
    /// Range valid of FLOE segment sizes in bytes. FLOE accepts _any_ segment size
    /// in this range and is not restricted to powers of 2.
    #[cfg(not(test))]
    pub const VALID_SEGMENT_LENGTHS: Range<u32> = 64..(u32::MAX - 1);

    /// Test-only segment-size range that includes the spec's 40-byte KATs.
    #[cfg(test)]
    pub const VALID_SEGMENT_LENGTHS: Range<u32> = 40..(u32::MAX - 1);

    /// FLOE with 64-byte encrypted segments.
    pub const SEGMENT_64_B: Self = Self::from_segment_length_unchecked(64);

    /// FLOE with 4 KiB encrypted segments.
    pub const SEGMENT_4_KIB: Self = Self::from_segment_length_unchecked(4 * 1024);

    /// FLOE with 1 MiB encrypted segments.
    pub const SEGMENT_1_MIB: Self = Self::from_segment_length_unchecked(1024 * 1024);

    /// FLOE with 4 MiB encrypted segments.
    pub const SEGMENT_4_MIB: Self = Self::from_segment_length_unchecked(4 * 1024 * 1024);

    /// FLOE with 5 MiB encrypted segments.
    pub const SEGMENT_5_MIB: Self = Self::from_segment_length_unchecked(5 * 1024 * 1024);

    /// FLOE with 8 MiB encrypted segments.
    pub const SEGMENT_8_MIB: Self = Self::from_segment_length_unchecked(8 * 1024 * 1024);

    /// FLOE with 16 MiB encrypted segments.
    pub const SEGMENT_16_MIB: Self = Self::from_segment_length_unchecked(16 * 1024 * 1024);

    /// Construct a [`Parameters`] instance with the provided segment length in bytes.
    /// `segment_len` can be any value in the range [`Parameters::VALID_SEGMENT_LENGTHS`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameters`] when `segment_len` is outside the
    /// supported range.
    pub fn from_segment_length(segment_len: u32) -> Result<Self> {
        if !Self::VALID_SEGMENT_LENGTHS.contains(&segment_len) {
            return Err(Error::InvalidParameters);
        }

        Ok(Self::from_segment_length_unchecked(segment_len))
    }

    const fn from_segment_length_unchecked(segment_len: u32) -> Self {
        Self {
            ciphertext_segment_length: segment_len,
            #[cfg(test)]
            rotation_mask: ROTATION_MASK,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_rotation_mask_for_test(
        segment_len: u32,
        rotation_mask: u64,
    ) -> Result<Self> {
        let mut parameters = Self::from_segment_length(segment_len)?;
        parameters.rotation_mask = rotation_mask;
        Ok(parameters)
    }

    /// Returns the exact length of every non-final ciphertext segment.
    #[must_use]
    #[inline]
    pub const fn ciphertext_segment_length(self) -> usize {
        length_u32_to_usize(self.ciphertext_segment_length)
    }

    pub(crate) const fn ciphertext_segment_length_u32(self) -> u32 {
        self.ciphertext_segment_length
    }

    /// Returns the plaintext length of every non-final segment and the maximum
    /// plaintext length of a final segment.
    #[must_use]
    #[inline]
    pub const fn plaintext_segment_length(self) -> usize {
        length_u32_to_usize(self.plaintext_segment_length_u32())
    }

    pub(crate) const fn plaintext_segment_length_u32(self) -> u32 {
        self.ciphertext_segment_length - SEGMENT_OVERHEAD_U32
    }

    /// Calculates the complete FLOE layout for `plaintext_length`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SegmentLimit`] when the message would exceed the
    /// specification's segment limit, or [`Error::LengthOverflow`] when the
    /// resulting ciphertext length cannot be represented as a `u64`.
    pub fn plaintext_layout(self, plaintext_length: u64) -> Result<MessageLayout> {
        let plaintext_segment_length = u64::from(self.plaintext_segment_length_u32());

        let segment_count = if plaintext_length == 0 {
            1
        } else {
            (plaintext_length - 1) / plaintext_segment_length + 1
        };

        if segment_count > AEAD_MAX_SEGMENTS {
            return Err(Error::SegmentLimit);
        }

        let framing_length = segment_count
            .checked_mul(SEGMENT_OVERHEAD_U64)
            .ok_or(Error::LengthOverflow)?;

        let ciphertext_length = HEADER_LENGTH_U64
            .checked_add(plaintext_length)
            .and_then(|length| length.checked_add(framing_length))
            .ok_or(Error::LengthOverflow)?;

        Ok(MessageLayout {
            parameters: self,
            plaintext_length,
            ciphertext_length,
            segment_count,
        })
    }

    /// Calculates the complete FLOE layout for `ciphertext_length`.
    ///
    /// `ciphertext_length` includes the FLOE header. This validates only the
    /// lengths implied by the file size and assumes every preceding segment is
    /// a full non-final segment. Each prefix and authentication tag must still
    /// be validated while decrypting. For streaming input whose complete
    /// length is unavailable, use [`SegmentFraming::decode`] instead.
    ///
    /// # Errors
    ///
    /// Returns an error when the ciphertext is too short, implies an invalid
    /// final segment length, or exceeds the specification's segment limit.
    pub fn ciphertext_layout(self, ciphertext_length: u64) -> Result<MessageLayout> {
        let body_length = ciphertext_length
            .checked_sub(HEADER_LENGTH_U64)
            .ok_or_else(|| Error::InvalidHeaderLength {
                actual: usize::try_from(ciphertext_length).unwrap_or(usize::MAX),
            })?;

        if body_length == 0 {
            return Err(Error::Truncated);
        }

        let ciphertext_segment_length = u64::from(self.ciphertext_segment_length_u32());

        let segment_count = (body_length - 1) / ciphertext_segment_length + 1;

        if segment_count > AEAD_MAX_SEGMENTS {
            return Err(Error::SegmentLimit);
        }

        let preceding_length = (segment_count - 1) * ciphertext_segment_length;
        let final_length = body_length - preceding_length;

        if final_length < SEGMENT_OVERHEAD_U64 {
            return Err(Error::InvalidCiphertextLength {
                actual: usize::try_from(final_length).unwrap_or(usize::MAX),
                required: LengthRequirement::Between {
                    minimum: SEGMENT_OVERHEAD,
                    maximum: self.ciphertext_segment_length(),
                },
            });
        }

        let framing_length = segment_count
            .checked_mul(SEGMENT_OVERHEAD_U64)
            .ok_or(Error::LengthOverflow)?;

        let plaintext_length = body_length
            .checked_sub(framing_length)
            .ok_or(Error::LengthOverflow)?;

        Ok(MessageLayout {
            parameters: self,
            plaintext_length,
            ciphertext_length,
            segment_count,
        })
    }

    /// Encodes the parameters as `AEAD_ID || KDF_ID || ENC_SEG_LEN || FLOE_IV_LEN`.
    #[must_use]
    #[inline]
    pub(crate) const fn encode(self) -> [u8; ENCODED_PARAMETERS_LENGTH] {
        let segment_length = self.ciphertext_segment_length.to_be_bytes();
        let iv_length = FLOE_IV_LENGTH_U32.to_be_bytes();
        [
            0,
            0,
            segment_length[0],
            segment_length[1],
            segment_length[2],
            segment_length[3],
            iv_length[0],
            iv_length[1],
            iv_length[2],
            iv_length[3],
        ]
    }

    pub(crate) fn decode(encoded: [u8; ENCODED_PARAMETERS_LENGTH]) -> Result<Self> {
        let mut seg_len_bytes = [0u8; 4];
        seg_len_bytes.copy_from_slice(&encoded[2..6]);

        let segment_length = u32::from_be_bytes(seg_len_bytes);
        let parameters = Self::from_segment_length(segment_length)?;

        if parameters.encode() == encoded {
            Ok(parameters)
        } else {
            Err(Error::InvalidHeaderParameters)
        }
    }

    #[inline]
    #[cfg(not(test))]
    pub(crate) const fn masked_position(self, position: u64) -> u64 {
        let _ = self;
        position & ROTATION_MASK
    }

    #[cfg(test)]
    pub(crate) const fn masked_position(self, position: u64) -> u64 {
        position & self.rotation_mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_encoding_matches_specification() {
        // Given the specification's encodings of the fixed parameter sets

        // Then each constant encodes to the specified bytes and reports the
        // specified segment length
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
    fn parameters_accept_every_valid_segment_length() {
        // Given segment lengths across the supported range, including both
        // endpoints
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

            // When parameters are constructed from the segment length
            let parameters = Parameters::from_segment_length(segment_length).unwrap();

            // Then they report that length and survive an encode/decode
            // round trip
            assert_eq!(
                parameters.ciphertext_segment_length(),
                usize::try_from(segment_length).unwrap()
            );
            assert_eq!(Parameters::decode(parameters.encode()), Ok(parameters));
        }
    }

    #[test]
    fn parameters_reject_segment_lengths_outside_valid_range() {
        // Given segment lengths just outside the supported range and at the
        // u32 extremes
        let valid_range = Parameters::VALID_SEGMENT_LENGTHS;
        let first_valid = valid_range.start;

        for segment_length in [0, first_valid - 1, valid_range.end, u32::MAX] {
            assert!(!valid_range.contains(&segment_length));

            // When parameters are constructed from the segment length
            // Then construction is rejected
            assert_eq!(
                Parameters::from_segment_length(segment_length),
                Err(Error::InvalidParameters)
            );

            // When the length is spliced into an otherwise valid encoding
            // Then decoding is rejected as well
            let mut encoded = Parameters::SEGMENT_4_KIB.encode();
            encoded[2..6].copy_from_slice(&segment_length.to_be_bytes());
            assert!(Parameters::decode(encoded).is_err());
        }
    }

    #[test]
    fn message_layouts_cover_plaintext_boundaries() {
        // Given plaintext lengths at and around every segment boundary
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext_segment_length =
            u64::try_from(parameters.plaintext_segment_length()).unwrap();
        let ciphertext_segment_length =
            u64::try_from(parameters.ciphertext_segment_length()).unwrap();
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
            // When the message layout is calculated from the plaintext length
            let layout = parameters.plaintext_layout(plaintext_length).unwrap();
            let expected_count = if plaintext_length == 0 {
                1
            } else {
                (plaintext_length - 1) / plaintext_segment_length + 1
            };

            // Then the layout reports the expected lengths and segment count,
            // and the ciphertext length maps back to the same layout
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

            // Then iteration, indexed access, and reverse iteration agree
            let segments: Vec<_> = layout.segments().collect();
            assert_eq!(u64::try_from(segments.len()).unwrap(), expected_count);
            assert_eq!(layout.into_iter().collect::<Vec<_>>(), segments);
            assert_eq!(
                layout.segments().next_back(),
                layout.segment_for_position(expected_count - 1)
            );

            // Then every segment carries consistent offsets, lengths, and
            // exactly the last position is final
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

            // Then positions beyond the message resolve to no segment
            assert_eq!(layout.segment_for_position(layout.segment_count()), None);
        }
    }

    #[test]
    fn message_layouts_enforce_segment_limit() {
        // Given the largest plaintext the specification's segment limit allows
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext_segment_length =
            u64::try_from(parameters.plaintext_segment_length()).unwrap();
        let maximum_plaintext_length = AEAD_MAX_SEGMENTS * plaintext_segment_length;

        // When its layout is calculated
        let maximum = parameters
            .plaintext_layout(maximum_plaintext_length)
            .unwrap();

        // Then the layout fills the limit exactly and ends with a final segment
        assert_eq!(maximum.segment_count(), AEAD_MAX_SEGMENTS);
        assert!(
            maximum
                .segment_for_position(AEAD_MAX_SEGMENTS - 1)
                .unwrap()
                .is_final()
        );

        // When one more byte is added on either the plaintext or ciphertext
        // side, then the segment limit rejects the layout
        assert_eq!(
            parameters.plaintext_layout(maximum_plaintext_length + 1),
            Err(Error::SegmentLimit)
        );
        assert_eq!(
            parameters.ciphertext_layout(maximum.ciphertext_length() + 1),
            Err(Error::SegmentLimit)
        );
    }

    #[test]
    fn ciphertext_layouts_classify_short_lengths() {
        // Given ciphertext lengths around the header and minimum-segment
        // boundaries
        let parameters = Parameters::SEGMENT_4_KIB;
        let header_length = u64::try_from(HEADER_LENGTH).unwrap();
        let overhead = u64::try_from(SEGMENT_OVERHEAD).unwrap();

        // When a length cannot hold a complete header,
        // then it is classified as an invalid header length
        assert!(matches!(
            parameters.ciphertext_layout(header_length - 1),
            Err(Error::InvalidHeaderLength { .. })
        ));

        // When a length holds the header but no body,
        // then it is classified as truncated
        assert_eq!(
            parameters.ciphertext_layout(header_length),
            Err(Error::Truncated)
        );

        // When the body cannot hold a minimum final segment,
        // then the segment length is rejected
        assert!(matches!(
            parameters.ciphertext_layout(header_length + overhead - 1),
            Err(Error::InvalidCiphertextLength { .. })
        ));

        // When the body holds exactly an empty final segment,
        // then the layout matches the empty message
        assert_eq!(
            parameters
                .ciphertext_layout(header_length + overhead)
                .unwrap(),
            parameters.plaintext_layout(0).unwrap()
        );
    }

    #[test]
    fn ciphertext_layout_accepts_length_valid_empty_final_segment() {
        // Given a ciphertext length implying one full segment plus an empty
        // final segment, a framing the canonical encoder never produces
        let parameters = Parameters::SEGMENT_4_KIB;
        let header_length = u64::try_from(HEADER_LENGTH).unwrap();
        let ciphertext_segment_length =
            u64::try_from(parameters.ciphertext_segment_length()).unwrap();
        let overhead = u64::try_from(SEGMENT_OVERHEAD).unwrap();
        let ciphertext_length = header_length + ciphertext_segment_length + overhead;

        // When the layout is calculated from that ciphertext length
        let layout = parameters.ciphertext_layout(ciphertext_length).unwrap();

        // Then it describes a full non-final segment and an empty final one
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

        // Then the canonical layout for the same plaintext differs, proving
        // this framing is an accepted alternative rather than the default
        let canonical = parameters
            .plaintext_layout(layout.plaintext_length())
            .unwrap();
        assert_eq!(canonical.segment_count(), 1);
        assert_ne!(canonical.ciphertext_length(), ciphertext_length);
    }

    #[test]
    fn segment_prefixes_classify_final_and_non_final_framing() {
        // Given the all-ones non-final prefix
        let parameters = Parameters::SEGMENT_4_KIB;

        // When it is decoded
        let non_final = SegmentFraming::decode(parameters, u32::MAX.to_be_bytes()).unwrap();

        // Then it classifies as a full non-final segment
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

        // Given final-segment lengths across the permitted range
        for encrypted_length in [
            SEGMENT_OVERHEAD,
            SEGMENT_OVERHEAD + 7,
            parameters.ciphertext_segment_length(),
        ] {
            // When the length prefix is decoded
            let prefix = u32::try_from(encrypted_length).unwrap().to_be_bytes();
            let final_segment = SegmentFraming::decode(parameters, prefix).unwrap();

            // Then it classifies as a final segment of exactly that length
            assert_eq!(final_segment.kind(), SegmentKind::Final);
            assert!(final_segment.is_final());
            assert_eq!(final_segment.ciphertext_length(), encrypted_length);
            assert_eq!(
                final_segment.plaintext_length(),
                encrypted_length - SEGMENT_OVERHEAD
            );
        }
    }

    #[test]
    fn segment_framing_rejects_lengths_outside_final_range() {
        // Given prefixes just below the minimum and just above the maximum
        // final-segment length
        let parameters = Parameters::SEGMENT_4_KIB;
        for invalid in [
            SEGMENT_OVERHEAD - 1,
            parameters.ciphertext_segment_length() + 1,
        ] {
            // When the prefix is decoded
            // Then the declared length is rejected
            let prefix = u32::try_from(invalid).unwrap().to_be_bytes();
            assert!(matches!(
                SegmentFraming::decode(parameters, prefix),
                Err(Error::InvalidCiphertextLength { .. })
            ));
        }
    }

    #[test]
    fn segment_framing_rejects_prefix_whose_low_bits_look_valid() {
        // Given forged prefixes whose low bytes alone would decode to a
        // valid final-segment length
        let parameters = Parameters::SEGMENT_4_KIB;
        for forged in [69_632_u32, 1_048_576 + 4_096] {
            // When the full 32-bit prefix is decoded
            // Then the forgery is rejected rather than truncated to its
            // low bits
            assert!(matches!(
                SegmentFraming::decode(parameters, forged.to_be_bytes()),
                Err(Error::InvalidCiphertextLength { .. })
            ));
        }
    }

    #[test]
    fn segment_payload_offset_follows_prefix_and_nonce() {
        // Given the specification's segment framing
        // Then the payload begins directly after the length prefix and nonce
        assert_eq!(
            SEGMENT_PAYLOAD_OFFSET,
            SEGMENT_PREFIX_LENGTH + AEAD_IV_LENGTH
        );
    }

    #[test]
    fn masked_positions_rotate_at_specification_interval() {
        const ROTATION_INTERVAL: u64 = 1 << 20;

        // Given the specification's key-rotation interval
        let parameters = Parameters::SEGMENT_4_KIB;

        // Then positions mask to the interval boundary below them, up to the
        // segment limit
        assert_eq!(parameters.masked_position(ROTATION_INTERVAL - 1), 0);
        assert_eq!(
            parameters.masked_position(ROTATION_INTERVAL),
            ROTATION_INTERVAL
        );
        assert_eq!(
            parameters.masked_position(AEAD_MAX_SEGMENTS - 1),
            AEAD_MAX_SEGMENTS - ROTATION_INTERVAL
        );
    }
}
