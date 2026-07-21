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

/// Segment length prefix size in bytes.
pub const SEGMENT_PREFIX_LENGTH: usize = 4;

/// Offset at which plaintext or ciphertext payload bytes begin in a segment.
///
/// Safe APIs encapsulate this detail in [`crate::SegmentBuffer`].
pub const SEGMENT_PAYLOAD_OFFSET: usize = SEGMENT_PREFIX_LENGTH + AEAD_IV_LENGTH;

pub(crate) const SEGMENT_OVERHEAD: usize = SEGMENT_PAYLOAD_OFFSET + AEAD_TAG_LENGTH;

const ROTATION_BITS: u8 = 20;
const FLOE_IV_LENGTH_U32: u32 = 32;

/// A supported FLOE parameter set.
///
/// See [`Self::SEGMENT_4_KIB`] or [`Self::SEGMENT_1_MIB`] for concrete instances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    ciphertext_segment_length: u32,
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
        let plaintext_segment_length_u64 = u64::try_from(plaintext_segment_length).ok()?;
        let ciphertext_segment_length = self.parameters.ciphertext_segment_length();
        let ciphertext_segment_length_u64 = u64::try_from(ciphertext_segment_length).ok()?;
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

        let ciphertext_offset =
            u64::try_from(HEADER_LENGTH).ok()? + position * ciphertext_segment_length_u64;

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
            let length = encoded as usize;
            let valid_range = SEGMENT_OVERHEAD..=parameters.ciphertext_segment_length();
            if !valid_range.contains(&length) {
                return Err(Error::InvalidCiphertextLength {
                    actual: length,
                    required: LengthRequirement::Between {
                        minimum: SEGMENT_OVERHEAD,
                        maximum: parameters.ciphertext_segment_length(),
                    },
                });
            }
            length
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
    /// FLOE with 4 KiB encrypted segments.
    ///
    /// The segment length is the only varying parameter in the current
    /// specification; AES-256-GCM, HKDF-Expand-SHA-384, and the 32-byte FLOE
    /// IV are fixed.
    pub const SEGMENT_4_KIB: Self = Self {
        ciphertext_segment_length: 4 * 1024,
    };

    /// FLOE with 1 MiB encrypted segments.
    ///
    /// The segment length is the only varying parameter in the current
    /// specification; AES-256-GCM, HKDF-Expand-SHA-384, and the 32-byte FLOE
    /// IV are fixed.
    pub const SEGMENT_1_MIB: Self = Self {
        ciphertext_segment_length: 1024 * 1024,
    };

    /// Every parameter profile supported by this crate.
    pub const ALL: [Self; 2] = [Self::SEGMENT_4_KIB, Self::SEGMENT_1_MIB];

    /// Returns the exact length of every non-final ciphertext segment.
    #[must_use]
    #[inline]
    pub const fn ciphertext_segment_length(self) -> usize {
        self.ciphertext_segment_length as usize
    }

    /// Returns the plaintext length of every non-final segment and the maximum
    /// plaintext length of a final segment.
    #[must_use]
    #[inline]
    pub const fn plaintext_segment_length(self) -> usize {
        self.ciphertext_segment_length() - SEGMENT_OVERHEAD
    }

    /// Calculates the complete FLOE layout for `plaintext_length`.
    ///
    /// This is the canonical encryption layout: empty plaintext produces one
    /// empty final segment, and an exact multiple of the plaintext segment
    /// length ends with a full-sized final segment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SegmentLimit`] when the message would exceed the
    /// specification's segment limit, or [`Error::LengthOverflow`] when the
    /// resulting ciphertext length cannot be represented as a `u64`.
    pub fn plaintext_layout(self, plaintext_length: u64) -> Result<MessageLayout> {
        let plaintext_segment_length =
            u64::try_from(self.plaintext_segment_length()).map_err(|_| Error::LengthOverflow)?;

        let segment_count = if plaintext_length == 0 {
            1
        } else {
            (plaintext_length - 1) / plaintext_segment_length + 1
        };

        if segment_count > AEAD_MAX_SEGMENTS {
            return Err(Error::SegmentLimit);
        }

        let framing_length = segment_count
            .checked_mul(u64::try_from(SEGMENT_OVERHEAD).map_err(|_| Error::LengthOverflow)?)
            .ok_or(Error::LengthOverflow)?;

        let ciphertext_length = u64::try_from(HEADER_LENGTH)
            .map_err(|_| Error::LengthOverflow)?
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
        let header_length = u64::try_from(HEADER_LENGTH).map_err(|_| Error::LengthOverflow)?;
        let body_length =
            ciphertext_length
                .checked_sub(header_length)
                .ok_or(Error::InvalidHeaderLength {
                    actual: usize::try_from(ciphertext_length).unwrap_or(usize::MAX),
                })?;

        if body_length == 0 {
            return Err(Error::Truncated);
        }

        let ciphertext_segment_length =
            u64::try_from(self.ciphertext_segment_length()).map_err(|_| Error::LengthOverflow)?;

        let segment_count = (body_length - 1) / ciphertext_segment_length + 1;

        if segment_count > AEAD_MAX_SEGMENTS {
            return Err(Error::SegmentLimit);
        }

        let preceding_length = (segment_count - 1) * ciphertext_segment_length;
        let final_length = body_length - preceding_length;
        let minimum = u64::try_from(SEGMENT_OVERHEAD).map_err(|_| Error::LengthOverflow)?;

        if final_length < minimum {
            return Err(Error::InvalidCiphertextLength {
                actual: usize::try_from(final_length).unwrap_or(usize::MAX),
                required: LengthRequirement::Between {
                    minimum: SEGMENT_OVERHEAD,
                    maximum: self.ciphertext_segment_length(),
                },
            });
        }

        let framing_length = segment_count
            .checked_mul(minimum)
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
        let mut segment_length = [0u8; 4];
        segment_length.copy_from_slice(&encoded[2..6]);
        let parameters = match u32::from_be_bytes(segment_length) {
            4096 => Self::SEGMENT_4_KIB,
            1_048_576 => Self::SEGMENT_1_MIB,
            _ => return Err(Error::InvalidHeaderParameters),
        };

        if parameters.encode() == encoded {
            Ok(parameters)
        } else {
            Err(Error::InvalidHeaderParameters)
        }
    }

    #[inline]
    pub(crate) const fn masked_position(position: u64) -> u64 {
        let low_bits = (1_u64 << ROTATION_BITS) - 1;
        position & !low_bits
    }
}
