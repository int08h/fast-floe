//! Authenticated random access to complete, seekable FLOE ciphertexts.
//!
//! [`Reader`] authenticates the header and final segment up front, then
//! serves lazily authenticated segment and range reads.
//!
//! It also implements [`Read`] and [`Seek`] over the plaintext, so the
//! decrypted view composes with code that expects an ordinary seekable stream.

use core::ops::{Bound, Range, RangeBounds};
use std::io::{self, Read, Seek, SeekFrom};

pub use crate::parameters::{MessageLayout, SegmentLayout, Segments};
use crate::wire::{decryption_error, length_overflow, read_exact_segment, read_header};
use crate::{
    DecryptionState, Error, HEADER_LENGTH_U64, Header, Key, Parameters, SegmentBuffer,
    length_usize_to_u64, start_decryption_inferred,
};

/// Authenticated random-access reader for a complete seekable FLOE ciphertext.
///
/// Construction treats the bytes from the reader's current position through
/// EOF as one complete FLOE message unless [`Self::new_with_length`]
/// is used. Both the header and final segment are authenticated before
/// exposing the message content.
///
/// The underlying `Reader` must not change while this reader is in use.
#[derive(Debug)]
pub struct Reader<R> {
    inner: R,
    state: DecryptionState,
    header: Header,
    layout: MessageLayout,
    message_start: u64,
    scratch: SegmentBuffer,
    plaintext_position: u64,
    cached_position: Option<u64>,
}

impl<R: Read + Seek> Reader<R> {
    /// Opens a seekable ciphertext using parameters read from its header.
    ///
    /// # Errors
    ///
    /// Returns an error for seek/read failures, an invalid or unauthenticated
    /// header, or an impossible complete ciphertext length.
    pub fn new(mut inner: R, key: &Key, aad: &[u8]) -> io::Result<Self> {
        let message_start = inner.stream_position()?;
        let header = read_header(&mut inner)?;
        let state = start_decryption_inferred(key, aad, &header).map_err(decryption_error)?;
        let ciphertext_length = remaining_length(&mut inner, message_start)?;
        Self::from_parts(inner, state, header, message_start, ciphertext_length)
    }

    /// Opens a ciphertext using an explicit length.
    ///
    /// `ciphertext_length` counts from the reader's current position and allows
    /// a FLOE message to be followed by non-FLOE data in the same seekable
    /// source.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, seek/read failures, an invalid or
    /// unauthenticated header, or a final segment inconsistent with the bound.
    pub fn new_with_length(
        mut inner: R,
        key: &Key,
        aad: &[u8],
        ciphertext_length: u64,
    ) -> io::Result<Self> {
        validate_header_bound(ciphertext_length)?;
        let message_start = inner.stream_position()?;
        let header = read_header(&mut inner)?;
        let state = start_decryption_inferred(key, aad, &header).map_err(decryption_error)?;
        Self::from_parts(inner, state, header, message_start, ciphertext_length)
    }

    fn from_parts(
        inner: R,
        state: DecryptionState,
        header: Header,
        message_start: u64,
        ciphertext_length: u64,
    ) -> io::Result<Self> {
        let parameters = state.parameters();
        let layout = parameters
            .ciphertext_layout(ciphertext_length)
            .map_err(decryption_error)?;

        let mut reader = Self {
            inner,
            state,
            header,
            layout,
            message_start,
            scratch: SegmentBuffer::new(parameters),
            plaintext_position: 0,
            cached_position: None,
        };

        reader.load_segment(layout.final_segment())?;
        reader.scratch.clear();
        reader.cached_position = None;
        reader.seek_to_body_start()?;
        Ok(reader)
    }

    /// Returns the authenticated header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Returns the authenticated parameter set.
    #[must_use]
    pub fn parameters(&self) -> Parameters {
        self.state.parameters()
    }

    /// Returns the complete plaintext length.
    #[must_use]
    pub const fn plaintext_length(&self) -> u64 {
        self.layout.plaintext_length()
    }

    /// Returns the authenticated complete-message segment count.
    #[must_use]
    pub const fn segment_count(&self) -> u64 {
        self.layout.segment_count()
    }

    /// Returns the authenticated complete message layout.
    #[must_use]
    pub const fn layout(&self) -> MessageLayout {
        self.layout
    }

    /// Authenticates and returns one complete plaintext segment by position.
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-range position, seek/read failure,
    /// malformed framing, or authentication failure.
    pub fn read_segment(&mut self, position: u64) -> io::Result<Vec<u8>> {
        let segment = self.segment(position)?;
        let mut plaintext = vec![0; segment.plaintext_length()];
        self.read_segment_into(position, &mut plaintext)?;
        Ok(plaintext)
    }

    /// Authenticates one complete plaintext segment into `output`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_segment`], plus an error when
    /// `output` is too small.
    pub fn read_segment_into(&mut self, position: u64, output: &mut [u8]) -> io::Result<usize> {
        let segment = self.segment(position)?;
        let required = segment.plaintext_length();
        if output.len() < required {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                Error::OutputTooSmall {
                    actual: output.len(),
                    required,
                },
            ));
        }
        self.decrypt_segment_direct(segment, &mut output[..required])?;
        Ok(required)
    }

    /// Authenticates and returns an arbitrary plaintext byte range.
    ///
    /// Accepts any range form (`a..b`, `a..=b`, `a..`, `..b`, `..`); open
    /// ends resolve against the complete plaintext length.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid range, length overflow, underlying I/O
    /// failure, malformed framing, or authentication failure.
    pub fn read_range(&mut self, range: impl RangeBounds<u64>) -> io::Result<Vec<u8>> {
        let range = resolve_bounds(&range, self.plaintext_length())?;
        let capacity = usize::try_from(range.end - range.start).map_err(|_| length_overflow())?;
        let mut output = vec![0; capacity];
        self.read_resolved_range_into(range, &mut output)?;
        Ok(output)
    }

    /// Authenticates an arbitrary plaintext byte range into `output`.
    ///
    /// `output` must have exactly the range length or be larger. The returned
    /// value is the number of plaintext bytes written.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_range`], plus an error when
    /// `output` is too small.
    pub fn read_range_into(
        &mut self,
        range: impl RangeBounds<u64>,
        output: &mut [u8],
    ) -> io::Result<usize> {
        let range = resolve_bounds(&range, self.plaintext_length())?;
        let required = usize::try_from(range.end - range.start).map_err(|_| length_overflow())?;
        if output.len() < required {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                Error::OutputTooSmall {
                    actual: output.len(),
                    required,
                },
            ));
        }
        self.read_resolved_range_into(range, output)
    }

    fn read_resolved_range_into(
        &mut self,
        range: Range<u64>,
        output: &mut [u8],
    ) -> io::Result<usize> {
        if range.is_empty() {
            return Ok(0);
        }

        let segment_length = u64::from(self.parameters().plaintext_segment_length_u32());
        let first = range.start / segment_length;
        let last = (range.end - 1) / segment_length;
        let mut written = 0;

        for position in first..=last {
            let segment = self.segment(position)?;
            let segment_start = segment.plaintext_offset();
            let segment_plaintext_length = length_usize_to_u64(segment.plaintext_length());

            let is_covered_fully = range.start <= segment_start
                && segment_start + segment_plaintext_length <= range.end;

            if is_covered_fully {
                // A fully covered segment decrypts straight into the caller's
                // buffer without an intermediate plaintext copy.
                let length = segment.plaintext_length();
                self.decrypt_segment_direct(segment, &mut output[written..written + length])?;
                written += length;
            } else {
                self.load_cached_segment(segment)?;
                let plaintext = self.scratch.plaintext().map_err(decryption_error)?;
                // The loop starts at `range.start / segment_length`, so this
                // difference is below one segment length and fits in usize.
                // The `.min(plaintext.len())` after the conversion is
                // redundant given that bound; it stays as cheap defense in
                // depth.
                let local_start = usize::try_from(range.start.saturating_sub(segment_start))
                    .map_err(|_| length_overflow())?
                    .min(plaintext.len());
                let local_end_u64 = range
                    .end
                    .min(segment_start + length_usize_to_u64(plaintext.len()))
                    - segment_start;
                // Bounded by `plaintext.len()`, which fits in usize by
                // construction.
                let local_end = usize::try_from(local_end_u64).map_err(|_| length_overflow())?;
                let chunk = &plaintext[local_start..local_end];
                output[written..written + chunk.len()].copy_from_slice(chunk);
                written += chunk.len();
            }
        }

        debug_assert_eq!(length_usize_to_u64(written), range.end - range.start);
        Ok(written)
    }

    /// Returns a shared reference to the wrapped seekable reader.
    #[must_use]
    pub const fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped seekable reader.
    pub const fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Extracts the wrapped reader, consuming this `Reader`.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn segment(&self, position: u64) -> io::Result<SegmentLayout> {
        self.layout.segment_for_position(position).ok_or_else(|| {
            let count = self.segment_count();
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("FLOE segment position {position} is outside 0..{count}"),
            )
        })
    }

    fn seek_to_segment(&mut self, segment: SegmentLayout) -> io::Result<()> {
        let offset = self
            .message_start
            .checked_add(segment.ciphertext_offset())
            .ok_or_else(length_overflow)?;

        self.inner.seek(SeekFrom::Start(offset))?;

        Ok(())
    }

    fn load_cached_segment(&mut self, segment: SegmentLayout) -> io::Result<()> {
        if self.cached_position == Some(segment.position()) {
            // segment is already loaded
            return Ok(());
        }
        self.load_segment(segment)
    }

    fn load_segment(&mut self, segment: SegmentLayout) -> io::Result<()> {
        self.cached_position = None;
        self.seek_to_segment(segment)?;

        let ciphertext = self
            .scratch
            .prepare_ciphertext(segment.ciphertext_length())
            .map_err(decryption_error)?;

        read_exact_segment(&mut self.inner, ciphertext)?;

        self.state
            .decrypt_segment_in_place(&mut self.scratch, segment)
            .map_err(decryption_error)?;

        self.cached_position = Some(segment.position());

        Ok(())
    }

    fn decrypt_segment_direct(
        &mut self,
        segment: SegmentLayout,
        output: &mut [u8],
    ) -> io::Result<()> {
        self.cached_position = None;
        self.seek_to_segment(segment)?;

        let ciphertext = self
            .scratch
            .prepare_ciphertext(segment.ciphertext_length())
            .map_err(decryption_error)?;

        read_exact_segment(&mut self.inner, ciphertext)?;

        let ciphertext = self.scratch.ciphertext().map_err(decryption_error)?;
        self.state
            .decrypt_segment_into(ciphertext, segment, output)
            .map_err(decryption_error)?;

        Ok(())
    }

    fn seek_to_body_start(&mut self) -> io::Result<()> {
        self.inner.seek(SeekFrom::Start(
            self.message_start
                .checked_add(HEADER_LENGTH_U64)
                .ok_or_else(length_overflow)?,
        ))?;

        Ok(())
    }
}

/// Reads decrypted plaintext sequentially from the current logical position.
///
/// Each segment is authenticated before its bytes are returned;
/// sequential reads within one segment reuse the internal plaintext cache.
impl<R: Read + Seek> Read for Reader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let total = self.plaintext_length();
        if self.plaintext_position >= total {
            return Ok(0);
        }

        let segment_length = u64::from(self.parameters().plaintext_segment_length_u32());
        let position = self.plaintext_position / segment_length;
        let segment = self.segment(position)?;
        self.load_cached_segment(segment)?;

        let plaintext = self.scratch.plaintext().map_err(decryption_error)?;
        // `position = plaintext_position / segment_length`, so this remainder
        // is below one segment length and fits in usize.
        let local = usize::try_from(self.plaintext_position - segment.plaintext_offset())
            .map_err(|_| length_overflow())?;
        let read = output.len().min(plaintext.len() - local);
        output[..read].copy_from_slice(&plaintext[local..local + read]);
        self.plaintext_position += length_usize_to_u64(read);
        Ok(read)
    }
}

/// Seeks within the decrypted plaintext.
///
/// Positions beyond the plaintext length are permitted, as with a file;
/// subsequent reads there return end-of-stream.
impl<R: Read + Seek> Seek for Reader<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let resolved = match position {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.plaintext_length().checked_add_signed(delta),
            SeekFrom::Current(delta) => self.plaintext_position.checked_add_signed(delta),
        };
        match resolved {
            Some(position) => {
                self.plaintext_position = position;
                Ok(position)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside the representable plaintext position range",
            )),
        }
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.plaintext_position)
    }
}

fn resolve_bounds(range: &impl RangeBounds<u64>, plaintext_length: u64) -> io::Result<Range<u64>> {
    let start = match range.start_bound() {
        Bound::Included(&start) => start,
        Bound::Excluded(&start) => start.checked_add(1).ok_or_else(length_overflow)?,
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(&end) => end.checked_add(1).ok_or_else(length_overflow)?,
        Bound::Excluded(&end) => end,
        Bound::Unbounded => plaintext_length,
    };
    validate_range(start, end, plaintext_length)?;
    Ok(start..end)
}

fn validate_range(start: u64, end: u64, plaintext_length: u64) -> io::Result<()> {
    if start > end || end > plaintext_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("plaintext range {start}..{end} is outside 0..{plaintext_length}"),
        ));
    }
    Ok(())
}

fn remaining_length(reader: &mut (impl Read + Seek), message_start: u64) -> io::Result<u64> {
    let end = reader.seek(SeekFrom::End(0))?;
    end.checked_sub(message_start).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "FLOE ciphertext ends before its starting position",
        )
    })
}

fn validate_header_bound(ciphertext_length: u64) -> io::Result<()> {
    if ciphertext_length < HEADER_LENGTH_U64 {
        Err(decryption_error(Error::InvalidHeaderLength {
            // On this branch `ciphertext_length < HEADER_LENGTH` (74), so the
            // clamp can never engage.
            actual: usize::try_from(ciphertext_length).unwrap_or(usize::MAX),
        }))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{Parameters, encrypt};

    #[test]
    fn reads_segment_ranges_without_decrypting_complete_message() {
        let key = Key::from_bytes_with_provider([0x33; Key::LEN], crate::Provider::COMPILED[0]);
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext: Vec<u8> = (0..2 * parameters.plaintext_segment_length() + 37)
            .map(|position| u8::try_from(position % 251).unwrap())
            .collect();
        let ciphertext = encrypt(&key, b"random reader", parameters, &plaintext).unwrap();
        let mut framed = b"pre".to_vec();
        framed.extend_from_slice(&ciphertext);
        let mut cursor = Cursor::new(framed);
        cursor.set_position(3);

        let mut reader = Reader::new(cursor, &key, b"random reader").unwrap();
        assert_eq!(reader.parameters(), parameters);
        assert_eq!(
            reader.plaintext_length(),
            u64::try_from(plaintext.len()).unwrap()
        );
        assert_eq!(
            reader.read_segment(1).unwrap(),
            plaintext
                [parameters.plaintext_segment_length()..2 * parameters.plaintext_segment_length()]
        );
        let mut segment_output = vec![0; parameters.plaintext_segment_length()];
        assert_eq!(
            reader.read_segment_into(1, &mut segment_output).unwrap(),
            segment_output.len()
        );
        assert_eq!(
            segment_output,
            plaintext
                [parameters.plaintext_segment_length()..2 * parameters.plaintext_segment_length()]
        );
        assert_eq!(
            reader.read_segment_into(1, &mut []).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        let range =
            parameters.plaintext_segment_length() - 11..parameters.plaintext_segment_length() + 19;
        let range = u64::try_from(range.start).unwrap()..u64::try_from(range.end).unwrap();
        assert_eq!(
            reader.read_range(range.clone()).unwrap(),
            plaintext[usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()]
        );

        // A range spanning a fully covered middle segment exercises the
        // direct-into-output path together with both cached edges.
        let full = reader.read_range(..).unwrap();
        assert_eq!(full, plaintext);
        let tail = reader.read_range(5..).unwrap();
        assert_eq!(tail, plaintext[5..]);
        let head = reader.read_range(..=9).unwrap();
        assert_eq!(head, plaintext[..10]);
    }

    #[test]
    fn read_and_seek_provide_authenticated_plaintext_view() {
        let key = Key::from_bytes_with_provider([0x37; Key::LEN], crate::Provider::COMPILED[0]);
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment_length = parameters.plaintext_segment_length();
        let plaintext: Vec<u8> = (0..2 * segment_length + 23)
            .map(|position| u8::try_from(position % 249).unwrap())
            .collect();
        let ciphertext = encrypt(&key, b"seekable", parameters, &plaintext).unwrap();

        let mut reader = Reader::new(Cursor::new(ciphertext), &key, b"seekable").unwrap();
        let mut streamed = Vec::new();
        reader.read_to_end(&mut streamed).unwrap();
        assert_eq!(streamed, plaintext);

        let offset = u64::try_from(segment_length + 100).unwrap();
        assert_eq!(reader.seek(SeekFrom::Start(offset)).unwrap(), offset);
        let mut chunk = [0u8; 64];
        reader.read_exact(&mut chunk).unwrap();
        let start = usize::try_from(offset).unwrap();
        assert_eq!(chunk, plaintext[start..start + 64]);

        assert_eq!(
            reader.seek(SeekFrom::End(-8)).unwrap(),
            u64::try_from(plaintext.len() - 8).unwrap()
        );
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, plaintext[plaintext.len() - 8..]);

        // Seeking past the end reads as end-of-stream, and negative seeks
        // from the current position are rejected.
        reader
            .seek(SeekFrom::Start(u64::try_from(plaintext.len() + 1).unwrap()))
            .unwrap();
        let mut empty = Vec::new();
        reader.read_to_end(&mut empty).unwrap();
        assert!(empty.is_empty());
        reader.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(
            reader.seek(SeekFrom::Current(-1)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)] // deliberately invalid range input
    fn rejects_invalid_ranges_and_supports_a_parameter_policy_check() {
        let key = Key::from_bytes_with_provider([0x44; Key::LEN], crate::Provider::COMPILED[0]);
        let ciphertext = encrypt(
            &key,
            b"random reader",
            Parameters::SEGMENT_4_KIB,
            b"plaintext",
        )
        .unwrap();

        let mut reader = Reader::new(Cursor::new(ciphertext), &key, b"random reader").unwrap();
        assert_ne!(reader.parameters(), Parameters::SEGMENT_1_MIB);
        assert_eq!(
            reader.read_range(0..u64::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            reader.read_range(5..2).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn construction_authenticates_complete_message_tail() {
        let key = Key::from_bytes_with_provider([0x45; Key::LEN], crate::Provider::COMPILED[0]);
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext = vec![0x5a; parameters.plaintext_segment_length() + 19];
        let ciphertext = encrypt(&key, b"random reader", parameters, &plaintext).unwrap();

        for length in 0..ciphertext.len() {
            let truncated = &ciphertext[..length];
            assert!(
                Reader::new(Cursor::new(truncated), &key, b"random reader").is_err(),
                "constructor accepted truncation at {length}"
            );
        }

        let mut appended = ciphertext.clone();
        appended.push(0);
        assert!(Reader::new(Cursor::new(appended), &key, b"random reader").is_err());

        let layout = parameters
            .ciphertext_layout(u64::try_from(ciphertext.len()).unwrap())
            .unwrap();
        let final_segment = layout.final_segment();
        let mut forged = ciphertext;
        let prefix_start = usize::try_from(final_segment.ciphertext_offset()).unwrap();
        let forged_length = u32::try_from(final_segment.ciphertext_length() - 1)
            .unwrap()
            .to_be_bytes();
        forged[prefix_start..prefix_start + crate::SEGMENT_PREFIX_LENGTH]
            .copy_from_slice(&forged_length);
        assert!(Reader::new(Cursor::new(forged), &key, b"random reader").is_err());
    }

    #[test]
    fn bounded_constructor_preserves_following_frame() {
        let key = Key::from_bytes_with_provider([0x46; Key::LEN], crate::Provider::COMPILED[0]);
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext = b"bounded random access";
        let ciphertext = encrypt(&key, b"random reader", parameters, plaintext).unwrap();
        let ciphertext_length = u64::try_from(ciphertext.len()).unwrap();
        let mut framed = b"pre".to_vec();
        framed.extend_from_slice(&ciphertext);
        framed.extend_from_slice(b"next frame");

        let mut cursor = Cursor::new(framed.clone());
        cursor.set_position(3);
        let mut reader =
            Reader::new_with_length(cursor, &key, b"random reader", ciphertext_length).unwrap();
        assert_eq!(reader.parameters(), parameters);
        assert_eq!(
            reader.read_range(0..plaintext.len() as u64).unwrap(),
            plaintext
        );
        let inner = reader.into_inner();
        let position = usize::try_from(inner.position()).unwrap();
        assert_eq!(&inner.get_ref()[position..], b"next frame");

        let mut cursor = Cursor::new(framed);
        cursor.set_position(3);
        assert!(Reader::new(cursor, &key, b"random reader").is_err());

        assert!(
            Reader::new_with_length(
                Cursor::new(vec![0; Header::LEN]),
                &key,
                b"random reader",
                u64::try_from(Header::LEN - 1).unwrap(),
            )
            .is_err()
        );
    }
}
