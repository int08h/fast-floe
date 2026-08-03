//! Authenticated random access to complete, seekable FLOE ciphertexts.
//!
//! [`Reader`] authenticates the header and final segment up front, then
//! serves lazily authenticated segment and range reads.
//!
//! It also implements [`Read`] and [`Seek`] over the plaintext, so the
//! decrypted view composes with code that expects an ordinary seekable stream.

use core::mem;
use core::ops::{Bound, Range, RangeBounds};
use std::io::{self, Read, Seek, SeekFrom};

use zeroize::Zeroizing;

pub use crate::parameters::{MessageLayout, SegmentLayout, Segments};
use crate::wire::{
    decryption_error, length_overflow, output_too_small, read_exact_segment, read_header,
};
use crate::{
    DecryptionState, Error, HEADER_LENGTH_U64, Header, Key, Parameters, SegmentBuffer,
    length_u64_to_usize_saturating, length_usize_to_u64, start_decryption,
    start_decryption_inferred,
};

/// Authenticated random-access reader for a complete seekable FLOE ciphertext.
///
/// Construction treats the bytes from the reader's current position through
/// EOF as one complete FLOE message unless [`Self::new_with_length`]
/// is used. Both the header and final segment are authenticated before
/// exposing the message content.
///
/// The underlying source must not change while this reader is in use.
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
    /// The wrapped reader's byte position when known, letting contiguous
    /// segment accesses skip redundant seeks (which would also discard any
    /// `BufReader` buffer). `None` whenever the position is uncertain.
    inner_position: Option<u64>,
}

impl<R: Read + Seek> Reader<R> {
    /// Opens a seekable ciphertext using parameters read from its header.
    ///
    /// # Errors
    ///
    /// Returns an error for seek/read failures, an invalid or unauthenticated
    /// header, an impossible complete ciphertext length, or a final segment
    /// that fails authentication (the final segment is authenticated during
    /// construction).
    pub fn new(mut inner: R, key: &Key, aad: &[u8]) -> io::Result<Self> {
        let message_start = inner.stream_position()?;
        let header = read_header(&mut inner)?;
        let state = start_decryption_inferred(key, aad, &header).map_err(decryption_error)?;
        let ciphertext_length = remaining_length(&mut inner, message_start)?;
        Self::from_parts(inner, state, header, message_start, ciphertext_length)
    }

    /// Opens a seekable ciphertext, requiring its header to declare
    /// `parameters`.
    ///
    /// Use this constructor to enforce a segment length: construction
    /// fails before any payload is produced when the authenticated header does
    /// not match `parameters`.
    ///
    /// # Errors
    ///
    /// In addition to the [`Self::new`] errors, returns an error when the
    /// header declares a parameter set other than `parameters`
    /// ([`Error::InvalidHeaderParameters`]).
    ///
    /// [`Error::InvalidHeaderParameters`]: crate::Error::InvalidHeaderParameters
    pub fn new_with_parameters(
        mut inner: R,
        key: &Key,
        aad: &[u8],
        parameters: Parameters,
    ) -> io::Result<Self> {
        let message_start = inner.stream_position()?;
        let header = read_header(&mut inner)?;
        let state = start_decryption(key, aad, parameters, &header).map_err(decryption_error)?;
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
    /// unauthenticated header, a final segment inconsistent with the bound,
    /// or a final segment that fails authentication (the final segment is
    /// authenticated during construction).
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

    /// Opens a ciphertext with an explicit length, requiring its header to
    /// declare `parameters`.
    ///
    /// Combines the explicit bound of [`Self::new_with_length`] with the
    /// parameters of [`Self::new_with_parameters`].
    ///
    /// # Errors
    ///
    /// In addition to the [`Self::new_with_length`] errors, returns an error
    /// when the header declares a parameter set other than `parameters`
    /// ([`Error::InvalidHeaderParameters`]).
    ///
    /// [`Error::InvalidHeaderParameters`]: crate::Error::InvalidHeaderParameters
    pub fn new_with_length_and_parameters(
        mut inner: R,
        key: &Key,
        aad: &[u8],
        ciphertext_length: u64,
        parameters: Parameters,
    ) -> io::Result<Self> {
        validate_header_bound(ciphertext_length)?;
        let message_start = inner.stream_position()?;
        let header = read_header(&mut inner)?;
        let state = start_decryption(key, aad, parameters, &header).map_err(decryption_error)?;
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
            inner_position: None,
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
        let mut plaintext = Zeroizing::new(vec![0; segment.plaintext_length()]);
        self.read_segment_into(position, &mut plaintext)?;

        Ok(mem::take(&mut *plaintext))
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
            return Err(output_too_small(output.len(), required));
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
        let mut output = Zeroizing::new(vec![0; capacity]);
        self.read_resolved_range_into(range, &mut output)?;

        Ok(mem::take(&mut *output))
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
            return Err(output_too_small(output.len(), required));
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

        let first = self.layout.position_for_plaintext_offset(range.start);
        let last = self.layout.position_for_plaintext_offset(range.end - 1);
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
                let local_start = usize::try_from(range.start.saturating_sub(segment_start))
                    .map_err(|_| length_overflow())?
                    .min(plaintext.len());
                let local_end_u64 = range
                    .end
                    .min(segment_start + length_usize_to_u64(plaintext.len()))
                    - segment_start;

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
    ///
    /// This discards the tracked stream position, so the next segment access
    /// seeks explicitly even if the wrapped reader was not moved.
    pub fn get_mut(&mut self) -> &mut R {
        self.inner_position = None;
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
        self.seek_inner_to(offset)
    }

    /// Seeks the wrapped reader to `offset`, skipping the call when the
    /// tracked position already matches.
    fn seek_inner_to(&mut self, offset: u64) -> io::Result<()> {
        if self.inner_position == Some(offset) {
            return Ok(());
        }
        self.inner_position = None;
        self.inner.seek(SeekFrom::Start(offset))?;
        self.inner_position = Some(offset);
        Ok(())
    }

    fn load_cached_segment(&mut self, segment: SegmentLayout) -> io::Result<()> {
        if self.cached_position == Some(segment.position()) {
            // segment is already loaded
            return Ok(());
        }
        self.load_segment(segment)
    }

    /// Invalidates the plaintext cache, then seeks to `segment` and reads its
    /// complete ciphertext into the scratch buffer.
    fn fetch_segment_ciphertext(&mut self, segment: SegmentLayout) -> io::Result<()> {
        self.cached_position = None;
        self.seek_to_segment(segment)?;

        // The stream position is uncertain while the read is outstanding: a
        // failed or short read leaves the reader somewhere inside the segment.
        let position_after_read = self.inner_position.take().and_then(|position| {
            position.checked_add(length_usize_to_u64(segment.ciphertext_length()))
        });

        let ciphertext = self
            .scratch
            .prepare_ciphertext(segment.ciphertext_length())
            .map_err(decryption_error)?;

        read_exact_segment(&mut self.inner, ciphertext)?;
        self.inner_position = position_after_read;
        Ok(())
    }

    fn load_segment(&mut self, segment: SegmentLayout) -> io::Result<()> {
        self.fetch_segment_ciphertext(segment)?;

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
        self.fetch_segment_ciphertext(segment)?;

        let ciphertext = self.scratch.ciphertext().map_err(decryption_error)?;
        self.state
            .decrypt_segment_into(ciphertext, segment, output)
            .map_err(decryption_error)?;

        Ok(())
    }

    fn seek_to_body_start(&mut self) -> io::Result<()> {
        let offset = self
            .message_start
            .checked_add(HEADER_LENGTH_U64)
            .ok_or_else(length_overflow)?;
        self.seek_inner_to(offset)
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

        let position = self
            .layout
            .position_for_plaintext_offset(self.plaintext_position);
        let segment = self.segment(position)?;
        self.load_cached_segment(segment)?;

        let plaintext = self.scratch.plaintext().map_err(decryption_error)?;
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
            actual: length_u64_to_usize_saturating(ciphertext_length),
        }))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;
    use std::rc::Rc;

    use super::*;
    use crate::key::test_key;
    use crate::{LengthRequirement, Parameters, encrypt};

    /// Delegating reader that counts how many `seek` calls reach the
    /// underlying stream.
    struct SeekCounting<R> {
        inner: R,
        seeks: Rc<Cell<usize>>,
    }

    impl<R: Read> Read for SeekCounting<R> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.inner.read(output)
        }
    }

    impl<R: Seek> Seek for SeekCounting<R> {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.seeks.set(self.seeks.get() + 1);
            self.inner.seek(position)
        }
    }

    /// Delegating seekable reader with injectable seek and read failures and
    /// an optional cap on total bytes served, after which it reports end of
    /// stream early.
    struct FailingSeeker<R> {
        inner: R,
        fail_seeks: bool,
        fail_reads: bool,
        remaining: Option<usize>,
    }

    impl<R> FailingSeeker<R> {
        fn new(inner: R) -> Self {
            Self {
                inner,
                fail_seeks: false,
                fail_reads: false,
                remaining: None,
            }
        }
    }

    impl<R: Read> Read for FailingSeeker<R> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.fail_reads {
                return Err(io::Error::other("injected read failure"));
            }
            match self.remaining {
                None => self.inner.read(output),
                Some(remaining) => {
                    let allowed = remaining.min(output.len());
                    let read = self.inner.read(&mut output[..allowed])?;
                    self.remaining = Some(remaining - read);
                    Ok(read)
                }
            }
        }
    }

    impl<R: Seek> Seek for FailingSeeker<R> {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            if self.fail_seeks {
                return Err(io::Error::other("injected seek failure"));
            }
            self.inner.seek(position)
        }
    }

    /// Broken `Seek` implementation whose reported end position lies before
    /// the message start.
    #[derive(Debug)]
    struct LyingEndSeeker(Cursor<Vec<u8>>);

    impl Read for LyingEndSeeker {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.0.read(output)
        }
    }

    impl Seek for LyingEndSeeker {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            match position {
                SeekFrom::End(_) => Ok(0),
                other => self.0.seek(other),
            }
        }
    }

    type FailingSeekerReader = Reader<FailingSeeker<Cursor<Vec<u8>>>>;

    fn failing_reader_fixture() -> (FailingSeekerReader, Vec<u8>, Parameters) {
        let (plaintext, ciphertext, parameters) = fixture_message();
        let reader = Reader::new(
            FailingSeeker::new(Cursor::new(ciphertext)),
            &test_key(),
            b"random reader",
        )
        .unwrap();
        (reader, plaintext, parameters)
    }

    /// The shared three-segment fixture message.
    fn fixture_message() -> (Vec<u8>, Vec<u8>, Parameters) {
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext: Vec<u8> = (0..2 * parameters.plaintext_segment_length() + 37)
            .map(|position| u8::try_from(position % 251).unwrap())
            .collect();
        let ciphertext = encrypt(&test_key(), b"random reader", parameters, &plaintext).unwrap();
        (plaintext, ciphertext, parameters)
    }

    fn framed_reader_fixture() -> (Reader<Cursor<Vec<u8>>>, Vec<u8>, Parameters) {
        let (plaintext, ciphertext, parameters) = fixture_message();
        let mut framed = b"pre".to_vec();
        framed.extend_from_slice(&ciphertext);
        let mut cursor = Cursor::new(framed);
        cursor.set_position(3);
        let reader = Reader::new(cursor, &test_key(), b"random reader").unwrap();
        (reader, plaintext, parameters)
    }

    #[test]
    fn reads_individual_segments_without_decrypting_complete_message() {
        // Given a reader over a three-segment message that starts mid-stream
        let (mut reader, plaintext, parameters) = framed_reader_fixture();
        assert_eq!(reader.parameters(), parameters);
        assert_eq!(
            reader.plaintext_length(),
            u64::try_from(plaintext.len()).unwrap()
        );

        // When the middle segment is read by position
        // Then exactly that segment's plaintext is returned
        assert_eq!(
            reader.read_segment(1).unwrap(),
            plaintext
                [parameters.plaintext_segment_length()..2 * parameters.plaintext_segment_length()]
        );

        // When it is read into a caller-provided buffer
        // Then the same bytes are written at the declared length
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

        // When the buffer is too small, then the read is rejected
        assert_eq!(
            reader.read_segment_into(1, &mut []).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn reads_arbitrary_ranges_across_segment_boundaries() {
        // Given a reader over a three-segment message that starts mid-stream
        let (mut reader, plaintext, parameters) = framed_reader_fixture();

        // When a range straddling a segment boundary is read
        // Then exactly the requested bytes are returned
        let range =
            parameters.plaintext_segment_length() - 11..parameters.plaintext_segment_length() + 19;
        let range = u64::try_from(range.start).unwrap()..u64::try_from(range.end).unwrap();
        assert_eq!(
            reader.read_range(range.clone()).unwrap(),
            plaintext[usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()]
        );

        // When every open and closed range form is read
        // Then each resolves against the plaintext length.
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
        // Given a reader over a message spanning three segments
        let key = test_key();
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment_length = parameters.plaintext_segment_length();
        let plaintext: Vec<u8> = (0..2 * segment_length + 23)
            .map(|position| u8::try_from(position % 249).unwrap())
            .collect();
        let ciphertext = encrypt(&key, b"seekable", parameters, &plaintext).unwrap();
        let mut reader = Reader::new(Cursor::new(ciphertext), &key, b"seekable").unwrap();

        // When the whole view is streamed with the Read implementation
        let mut streamed = Vec::new();
        reader.read_to_end(&mut streamed).unwrap();

        // Then the complete plaintext is produced
        assert_eq!(streamed, plaintext);

        // When the reader seeks from the start and reads a chunk
        let offset = u64::try_from(segment_length + 100).unwrap();
        assert_eq!(reader.seek(SeekFrom::Start(offset)).unwrap(), offset);
        let mut chunk = [0u8; 64];
        reader.read_exact(&mut chunk).unwrap();

        // Then the chunk matches the plaintext at that offset
        let start = usize::try_from(offset).unwrap();
        assert_eq!(chunk, plaintext[start..start + 64]);

        // When the reader seeks from the end and reads to the end
        assert_eq!(
            reader.seek(SeekFrom::End(-8)).unwrap(),
            u64::try_from(plaintext.len() - 8).unwrap()
        );
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).unwrap();

        // Then exactly the plaintext tail is produced
        assert_eq!(tail, plaintext[plaintext.len() - 8..]);
    }

    #[test]
    fn seeks_past_end_read_as_empty_and_negative_seeks_rejected() {
        // Given a seekable reader over a short message
        let key = test_key();
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext = b"seek boundaries";
        let ciphertext = encrypt(&key, b"seekable", parameters, plaintext).unwrap();
        let mut reader = Reader::new(Cursor::new(ciphertext), &key, b"seekable").unwrap();

        // When the reader seeks past the end of the plaintext
        reader
            .seek(SeekFrom::Start(u64::try_from(plaintext.len() + 1).unwrap()))
            .unwrap();

        // Then reading produces end-of-stream rather than an error
        let mut empty = Vec::new();
        reader.read_to_end(&mut empty).unwrap();
        assert!(empty.is_empty());

        // When the reader seeks before position zero
        // Then the seek is rejected
        reader.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(
            reader.seek(SeekFrom::Current(-1)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)] // deliberately invalid range input
    fn rejects_invalid_ranges_and_supports_a_parameter_check() {
        // Given a reader over a single-segment message
        let key = test_key();
        let ciphertext = encrypt(
            &key,
            b"random reader",
            Parameters::SEGMENT_4_KIB,
            b"plaintext",
        )
        .unwrap();
        let mut reader = Reader::new(Cursor::new(ciphertext), &key, b"random reader").unwrap();

        // Then the authenticated parameters are available
        assert_ne!(reader.parameters(), Parameters::SEGMENT_1_MIB);

        // When a range beyond the plaintext or a reversed range is read
        // Then each is rejected as invalid input
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
    fn contiguous_segment_reads_skip_redundant_seeks() {
        // Given a reader over a three-segment message whose underlying
        // stream counts seek calls
        let key = test_key();
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext: Vec<u8> = (0..2 * parameters.plaintext_segment_length() + 11)
            .map(|position| u8::try_from(position % 251).unwrap())
            .collect();
        let ciphertext = encrypt(&key, b"seek count", parameters, &plaintext).unwrap();
        let seeks = Rc::new(Cell::new(0));
        let counting = SeekCounting {
            inner: Cursor::new(ciphertext),
            seeks: Rc::clone(&seeks),
        };
        let mut reader = Reader::new(counting, &key, b"seek count").unwrap();

        // When the plaintext is streamed sequentially after construction
        seeks.set(0);
        let mut streamed = Vec::new();
        reader.read_to_end(&mut streamed).unwrap();

        // Then every segment followed the previous one and no seek was needed
        assert_eq!(streamed, plaintext);
        assert_eq!(seeks.get(), 0, "contiguous reads must not reseek");

        // When a whole-message range read follows the sequential pass
        seeks.set(0);
        assert_eq!(reader.read_range(..).unwrap(), plaintext);

        // Then only the initial repositioning to the first segment seeks
        assert_eq!(seeks.get(), 1, "only the first segment requires a seek");
    }

    #[test]
    fn moving_the_inner_reader_through_get_mut_is_tolerated() {
        // Given a reader over a three-segment message
        let key = test_key();
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment_length = parameters.plaintext_segment_length();
        let plaintext: Vec<u8> = (0..2 * segment_length + 17)
            .map(|position| u8::try_from(position % 251).unwrap())
            .collect();
        let ciphertext = encrypt(&key, b"get_mut", parameters, &plaintext).unwrap();
        let mut reader = Reader::new(Cursor::new(ciphertext), &key, b"get_mut").unwrap();
        assert_eq!(
            reader.read_segment(1).unwrap(),
            plaintext[segment_length..2 * segment_length]
        );

        // When the wrapped reader is repositioned behind the reader's back
        reader.get_mut().seek(SeekFrom::Start(0)).unwrap();

        // Then subsequent segment reads reposition explicitly and still
        // authenticate the correct segments
        assert_eq!(
            reader.read_segment(2).unwrap(),
            plaintext[2 * segment_length..]
        );
        assert_eq!(reader.read_segment(0).unwrap(), plaintext[..segment_length]);
    }

    #[test]
    fn construction_authenticates_complete_message_tail() {
        // Given a valid two-segment ciphertext
        let key = test_key();
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext = vec![0x5a; parameters.plaintext_segment_length() + 19];
        let ciphertext = encrypt(&key, b"random reader", parameters, &plaintext).unwrap();

        // When a reader is constructed over every truncation of it
        for length in 0..ciphertext.len() {
            let truncated = &ciphertext[..length];

            // Then construction rejects the incomplete message up front
            assert!(
                Reader::new(Cursor::new(truncated), &key, b"random reader").is_err(),
                "constructor accepted truncation at {length}"
            );
        }

        // When one byte is appended to the complete message
        // Then construction rejects the trailing data
        let mut appended = ciphertext.clone();
        appended.push(0);
        assert!(Reader::new(Cursor::new(appended), &key, b"random reader").is_err());

        // When the final segment's length prefix understates its length
        // Then construction rejects the forged tail
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
        // Given a stream holding a complete message between unrelated bytes
        let key = test_key();
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext = b"bounded random access";
        let ciphertext = encrypt(&key, b"random reader", parameters, plaintext).unwrap();
        let ciphertext_length = u64::try_from(ciphertext.len()).unwrap();
        let mut framed = b"pre".to_vec();
        framed.extend_from_slice(&ciphertext);
        framed.extend_from_slice(b"next frame");

        // When a reader is constructed with the message's explicit length
        let mut cursor = Cursor::new(framed.clone());
        cursor.set_position(3);
        let mut reader =
            Reader::new_with_length(cursor, &key, b"random reader", ciphertext_length).unwrap();

        // Then the bounded message reads fully and the inner reader stops
        // exactly at the following frame
        assert_eq!(reader.parameters(), parameters);
        assert_eq!(
            reader.read_range(0..plaintext.len() as u64).unwrap(),
            plaintext
        );
        let inner = reader.into_inner();
        let position = usize::try_from(inner.position()).unwrap();
        assert_eq!(&inner.get_ref()[position..], b"next frame");

        // When the unbounded constructor sees the same stream
        // Then the trailing frame makes construction fail
        let mut cursor = Cursor::new(framed);
        cursor.set_position(3);
        assert!(Reader::new(cursor, &key, b"random reader").is_err());

        // When the declared bound cannot hold a complete header
        // Then construction fails
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

    #[test]
    fn read_range_into_writes_exact_range() {
        // Given a range spanning a partial, a full, and a partial segment
        let (mut reader, plaintext, parameters) = framed_reader_fixture();
        let capacity = parameters.plaintext_segment_length();
        let start = capacity - 7;
        let end = 2 * capacity + 5;
        let required = end - start;

        // When the range is read into an oversized output allocation
        let mut output = vec![0xEE; required + 9];
        let written = reader
            .read_range_into(
                u64::try_from(start).unwrap()..u64::try_from(end).unwrap(),
                &mut output,
            )
            .unwrap();

        // Then exactly the requested bytes are written and the remainder of
        // the allocation is untouched
        assert_eq!(written, required);
        assert_eq!(&output[..written], &plaintext[start..end]);
        assert!(output[written..].iter().all(|&byte| byte == 0xEE));
    }

    #[test]
    fn read_range_into_rejects_small_output() {
        // Given an output allocation one byte too small for the range
        let (mut reader, _, _) = framed_reader_fixture();
        let mut output = [0u8; 9];

        // When the range is read into it
        let error = reader.read_range_into(0u64..10, &mut output).unwrap_err();

        // Then the exact shortfall is classified as invalid input
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(matches!(
            Error::io_source(&error),
            Some(Error::OutputTooSmall {
                actual: 9,
                required: 10,
            })
        ));
    }

    #[test]
    fn empty_range_reads_no_segments() {
        // Given a reader whose source fails on any further seek or read
        let (mut reader, _, _) = failing_reader_fixture();
        reader.get_mut().fail_seeks = true;
        reader.get_mut().fail_reads = true;

        // When empty ranges are read through both range APIs
        // Then both succeed without performing any I/O
        assert_eq!(reader.read_range(7u64..7).unwrap(), Vec::<u8>::new());
        let mut output = [0u8; 4];
        assert_eq!(reader.read_range_into(7u64..7, &mut output).unwrap(), 0);
    }

    #[test]
    fn read_segment_rejects_position_equal_to_segment_count() {
        // Given a reader over a three-segment message
        let (mut reader, _, _) = framed_reader_fixture();
        let count = reader.segment_count();
        assert_eq!(count, 3);

        // When the first out-of-range position is read
        let error = reader.read_segment(count).unwrap_err();

        // Then the position and valid range are reported as invalid input
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains(&format!("position {count} is outside 0..{count}"))
        );
    }

    #[test]
    fn range_bounds_overflowing_u64_are_rejected() {
        // Given range bounds whose resolution overflows u64
        struct ExcludedMaxStart;

        impl RangeBounds<u64> for ExcludedMaxStart {
            fn start_bound(&self) -> Bound<&u64> {
                Bound::Excluded(&u64::MAX)
            }

            fn end_bound(&self) -> Bound<&u64> {
                Bound::Unbounded
            }
        }

        let (mut reader, _, _) = framed_reader_fixture();

        // When either overflowing form is read
        // Then both are classified as invalid input carrying LengthOverflow
        for error in [
            reader.read_range(ExcludedMaxStart).unwrap_err(),
            reader.read_range(0..=u64::MAX).unwrap_err(),
        ] {
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(matches!(
                Error::io_source(&error),
                Some(Error::LengthOverflow)
            ));
        }
    }

    #[test]
    fn seek_failure_while_loading_a_segment_propagates() {
        // Given a reader whose source rejects seeks, with the tracked
        // position discarded by get_mut
        let (mut reader, plaintext, parameters) = failing_reader_fixture();
        reader.get_mut().fail_seeks = true;

        // When a non-cached segment is loaded
        let error = reader.read_segment(1).unwrap_err();

        // Then the injected failure is propagated
        assert!(error.to_string().contains("injected seek failure"));

        // Then clearing the fault restores the reader
        reader.get_mut().fail_seeks = false;
        assert_eq!(
            reader.read_segment(1).unwrap(),
            plaintext
                [parameters.plaintext_segment_length()..2 * parameters.plaintext_segment_length()]
        );
    }

    #[test]
    fn read_failure_after_successful_seek_propagates() {
        // Given a reader whose source fails reads but not seeks
        let (mut reader, _, _) = failing_reader_fixture();
        reader.get_mut().fail_reads = true;

        // When a segment is loaded, then the injected failure is propagated
        let error = reader.read_segment(1).unwrap_err();
        assert!(error.to_string().contains("injected read failure"));
    }

    #[test]
    fn short_segment_read_reports_exact_length_diagnostics() {
        // Given a source that serves only 100 more bytes of a full segment
        let (mut reader, _, parameters) = failing_reader_fixture();
        reader.get_mut().remaining = Some(100);

        // When the full first segment is read
        let error = reader.read_segment(0).unwrap_err();

        // Then the short read is classified with both exact lengths
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(matches!(
            Error::io_source(&error),
            Some(Error::InvalidCiphertextLength {
                actual: 100,
                required: LengthRequirement::Exactly(required),
            }) if *required == parameters.ciphertext_segment_length()
        ));
    }

    #[test]
    fn construction_rejects_end_position_before_message_start() {
        // Given a broken source whose reported end lies before the message
        // start position
        let key = test_key();
        let parameters = Parameters::SEGMENT_4_KIB;
        let ciphertext = encrypt(&key, b"random reader", parameters, b"data").unwrap();
        let mut framed = b"pre".to_vec();
        framed.extend_from_slice(&ciphertext);
        let mut cursor = Cursor::new(framed);
        cursor.set_position(3);

        // When a reader is constructed over it
        let error = Reader::new(LyingEndSeeker(cursor), &key, b"random reader").unwrap_err();

        // Then the impossible geometry is rejected as invalid data
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("ends before its starting position")
        );
    }

    #[test]
    fn accessors_and_plaintext_position_are_observable() {
        // Given a reader over a three-segment message
        let (mut reader, plaintext, parameters) = framed_reader_fixture();
        let total = u64::try_from(plaintext.len()).unwrap();

        // Then the header, layout, and count accessors agree with the
        // authenticated message geometry
        assert_eq!(reader.header().unverified_parameters().unwrap(), parameters);
        assert_eq!(reader.layout().plaintext_length(), total);
        assert_eq!(reader.layout().segment_count(), 3);
        assert_eq!(reader.segment_count(), 3);
        assert!(reader.get_ref().position() > 0);

        // When the plaintext view seeks and reads
        // Then empty reads leave the position alone and reads advance it
        reader.seek(SeekFrom::Start(5)).unwrap();
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        assert_eq!(reader.stream_position().unwrap(), 5);
        reader.read_exact(&mut [0u8; 4]).unwrap();
        assert_eq!(reader.stream_position().unwrap(), 9);

        // Then the wrapped reader is recoverable
        let inner = reader.into_inner();
        assert!(inner.position() > 0);
    }
}
