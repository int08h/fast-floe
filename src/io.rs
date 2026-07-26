//! Bounded-memory `std::io` adapters for FLOE streams.
//!
//! [`EncryptReader`]/[`EncryptWriter`] are the recommended encryption adapters.
//! [`Write::flush`] semantics that FLOE's framing makes unavoidable — see its
//! type documentation.
//!
//! [`DecryptReader`] decrypts a stream and, by default,
//! requires the message to occupy the entire underlying stream; use its
//! `*_frame` finalizers when another frame follows. No push-side decryption
//! adapter exists because it would reproduce the same partial-segment flush
//! problem as [`EncryptWriter`] without a pull-side alternative.

use std::io::{self, Read, Write};

use crate::online::{Decryptor, Encryptor};
use crate::wire::{decryption_error, encryption_error, read_fully, read_header};
use crate::{Error, Header, Key, LengthRequirement, Parameters, SegmentBuffer};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamStatus {
    Open,
    Finished,
    Failed,
}

/// Error returned when consuming I/O-adapter finalization cannot complete.
///
/// The wrapped I/O object remains recoverable with [`Self::into_inner`],
/// although its stream position or contents may reflect a partial operation.
pub struct FinishError<W> {
    inner: W,
    error: io::Error,
}

impl<W> FinishError<W> {
    /// Returns the I/O or encryption error that prevented finalization.
    #[must_use]
    pub const fn error(&self) -> &io::Error {
        &self.error
    }

    /// Recovers the wrapped I/O object.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Separates the finalization error and wrapped I/O object.
    #[must_use]
    pub fn into_parts(self) -> (io::Error, W) {
        (self.error, self.inner)
    }
}

impl<W> core::fmt::Display for FinishError<W> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "failed to finish FLOE stream: {}", self.error)
    }
}

impl<W> core::fmt::Debug for FinishError<W> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FinishError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<W> std::error::Error for FinishError<W> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// A bounded-memory FLOE encrypting writer.
///
/// Complete the message with [`Self::finish`], which consumes this adapter and
/// returns the wrapped writer. Use [`Self::into_inner_unfinished`] only when
/// deliberately abandoning an incomplete ciphertext.
///
/// Because FLOE permits only full-sized non-final segments, [`Write::flush`]
/// cannot emit a buffered partial segment without closing the message. It
/// flushes only ciphertext already written to the wrapped writer. Only
/// [`Self::try_finish`] or [`Self::finish`] emits the buffered partial segment.
/// Dropping this type without successful finalization leaves a truncated
/// ciphertext. Prefer [`EncryptReader`] when pull-side composition fits.
#[derive(Debug)]
pub struct EncryptWriter<W> {
    inner: W,
    encryptor: Option<Encryptor>,
    header: Header,
    parameters: Parameters,
    buffer: SegmentBuffer,
    plaintext_length: usize,
    status: StreamStatus,
}

impl<W: Write> EncryptWriter<W> {
    /// Creates an encrypting writer and writes its authenticated header.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption initialization, random generation, or
    /// writing the header fails.
    pub fn new(mut inner: W, key: &Key, aad: &[u8], parameters: Parameters) -> io::Result<Self> {
        let encryptor = Encryptor::new(key, aad, parameters).map_err(encryption_error)?;
        let header = *encryptor.header();
        inner.write_all(header.as_ref())?;
        Ok(Self {
            inner,
            encryptor: Some(encryptor),
            header,
            parameters,
            buffer: SegmentBuffer::new(parameters),
            plaintext_length: 0,
            status: StreamStatus::Open,
        })
    }

    /// Returns the authenticated header already written to the wrapped writer.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Returns this writer's parameter set.
    #[must_use]
    pub const fn parameters(&self) -> Parameters {
        self.parameters
    }

    /// Returns a shared reference to the wrapped writer.
    #[must_use]
    pub const fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped writer.
    ///
    /// Writing ciphertext directly can corrupt the FLOE message.
    pub const fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Returns whether finalization completed successfully.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self.status, StreamStatus::Finished)
    }

    /// Attempts finalization without consuming the adapter.
    ///
    /// This is idempotent after success. After an error, the writer is poisoned
    /// because the wrapped output may contain a partial segment.
    ///
    /// # Errors
    ///
    /// Returns an error if final-segment encryption, ciphertext output, or
    /// flushing fails.
    pub fn try_finish(&mut self) -> io::Result<()> {
        match self.status {
            StreamStatus::Finished => return Ok(()),
            StreamStatus::Failed => return Err(poisoned_error()),
            StreamStatus::Open => {}
        }

        let encryptor = self.encryptor.take().ok_or_else(poisoned_error)?;
        self.buffer
            .prepare_plaintext(self.plaintext_length)
            .map_err(encryption_error)?;
        if let Err(error) = encryptor.encrypt_final_segment_in_place(&mut self.buffer) {
            self.status = StreamStatus::Failed;
            return Err(encryption_error(error.into_error()));
        }

        let ciphertext = self.buffer.ciphertext().map_err(encryption_error)?;
        if let Err(error) = self.inner.write_all(ciphertext) {
            self.status = StreamStatus::Failed;
            return Err(error);
        }
        self.plaintext_length = 0;
        if let Err(error) = self.inner.flush() {
            self.status = StreamStatus::Failed;
            return Err(error);
        }
        self.status = StreamStatus::Finished;
        Ok(())
    }

    /// Finalizes the FLOE message and returns the wrapped writer.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::try_finish`] fails.
    pub fn finish(mut self) -> Result<W, FinishError<W>> {
        match self.try_finish() {
            Ok(()) => Ok(self.inner),
            Err(error) => Err(FinishError {
                inner: self.inner,
                error,
            }),
        }
    }

    /// Consumes this writer and extracts the wrapped writer without
    /// completing the FLOE message.
    ///
    /// The result is likely a truncated, invalid FLOE ciphertext.
    #[must_use]
    pub fn into_inner_unfinished(self) -> W {
        self.inner
    }

    fn emit_non_final(&mut self) -> io::Result<()> {
        self.buffer
            .prepare_plaintext(self.plaintext_length)
            .map_err(encryption_error)?;
        if let Err(error) = self
            .encryptor
            .as_mut()
            .ok_or_else(poisoned_error)?
            .encrypt_non_final_segment_in_place(&mut self.buffer)
        {
            self.status = StreamStatus::Failed;
            return Err(encryption_error(error));
        }
        let ciphertext = self.buffer.ciphertext().map_err(encryption_error)?;
        if let Err(error) = self.inner.write_all(ciphertext) {
            self.status = StreamStatus::Failed;
            return Err(error);
        }
        self.plaintext_length = 0;
        Ok(())
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        match self.status {
            StreamStatus::Open => {}
            StreamStatus::Finished => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "FLOE encrypting writer is already finished",
                ));
            }
            StreamStatus::Failed => return Err(poisoned_error()),
        }

        let capacity = self.parameters.plaintext_segment_length();
        if self.plaintext_length == capacity {
            self.emit_non_final()?;
        }

        let written = input.len().min(capacity - self.plaintext_length);
        let start = self.plaintext_length;
        let plaintext = self
            .buffer
            .prepare_plaintext(capacity)
            .map_err(encryption_error)?;
        plaintext[start..start + written].copy_from_slice(&input[..written]);
        self.plaintext_length += written;
        Ok(written)
    }

    /// Flushes the wrapped writer, kinda.
    ///
    /// FLOE cannot emit a partial non-final segment, so buffered plaintext is
    /// **not** written by this method. If you are done encrypting, call
    /// [`Self::try_finish`] or [`Self::finish`] instead of `flush()`.
    ///
    /// An `Ok(())` result does not mean that all previously written plaintext
    /// has reached the wrapped writer — only that already-emitted ciphertext
    /// has been flushed.
    fn flush(&mut self) -> io::Result<()> {
        if self.status == StreamStatus::Failed {
            return Err(poisoned_error());
        }
        self.inner.flush()
    }
}

/// A bounded-memory FLOE encrypting reader.
///
/// This pull-side adapter avoids the weakened flush semantics inherent in an
/// encrypting [`Write`] adapter. Read it to EOF to obtain the complete header,
/// encrypted body, and authenticated final segment.
///
/// Dropping the adapter or calling [`Self::into_inner_unfinished`] before
/// [`Self::is_finished`] is true abandons the incomplete ciphertext stream.
#[derive(Debug)]
pub struct EncryptReader<R> {
    inner: R,
    encryptor: Option<Encryptor>,
    header: Header,
    parameters: Parameters,
    header_position: usize,
    buffer: SegmentBuffer,
    ciphertext_position: usize,
    ciphertext_length: usize,
    lookahead: Option<u8>,
    status: StreamStatus,
}

impl<R: Read> EncryptReader<R> {
    /// Creates a pull-side encrypting reader.
    ///
    /// # Errors
    ///
    /// Returns an error for encryption initialization or random-generation
    /// failure.
    pub fn new(inner: R, key: &Key, aad: &[u8], parameters: Parameters) -> io::Result<Self> {
        let encryptor = Encryptor::new(key, aad, parameters).map_err(encryption_error)?;
        let header = *encryptor.header();
        Ok(Self {
            inner,
            encryptor: Some(encryptor),
            header,
            parameters,
            header_position: 0,
            buffer: SegmentBuffer::new(parameters),
            ciphertext_position: 0,
            ciphertext_length: 0,
            lookahead: None,
            status: StreamStatus::Open,
        })
    }

    /// Returns the authenticated header emitted at the start of this reader.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Returns this reader's parameter set.
    #[must_use]
    pub const fn parameters(&self) -> Parameters {
        self.parameters
    }

    /// Returns a shared reference to the wrapped plaintext reader.
    #[must_use]
    pub const fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped plaintext reader.
    ///
    /// Reading plaintext directly can corrupt the encryption stream.
    pub const fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Returns whether the complete final segment was emitted to the caller.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self.status, StreamStatus::Finished)
            && self.ciphertext_position == self.ciphertext_length
    }

    /// Extracts the wrapped reader without requiring complete ciphertext
    /// production.
    #[must_use]
    pub fn into_inner_unfinished(self) -> R {
        self.inner
    }

    fn load_segment(&mut self) -> io::Result<()> {
        let result = self.try_load_segment();
        if result.is_err() {
            self.status = StreamStatus::Failed;
        }
        result
    }

    fn try_load_segment(&mut self) -> io::Result<()> {
        let capacity = self.parameters.plaintext_segment_length();
        let plaintext = self
            .buffer
            .prepare_plaintext(capacity)
            .map_err(encryption_error)?;
        let mut plaintext_length = 0;

        if let Some(byte) = self.lookahead.take() {
            plaintext[0] = byte;
            plaintext_length = 1;
        }
        plaintext_length +=
            read_fully(&mut self.inner, &mut plaintext[plaintext_length..capacity])?;

        let is_final = if plaintext_length < capacity {
            true
        } else {
            let mut trailing = [0; 1];
            if read_fully(&mut self.inner, &mut trailing)? == 0 {
                true
            } else {
                self.lookahead = Some(trailing[0]);
                false
            }
        };

        self.buffer
            .prepare_plaintext(plaintext_length)
            .map_err(encryption_error)?;
        self.ciphertext_position = 0;
        self.ciphertext_length = if is_final {
            let encryptor = self.encryptor.take().ok_or_else(poisoned_error)?;
            match encryptor.encrypt_final_segment_in_place(&mut self.buffer) {
                Ok(encrypted) => {
                    self.status = StreamStatus::Finished;
                    encrypted.len()
                }
                Err(error) => return Err(encryption_error(error.into_error())),
            }
        } else {
            self.encryptor
                .as_mut()
                .ok_or_else(poisoned_error)?
                .encrypt_non_final_segment_in_place(&mut self.buffer)
                .map_err(encryption_error)?
                .len()
        };
        Ok(())
    }
}

impl<R: Read> Read for EncryptReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.status == StreamStatus::Failed {
            return Err(poisoned_error());
        }

        if self.header_position < Header::LEN {
            let read = output.len().min(Header::LEN - self.header_position);
            let end = self.header_position + read;
            output[..read].copy_from_slice(&self.header.as_bytes()[self.header_position..end]);
            self.header_position = end;
            return Ok(read);
        }

        if self.ciphertext_position == self.ciphertext_length {
            if self.status == StreamStatus::Finished {
                return Ok(0);
            }
            self.load_segment()?;
        }

        let ciphertext = self.buffer.ciphertext().map_err(encryption_error)?;
        let read = output
            .len()
            .min(self.ciphertext_length - self.ciphertext_position);
        let end = self.ciphertext_position + read;
        output[..read].copy_from_slice(&ciphertext[self.ciphertext_position..end]);
        self.ciphertext_position = end;
        Ok(read)
    }
}

/// A bounded-memory FLOE decrypting reader.
///
/// The [`Read`] implementation stops exactly after the authenticated final
/// segment. [`Self::try_finish`] and [`Self::finish`] then authenticate any
/// unread remainder **and require the underlying stream to end there**,
/// consistent with [`crate::decrypt`] and [`crate::random_access::Reader`].
///
/// When the FLOE message is deliberately embedded in a larger stream and
/// bytes may follow, use [`Self::try_finish_frame`] or [`Self::finish_frame`],
/// which leaves following bytes unread.
#[derive(Debug)]
pub struct DecryptReader<R> {
    inner: R,
    decryptor: Option<Decryptor>,
    header: Header,
    parameters: Parameters,
    buffer: SegmentBuffer,
    plaintext_consumed: usize,
    plaintext_available: usize,
    status: StreamStatus,
}

impl<R: Read> DecryptReader<R> {
    /// Creates a reader using the parameters in the header.
    ///
    /// # Errors
    ///
    /// Returns an error if the header cannot be read or authenticated, or its
    /// encoded parameter set is unsupported.
    pub fn new(mut inner: R, key: &Key, aad: &[u8]) -> io::Result<Self> {
        let header = read_header(&mut inner)?;
        let decryptor = Decryptor::new(key, aad, &header).map_err(decryption_error)?;
        let parameters = decryptor.parameters();
        Ok(Self {
            inner,
            decryptor: Some(decryptor),
            header,
            parameters,
            buffer: SegmentBuffer::new(parameters),
            plaintext_consumed: 0,
            plaintext_available: 0,
            status: StreamStatus::Open,
        })
    }

    /// Returns the authenticated header consumed by this reader.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Returns the authenticated parameter set.
    #[must_use]
    pub const fn parameters(&self) -> Parameters {
        self.parameters
    }

    /// Returns a shared reference to the wrapped reader.
    #[must_use]
    pub const fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped reader.
    ///
    /// Reading ciphertext directly can corrupt the FLOE message boundary.
    pub const fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Returns whether the final segment was authenticated and all its
    /// plaintext was consumed.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self.status, StreamStatus::Finished)
            && self.plaintext_consumed == self.plaintext_available
    }

    /// Authenticates any unread remainder of the message and requires
    /// underlying EOF, without consuming this adapter.
    ///
    /// This is idempotent after success. After an error, the reader is
    /// poisoned because invalid input may have been partially consumed.
    /// Detecting trailing data consumes one byte from the wrapped reader.
    ///
    /// # Errors
    ///
    /// Returns an error for truncated, malformed, or unauthenticated unread
    /// ciphertext, or for any byte after the authenticated final segment.
    pub fn try_finish(&mut self) -> io::Result<()> {
        self.drain_message()?;
        let mut trailing = [0; 1];
        match read_fully(&mut self.inner, &mut trailing) {
            Ok(0) => Ok(()),
            Ok(_) => {
                self.status = StreamStatus::Failed;
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FLOE ciphertext has data after its final segment",
                ))
            }
            Err(error) => {
                self.status = StreamStatus::Failed;
                Err(error)
            }
        }
    }

    /// Authenticates any unread remainder of one framed message, leaving
    /// bytes of a following frame unread, without consuming this adapter.
    ///
    /// Unlike [`Self::try_finish`], this does not require underlying EOF; the
    /// wrapped reader is left positioned exactly after the final segment.
    /// This is idempotent after success. After an error, the reader is
    /// poisoned because invalid input may have been partially consumed.
    ///
    /// # Errors
    ///
    /// Returns an error for truncated, malformed, or unauthenticated unread
    /// ciphertext.
    pub fn try_finish_frame(&mut self) -> io::Result<()> {
        self.drain_message()
    }

    /// Authenticates the complete message, requires underlying EOF, and
    /// returns the wrapped reader.
    ///
    /// # Errors
    ///
    /// Returns an error preserving the wrapped reader for invalid unread
    /// ciphertext or any byte after the authenticated final segment.
    pub fn finish(mut self) -> Result<R, FinishError<R>> {
        match self.try_finish() {
            Ok(()) => Ok(self.inner),
            Err(error) => Err(FinishError {
                inner: self.inner,
                error,
            }),
        }
    }

    /// Authenticates one framed message and returns the wrapped reader
    /// positioned exactly after the final segment.
    ///
    /// # Errors
    ///
    /// Returns an error preserving the wrapped reader when finalization fails.
    /// A recovered reader is unchecked and may be positioned after partially
    /// consumed invalid input.
    pub fn finish_frame(mut self) -> Result<R, FinishError<R>> {
        match self.try_finish_frame() {
            Ok(()) => Ok(self.inner),
            Err(error) => Err(FinishError {
                inner: self.inner,
                error,
            }),
        }
    }

    /// Extracts the reader without authenticating unread ciphertext.
    #[must_use]
    pub fn into_inner_unchecked(self) -> R {
        self.inner
    }

    fn drain_message(&mut self) -> io::Result<()> {
        self.plaintext_consumed = self.plaintext_available;

        while self.status == StreamStatus::Open {
            self.load_segment()?;
            self.plaintext_consumed = self.plaintext_available;
        }

        if self.status == StreamStatus::Failed {
            Err(poisoned_error())
        } else {
            Ok(())
        }
    }

    fn load_segment(&mut self) -> io::Result<()> {
        let result = self.try_load_segment();
        if result.is_err() {
            self.status = StreamStatus::Failed;
        }
        result
    }

    fn try_load_segment(&mut self) -> io::Result<()> {
        let mut prefix = [0; crate::SEGMENT_PREFIX_LENGTH];
        let actual = read_fully(&mut self.inner, &mut prefix)?;
        if actual != prefix.len() {
            return Err(decryption_error(Error::Truncated));
        }

        let framing =
            crate::SegmentFraming::decode(self.parameters, prefix).map_err(decryption_error)?;
        let ciphertext_length = framing.ciphertext_length();
        let ciphertext = self
            .buffer
            .prepare_ciphertext(ciphertext_length)
            .map_err(decryption_error)?;

        ciphertext[..prefix.len()].copy_from_slice(&prefix);
        let actual = read_fully(&mut self.inner, &mut ciphertext[prefix.len()..])?;
        let expected_remainder = ciphertext_length - prefix.len();
        if actual != expected_remainder {
            return Err(decryption_error(Error::InvalidCiphertextLength {
                actual: prefix.len() + actual,
                required: LengthRequirement::Exactly(ciphertext_length),
            }));
        }

        let decryptor = self.decryptor.as_mut().ok_or_else(poisoned_error)?;
        let plaintext_length = decryptor
            .decrypt_segment_in_place(&mut self.buffer)
            .map_err(decryption_error)?
            .len();

        if framing.is_final() {
            self.decryptor
                .take()
                .ok_or_else(poisoned_error)?
                .finish()
                .map_err(decryption_error)?;
            self.status = StreamStatus::Finished;
        }

        self.plaintext_consumed = 0;
        self.plaintext_available = plaintext_length;
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        if self.status == StreamStatus::Failed {
            return Err(poisoned_error());
        }

        if self.plaintext_consumed == self.plaintext_available {
            if self.status == StreamStatus::Finished {
                return Ok(0);
            }
            self.load_segment()?;
            if self.plaintext_consumed == self.plaintext_available {
                debug_assert_eq!(self.status, StreamStatus::Finished);
                return Ok(0);
            }
        }

        let plaintext = self.buffer.plaintext().map_err(decryption_error)?;
        let read = output
            .len()
            .min(self.plaintext_available - self.plaintext_consumed);
        let end = self.plaintext_consumed + read;
        output[..read].copy_from_slice(&plaintext[self.plaintext_consumed..end]);
        self.plaintext_consumed = end;

        Ok(read)
    }
}

fn poisoned_error() -> io::Error {
    io::Error::other("FLOE stream is poisoned after an earlier error")
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read as _, Write as _};

    use super::*;
    use crate::key::test_key;
    use crate::{decrypt, decrypt_with_parameters, encrypt, random_access};

    #[derive(Debug, Default)]
    struct FlushFails(Vec<u8>);

    impl Write for FlushFails {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("injected flush failure"))
        }
    }

    #[test]
    fn encrypt_reader_round_trips_plaintext_boundaries() {
        // Given plaintext lengths at and around the segment boundary
        let parameters = Parameters::SEGMENT_4_KIB;
        let capacity = parameters.plaintext_segment_length();
        for length in [0, 1, capacity - 1, capacity, capacity + 1, 2 * capacity] {
            let plaintext = vec![0x31; length];

            // When the plaintext is pulled through an EncryptReader
            let mut reader =
                EncryptReader::new(Cursor::new(&plaintext), &test_key(), b"io", parameters)
                    .unwrap();
            let mut ciphertext = Vec::new();
            reader.read_to_end(&mut ciphertext).unwrap();

            // Then the reader finishes and the ciphertext round-trips
            assert!(
                reader.is_finished(),
                "reader did not finish at length {length}"
            );
            assert_eq!(
                decrypt(&test_key(), b"io", &ciphertext).unwrap(),
                plaintext,
                "reader round trip failed at length {length}"
            );
        }
    }

    #[test]
    fn adapters_round_trip_across_parameter_sets() {
        // Given a message longer than one segment, under each parameter set
        for parameters in [Parameters::SEGMENT_4_KIB, Parameters::SEGMENT_1_MIB] {
            let plaintext = vec![0x31; parameters.plaintext_segment_length() + 7];

            // When it is written through an EncryptWriter and read back
            // through a DecryptReader
            let mut writer =
                EncryptWriter::new(Vec::new(), &test_key(), b"io", parameters).unwrap();
            writer.write_all(&plaintext).unwrap();
            let ciphertext = writer.finish().unwrap();
            let mut reader =
                DecryptReader::new(Cursor::new(ciphertext), &test_key(), b"io").unwrap();
            let mut recovered = Vec::new();
            reader.read_to_end(&mut recovered).unwrap();

            // Then the plaintext round-trips and the reader finishes
            assert_eq!(recovered, plaintext);
            assert!(reader.is_finished());
        }
    }

    #[test]
    fn try_finish_verifies_complete_message_without_reading() {
        // Given a reader over a complete valid ciphertext
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext = vec![0x31; parameters.plaintext_segment_length() + 7];
        let mut reader = DecryptReader::new(
            Cursor::new(encrypt(&test_key(), b"io", parameters, &plaintext).unwrap()),
            &test_key(),
            b"io",
        )
        .unwrap();

        // When the remainder is verified without extracting plaintext
        reader.try_finish().unwrap();

        // Then the reader reaches the finished state
        assert!(reader.is_finished());
    }

    #[test]
    fn writer_boundary_lengths_round_trip() {
        // Given plaintext lengths at and around the segment boundary
        let parameters = Parameters::SEGMENT_4_KIB;
        let capacity = parameters.plaintext_segment_length();
        for length in [0, 1, capacity - 1, capacity, capacity + 1, 2 * capacity] {
            let plaintext = vec![0x32; length];

            // When the plaintext is written through an EncryptWriter
            let mut writer =
                EncryptWriter::new(Vec::new(), &test_key(), b"io", parameters).unwrap();
            writer.write_all(&plaintext).unwrap();
            let ciphertext = writer.finish().unwrap();

            // Then the finished ciphertext round-trips
            assert_eq!(
                decrypt(&test_key(), b"io", &ciphertext).unwrap(),
                plaintext,
                "writer round trip failed at length {length}"
            );
        }
    }

    #[test]
    fn writer_flush_does_not_emit_partial_segment() {
        // Given a writer holding buffered, unfinalized plaintext
        let mut writer =
            EncryptWriter::new(Vec::new(), &test_key(), b"io", Parameters::SEGMENT_4_KIB).unwrap();
        writer.write_all(b"buffered plaintext").unwrap();

        // When the writer is flushed before finish
        writer.flush().unwrap();

        // Then only the header has been emitted
        assert_eq!(writer.get_ref().len(), Header::LEN);

        // Then finishing still produces a complete round-trippable message
        let ciphertext = writer.finish().unwrap();
        assert_eq!(
            decrypt(&test_key(), b"io", &ciphertext).unwrap(),
            b"buffered plaintext"
        );
    }

    #[test]
    fn frame_finish_preserves_trailing_data() {
        // Given a stream holding one complete message followed by more data
        let parameters = Parameters::SEGMENT_4_KIB;
        let mut writer = EncryptWriter::new(Vec::new(), &test_key(), b"io", parameters).unwrap();
        writer.write_all(b"message").unwrap();
        let mut framed = writer.finish().unwrap();
        framed.extend_from_slice(b"next frame");

        // When the message is read and finished as a frame
        let mut reader = DecryptReader::new(Cursor::new(framed), &test_key(), b"io").unwrap();
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext).unwrap();
        assert_eq!(plaintext, b"message");
        let inner = reader.finish_frame().unwrap();

        // Then the inner reader is positioned exactly at the trailing data
        assert_eq!(
            &inner.get_ref()[usize::try_from(inner.position()).unwrap()..],
            b"next frame"
        );
    }

    #[test]
    fn default_finish_rejects_trailing_data() {
        // Given a stream holding one complete message plus one extra byte
        let parameters = Parameters::SEGMENT_4_KIB;
        let mut writer = EncryptWriter::new(Vec::new(), &test_key(), b"io", parameters).unwrap();
        writer.write_all(b"message").unwrap();
        let mut bytes = writer.finish().unwrap();
        bytes.push(0);

        // When the message is read and finished with the whole-stream API
        let mut reader = DecryptReader::new(Cursor::new(bytes), &test_key(), b"io").unwrap();
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext).unwrap();

        // Then the unconsumed trailing byte is rejected
        assert_eq!(
            reader.finish().unwrap_err().error().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn consuming_reader_finish_error_preserves_wrapped_reader() {
        // Given a reader over a ciphertext missing its final byte
        let mut ciphertext = {
            let mut writer =
                EncryptWriter::new(Vec::new(), &test_key(), b"io", Parameters::SEGMENT_4_KIB)
                    .unwrap();
            writer.write_all(b"message").unwrap();
            writer.finish().unwrap()
        };
        ciphertext.pop();
        let reader = DecryptReader::new(Cursor::new(ciphertext), &test_key(), b"io").unwrap();

        // When the consuming finish fails
        let failure = reader.finish().unwrap_err();

        // Then the error is classified and the wrapped reader is returned
        // intact
        assert_eq!(failure.error().kind(), io::ErrorKind::InvalidData);
        let inner = failure.into_inner();
        assert!(inner.position() >= u64::try_from(Header::LEN).unwrap());
    }

    #[test]
    fn reader_constructors_classify_short_headers_consistently() {
        // Given inputs shorter than a complete header
        for length in 0..Header::LEN {
            let input = vec![0u8; length];

            // When each reader constructor parses the input
            let stream_error =
                DecryptReader::new(Cursor::new(&input), &test_key(), b"io").unwrap_err();
            let random_error =
                random_access::Reader::new(Cursor::new(&input), &test_key(), b"io").unwrap_err();

            // Then both classify the short header identically
            for error in [stream_error, random_error] {
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(matches!(
                    error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<Error>()),
                    Some(Error::InvalidHeaderLength { actual }) if *actual == length
                ));
            }
        }
    }

    #[test]
    fn unfinished_extraction_is_explicit_and_truncated() {
        // Given a writer that has emitted no final segment
        let writer =
            EncryptWriter::new(Vec::new(), &test_key(), b"io", Parameters::SEGMENT_4_KIB).unwrap();

        // When its inner buffer is extracted through the explicit
        // unfinished API
        let ciphertext = writer.into_inner_unfinished();

        // Then the extracted bytes decrypt as a truncated message
        assert_eq!(
            decrypt(&test_key(), b"io", &ciphertext),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn consuming_finish_error_preserves_wrapped_writer() {
        // Given a writer whose inner sink fails on flush
        let mut writer = EncryptWriter::new(
            FlushFails::default(),
            &test_key(),
            b"io",
            Parameters::SEGMENT_4_KIB,
        )
        .unwrap();
        writer.write_all(b"message").unwrap();

        // When the consuming finish fails
        let error = writer.finish().unwrap_err();

        // Then the error is classified and the wrapped sink is returned
        // with the bytes it accepted
        assert_eq!(error.error().kind(), io::ErrorKind::Other);
        assert!(!error.into_inner().0.is_empty());
    }

    #[test]
    fn finish_error_does_not_require_inner_type_to_implement_debug() {
        // Given a wrapped type without a Debug implementation
        struct NoDebug;

        // Then FinishError still implements the standard Error trait
        fn assert_error<T: std::error::Error>() {}
        assert_error::<FinishError<NoDebug>>();
    }

    #[test]
    fn parameter_policy_checkable_after_construction() {
        // Given a message written with the 1 MiB profile
        let parameters = Parameters::SEGMENT_1_MIB;
        let mut writer = EncryptWriter::new(Vec::new(), &test_key(), b"io", parameters).unwrap();
        writer.write_all(b"message").unwrap();
        let ciphertext = writer.finish().unwrap();

        // When the profile is demanded explicitly during whole-message
        // decryption, then the message decrypts
        assert_eq!(
            decrypt_with_parameters(&test_key(), b"io", parameters, &ciphertext).unwrap(),
            b"message"
        );

        // When a streaming reader is constructed, then the authenticated
        // parameters are available for a policy check
        let reader = DecryptReader::new(Cursor::new(ciphertext), &test_key(), b"io").unwrap();
        assert_eq!(reader.parameters(), parameters);
    }
}
