//! Misuse-resistant sequential (online) segment processing.
//!
//! [`Encryptor`] and [`Decryptor`] implement in-order bounded memory
//! segment processing.
//!
//! The free functions [`encrypt`] and [`decrypt`] provide a one-shot
//! interface for encrypting and decrypting whole messages.
//!
//! To drive a [`Decryptor`] from a raw byte stream, read the
//! [`SEGMENT_PREFIX_LENGTH`]-byte prefix, size the segment with
//! [`SegmentFraming::decode`](crate::SegmentFraming::decode), then pass the
//! complete segment to [`Decryptor::decrypt_segment`].

pub use crate::buffer::SegmentBuffer;
use crate::wire::split_header;
use crate::{
    AEAD_MAX_SEGMENTS, DecryptionState, EncryptionState, Error, Header, Key, LengthRequirement,
    Parameters, Result, SEGMENT_PREFIX_LENGTH, SegmentKind, length_usize_to_u64, start_decryption,
    start_decryption_inferred, start_encryption,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SegmentCounter {
    next: u64,
    closed: bool,
}

impl SegmentCounter {
    const fn new() -> Self {
        Self {
            next: 0,
            closed: false,
        }
    }

    const fn next_position(self) -> u64 {
        self.next
    }

    const fn is_finished(self) -> bool {
        self.closed
    }

    fn position_for(self, kind: SegmentKind) -> Result<u64> {
        if self.closed {
            return Err(Error::Closed);
        }
        match kind {
            SegmentKind::NonFinal if self.next == AEAD_MAX_SEGMENTS - 1 => Err(Error::SegmentLimit),
            SegmentKind::Final if self.next >= AEAD_MAX_SEGMENTS => Err(Error::SegmentLimit),
            SegmentKind::NonFinal | SegmentKind::Final => Ok(self.next),
        }
    }

    fn complete(&mut self, kind: SegmentKind) {
        match kind {
            SegmentKind::NonFinal => self.next += 1,
            SegmentKind::Final => self.closed = true,
        }
    }

    const fn finish(self) -> Result<()> {
        if self.closed {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }
}

/// Misuse-resistant sequential FLOE encryptor.
///
/// Encrypt full non-final segments with [`Self::encrypt_non_final_segment`],
/// then consume the encryptor with [`Self::encrypt_final_segment`]. Consuming
/// finalization makes it impossible to use the state after the final segment.
#[derive(Debug)]
pub struct Encryptor {
    state: EncryptionState,
    header: Header,
    counter: SegmentCounter,
}

/// Error returned when final-segment encryption fails.
///
/// The original encryptor remains recoverable, so a caller can correct a
/// deterministic input or buffer error and retry without abandoning the
/// message and its already-emitted header.
pub struct FinalEncryptError {
    encryptor: Box<Encryptor>,
    error: Error,
}

impl FinalEncryptError {
    /// Returns the error that prevented final-segment encryption.
    #[must_use]
    pub const fn error(&self) -> &Error {
        &self.error
    }

    /// Recovers the encryptor.
    #[must_use]
    pub fn into_encryptor(self) -> Encryptor {
        *self.encryptor
    }

    /// Returns the underlying error and drops the recovered encryptor.
    #[must_use]
    pub fn into_error(self) -> Error {
        self.error
    }

    /// Separates the error and recovered encryptor.
    #[must_use]
    pub fn into_parts(self) -> (Error, Encryptor) {
        (self.error, *self.encryptor)
    }
}

impl core::fmt::Debug for FinalEncryptError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FinalEncryptError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Display for FinalEncryptError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "failed to encrypt final FLOE segment: {}",
            self.error
        )
    }
}

impl std::error::Error for FinalEncryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl Encryptor {
    /// Starts online encryption and creates a fresh authenticated header.
    ///
    /// # Errors
    ///
    /// Returns an error for backend initialization or random-generation
    /// failure.
    pub fn new(key: &Key, aad: &[u8], parameters: Parameters) -> Result<Self> {
        let (state, header) = start_encryption(key, aad, parameters)?;
        Ok(Self {
            state,
            header,
            counter: SegmentCounter::new(),
        })
    }

    /// Returns the authenticated header that must precede the encrypted body.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Returns the provider used by this encryptor.
    #[must_use]
    pub fn provider(&self) -> crate::Provider {
        self.state.provider()
    }

    /// Returns this encryptor's parameter set.
    #[must_use]
    pub fn parameters(&self) -> Parameters {
        self.state.parameters()
    }

    /// Returns the next segment position.
    #[must_use]
    pub const fn next_position(&self) -> u64 {
        self.counter.next_position()
    }

    /// Encrypts one full, non-final plaintext segment.
    ///
    /// # Errors
    ///
    /// Returns an error if the segment limit is reached, the plaintext does not
    /// have the exact full-segment length, or encryption fails.
    pub fn encrypt_non_final_segment(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let position = self.counter.position_for(SegmentKind::NonFinal)?;
        let encrypted =
            self.state
                .encrypt_segment_at(plaintext, position, SegmentKind::NonFinal)?;
        self.counter.complete(SegmentKind::NonFinal);
        Ok(encrypted)
    }

    /// Encrypts one full, non-final segment into `output`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt_non_final_segment`], plus
    /// [`Error::OutputTooSmall`] when necessary.
    pub fn encrypt_non_final_segment_into(
        &mut self,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        let position = self.counter.position_for(SegmentKind::NonFinal)?;
        let written = self.state.encrypt_segment_into_at(
            plaintext,
            position,
            SegmentKind::NonFinal,
            output,
        )?;
        self.counter.complete(SegmentKind::NonFinal);
        Ok(written)
    }

    /// Encrypts one full, non-final payload prepared in `buffer`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid buffer state or parameters, segment-limit
    /// exhaustion, or encryption failure.
    pub fn encrypt_non_final_segment_in_place<'a>(
        &mut self,
        buffer: &'a mut SegmentBuffer,
    ) -> Result<&'a [u8]> {
        let position = self.counter.position_for(SegmentKind::NonFinal)?;
        let encrypted =
            self.state
                .encrypt_segment_in_place_at(buffer, position, SegmentKind::NonFinal)?;
        self.counter.complete(SegmentKind::NonFinal);
        Ok(encrypted)
    }

    /// Encrypts the final plaintext segment and consumes this encryptor.
    ///
    /// # Errors
    ///
    /// Returns an error when the final payload is too large, the segment limit
    /// is exhausted, or encryption fails. The returned
    /// [`FinalEncryptError`] preserves this encryptor for correction or retry.
    pub fn encrypt_final_segment(
        mut self,
        plaintext: &[u8],
    ) -> core::result::Result<Vec<u8>, FinalEncryptError> {
        let result = self
            .counter
            .position_for(SegmentKind::Final)
            .and_then(|position| {
                self.state
                    .encrypt_segment_at(plaintext, position, SegmentKind::Final)
            });
        match result {
            Ok(encrypted) => Ok(encrypted),
            Err(error) => Err(FinalEncryptError {
                encryptor: Box::new(self),
                error,
            }),
        }
    }

    /// Encrypts the final plaintext segment into `output` and consumes this
    /// encryptor.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encrypt_final_segment`], plus
    /// [`Error::OutputTooSmall`] when necessary. The returned
    /// [`FinalEncryptError`] preserves this encryptor.
    pub fn encrypt_final_segment_into(
        mut self,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> core::result::Result<usize, FinalEncryptError> {
        let result = self
            .counter
            .position_for(SegmentKind::Final)
            .and_then(|position| {
                self.state
                    .encrypt_segment_into_at(plaintext, position, SegmentKind::Final, output)
            });
        match result {
            Ok(written) => Ok(written),
            Err(error) => Err(FinalEncryptError {
                encryptor: Box::new(self),
                error,
            }),
        }
    }

    /// Encrypts the final payload prepared in `buffer` and consumes this
    /// encryptor.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid buffer state or parameters, an oversized
    /// payload, segment-limit exhaustion, or encryption failure. The returned
    /// [`FinalEncryptError`] preserves this encryptor.
    pub fn encrypt_final_segment_in_place(
        mut self,
        buffer: &mut SegmentBuffer,
    ) -> core::result::Result<&[u8], FinalEncryptError> {
        let result = self
            .counter
            .position_for(SegmentKind::Final)
            .and_then(|position| {
                self.state
                    .encrypt_segment_in_place_at(buffer, position, SegmentKind::Final)
            });
        match result {
            Ok(encrypted) => Ok(encrypted),
            Err(error) => Err(FinalEncryptError {
                encryptor: Box::new(self),
                error,
            }),
        }
    }
}

/// Misuse-resistant sequential FLOE decryptor.
///
/// [`Self::decrypt_segment`] reads the authenticated final/non-final choice
/// from each segment prefix. After the input source ends, consume the decryptor
/// with [`Self::finish`] to reject truncation.
#[derive(Debug)]
pub struct Decryptor {
    state: DecryptionState,
    counter: SegmentCounter,
}

impl Decryptor {
    /// Starts online decryption using the authenticated parameters in `header`.
    ///
    /// When application policy requires a specific profile, check
    /// [`Self::parameters`] after construction; the parameter set is
    /// authenticated before any payload is produced. The whole-message
    /// [`decrypt_with_parameters`] helper performs that policy check for
    /// complete slices.
    ///
    /// # Errors
    ///
    /// Returns an error when the encoded parameters or authenticated header are
    /// invalid.
    pub fn new(key: &Key, aad: &[u8], header: &Header) -> Result<Self> {
        let state = start_decryption_inferred(key, aad, header)?;
        Ok(Self {
            state,
            counter: SegmentCounter::new(),
        })
    }

    pub(crate) fn new_with_parameters(
        key: &Key,
        aad: &[u8],
        parameters: Parameters,
        header: &Header,
    ) -> Result<Self> {
        let state = start_decryption(key, aad, parameters, header)?;
        Ok(Self {
            state,
            counter: SegmentCounter::new(),
        })
    }

    /// Returns the provider used by this decryptor.
    #[must_use]
    pub fn provider(&self) -> crate::Provider {
        self.state.provider()
    }

    /// Returns this decryptor's authenticated parameter set.
    #[must_use]
    pub fn parameters(&self) -> Parameters {
        self.state.parameters()
    }

    /// Returns the next segment position.
    #[must_use]
    pub const fn next_position(&self) -> u64 {
        self.counter.next_position()
    }

    /// Returns whether an authenticated final segment has been processed.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.counter.is_finished()
    }

    /// Authenticates and decrypts the next segment.
    ///
    /// The final/non-final operation is selected from the segment prefix and
    /// authenticated by AES-GCM. Use [`Self::is_finished`] to detect the final
    /// segment while processing a sequence.
    ///
    /// # Errors
    ///
    /// Returns an error for a closed state, invalid framing, segment-limit
    /// exhaustion, or authentication failure.
    pub fn decrypt_segment(&mut self, ciphertext_segment: &[u8]) -> Result<Vec<u8>> {
        let framing = self.framing(ciphertext_segment)?;
        let kind = framing.kind();
        let position = self.counter.position_for(kind)?;
        let plaintext = self
            .state
            .decrypt_segment_at(ciphertext_segment, position, kind)?;
        self.counter.complete(kind);
        Ok(plaintext)
    }

    /// Authenticates and decrypts the next segment into `output`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decrypt_segment`], plus
    /// [`Error::OutputTooSmall`] when necessary.
    pub fn decrypt_segment_into(
        &mut self,
        ciphertext_segment: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        let framing = self.framing(ciphertext_segment)?;
        self.decrypt_segment_into_framed(ciphertext_segment, framing, output)
    }

    fn decrypt_segment_into_framed(
        &mut self,
        ciphertext_segment: &[u8],
        framing: crate::SegmentFraming,
        output: &mut [u8],
    ) -> Result<usize> {
        let kind = framing.kind();
        let position = self.counter.position_for(kind)?;
        let written = self.state.decrypt_segment_into_at_framed(
            ciphertext_segment,
            position,
            framing,
            output,
        )?;
        self.counter.complete(kind);
        Ok(written)
    }

    /// Authenticates and decrypts the encrypted segment prepared in `buffer`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid buffer state or parameters, malformed
    /// framing, a closed state, or authentication failure.
    pub fn decrypt_segment_in_place<'a>(
        &mut self,
        buffer: &'a mut SegmentBuffer,
    ) -> Result<&'a mut [u8]> {
        let prefix = {
            let ciphertext = buffer.ciphertext()?;
            segment_prefix(ciphertext, self.parameters())?
        };
        let framing = crate::SegmentFraming::decode(self.parameters(), prefix)?;
        let kind = framing.kind();
        let position = self.counter.position_for(kind)?;
        let plaintext = self
            .state
            .decrypt_segment_in_place_at(buffer, position, kind)?;
        self.counter.complete(kind);
        Ok(plaintext)
    }

    /// Consumes this decryptor and verifies that a final segment was processed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] unless an authenticated final segment was
    /// processed.
    pub fn finish(self) -> Result<()> {
        self.counter.finish()
    }

    fn framing(&self, ciphertext_segment: &[u8]) -> Result<crate::SegmentFraming> {
        let prefix = segment_prefix(ciphertext_segment, self.parameters())?;
        crate::SegmentFraming::decode(self.parameters(), prefix)
    }
}

fn segment_prefix(
    ciphertext_segment: &[u8],
    parameters: Parameters,
) -> Result<[u8; SEGMENT_PREFIX_LENGTH]> {
    if ciphertext_segment.len() < SEGMENT_PREFIX_LENGTH {
        return Err(Error::InvalidCiphertextLength {
            actual: ciphertext_segment.len(),
            required: LengthRequirement::Between {
                minimum: SEGMENT_PREFIX_LENGTH,
                maximum: parameters.ciphertext_segment_length(),
            },
        });
    }
    ciphertext_segment[..SEGMENT_PREFIX_LENGTH]
        .try_into()
        .map_err(|_| Error::InvalidSegmentPrefix)
}

/// Encrypts a complete plaintext, including its header and final segment.
///
/// # Errors
///
/// Returns an error for length or segment-count overflow, random-generation
/// failure, or encryption failure.
pub fn encrypt(key: &Key, aad: &[u8], parameters: Parameters, plaintext: &[u8]) -> Result<Vec<u8>> {
    let encryptor = Encryptor::new(key, aad, parameters)?;
    encrypt_body(encryptor, plaintext)
}

fn encrypt_body(encryptor: Encryptor, plaintext: &[u8]) -> Result<Vec<u8>> {
    let plaintext_length = length_usize_to_u64(plaintext.len());
    let parameters = encryptor.parameters();
    let layout = parameters.plaintext_layout(plaintext_length)?;
    let capacity =
        usize::try_from(layout.ciphertext_length()).map_err(|_| Error::LengthOverflow)?;
    let mut ciphertext = Vec::with_capacity(capacity);
    ciphertext.extend_from_slice(encryptor.header().as_ref());
    let mut encryptor = Some(encryptor);

    for segment in layout.segments() {
        let plaintext_start =
            usize::try_from(segment.plaintext_offset()).map_err(|_| Error::LengthOverflow)?;
        let plaintext_end = plaintext_start
            .checked_add(segment.plaintext_length())
            .ok_or(Error::LengthOverflow)?;
        let output_start = ciphertext.len();
        let output_end = output_start
            .checked_add(segment.ciphertext_length())
            .ok_or(Error::LengthOverflow)?;
        ciphertext.resize(output_end, 0);
        let chunk = &plaintext[plaintext_start..plaintext_end];
        let output = &mut ciphertext[output_start..];

        match segment.kind() {
            SegmentKind::NonFinal => {
                encryptor
                    .as_mut()
                    .expect("only the last segment of a layout is final")
                    .encrypt_non_final_segment_into(chunk, output)?;
            }
            SegmentKind::Final => {
                encryptor
                    .take()
                    .expect("every layout contains exactly one final segment")
                    .encrypt_final_segment_into(chunk, output)
                    .map_err(FinalEncryptError::into_error)?;
            }
        }
    }

    Ok(ciphertext)
}

/// Decrypts a complete FLOE ciphertext using its authenticated parameter set.
///
/// # Errors
///
/// Returns an error for invalid header or segment framing, truncation, segment
/// limits, or authentication failure.
pub fn decrypt(key: &Key, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let (header, body) = split_header(ciphertext)?;
    let decryptor = Decryptor::new(key, aad, &header)?;
    decrypt_body(decryptor, body)
}

/// Decrypts a complete FLOE ciphertext and requires `parameters`.
///
/// # Errors
///
/// Returns the same errors as [`decrypt`], including
/// [`Error::InvalidHeaderParameters`] when the header uses another profile.
pub fn decrypt_with_parameters(
    key: &Key,
    aad: &[u8],
    parameters: Parameters,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let (header, body) = split_header(ciphertext)?;
    let decryptor = Decryptor::new_with_parameters(key, aad, parameters, &header)?;
    decrypt_body(decryptor, body)
}

fn decrypt_body(mut decryptor: Decryptor, mut body: &[u8]) -> Result<Vec<u8>> {
    let parameters = decryptor.parameters();
    let mut plaintext = Vec::with_capacity(body.len());

    while !body.is_empty() {
        let prefix = segment_prefix(body, parameters)?;
        let framing = crate::SegmentFraming::decode(parameters, prefix)?;
        let segment_length = framing.ciphertext_length();
        if body.len() < segment_length {
            return Err(Error::InvalidCiphertextLength {
                actual: body.len(),
                required: LengthRequirement::AtLeast(segment_length),
            });
        }
        if framing.is_final() && segment_length != body.len() {
            return Err(Error::InvalidCiphertextLength {
                actual: body.len(),
                required: LengthRequirement::Exactly(segment_length),
            });
        }

        let (segment, rest) = body.split_at(segment_length);
        let start = plaintext.len();
        plaintext.resize(start + framing.plaintext_length(), 0);
        decryptor.decrypt_segment_into_framed(segment, framing, &mut plaintext[start..])?;
        body = rest;
    }

    decryptor.finish()?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_key;
    use crate::{HEADER_LENGTH, SEGMENT_OVERHEAD};

    #[test]
    fn online_states_reserve_last_position_for_final_segment() {
        // Given online states advanced to the last permitted position
        let key = test_key();
        let parameters = Parameters::SEGMENT_4_KIB;
        let mut encryption = Encryptor::new(&key, b"segment limit", parameters).unwrap();
        let header = *encryption.header();
        encryption.counter.next = AEAD_MAX_SEGMENTS - 1;

        // When a non-final segment is encrypted there
        // Then the position is refused; it is reserved for the final segment
        assert_eq!(
            encryption.encrypt_non_final_segment(&[]),
            Err(Error::SegmentLimit)
        );

        // When the final segment is encrypted there instead
        let final_segment = encryption.encrypt_final_segment(b"last").unwrap();

        // Then a decryptor at the same position accepts it and finishes
        let mut decryption = Decryptor::new(&key, b"segment limit", &header).unwrap();
        assert_eq!(decryption.parameters(), parameters);
        decryption.counter.next = AEAD_MAX_SEGMENTS - 1;
        assert_eq!(decryption.decrypt_segment(&final_segment).unwrap(), b"last");
        assert!(decryption.is_finished());
        decryption.finish().unwrap();
    }

    #[test]
    fn complete_message_round_trips_boundaries() {
        // Given plaintext lengths at and around every segment boundary
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment_length = parameters.plaintext_segment_length();
        for length in [
            0,
            1,
            segment_length - 1,
            segment_length,
            segment_length + 1,
            2 * segment_length,
            2 * segment_length + 3,
        ] {
            let plaintext: Vec<u8> = (0..length)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();

            // When the message is encrypted and decrypted whole
            let ciphertext = encrypt(&test_key(), b"aad", parameters, &plaintext).unwrap();

            // Then the plaintext round-trips
            assert_eq!(
                decrypt(&test_key(), b"aad", &ciphertext).unwrap(),
                plaintext,
                "round trip failed at length {length}"
            );
        }
    }

    #[test]
    fn complete_message_decrypts_full_non_final_and_empty_final_segments() {
        // Given a message framed as one full non-final segment followed by
        // an empty final segment, instead of the encoder's canonical framing
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext = vec![0x5a; parameters.plaintext_segment_length()];
        let mut encryption = Encryptor::new(&test_key(), b"alternate framing", parameters).unwrap();
        let header = *encryption.header();
        let non_final = encryption.encrypt_non_final_segment(&plaintext).unwrap();
        let final_segment = encryption.encrypt_final_segment(b"").unwrap();

        let mut ciphertext =
            Vec::with_capacity(Header::LEN + non_final.len() + final_segment.len());
        ciphertext.extend_from_slice(header.as_ref());
        ciphertext.extend_from_slice(&non_final);
        ciphertext.extend_from_slice(&final_segment);

        // When the complete message is decrypted
        // Then the alternate framing is accepted and the plaintext recovered
        let layout = parameters
            .ciphertext_layout(u64::try_from(ciphertext.len()).unwrap())
            .unwrap();
        assert_eq!(layout.segment_count(), 2);
        assert_eq!(
            decrypt(&test_key(), b"alternate framing", &ciphertext).unwrap(),
            plaintext
        );
    }

    #[test]
    fn finish_before_final_segment_reports_truncation() {
        // Given a decryptor that has processed no final segment
        let parameters = Parameters::SEGMENT_4_KIB;
        let encryption = Encryptor::new(&test_key(), b"aad", parameters).unwrap();
        let header = *encryption.header();
        let decryption = Decryptor::new(&test_key(), b"aad", &header).unwrap();

        // When it is finished
        // Then the missing final segment is reported as truncation
        assert_eq!(decryption.finish(), Err(Error::Truncated));
    }

    #[test]
    fn decryptor_closes_after_final_segment() {
        // Given a message consisting of one final segment
        let parameters = Parameters::SEGMENT_4_KIB;
        let encryption = Encryptor::new(&test_key(), b"aad", parameters).unwrap();
        assert_eq!(encryption.next_position(), 0);
        let header = *encryption.header();
        let final_segment = encryption.encrypt_final_segment(b"done").unwrap();

        // When the final segment is decrypted
        let mut decryption = Decryptor::new(&test_key(), b"aad", &header).unwrap();
        assert_eq!(decryption.decrypt_segment(&final_segment).unwrap(), b"done");

        // Then the decryptor is finished, refuses further segments, and
        // finishes cleanly
        assert!(decryption.is_finished());
        assert_eq!(
            decryption.decrypt_segment(&final_segment),
            Err(Error::Closed)
        );
        assert!(decryption.finish().is_ok());
    }

    #[test]
    fn decrypt_segment_into_requires_sufficient_output() {
        // Given a four-byte final segment and an undersized output buffer
        let parameters = Parameters::SEGMENT_4_KIB;
        let encryption = Encryptor::new(&test_key(), b"aad", parameters).unwrap();
        let header = *encryption.header();
        let final_segment = encryption.encrypt_final_segment(b"done").unwrap();
        let mut decryption = Decryptor::new(&test_key(), b"aad", &header).unwrap();
        assert_eq!(decryption.next_position(), 0);

        // When the segment is decrypted into three bytes of output
        // Then the buffer is rejected without consuming the segment
        let mut too_small = [0u8; 3];
        assert!(matches!(
            decryption.decrypt_segment_into(&final_segment, &mut too_small),
            Err(Error::OutputTooSmall { .. })
        ));

        // When it is decrypted into an exactly sized buffer
        // Then the plaintext is written and the decryptor finishes
        let mut output = [0u8; 4];
        assert_eq!(
            decryption
                .decrypt_segment_into(&final_segment, &mut output)
                .unwrap(),
            output.len()
        );
        assert_eq!(&output, b"done");
        assert!(decryption.finish().is_ok());
    }

    #[test]
    fn segments_shorter_than_minimum_overhead_rejected() {
        // Given a segment whose prefix declares less than the framing
        // overhead
        let parameters = Parameters::SEGMENT_4_KIB;
        let encryption = Encryptor::new(&test_key(), b"aad", parameters).unwrap();
        let header = *encryption.header();
        let mut invalid_prefix = [0u8; SEGMENT_OVERHEAD];
        invalid_prefix[..SEGMENT_PREFIX_LENGTH]
            .copy_from_slice(&u32::try_from(SEGMENT_OVERHEAD - 1).unwrap().to_be_bytes());

        // When the segment is decrypted
        // Then the declared length is rejected as out of range
        let mut decryption = Decryptor::new(&test_key(), b"aad", &header).unwrap();
        assert!(matches!(
            decryption.decrypt_segment(&invalid_prefix),
            Err(Error::InvalidCiphertextLength {
                actual,
                required: LengthRequirement::Between {..},
            }) if actual == SEGMENT_OVERHEAD - 1
        ));
    }

    #[test]
    fn final_segment_round_trips_in_place() {
        // Given a final payload prepared in a reusable segment buffer
        let parameters = Parameters::SEGMENT_4_KIB;
        let encryption = Encryptor::new(&test_key(), b"aad", parameters).unwrap();
        let header = *encryption.header();
        let mut in_place = SegmentBuffer::new(parameters);
        in_place
            .prepare_plaintext(4)
            .unwrap()
            .copy_from_slice(b"done");

        // When the buffer is encrypted and decrypted in place
        encryption
            .encrypt_final_segment_in_place(&mut in_place)
            .unwrap();
        let mut decryption = Decryptor::new(&test_key(), b"aad", &header).unwrap();

        // Then the plaintext is recovered and the decryptor finishes
        assert_eq!(
            decryption.decrypt_segment_in_place(&mut in_place).unwrap(),
            b"done"
        );
        assert!(decryption.finish().is_ok());
    }

    #[test]
    fn failed_final_encryption_returns_reusable_state() {
        // Given final-segment encryption that fails on an undersized buffer
        let parameters = Parameters::SEGMENT_4_KIB;
        let encryption = Encryptor::new(&test_key(), b"recover final", parameters).unwrap();
        let header = *encryption.header();
        let mut too_small = [0u8; SEGMENT_OVERHEAD];

        // When the failure is returned
        let failure = encryption
            .encrypt_final_segment_into(b"retry", &mut too_small)
            .unwrap_err();

        // Then it reports the cause without leaking encryptor internals
        assert!(matches!(failure.error(), Error::OutputTooSmall { .. }));
        assert!(!format!("{failure:?}").contains("Encryptor"));

        // When the encryptor is recovered from the failure
        let encryption = failure.into_encryptor();

        // Then its state is unchanged and the retry produces a message the
        // original header still authenticates
        assert_eq!(encryption.header(), &header);
        assert_eq!(encryption.next_position(), 0);
        let encrypted = encryption.encrypt_final_segment(b"retry").unwrap();
        let mut decryption = Decryptor::new(&test_key(), b"recover final", &header).unwrap();
        assert_eq!(decryption.decrypt_segment(&encrypted).unwrap(), b"retry");
        decryption.finish().unwrap();
    }

    #[test]
    fn wrong_aad_fails_header_authentication() {
        // Given a ciphertext encrypted under one AAD
        let parameters = Parameters::SEGMENT_4_KIB;
        let ciphertext = encrypt(&test_key(), b"correct aad", parameters, b"plaintext").unwrap();

        // When it is decrypted under another
        // Then the header tag is rejected before any payload is produced
        assert_eq!(
            decrypt(&test_key(), b"wrong aad", &ciphertext),
            Err(Error::InvalidHeaderTag)
        );
    }

    #[test]
    fn header_slices_require_exact_length() {
        // Given slices one byte shorter and one byte longer than a header
        let parameters = Parameters::SEGMENT_4_KIB;
        let ciphertext = encrypt(&test_key(), b"correct aad", parameters, b"plaintext").unwrap();

        // When each is parsed as a header
        // Then both lengths are rejected
        assert!(matches!(
            Header::try_from(&ciphertext[..HEADER_LENGTH - 1]),
            Err(Error::InvalidHeaderLength { .. })
        ));
        assert!(matches!(
            Header::try_from(&ciphertext[..=HEADER_LENGTH]),
            Err(Error::InvalidHeaderLength { .. })
        ));
    }

    #[test]
    fn flipped_header_bit_fails_header_authentication() {
        // Given a ciphertext whose header tag has one flipped bit
        let parameters = Parameters::SEGMENT_4_KIB;
        let ciphertext = encrypt(&test_key(), b"correct aad", parameters, b"plaintext").unwrap();
        let mut bad_header = ciphertext.clone();
        bad_header[HEADER_LENGTH - 1] ^= 1;

        // When it is decrypted
        // Then the header tag is rejected
        assert_eq!(
            decrypt(&test_key(), b"correct aad", &bad_header),
            Err(Error::InvalidHeaderTag)
        );
    }

    #[test]
    fn flipped_ciphertext_bit_fails_segment_authentication() {
        // Given a ciphertext whose final byte has one flipped bit
        let parameters = Parameters::SEGMENT_4_KIB;
        let ciphertext = encrypt(&test_key(), b"correct aad", parameters, b"plaintext").unwrap();
        let mut bad_segment = ciphertext.clone();
        *bad_segment.last_mut().unwrap() ^= 1;

        // When it is decrypted
        // Then segment authentication fails
        assert_eq!(
            decrypt(&test_key(), b"correct aad", &bad_segment),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn truncated_ciphertexts_classified_by_missing_bytes() {
        // Given a valid single-segment ciphertext
        let parameters = Parameters::SEGMENT_4_KIB;
        let ciphertext = encrypt(&test_key(), b"correct aad", parameters, b"plaintext").unwrap();

        // When only the header survives
        // Then the missing body is reported as truncation
        let header_only = &ciphertext[..HEADER_LENGTH];
        assert_eq!(
            decrypt(&test_key(), b"correct aad", header_only),
            Err(Error::Truncated)
        );

        // When the final byte is missing
        // Then the segment is rejected with the exact shortfall
        let truncated = &ciphertext[..ciphertext.len() - 1];
        assert_eq!(
            decrypt(&test_key(), b"correct aad", truncated),
            Err(Error::InvalidCiphertextLength {
                actual: truncated.len() - HEADER_LENGTH,
                required: LengthRequirement::AtLeast(ciphertext.len() - HEADER_LENGTH)
            })
        );

        // When the body is only a prefix declaring an undersized segment
        // Then the declared length is rejected
        let mut undersized_final = header_only.to_vec();
        undersized_final.extend_from_slice(&4_u32.to_be_bytes());
        assert!(matches!(
            decrypt(&test_key(), b"correct aad", &undersized_final),
            Err(Error::InvalidCiphertextLength { .. })
        ));
    }

    #[test]
    fn every_truncation_of_valid_ciphertext_rejected() {
        // Given a valid multi-segment ciphertext
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext = vec![0x3c; 3 * parameters.plaintext_segment_length() + 7];
        let ciphertext = encrypt(&test_key(), b"aad", parameters, &plaintext).unwrap();

        // When it is truncated to every possible length
        for end in 0..ciphertext.len() {
            // Then no truncation decrypts successfully
            assert!(
                decrypt(&test_key(), b"aad", &ciphertext[..end]).is_err(),
                "accepted ciphertext truncated to {end} bytes"
            );
        }
    }

    #[test]
    fn decrypt_with_parameters_rejects_mismatched_profile() {
        // Given a ciphertext encrypted with 4 KiB segments
        let parameters = Parameters::SEGMENT_4_KIB;
        let ciphertext = encrypt(&test_key(), b"aad", parameters, b"plaintext").unwrap();

        // When decryption demands the 1 MiB profile
        // Then the header's parameters are rejected
        assert_eq!(
            decrypt_with_parameters(&test_key(), b"aad", Parameters::SEGMENT_1_MIB, &ciphertext,),
            Err(Error::InvalidHeaderParameters)
        );
    }
}
