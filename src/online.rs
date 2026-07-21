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
    Parameters, Result, SEGMENT_PREFIX_LENGTH, SegmentKind, start_decryption,
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
    let plaintext_length = u64::try_from(plaintext.len()).map_err(|_| Error::LengthOverflow)?;
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
mod boundary_tests {
    use super::*;

    #[test]
    fn online_states_reserve_last_position_for_final_segment() {
        let key = Key::from_bytes_with_provider([0; Key::LEN], crate::Provider::COMPILED[0]);
        let parameters = Parameters::SEGMENT_4_KIB;
        let mut encryption = Encryptor::new(&key, b"segment limit", parameters).unwrap();
        let header = *encryption.header();
        encryption.counter.next = AEAD_MAX_SEGMENTS - 1;
        assert_eq!(
            encryption.encrypt_non_final_segment(&[]),
            Err(Error::SegmentLimit)
        );
        let final_segment = encryption.encrypt_final_segment(b"last").unwrap();

        let mut decryption = Decryptor::new(&key, b"segment limit", &header).unwrap();
        assert_eq!(decryption.parameters(), parameters);
        decryption.counter.next = AEAD_MAX_SEGMENTS - 1;
        assert_eq!(decryption.decrypt_segment(&final_segment).unwrap(), b"last");
        assert!(decryption.is_finished());
        decryption.finish().unwrap();
    }
}
