use std::sync::Arc;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::backends::{AeadKey, ProviderRng};
use crate::{
    AEAD_IV_LENGTH, AEAD_MAX_SEGMENTS, AEAD_TAG_LENGTH, ENCODED_PARAMETERS_LENGTH, Error,
    FLOE_IV_LENGTH, HEADER_LENGTH, HEADER_TAG_LENGTH, Key, LengthRequirement, Parameters, Provider,
    Result, SEGMENT_OVERHEAD, SEGMENT_PAYLOAD_OFFSET, SEGMENT_PREFIX_LENGTH, SegmentBuffer,
    SegmentFraming, SegmentKind, SegmentLayout, length_u32_to_usize, length_usize_to_u64,
};

const HEADER_TAG_PURPOSE: &[u8] = b"HEADER_TAG:";
const MESSAGE_KEY_PURPOSE: &[u8] = b"MESSAGE_KEY:";
const SEGMENT_KEY_PURPOSE: &[u8] = b"DEK:";
const NONCE_BATCH_SIZE: usize = 64;
const NONCE_BATCH_LENGTH: usize = AEAD_IV_LENGTH * NONCE_BATCH_SIZE;
const SEGMENT_AAD_LENGTH: usize = 9;

#[inline]
fn segment_aad(position: u64, kind: SegmentKind) -> [u8; SEGMENT_AAD_LENGTH] {
    let mut aad = [0u8; SEGMENT_AAD_LENGTH];
    aad[..8].copy_from_slice(&position.to_be_bytes());
    aad[8] = kind.indicator();
    aad
}

/// A complete fixed-size FLOE header.
///
/// Use [`Self::unverified_parameters`] only for selecting policy or preparing
/// buffers. The encoded parameters are not authenticated until decryption
/// initialization succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header([u8; HEADER_LENGTH]);

impl Header {
    /// Length of every FLOE header in bytes.
    pub const LEN: usize = HEADER_LENGTH;

    /// Returns the complete header bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HEADER_LENGTH] {
        &self.0
    }

    /// Decodes the parameter set declared by this header.
    ///
    /// This does not authenticate the header. Do not trust the result until
    /// [`start_decryption`] or [`start_decryption_inferred`] successfully
    /// authenticates the header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHeaderParameters`] if the encoded parameter set
    /// is not supported.
    pub fn unverified_parameters(&self) -> Result<Parameters> {
        let mut encoded = [0u8; ENCODED_PARAMETERS_LENGTH];
        encoded.copy_from_slice(&self.0[..ENCODED_PARAMETERS_LENGTH]);
        Parameters::decode(encoded)
    }
}

impl AsRef<[u8]> for Header {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; HEADER_LENGTH]> for Header {
    fn from(bytes: [u8; HEADER_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl From<Header> for [u8; HEADER_LENGTH] {
    fn from(header: Header) -> Self {
        header.0
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; HEADER_LENGTH] =
            bytes.try_into().map_err(|_| Error::InvalidHeaderLength {
                actual: bytes.len(),
            })?;
        Ok(Self(bytes))
    }
}

struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    fn expose_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct CachedKey {
    masked_position: u64,
    key: AeadKey,
}

struct MessageContext {
    provider: Provider,
    parameters: Parameters,
    message_key: SecretBytes<48>,
    floe_iv: [u8; FLOE_IV_LENGTH],
    aad: Box<[u8]>,
}

impl core::fmt::Debug for MessageContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MessageContext")
            .field("provider", &self.provider)
            .field("parameters", &self.parameters)
            .field("floe_iv", &self.floe_iv)
            .field("aad_length", &self.aad.len())
            .finish_non_exhaustive()
    }
}

impl MessageContext {
    #[inline]
    fn new(
        provider: Provider,
        parameters: Parameters,
        message_key: SecretBytes<48>,
        floe_iv: [u8; FLOE_IV_LENGTH],
        aad: &[u8],
    ) -> Self {
        Self {
            provider,
            parameters,
            message_key,
            floe_iv,
            aad: aad.into(),
        }
    }
}

struct KeyCache {
    cached_key: Option<CachedKey>,
}

impl core::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyCache")
            .field(
                "masked_position",
                &self
                    .cached_key
                    .as_ref()
                    .map(|cached| cached.masked_position),
            )
            .finish_non_exhaustive()
    }
}

impl KeyCache {
    #[inline]
    fn new(context: &MessageContext) -> Result<Self> {
        Ok(Self {
            cached_key: Some(CachedKey {
                masked_position: 0,
                key: derive_segment_key(
                    context.provider,
                    context.parameters,
                    &context.message_key,
                    &context.floe_iv,
                    &context.aad,
                    0,
                )?,
            }),
        })
    }

    #[inline]
    const fn empty() -> Self {
        Self { cached_key: None }
    }

    #[inline]
    fn key_for_position(&mut self, context: &MessageContext, position: u64) -> Result<&AeadKey> {
        if position >= AEAD_MAX_SEGMENTS {
            return Err(Error::SegmentLimit);
        }

        let masked_position = Parameters::masked_position(position);
        if self
            .cached_key
            .as_ref()
            .is_none_or(|cached| cached.masked_position != masked_position)
        {
            self.cached_key = Some(CachedKey {
                masked_position,
                key: derive_segment_key(
                    context.provider,
                    context.parameters,
                    &context.message_key,
                    &context.floe_iv,
                    &context.aad,
                    masked_position,
                )?,
            });
        }
        self.cached_key
            .as_ref()
            .map(|cached| &cached.key)
            .ok_or(Error::CryptoFailure)
    }
}

struct NonceGenerator {
    rng: ProviderRng,
    bytes: [u8; NONCE_BATCH_LENGTH],
    next: usize,
}

impl core::fmt::Debug for NonceGenerator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let remaining = (NONCE_BATCH_LENGTH - self.next) / AEAD_IV_LENGTH;
        f.debug_struct("NonceGenerator")
            .field("remaining", &remaining)
            .finish_non_exhaustive()
    }
}

impl NonceGenerator {
    #[inline]
    fn new(rng: ProviderRng) -> Self {
        Self {
            rng,
            bytes: [0; NONCE_BATCH_LENGTH],
            next: NONCE_BATCH_LENGTH,
        }
    }

    #[inline]
    fn next(&mut self) -> Result<[u8; AEAD_IV_LENGTH]> {
        if self.next == NONCE_BATCH_LENGTH {
            self.rng.fill(&mut self.bytes)?;
            self.next = 0;
        }
        let mut nonce = [0; AEAD_IV_LENGTH];
        nonce.copy_from_slice(&self.bytes[self.next..self.next + AEAD_IV_LENGTH]);
        self.next += AEAD_IV_LENGTH;
        Ok(nonce)
    }
}

#[inline]
fn ciphertext_segment_size(
    context: &MessageContext,
    plaintext_length: usize,
    kind: SegmentKind,
) -> Result<usize> {
    let maximum = context.parameters.plaintext_segment_length();
    match kind {
        SegmentKind::Final if plaintext_length <= maximum => SEGMENT_OVERHEAD
            .checked_add(plaintext_length)
            .ok_or(Error::LengthOverflow),
        SegmentKind::Final => Err(Error::InvalidPlaintextLength {
            actual: plaintext_length,
            required: LengthRequirement::AtMost(maximum),
        }),
        SegmentKind::NonFinal if plaintext_length == maximum => {
            Ok(context.parameters.ciphertext_segment_length())
        }
        SegmentKind::NonFinal => Err(Error::InvalidPlaintextLength {
            actual: plaintext_length,
            required: LengthRequirement::Exactly(maximum),
        }),
    }
}

#[inline]
fn encrypt_segment_into_inner(
    context: &MessageContext,
    keys: &mut KeyCache,
    nonces: &mut NonceGenerator,
    plaintext: &[u8],
    position: u64,
    kind: SegmentKind,
    output: &mut [u8],
) -> Result<usize> {
    let required = ciphertext_segment_size(context, plaintext.len(), kind)?;
    if output.len() < required {
        return Err(Error::OutputTooSmall {
            actual: output.len(),
            required,
        });
    }
    let plaintext_start = SEGMENT_PAYLOAD_OFFSET;
    output[plaintext_start..plaintext_start + plaintext.len()].copy_from_slice(plaintext);
    encrypt_prepared_segment(
        context,
        keys,
        nonces,
        output,
        plaintext.len(),
        position,
        kind,
        required,
    )
}

#[inline]
fn encrypt_segment_in_place_inner(
    context: &MessageContext,
    keys: &mut KeyCache,
    nonces: &mut NonceGenerator,
    buffer: &mut [u8],
    plaintext_length: usize,
    position: u64,
    kind: SegmentKind,
) -> Result<usize> {
    let required = ciphertext_segment_size(context, plaintext_length, kind)?;
    if buffer.len() < required {
        return Err(Error::OutputTooSmall {
            actual: buffer.len(),
            required,
        });
    }
    encrypt_prepared_segment(
        context,
        keys,
        nonces,
        buffer,
        plaintext_length,
        position,
        kind,
        required,
    )
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn encrypt_prepared_segment(
    context: &MessageContext,
    keys: &mut KeyCache,
    nonces: &mut NonceGenerator,
    output: &mut [u8],
    plaintext_length: usize,
    position: u64,
    kind: SegmentKind,
    required: usize,
) -> Result<usize> {
    let nonce = nonces.next()?;
    let key = keys.key_for_position(context, position)?;
    let prefix = match kind {
        SegmentKind::NonFinal => u32::MAX,
        // `ciphertext_segment_size` bounds `required` at
        // `ciphertext_segment_length`, at most 1 MiB, so the conversion cannot
        // fail. The same bound keeps an encoded final length from ever
        // colliding with the `u32::MAX` non-final sentinel.
        SegmentKind::Final => u32::try_from(required).map_err(|_| Error::LengthOverflow)?,
    };
    output[..SEGMENT_PREFIX_LENGTH].copy_from_slice(&prefix.to_be_bytes());

    let nonce_start = SEGMENT_PREFIX_LENGTH;
    let ciphertext_start = nonce_start + AEAD_IV_LENGTH;
    let tag_start = ciphertext_start + plaintext_length;
    let segment_aad = segment_aad(position, kind);
    let mut tag = [0u8; AEAD_TAG_LENGTH];

    key.seal(
        &nonce,
        &segment_aad,
        &mut output[ciphertext_start..tag_start],
        &mut tag,
    )?;

    output[nonce_start..ciphertext_start].copy_from_slice(&nonce);
    output[tag_start..required].copy_from_slice(&tag);
    Ok(required)
}

#[inline]
fn validate_segment(
    context: &MessageContext,
    ciphertext_segment: &[u8],
    kind: SegmentKind,
) -> Result<usize> {
    let maximum = context.parameters.ciphertext_segment_length();
    match kind {
        SegmentKind::Final if !(SEGMENT_OVERHEAD..=maximum).contains(&ciphertext_segment.len()) => {
            return Err(Error::InvalidCiphertextLength {
                actual: ciphertext_segment.len(),
                required: LengthRequirement::Between {
                    minimum: SEGMENT_OVERHEAD,
                    maximum,
                },
            });
        }
        SegmentKind::NonFinal if ciphertext_segment.len() != maximum => {
            return Err(Error::InvalidCiphertextLength {
                actual: ciphertext_segment.len(),
                required: LengthRequirement::Exactly(maximum),
            });
        }
        SegmentKind::Final | SegmentKind::NonFinal => {}
    }

    let prefix = u32::from_be_bytes(
        ciphertext_segment[..SEGMENT_PREFIX_LENGTH]
            .try_into()
            .map_err(|_| Error::InvalidSegmentPrefix)?,
    );

    match kind {
        // Compared in u64 space: the equality must not depend on the width of
        // usize, because `prefix` is attacker-controlled and unauthenticated.
        SegmentKind::Final
            if u64::from(prefix) != length_usize_to_u64(ciphertext_segment.len()) =>
        {
            return Err(Error::InvalidCiphertextLength {
                actual: ciphertext_segment.len(),
                required: LengthRequirement::Exactly(length_u32_to_usize(prefix)),
            });
        }
        SegmentKind::NonFinal if prefix != u32::MAX => {
            return Err(Error::InvalidSegmentPrefix);
        }
        SegmentKind::Final | SegmentKind::NonFinal => {}
    }

    Ok(ciphertext_segment.len() - SEGMENT_OVERHEAD)
}

#[inline]
fn decrypt_segment_into_inner(
    context: &MessageContext,
    keys: &mut KeyCache,
    ciphertext_segment: &[u8],
    position: u64,
    kind: SegmentKind,
    plaintext_length: usize,
    output: &mut [u8],
) -> Result<usize> {
    if output.len() < plaintext_length {
        return Err(Error::OutputTooSmall {
            actual: output.len(),
            required: plaintext_length,
        });
    }

    let key = keys.key_for_position(context, position)?;
    let nonce_start = SEGMENT_PREFIX_LENGTH;
    let ciphertext_start = nonce_start + AEAD_IV_LENGTH;
    let tag_start = ciphertext_segment.len() - AEAD_TAG_LENGTH;
    let segment_aad = segment_aad(position, kind);
    let nonce: &[u8; AEAD_IV_LENGTH] = ciphertext_segment[nonce_start..ciphertext_start]
        .try_into()
        .map_err(|_| Error::CryptoFailure)?;
    let tag: &[u8; AEAD_TAG_LENGTH] = ciphertext_segment[tag_start..]
        .try_into()
        .map_err(|_| Error::CryptoFailure)?;

    key.open(
        nonce,
        &segment_aad,
        &ciphertext_segment[ciphertext_start..tag_start],
        tag,
        &mut output[..plaintext_length],
    )?;
    Ok(plaintext_length)
}

#[inline]
fn decrypt_segment_in_place_inner<'a>(
    context: &MessageContext,
    keys: &mut KeyCache,
    ciphertext_segment: &'a mut [u8],
    position: u64,
    kind: SegmentKind,
) -> Result<&'a mut [u8]> {
    let plaintext_length = validate_segment(context, ciphertext_segment, kind)?;
    let key = keys.key_for_position(context, position)?;
    let ciphertext_start = SEGMENT_PAYLOAD_OFFSET;
    let (framing, ciphertext_and_tag) = ciphertext_segment.split_at_mut(ciphertext_start);
    let nonce: &[u8; AEAD_IV_LENGTH] = framing[SEGMENT_PREFIX_LENGTH..]
        .try_into()
        .map_err(|_| Error::CryptoFailure)?;
    let (ciphertext, tag_bytes) = ciphertext_and_tag.split_at_mut(plaintext_length);
    let tag: &[u8; AEAD_TAG_LENGTH] = (&*tag_bytes).try_into().map_err(|_| Error::CryptoFailure)?;

    let segment_aad = segment_aad(position, kind);
    key.open_in_place(nonce, &segment_aad, tag, ciphertext)?;
    Ok(ciphertext)
}

#[inline]
fn validate_layout(context: &MessageContext, segment: SegmentLayout) -> Result<()> {
    if segment.parameters() == context.parameters {
        Ok(())
    } else {
        Err(Error::InvalidParameters)
    }
}

/// State for the specification's random-access encryption functions.
///
/// Use [`Parameters::plaintext_layout`] and pass each resulting
/// [`SegmentLayout`] directly to the corresponding segment operation.
///
/// The caller must encrypt each position at most once, produce exactly one
/// final segment, leave no gaps, and never encrypt a position beyond the final
/// segment.
#[derive(Debug)]
pub struct EncryptionState {
    context: Arc<MessageContext>,
    keys: KeyCache,
    nonces: NonceGenerator,
}

impl EncryptionState {
    /// Returns the provider used by this state.
    #[must_use]
    pub fn provider(&self) -> Provider {
        self.context.provider
    }

    /// Returns this state's parameter set.
    #[must_use]
    pub fn parameters(&self) -> Parameters {
        self.context.parameters
    }

    /// Consumes this state and makes its immutable message context shareable
    /// by independent encryption states.
    #[must_use]
    pub fn into_shared(self) -> SharedEncryptionContext {
        let Self { context, .. } = self;
        SharedEncryptionContext { context }
    }

    /// Encrypts one random-access segment into a newly allocated buffer.
    ///
    /// # Errors
    ///
    /// Returns an error when the layout belongs to another parameter set, the
    /// plaintext length does not match the layout, the position is invalid, or
    /// the selected backend cannot generate a nonce or encrypt the segment.
    pub fn encrypt_segment(&mut self, plaintext: &[u8], segment: SegmentLayout) -> Result<Vec<u8>> {
        self.validate_plaintext_layout(plaintext.len(), segment)?;
        self.encrypt_segment_at(plaintext, segment.position(), segment.kind())
    }

    /// Encrypts one random-access segment into `output`, returning bytes written.
    ///
    /// [`SegmentLayout::ciphertext_length`] gives the required
    /// output length for a segment in a complete message layout.
    ///
    /// This method performs no heap allocation on the normal per-segment path.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, insufficient output space, segment
    /// limit exhaustion, random generation failure, or encryption failure.
    #[inline]
    pub fn encrypt_segment_into(
        &mut self,
        plaintext: &[u8],
        segment: SegmentLayout,
        output: &mut [u8],
    ) -> Result<usize> {
        self.validate_plaintext_layout(plaintext.len(), segment)?;
        self.encrypt_segment_into_at(plaintext, segment.position(), segment.kind(), output)
    }

    /// Encrypts plaintext prepared in a reusable [`SegmentBuffer`].
    ///
    /// Prepare the payload with [`SegmentBuffer::prepare_plaintext`]. On
    /// success, [`SegmentBuffer::ciphertext`] returns the complete ciphertext
    /// segment without copying the plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, insufficient buffer space, segment
    /// limit exhaustion, random generation failure, or encryption failure.
    #[inline]
    pub fn encrypt_segment_in_place<'a>(
        &mut self,
        buffer: &'a mut SegmentBuffer,
        segment: SegmentLayout,
    ) -> Result<&'a [u8]> {
        self.validate_plaintext_layout(buffer.plaintext_length()?, segment)?;
        self.encrypt_segment_in_place_at(buffer, segment.position(), segment.kind())
    }

    pub(crate) fn encrypt_segment_in_place_at<'a>(
        &mut self,
        buffer: &'a mut SegmentBuffer,
        position: u64,
        kind: SegmentKind,
    ) -> Result<&'a [u8]> {
        if !buffer.matches(self.parameters()) {
            return Err(Error::InvalidParameters);
        }

        let plaintext_length = buffer.plaintext_length()?;
        let result = self.encrypt_segment_in_place_raw_at(
            buffer.raw_mut(),
            plaintext_length,
            position,
            kind,
        );

        match result {
            Ok(written) => {
                buffer.mark_ciphertext(written);
                buffer.ciphertext()
            }
            Err(error) => {
                buffer.mark_empty();
                Err(error)
            }
        }
    }

    /// Encrypts a segment in caller-managed storage.
    ///
    /// Before calling, place [`SegmentLayout::plaintext_length`] bytes at
    /// [`crate::low_level::SEGMENT_PAYLOAD_OFFSET`]. The buffer must be large
    /// enough for the complete encrypted segment. Prefer
    /// [`SegmentBuffer`] unless direct pool, stack, or arena integration is
    /// required.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid position or plaintext length,
    /// insufficient buffer space, segment-limit exhaustion, random-generation
    /// failure, or encryption failure.
    pub fn encrypt_segment_in_place_raw(
        &mut self,
        buffer: &mut [u8],
        segment: SegmentLayout,
    ) -> Result<usize> {
        validate_layout(&self.context, segment)?;
        let plaintext_length = segment.plaintext_length();

        self.encrypt_segment_in_place_raw_at(
            buffer,
            plaintext_length,
            segment.position(),
            segment.kind(),
        )
    }

    pub(crate) fn encrypt_segment_at(
        &mut self,
        plaintext: &[u8],
        position: u64,
        kind: SegmentKind,
    ) -> Result<Vec<u8>> {
        let required = ciphertext_segment_size(&self.context, plaintext.len(), kind)?;
        let mut output = vec![0u8; required];
        self.encrypt_segment_into_at(plaintext, position, kind, &mut output)?;
        Ok(output)
    }

    pub(crate) fn encrypt_segment_into_at(
        &mut self,
        plaintext: &[u8],
        position: u64,
        kind: SegmentKind,
        output: &mut [u8],
    ) -> Result<usize> {
        encrypt_segment_into_inner(
            &self.context,
            &mut self.keys,
            &mut self.nonces,
            plaintext,
            position,
            kind,
            output,
        )
    }

    pub(crate) fn encrypt_segment_in_place_raw_at(
        &mut self,
        buffer: &mut [u8],
        plaintext_length: usize,
        position: u64,
        kind: SegmentKind,
    ) -> Result<usize> {
        encrypt_segment_in_place_inner(
            &self.context,
            &mut self.keys,
            &mut self.nonces,
            buffer,
            plaintext_length,
            position,
            kind,
        )
    }

    fn validate_plaintext_layout(&self, actual: usize, segment: SegmentLayout) -> Result<()> {
        validate_layout(&self.context, segment)?;
        let expected = segment.plaintext_length();

        if actual == expected {
            Ok(())
        } else {
            Err(Error::InvalidPlaintextLength {
                actual,
                required: LengthRequirement::Exactly(expected),
            })
        }
    }
}

/// Shareable message context for parallel random-access encryption.
///
/// Create this by consuming an [`EncryptionState`] with
/// [`EncryptionState::into_shared`], then create one [`EncryptionState`] for
/// each independently executing task.
#[derive(Clone, Debug)]
pub struct SharedEncryptionContext {
    context: Arc<MessageContext>,
}

impl SharedEncryptionContext {
    /// Returns the provider retained by this context.
    #[must_use]
    pub fn provider(&self) -> Provider {
        self.context.provider
    }

    /// Returns this context's parameter set.
    #[must_use]
    pub fn parameters(&self) -> Parameters {
        self.context.parameters
    }

    /// Creates an independent encryption state with its own key cache and
    /// nonce generator.
    #[must_use]
    pub fn fork(&self) -> EncryptionState {
        EncryptionState {
            context: Arc::clone(&self.context),
            keys: KeyCache::empty(),
            nonces: NonceGenerator::new(ProviderRng::new(self.context.provider)),
        }
    }
}

/// State for the specification's random-access decryption functions.
///
/// For a seekable complete ciphertext, [`Parameters::ciphertext_layout`]
/// supplies a [`SegmentLayout`] that can be passed directly to each operation.
/// Layout metadata is not authenticated until segment decryption succeeds.
///
/// Prefer [`crate::random_access::Reader`] when the input implements `Read + Seek`.
#[derive(Debug)]
pub struct DecryptionState {
    context: Arc<MessageContext>,
    keys: KeyCache,
}

impl DecryptionState {
    /// Returns the provider used by this state.
    #[must_use]
    pub fn provider(&self) -> Provider {
        self.context.provider
    }

    /// Returns this state's parameter set.
    #[must_use]
    pub fn parameters(&self) -> Parameters {
        self.context.parameters
    }

    /// Consumes this state and makes its immutable message context shareable
    /// by independent decryption states.
    #[must_use]
    pub fn into_shared(self) -> SharedDecryptionContext {
        let Self { context, .. } = self;
        SharedDecryptionContext { context }
    }

    /// Decrypts one random-access segment into a newly allocated buffer.
    ///
    /// # Errors
    ///
    /// Returns an error when the layout belongs to another parameter set, the
    /// encrypted length does not match it, framing, position, or authentication
    /// validation fails, or the selected backend rejects the segment key.
    pub fn decrypt_segment(
        &mut self,
        ciphertext_segment: &[u8],
        segment: SegmentLayout,
    ) -> Result<Vec<u8>> {
        self.validate_ciphertext_layout(ciphertext_segment.len(), segment)?;
        self.decrypt_segment_at(ciphertext_segment, segment.position(), segment.kind())
    }

    /// Decrypts one random-access segment into `output`, returning bytes written.
    ///
    /// [`SegmentLayout::plaintext_length`] gives the required output length.
    ///
    /// Authentication failure may overwrite bytes in `output`; callers must not
    /// use its contents unless this method succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, insufficient output space, an
    /// invalid position, key derivation failure, or authentication failure.
    #[inline]
    pub fn decrypt_segment_into(
        &mut self,
        ciphertext_segment: &[u8],
        segment: SegmentLayout,
        output: &mut [u8],
    ) -> Result<usize> {
        self.validate_ciphertext_layout(ciphertext_segment.len(), segment)?;
        self.decrypt_segment_into_at(
            ciphertext_segment,
            segment.position(),
            segment.kind(),
            output,
        )
    }

    /// Authenticates and decrypts a segment in a reusable [`SegmentBuffer`].
    ///
    /// Prepare the ciphertext with [`SegmentBuffer::prepare_ciphertext`]. On
    /// success, this returns the authenticated plaintext within the buffer.
    ///
    /// Authentication failure may overwrite the ciphertext payload. Callers
    /// must not use the returned buffer contents unless this method succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, an invalid position, key
    /// derivation failure, or authentication failure.
    #[inline]
    pub fn decrypt_segment_in_place<'a>(
        &mut self,
        buffer: &'a mut SegmentBuffer,
        segment: SegmentLayout,
    ) -> Result<&'a mut [u8]> {
        self.validate_ciphertext_layout(buffer.ciphertext_length()?, segment)?;
        self.decrypt_segment_in_place_at(buffer, segment.position(), segment.kind())
    }

    pub(crate) fn decrypt_segment_in_place_at<'a>(
        &mut self,
        buffer: &'a mut SegmentBuffer,
        position: u64,
        kind: SegmentKind,
    ) -> Result<&'a mut [u8]> {
        if !buffer.matches(self.parameters()) {
            return Err(Error::InvalidParameters);
        }
        let ciphertext_length = buffer.ciphertext_length()?;
        let result = self.decrypt_segment_in_place_raw_at(
            &mut buffer.raw_mut()[..ciphertext_length],
            position,
            kind,
        );
        match result {
            Ok(plaintext) => {
                let length = plaintext.len();
                buffer.mark_plaintext(SEGMENT_PAYLOAD_OFFSET, length);
                buffer
                    .raw_mut()
                    .get_mut(SEGMENT_PAYLOAD_OFFSET..SEGMENT_PAYLOAD_OFFSET + length)
                    .ok_or(Error::InvalidBufferState)
            }
            Err(error) => {
                buffer.mark_empty();
                Err(error)
            }
        }
    }

    /// Authenticates and decrypts a segment in caller-managed storage.
    ///
    /// On success, the returned slice identifies the authenticated plaintext
    /// within `ciphertext_segment`. Prefer [`SegmentBuffer`] unless direct pool,
    /// stack, or arena integration is required.
    ///
    /// Authentication failure may overwrite the ciphertext payload. Callers
    /// must not use the buffer contents unless this method succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed framing, an invalid position, key
    /// derivation failure, or authentication failure.
    pub fn decrypt_segment_in_place_raw<'a>(
        &mut self,
        ciphertext_segment: &'a mut [u8],
        segment: SegmentLayout,
    ) -> Result<&'a mut [u8]> {
        validate_layout(&self.context, segment)?;
        let required = segment.ciphertext_length();
        if ciphertext_segment.len() < required {
            return Err(Error::InvalidCiphertextLength {
                actual: ciphertext_segment.len(),
                required: LengthRequirement::AtLeast(required),
            });
        }
        self.decrypt_segment_in_place_raw_at(
            &mut ciphertext_segment[..required],
            segment.position(),
            segment.kind(),
        )
    }

    pub(crate) fn decrypt_segment_at(
        &mut self,
        ciphertext_segment: &[u8],
        position: u64,
        kind: SegmentKind,
    ) -> Result<Vec<u8>> {
        let plaintext_length = validate_segment(&self.context, ciphertext_segment, kind)?;
        let mut output = vec![0u8; plaintext_length];
        decrypt_segment_into_inner(
            &self.context,
            &mut self.keys,
            ciphertext_segment,
            position,
            kind,
            plaintext_length,
            &mut output,
        )?;
        Ok(output)
    }

    pub(crate) fn decrypt_segment_into_at(
        &mut self,
        ciphertext_segment: &[u8],
        position: u64,
        kind: SegmentKind,
        output: &mut [u8],
    ) -> Result<usize> {
        let plaintext_length = validate_segment(&self.context, ciphertext_segment, kind)?;
        decrypt_segment_into_inner(
            &self.context,
            &mut self.keys,
            ciphertext_segment,
            position,
            kind,
            plaintext_length,
            output,
        )
    }

    pub(crate) fn decrypt_segment_into_at_framed(
        &mut self,
        ciphertext_segment: &[u8],
        position: u64,
        framing: SegmentFraming,
        output: &mut [u8],
    ) -> Result<usize> {
        let expected = framing.ciphertext_length();
        if ciphertext_segment.len() != expected {
            return Err(Error::InvalidCiphertextLength {
                actual: ciphertext_segment.len(),
                required: LengthRequirement::Exactly(expected),
            });
        }
        decrypt_segment_into_inner(
            &self.context,
            &mut self.keys,
            ciphertext_segment,
            position,
            framing.kind(),
            framing.plaintext_length(),
            output,
        )
    }

    pub(crate) fn decrypt_segment_in_place_raw_at<'a>(
        &mut self,
        ciphertext_segment: &'a mut [u8],
        position: u64,
        kind: SegmentKind,
    ) -> Result<&'a mut [u8]> {
        decrypt_segment_in_place_inner(
            &self.context,
            &mut self.keys,
            ciphertext_segment,
            position,
            kind,
        )
    }

    fn validate_ciphertext_layout(&self, actual: usize, segment: SegmentLayout) -> Result<()> {
        validate_layout(&self.context, segment)?;
        let expected = segment.ciphertext_length();
        if actual == expected {
            Ok(())
        } else {
            Err(Error::InvalidCiphertextLength {
                actual,
                required: LengthRequirement::Exactly(expected),
            })
        }
    }
}

/// Shareable message context for parallel/concurrent random-access decryption.
///
/// Create this by consuming a [`DecryptionState`] with
/// [`DecryptionState::into_shared`], then create one [`DecryptionState`] for
/// each independently executing task/thread.
#[derive(Clone, Debug)]
pub struct SharedDecryptionContext {
    context: Arc<MessageContext>,
}

impl SharedDecryptionContext {
    /// Returns the provider retained by this context.
    #[must_use]
    pub fn provider(&self) -> Provider {
        self.context.provider
    }

    /// Returns this context's parameter set.
    #[must_use]
    pub fn parameters(&self) -> Parameters {
        self.context.parameters
    }

    /// Creates an independent decryption state with its own key cache.
    #[must_use]
    pub fn fork(&self) -> DecryptionState {
        DecryptionState {
            context: Arc::clone(&self.context),
            keys: KeyCache::empty(),
        }
    }
}

/// Initialize a FLOE encryption state.
///
/// # Errors
///
/// Returns an error if a provider is required or the selected provider cannot
/// initialize or generate the FLOE IV.
pub fn start_encryption(
    key: &Key,
    aad: &[u8],
    parameters: Parameters,
) -> Result<(EncryptionState, Header)> {
    let provider = key.provider()?;
    let mut rng = ProviderRng::new(provider);
    let mut floe_iv = [0u8; FLOE_IV_LENGTH];
    rng.fill(&mut floe_iv)?;

    let encoded = parameters.encode();
    let header_info: [&[u8]; 4] = [&encoded, &floe_iv, HEADER_TAG_PURPOSE, aad];
    let mut header_tag = provider.kdf_expand::<HEADER_TAG_LENGTH>(key.as_bytes(), &header_info)?;

    let message_info: [&[u8]; 4] = [&encoded, &floe_iv, MESSAGE_KEY_PURPOSE, aad];
    let message_key = SecretBytes(provider.kdf_expand::<48>(key.as_bytes(), &message_info)?);

    let mut header = [0u8; HEADER_LENGTH];
    header[..ENCODED_PARAMETERS_LENGTH].copy_from_slice(&encoded);
    header[ENCODED_PARAMETERS_LENGTH..ENCODED_PARAMETERS_LENGTH + FLOE_IV_LENGTH]
        .copy_from_slice(&floe_iv);
    header[ENCODED_PARAMETERS_LENGTH + FLOE_IV_LENGTH..].copy_from_slice(&header_tag);
    header_tag.zeroize();

    let context = Arc::new(MessageContext::new(
        provider,
        parameters,
        message_key,
        floe_iv,
        aad,
    ));
    let keys = KeyCache::new(&context)?;
    let nonces = NonceGenerator::new(rng);

    Ok((
        EncryptionState {
            context,
            keys,
            nonces,
        },
        Header(header),
    ))
}

/// Starts decryption using the provided parameter set and header.
///
/// # Errors
///
/// Returns an error if the encoded parameters or header is invalid,
/// if the provided parameters don't match the parameters in the header,
/// or if an explicit provider is required.
pub fn start_decryption(
    key: &Key,
    aad: &[u8],
    parameters: Parameters,
    header: &Header,
) -> Result<DecryptionState> {
    let provider = key.provider()?;
    start_decryption_with_provider(key, provider, aad, parameters, header)
}

fn start_decryption_with_provider(
    key: &Key,
    provider: Provider,
    aad: &[u8],
    parameters: Parameters,
    header: &Header,
) -> Result<DecryptionState> {
    let header = header.as_bytes();
    let encoded = parameters.encode();

    if header[..ENCODED_PARAMETERS_LENGTH] != encoded {
        return Err(Error::InvalidHeaderParameters);
    }

    let mut floe_iv = [0u8; FLOE_IV_LENGTH];
    floe_iv.copy_from_slice(
        &header[ENCODED_PARAMETERS_LENGTH..ENCODED_PARAMETERS_LENGTH + FLOE_IV_LENGTH],
    );

    let header_info: [&[u8]; 4] = [&encoded, &floe_iv, HEADER_TAG_PURPOSE, aad];
    let mut expected_tag =
        provider.kdf_expand::<HEADER_TAG_LENGTH>(key.as_bytes(), &header_info)?;
    let tag_matches: bool = expected_tag
        .as_slice()
        .ct_eq(&header[ENCODED_PARAMETERS_LENGTH + FLOE_IV_LENGTH..])
        .into();
    expected_tag.zeroize();

    if !tag_matches {
        return Err(Error::InvalidHeaderTag);
    }

    let message_info: [&[u8]; 4] = [&encoded, &floe_iv, MESSAGE_KEY_PURPOSE, aad];
    let message_key = SecretBytes(provider.kdf_expand::<48>(key.as_bytes(), &message_info)?);
    let context = Arc::new(MessageContext::new(
        provider,
        parameters,
        message_key,
        floe_iv,
        aad,
    ));
    let keys = KeyCache::new(&context)?;

    Ok(DecryptionState { context, keys })
}

/// Starts decryption using the parameter set in `header`.
///
/// Use [`start_decryption`] to provide the parameters explicitly.
///
/// # Errors
///
/// Returns an error if the parameters or header are invalid, or
/// if an explicit provider is required.
pub fn start_decryption_inferred(
    key: &Key,
    aad: &[u8],
    header: &Header,
) -> Result<DecryptionState> {
    let provider = key.provider()?;
    let parameters = header.unverified_parameters()?;
    start_decryption_with_provider(key, provider, aad, parameters, header)
}

fn derive_segment_key(
    provider: Provider,
    parameters: Parameters,
    message_key: &SecretBytes<48>,
    floe_iv: &[u8; FLOE_IV_LENGTH],
    aad: &[u8],
    masked_position: u64,
) -> Result<AeadKey> {
    let encoded = parameters.encode();
    let position_bytes = masked_position.to_be_bytes();
    let info: [&[u8]; 5] = [&encoded, floe_iv, SEGMENT_KEY_PURPOSE, &position_bytes, aad];
    let mut key_material = provider.kdf_expand::<32>(message_key.expose_bytes(), &info)?;
    let key = AeadKey::new(provider, &key_material);
    key_material.zeroize();
    key
}
