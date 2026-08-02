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
const NONCE_BATCH_SIZE: usize = 256;
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
/// The encoded parameters are not authenticated until decryption
/// initialization succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header([u8; HEADER_LENGTH]);

impl Header {
    /// Length of every FLOE header in bytes.
    pub const LEN: usize = HEADER_LENGTH;

    const FLOE_IV_OFFSET: usize = ENCODED_PARAMETERS_LENGTH;
    const TAG_OFFSET: usize = Self::FLOE_IV_OFFSET + FLOE_IV_LENGTH;

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
        Parameters::decode(*self.encoded_parameters())
    }

    fn from_fields(
        encoded: &[u8; ENCODED_PARAMETERS_LENGTH],
        floe_iv: &[u8; FLOE_IV_LENGTH],
        tag: &[u8; HEADER_TAG_LENGTH],
    ) -> Self {
        let mut bytes = [0u8; HEADER_LENGTH];
        bytes[..Self::FLOE_IV_OFFSET].copy_from_slice(encoded);
        bytes[Self::FLOE_IV_OFFSET..Self::TAG_OFFSET].copy_from_slice(floe_iv);
        bytes[Self::TAG_OFFSET..].copy_from_slice(tag);
        Self(bytes)
    }

    fn encoded_parameters(&self) -> &[u8; ENCODED_PARAMETERS_LENGTH] {
        self.0[..Self::FLOE_IV_OFFSET]
            .try_into()
            .expect("header field offsets are compile-time constants")
    }

    fn floe_iv(&self) -> &[u8; FLOE_IV_LENGTH] {
        self.0[Self::FLOE_IV_OFFSET..Self::TAG_OFFSET]
            .try_into()
            .expect("header field offsets are compile-time constants")
    }

    fn tag(&self) -> &[u8; HEADER_TAG_LENGTH] {
        self.0[Self::TAG_OFFSET..]
            .try_into()
            .expect("header field offsets are compile-time constants")
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

impl CachedKey {
    fn derive(context: &MessageContext, masked_position: u64) -> Result<Self> {
        Ok(Self {
            masked_position,
            key: derive_segment_key(
                context.provider,
                context.parameters,
                &context.message_key,
                &context.floe_iv,
                &context.aad,
                masked_position,
            )?,
        })
    }
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
            cached_key: Some(CachedKey::derive(context, 0)?),
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

        let masked_position = context.parameters.masked_position(position);
        if self
            .cached_key
            .as_ref()
            .is_none_or(|cached| cached.masked_position != masked_position)
        {
            self.cached_key = Some(CachedKey::derive(context, masked_position)?);
        }
        let cached = self
            .cached_key
            .as_ref()
            .expect("populated by the branch above");
        Ok(&cached.key)
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

/// Validates the segment lengths, writes the framing bytes into `output`, and
/// resolves the segment key. Returns everything the caller's seal needs: the
/// complete segment length, the fresh nonce, the key, and the segment AAD.
#[inline]
fn begin_segment_encryption<'a>(
    context: &MessageContext,
    keys: &'a mut KeyCache,
    nonces: &mut NonceGenerator,
    output: &mut [u8],
    plaintext_length: usize,
    position: u64,
    kind: SegmentKind,
) -> Result<(
    usize,
    [u8; AEAD_IV_LENGTH],
    &'a AeadKey,
    [u8; SEGMENT_AAD_LENGTH],
)> {
    let required = ciphertext_segment_size(context, plaintext_length, kind)?;
    if output.len() < required {
        return Err(Error::OutputTooSmall {
            actual: output.len(),
            required,
        });
    }
    let nonce = write_segment_framing(nonces, output, kind, required)?;
    let key = keys.key_for_position(context, position)?;
    Ok((required, nonce, key, segment_aad(position, kind)))
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
    let (required, nonce, key, segment_aad) = begin_segment_encryption(
        context,
        keys,
        nonces,
        output,
        plaintext.len(),
        position,
        kind,
    )?;
    key.seal_into(
        &nonce,
        &segment_aad,
        plaintext,
        &mut output[SEGMENT_PAYLOAD_OFFSET..required],
    )?;
    Ok(required)
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
    let (required, nonce, key, segment_aad) = begin_segment_encryption(
        context,
        keys,
        nonces,
        buffer,
        plaintext_length,
        position,
        kind,
    )?;
    let tag_start = SEGMENT_PAYLOAD_OFFSET + plaintext_length;
    let mut tag = [0u8; AEAD_TAG_LENGTH];
    key.seal(
        &nonce,
        &segment_aad,
        &mut buffer[SEGMENT_PAYLOAD_OFFSET..tag_start],
        &mut tag,
    )?;
    buffer[tag_start..required].copy_from_slice(&tag);
    Ok(required)
}

/// Writes the length prefix and a fresh nonce into the segment's framing
/// bytes and returns the nonce. The payload region is not touched.
#[inline]
fn write_segment_framing(
    nonces: &mut NonceGenerator,
    output: &mut [u8],
    kind: SegmentKind,
    required: usize,
) -> Result<[u8; AEAD_IV_LENGTH]> {
    let prefix = match kind {
        SegmentKind::NonFinal => u32::MAX,
        SegmentKind::Final => u32::try_from(required).map_err(|_| Error::LengthOverflow)?,
    };
    output[..SEGMENT_PREFIX_LENGTH].copy_from_slice(&prefix.to_be_bytes());
    let nonce = nonces.next()?;
    output[SEGMENT_PREFIX_LENGTH..SEGMENT_PAYLOAD_OFFSET].copy_from_slice(&nonce);
    Ok(nonce)
}

#[inline]
fn validate_segment(
    context: &MessageContext,
    ciphertext_segment: &[u8],
    kind: SegmentKind,
) -> Result<usize> {
    let maximum = context.parameters.ciphertext_segment_length();
    match kind {
        SegmentKind::Final => {
            context
                .parameters
                .validate_ciphertext_segment_length(ciphertext_segment.len())?;
        }
        SegmentKind::NonFinal if ciphertext_segment.len() != maximum => {
            return Err(Error::InvalidCiphertextLength {
                actual: ciphertext_segment.len(),
                required: LengthRequirement::Exactly(maximum),
            });
        }
        SegmentKind::NonFinal => {}
    }

    let prefix = u32::from_be_bytes(
        ciphertext_segment[..SEGMENT_PREFIX_LENGTH]
            .try_into()
            .map_err(|_| Error::InvalidSegmentPrefix)?,
    );

    match kind {
        // `prefix` is attacker-controlled, usize might not be 64-bits, so
        // promote everything to u64 for comparison
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
    let tag_start = ciphertext_segment.len() - AEAD_TAG_LENGTH;
    let segment_aad = segment_aad(position, kind);
    let nonce: &[u8; AEAD_IV_LENGTH] = ciphertext_segment
        [SEGMENT_PREFIX_LENGTH..SEGMENT_PAYLOAD_OFFSET]
        .try_into()
        .map_err(|_| Error::CryptoFailure)?;
    let tag: &[u8; AEAD_TAG_LENGTH] = ciphertext_segment[tag_start..]
        .try_into()
        .map_err(|_| Error::CryptoFailure)?;

    key.open(
        nonce,
        &segment_aad,
        &ciphertext_segment[SEGMENT_PAYLOAD_OFFSET..tag_start],
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
    open_segment_in_place(
        context,
        keys,
        ciphertext_segment,
        position,
        kind,
        plaintext_length,
    )
}

/// Opens a segment whose framing has already been validated (or supplied by
/// a decoded [`SegmentFraming`] whose length matched the segment).
#[inline]
fn open_segment_in_place<'a>(
    context: &MessageContext,
    keys: &mut KeyCache,
    ciphertext_segment: &'a mut [u8],
    position: u64,
    kind: SegmentKind,
    plaintext_length: usize,
) -> Result<&'a mut [u8]> {
    let key = keys.key_for_position(context, position)?;
    let (framing, ciphertext_and_tag) = ciphertext_segment.split_at_mut(SEGMENT_PAYLOAD_OFFSET);
    let nonce: &[u8; AEAD_IV_LENGTH] = framing[SEGMENT_PREFIX_LENGTH..]
        .try_into()
        .map_err(|_| Error::CryptoFailure)?;
    let (ciphertext, tag_bytes) = ciphertext_and_tag.split_at_mut(plaintext_length);
    let tag: &[u8; AEAD_TAG_LENGTH] = (&*tag_bytes).try_into().map_err(|_| Error::CryptoFailure)?;

    let segment_aad = segment_aad(position, kind);
    key.open_in_place(nonce, &segment_aad, tag, ciphertext)?;
    Ok(ciphertext)
}

/// Applies an in-place decryption outcome to the buffer's state machine:
/// authenticated plaintext on success, an empty buffer on failure.
fn finish_in_place_decrypt(buffer: &mut SegmentBuffer, result: Result<usize>) -> Result<&mut [u8]> {
    match result {
        Ok(length) => {
            buffer.mark_plaintext(length);
            buffer.plaintext_mut()
        }
        Err(error) => {
            buffer.mark_empty();
            Err(error)
        }
    }
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
        let result = self
            .decrypt_segment_in_place_raw_at(
                &mut buffer.raw_mut()[..ciphertext_length],
                position,
                kind,
            )
            .map(|plaintext| plaintext.len());
        finish_in_place_decrypt(buffer, result)
    }

    /// In-place decryption for a segment whose framing prefix was already
    /// decoded, so the prefix is not parsed and validated a second time.
    pub(crate) fn decrypt_segment_in_place_at_framed<'a>(
        &mut self,
        buffer: &'a mut SegmentBuffer,
        position: u64,
        framing: SegmentFraming,
    ) -> Result<&'a mut [u8]> {
        if !buffer.matches(self.parameters()) {
            return Err(Error::InvalidParameters);
        }
        let ciphertext_length = buffer.ciphertext_length()?;
        let expected = framing.ciphertext_length();
        if ciphertext_length != expected {
            return Err(Error::InvalidCiphertextLength {
                actual: ciphertext_length,
                required: LengthRequirement::Exactly(expected),
            });
        }
        let result = open_segment_in_place(
            &self.context,
            &mut self.keys,
            &mut buffer.raw_mut()[..ciphertext_length],
            position,
            framing.kind(),
            framing.plaintext_length(),
        )
        .map(|plaintext| plaintext.len());
        finish_in_place_decrypt(buffer, result)
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

    /// Allocating decryption for a segment whose framing prefix was already
    /// decoded, so the prefix is not parsed and validated a second time.
    pub(crate) fn decrypt_segment_at_framed(
        &mut self,
        ciphertext_segment: &[u8],
        position: u64,
        framing: SegmentFraming,
    ) -> Result<Vec<u8>> {
        let mut output = vec![0u8; framing.plaintext_length()];
        self.decrypt_segment_into_at_framed(ciphertext_segment, position, framing, &mut output)?;
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
    let mut header_tag = derive_header_tag(provider, key, &encoded, &floe_iv, aad)?;
    let message_key = derive_message_key(provider, key, &encoded, &floe_iv, aad)?;

    let header = Header::from_fields(&encoded, &floe_iv, &header_tag);
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
        header,
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
    let encoded = parameters.encode();

    if header.encoded_parameters() != &encoded {
        return Err(Error::InvalidHeaderParameters);
    }

    let floe_iv = *header.floe_iv();

    let mut expected_tag = derive_header_tag(provider, key, &encoded, &floe_iv, aad)?;
    let tag_matches: bool = expected_tag.as_slice().ct_eq(header.tag()).into();
    expected_tag.zeroize();

    if !tag_matches {
        return Err(Error::InvalidHeaderTag);
    }

    let message_key = derive_message_key(provider, key, &encoded, &floe_iv, aad)?;
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

fn derive_header_tag(
    provider: Provider,
    key: &Key,
    encoded: &[u8; ENCODED_PARAMETERS_LENGTH],
    floe_iv: &[u8; FLOE_IV_LENGTH],
    aad: &[u8],
) -> Result<[u8; HEADER_TAG_LENGTH]> {
    let info: [&[u8]; 4] = [encoded, floe_iv, HEADER_TAG_PURPOSE, aad];
    provider.kdf_expand::<HEADER_TAG_LENGTH>(key.as_bytes(), &info)
}

fn derive_message_key(
    provider: Provider,
    key: &Key,
    encoded: &[u8; ENCODED_PARAMETERS_LENGTH],
    floe_iv: &[u8; FLOE_IV_LENGTH],
    aad: &[u8],
) -> Result<SecretBytes<48>> {
    let info: [&[u8]; 4] = [encoded, floe_iv, MESSAGE_KEY_PURPOSE, aad];
    Ok(SecretBytes(
        provider.kdf_expand::<48>(key.as_bytes(), &info)?,
    ))
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rayon::prelude::*;

    use super::*;
    use crate::key::test_key;
    use crate::{decrypt, encrypt};

    #[test]
    fn inferred_decryption_uses_header_declared_parameters() {
        // Given a ciphertext whose header declares 1 MiB segments
        let plaintext = b"header-selected parameters";
        let ciphertext = encrypt(
            &test_key(),
            b"header inference",
            Parameters::SEGMENT_1_MIB,
            plaintext,
        )
        .unwrap();

        // When the header is parsed from the ciphertext prefix
        let header = Header::try_from(&ciphertext[..Header::LEN]).unwrap();

        // Then the typed header has the specified length and exposes the
        // declared parameters before authentication
        assert_eq!(Header::LEN, HEADER_LENGTH);
        assert_eq!(
            header.unverified_parameters().unwrap(),
            Parameters::SEGMENT_1_MIB
        );

        // Then inferred decryption adopts those parameters and the message
        // decrypts
        assert_eq!(
            start_decryption_inferred(&test_key(), b"header inference", &header)
                .unwrap()
                .parameters(),
            Parameters::SEGMENT_1_MIB
        );
        assert_eq!(
            decrypt(&test_key(), b"header inference", &ciphertext).unwrap(),
            plaintext
        );
    }

    #[test]
    fn tampered_header_parameters_fail_header_authentication() {
        // Given a valid ciphertext whose encoded parameters are overwritten
        // with a different, individually valid parameter set
        let ciphertext = encrypt(
            &test_key(),
            b"header inference",
            Parameters::SEGMENT_1_MIB,
            b"header-selected parameters",
        )
        .unwrap();
        let mut changed_parameters = ciphertext.clone();
        changed_parameters[..ENCODED_PARAMETERS_LENGTH]
            .copy_from_slice(&Parameters::SEGMENT_4_KIB.encode());

        // When the tampered header is parsed
        let changed_header = Header::try_from(&changed_parameters[..Header::LEN]).unwrap();

        // Then the unauthenticated view reports the tampered parameters,
        // but decryption rejects the header tag
        assert_eq!(
            changed_header.unverified_parameters().unwrap(),
            Parameters::SEGMENT_4_KIB
        );
        assert_eq!(
            decrypt(&test_key(), b"header inference", &changed_parameters),
            Err(Error::InvalidHeaderTag)
        );
    }

    #[test]
    fn unsupported_header_parameters_rejected_before_authentication() {
        // Given a header whose parameter encoding declares an unsupported
        // profile
        let (_, header) =
            start_encryption(&test_key(), b"header inference", Parameters::SEGMENT_1_MIB).unwrap();
        let mut unsupported = <[u8; Header::LEN]>::from(header);
        unsupported[0] = 1;
        let unsupported = Header::from(unsupported);

        // When the parameters are decoded or inferred decryption starts
        // Then both reject the encoded parameters
        assert_eq!(
            unsupported.unverified_parameters(),
            Err(Error::InvalidHeaderParameters)
        );
        assert!(matches!(
            start_decryption_inferred(&test_key(), b"header inference", &unsupported),
            Err(Error::InvalidHeaderParameters)
        ));
    }

    #[test]
    fn final_segment_prefix_must_equal_actual_segment_length() {
        // This drives `decrypt_segment_at` directly because
        // `SegmentFraming::decode` would reject the prefix before
        // `validate_segment` is exercised on the online path.

        // Given a valid final segment whose length prefix is forged to
        // declare an extra high bit
        let parameters = Parameters::SEGMENT_4_KIB;
        let (mut encryption, header) =
            start_encryption(&test_key(), b"forged final prefix", parameters).unwrap();
        let layout = parameters.plaintext_layout(4).unwrap();
        let mut segment = encryption
            .encrypt_segment(b"last", layout.final_segment())
            .unwrap();
        let true_length = u32::try_from(segment.len()).unwrap();
        let forged = true_length | 0x0001_0000;
        segment[..SEGMENT_PREFIX_LENGTH].copy_from_slice(&forged.to_be_bytes());

        // When the segment is decrypted at its position
        let mut decryption =
            start_decryption(&test_key(), b"forged final prefix", parameters, &header).unwrap();
        let error = decryption
            .decrypt_segment_at(&segment, 0, SegmentKind::Final)
            .unwrap_err();

        // Then the mismatch between declared and actual length is rejected
        assert!(matches!(
            error,
            Error::InvalidCiphertextLength {
                actual,
                required: LengthRequirement::Exactly(required),
            } if actual == segment.len() && required == segment.len() + 0x1_0000
        ));
    }

    #[test]
    fn random_access_segments_decrypt_out_of_order() {
        // Given a two-segment message encrypted segment by segment
        let parameters = Parameters::SEGMENT_4_KIB;
        let full = vec![0x5a; parameters.plaintext_segment_length()];
        let final_plaintext = b"final";
        let layout = parameters
            .plaintext_layout(u64::try_from(full.len() + final_plaintext.len()).unwrap())
            .unwrap();
        let segment_zero_layout = layout.segment_for_position(0).unwrap();
        let segment_one_layout = layout.segment_for_position(1).unwrap();
        let (mut encryption, header) =
            start_encryption(&test_key(), b"random access", parameters).unwrap();
        let segment_zero = encryption
            .encrypt_segment(&full, segment_zero_layout)
            .unwrap();
        let segment_one = encryption
            .encrypt_segment(final_plaintext, segment_one_layout)
            .unwrap();

        // When the segments are decrypted in reverse order
        let mut decryption =
            start_decryption(&test_key(), b"random access", parameters, &header).unwrap();

        // Then each decrypts independently of processing order
        assert_eq!(
            decryption
                .decrypt_segment(&segment_one, segment_one_layout)
                .unwrap(),
            final_plaintext
        );
        assert_eq!(
            decryption
                .decrypt_segment(&segment_zero, segment_zero_layout)
                .unwrap(),
            full
        );
    }

    #[test]
    fn states_and_shared_contexts_cross_thread_boundaries() {
        // Given the parallel-processing state and context types
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        // Then states move between threads and shared contexts are also
        // safe to reference concurrently
        assert_send::<EncryptionState>();
        assert_send::<DecryptionState>();
        assert_send::<SharedEncryptionContext>();
        assert_sync::<SharedEncryptionContext>();
        assert_send::<SharedDecryptionContext>();
        assert_sync::<SharedDecryptionContext>();
    }

    #[test]
    fn parallel_contexts_create_independent_states() {
        // Given an eight-segment message split across a thread pool
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment_length = parameters.plaintext_segment_length();
        let plaintext_segments: Vec<Vec<u8>> = (0..8)
            .map(|position| {
                let length = if position == 7 { 17 } else { segment_length };
                vec![u8::try_from(position).unwrap(); length]
            })
            .collect();
        let layout = parameters
            .plaintext_layout(
                plaintext_segments
                    .iter()
                    .map(|segment| u64::try_from(segment.len()).unwrap())
                    .sum(),
            )
            .unwrap();

        // When every segment is encrypted on its own forked state
        let (encryption, header) =
            start_encryption(&test_key(), b"parallel states", parameters).unwrap();
        let encryption = encryption.into_shared();
        assert_eq!(encryption.parameters(), parameters);
        let encrypted_segments: Vec<Vec<u8>> = plaintext_segments
            .par_iter()
            .enumerate()
            .map_init(
                || encryption.fork(),
                |state, (position, plaintext)| {
                    assert_eq!(state.parameters(), parameters);
                    let segment = layout
                        .segment_for_position(u64::try_from(position).unwrap())
                        .unwrap();
                    state.encrypt_segment(plaintext, segment)
                },
            )
            .collect::<crate::Result<_>>()
            .unwrap();

        // When every encrypted segment is decrypted on its own forked state
        let decryption =
            start_decryption(&test_key(), b"parallel states", parameters, &header).unwrap();
        let decryption = decryption.into_shared();
        assert_eq!(decryption.parameters(), parameters);
        let decrypted_segments: Vec<Vec<u8>> = encrypted_segments
            .par_iter()
            .enumerate()
            .map_init(
                || decryption.fork(),
                |state, (position, encrypted)| {
                    assert_eq!(state.parameters(), parameters);
                    let segment = layout
                        .segment_for_position(u64::try_from(position).unwrap())
                        .unwrap();
                    state.decrypt_segment(encrypted, segment)
                },
            )
            .collect::<crate::Result<_>>()
            .unwrap();

        // Then the reassembled plaintext matches the original
        assert_eq!(decrypted_segments, plaintext_segments);
    }

    #[test]
    fn rotation_and_position_boundaries_match_specification() {
        const ROTATION_INTERVAL: u64 = 1 << 20;

        // Given segments encrypted on both sides of a key-rotation boundary
        // and at the last permitted position
        let parameters = Parameters::SEGMENT_4_KIB;
        let (mut encryption, header) =
            start_encryption(&test_key(), b"position boundaries", parameters).unwrap();
        let before_rotation = encryption
            .encrypt_segment_at(b"before", ROTATION_INTERVAL - 1, SegmentKind::Final)
            .unwrap();
        let after_rotation = encryption
            .encrypt_segment_at(b"after", ROTATION_INTERVAL, SegmentKind::Final)
            .unwrap();
        let last_position = encryption
            .encrypt_segment_at(b"last", AEAD_MAX_SEGMENTS - 1, SegmentKind::Final)
            .unwrap();

        // Then encryption past the segment limit is rejected
        assert_eq!(
            encryption.encrypt_segment_at(b"past", AEAD_MAX_SEGMENTS, SegmentKind::Final),
            Err(Error::SegmentLimit)
        );

        // When each boundary segment is decrypted at its position
        let mut decryption =
            start_decryption(&test_key(), b"position boundaries", parameters, &header).unwrap();

        // Then each round-trips across the rotation and limit boundaries,
        // and decryption past the segment limit is rejected
        assert_eq!(
            decryption
                .decrypt_segment_at(&before_rotation, ROTATION_INTERVAL - 1, SegmentKind::Final,)
                .unwrap(),
            b"before"
        );
        assert_eq!(
            decryption
                .decrypt_segment_at(&after_rotation, ROTATION_INTERVAL, SegmentKind::Final)
                .unwrap(),
            b"after"
        );
        assert_eq!(
            decryption
                .decrypt_segment_at(&last_position, AEAD_MAX_SEGMENTS - 1, SegmentKind::Final,)
                .unwrap(),
            b"last"
        );
        assert_eq!(
            decryption.decrypt_segment_at(&last_position, AEAD_MAX_SEGMENTS, SegmentKind::Final,),
            Err(Error::SegmentLimit)
        );
    }

    #[test]
    fn batched_nonces_remain_unique_across_refills() {
        // Given more segments than one 64-nonce batch covers
        let parameters = Parameters::SEGMENT_4_KIB;
        let plaintext = vec![0x5a; parameters.plaintext_segment_length()];
        let mut encrypted = vec![0u8; parameters.ciphertext_segment_length()];
        let (mut encryption, _) =
            start_encryption(&test_key(), b"nonce batches", parameters).unwrap();
        let mut nonces = HashSet::new();

        let positions = u64::try_from(2 * NONCE_BATCH_SIZE + 2).unwrap();
        for position in 0..positions {
            // When each segment is encrypted
            encryption
                .encrypt_segment_into_at(
                    &plaintext,
                    position,
                    SegmentKind::NonFinal,
                    &mut encrypted,
                )
                .unwrap();

            // Then the nonce embedded in the segment has never been used
            let nonce: [u8; AEAD_IV_LENGTH] = encrypted
                [SEGMENT_PREFIX_LENGTH..SEGMENT_PREFIX_LENGTH + AEAD_IV_LENGTH]
                .try_into()
                .unwrap();
            assert!(
                nonces.insert(nonce),
                "nonce repeated at position {position}"
            );
        }
    }

    #[test]
    fn segment_layouts_from_other_parameter_sets_rejected() {
        // Given an encryption state and a segment layout calculated with a
        // different parameter set
        let parameters = Parameters::SEGMENT_4_KIB;
        let (mut encryption, _) = start_encryption(&test_key(), b"", parameters).unwrap();
        let wrong_profile_segment = Parameters::SEGMENT_1_MIB
            .plaintext_layout(3)
            .unwrap()
            .segment_for_position(0)
            .unwrap();

        // When a segment is encrypted with the mismatched layout
        // Then the layout is rejected
        assert_eq!(
            encryption.encrypt_segment(b"abc", wrong_profile_segment),
            Err(Error::InvalidParameters)
        );
    }

    #[test]
    fn plaintext_length_must_match_segment_layout() {
        // Given a segment layout describing exactly three plaintext bytes
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment = parameters
            .plaintext_layout(3)
            .unwrap()
            .segment_for_position(0)
            .unwrap();
        let (mut encryption, _) = start_encryption(&test_key(), b"", parameters).unwrap();

        // When two bytes are encrypted against it
        // Then the length mismatch is rejected
        assert_eq!(
            encryption.encrypt_segment(b"ab", segment),
            Err(Error::InvalidPlaintextLength {
                actual: 2,
                required: LengthRequirement::Exactly(3),
            })
        );
    }

    #[test]
    fn undersized_output_buffers_rejected_before_encryption() {
        // Given an output buffer one byte smaller than the segment needs
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment = parameters
            .plaintext_layout(3)
            .unwrap()
            .segment_for_position(0)
            .unwrap();
        let (mut encryption, _) = start_encryption(&test_key(), b"", parameters).unwrap();
        let mut too_small = [0u8; SEGMENT_OVERHEAD + 2];

        // When the segment is encrypted into it
        // Then the buffer is rejected
        assert!(matches!(
            encryption.encrypt_segment_into(
                b"abc",
                segment,
                &mut too_small[..SEGMENT_OVERHEAD + 2]
            ),
            Err(Error::OutputTooSmall { .. })
        ));
    }

    #[test]
    fn into_apis_write_exact_segment_lengths() {
        // Given exactly sized caller-provided buffers on both sides
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment = parameters
            .plaintext_layout(3)
            .unwrap()
            .segment_for_position(0)
            .unwrap();
        let (mut encryption, header) = start_encryption(&test_key(), b"", parameters).unwrap();

        // When the segment is encrypted and decrypted through the into APIs
        let mut encrypted = [0u8; SEGMENT_OVERHEAD + 3];
        let encrypted_length = encryption
            .encrypt_segment_into(b"abc", segment, &mut encrypted)
            .unwrap();

        // Then each call writes exactly the declared length and the
        // plaintext round-trips
        assert_eq!(encrypted_length, SEGMENT_OVERHEAD + 3);
        let mut decryption = start_decryption(&test_key(), b"", parameters, &header).unwrap();
        let mut plaintext = [0u8; 3];
        assert_eq!(
            decryption
                .decrypt_segment_into(&encrypted[..encrypted_length], segment, &mut plaintext,)
                .unwrap(),
            3
        );
        assert_eq!(&plaintext, b"abc");
    }

    #[test]
    fn segment_buffers_round_trip_in_place() {
        // Given plaintext prepared in a reusable segment buffer
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment = parameters
            .plaintext_layout(3)
            .unwrap()
            .segment_for_position(0)
            .unwrap();
        let (mut encryption, header) = start_encryption(&test_key(), b"", parameters).unwrap();
        let mut in_place = SegmentBuffer::new(parameters);
        in_place
            .prepare_plaintext(3)
            .unwrap()
            .copy_from_slice(b"abc");

        // When the buffer is encrypted and decrypted in place
        assert_eq!(
            encryption
                .encrypt_segment_in_place(&mut in_place, segment)
                .unwrap()
                .len(),
            SEGMENT_OVERHEAD + 3
        );
        let mut decryption = start_decryption(&test_key(), b"", parameters, &header).unwrap();

        // Then the original plaintext is recovered without copying
        assert_eq!(
            decryption
                .decrypt_segment_in_place(&mut in_place, segment)
                .unwrap(),
            b"abc"
        );
    }

    #[test]
    fn in_place_decryption_rejects_tampered_ciphertext() {
        // Given an in-place encrypted segment whose last byte is flipped
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment = parameters
            .plaintext_layout(3)
            .unwrap()
            .segment_for_position(0)
            .unwrap();
        let (mut encryption, header) = start_encryption(&test_key(), b"", parameters).unwrap();
        let mut in_place = SegmentBuffer::new(parameters);
        in_place
            .prepare_plaintext(3)
            .unwrap()
            .copy_from_slice(b"abc");
        encryption
            .encrypt_segment_in_place(&mut in_place, segment)
            .unwrap();

        let mut tampered = SegmentBuffer::new(parameters);
        tampered
            .prepare_ciphertext(SEGMENT_OVERHEAD + 3)
            .unwrap()
            .copy_from_slice(in_place.ciphertext().unwrap());
        *tampered
            .prepare_ciphertext(SEGMENT_OVERHEAD + 3)
            .unwrap()
            .last_mut()
            .unwrap() ^= 1;

        // When the tampered buffer is decrypted in place
        // Then authentication fails
        let mut decryption = start_decryption(&test_key(), b"", parameters, &header).unwrap();
        assert_eq!(
            decryption.decrypt_segment_in_place(&mut tampered, segment),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn segment_position_is_authenticated() {
        // Given a segment encrypted at position five
        let parameters = Parameters::SEGMENT_4_KIB;
        let (mut encryption, header) = start_encryption(&test_key(), b"", parameters).unwrap();
        let segment_bytes = encryption
            .encrypt_segment_at(b"data", 5, SegmentKind::Final)
            .unwrap();

        // When it is decrypted at position six
        // Then authentication fails
        let mut decryption = start_decryption(&test_key(), b"", parameters, &header).unwrap();
        assert_eq!(
            decryption.decrypt_segment_at(&segment_bytes, 6, SegmentKind::Final),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn final_indicator_is_authenticated() {
        // Given a final segment reframed with a non-final prefix and padded
        // to the full segment length
        let parameters = Parameters::SEGMENT_4_KIB;
        let (mut encryption, header) = start_encryption(&test_key(), b"", parameters).unwrap();
        let segment_bytes = encryption
            .encrypt_segment_at(b"data", 5, SegmentKind::Final)
            .unwrap();
        let mut forged_non_final = vec![0u8; parameters.ciphertext_segment_length()];
        forged_non_final[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        forged_non_final[4..4 + segment_bytes.len() - 4].copy_from_slice(&segment_bytes[4..]);

        // When it is decrypted as a non-final segment at its true position
        // Then authentication fails
        let mut decryption = start_decryption(&test_key(), b"", parameters, &header).unwrap();
        assert_eq!(
            decryption.decrypt_segment_at(&forged_non_final, 5, SegmentKind::NonFinal),
            Err(Error::AuthenticationFailed)
        );
    }

    /// Encrypts `payload` as a raw in-place segment at position zero of a
    /// message with `trailing_plaintext` further bytes (non-final when more
    /// follows, final otherwise), returning the exactly sized encrypted
    /// storage, the segment layout, and a decryption state for the message.
    fn raw_encrypted_segment(
        payload: &[u8],
        trailing_plaintext: u64,
    ) -> (Vec<u8>, SegmentLayout, DecryptionState) {
        let parameters = Parameters::SEGMENT_4_KIB;
        let total = length_usize_to_u64(payload.len()) + trailing_plaintext;
        let segment = parameters
            .plaintext_layout(total)
            .unwrap()
            .segment_for_position(0)
            .unwrap();
        assert_eq!(segment.plaintext_length(), payload.len());
        let (mut encryption, header) = start_encryption(&test_key(), b"raw", parameters).unwrap();
        let mut storage = vec![0u8; segment.ciphertext_length()];
        storage[SEGMENT_PAYLOAD_OFFSET..SEGMENT_PAYLOAD_OFFSET + payload.len()]
            .copy_from_slice(payload);
        let written = encryption
            .encrypt_segment_in_place_raw(&mut storage, segment)
            .unwrap();
        assert_eq!(written, segment.ciphertext_length());
        let decryption = start_decryption(&test_key(), b"raw", parameters, &header).unwrap();
        (storage, segment, decryption)
    }

    #[test]
    fn raw_in_place_final_segment_round_trips() {
        // Given a raw-encrypted final segment in exactly sized storage
        let (mut storage, segment, mut decryption) = raw_encrypted_segment(b"hello", 0);

        // Then the final prefix encodes the exact segment length
        let prefix = u32::from_be_bytes(storage[..SEGMENT_PREFIX_LENGTH].try_into().unwrap());
        assert_eq!(prefix, u32::try_from(storage.len()).unwrap());

        // When the same storage is decrypted in place
        // Then the original plaintext is recovered
        let plaintext = decryption
            .decrypt_segment_in_place_raw(&mut storage, segment)
            .unwrap();
        assert_eq!(&plaintext[..], b"hello");
    }

    #[test]
    fn raw_in_place_non_final_segment_round_trips() {
        // Given a raw-encrypted full non-final segment
        let parameters = Parameters::SEGMENT_4_KIB;
        let full = vec![0x5a; parameters.plaintext_segment_length()];
        let (mut storage, segment, mut decryption) = raw_encrypted_segment(&full, 5);

        // Then the storage spans one full segment with the non-final prefix
        assert_eq!(storage.len(), parameters.ciphertext_segment_length());
        let prefix = u32::from_be_bytes(storage[..SEGMENT_PREFIX_LENGTH].try_into().unwrap());
        assert_eq!(prefix, u32::MAX);

        // When the same storage is decrypted in place
        // Then the original payload is recovered
        let plaintext = decryption
            .decrypt_segment_in_place_raw(&mut storage, segment)
            .unwrap();
        assert_eq!(&plaintext[..], &full[..]);
    }

    #[test]
    fn raw_in_place_encryption_rejects_short_storage() {
        // Given storage one byte smaller than the encrypted segment needs
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment = parameters.plaintext_layout(5).unwrap().final_segment();
        let required = segment.ciphertext_length();
        let (mut encryption, _header) = start_encryption(&test_key(), b"raw", parameters).unwrap();
        let mut storage = vec![0u8; required - 1];

        // When the segment is encrypted, then the exact shortfall is reported
        assert_eq!(
            encryption.encrypt_segment_in_place_raw(&mut storage, segment),
            Err(Error::OutputTooSmall {
                actual: required - 1,
                required,
            })
        );
    }

    #[test]
    fn raw_in_place_decryption_rejects_short_storage() {
        // Given storage one byte smaller than the segment layout requires
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment = parameters.plaintext_layout(5).unwrap().final_segment();
        let required = segment.ciphertext_length();
        let (_, header) = start_encryption(&test_key(), b"raw", parameters).unwrap();
        let mut decryption = start_decryption(&test_key(), b"raw", parameters, &header).unwrap();
        let mut storage = vec![0u8; required - 1];

        // When the segment is decrypted, then the requirement is reported
        assert!(matches!(
            decryption.decrypt_segment_in_place_raw(&mut storage, segment),
            Err(Error::InvalidCiphertextLength {
                actual,
                required: LengthRequirement::AtLeast(at_least),
            }) if actual == required - 1 && at_least == required
        ));
    }

    #[test]
    fn raw_in_place_apis_reject_layout_from_another_parameter_set() {
        // Given a layout computed for a different parameter set
        let parameters = Parameters::SEGMENT_4_KIB;
        let foreign = Parameters::SEGMENT_1_MIB
            .plaintext_layout(5)
            .unwrap()
            .final_segment();
        let (mut encryption, header) = start_encryption(&test_key(), b"raw", parameters).unwrap();
        let mut decryption = start_decryption(&test_key(), b"raw", parameters, &header).unwrap();
        let mut storage = vec![0u8; foreign.ciphertext_length()];

        // When either raw in-place entry point receives the foreign layout
        // Then it is rejected before any storage access
        assert_eq!(
            encryption.encrypt_segment_in_place_raw(&mut storage, foreign),
            Err(Error::InvalidParameters)
        );
        assert!(matches!(
            decryption.decrypt_segment_in_place_raw(&mut storage, foreign),
            Err(Error::InvalidParameters)
        ));
    }

    #[test]
    fn raw_in_place_decryption_rejects_forged_final_prefix() {
        // Given a valid raw-encrypted final segment
        let (mut storage, segment, mut decryption) = raw_encrypted_segment(b"hello", 0);

        // When the final length prefix disagrees with the actual length
        // Then the framing mismatch is rejected with both lengths
        let mut forged = storage.clone();
        let declared = u32::try_from(segment.ciphertext_length()).unwrap() + 1;
        forged[..SEGMENT_PREFIX_LENGTH].copy_from_slice(&declared.to_be_bytes());
        assert!(matches!(
            decryption.decrypt_segment_in_place_raw(&mut forged, segment),
            Err(Error::InvalidCiphertextLength {
                actual,
                required: LengthRequirement::Exactly(required),
            }) if actual == segment.ciphertext_length()
                && required == segment.ciphertext_length() + 1
        ));

        // Then the untouched segment still decrypts afterward
        assert_eq!(
            &decryption
                .decrypt_segment_in_place_raw(&mut storage, segment)
                .unwrap()[..],
            b"hello"
        );
    }

    #[test]
    fn raw_in_place_non_final_decryption_rejects_corrupt_prefix() {
        // Given a raw-encrypted non-final segment whose prefix is zeroed
        let full = vec![0x5a; Parameters::SEGMENT_4_KIB.plaintext_segment_length()];
        let (mut storage, segment, mut decryption) = raw_encrypted_segment(&full, 5);
        storage[..SEGMENT_PREFIX_LENGTH].fill(0);

        // When the corrupted segment is decrypted in place
        // Then the non-final prefix is rejected as framing, not as content
        assert!(matches!(
            decryption.decrypt_segment_in_place_raw(&mut storage, segment),
            Err(Error::InvalidSegmentPrefix)
        ));
    }

    #[test]
    fn in_place_wrappers_reject_buffers_from_another_parameter_set() {
        // Given a segment buffer built for a different parameter set
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment = parameters.plaintext_layout(3).unwrap().final_segment();
        let (mut encryption, header) = start_encryption(&test_key(), b"raw", parameters).unwrap();
        let mut decryption = start_decryption(&test_key(), b"raw", parameters, &header).unwrap();
        let mut foreign = SegmentBuffer::new(Parameters::SEGMENT_64_B);

        // When the foreign buffer holds plaintext for encryption
        // Then the parameter mismatch is rejected
        foreign
            .prepare_plaintext(3)
            .unwrap()
            .copy_from_slice(b"abc");
        assert_eq!(
            encryption.encrypt_segment_in_place(&mut foreign, segment),
            Err(Error::InvalidParameters)
        );

        // When the foreign buffer holds ciphertext for decryption
        // Then the parameter mismatch is rejected the same way
        foreign.prepare_ciphertext(SEGMENT_OVERHEAD + 3).unwrap();
        assert!(matches!(
            decryption.decrypt_segment_in_place(&mut foreign, segment),
            Err(Error::InvalidParameters)
        ));
    }

    #[test]
    fn in_place_decryption_rejects_prepared_length_disagreeing_with_layout() {
        // Given prepared ciphertext one byte longer than the layout declares
        let parameters = Parameters::SEGMENT_4_KIB;
        let segment = parameters.plaintext_layout(3).unwrap().final_segment();
        let (_, header) = start_encryption(&test_key(), b"raw", parameters).unwrap();
        let mut decryption = start_decryption(&test_key(), b"raw", parameters, &header).unwrap();
        let mut buffer = SegmentBuffer::new(parameters);
        buffer.prepare_ciphertext(SEGMENT_OVERHEAD + 4).unwrap();

        // When the buffer is decrypted against the shorter layout
        // Then the exact length disagreement is reported
        assert!(matches!(
            decryption.decrypt_segment_in_place(&mut buffer, segment),
            Err(Error::InvalidCiphertextLength {
                actual,
                required: LengthRequirement::Exactly(required),
            }) if actual == SEGMENT_OVERHEAD + 4 && required == SEGMENT_OVERHEAD + 3
        ));
    }
}
