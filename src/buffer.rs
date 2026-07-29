use zeroize::Zeroize;

use crate::{Error, LengthRequirement, Parameters, Result, SEGMENT_PAYLOAD_OFFSET};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BufferState {
    Empty,
    Plaintext { length: usize },
    Ciphertext { length: usize },
}

/// Reusable storage for allocation-free segment encryption and decryption.
///
/// This type owns the framing offset arithmetic required by FLOE. Callers
/// prepare either a plaintext payload or an encrypted segment, pass the buffer
/// to an in-place operation, and then retrieve the authenticated result.
#[derive(Debug)]
pub struct SegmentBuffer {
    parameters: Parameters,
    bytes: Vec<u8>,
    state: BufferState,
}

impl SegmentBuffer {
    /// Allocates one reusable encrypted-segment-sized buffer.
    #[must_use]
    pub fn new(parameters: Parameters) -> Self {
        Self {
            parameters,
            bytes: vec![0u8; parameters.ciphertext_segment_length()],
            state: BufferState::Empty,
        }
    }

    /// Returns this buffer's parameter set.
    #[must_use]
    pub const fn parameters(&self) -> Parameters {
        self.parameters
    }

    /// Returns the complete reusable storage capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.bytes.len()
    }

    /// Prepares a plaintext payload and returns a slice ready for the
    /// caller to write into it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPlaintextLength`] when `length` exceeds one
    /// segment's payload capacity. A non-final operation will additionally
    /// require the exact full payload length.
    pub fn prepare_plaintext(&mut self, length: usize) -> Result<&mut [u8]> {
        let maximum = self.parameters.plaintext_segment_length();

        if length > maximum {
            return Err(Error::InvalidPlaintextLength {
                actual: length,
                required: LengthRequirement::AtMost(maximum),
            });
        }

        self.state = BufferState::Plaintext { length };

        let end = SEGMENT_PAYLOAD_OFFSET + length;
        Ok(&mut self.bytes[SEGMENT_PAYLOAD_OFFSET..end])
    }

    /// Prepares storage for a ciphertext segment of `length` bytes
    /// and returns a slice ready for the caller to write into it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCiphertextLength`] when `length` cannot
    /// represent a segment for this parameter set.
    pub fn prepare_ciphertext(&mut self, length: usize) -> Result<&mut [u8]> {
        self.parameters.validate_ciphertext_segment_length(length)?;
        self.state = BufferState::Ciphertext { length };
        Ok(&mut self.bytes[..length])
    }

    /// Returns a slice positioned at the prepared or authenticated plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBufferState`] unless the buffer currently holds
    /// plaintext.
    pub fn plaintext(&self) -> Result<&[u8]> {
        match self.state {
            BufferState::Plaintext { length } => {
                Ok(&self.bytes[SEGMENT_PAYLOAD_OFFSET..SEGMENT_PAYLOAD_OFFSET + length])
            }
            BufferState::Empty | BufferState::Ciphertext { .. } => Err(Error::InvalidBufferState),
        }
    }

    pub(crate) fn plaintext_mut(&mut self) -> Result<&mut [u8]> {
        match self.state {
            BufferState::Plaintext { length } => {
                Ok(&mut self.bytes[SEGMENT_PAYLOAD_OFFSET..SEGMENT_PAYLOAD_OFFSET + length])
            }
            BufferState::Empty | BufferState::Ciphertext { .. } => Err(Error::InvalidBufferState),
        }
    }

    /// Returns a slice positioned at the prepared or generated ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBufferState`] unless the buffer currently holds
    /// a ciphertext segment.
    pub fn ciphertext(&self) -> Result<&[u8]> {
        match self.state {
            BufferState::Ciphertext { length } => Ok(&self.bytes[..length]),
            BufferState::Empty | BufferState::Plaintext { .. } => Err(Error::InvalidBufferState),
        }
    }

    /// Clears the logical contents and zeroizes the reusable storage.
    pub fn clear(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        self.state = BufferState::Empty;
    }

    pub(crate) const fn plaintext_length(&self) -> Result<usize> {
        match self.state {
            BufferState::Plaintext { length } => Ok(length),
            BufferState::Empty | BufferState::Ciphertext { .. } => Err(Error::InvalidBufferState),
        }
    }

    pub(crate) const fn ciphertext_length(&self) -> Result<usize> {
        match self.state {
            BufferState::Ciphertext { length } => Ok(length),
            BufferState::Empty | BufferState::Plaintext { .. } => Err(Error::InvalidBufferState),
        }
    }

    /// Appends `input` to the buffered plaintext payload and returns how many
    /// bytes were copied, stopping at one segment's payload capacity.
    ///
    /// A buffer holding no plaintext (empty or holding a ciphertext segment)
    /// starts a fresh payload.
    pub(crate) fn extend_plaintext(&mut self, input: &[u8]) -> usize {
        let length = match self.state {
            BufferState::Plaintext { length } => length,
            BufferState::Empty | BufferState::Ciphertext { .. } => 0,
        };
        let capacity = self.parameters.plaintext_segment_length();
        let copied = input.len().min(capacity - length);
        let start = SEGMENT_PAYLOAD_OFFSET + length;
        self.bytes[start..start + copied].copy_from_slice(&input[..copied]);
        self.state = BufferState::Plaintext {
            length: length + copied,
        };
        copied
    }

    /// Shrinks the buffered plaintext payload to its first `length` bytes.
    pub(crate) fn truncate_plaintext(&mut self, length: usize) -> Result<()> {
        let current = self.plaintext_length()?;
        if length > current {
            return Err(Error::InvalidPlaintextLength {
                actual: length,
                required: LengthRequirement::AtMost(current),
            });
        }
        self.state = BufferState::Plaintext { length };
        Ok(())
    }

    pub(crate) fn raw_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub(crate) fn matches(&self, parameters: Parameters) -> bool {
        self.parameters == parameters
    }

    pub(crate) const fn mark_ciphertext(&mut self, length: usize) {
        self.state = BufferState::Ciphertext { length };
    }

    pub(crate) const fn mark_plaintext(&mut self, length: usize) {
        self.state = BufferState::Plaintext { length };
    }

    pub(crate) const fn mark_empty(&mut self) {
        self.state = BufferState::Empty;
    }
}

impl Drop for SegmentBuffer {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SEGMENT_OVERHEAD;

    #[test]
    fn extend_plaintext_appends_and_saturates_at_capacity() {
        // Given an empty reusable buffer
        let parameters = Parameters::SEGMENT_4_KIB;
        let capacity = parameters.plaintext_segment_length();
        let mut buffer = SegmentBuffer::new(parameters);

        // When plaintext arrives in pieces
        assert_eq!(buffer.extend_plaintext(b"abc"), 3);
        assert_eq!(buffer.extend_plaintext(b"de"), 2);

        // Then the payload accumulates in order
        assert_eq!(buffer.plaintext().unwrap(), b"abcde");
        assert_eq!(buffer.plaintext_length().unwrap(), 5);

        // When more input arrives than one segment holds
        let oversized = vec![0x5a; capacity];
        assert_eq!(buffer.extend_plaintext(&oversized), capacity - 5);

        // Then the payload stops exactly at capacity and further appends
        // copy nothing
        assert_eq!(buffer.plaintext_length().unwrap(), capacity);
        assert_eq!(buffer.extend_plaintext(b"x"), 0);
        assert_eq!(buffer.plaintext_length().unwrap(), capacity);
    }

    #[test]
    fn extend_plaintext_starts_fresh_after_ciphertext_or_clear() {
        // Given a buffer holding a prepared ciphertext segment
        let parameters = Parameters::SEGMENT_4_KIB;
        let mut buffer = SegmentBuffer::new(parameters);
        buffer.prepare_ciphertext(SEGMENT_OVERHEAD).unwrap();

        // When plaintext is appended
        // Then a fresh payload replaces the ciphertext state
        assert_eq!(buffer.extend_plaintext(b"fresh"), 5);
        assert_eq!(buffer.plaintext().unwrap(), b"fresh");

        // When the buffer is cleared and appended again
        buffer.clear();
        assert_eq!(buffer.extend_plaintext(b"again"), 5);
        assert_eq!(buffer.plaintext().unwrap(), b"again");
    }

    #[test]
    fn truncate_plaintext_shrinks_but_never_grows() {
        // Given a buffer holding five plaintext bytes
        let parameters = Parameters::SEGMENT_4_KIB;
        let mut buffer = SegmentBuffer::new(parameters);
        buffer.extend_plaintext(b"abcde");

        // When the payload is truncated
        // Then only shrinking is permitted
        buffer.truncate_plaintext(3).unwrap();
        assert_eq!(buffer.plaintext().unwrap(), b"abc");
        assert!(matches!(
            buffer.truncate_plaintext(4),
            Err(Error::InvalidPlaintextLength { .. })
        ));

        // When the buffer holds no plaintext
        // Then truncation reports the invalid state
        buffer.clear();
        assert_eq!(buffer.truncate_plaintext(0), Err(Error::InvalidBufferState));
    }
}
