use std::io::{self, Read};

use crate::{Error, Header, LengthRequirement, Result};

pub(crate) fn split_header(ciphertext: &[u8]) -> Result<(Header, &[u8])> {
    let (header, body) =
        ciphertext
            .split_at_checked(Header::LEN)
            .ok_or(Error::InvalidHeaderLength {
                actual: ciphertext.len(),
            })?;
    Ok((Header::try_from(header)?, body))
}

pub(crate) fn read_header(reader: &mut impl Read) -> io::Result<Header> {
    let mut header = [0; Header::LEN];
    let actual = read_fully(reader, &mut header)?;
    if actual == header.len() {
        Ok(Header::from(header))
    } else {
        Err(decryption_error(Error::InvalidHeaderLength { actual }))
    }
}

pub(crate) fn read_exact_segment(reader: &mut impl Read, output: &mut [u8]) -> io::Result<()> {
    let expected = output.len();
    let actual = read_fully(reader, output)?;
    if actual == expected {
        Ok(())
    } else {
        Err(decryption_error(Error::InvalidCiphertextLength {
            actual,
            required: LengthRequirement::Exactly(expected),
        }))
    }
}

pub(crate) fn read_fully(reader: &mut impl Read, mut output: &mut [u8]) -> io::Result<usize> {
    let required = output.len();
    while !output.is_empty() {
        match reader.read(output) {
            Ok(0) => break,
            Ok(read) => output = &mut output[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(required - output.len())
}

pub(crate) fn encryption_error(error: Error) -> io::Error {
    io::Error::other(error)
}

pub(crate) fn decryption_error(error: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

pub(crate) fn length_overflow() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, Error::LengthOverflow)
}

pub(crate) fn output_too_small(actual: usize, required: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        Error::OutputTooSmall { actual, required },
    )
}
