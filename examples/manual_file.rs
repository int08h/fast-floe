//! Demonstrates segment-oriented file encryption and decryption using the iterator
//! returned by `MessageLayout::segments`.
//!
//! ```text
//! cargo run --example manual_file --features ring -- \
//!     encrypt INPUT OUTPUT 64_HEX_KEY [4k|1m]
//! cargo run --example manual_file --features ring -- \
//!     decrypt INPUT OUTPUT 64_HEX_KEY [4k|1m]
//! ```

mod common;

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use common::{AAD, AnyResult, Operation, create_output};
use fast_floe::low_level::{SegmentBuffer, start_decryption, start_encryption};
use fast_floe::{Header, Key, Parameters};

fn main() {
    if let Err(error) = run() {
        eprintln!("manual_file: {error}");
        std::process::exit(1);
    }
}

fn run() -> AnyResult<()> {
    let arguments = common::arguments("manual_file")?;
    match arguments.operation {
        Operation::Encrypt => encrypt_file(
            &arguments.input,
            &arguments.output,
            &arguments.key,
            arguments.parameters,
        ),
        Operation::Decrypt => decrypt_file(
            &arguments.input,
            &arguments.output,
            &arguments.key,
            arguments.parameters,
        ),
    }
}

fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    key: &Key,
    parameters: Parameters,
) -> AnyResult<()> {
    let (mut encryption, header) = start_encryption(key, AAD, parameters)?;

    let mut input = File::open(input_path)?;
    let in_size = input.metadata()?.len();
    let mut output = create_output(output_path)?;
    output.write_all(header.as_ref())?;

    let layout = parameters.plaintext_layout(in_size)?;
    let mut buffer = SegmentBuffer::new(parameters);

    for segment in layout {
        let dest = buffer.prepare_plaintext(segment.plaintext_length())?;
        input.read_exact(dest)?;
        let encrypted = encryption.encrypt_segment_in_place(&mut buffer, segment)?;
        output.write_all(encrypted)?;
    }

    Ok(())
}

fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    key: &Key,
    parameters: Parameters,
) -> AnyResult<()> {
    let mut input = File::open(input_path)?;
    let in_size = input.metadata()?.len();
    let mut output = create_output(output_path)?;

    let mut header_bytes = [0u8; Header::LEN];
    input.read_exact(&mut header_bytes)?;
    let header = Header::from(header_bytes);

    let mut decryption = start_decryption(key, AAD, parameters, &header)?;

    let layout = parameters.ciphertext_layout(in_size)?;
    let mut buffer = SegmentBuffer::new(parameters);

    for segment in layout {
        let dest = buffer.prepare_ciphertext(segment.ciphertext_length())?;
        input.read_exact(dest)?;
        let plaintext = decryption.decrypt_segment_in_place(&mut buffer, segment)?;
        output.write_all(plaintext)?;
    }

    Ok(())
}
