//! Demonstrates file encryption and decryption using the `std::io` adapters.
//!
//! ```text
//! cargo run --example serial_file --features ring -- \
//!     encrypt INPUT OUTPUT 64_HEX_KEY [4k|1m]
//! cargo run --example serial_file --features ring -- \
//!     decrypt INPUT OUTPUT 64_HEX_KEY [4k|1m]
//! ```

mod common;

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use common::{AAD, AnyResult, Operation, create_output};
use fast_floe::io::{DecryptReader, EncryptReader};
use fast_floe::{Key, Parameters};

fn main() {
    if let Err(error) = run() {
        eprintln!("serial_file: {error}");
        std::process::exit(1);
    }
}

fn run() -> AnyResult<()> {
    let arguments = common::arguments("serial_file")?;
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
    let input = File::open(input_path)?;
    let mut reader = EncryptReader::new(input, key, AAD, parameters)?;
    let mut output = create_output(output_path)?;

    io::copy(&mut reader, &mut output)?;
    output.flush()?;
    Ok(())
}

fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    key: &Key,
    parameters: Parameters,
) -> AnyResult<()> {
    let input = File::open(input_path)?;
    let mut reader = DecryptReader::new(input, key, AAD)?;

    if reader.parameters() != parameters {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "parameters read from ciphertext header don't match provided parameters",
        )
        .into());
    }

    let mut output = create_output(output_path)?;

    io::copy(&mut reader, &mut output)?;
    reader.finish()?;
    output.flush()?;

    Ok(())
}
