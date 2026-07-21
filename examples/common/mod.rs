use std::error::Error;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::{env, io};

use fast_floe::{Key, Parameters};

pub const AAD: &[u8] = b"fast-floe file examples";

pub type AnyError = Box<dyn Error + Send + Sync>;
pub type AnyResult<T> = Result<T, AnyError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

pub struct Arguments {
    pub operation: Operation,
    pub input: PathBuf,
    pub output: PathBuf,
    pub key: Key,
    pub parameters: Parameters,
}

pub fn arguments(default_program: &str) -> AnyResult<Arguments> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from(default_program));
    let operation = required(&mut arguments, &program)?;
    let input = PathBuf::from(required(&mut arguments, &program)?);
    let output = PathBuf::from(required(&mut arguments, &program)?);
    let key = parse_key(&required(&mut arguments, &program)?)?;
    let parameter_name = arguments.next();
    let parameters = parse_parameters(parameter_name.as_ref())?;
    if arguments.next().is_some() || input == output {
        return Err(usage_error(&program));
    }

    let operation = match operation.to_str() {
        Some("e" | "encrypt") => Operation::Encrypt,
        Some("d" | "decrypt") => Operation::Decrypt,
        _ => return Err(usage_error(&program)),
    };
    Ok(Arguments {
        operation,
        input,
        output,
        key,
        parameters,
    })
}

pub fn create_output(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn required(
    arguments: &mut impl Iterator<Item = OsString>,
    program: &OsString,
) -> AnyResult<OsString> {
    arguments.next().ok_or_else(|| usage_error(program))
}

fn parse_key(encoded: &OsString) -> AnyResult<Key> {
    let encoded = encoded
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "key must be UTF-8 hex"))?;
    let decoded = hex::decode(encoded)?;
    Key::try_from(decoded.as_slice()).map_err(Into::into)
}

fn parse_parameters(name: Option<&OsString>) -> AnyResult<Parameters> {
    match name.and_then(|value| value.to_str()) {
        None | Some("1m" | "1M") => Ok(Parameters::SEGMENT_1_MIB),
        Some("4k" | "4K") => Ok(Parameters::SEGMENT_4_KIB),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "segment size must be either 4k or 1m",
        )
        .into()),
    }
}

fn usage_error(program: &OsString) -> AnyError {
    let program = Path::new(program)
        .file_name()
        .unwrap_or(program.as_os_str())
        .to_string_lossy();
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("usage: {program} <encrypt|decrypt> <input> <output> <64-hex-key> [4k|1m]"),
    )
    .into()
}
