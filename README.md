# fast-floe

An optimized, spec-compliant Rust implementation of Fast Lightweight Online
Encryption (FLOE): authenticated encryption for large files and byte streams,
with bounded memory, random access and a choice of four cryptography
providers.

## Introduction

`fast-floe` implements the [Fast Lightweight Online Encryption (FLOE)
specification](https://c2sp.org/FLOE) in Rust. FLOE splits a message into
segments of a length the caller chooses, then encrypts and authenticates each
segment independently. A recipient can decrypt a large message one segment at
a time, or seek directly to any part of the ciphertext.

That design suits data too large to hold in memory, streams of unknown
length, segments that arrive out of order and random access into encrypted
data.

The segment length, chosen at encryption time, trades throughput against
random-access cost: smaller segments make random access cheaper; larger
segments raise throughput.

The crate supports four cryptography providers: aws-lc-rs, boring, ring and
`RustCrypto`. All four produce the same wire format and interoperate freely.

## Quick start

Add `fast-floe` from [crates.io](https://crates.io/crates/fast-floe) to
`Cargo.toml`. In Rust code the crate is named `fast_floe`.

```toml
[dependencies]
fast-floe = "0.3"
```

The default cryptographic provider is aws-lc-rs; the "_Cryptographic
providers_" section explains how to pick another.

```rust
use fast_floe::{Key, Parameters, decrypt, encrypt};

# fn main() -> Result<(), fast_floe::Error> {
let key = Key::generate()?;
let aad = b"tenant=acme;object=backup";
let plaintext = b"data to protect";
let params = Parameters::from_segment_length(1_000_000)?;

let ciphertext = encrypt(
    &key,
    aad,
    params,
    plaintext,
)?;

let recovered = decrypt(&key, aad, &ciphertext)?;
assert_eq!(recovered, plaintext);
# Ok(())
# }
```

`encrypt` returns one complete FLOE message: an authenticated header followed
by encrypted segments. `decrypt` authenticates the message before returning
its plaintext.

The three inputs are:

- `Key`: a 32-byte secret. `Key::generate` creates a random key;
  `Key::from_bytes` imports existing key material.
- `AAD`: context that is authenticated with the ciphertext, such as a session
  ID or protocol version. FLOE does not store the AAD, so decryption must
  supply the same bytes.
- `Parameters`: the encrypted segment length. FLOE accepts any length from 64
  to 4,294,967,294 (`u32::MAX` - 1) bytes.

## Choose an API

The APIs below run from simplest to most powerful. Use the highest layer that
fits:

| Need                                         | API                        | Input                     |
|----------------------------------------------|----------------------------|---------------------------|
| Encrypt or decrypt bytes already in memory   | `encrypt`, `decrypt`       | One-shot complete message |
| Process a file, socket, or `std::io` adapter | `fast_floe::io`            | `Read` or `Write`         |
| Read selected authenticated ranges           | `fast_floe::random_access` | `Read + Seek` ciphertext  |
| Exchange segments strictly in order          | `fast_floe::online`        | Streaming data            |
| Process segments manually, in parallel, or out of order | `fast_floe::low_level` | Experts needing control |

### Whole messages

Use the quick-start `encrypt` and `decrypt` functions when the whole input
and output fit in memory. Both return a new `Vec<u8>`.

`decrypt` takes the profile (segment length) from the authenticated header.
To choose the profile yourself, use `decrypt_with_parameters`.

### Streams with `std::io`

`EncryptReader` and `DecryptReader` keep memory bounded. They connect with the
standard Rust I/O traits:

```rust
use std::io::{self, Cursor};

use fast_floe::io::{DecryptReader, EncryptReader};
use fast_floe::{Key, Parameters};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let key = Key::from_bytes([0x42; Key::LEN]);
let aad = b"file metadata";
let params = Parameters::from_segment_length(4096)?;

let input = Cursor::new(b"a potentially large input".as_slice());
let mut encrypting = EncryptReader::new(
    input,
    &key,
    aad,
    params
)?;
let mut ciphertext = Vec::new();
io::copy(&mut encrypting, &mut ciphertext)?;

let mut decrypting = DecryptReader::new(Cursor::new(ciphertext), &key, aad)?;
let mut plaintext = Vec::new();
io::copy(&mut decrypting, &mut plaintext)?;
decrypting.finish()?;

assert_eq!(plaintext, b"a potentially large input");
# Ok(())
# }
```

Reading `EncryptReader` to EOF completes encryption. `EncryptWriter` serves
callers that prefer a `Write` interface.

`DecryptReader::finish` authenticates the unread ciphertext and rejects
trailing bytes. When non-FLOE data comes after the FLOE message, use
`finish_frame`.

**IMPORTANT**: Always call `finish` or `try_finish` to complete the FLOE
message. `flush` will not emit a partial non-final segment, and dropping an
unfinished writer leaves a truncated message.

### Authenticated random access

`random_access::Reader` reads a seekable ciphertext and returns authenticated
plaintext. It implements `Read + Seek` and also reads explicit ranges:

```rust
use std::io::Cursor;

use fast_floe::random_access::Reader;
use fast_floe::{Key, Parameters, encrypt};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let key = Key::from_bytes([0x42; Key::LEN]);
let aad = b"object 17";
let plaintext = vec![0x5a; 10_000];
let ciphertext = encrypt(
    &key,
    aad,
    Parameters::SEGMENT_4_KIB,
    &plaintext,
)?;

let mut reader = Reader::new(Cursor::new(ciphertext), &key, aad)?;
let range = reader.read_range(1_000..1_100)?;
assert_eq!(range, plaintext[1_000..1_100]);
# Ok(())
# }
```

Constructing a `Reader` authenticates the header and final segment, which
establishes the FLOE profile (segment length) and the total length. The
reader authenticates each requested segment before returning its bytes. The
underlying source must not change while the reader is in use. Use
`Reader::new_with_length` when non-FLOE data follows the last segment.

### Segment-oriented processing

Use `online::Encryptor` and `online::Decryptor` when your transport already
deals in packets, buffers or similar units. Both process segments strictly
in order, so the transport must preserve segment order; for out-of-order or
parallel segment processing, use `fast_floe::low_level`.

```rust
use std::io::{Cursor, Read};

use fast_floe::online::{Decryptor, Encryptor};
use fast_floe::{Key, Parameters};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let key = Key::generate()?;
let aad = b"example stream";
let parameters = Parameters::from_segment_length(64 * 1024)?;
let segment_size = parameters.plaintext_segment_length();
let plaintext = vec![b'A'; segment_size * 2 + segment_size / 2];
let mut input = Cursor::new(&plaintext);

let mut encryptor = Encryptor::new(&key, aad, parameters)?;
let header = *encryptor.header();
let mut encrypted_segments = Vec::new();
let mut buffer = Vec::with_capacity(segment_size);

loop {
    buffer.clear();
    input
        .by_ref()
        .take(segment_size as u64)
        .read_to_end(&mut buffer)?;

    if buffer.len() < segment_size {
        encrypted_segments.push(encryptor.encrypt_final_segment(&buffer)?);
        break;
    }

    encrypted_segments.push(encryptor.encrypt_non_final_segment(&buffer)?);
}

let mut decryptor = Decryptor::new(&key, aad, &header)?;
let mut recovered = Vec::new();
for segment in encrypted_segments {
    recovered.extend(decryptor.decrypt_segment(&segment)?);
}
decryptor.finish()?;

assert_eq!(recovered, plaintext);
# Ok(())
# }
```

Every non-final plaintext segment must contain exactly
`parameters.plaintext_segment_length()` bytes; the final segment may be
shorter, or empty. Encrypting the final segment consumes the encryptor. The
decryptor reads and authenticates the final marker in each segment, and
`finish` detects a missing final segment (that is, truncation). If the input
ends exactly on a segment boundary, the next loop iteration emits an empty
final segment.

### Low-level API

`fast_floe::low_level` exposes the details of the FLOE specification. A
`MessageLayout` supplies the position, length, offset and finality of every
segment; use one when you know the plaintext length in advance:

```rust
use fast_floe::low_level::start_encryption;
use fast_floe::{Key, Parameters};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let key = Key::from_bytes([0x42; Key::LEN]);
let aad = b"context stuff";
let parameters = Parameters::SEGMENT_8_MIB;
let plaintext = b"low-level api data example";
let layout = parameters.plaintext_layout(plaintext.len() as u64)?;

let (mut state, header) = start_encryption(&key, aad, parameters)?;
let mut ciphertext = header.as_ref().to_vec();

for segment in layout {
    let start = usize::try_from(segment.plaintext_offset())?;
    let end = start + segment.plaintext_length();
    let encrypted = state.encrypt_segment(&plaintext[start..end], segment)?;
    ciphertext.extend_from_slice(&encrypted);
}

assert_eq!(ciphertext.len() as u64, layout.ciphertext_length());
# Ok(())
# }
```

Parallel workloads can call `state.into_shared()`, then `shared.fork()` for
each worker or thread. `SharedEncryptionContext` and
`SharedDecryptionContext` are thread-safe (`Send + Sync`).

The low-level API leaves every FLOE invariant to the caller: process each
position once, produce exactly one final segment, leave no gaps and process
nothing after the final segment. Breaking these rules can break the security
of the message, so prefer the misuse-resistant higher-level APIs.

`low_level::SegmentBuffer` provides reusable in-place storage. Callers that
manage their own allocation can use the `*_raw` methods with their own
buffers.

## Notes

- FLOE authenticates the AAD but does not store it in the ciphertext. Store
  or derive it separately and reproduce it exactly.
- The library releases each segment only after that segment authenticates. A
  stream consumer can therefore receive valid early segments before
  discovering later corruption or truncation. Applications that need
  all-or-nothing release must hold plaintext until finalization.
- Segment prefixes and layout calculations describe framing only. Treat them
  as untrusted until the corresponding header or segment authenticates.

## Handling errors from the `std::io` adapters

The `io` and `random_access` adapters report FLOE failures as `io::Error`
values with the crate `Error` attached as the source. Use
`Error::io_source` to separate FLOE failures, such as tampering, from
ordinary I/O errors:

```rust
use std::io::Read;

use fast_floe::io::DecryptReader;
use fast_floe::Error;

fn read_message(reader: &mut DecryptReader<impl Read>) -> std::io::Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    if let Err(error) = reader.read_to_end(&mut plaintext) {
        if let Some(Error::AuthenticationFailed) = Error::io_source(&error) {
            eprintln!("ciphertext is corrupted or was tampered with");
        }
        return Err(error);
    }
    reader.try_finish()?;
    Ok(plaintext)
}
```

## Segment sizes

FLOE accepts any segment length from 64 to 4,294,967,294 (`u32::MAX` - 1)
bytes, inclusive, including odd lengths and lengths that are not powers of
two. The constant `Parameters::VALID_SEGMENT_LENGTHS` encodes this range.

Construct `Parameters` with `Parameters::from_segment_length()`, or use one
of the `Parameters::SEGMENT_*` constants.

Only the encrypted segment length varies; the other FLOE parameters
(AES-256-GCM, HKDF-SHA-384, IV length) are fixed.

`Parameters::plaintext_layout` and `Parameters::ciphertext_layout` calculate
a complete `random_access::MessageLayout`. Use them for storage sizing and
manual segment processing.

## Cryptographic providers

The crate delegates AES-256-GCM, HKDF-SHA-384 and random-number generation
to one of four providers. The default is `aws-lc-rs`:

| Feature               | Provider crate(s)                                                                                                 |
|-----------------------|-------------------------------------------------------------------------------------------------------------------|
| `aws-lc-rs` (default) | [aws-lc-rs](https://crates.io/crates/aws-lc-rs)                                                                   |
| `boring`              | [boring](https://crates.io/crates/boring)                                                                         |
| `ring`                | [ring](https://crates.io/crates/ring)                                                                             |
| `rustcrypto`          | `RustCrypto` [aes-gcm](https://crates.io/crates/aes-gcm) and [rand_chacha](https://crates.io/crates/rand_chacha/) |

Provider choice does not change the FLOE wire format; ciphertext from any
provider decrypts with any other.

To use another provider:

```toml
fast-floe = { version = "0.3", default-features = false, features = ["ring"] }
```

Provider features are additive. With exactly one provider compiled,
`Key::generate` and `Key::from_bytes` use it automatically. With several,
bind one to the key with `Key::generate_with_provider` or
`Key::from_bytes_with_provider`.

## Examples and development

The repository includes two file examples:

- `serial_file` uses the bounded-memory `std::io` adapters.
- `manual_file` uses message layouts and low-level segment operations.

Run the examples with:

```text
cargo run --example serial_file -- encrypt INPUT OUTPUT 64_HEX_KEY [4k|1m]
cargo run --example manual_file -- encrypt INPUT OUTPUT 64_HEX_KEY [4k|1m]
```

For a provider that is not the default, add
`--no-default-features --features ring` before `--`.

Run the default-provider tests and documentation checks with:

```sh
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

Run all provider and segment-length benchmarks with:

```sh
./scripts/bench-matrix.sh
```

### Benchmark results

Median throughput in GiB/s, with each provider compiled alone with
`-C target-cpu=native` and a single codegen unit. Each benchmark sizes its
buffer to at least four times the detected last-level cache, so the run
measures memory, not the cache.

The "into" columns encrypt or decrypt into a separate output buffer (with
scatter/gather where the provider supports it); the "in place" columns
overwrite their input.

#### AMD Zen 5 9950X (VAES, AVX-512), Rust 1.97.1

FLOE segment-oriented performance in GiB/sec, higher is better

| Provider     | Segments | Encrypt into | Encrypt in place | Decrypt into | Decrypt in place |
|--------------|----------|-------------:|-----------------:|-------------:|-----------------:|
| `aws-lc-rs`  | 1 MiB    |        13.88 |            21.50 |        12.05 |            22.25 |
| `boring`     | 1 MiB    |        11.98 |            17.72 |         8.56 |            19.29 |
| `ring`       | 1 MiB    |         6.18 |            11.87 |         6.43 |            12.90 |
| `rustcrypto` | 1 MiB    |         4.84 |             4.87 |         4.93 |             4.94 |
| `aws-lc-rs`  | 4 KiB    |         8.85 |            10.15 |         9.18 |            11.31 |
| `boring`     | 4 KiB    |        10.95 |            14.76 |         7.98 |            16.12 |
| `ring`       | 4 KiB    |         5.99 |             9.15 |         6.91 |            10.31 |
| `rustcrypto` | 4 KiB    |         4.67 |             4.84 |         4.81 |             4.59 |

Against each provider's bare AES-256-GCM, FLOE "in place" on the Zen 5 comes
within about 5% on 1 MiB segments for `aws-lc-rs`, `ring` and `rustcrypto`
(`boring` is about 12% slower), and runs 5-45% slower on 4 KiB segments.

The `std::io` adapters and the random-access reader add overhead to the
segment operations above. The `Reader` handles whole segments without
copying; reads smaller than a segment are buffered, at the cost of one copy.

| Provider     | Segments | `EncryptWriter` | `EncryptReader` | `DecryptReader` | Reader (seq) | Reader (range) |
|--------------|----------|--------------:|--------------:|--------------:|-------------:|---------------:|
| `aws-lc-rs`  | 1 MiB    |         18.07 |         13.79 |         12.35 |        10.85 |           9.48 |
| `boring`     | 1 MiB    |         16.62 |         13.27 |         10.22 |        10.56 |           6.96 |
| `ring`       | 1 MiB    |          8.22 |          7.48 |          7.34 |         7.55 |           5.63 |
| `rustcrypto` | 1 MiB    |          4.89 |          4.18 |          4.24 |         3.87 |           3.92 |
| `aws-lc-rs`  | 4 KiB    |         11.91 |         10.89 |          9.03 |         6.81 |           6.93 |
| `boring`     | 4 KiB    |         14.96 |          9.42 |          8.55 |         8.97 |           6.81 |
| `ring`       | 4 KiB    |          8.12 |          7.29 |          7.82 |         7.10 |           5.96 |
| `rustcrypto` | 4 KiB    |          4.97 |          4.43 |          3.96 |         3.78 |           4.03 |

#### Apple M3, Rust 1.97.1

FLOE segment-oriented performance in GiB/sec, higher is better.

| Provider     | Segments | Encrypt into | Encrypt in place | Decrypt into | Decrypt in place |
|--------------|----------|-------------:|-----------------:|-------------:|-----------------:|
| `aws-lc-rs`  | 1 MiB    |         8.61 |             8.61 |         8.67 |             8.76 |
| `boring`     | 1 MiB    |         7.19 |             7.22 |         6.01 |             7.19 |
| `ring`       | 1 MiB    |         6.05 |             7.18 |         6.06 |             7.17 |
| `rustcrypto` | 1 MiB    |         5.77 |             5.75 |         5.80 |             5.77 |
| `aws-lc-rs`  | 4 KiB    |         6.92 |             7.39 |         7.28 |             7.52 |
| `boring`     | 4 KiB    |         6.47 |             6.51 |         5.85 |             6.63 |
| `ring`       | 4 KiB    |         5.43 |             6.16 |         5.80 |             6.40 |
| `rustcrypto` | 4 KiB    |         5.54 |             5.50 |         5.59 |             5.56 |

Against each provider's bare AES-256-GCM, FLOE "in place" on the M3 comes
within about 1% on 1 MiB segments and runs 3-15% slower on 4 KiB segments.

The `std::io` adapter and random-access reader results on the M3, measured as
for the Zen 5:

| Provider     | Segments | `EncryptWriter` | `EncryptReader` | `DecryptReader` | Reader (seq) | Reader (range) |
|--------------|----------|--------------:|--------------:|--------------:|-------------:|---------------:|
| `aws-lc-rs`  | 1 MiB    |          8.33 |          7.34 |          7.14 |         6.52 |           6.98 |
| `boring`     | 1 MiB    |          6.89 |          6.23 |          5.48 |         5.56 |           5.60 |
| `ring`       | 1 MiB    |          6.28 |          5.64 |          5.50 |         5.62 |           5.61 |
| `rustcrypto` | 1 MiB    |          5.64 |          5.10 |          5.15 |         4.71 |           4.97 |
| `aws-lc-rs`  | 4 KiB    |          7.36 |          6.68 |          6.78 |         6.14 |           6.57 |
| `boring`     | 4 KiB    |          6.49 |          5.94 |          5.53 |         5.49 |           5.45 |
| `ring`       | 4 KiB    |          5.59 |          5.29 |          5.49 |         5.18 |           5.40 |
| `rustcrypto` | 4 KiB    |          5.55 |          4.98 |          5.06 |         4.77 |           5.07 |

## License

Licensed under the [Apache License 2.0](./LICENSE).
