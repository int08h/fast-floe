# fast-floe

`fast-floe` is an optimized, multi-provider, spec-compliant implementation of
Fast Lightweight Online Encryption (FLOE). FLOE is an authenticated encryption
scheme for large files and byte streams. It operates with bounded memory and
gives random access into the ciphertext.

## Introduction

`fast-floe` implements the [Fast Lightweight Online Encryption (FLOE)
specification](https://c2sp.org/FLOE) in Rust. FLOE divides a message into
segments of a length that the caller selects. FLOE encrypts and authenticates
each segment independently. A recipient can decrypt a large message one segment
at a time. A recipient can also read and seek to any position in the
ciphertext.

FLOE is made for very large data, streams with an unknown length, segments that
arrive out of order, and random access into encrypted data.

The caller selects the segment length at encryption time. A smaller segment
length makes random access less costly. A larger segment length gives more
throughput.

The crate supports four cryptography providers: aws-lc-rs, boring, ring, and
`RustCrypto`. The provider selection does not change the wire format. All
providers interoperate with each other.

## Quick start

Add `fast-floe` from [crates.io](https://crates.io/crates/fast-floe) to
`Cargo.toml`. In Rust code, the crate name is `fast_floe`.

```toml
[dependencies]
fast-floe = "0.3"
```

The default cryptographic provider is aws-lc-rs. To select a different
provider, refer to the "_Cryptographic providers_" section.

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

`encrypt` returns one complete FLOE message: an authenticated header, then the
encrypted segments. `decrypt` authenticates the message before it returns the
plaintext.

The three inputs are:

- `Key`: a 32-byte secret. Use `Key::generate` to make a new random key. Use
  `Key::from_bytes` to import existing key material.
- `AAD`: context data that FLOE authenticates with the ciphertext, for example
  a session ID or a protocol version. FLOE does not store the AAD. Decryption
  must receive the same AAD bytes.
- `Parameters`: the encrypted segment length. FLOE supports all segment
  lengths from 64 through 4,294,967,294 (`u32::MAX` - 2) bytes.

## Choose an API

The table lists the APIs from the most simple (high-level) to the most
advanced (low-level). Use the highest layer that satisfies your needs:

| Need                                         | API                        | Input                     |
|----------------------------------------------|----------------------------|---------------------------|
| Encrypt or decrypt bytes already in memory   | `encrypt`, `decrypt`       | One-shot complete message |
| Process a file, socket, or `std::io` adapter | `fast_floe::io`            | `Read` or `Write`         |
| Read selected authenticated ranges           | `fast_floe::random_access` | `Read + Seek` ciphertext  |
| Exchange segments, possibly out-of-order     | `fast_floe::online`        | Streaming data            |
| Process segments manually or in parallel     | `fast_floe::low_level`     | Experts needing control   |

### Whole messages

When the complete input and output fit in memory, use the quick-start
`encrypt` and `decrypt` functions. The two functions return a new `Vec<u8>`.

`decrypt` reads the authenticated profile (the segment length) from the
header. If your application must select the profile, use
`decrypt_with_parameters`.

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

Read `EncryptReader` to EOF to complete the encryption. When a `Write`
interface is a better fit, use `EncryptWriter`.

`DecryptReader::finish` authenticates the unread ciphertext and rejects
trailing bytes. When non-FLOE data comes after the FLOE message, use
`finish_frame`.

**IMPORTANT**: Always call `finish` or `try_finish` to complete the FLOE
message. `flush` does not write a partial non-final segment. If you drop an
unfinished writer, the message stays truncated.

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

When you construct a `Reader`, it authenticates the header and the final
segment. This step establishes the FLOE profile (the segment length) and the
complete message length. The reader authenticates each requested segment
before it returns the bytes. Do not change the underlying seekable source
while the reader is in use. When non-FLOE data comes after the last segment,
use `Reader::new_with_length`.

### Segment-oriented processing

When your transport already operates on packets, buffers, or other
segment-like units, use `online::Encryptor` and `online::Decryptor`.

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

Each non-final plaintext segment must have exactly
`parameters.plaintext_segment_length()` bytes. The final segment can be
shorter or empty. Encryption of the final segment consumes the encryptor. The
decryptor reads the final marker from each segment and authenticates it.
`finish` detects a missing final segment, for example a truncated message. If
the input ends exactly on a segment boundary, the next loop iteration writes
an empty final segment.

### Low-level API

`fast_floe::low_level` exposes the details of the FLOE specification. A
`MessageLayout` supplies the correct position, length, offset, and finality
for each segment. When you know the plaintext length in advance, use a
`MessageLayout`:

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

For parallel or concurrent work, call `state.into_shared()`, then call
`shared.fork()` for each worker or thread. `SharedEncryptionContext` and
`SharedDecryptionContext` are thread-safe (`Send + Sync`).

The low-level API makes the caller responsible for all FLOE invariants:

- Process each position one time.
- Produce exactly one final segment.
- Leave no gaps.
- Process nothing after the final segment.

If you do not obey these rules, the security of the message is not guaranteed.
When possible, use the misuse-resistant high-level APIs.

`low_level::SegmentBuffer` supplies reusable in-place storage. If you must
control allocation, use the `*_raw` methods with your own buffer management.

## Notes

- FLOE authenticates the AAD but does not store it in the ciphertext. Store or
  derive the AAD separately, and give the same bytes to decryption.
- The library releases each segment only after the authentication of that
  segment succeeds. A stream consumer can receive valid early segments before
  it finds a later corruption or truncation. If your application requires
  all-or-nothing release, hold the plaintext until finalization.
- Segment prefixes and layout calculations describe framing only. Treat them
  as untrusted data until the related header or segment authenticates.

## Segment sizes

FLOE supports all segment lengths from 64 through 4,294,967,294
(`u32::MAX` - 2) bytes. Each length in this range is valid, including odd
lengths and lengths that are not powers of 2. The constant
`Parameters::VALID_SEGMENT_LENGTHS` encodes this range.

Use `Parameters::from_segment_length()` to construct `Parameters` with your
selected length. Or use one of the `Parameters::SEGMENT_*` constants.

Only the encrypted segment length changes. All other FLOE parameters
(AES-256-GCM, HKDF-SHA-384, IV length) stay the same.

`Parameters::plaintext_layout` and `Parameters::ciphertext_layout` calculate a
complete `random_access::MessageLayout`. Use them for storage sizing and
manual segment processing.

## Cryptographic providers

The crate uses external providers for AES-256-GCM, HKDF-SHA-384, and
random-number generation. The default provider is `aws-lc-rs`. The crate
supports these providers:

| Feature               | Provider crate(s)                                                                                                 |
|-----------------------|-------------------------------------------------------------------------------------------------------------------|
| `aws-lc-rs` (default) | [aws-lc-rs](https://crates.io/crates/aws-lc-rs)                                                                   |
| `boring`              | [boring](https://crates.io/crates/boring)                                                                         |
| `ring`                | [ring](https://crates.io/crates/ring)                                                                             |
| `rustcrypto`          | `RustCrypto` [aes-gcm](https://crates.io/crates/aes-gcm) and [rand_chacha](https://crates.io/crates/rand_chacha/) |

The provider selection does not change the FLOE wire format. All providers are
compatible with each other.

To use a different provider:

```toml
fast-floe = { version = "0.3", default-features = false, features = ["ring"] }
```

Provider features are additive. When you compile exactly one provider,
`Key::generate` and `Key::from_bytes` use that provider automatically. When
you compile more than one provider, bind one provider to the key with
`Key::generate_with_provider` or `Key::from_bytes_with_provider`.

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

Run the default-provider tests and the documentation checks with:

```sh
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

Run all provider and segment-length benchmarks with:

```sh
./scripts/bench-matrix.sh
```

### Benchmark results

The tables show the median throughput in GiB/s. Each provider is compiled
alone with `-C target-cpu=native` and one codegen unit. Each benchmark makes
its buffer at least 4x the size of the detected last-level cache. This size
makes sure that the benchmark measures memory, not the cache.

The "into" columns encrypt or decrypt into a separate output buffer. When the
provider supports it, these operations use scatter/gather. The "in place"
columns overwrite the input.

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

The next lines compare FLOE "in place" with "bare" AES-256-GCM from each
provider on the Zen 5. With 1 MiB segments, `aws-lc-rs`, `ring`, and
`rustcrypto` are within approximately 5%, and `boring` is approximately 12%
slower. With 4 KiB segments, FLOE is approximately 5% to 45% slower.

The `std::io` adapters and the random-access reader add overhead to the
segment operations above. The `Reader` operates on whole segments without a
copy. Reads that are smaller than one segment are buffered (one copy).

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

The next lines compare FLOE "in place" with "bare" AES-256-GCM from each
provider on the M3. With 1 MiB segments, FLOE is within approximately 1%.
With 4 KiB segments, FLOE is approximately 3% to 15% slower.

The next table shows the `std::io` adapter and random-access reader results
on the M3, measured in the same way as the Zen 5 tables:

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
