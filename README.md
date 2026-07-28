# fast-floe

An optimized, multi-provider, spec-complianct implementation of 
the Fast Lightweight Online Encryption (FLOE) scheme for authenticated encryption of 
large files and byte streams with bounded-memory and random access.

## Introduction

`fast-floe` implements the [Fast Lightweight Online Encryption (FLOE)
specification](https://c2sp.org/FLOE) in Rust. FLOE divides a message into independently authenticated
and encrypted segments of user chosen length. A recipient can encrypt/decrypt a
large message one segment at a time and read/seek randomly into the ciphertext. 

FLOE is built for really big data, streaming data where you might not know size ahead 
of time, data that might arrive out-of-order, and random-access into encrypted data.

Callers select the segment length at encryption time to trade off throughput
for random-access overhead (smaller segment length == cheaper random access, and larger segment
length == more throughput).

Multiple cryptography providers are supported (aws-lc-rs, boring, ring, and `RustCrypto`).
They all interoperate with each other (i.e. provider choice does not affect wire format).

## Quick start

Add `fast-floe` from [crates.io](https://crates.io/crates/fast-floe) to
`Cargo.toml`. Rust refers to the crate as `fast_floe`.

```toml
[dependencies]
fast-floe = "0.3"
```

aws-lc-rs is the default cryptographic provider, but can be overridden, 
see the "_Cryptographic Providers_" section below.

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
by encrypted segments. `decrypt` authenticates the message before returning its
plaintext.

The three inputs are:

- `Key`: a 32-byte secret. use `Key::from_bytes` to import existing key material 
  and `Key::generate` to generate a new random key.
- `AAD`: context that must be authenticated with the ciphertext, such as an
  session ID or protocol version. FLOE does not store the AAD. Decryption requires the
  same AAD bytes to succeed.
- `Parameters`: the encrypted segment length. FLOE supports all segments lengths from
  64 to 4,294,967,294 (`u32::MAX` - 2) bytes.

## Choose an API

Ordered below from simplest (and more high-level) to more advanced (and low-level). 
Use the highest layer that fits your needs:

| Need                                         | API                        | Input                     |
|----------------------------------------------|----------------------------|---------------------------|
| Encrypt or decrypt bytes already in memory   | `encrypt`, `decrypt`       | One-shot complete message |
| Process a file, socket, or `std::io` adapter | `fast_floe::io`            | `Read` or `Write`         |
| Read selected authenticated ranges           | `fast_floe::random_access` | `Read + Seek` ciphertext  |
| Exchange segments, possibly out-of-order     | `fast_floe::online`        | Streaming data            |
| Process segments manually or in parallel     | `fast_floe::low_level`     | Experts needing control   |

### Whole messages

Use the quick-start `encrypt` and `decrypt` functions when the complete input
and output fit in memory. Both return a new `Vec<u8>`.

`decrypt` uses the authenticated profile (segment size) read from the header. 
If your application wants to choose the profile instead, use `decrypt_with_parameters`.

### Streams with `std::io`

`EncryptReader` and `DecryptReader` keep memory bounded while composing with
ordinary Rust I/O:

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

Read `EncryptReader` to EOF to complete encryption. `EncryptWriter` is available
when a `Write` interface fits better.

`DecryptReader::finish` authenticates unread ciphertext and rejects trailing
bytes. Use `finish_frame` when non-FLOE data follows the FLOE message.

**IMPORTANT**: always call `finish` or `try_finish` to complete the FLOE message. 
`flush` will not emit a partial non-final FLOE segment, and dropping an 
unfinished writer leaves a truncated message.

### Authenticated random access

`random_access::Reader` presents a seekable ciphertext as authenticated
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

`Reader` construction authenticates the header and final segment, which establishes the
FLOE profile (segment size) and complete length. Each requested segment is authenticated
before its bytes are returned. The underlying seekable source must remain unchanged while 
the reader is in use. Use `Reader::new_with_length` when non-FLOE data follows the last segment.

### Segment-oriented processing

Use `online::Encryptor` and `online::Decryptor` when your transport already
works with packets, buffers, or other segment-like things. 

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

All non-final plaintext segments must have exactly
`parameters.plaintext_segment_length()` bytes. The final segment may be shorter,
including empty. Final encryption consumes the encryptor. Decryption reads the
final marker from each segment, authenticates it, and `finish` detects a missing
final segment (e.g. detects truncation). If the input ends exactly on a segment 
boundary, the next loop iteration emits an empty final segment.

### Low-level API

`fast_floe::low_level` exposes the FLOE specification's details. A
`MessageLayout` supplies the correct position, lengths, offsets, and finality
for every segment and you should use it when you know the plaintext length in advance:

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

Parallel or concurrent workloads can call `state.into_shared()` and then `shared.fork()` 
for each distinct worker/thread. `SharedEncryptionContext` and `SharedDecryptionContext` 
are thread-safe (e.g. they are `Send + Sync`).

Low-level encryption requires the caller to handle all FLOE invariants: process 
every position once, produce exactly one final segment, leave no gaps, and process 
nothing after the final segment. Breaking these rules can break message security. 
Prefer the misuse-resistant higher-level APIs.

`low_level::SegmentBuffer` supports reusable in-place storage. If you need to control
allocation, `*_raw` methods are available for use w/ your own buffer management.

## Notes

- AAD is authenticated but is not stored in the ciphertext. Store or derive it
  separately and reproduce it exactly.
- Each segment is released only after its own authentication succeeds. A stream
  consumer may receive valid early segments before a later corruption or
  truncation is discovered. Callers should stage plaintext until finalization when the
  application requires all-or-nothing release.
- Segment prefixes and layout calculations describe framing. Treat them as
  untrusted until the corresponding header or segment authenticates.

## Segment sizes

FLOE supports all segment lengths between 64 and 4,294,967,294 (`u32::MAX` - 2) bytes, inclusive.
Any size in that range is valid, including odd lengths and non-powers-of-2. The constant
`Parameters::VALID_SEGMENT_LENGTHS` encodes this range.

Use `Parameters::from_segment_length()` to construct `Parameters` with your desired length,
or use one of the `Parameters::SEGMENT_*` convenience constants.

Only the encrypted segment size differs, all other FLOE parameters (AES-256-GCM, HKDF-SHA-384,
IV length) are the same.

`Parameters::plaintext_layout` and `Parameters::ciphertext_layout` calculate a
complete `random_access::MessageLayout`. Use them for storage sizing and manual
segment processing. 

## Cryptographic providers

This crate uses different providers to implement AES-256-GCM, HKDF-SHA-384, 
and random-number generation. The crate default is `aws-lc-rs`, but all
of these are supported:

| Feature               | Provider crate(s)                                                                                                 |
|-----------------------|-------------------------------------------------------------------------------------------------------------------|
| `aws-lc-rs` (default) | [aws-lc-rs](https://crates.io/crates/aws-lc-rs)                                                                   |
| `boring`              | [boring](https://crates.io/crates/boring)                                                                         |
| `ring`                | [ring](https://crates.io/crates/ring)                                                                             |
| `rustcrypto`          | `RustCrypto` [aes-gcm](https://crates.io/crates/aes-gcm) and [rand_chacha](https://crates.io/crates/rand_chacha/) |

Provider choice does not change the FLOE wire format. They are all compatible with each other.

To use an alternate provider:

```toml
fast-floe = { version = "0.3", default-features = false, features = ["ring"] }
```

Provider features are additive. With exactly one compiled provider,
`Key::generate` and `Key::from_bytes` use it automatically. But with several,
you must bind one to the key with `Key::generate_with_provider` or `Key::from_bytes_with_provider`. 

## Examples and development

The repository includes two file examples:

- `serial_file` uses the bounded-memory `std::io` adapters.
- `manual_file` uses message layouts and low-level segment operations.

Run them with:

```text
cargo run --example serial_file -- encrypt INPUT OUTPUT 64_HEX_KEY [4k|1m]
cargo run --example manual_file -- encrypt INPUT OUTPUT 64_HEX_KEY [4k|1m]
```

For a non-default provider, add `--no-default-features --features ring`
before `--`.

Run the default-provider test and documentation checks with:

```sh
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

Run all provider and segment-size benchmarks with:

```sh
./scripts/bench-matrix.sh
```

### Benchmark results

Median throughput in GiB/s with each provider compiled solo with `-C target-cpu=native`. Each
benchmark trial sizes its buffer to be at least 4x the detected last-level-cache size to ensure
we're reaching actual memory, not spinning in cache.

The "into" columns encrypt or decrypt into a separate output buffer in one pass
(using scatter/gather when the provider supports it) while "in place" overwrite
their input, processing segments within one contiguous arena.

#### AMD Zen 5 9950X (VAES, AVX-512), Rust 1.97.1

FLOE performance in GiB/sec, higher is better

| Provider     | Segments | Encrypt into | Encrypt in place | Decrypt into | Decrypt in place |
|--------------|----------|-------------:|-----------------:|-------------:|-----------------:|
| `aws-lc-rs`  | 1 MiB    |        13.06 |            19.82 |        14.13 |            19.93 |
| `boring`     | 1 MiB    |        12.31 |            17.82 |         8.41 |            16.59 |
| `ring`       | 1 MiB    |         6.32 |            11.43 |         6.14 |            12.38 |
| `rustcrypto` | 1 MiB    |         4.65 |             4.74 |         4.88 |             4.60 |
| `aws-lc-rs`  | 4 KiB    |         8.36 |             9.09 |         7.97 |            10.34 |
| `boring`     | 4 KiB    |        10.26 |            14.52 |         7.71 |            16.16 |
| `ring`       | 4 KiB    |         5.06 |             8.47 |         6.97 |            10.59 |
| `rustcrypto` | 4 KiB    |         4.35 |             4.31 |         4.31 |             4.49 |

Compared to "bare" AES-256-GCM from each provider, FLOE on Zen5 is within ~1% on 1 MiB segments
(the FLOE overhead is easily amortized), and FLOE is ~10%-40% slower on 4 KiB segments. 

#### Apple M3, Rust 1.97.1

FLOE performance in GiB/sec, higher is better

| Provider     | Segments | Encrypt into | Encrypt in place | Decrypt into | Decrypt in place |
|--------------|----------|-------------:|-----------------:|-------------:|-----------------:|
| `aws-lc-rs`  | 1 MiB    |         8.63 |             8.65 |         8.75 |             8.76 |
| `boring`     | 1 MiB    |         7.22 |             7.20 |         6.08 |             7.15 |
| `ring`       | 1 MiB    |         6.08 |             7.20 |         6.03 |             7.17 |
| `rustcrypto` | 1 MiB    |         3.56 |             3.63 |         3.62 |             3.65 |
| `aws-lc-rs`  | 4 KiB    |         6.97 |             7.39 |         7.40 |             7.68 |
| `boring`     | 4 KiB    |         6.51 |             6.22 |         5.82 |             6.64 |
| `ring`       | 4 KiB    |         5.46 |             6.09 |         5.77 |             6.14 |
| `rustcrypto` | 4 KiB    |         3.45 |             3.47 |         3.48 |             3.45 |

Compared to "bare" AES-256-GCM from each provider, FLOE on the M3 is within ~1% on 1 MiB
segments and ~15%-25% slower on 4 KiB segments.

## License

Licensed under the [Apache License 2.0](./LICENSE).
