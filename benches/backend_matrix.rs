use std::time::{Duration, Instant};

use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use fast_floe::low_level::SegmentBuffer;
use fast_floe::online::{Decryptor, Encryptor, FinalEncryptError};
use fast_floe::random_access::MessageLayout;
use fast_floe::{Header, Key, Parameters, Provider, SegmentKind, encrypt};

const AAD: &[u8] = b"benchmark";
const KEY_BYTES: [u8; 32] = [0x42; 32];
// Reuse is intentional for deterministic, discarded benchmark output only.
const BASELINE_NONCE: [u8; 12] = [0x24; 12];
const AEAD_TAG_LENGTH: usize = 16;
const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

/// Minimum working-set size relative to the detected last-level cache.
const LLC_MULTIPLE: usize = 4;

/// Minimum number of segments processed by each benchmark invocation.
const MIN_SEGMENT_COUNT: usize = 96;

/// Fallback message sizes if last-level cache cannot be detected.
const DEFAULT_SMALL_SEGMENT_TARGET: usize = 4 * MIB;
const DEFAULT_LARGE_SEGMENT_TARGET: usize = 64 * MIB;

#[allow(clippy::large_enum_variant)]
enum BaselineAead {
    #[cfg(feature = "aws-lc-rs")]
    AwsLcRs(aws_lc_rs::aead::LessSafeKey),
    #[cfg(feature = "boring")]
    Boring(boring::aead::AeadCtx),
    #[cfg(feature = "ring")]
    Ring(ring::aead::LessSafeKey),
    #[cfg(feature = "rustcrypto")]
    RustCrypto(aes_gcm::Aes256Gcm),
}

impl BaselineAead {
    fn new(provider: Provider) -> Self {
        #[allow(unreachable_patterns)]
        match provider {
            #[cfg(feature = "aws-lc-rs")]
            Provider::AWS_LC_RS => {
                let key =
                    aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::AES_256_GCM, &KEY_BYTES)
                        .expect("AWS-LC baseline key setup failed");
                Self::AwsLcRs(aws_lc_rs::aead::LessSafeKey::new(key))
            }
            #[cfg(feature = "boring")]
            Provider::BORING => {
                let algorithm = boring::aead::Algorithm::aes_256_gcm();
                let key = boring::aead::AeadCtx::new(&algorithm, &KEY_BYTES, AEAD_TAG_LENGTH)
                    .expect("BoringSSL baseline key setup failed");
                Self::Boring(key)
            }
            #[cfg(feature = "ring")]
            Provider::RING => {
                let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &KEY_BYTES)
                    .expect("Ring baseline key setup failed");
                Self::Ring(ring::aead::LessSafeKey::new(key))
            }
            #[cfg(feature = "rustcrypto")]
            Provider::RUSTCRYPTO => {
                use aes_gcm::KeyInit;

                Self::RustCrypto(
                    aes_gcm::Aes256Gcm::new_from_slice(&KEY_BYTES)
                        .expect("RustCrypto baseline key setup failed"),
                )
            }
            _ => unreachable!("provider is compiled into this benchmark"),
        }
    }

    fn seal_in_place(&self, in_out: &mut [u8]) -> [u8; AEAD_TAG_LENGTH] {
        let mut tag = [0; AEAD_TAG_LENGTH];
        match self {
            #[cfg(feature = "aws-lc-rs")]
            Self::AwsLcRs(key) => {
                use aws_lc_rs::aead::{Aad, Nonce};

                let generated = key
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key(BASELINE_NONCE),
                        Aad::from(AAD),
                        in_out,
                    )
                    .expect("AWS-LC baseline encryption failed");
                tag.copy_from_slice(generated.as_ref());
            }
            #[cfg(feature = "boring")]
            Self::Boring(key) => {
                let written = key
                    .seal_in_place(&BASELINE_NONCE, in_out, &mut tag, AAD)
                    .expect("BoringSSL baseline encryption failed");
                assert_eq!(written.len(), AEAD_TAG_LENGTH);
            }
            #[cfg(feature = "ring")]
            Self::Ring(key) => {
                use ring::aead::{Aad, Nonce};

                let generated = key
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key(BASELINE_NONCE),
                        Aad::from(AAD),
                        in_out,
                    )
                    .expect("Ring baseline encryption failed");
                tag.copy_from_slice(generated.as_ref());
            }
            #[cfg(feature = "rustcrypto")]
            Self::RustCrypto(key) => {
                use aes_gcm::aead::{AeadInOut, Nonce};

                let generated = key
                    .encrypt_inout_detached(
                        &Nonce::<aes_gcm::Aes256Gcm>::from(BASELINE_NONCE),
                        AAD,
                        in_out.into(),
                    )
                    .expect("RustCrypto baseline encryption failed");
                tag.copy_from_slice(&generated);
            }
        }
        tag
    }

    fn open_in_place(&self, tag: &[u8; AEAD_TAG_LENGTH], in_out: &mut [u8]) {
        match self {
            #[cfg(feature = "aws-lc-rs")]
            Self::AwsLcRs(key) => {
                use aws_lc_rs::aead::{Aad, Nonce};

                key.open_in_place_separate_tag(
                    Nonce::assume_unique_for_key(BASELINE_NONCE),
                    Aad::from(AAD),
                    tag,
                    in_out,
                )
                .expect("AWS-LC baseline decryption failed");
            }
            #[cfg(feature = "boring")]
            Self::Boring(key) => {
                key.open_in_place(&BASELINE_NONCE, in_out, tag, AAD)
                    .expect("BoringSSL baseline decryption failed");
            }
            #[cfg(feature = "ring")]
            Self::Ring(key) => {
                use ring::aead::{Aad, Nonce, Tag};

                key.open_in_place_separate_tag(
                    Nonce::assume_unique_for_key(BASELINE_NONCE),
                    Aad::from(AAD),
                    Tag::from(*tag),
                    in_out,
                    0..,
                )
                .expect("Ring baseline decryption failed");
            }
            #[cfg(feature = "rustcrypto")]
            Self::RustCrypto(key) => {
                use aes_gcm::aead::{AeadInOut, Nonce, Tag};

                key.decrypt_inout_detached(
                    &Nonce::<aes_gcm::Aes256Gcm>::from(BASELINE_NONCE),
                    AAD,
                    in_out.into(),
                    &Tag::<aes_gcm::Aes256Gcm>::from(*tag),
                )
                .expect("RustCrypto baseline decryption failed");
            }
        }
    }
}

#[derive(Clone, Copy)]
struct BenchmarkCase<'a> {
    provider: Provider,
    name: &'a str,
    parameters: Parameters,
    plaintext: &'a [u8],
    layout: MessageLayout,
}

fn benchmark_backend_matrix(criterion: &mut Criterion) {
    let (small_target, large_target) = target_lengths();
    let cases = [
        (
            format!("4KiB-segments_{}-target", format_size(small_target)),
            Parameters::SEGMENT_4_KIB,
            small_target,
        ),
        (
            format!("1MiB-segments_{}-target", format_size(large_target)),
            Parameters::SEGMENT_1_MIB,
            large_target,
        ),
    ];
    for &provider in Provider::COMPILED {
        let key = Key::from_bytes_with_provider(KEY_BYTES, provider);
        let baseline_key = BaselineAead::new(provider);
        for (case_name, parameters, target_length) in &cases {
            let (case_name, parameters, target_length) =
                (case_name.as_str(), *parameters, *target_length);
            let plaintext = vec![0x5a; target_length];
            let layout = parameters
                .plaintext_layout(
                    u64::try_from(plaintext.len()).expect("target length fits in u64"),
                )
                .expect("benchmark layout must be valid");
            assert!(
                layout.segment_count()
                    >= u64::try_from(MIN_SEGMENT_COUNT).expect("minimum segment count fits in u64"),
                "benchmark case must process at least {MIN_SEGMENT_COUNT} segments"
            );
            let ciphertext = encrypt(&key, AAD, parameters, &plaintext)
                .expect("benchmark setup encryption failed");
            let case = BenchmarkCase {
                provider,
                name: case_name,
                parameters,
                plaintext: &plaintext,
                layout,
            };

            benchmark_encryption(criterion, &key, &baseline_key, case);
            benchmark_decryption(criterion, &key, &baseline_key, case, &ciphertext);
        }
    }
}

fn benchmark_encryption(
    criterion: &mut Criterion,
    key: &Key,
    baseline_key: &BaselineAead,
    case: BenchmarkCase<'_>,
) {
    let BenchmarkCase {
        provider,
        name: case_name,
        parameters,
        plaintext,
        layout,
    } = case;
    let benchmark_id = || BenchmarkId::new(provider.name(), case_name);
    let mut encrypted_output = vec![
        0;
        usize::try_from(layout.ciphertext_length())
            .expect("benchmark length fits in usize")
    ];

    let mut into_group = criterion.benchmark_group("encrypt_complete_into");
    into_group.sampling_mode(SamplingMode::Flat);
    into_group.throughput(Throughput::Bytes(plaintext.len() as u64));
    into_group.bench_function(benchmark_id(), |bencher| {
        bencher.iter(|| {
            std::hint::black_box(encrypt_complete_into(
                key,
                parameters,
                std::hint::black_box(plaintext),
                &mut encrypted_output,
                layout,
            ));
        });
    });
    into_group.finish();

    let mut in_place_group = criterion.benchmark_group("encrypt_complete_in_place");
    in_place_group.sampling_mode(SamplingMode::Flat);
    in_place_group.throughput(Throughput::Bytes(plaintext.len() as u64));
    // Buffers are allocated once and refilled between iterations. Criterion's
    // warm-up estimate counts untimed setup wall-clock, so per-iteration
    // allocation of LLC-multiple working sets would trip its sample-count
    // warning even though setup is excluded from the measurement.
    let mut buffers = segment_buffers(parameters, layout);
    in_place_group.bench_function(benchmark_id(), |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                refill_plaintext(&mut buffers, plaintext, layout);
                let start = Instant::now();
                std::hint::black_box(encrypt_complete_in_place(key, parameters, &mut buffers));
                elapsed += start.elapsed();
            }
            elapsed
        });
    });
    let mut baseline_buffer = plaintext.to_vec();
    in_place_group.bench_function(baseline_benchmark_id(provider, case_name), |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                baseline_buffer.copy_from_slice(plaintext);
                let start = Instant::now();
                std::hint::black_box(
                    baseline_key.seal_in_place(std::hint::black_box(&mut baseline_buffer)),
                );
                elapsed += start.elapsed();
            }
            elapsed
        });
    });
    in_place_group.finish();
}

fn benchmark_decryption(
    criterion: &mut Criterion,
    key: &Key,
    baseline_key: &BaselineAead,
    case: BenchmarkCase<'_>,
    ciphertext: &[u8],
) {
    let BenchmarkCase {
        provider,
        name: case_name,
        parameters,
        plaintext,
        layout,
    } = case;
    let benchmark_id = || BenchmarkId::new(provider.name(), case_name);
    let plaintext_length =
        usize::try_from(layout.plaintext_length()).expect("benchmark length fits in usize");
    let mut plaintext_output = vec![0; plaintext_length];
    let mut baseline_ciphertext = plaintext.to_vec();
    let baseline_tag = baseline_key.seal_in_place(&mut baseline_ciphertext);
    let mut baseline_round_trip = baseline_ciphertext.clone();
    baseline_key.open_in_place(&baseline_tag, &mut baseline_round_trip);
    assert_eq!(baseline_round_trip, plaintext);
    drop(baseline_round_trip);

    let mut into_group = criterion.benchmark_group("decrypt_complete_into");
    into_group.sampling_mode(SamplingMode::Flat);
    into_group.throughput(Throughput::Bytes(plaintext_length as u64));
    into_group.bench_function(benchmark_id(), |bencher| {
        bencher.iter(|| {
            std::hint::black_box(decrypt_complete_into(
                key,
                std::hint::black_box(ciphertext),
                &mut plaintext_output,
                layout,
            ));
        });
    });
    into_group.finish();

    let mut in_place_group = criterion.benchmark_group("decrypt_complete_in_place");
    in_place_group.sampling_mode(SamplingMode::Flat);
    in_place_group.throughput(Throughput::Bytes(plaintext_length as u64));
    // See encrypt_complete_in_place for why buffers are refilled, not rebuilt.
    let mut buffers = segment_buffers(parameters, layout);
    in_place_group.bench_function(benchmark_id(), |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                refill_ciphertext(&mut buffers, ciphertext, layout);
                let start = Instant::now();
                std::hint::black_box(decrypt_complete_in_place(key, ciphertext, &mut buffers));
                elapsed += start.elapsed();
            }
            elapsed
        });
    });
    let mut baseline_buffer = baseline_ciphertext.clone();
    in_place_group.bench_function(baseline_benchmark_id(provider, case_name), |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                baseline_buffer.copy_from_slice(&baseline_ciphertext);
                let start = Instant::now();
                baseline_key.open_in_place(
                    std::hint::black_box(&baseline_tag),
                    std::hint::black_box(&mut baseline_buffer),
                );
                elapsed += start.elapsed();
            }
            elapsed
        });
    });
    in_place_group.finish();
}

fn baseline_benchmark_id(provider: Provider, case_name: &str) -> BenchmarkId {
    BenchmarkId::new(format!("{}-aes-256-gcm", provider.name()), case_name)
}

fn encrypt_complete_into(
    key: &Key,
    parameters: Parameters,
    plaintext: &[u8],
    ciphertext: &mut [u8],
    layout: MessageLayout,
) -> usize {
    let mut encryptor =
        Some(Encryptor::new(key, AAD, parameters).expect("encryption setup failed"));
    ciphertext[..Header::LEN].copy_from_slice(
        encryptor
            .as_ref()
            .expect("encryptor is present")
            .header()
            .as_ref(),
    );
    let mut written_total = Header::LEN;

    for segment in layout {
        let plaintext_start =
            usize::try_from(segment.plaintext_offset()).expect("offset fits in usize");
        let plaintext_end = plaintext_start + segment.plaintext_length();
        let encrypted_start =
            usize::try_from(segment.ciphertext_offset()).expect("offset fits in usize");
        let encrypted_end = encrypted_start + segment.ciphertext_length();
        let written = match segment.kind() {
            SegmentKind::NonFinal => encryptor
                .as_mut()
                .expect("encryptor is present")
                .encrypt_non_final_segment_into(
                    &plaintext[plaintext_start..plaintext_end],
                    &mut ciphertext[encrypted_start..encrypted_end],
                ),
            SegmentKind::Final => encryptor
                .take()
                .expect("final segment appears once")
                .encrypt_final_segment_into(
                    &plaintext[plaintext_start..plaintext_end],
                    &mut ciphertext[encrypted_start..encrypted_end],
                )
                .map_err(FinalEncryptError::into_error),
        }
        .expect("segment encryption failed");
        written_total += written;
    }
    written_total
}

fn encrypt_complete_in_place(
    key: &Key,
    parameters: Parameters,
    buffers: &mut [SegmentBuffer],
) -> usize {
    let mut encryptor =
        Some(Encryptor::new(key, AAD, parameters).expect("encryption setup failed"));
    let mut written = Header::LEN;
    let last = buffers.len() - 1;
    for (position, buffer) in buffers.iter_mut().enumerate() {
        written += if position == last {
            encryptor
                .take()
                .expect("final segment appears once")
                .encrypt_final_segment_in_place(buffer)
                .map_err(FinalEncryptError::into_error)
        } else {
            encryptor
                .as_mut()
                .expect("encryptor is present")
                .encrypt_non_final_segment_in_place(buffer)
        }
        .expect("in-place segment encryption failed")
        .len();
    }
    written
}

fn decrypt_complete_into(
    key: &Key,
    ciphertext: &[u8],
    plaintext: &mut [u8],
    layout: MessageLayout,
) -> usize {
    let header = Header::try_from(&ciphertext[..Header::LEN]).expect("complete header");
    let mut decryptor = Decryptor::new(key, AAD, &header).expect("decryption setup failed");
    let mut written_total = 0;

    for segment in layout {
        let encrypted_start =
            usize::try_from(segment.ciphertext_offset()).expect("offset fits in usize");
        let encrypted_end = encrypted_start + segment.ciphertext_length();
        let plaintext_start =
            usize::try_from(segment.plaintext_offset()).expect("offset fits in usize");
        let plaintext_end = plaintext_start + segment.plaintext_length();
        written_total += decryptor
            .decrypt_segment_into(
                &ciphertext[encrypted_start..encrypted_end],
                &mut plaintext[plaintext_start..plaintext_end],
            )
            .expect("segment decryption failed");
    }
    decryptor.finish().expect("final segment was present");
    written_total
}

fn decrypt_complete_in_place(key: &Key, ciphertext: &[u8], buffers: &mut [SegmentBuffer]) -> usize {
    let header = Header::try_from(&ciphertext[..Header::LEN]).expect("complete header");
    let mut decryptor = Decryptor::new(key, AAD, &header).expect("decryption setup failed");
    let mut written = 0;
    for buffer in buffers {
        written += decryptor
            .decrypt_segment_in_place(buffer)
            .expect("in-place segment decryption failed")
            .len();
    }
    decryptor.finish().expect("final segment was present");
    written
}

fn segment_buffers(parameters: Parameters, layout: MessageLayout) -> Vec<SegmentBuffer> {
    layout
        .into_iter()
        .map(|_| SegmentBuffer::new(parameters))
        .collect()
}

fn refill_plaintext(buffers: &mut [SegmentBuffer], plaintext: &[u8], layout: MessageLayout) {
    for (buffer, segment) in buffers.iter_mut().zip(layout) {
        let start = usize::try_from(segment.plaintext_offset()).expect("offset fits in usize");
        let end = start + segment.plaintext_length();
        buffer
            .prepare_plaintext(segment.plaintext_length())
            .expect("valid plaintext length")
            .copy_from_slice(&plaintext[start..end]);
    }
}

fn refill_ciphertext(buffers: &mut [SegmentBuffer], ciphertext: &[u8], layout: MessageLayout) {
    for (buffer, segment) in buffers.iter_mut().zip(layout) {
        let start = usize::try_from(segment.ciphertext_offset()).expect("offset fits in usize");
        let end = start + segment.ciphertext_length();
        buffer
            .prepare_ciphertext(segment.ciphertext_length())
            .expect("valid encrypted length")
            .copy_from_slice(&ciphertext[start..end]);
    }
}

/// Pick per-case message lengths from the detected last-level cache size so
/// the benchmark measures main-memory throughput rather than cache residency.
fn target_length(parameters: Parameters, minimum_target: usize) -> usize {
    let segment_target = parameters
        .plaintext_segment_length()
        .checked_mul(MIN_SEGMENT_COUNT)
        .expect("benchmark segment target fits in usize");

    minimum_target.max(segment_target)
}

fn target_lengths() -> (usize, usize) {
    if let Some(llc) = last_level_cache_size() {
        let cache_target = llc
            .checked_mul(LLC_MULTIPLE)
            .expect("benchmark cache target fits in usize");
        let small = target_length(Parameters::SEGMENT_4_KIB, cache_target);
        let large = target_length(Parameters::SEGMENT_1_MIB, cache_target);
        eprintln!(
            "detected {} last-level cache; minimum working set: {}; message targets: {} (4KiB segments), {} (1MiB segments)",
            format_size(llc),
            format_size(cache_target),
            format_size(small),
            format_size(large),
        );
        (small, large)
    } else {
        let small = target_length(Parameters::SEGMENT_4_KIB, DEFAULT_SMALL_SEGMENT_TARGET);
        let large = target_length(Parameters::SEGMENT_1_MIB, DEFAULT_LARGE_SEGMENT_TARGET);
        eprintln!(
            "unable to detect last-level cache size; using fallback message targets: {} and {}",
            format_size(small),
            format_size(large),
        );
        (small, large)
    }
}

fn format_size(bytes: usize) -> String {
    if bytes.is_multiple_of(MIB) {
        format!("{}MiB", bytes / MIB)
    } else if bytes.is_multiple_of(KIB) {
        format!("{}KiB", bytes / KIB)
    } else {
        format!("{bytes}B")
    }
}

/// Largest data or unified cache reported by sysfs for cpu0. On multi-die
/// parts this is one die's share of the total, which still bounds the
/// working set a single benchmark thread can keep resident.
#[cfg(target_os = "linux")]
fn last_level_cache_size() -> Option<usize> {
    let entries = std::fs::read_dir("/sys/devices/system/cpu/cpu0/cache").ok()?;
    let mut last_level: Option<(u32, usize)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = std::fs::read_to_string(path.join("type")) else {
            continue;
        };
        if kind.trim() == "Instruction" {
            continue;
        }
        let Some(level) = std::fs::read_to_string(path.join("level"))
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
        else {
            continue;
        };
        let Some(size) = std::fs::read_to_string(path.join("size"))
            .ok()
            .as_deref()
            .and_then(parse_cache_size)
        else {
            continue;
        };
        if last_level.is_none_or(|(best_level, _)| level > best_level) {
            last_level = Some((level, size));
        }
    }
    last_level.map(|(_, size)| size)
}

/// Parses sysfs cache sizes such as `32768K`.
#[cfg(target_os = "linux")]
fn parse_cache_size(text: &str) -> Option<usize> {
    let text = text.trim();
    let (digits, multiplier) = match text.as_bytes().last()? {
        b'K' => (&text[..text.len() - 1], KIB),
        b'M' => (&text[..text.len() - 1], MIB),
        _ => (text, 1),
    };
    let value = digits.parse::<usize>().ok()?;
    Some(value * multiplier)
}

/// Intel Macs report an L3; Apple Silicon has no L3, so the
/// performance cores' shared L2 is the last-level cache.
#[cfg(target_os = "macos")]
fn last_level_cache_size() -> Option<usize> {
    [
        "hw.l3cachesize",
        "hw.perflevel0.l2cachesize",
        "hw.l2cachesize",
    ]
    .into_iter()
    .find_map(sysctl_size)
}

#[cfg(target_os = "macos")]
fn sysctl_size(name: &str) -> Option<usize> {
    let output = std::process::Command::new("sysctl")
        .args(["-n", name])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout)
        .ok()?
        .trim()
        .parse::<usize>()
        .ok()?;
    (value > 0).then_some(value)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn last_level_cache_size() -> Option<usize> {
    None
}

criterion_group! {
    name = benches;
    // 10 samples (the Criterion minimum) keeps sample_size * iteration_time
    // within the 3s measurement window for the selected message sizes, so
    // Criterion does not warn about sample counts.
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    targets = benchmark_backend_matrix
}
criterion_main!(benches);
