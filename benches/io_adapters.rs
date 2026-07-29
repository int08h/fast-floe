//! Criterion benchmarks for the `std::io` adapters and the random-access
//! reader.
//!
//! These cover the adapter overhead above the raw segment operations that
//! `benches/backend_matrix.rs` measures: staging copies, segment framing over
//! streams, and per-segment seeks. Buffers are allocated once and reused so
//! allocator placement does not dominate the measurement (see the in-place
//! arena comment in `backend_matrix.rs`).

use std::io::{Cursor, Read, Write};
use std::time::Duration;

use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use fast_floe::io::{DecryptReader, EncryptReader, EncryptWriter};
use fast_floe::random_access::Reader as RandomAccessReader;
use fast_floe::{Key, Parameters, Provider, encrypt};

const AAD: &[u8] = b"adapter-benchmark";
const KEY_BYTES: [u8; 32] = [0x42; 32];
const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

/// Large enough that both parameter cases stream several times the last-level
/// cache of the dev machines this crate is benchmarked on.
const MESSAGE_LENGTH: usize = 128 * MIB;

/// Sub-segment read size exercising the buffered (copy-out) adapter paths.
const SMALL_CHUNK: usize = KIB;

struct AdapterCase {
    provider: Provider,
    name: String,
    parameters: Parameters,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn benchmark_io_adapters(criterion: &mut Criterion) {
    let parameter_cases = [
        ("4KiB-segments_128MiB", Parameters::SEGMENT_4_KIB),
        ("1MiB-segments_128MiB", Parameters::SEGMENT_1_MIB),
    ];

    for &provider in Provider::COMPILED {
        let key = Key::from_bytes_with_provider(KEY_BYTES, provider);
        for (case_name, parameters) in &parameter_cases {
            let plaintext = vec![0x5a; MESSAGE_LENGTH];
            let ciphertext = encrypt(&key, AAD, *parameters, &plaintext)
                .expect("benchmark setup encryption failed");
            let case = AdapterCase {
                provider,
                name: (*case_name).to_string(),
                parameters: *parameters,
                plaintext,
                ciphertext,
            };

            benchmark_encrypt_writer(criterion, &key, &case);
            benchmark_encrypt_reader(criterion, &key, &case);
            benchmark_decrypt_reader(criterion, &key, &case);
            benchmark_random_reader(criterion, &key, &case);
        }
    }
}

fn benchmark_encrypt_writer(criterion: &mut Criterion, key: &Key, case: &AdapterCase) {
    let mut group = criterion.benchmark_group("encrypt_writer_write_all");
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Bytes(case.plaintext.len() as u64));
    group.bench_function(BenchmarkId::new(case.provider.name(), &case.name), |b| {
        b.iter(|| {
            let mut writer = EncryptWriter::new(std::io::sink(), key, AAD, case.parameters)
                .expect("writer setup failed");
            writer
                .write_all(std::hint::black_box(&case.plaintext))
                .expect("write failed");
            writer.finish().expect("finish failed");
        });
    });
    group.finish();
}

fn benchmark_encrypt_reader(criterion: &mut Criterion, key: &Key, case: &AdapterCase) {
    let chunk_cases = [
        (
            "segment_chunks",
            case.parameters.ciphertext_segment_length(),
        ),
        ("small_chunks", SMALL_CHUNK),
    ];
    for (chunk_name, chunk_length) in chunk_cases {
        let mut group = criterion.benchmark_group(format!("encrypt_reader_{chunk_name}"));
        group.sampling_mode(SamplingMode::Flat);
        group.throughput(Throughput::Bytes(case.plaintext.len() as u64));
        let mut chunk = vec![0u8; chunk_length];
        group.bench_function(BenchmarkId::new(case.provider.name(), &case.name), |b| {
            b.iter(|| {
                let mut reader = EncryptReader::new(
                    Cursor::new(case.plaintext.as_slice()),
                    key,
                    AAD,
                    case.parameters,
                )
                .expect("reader setup failed");
                let mut total = 0usize;
                loop {
                    let read = reader.read(&mut chunk).expect("read failed");
                    if read == 0 {
                        break;
                    }
                    total += read;
                }
                assert_eq!(total, case.ciphertext.len());
                std::hint::black_box(total)
            });
        });
        group.finish();
    }
}

fn benchmark_decrypt_reader(criterion: &mut Criterion, key: &Key, case: &AdapterCase) {
    let chunk_cases = [
        (
            "segment_chunks",
            case.parameters.ciphertext_segment_length(),
        ),
        ("small_chunks", SMALL_CHUNK),
    ];
    for (chunk_name, chunk_length) in chunk_cases {
        let mut group = criterion.benchmark_group(format!("decrypt_reader_{chunk_name}"));
        group.sampling_mode(SamplingMode::Flat);
        group.throughput(Throughput::Bytes(case.plaintext.len() as u64));
        let mut chunk = vec![0u8; chunk_length];
        group.bench_function(BenchmarkId::new(case.provider.name(), &case.name), |b| {
            b.iter(|| {
                let mut reader =
                    DecryptReader::new(Cursor::new(case.ciphertext.as_slice()), key, AAD)
                        .expect("reader setup failed");
                let mut total = 0usize;
                loop {
                    let read = reader.read(&mut chunk).expect("read failed");
                    if read == 0 {
                        break;
                    }
                    total += read;
                }
                assert_eq!(total, case.plaintext.len());
                std::hint::black_box(total)
            });
        });
        group.finish();
    }
}

fn benchmark_random_reader(criterion: &mut Criterion, key: &Key, case: &AdapterCase) {
    let mut sequential_group = criterion.benchmark_group("random_reader_sequential");
    sequential_group.sampling_mode(SamplingMode::Flat);
    sequential_group.throughput(Throughput::Bytes(case.plaintext.len() as u64));
    let mut chunk = vec![0u8; case.parameters.plaintext_segment_length()];
    sequential_group.bench_function(BenchmarkId::new(case.provider.name(), &case.name), |b| {
        b.iter(|| {
            let mut reader =
                RandomAccessReader::new(Cursor::new(case.ciphertext.as_slice()), key, AAD)
                    .expect("reader setup failed");
            let mut total = 0usize;
            loop {
                let read = reader.read(&mut chunk).expect("read failed");
                if read == 0 {
                    break;
                }
                total += read;
            }
            assert_eq!(total, case.plaintext.len());
            std::hint::black_box(total)
        });
    });
    sequential_group.finish();

    let mut range_group = criterion.benchmark_group("random_reader_read_range");
    range_group.sampling_mode(SamplingMode::Flat);
    range_group.throughput(Throughput::Bytes(case.plaintext.len() as u64));
    let mut output = vec![0u8; case.plaintext.len()];
    range_group.bench_function(BenchmarkId::new(case.provider.name(), &case.name), |b| {
        b.iter(|| {
            let mut reader =
                RandomAccessReader::new(Cursor::new(case.ciphertext.as_slice()), key, AAD)
                    .expect("reader setup failed");
            let written = reader
                .read_range_into(.., std::hint::black_box(&mut output[..]))
                .expect("range read failed");
            assert_eq!(written, case.plaintext.len());
            std::hint::black_box(written)
        });
    });
    range_group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    targets = benchmark_io_adapters
}
criterion_main!(benches);
