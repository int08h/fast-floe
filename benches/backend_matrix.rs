use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fast_floe::low_level::SegmentBuffer;
use fast_floe::online::{Decryptor, Encryptor, FinalEncryptError};
use fast_floe::random_access::MessageLayout;
use fast_floe::{Header, Key, Parameters, Provider, SegmentKind, encrypt};

const AAD: &[u8] = b"benchmark";
const MIB: usize = 1024 * 1024;

fn benchmark_backend_matrix(criterion: &mut Criterion) {
    for &provider in Provider::COMPILED {
        let key = Key::from_bytes_with_provider([0x42; Key::LEN], provider);
        for (case_name, parameters, target_length) in [
            (
                "4KiB-segments_4MiB-target",
                Parameters::SEGMENT_4_KIB,
                4 * MIB,
            ),
            (
                "1MiB-segments_64MiB-target",
                Parameters::SEGMENT_1_MIB,
                64 * MIB,
            ),
        ] {
            let plaintext = vec![0x5a; target_length];
            let layout = parameters
                .plaintext_layout(
                    u64::try_from(plaintext.len()).expect("target length fits in u64"),
                )
                .expect("benchmark layout must be valid");
            let ciphertext = encrypt(&key, AAD, parameters, &plaintext)
                .expect("benchmark setup encryption failed");

            benchmark_encryption(
                criterion, &key, provider, case_name, parameters, &plaintext, layout,
            );
            benchmark_decryption(
                criterion,
                &key,
                provider,
                case_name,
                parameters,
                &ciphertext,
                layout,
            );
        }
    }
}

fn benchmark_encryption(
    criterion: &mut Criterion,
    key: &Key,
    provider: Provider,
    case_name: &str,
    parameters: Parameters,
    plaintext: &[u8],
    layout: MessageLayout,
) {
    let benchmark_id = || BenchmarkId::new(provider.name(), case_name);
    let mut encrypted_output = vec![
        0;
        usize::try_from(layout.ciphertext_length())
            .expect("benchmark length fits in usize")
    ];

    let mut into_group = criterion.benchmark_group("encrypt_complete_into");
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
    in_place_group.throughput(Throughput::Bytes(plaintext.len() as u64));
    in_place_group.bench_function(benchmark_id(), |bencher| {
        bencher.iter_batched_ref(
            || plaintext_buffers(parameters, plaintext, layout),
            |buffers| {
                std::hint::black_box(encrypt_complete_in_place(key, parameters, buffers));
            },
            BatchSize::NumIterations(1),
        );
    });
    in_place_group.finish();
}

fn benchmark_decryption(
    criterion: &mut Criterion,
    key: &Key,
    provider: Provider,
    case_name: &str,
    parameters: Parameters,
    ciphertext: &[u8],
    layout: MessageLayout,
) {
    let benchmark_id = || BenchmarkId::new(provider.name(), case_name);
    let plaintext_length =
        usize::try_from(layout.plaintext_length()).expect("benchmark length fits in usize");
    let mut plaintext_output = vec![0; plaintext_length];

    let mut into_group = criterion.benchmark_group("decrypt_complete_into");
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
    in_place_group.throughput(Throughput::Bytes(plaintext_length as u64));
    in_place_group.bench_function(benchmark_id(), |bencher| {
        bencher.iter_batched_ref(
            || ciphertext_buffers(parameters, ciphertext, layout),
            |buffers| {
                std::hint::black_box(decrypt_complete_in_place(key, ciphertext, buffers));
            },
            BatchSize::NumIterations(1),
        );
    });
    in_place_group.finish();
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

fn plaintext_buffers(
    parameters: Parameters,
    plaintext: &[u8],
    layout: MessageLayout,
) -> Vec<SegmentBuffer> {
    layout
        .into_iter()
        .map(|segment| {
            let start = usize::try_from(segment.plaintext_offset()).expect("offset fits in usize");
            let end = start + segment.plaintext_length();
            let mut buffer = SegmentBuffer::new(parameters);
            buffer
                .prepare_plaintext(segment.plaintext_length())
                .expect("valid plaintext length")
                .copy_from_slice(&plaintext[start..end]);
            buffer
        })
        .collect()
}

fn ciphertext_buffers(
    parameters: Parameters,
    ciphertext: &[u8],
    layout: MessageLayout,
) -> Vec<SegmentBuffer> {
    layout
        .into_iter()
        .map(|segment| {
            let start = usize::try_from(segment.ciphertext_offset()).expect("offset fits in usize");
            let end = start + segment.ciphertext_length();
            let mut buffer = SegmentBuffer::new(parameters);
            buffer
                .prepare_ciphertext(segment.ciphertext_length())
                .expect("valid encrypted length")
                .copy_from_slice(&ciphertext[start..end]);
            buffer
        })
        .collect()
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = benchmark_backend_matrix
}
criterion_main!(benches);
