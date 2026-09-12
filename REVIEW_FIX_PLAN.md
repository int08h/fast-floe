# Review findings implementation plan

Base: `9d0e198`. This plan and its implementation are AI-assisted using Codex.

Address the five reviewed findings while preserving public signatures, provider
selection, and the FLOE wire format. Keep each fix in a focused commit with its
tests. Implement findings 1 and 3 consecutively because they share decryption
helpers. Broader API renaming and whole-message encoder refactoring are separate
work.

## 1. Validate complete segments before allocation

- Extract the declared-versus-actual ciphertext length check into one private
  helper used by allocating, separate-output, and buffered framed decryption.
- Validate before allocating plaintext and avoid repeating the check before the
  crypto operation. Length validation does not authenticate framing.
- Preserve length diagnostics, position tracking, and successful retry behavior.
- Test short final and non-final segments, both directions of length mismatch,
  equivalent errors across output paths, and retry at the same position.
- Repeat the bounded 64 MiB profile/four-byte input memory reproduction in a
  separate process. Functional error assertions alone cannot detect allocation
  ordering; keep platform-dependent RSS thresholds outside unit tests.

Acceptance: malformed input is rejected before allocation proportional to its
claimed length; valid segments and retries continue to work.

## 2. Redact plaintext-bearing Debug output

- Replace SegmentBuffer's derived Debug with metadata-only formatting:
  parameters, capacity, and logical state, with no backing bytes.
- Omit EncryptReader's plaintext lookahead byte from diagnostic output.
- Test normal and alternate formatting, prepared and authenticated plaintext,
  stale bytes beyond a shortened payload, ciphertext, and empty buffers.
- Check enclosing adapter formatting using redacted underlying I/O objects so
  the tests isolate storage owned by this crate.

Acceptance: debug formatting exposes no current or stale crate-owned payload.

## 3. Enforce one buffered-decryption cleanup boundary

- Have validation and authentication produce Result<usize>, then apply the
  buffer transition exactly once at the outer operation boundary.
- On success expose authenticated plaintext; on any failure zeroize the whole
  allocation and mark it empty, including early validation failures.
- Apply the rule consistently to low-level and online SegmentBuffer operations.
  Preserve online position on error and document that retry requires refilling
  the cleared buffer. Raw caller-managed slices retain their own error contract.
- Cover invalid preparation, parameter/layout mismatches, malformed framing,
  authentication failure, closed states, segment limits, stale bytes, successful
  empty-final decryption, and retry after refilling.

Acceptance: every failed buffered decryption leaves zeroized, empty storage and
does not consume an online segment position.

## 4. Make whole-stream finalization idempotent

- Give DecryptReader private Open, FrameComplete, StreamComplete, and Failed
  lifecycle states. Encryption adapters retain their existing lifecycle.
- Frame finalization drains without checking EOF. Whole-stream finalization
  checks EOF once and records success; later finalization does no further I/O.
- Preserve is_finished's meaning: final segment authenticated and plaintext
  consumed. Document that it does not establish underlying EOF.
- Mutable underlying access invalidates verified EOF, returning StreamComplete
  to FrameComplete so a subsequent finalization checks the changed source.
- Test with a counting reader that errors after its first EOF, including
  repeated finalization, consuming finish after try_finish, frame then stream
  completion, trailing bytes, EOF errors, mutable access, buffered reads, and
  direct-output reads.

Acceptance: successful finalization is idempotent until mutable access invalidates
EOF verification, and frame finalization preserves following bytes.

## 5. Correct provider flags in file examples

- Update all four commands in serial_file.rs and manual_file.rs to use
  --no-default-features --features ring.
- Search other documentation for equivalent commands and keep them consistent.
- Run both examples' encrypt/decrypt round trips in temporary directories and
  compare recovered bytes with the originals. No documentation-only unit test
  is required.

Acceptance: the documented commands select ring alone and work.

## Validation

Run focused regressions first, followed by:

```sh
cargo test --all-targets
cargo test --doc
for provider in ring rustcrypto boring; do
    cargo test --all-targets --no-default-features --features "$provider"
done
cargo test --all-targets --all-features
cargo test --manifest-path tests/fixtures/provider-unification/Cargo.toml
cargo +nightly fmt --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Record before/after Criterion results for segment decryption and DecryptReader,
with each provider compiled alone and the same build and benchmark settings.
Preserve KATs and verify interoperability. Record actual outcomes below, including
limitations of short benchmark runs. Keep all newly authored text ASCII.

## Execution record

- Plan saved before implementation. Baseline source and benchmark measurements
  will be retained outside the working tree during implementation.
