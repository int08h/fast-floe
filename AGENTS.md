# Repository Guidelines

## Project Structure & Module Organization

`fast-floe` is a Rust 2024 library crate. Public entry points live in `src/lib.rs`; higher-level APIs are organized under `src/io.rs`, `src/online.rs`, and `src/random_access.rs`. Provider selection and cryptographic implementations are in `src/provider.rs` and `src/backends.rs`, while framing and state-machine details remain internal or are exposed through `low_level`.

Most unit and interoperability tests live in `src/tests.rs`, with focused module tests beside their implementations. `kats/` contains vendored known-answer vectors; preserve their upstream filenames and contents. `tests/fixtures/provider-unification/` is a standalone workspace that checks Cargo feature unification. Examples are under `examples/`, and Criterion benchmarks are in `benches/backend_matrix.rs`.

## Build, Test, and Development Commands

- `cargo build` builds with the default `aws-lc-rs` provider.
- `cargo test --all-targets` runs library, example, and benchmark-target tests; `cargo test --doc` validates README-backed doctests.
- `cargo test --no-default-features --features ring` tests one provider explicitly. Substitute `aws-lc-rs`, `boring`, `ring`, or `rustcrypto` as needed.
- `cargo test --manifest-path tests/fixtures/provider-unification/Cargo.toml` validates additive provider selection across dependent crates.
- `cargo +nightly fmt --check` applies the repository's nightly rustfmt settings.
- `cargo clippy --all-targets --all-features -- -D warnings` enforces lint cleanliness.
- `./scripts/bench-matrix.sh` runs the offline Criterion provider matrix after dependencies are cached.

## Coding Style & Naming Conventions

Use four-space rustfmt formatting and idiomatic Rust naming: `snake_case` for functions/modules, `PascalCase` for types, and `SCREAMING_SNAKE_CASE` for constants. The crate forbids unsafe code and enables Clippy's `all` and `pedantic` groups. Keep common workflows in safe, high-level APIs; place sharp primitives behind `low_level`. Document public behavior, error cases, and framing/finalization obligations.

## Testing Guidelines

Name tests after observable behavior, such as `every_truncation_of_valid_ciphertext_rejected`. Add focused regression tests for boundary lengths, authentication failures, final segments, and provider interoperability. Do not update KATs merely to make a test pass; wire-format changes must remain specification-compatible. Run the default suite, relevant single-provider configurations, and doctests before submitting. Compile each provider one at a time (do not use --all-features) when benchmarking.

## Commit & Pull Request Guidelines

History favors short, imperative summaries such as `Support additive encryption providers` or `Refresh README`. Keep each commit focused and include tests with behavioral changes. Pull requests should explain the caller-visible effect, identify provider/feature combinations tested, link relevant issues, and include before/after Criterion results for performance-sensitive changes. Never add a "Co-Authored-By" line to commits.

## Communication

Only use ASCII for all communications, commit messages, comments, PRs, etc. Never use emojis or unicode in communications.
