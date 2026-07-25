# Numeric Conversion Cleanup Plan

Status: amended after review, implemented by the accompanying commits. The
amendments are integrated into the phases below and summarized in "Review
amendments" at the end.

This plan addresses the results of an audit of every numeric conversion in
`fast-floe`. It is ordered so that the target-width contract and
security-sensitive framing hardening land first, independently of the
mechanical cleanup. All new conversion helpers, constants, and accessors are
crate-private; this work does not require a public API change.

## Background

The crate performs 34 numeric conversions in non-test code, confined to four
files:

| File | Sites |
| --- | --- |
| `src/parameters.rs` | 14 |
| `src/random_access.rs` | 14 |
| `src/online.rs` | 3 |
| `src/state.rs` | 3 |

`src/io.rs`, `src/wire.rs`, `src/buffer.rs`, `src/key.rs`, and `src/backends.rs`
contain none; they operate in `usize` end to end.

Of the 34 sites, only three can propagate a conversion failure or change
control flow on a target this crate supports:

- `src/online.rs:521` - `usize::try_from(layout.ciphertext_length())` sizing a `Vec`
- `src/random_access.rs:182` - `usize::try_from(range.end - range.start)` sizing a `Vec`
- `src/random_access.rs:203` - the same, for the caller-supplied-buffer variant

Each is a message larger than a 32-bit address space. Those three checks are
correct and this plan does not touch them.

The remaining 31 sites fall into six patterns:

- **A. `usize` constant to `u64`** (7 sites): `HEADER_LENGTH` (74),
  `SEGMENT_OVERHEAD` (32), `Header::LEN` (74) converted with a fallible
  `try_from` at `parameters.rs:155,418,421,448,471` and
  `random_access.rs:360,466`. Every associated error branch is unreachable on
  any conceivable target.
- **B. `u32` laundered through `usize` and back to `u64`** (6 sites):
  `parameters.rs:135,137,405,461` and `random_access.rs:225,386`. The
  `Parameters::ciphertext_segment_length` field is a `u32`; the public accessor
  widens it to `usize`, and these callers then narrow-check it back to `u64`.
  The round trip through `usize` is what manufactures the fallibility.
- **C. runtime `usize` to `u64`** (5 sites): `online.rs:517`,
  `random_access.rs:235,254,264,397`. Infallible on every target admitted by
  the contract introduced in Phase 1, but not provable through the type system
  because `std` declines to provide `From<usize> for u64`.
- **D. `u64` to `usize` bounded by a layout invariant** (6 sites):
  `parameters.rs:149`, `online.rs:528`, `random_access.rs:249,256,393`, plus
  `state.rs:362` (`u32::try_from`). Each is bounded by segment arithmetic, but
  the bound lives in the layout math rather than in a type.
- **E. `u64` to `usize` used only for bounded error diagnostics** (3 sites):
  `usize::try_from(len).unwrap_or(usize::MAX)` at `parameters.rs:453,475` and
  `random_access.rs:469`. The observable error paths bound header lengths below
  74 and final-segment lengths below 32. The first site is currently evaluated
  eagerly through `Option::ok_or`, even when no error is returned; Phase 4
  makes that construction lazy before relying on the bound.
- **F. bare `as` casts on the `u32` to `usize` direction** (4 sites):
  `parameters.rs:305,381` and `state.rs:417,420`. Two of these sit on the
  authentication path.

### Verified platform facts

These were confirmed by compiling each form under the crate's lint
configuration (`clippy::all` + `clippy::pedantic` at warn), not assumed:

| Form | Result |
| --- | --- |
| `usize as u64` | no lint |
| `u32 as usize` | no lint |
| `u64 as usize` | warns (`cast_possible_truncation`) |
| `usize as u32` | warns (`cast_possible_truncation`) |
| `u64::from(x: u32)` | infallible `From` impl exists |
| `u64::from(x: usize)` | does not compile; no such impl |
| `const X: u64 = HEADER_LENGTH as u64` | const-evaluates, no lint |

Clippy declining to lint `usize as u64` is consistent with current Rust target
widths, but the language does not encode the guarantee needed by this crate.
Phase 1 makes the crate's 32- or 64-bit requirement explicit.

## Phase 1: Enforce the target contract and harden framing

### 1.1 The problem

`SegmentFraming::decode` (`parameters.rs:299-328`) reads an
**attacker-controlled** 32-bit segment length prefix and narrows it with a bare
cast before validating it:

```rust
let encoded = u32::from_be_bytes(prefix);
// ...
let length = encoded as usize;                                  // line 305
let valid_range = SEGMENT_OVERHEAD..=parameters.ciphertext_segment_length();
if !valid_range.contains(&length) { /* reject */ }
```

`validate_segment` (`state.rs:410-427`) does the same on the equality path:

```rust
SegmentKind::Final if prefix as usize != ciphertext_segment.len() => { /* reject */ }
```

On a target with a 16-bit `usize`, `encoded as usize` discards the high half.
A forged prefix of `69632` (`0x0001_1000`) truncates to `4096`, which passes the
range check for `Parameters::SEGMENT_4_KIB` and compares equal to a 4096-byte
segment. The validation would accept a prefix whose true value it should have
rejected.

This is **not exploitable on any target the crate can currently be built for**.
No 16-bit `std` target exists, and `fast-floe` requires `std` (`Box`, `Vec`,
`std::io`). It is recorded here because it is the only place where a width
assumption sits on the authentication path rather than in bookkeeping, and
because the assumption is currently unstated and unchecked.

### 1.2 Root cause is broader than the prefix check

On a 16-bit target the crate is already broken in a more basic way:
`Parameters::SEGMENT_1_MIB` has a `ciphertext_segment_length` of `1_048_576`,
and `ciphertext_segment_length()` (`parameters.rs:381`) returns
`1_048_576 as usize`, which is `0`. Every length calculation derived from it
would be nonsense. The prefix truncation is a symptom of an unenforced
platform contract, not an isolated bug.

The fix is therefore to *enforce the contract*, and additionally to make the
authentication-path comparison width-independent so the property is locally
evident rather than dependent on an assertion in another module.

### 1.3 Task: state the platform contract as a build-time assertion

Add to `src/parameters.rs`, beside the existing
`const _: () = assert!(HEADER_LENGTH == 74, ...)`:

```rust
// Every length in this crate crosses between usize and the u32 wire format or
// u64 message arithmetic. A 16-bit usize cannot represent SEGMENT_1_MIB and
// would silently truncate attacker-controlled segment prefixes; a usize wider
// than u64 would break the message-length conversions. Fail the build instead.
const _: () = assert!(
    usize::BITS >= 32 && usize::BITS <= 64,
    "fast-floe supports only 32-bit and 64-bit targets"
);
```

Verified: a violating configuration produces `error[E0080]: evaluation
panicked: fast-floe supports only 32-bit and 64-bit targets` at compile time.
This converts a silent miscompile into a build failure and makes every
`u32 as usize` and `usize as u64` in the crate lossless by construction.

### 1.4 Task: centralize the lossless length conversions

Add two crate-private helpers in `src/parameters.rs`, one per direction. Both
are justified by the same `usize::BITS` assertion, so they are introduced
together here (amendment: the second helper originally arrived in Phase 2, but
Phase 1.5 needs it to compare prefixes without adding a panic path). These are
the only bare `u32 as usize` and `usize as u64` conversions needed after the
cleanup:

```rust
/// Converts a wire-format length to the crate's in-memory length type.
///
/// Lossless on every supported target; see the `usize::BITS` assertion above.
#[inline]
pub(crate) const fn length_u32_to_usize(value: u32) -> usize {
    value as usize
}

/// Converts an in-memory length to the crate's message-arithmetic type.
///
/// Lossless on every supported target; see the `usize::BITS` assertion above.
/// `std` provides no `From<usize> for u64`, so this documents the assumption
/// once instead of at each call site.
#[inline]
pub(crate) const fn length_usize_to_u64(value: usize) -> u64 {
    value as u64
}
```

Keep them internal by re-exporting them only through the existing `pub(crate)
use parameters::{...}` list in `src/lib.rs` if sibling modules need them. Do
not add any public conversion helper.

Add the one `u32`-typed `Parameters` accessor needed by framing. Phase 2 adds
the corresponding plaintext accessor for arithmetic cleanup:

```rust
pub(crate) const fn ciphertext_segment_length_u32(self) -> u32 {
    self.ciphertext_segment_length
}
```

Declare the `u32` mirror of `SEGMENT_OVERHEAD` primitively and cross-check it,
following the existing `FLOE_IV_LENGTH_U32` precedent at `parameters.rs:28`.
Note that `SEGMENT_OVERHEAD as u32` is *not* usable here - it trips
`cast_possible_truncation` on 64-bit targets:

```rust
pub(crate) const SEGMENT_OVERHEAD_U32: u32 = 32;
const _: () = assert!(length_u32_to_usize(SEGMENT_OVERHEAD_U32) == SEGMENT_OVERHEAD);
```

While there, add the same cross-check to the existing `FLOE_IV_LENGTH_U32`,
which currently has no assertion tying it to `FLOE_IV_LENGTH`.

### 1.5 Task: validate prefixes in their wire-format width

In `SegmentFraming::decode`, validate in `u32` space. Convert to `usize` only
for the public error fields and the successfully decoded result:

```rust
let ciphertext_length = if encoded == u32::MAX {
    parameters.ciphertext_segment_length()
} else {
    // Validated in u32 space: the range check must not depend on the width of
    // usize, because `encoded` is attacker-controlled and unauthenticated.
    let maximum = parameters.ciphertext_segment_length_u32();
    if !(SEGMENT_OVERHEAD_U32..=maximum).contains(&encoded) {
        return Err(Error::InvalidCiphertextLength {
            actual: length_u32_to_usize(encoded),
            required: LengthRequirement::Between {
                minimum: SEGMENT_OVERHEAD,
                maximum: parameters.ciphertext_segment_length(),
            },
        });
    }
    length_u32_to_usize(encoded)
};
```

In `validate_segment`, compare in `u64` space, where both sides convert
losslessly. This keeps the comparison width-independent without introducing a
panic path on the authentication path (amendment: an earlier draft converted
with `u32::try_from(...).expect(...)`, which is provable from the length check
at the top of the function but adds a panic branch where none exists today;
the `u64` comparison needs no proof at all):

```rust
match kind {
    // Compared in u64 space: the equality must not depend on the width of
    // usize, because `prefix` is attacker-controlled and unauthenticated.
    SegmentKind::Final
        if u64::from(prefix) != length_usize_to_u64(ciphertext_segment.len()) =>
    {
        return Err(Error::InvalidCiphertextLength {
            actual: ciphertext_segment.len(),
            required: LengthRequirement::Exactly(length_u32_to_usize(prefix)),
        });
    }
    // Existing non-final and catch-all arms remain unchanged.
}
```

This removes both bare casts at `state.rs:417,420`. It also keeps the
final-length comparison distinct from the `u32::MAX` non-final sentinel.

### 1.6 Task: document the sentinel invariant

`state.rs:362` encodes a final segment's length as
`u32::try_from(required).map_err(|_| Error::LengthOverflow)?`. This cannot fail:
`ciphertext_segment_size` bounds `required` at `ciphertext_segment_length`, so
at most 1 MiB. That bound is also what keeps a final length from ever colliding
with the `u32::MAX` non-final sentinel, which is currently load-bearing and
undocumented. Add a comment stating both facts. Leave the `try_from` in place -
it is cheap and the invariant lives in another function.

### 1.7 Tests

Name tests after observable behavior, per `AGENTS.md`.

- `segment_framing_rejects_prefix_whose_low_bits_look_valid` - decode a prefix
  of `69632` against `SEGMENT_4_KIB` and assert
  `Error::InvalidCiphertextLength`. Also `1_048_576 + 4096` against
  `SEGMENT_4_KIB`. This already passes on every supported target, so treat it as
  a characterization test that documents the truncation class, not as a
  red-green regression test. Include a comment naming the 16-bit truncation it
  guards against, so it is not "simplified" later.
- `final_segment_prefix_must_equal_actual_segment_length` - use the internal
  explicit-kind `DecryptionState::decrypt_segment_at` path with a prefix that
  differs from the real length only in bits above the low 16. Calling through
  the online decryptor is insufficient because `SegmentFraming::decode` can
  reject the prefix before `validate_segment` is exercised. This is also a
  characterization test on supported targets. Assert the exact
  `Error::InvalidCiphertextLength` variant: the rejection happens before any
  authentication is attempted, and the test should pin that.
- Do not add a runtime pointer-width test. The compile-time assertion is the
  contract, and an unsupported target cannot compile far enough to run a test.
- Confirm the existing `segment_prefix_classification_exposes_valid_framing`
  (`tests.rs:470`) still passes unchanged; it covers the accepted boundaries
  `SEGMENT_OVERHEAD`, `SEGMENT_OVERHEAD + 7`, `ciphertext_segment_length`, and
  the rejected `SEGMENT_OVERHEAD - 1` and `ciphertext_segment_length + 1`.
- Re-run the KAT suite. No wire-format change is intended: the accepted set of
  prefixes is identical on 32- and 64-bit targets. Do not touch `kats/`.

## Phase 2: Eliminate constant and `u32` round trips

Pattern A and B, 13 sites. Mechanical, no behavior change on any supported
target, and each removal deletes an unreachable error branch.

### 2.1 Fixed-width constants

`length_usize_to_u64` already exists (Phase 1.4, amended). Use it to define
the fixed-width internal constants:

```rust
pub(crate) const HEADER_LENGTH_U64: u64 = length_usize_to_u64(HEADER_LENGTH);
pub(crate) const SEGMENT_OVERHEAD_U64: u64 = length_usize_to_u64(SEGMENT_OVERHEAD);
```

Both const-evaluate and neither trips a lint. Replace at:

- `parameters.rs:155` - `u64::try_from(HEADER_LENGTH).ok()?`
- `parameters.rs:418` - `u64::try_from(SEGMENT_OVERHEAD).map_err(...)`
- `parameters.rs:421` - `u64::try_from(HEADER_LENGTH).map_err(...)`
- `parameters.rs:448` - `u64::try_from(HEADER_LENGTH).map_err(...)`
- `parameters.rs:471` - `u64::try_from(SEGMENT_OVERHEAD).map_err(...)`
- `random_access.rs:360` - `u64::try_from(Header::LEN).map_err(...)`; use the
  crate-private `HEADER_LENGTH_U64`
- `random_access.rs:466` - the same

Do not add `Header::LEN_U64`: it would expand a public type solely for internal
bookkeeping. Re-export `HEADER_LENGTH_U64` only through the crate-private import
surface already used by the implementation.

### 2.2 `u32`-backed segment lengths (6 sites)

`Parameters` has exactly two constructors - `SEGMENT_4_KIB` (`parameters.rs:362`)
and `SEGMENT_1_MIB` (`parameters.rs:371`) - and `Parameters::decode`
(`parameters.rs:519`) accepts only the literals `4096` and `1_048_576`. The
field is therefore always one of two small values, and
`plaintext_segment_length` cannot underflow.

Phase 1 already adds `ciphertext_segment_length_u32`. Add only the corresponding
crate-private plaintext accessor:

```rust
pub(crate) const fn plaintext_segment_length_u32(self) -> u32 {
    self.ciphertext_segment_length - SEGMENT_OVERHEAD_U32
}
```

Redefine the public `usize` accessor in terms of it, so the segment-overhead
subtraction exists in one width instead of drifting between two (amendment):

```rust
pub const fn plaintext_segment_length(self) -> usize {
    length_u32_to_usize(self.plaintext_segment_length_u32())
}
```

At the six call sites, call `u64::from` on one of the two `u32` accessors. Do
not add `const fn` u64 accessors: `From::from` is not stable in const functions,
including on Rust versions newer than this crate's 1.87 MSRV. Direct runtime
conversion is infallible and keeps the internal accessor surface small.

Replace at:

- `parameters.rs:135` - `u64::try_from(plaintext_segment_length).ok()?`
- `parameters.rs:137` - `u64::try_from(ciphertext_segment_length).ok()?`
- `parameters.rs:405` - `u64::try_from(self.plaintext_segment_length())`
- `parameters.rs:461` - `u64::try_from(self.ciphertext_segment_length())`
- `random_access.rs:225` - `u64::try_from(self.parameters().plaintext_segment_length())`
- `random_access.rs:386` - `u64::try_from(self.parameters().plaintext_segment_length())`

Update `ciphertext_segment_length()` (`parameters.rs:381`) to call
`length_u32_to_usize(self.ciphertext_segment_length)`. This removes the final
bare `u32 as usize` outside the helper and ties the public accessor directly to
the target-width contract.

### 2.3 Consequences to check

`MessageLayout::segment_for_position` (`parameters.rs:129`) currently returns
`Option` partly because of the conversions at lines 135, 137, and 155. After
2.1 and 2.2 the only remaining fallible step is line 149
(`usize::try_from(self.plaintext_length - plaintext_offset)`), which is bounded
by the layout invariant. Do **not** change the `Option` return in this phase -
it is public API and `segments()`/`final_segment()` depend on its shape. Note
the observation for a future API review instead.

### 2.4 Tests

No behavior change is expected, so the existing suite is the test. Run the full
matrix (below). The `Error::LengthOverflow` reachability question is resolved
(amendment): the variant remains genuinely reachable after Phases 2 and 3. The
checked arithmetic in `plaintext_layout` and `ciphertext_layout` still
overflows for lengths near `u64::MAX`, and the capacity check at
`online.rs:521` plus the `checked_add` calls below it remain reachable on
32-bit targets. Do not remove the variant - it is public and
`#[non_exhaustive]` does not make removing a variant compatible.

## Phase 3: Replace runtime `usize`-to-`u64` checks

Pattern C, 5 sites. Route all of them through the crate-private
`length_usize_to_u64` helper introduced and exercised by Phase 2. This makes the
three genuinely fallible `u64`-to-`usize` capacity checks visually distinct.

Replace at:

- `online.rs:517` - `u64::try_from(plaintext.len())`
- `random_access.rs:235` - `u64::try_from(segment.plaintext_length())`
- `random_access.rs:254` - `u64::try_from(plaintext.len())`
- `random_access.rs:397` - `u64::try_from(read)`
- `random_access.rs:264` - `u64::try_from(written).unwrap_or(u64::MAX)` in a
  `debug_assert_eq!`; use `length_usize_to_u64(written)`, which also removes a
  clamp that could mask a real mismatch in a debug build

`encrypt_body` (`online.rs:516`) loses its `Error::LengthOverflow` on the first
line. Checked (amendment): the `# Errors` sections of `encrypt` and
`encrypt_body`'s callers remain accurate, because the layout computation and
the 32-bit capacity check inside the same function can still overflow. No doc
change is needed.

## Phase 4: Make bounded narrowings explicit

### 4.1 Layout-bounded conversions

Pattern D, 6 sites. These stay as `try_from`; add comments explaining why each
bound holds so a future reader does not mistake the conversion for a genuine
capacity check or replace it with an unexplained cast.

| Site | Bound |
| --- | --- |
| `parameters.rs:149` | Final segment: `plaintext_length - position * seg <= seg`, by the `segment_count` arithmetic |
| `online.rs:528` | `segment.plaintext_offset()` indexes a `&[u8]` already in memory, so it is below `usize::MAX` |
| `random_access.rs:249` | Loop starts at `range.start / seg`, so `range.start - segment_start < seg` |
| `random_access.rs:256` | `local_end_u64` is bounded by `plaintext.len()` |
| `random_access.rs:393` | `position = plaintext_position / seg`, so the remainder is below `seg` |
| `state.rs:362` | Covered by Phase 1.6 |

While documenting `random_access.rs:249`, note that the `.min(plaintext.len())`
applied *after* the `try_from` is redundant given the bound. Leave it; it is
cheap and defensive. Say so in the comment rather than deleting it.

### 4.2 Error-path conversions

Pattern E, 3 sites. Keep the public `usize` error fields unchanged. The values
actually reported by these branches are small enough to fit every Rust
`usize`, including 16-bit targets:

| Site | Bound |
| --- | --- |
| `parameters.rs:453` | `checked_sub(HEADER_LENGTH_U64)` failed, so `ciphertext_length < 74` |
| `parameters.rs:475` | guarded by `final_length < SEGMENT_OVERHEAD_U64`, so `final_length < 32` |
| `random_access.rs:469` | guarded by `ciphertext_length < HEADER_LENGTH_U64`, so `ciphertext_length < 74` |

At `parameters.rs:453`, change `ok_or(...)` to `ok_or_else(...)`. This is a
correctness prerequisite for any future change at that site, not a style fix:
the eager `ok_or` argument is evaluated on every call, so any panicking
conversion placed there would fire for *valid* ciphertexts longer than 4 GiB
on a 32-bit target. Making it lazy confines the conversion to the branch where
`ciphertext_length < 74`. Nothing in the verification matrix would catch a
regression here (the 32-bit check is compile-only), so the laziness is also
documented with a comment at the site.

Amendment: keep the `unwrap_or(usize::MAX)` clamps rather than replacing them
with `expect`. The clamps are panic-free, and these values feed error
diagnostics only: the worst case of a clamp is a misleading number inside an
error message, while the worst case of an `expect` is a panic while
constructing an error. Two of the three sites are also inside the public
`ciphertext_layout`, where a new `expect` would trip
`clippy::missing_panics_doc` under the crate's pedantic `-D warnings`
configuration. The "misleading clamp" objection is addressed by a comment at
each site stating the proven bound:

```rust
// On this branch `ciphertext_length < HEADER_LENGTH` (74), so the clamp can
// never engage.
actual: usize::try_from(ciphertext_length).unwrap_or(usize::MAX),
```

This preserves exact diagnostics without widening `Error`, changing
`LengthRequirement`, adding a new public variant, or adding a panic path.

## Non-goals

- No change to the wire format. The set of accepted segment prefixes must be
  byte-for-byte identical before and after. `kats/` is not to be modified;
  per `AGENTS.md`, KATs are never updated to make a test pass.
- No change to the three genuine `u64`-to-`usize` capacity checks at
  `online.rs:521` and `random_access.rs:182,203`.
- No `Error` variant removals, including `LengthOverflow` even if Phases 2 and
  3 leave it with few reachable constructions.
- No widening of `Error` fields or `LengthRequirement`; the audited diagnostics
  are bounded before they are reported.
- No new public conversion helpers, fixed-width accessors, or associated
  constants. All additions are `pub(crate)` or private.
- No change to `MessageLayout::segment_for_position`'s `Option` return
  (see 2.3).
- No attempt to make the crate work on a 16-bit target. Phase 1.3 rejects such
  targets deliberately; supporting them would require a `u32`-based length
  model throughout and is out of scope.
- No new panic paths. Phase 1.5 compares in `u64` space instead of converting
  with `expect`, and Phase 4.2 keeps the panic-free clamps; the cleanup is
  panic-neutral end to end.

## Sequencing

Phase 1 is independently compilable and should land first because it touches
attacker-controlled framing and states the platform contract. It is hardening:
accepted behavior does not change on supported 32- and 64-bit targets.

Phase 2 introduces the fixed-width constants and the plaintext `u32` accessor,
building on the helpers established in Phase 1. Phase 3 then applies
`length_usize_to_u64` to runtime values. Phase 4 can ride with Phase 3 because
it documents or makes explicit the invariants around the conversions that
intentionally remain.

Suggested commits, following the repository's short imperative style:

1. `Enforce supported target width and validate prefixes in u32 space`
2. `Replace infallible fixed-width length conversions`
3. `Make bounded length conversions explicit`

## Verification

Run for each phase:

```sh
cargo +nightly fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --doc
cargo test --manifest-path tests/fixtures/provider-unification/Cargo.toml
```

And per provider, one at a time (not `--all-features`, per `AGENTS.md`):

```sh
for p in aws-lc-rs boring ring rustcrypto; do
  cargo test --no-default-features --features "$p" || break
done
```

Phase 1 additionally warrants a 32-bit cross-check, since the truncation class
under discussion is width-dependent and CI is 64-bit only:

```sh
rustup target add i686-unknown-linux-gnu
cargo check --target i686-unknown-linux-gnu --no-default-features --features rustcrypto
```

`cargo check` is enough to confirm the constants, assertions, and lints hold at
32 bits; selecting the pure-Rust provider avoids unrelated native-backend
cross-compilation failures. Running the suite there needs a cross-test runner
and is optional. Note that a 32-bit target makes the `online.rs:521` and
`random_access.rs:182,203` checks genuinely reachable, so any test allocating a
multi-gigabyte message will behave differently there.

No benchmark impact is expected: every change either removes a branch or
replaces a checked conversion with a cast. If `benches/backend_matrix.rs`
results move measurably, report before/after Criterion numbers in the PR as
`AGENTS.md` requires.

## Review amendments

The plan was reviewed against the source before implementation; every line
number, invariant, and platform claim was confirmed. Four changes were made,
integrated into the phases above:

1. Both conversion helpers are introduced in Phase 1 (1.4), and
   `validate_segment` compares prefixes in `u64` space instead of
   `u32::try_from(...).expect(...)` (1.5). The original draft would have added
   a panic branch on the authentication path; the `u64` comparison is equally
   width-independent and needs no reachability proof.
2. Phase 4.2 keeps the panic-free `unwrap_or(usize::MAX)` clamps, documented
   with bound comments, instead of converting them to `expect`. The
   `ok_or_else` change is retained and marked as a correctness prerequisite:
   with the eager `ok_or`, a panicking conversion at that site would fire for
   valid ciphertexts over 4 GiB on 32-bit targets, and no test in the matrix
   would catch it.
3. `plaintext_segment_length()` is redefined through
   `plaintext_segment_length_u32()` (2.2) so the segment-overhead subtraction
   exists in one width only.
4. The `Error::LengthOverflow` reachability question (2.4) is resolved: the
   variant remains reachable through checked arithmetic on near-`u64::MAX`
   lengths and through the 32-bit capacity checks, so no variant or rustdoc
   changes follow.

Net effect of the amendments: the cleanup adds zero panic paths anywhere in
the library, including the three unreachable-but-panicking branches the
original draft would have introduced.
