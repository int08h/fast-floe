# Numeric Conversion Cleanup Plan

Status: proposed, not yet implemented.

This plan addresses the results of an audit of every numeric conversion in
`fast-floe`. It is ordered so that the security-relevant work lands first and
independently of the ergonomic cleanup.

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

Of the 34 sites, only three can fail on a target this crate supports:

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
  `random_access.rs:235,254,264,397`. Infallible on every Rust target, but not
  provable through the type system because `std` declines to provide
  `From<usize> for u64`.
- **D. `u64` to `usize` bounded by a layout invariant** (6 sites):
  `parameters.rs:149`, `online.rs:528`, `random_access.rs:249,256,393`, plus
  `state.rs:362` (`u32::try_from`). Each is bounded by segment arithmetic, but
  the bound lives in the layout math rather than in a type.
- **E. lossy by design in error reporting** (3 sites):
  `usize::try_from(len).unwrap_or(usize::MAX)` at `parameters.rs:453,475` and
  `random_access.rs:469`.
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

Clippy declining to lint `usize as u64` reflects the same assumption this plan
makes explicit: every Rust target has a 16-, 32-, or 64-bit `usize`.

## Phase 1: Security-relevant work (do first, ship alone)

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

### 1.4 Task: make the prefix comparison width-independent

Two changes, both defense in depth on top of 1.3.

Add `pub(crate)` `u32`-typed accessors to `Parameters` (see Phase 2.2, which
introduces the same accessor family; Phase 1 needs only the `u32` pair):

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
const _: () = assert!(SEGMENT_OVERHEAD_U32 as usize == SEGMENT_OVERHEAD);
```

While there, add the same cross-check to the existing `FLOE_IV_LENGTH_U32`,
which currently has no assertion tying it to `FLOE_IV_LENGTH`.

Then in `SegmentFraming::decode`, validate in `u32` space and narrow only the
already-validated value:

```rust
let ciphertext_length = if encoded == u32::MAX {
    parameters.ciphertext_segment_length()
} else {
    // Validated in u32 space: the range check must not depend on the width of
    // usize, because `encoded` is attacker-controlled and unauthenticated.
    let maximum = parameters.ciphertext_segment_length_u32();
    if !(SEGMENT_OVERHEAD_U32..=maximum).contains(&encoded) {
        return Err(Error::InvalidCiphertextLength {
            actual: usize::try_from(encoded).unwrap_or(usize::MAX),
            required: LengthRequirement::Between {
                minimum: SEGMENT_OVERHEAD,
                maximum: parameters.ciphertext_segment_length(),
            },
        });
    }
    usize::try_from(encoded).map_err(|_| Error::LengthOverflow)?
};
```

The `unwrap_or(usize::MAX)` on the *error reporting* path is intentional and is
addressed by Phase 5; it cannot affect the accept/reject decision, which has
already been made in `u32` space.

In `validate_segment`, compare in `u64` so the comparison is exact at every
width and needs no fallible conversion or sentinel handling:

```rust
SegmentKind::Final if u64::from(prefix) != widen(ciphertext_segment.len()) => {
```

using the `widen` helper from Phase 3.3. `u64::from(u32)` is infallible, and
`widen` is lossless given 1.3, so no `unwrap` or clamp is involved. This also
removes the latent question of what should happen if a length ever equalled the
`u32::MAX` non-final sentinel.

### 1.5 Task: document the sentinel invariant

`state.rs:362` encodes a final segment's length as
`u32::try_from(required).map_err(|_| Error::LengthOverflow)?`. This cannot fail:
`ciphertext_segment_size` bounds `required` at `ciphertext_segment_length`, so
at most 1 MiB. That bound is also what keeps a final length from ever colliding
with the `u32::MAX` non-final sentinel, which is currently load-bearing and
undocumented. Add a comment stating both facts. Leave the `try_from` in place -
it is cheap and the invariant lives in another function.

### 1.6 Tests

Name tests after observable behavior, per `AGENTS.md`.

- `segment_framing_rejects_prefix_whose_low_bits_look_valid` - decode a prefix
  of `69632` against `SEGMENT_4_KIB` and assert
  `Error::InvalidCiphertextLength`. Also `1_048_576 + 4096` against
  `SEGMENT_4_KIB`. These pass on 64-bit today; the test documents the
  truncation class and pins the u32-space check. Include a comment naming the
  16-bit truncation it guards against, so it is not "simplified" later.
- `final_segment_prefix_must_equal_actual_segment_length` - extend the existing
  coverage near `tests.rs:790` with a prefix that differs from the real length
  only in bits above the low 16.
- `supported_target_pointer_width` - a runtime `assert!(matches!(usize::BITS, 32
  | 64))`, so the contract is visible in test output as well as at build time.
- Confirm the existing `segment_prefix_classification_exposes_valid_framing`
  (`tests.rs:470`) still passes unchanged; it covers the accepted boundaries
  `SEGMENT_OVERHEAD`, `SEGMENT_OVERHEAD + 7`, `ciphertext_segment_length`, and
  the rejected `SEGMENT_OVERHEAD - 1` and `ciphertext_segment_length + 1`.
- Re-run the KAT suite. No wire-format change is intended: the accepted set of
  prefixes is identical on 32- and 64-bit targets. Do not touch `kats/`.

## Phase 2: Eliminate provably-dead conversions

Pattern A and B, 13 sites. Mechanical, no behavior change on any supported
target, and each removal deletes an unreachable error branch.

### 2.1 `usize` constants to `u64` (7 sites)

Add beside the existing constants in `src/parameters.rs`:

```rust
pub(crate) const HEADER_LENGTH_U64: u64 = HEADER_LENGTH as u64;
pub(crate) const SEGMENT_OVERHEAD_U64: u64 = SEGMENT_OVERHEAD as u64;
```

Both const-evaluate and neither trips a lint. Replace at:

- `parameters.rs:155` - `u64::try_from(HEADER_LENGTH).ok()?`
- `parameters.rs:418` - `u64::try_from(SEGMENT_OVERHEAD).map_err(...)`
- `parameters.rs:421` - `u64::try_from(HEADER_LENGTH).map_err(...)`
- `parameters.rs:448` - `u64::try_from(HEADER_LENGTH).map_err(...)`
- `parameters.rs:471` - `u64::try_from(SEGMENT_OVERHEAD).map_err(...)`
- `random_access.rs:360` - `u64::try_from(Header::LEN).map_err(...)`
- `random_access.rs:466` - `u64::try_from(Header::LEN).map_err(...)`

`Header::LEN` is `HEADER_LENGTH` (`state.rs:39`); consider adding
`Header::LEN_U64` so `random_access.rs` need not reach into `parameters`.

### 2.2 `u32`-backed segment lengths (6 sites)

`Parameters` has exactly two constructors - `SEGMENT_4_KIB` (`parameters.rs:362`)
and `SEGMENT_1_MIB` (`parameters.rs:371`) - and `Parameters::decode`
(`parameters.rs:519`) accepts only the literals `4096` and `1_048_576`. The
field is therefore always one of two small values, and
`plaintext_segment_length` cannot underflow.

Add `pub(crate)` accessors returning the natural widths:

```rust
pub(crate) const fn ciphertext_segment_length_u32(self) -> u32 {
    self.ciphertext_segment_length
}

pub(crate) const fn plaintext_segment_length_u32(self) -> u32 {
    self.ciphertext_segment_length - SEGMENT_OVERHEAD_U32
}

pub(crate) const fn ciphertext_segment_length_u64(self) -> u64 {
    u64::from(self.ciphertext_segment_length)
}

pub(crate) const fn plaintext_segment_length_u64(self) -> u64 {
    u64::from(self.plaintext_segment_length_u32())
}
```

`u64::from(u32)` is a genuine infallible `From`, so this is strictly stronger
than the current code rather than a weakening: it removes the platform-dependent
`usize` hop entirely. Replace at:

- `parameters.rs:135` - `u64::try_from(plaintext_segment_length).ok()?`
- `parameters.rs:137` - `u64::try_from(ciphertext_segment_length).ok()?`
- `parameters.rs:405` - `u64::try_from(self.plaintext_segment_length())`
- `parameters.rs:461` - `u64::try_from(self.ciphertext_segment_length())`
- `random_access.rs:225` - `u64::try_from(self.parameters().plaintext_segment_length())`
- `random_access.rs:386` - `u64::try_from(self.parameters().plaintext_segment_length())`

Six accessors on `Parameters` is a wide surface for an internal detail. If it
reads poorly in review, keep the `u32` pair as the primitives and drop the
`u64` pair in favour of `u64::from(p.plaintext_segment_length_u32())` at the
call sites.

`ciphertext_segment_length()` (`parameters.rs:381`) keeps its `u32 as usize`
cast. Given Phase 1.3 it is lossless by construction; add a comment saying so
and pointing at the assertion.

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
matrix (below). Confirm the `Error::LengthOverflow` variant is still
constructed somewhere reachable after the deletions; if Phase 2 and 3 remove
every reachable construction, that is worth knowing before considering the
variant's fate. Do not remove the variant - it is public and `#[non_exhaustive]`
does not make removing a variant compatible.

## Phase 3: Make the `usize`-to-`u64` assumption explicit

Pattern C, 5 sites. These are the conversions that are infallible on every
Rust target but not provable through the type system.

### 3.1 The choice

Three options:

1. Leave them. Cost: five unreachable error branches, and the reader cannot
   tell them apart from the three real checks in `online.rs:521` and
   `random_access.rs:182,203`.
2. Convert to `as u64` casts. Lossless given Phase 1.3 and clippy-clean, but
   scatters bare casts through length arithmetic.
3. Route through one documented helper. Preferred.

### 3.2 Recommendation

Option 3, because the value of this phase is making the three genuine checks
legible by removing the five look-alikes.

### 3.3 Task

Add to `src/parameters.rs`:

```rust
/// Widens a `usize` to a `u64`.
///
/// Lossless on every supported target; see the `usize::BITS` assertion above.
/// `std` provides no `From<usize> for u64`, so this documents the assumption
/// once instead of at each call site.
#[inline]
pub(crate) const fn widen(value: usize) -> u64 {
    value as u64
}
```

Replace at:

- `online.rs:517` - `u64::try_from(plaintext.len())`
- `random_access.rs:235` - `u64::try_from(segment.plaintext_length())`
- `random_access.rs:254` - `u64::try_from(plaintext.len())`
- `random_access.rs:397` - `u64::try_from(read)`
- `random_access.rs:264` - `u64::try_from(written).unwrap_or(u64::MAX)` in a
  `debug_assert_eq!`; becomes `widen(written)`, which also removes a clamp that
  could mask a real mismatch in a debug build

`encrypt_body` (`online.rs:516`) loses its `Error::LengthOverflow` on the first
line. Check its rustdoc `# Errors` section, and that of `encrypt`
(`online.rs:511`), still describes what the function can actually return.

## Phase 4: Document the invariant-bounded narrowings

Pattern D, 6 sites. These stay as `try_from`; the work is comments explaining
why the bound holds, so a future reader does not mistake them for real checks
or "optimize" them into casts.

| Site | Bound |
| --- | --- |
| `parameters.rs:149` | Final segment: `plaintext_length - position * seg <= seg`, by the `segment_count` arithmetic |
| `online.rs:528` | `segment.plaintext_offset()` indexes a `&[u8]` already in memory, so it is below `usize::MAX` |
| `random_access.rs:249` | Loop starts at `range.start / seg`, so `range.start - segment_start < seg` |
| `random_access.rs:256` | `local_end_u64` is bounded by `plaintext.len()` |
| `random_access.rs:393` | `position = plaintext_position / seg`, so the remainder is below `seg` |
| `state.rs:362` | Covered by Phase 1.5 |

While documenting `random_access.rs:249`, note that the `.min(plaintext.len())`
applied *after* the `try_from` is redundant given the bound. Leave it; it is
cheap and defensive. Say so in the comment rather than deleting it.

## Phase 5: Error field widths (breaking; defer)

Pattern E, 3 sites. `Error::InvalidHeaderLength { actual: usize }` and
`Error::InvalidCiphertextLength { actual: usize }` (`error.rs:46,53`) are
`usize`-typed, but the values reaching them at `parameters.rs:453,475` and
`random_access.rs:469` come from `u64` message arithmetic. The call sites
therefore clamp:

```rust
actual: usize::try_from(ciphertext_length).unwrap_or(usize::MAX),
```

On a 32-bit target a 5 GiB ciphertext reports `actual: 4294967295`. This is a
diagnostic defect only - no accept/reject decision depends on it - but the
report is silently wrong rather than approximate.

Options:

1. Widen `actual` to `u64` on both variants, and `LengthRequirement`
   (`error.rs:8`) with it. Correct, and breaking: these are public, and
   `#[non_exhaustive]` on the enum does not cover changing a field's type.
   Ripples into every `Error::InvalidCiphertextLength` construction and into
   test matches such as `tests.rs:795`.
2. Split the length-arithmetic errors into a separate `u64`-carrying variant
   and leave the segment-level `usize` variants alone. Additive, and arguably a
   more honest model, since a segment length and a whole-message length are
   different quantities. Still visible API growth.
3. Leave it, with a comment at each clamp.

Recommend deciding this alongside the next intentional breaking release rather
than driving a release on its own. Until then apply option 3 so the clamps read
as deliberate. If option 1 or 2 is chosen, do it in one commit with the
`# Errors` rustdoc updated, and note the API change in the release notes.

## Non-goals

- No change to the wire format. The set of accepted segment prefixes must be
  byte-for-byte identical before and after. `kats/` is not to be modified;
  per `AGENTS.md`, KATs are never updated to make a test pass.
- No change to the three genuine `u64`-to-`usize` capacity checks at
  `online.rs:521` and `random_access.rs:182,203`.
- No `Error` variant removals, including `LengthOverflow` even if Phases 2 and
  3 leave it with few reachable constructions.
- No change to `MessageLayout::segment_for_position`'s `Option` return
  (see 2.3).
- No attempt to make the crate work on a 16-bit target. Phase 1.3 rejects such
  targets deliberately; supporting them would require a `u32`-based length
  model throughout and is out of scope.

## Sequencing

Phase 1 is independent and should ship first as its own commit and PR, since it
is the only phase with security relevance. Phases 2 and 3 share the constants
and helper introduced in Phase 1 and should follow in that order. Phase 4 is
comment-only and can ride with Phase 3. Phase 5 is deferred.

Suggested commits, following the repository's short imperative style:

1. `Enforce supported target width and validate prefixes in u32 space`
2. `Replace infallible constant length conversions`
3. `Convert segment lengths without a usize round trip`
4. `Document invariant-bounded length narrowings`

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
cargo check --target i686-unknown-linux-gnu
```

`cargo check` is enough to confirm the constants, assertions, and lints hold at
32 bits; running the suite there needs a cross-test runner and is optional. Note
that a 32-bit target makes the `online.rs:521` and `random_access.rs:182,203`
checks genuinely reachable, so any test allocating a multi-gigabyte message will
behave differently there.

No benchmark impact is expected: every change either removes a branch or
replaces a checked conversion with a cast. If `benches/backend_matrix.rs`
results move measurably, report before/after Criterion numbers in the PR as
`AGENTS.md` requires.
