//! Pins the released segment-length contract.
//!
//! Integration tests compile the library without `cfg(test)`, so these
//! assertions exercise the exact validation range that downstream callers
//! see, guarding against any test-only substitution of the public bounds.

use fast_floe::{Error, Parameters};

#[test]
fn release_build_enforces_documented_segment_length_bounds() {
    assert_eq!(Parameters::VALID_SEGMENT_LENGTHS, 64..u32::MAX);

    // Both documented endpoints are accepted
    assert!(Parameters::from_segment_length(64).is_ok());
    assert!(Parameters::from_segment_length(u32::MAX - 1).is_ok());

    // Values just outside the documented range are rejected with the
    // offending value
    assert_eq!(
        Parameters::from_segment_length(63),
        Err(Error::InvalidSegmentLength { actual: 63 })
    );
    assert_eq!(
        Parameters::from_segment_length(u32::MAX),
        Err(Error::InvalidSegmentLength { actual: u32::MAX })
    );
}
