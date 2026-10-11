// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Decoder behavior on malformed/adversarial input, exercised through the
//! public API as an external caller would see it.
//!
//! This crate decodes untrusted, potentially adversarial bytes (a CBOR
//! manifest embedded in someone else's asset), so the decoder must never
//! panic, over-allocate, or recurse without bound on such input -- it must
//! return an `Err` instead. These cases already have unit-test coverage
//! inside `src/lib.rs`; this file re-exercises the same protections as
//! ordinary integration tests against the public API, so they're covered
//! even if the internal test module changes.

use c2pa_cbor::{Decoder, Value, from_slice, from_slice_with_limit};

#[test]
fn truncated_input_is_rejected_not_panics() {
    // A definite-length array header claiming 3 items, but only 1 is present.
    let cbor = [0x83u8, 0x01];
    let result: Result<Value, _> = from_slice(&cbor);
    assert!(result.is_err(), "truncated array should be rejected");
}

#[test]
fn truncated_string_length_is_rejected_not_panics() {
    // A text string claiming a 1-byte length of 50, but no payload bytes follow.
    let cbor = [0x78u8, 50];
    let result: Result<Value, _> = from_slice(&cbor);
    assert!(result.is_err(), "truncated string should be rejected");
}

#[test]
fn huge_length_prefix_is_rejected_before_allocating() {
    // A byte string claiming to be 200MB, well past the default 100MB
    // allocation limit, with none of the claimed bytes actually present.
    // The decoder must reject this from the length prefix alone, not by
    // trying to allocate/read 200MB first.
    let mut cbor = vec![0x5a]; // byte string, u32 length follows
    cbor.extend_from_slice(&200_000_000u32.to_be_bytes());

    let result: Result<Vec<u8>, _> = from_slice(&cbor);
    assert!(
        result.is_err(),
        "oversized length prefix should be rejected"
    );
}

#[test]
fn huge_length_prefix_is_allowed_under_a_raised_custom_limit() {
    // Same shape as above, but decoded with an explicit limit high enough to
    // admit it -- confirms the rejection above is really the allocation
    // limit (and configurable), not some unrelated failure.
    let mut cbor = vec![0x5a]; // byte string, u32 length follows
    cbor.extend_from_slice(&10_000u32.to_be_bytes()); // claims 10KB
    cbor.extend_from_slice(&[0u8; 100]); // only 100 bytes actually present

    let result: Result<Vec<u8>, _> = from_slice_with_limit(&cbor, 20_000);
    // Truncated input still fails, but not with an allocation-limit error --
    // proving the 10KB claim was accepted under the raised 20KB limit.
    let err = result.expect_err("truncated payload should still fail");
    assert!(!err.to_string().contains("exceeds maximum"));
}

#[test]
fn deeply_nested_arrays_exceed_the_default_depth_limit() {
    // 150 nested indefinite-length arrays exceeds DEFAULT_MAX_DEPTH (128).
    let mut cbor = vec![0x9fu8; 150];
    cbor.push(0x00); // innermost value
    cbor.extend(std::iter::repeat_n(0xffu8, 150));

    let result: Result<Value, _> = from_slice(&cbor);
    assert!(
        result.is_err(),
        "excessive array nesting should be rejected"
    );
}

#[test]
fn deeply_nested_tag_chain_exceeds_the_default_depth_limit() {
    // 150 nested tag(0, ...) wrappers recurse through the same
    // tag-decoding path on each level, so it must be bounded by the same
    // recursion guard as nested arrays/maps.
    let mut cbor = vec![0xc0u8; 150];
    cbor.push(0x00); // innermost value

    let result: Result<Value, _> = from_slice(&cbor);
    assert!(result.is_err(), "excessive tag nesting should be rejected");
}

#[test]
fn custom_depth_limit_rejects_nesting_a_default_decode_would_accept() {
    // 5 levels of nesting is well within the default limit (128), but is
    // rejected once the caller tightens the limit to 2 -- confirms
    // `with_max_depth` actually takes effect rather than the default always
    // winning.
    let cbor = [0x81u8, 0x81, 0x81, 0x81, 0x00]; // [[[[0]]]]

    let mut decoder = Decoder::new(std::io::Cursor::new(&cbor[..])).with_max_depth(2);
    let result: Result<Value, _> = decoder.decode();
    assert!(
        result.is_err(),
        "nesting beyond a tightened custom depth limit should be rejected"
    );
}
