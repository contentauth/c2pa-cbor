#![no_main]

//! Fuzz target: decoding arbitrary bytes must never panic, over-allocate, or
//! loop/recurse forever, regardless of whether the bytes are valid CBOR. Run
//! with `cargo +nightly fuzz run decode` (requires `cargo install cargo-fuzz`).

use c2pa_cbor::cose::CoseSign1;
use c2pa_cbor::{from_slice, Value};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = from_slice::<Value>(data);
    if let Ok(sign1) = CoseSign1::from_tagged_slice_with_limit(data, 1024 * 1024) {
        let encoded = sign1.to_tagged_vec().unwrap();
        let decoded = CoseSign1::from_tagged_slice(&encoded).unwrap();
        assert_eq!(
            decoded.protected.original_data,
            sign1.protected.original_data
        );
        assert_eq!(decoded.payload, sign1.payload);
        assert_eq!(decoded.signature, sign1.signature);
        if sign1.payload.is_some() {
            assert_eq!(
                decoded.tbs_data(b"fuzz aad").unwrap(),
                sign1.tbs_data(b"fuzz aad").unwrap()
            );
        } else {
            assert_eq!(
                decoded.detached_tbs_data(b"fuzz aad", b"payload").unwrap(),
                sign1.detached_tbs_data(b"fuzz aad", b"payload").unwrap()
            );
        }
    }
});
