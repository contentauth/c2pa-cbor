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

//! Tests for RFC 8949 §4.2.1 Core Deterministic Encoding Requirement:
//! map/struct keys must be written in the bytewise-lexicographic order of
//! their encoded bytes.

use std::collections::HashMap;

use c2pa_cbor::{Encoder, Value, from_slice, to_vec, to_vec_deterministic};
use serde::{Deserialize, Serialize};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn struct_fields_are_sorted_by_encoded_key_bytes() {
    // Declared out of alphabetical order; "b" and "aa" also probe the case
    // where naive string comparison would disagree with CBOR's bytewise
    // order (shorter keys' length-encoding byte sorts first).
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct S {
        zebra: i32,
        apple: i32,
        b: i32,
        aa: i32,
    }

    let s = S {
        zebra: 1,
        apple: 2,
        b: 3,
        aa: 4,
    };

    let encoded = to_vec_deterministic(&s).unwrap();
    // Expected key order: "b" (len 1, header sorts lowest), "aa" (len 2),
    // "apple" (len 5), "zebra" (len 5, tie-broken bytewise: 'a' < 'z').
    assert_eq!(
        hex(&encoded),
        "a461620362616104656170706c6502657a6562726101"
    );

    let decoded: S = from_slice(&encoded).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn hashmap_keys_are_sorted_regardless_of_insertion_order() {
    let mut map = HashMap::new();
    map.insert("zebra".to_string(), 1);
    map.insert("apple".to_string(), 2);
    map.insert("b".to_string(), 3);
    map.insert("aa".to_string(), 4);

    let encoded = to_vec_deterministic(&map).unwrap();
    assert_eq!(
        hex(&encoded),
        "a461620362616104656170706c6502657a6562726101"
    );
}

#[test]
fn mixed_sign_integer_keys_follow_cbor_byte_order_not_numeric_order() {
    // CBOR sorts by encoded bytes: unsigned ints (major type 0) always sort
    // before negative ints (major type 1), regardless of numeric value.
    // A naive numeric/Ord-based sort would put -5 before 3.
    let mut map = std::collections::BTreeMap::new();
    map.insert(Value::Integer(3), Value::Bool(true));
    map.insert(Value::Integer(-5), Value::Bool(false));
    let value = Value::Map(map);

    let encoded = to_vec_deterministic(&value).unwrap();
    // {3: true, -5: false} -> a2 03 f5 24 f4
    assert_eq!(hex(&encoded), "a203f524f4");
}

#[test]
fn enum_struct_variant_fields_are_sorted() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    enum E {
        Variant { zebra: i32, apple: i32 },
    }

    let e = E::Variant { zebra: 1, apple: 2 };
    let encoded = to_vec_deterministic(&e).unwrap();
    // {"Variant": {"apple": 2, "zebra": 1}}
    assert_eq!(
        hex(&encoded),
        "a16756617269616e74a2656170706c6502657a6562726101"
    );

    let decoded: E = from_slice(&encoded).unwrap();
    assert_eq!(decoded, e);
}

#[test]
fn to_vec_preserves_declaration_order_by_default() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct S {
        zebra: i32,
        apple: i32,
    }

    let s = S { zebra: 1, apple: 2 };

    let encoded = to_vec(&s).unwrap();
    // Declaration order preserved: zebra, then apple.
    assert_eq!(hex(&encoded), "a2657a6562726101656170706c6502");

    let decoded: S = from_slice(&encoded).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn encoder_default_matches_to_vec() {
    #[derive(Serialize)]
    struct S {
        zebra: i32,
        apple: i32,
    }
    let s = S { zebra: 1, apple: 2 };

    let mut buf = Vec::new();
    let mut encoder = Encoder::new(&mut buf);
    encoder.encode(&s).unwrap();

    assert_eq!(hex(&buf), hex(&to_vec(&s).unwrap()));
}

#[test]
fn duplicate_keys_are_rejected_in_deterministic_mode() {
    // #[serde(flatten)] can produce a map with a key that collides with a
    // sibling field's name; RFC 8949 §4.2.1 forbids duplicate keys.
    #[derive(Serialize)]
    struct Outer {
        name: String,
        #[serde(flatten)]
        extra: HashMap<String, String>,
    }

    let mut extra = HashMap::new();
    extra.insert("name".to_string(), "duplicate!".to_string());
    let outer = Outer {
        name: "original".to_string(),
        extra,
    };

    let err = to_vec_deterministic(&outer).unwrap_err();
    assert!(err.to_string().contains("duplicate"), "{}", err);
}

#[test]
fn duplicate_keys_are_allowed_by_default() {
    use std::collections::HashMap;

    #[derive(Serialize)]
    struct Outer {
        name: String,
        #[serde(flatten)]
        extra: HashMap<String, String>,
    }

    let mut extra = HashMap::new();
    extra.insert("name".to_string(), "duplicate!".to_string());
    let outer = Outer {
        name: "original".to_string(),
        extra,
    };

    // Duplicate-key rejection only applies in deterministic mode.
    let bytes = to_vec(&outer).unwrap();
    assert_eq!(
        hex(&bytes),
        "a2646e616d65686f726967696e616c646e616d656a6475706c696361746521"
    );
}

#[test]
fn deterministic_mode_uses_preferred_float_encoding_without_compact_floats_feature() {
    // RFC 8949 §4.2.1's "Core Deterministic Encoding Requirements" bundles
    // preferred serialization (shortest-form floats) together with sorted
    // map keys. Deterministic mode must apply both, regardless of whether
    // the crate was built with the separate `compact_floats` feature.
    assert_eq!(hex(&to_vec_deterministic(&1.5f64).unwrap()), "f93e00");
    assert_eq!(hex(&to_vec_deterministic(&4.0f32).unwrap()), "f94400");
    assert_eq!(
        hex(&to_vec_deterministic(&1.0e+300f64).unwrap()),
        "fb7e37e43c8800759c"
    );

    // Without the `compact_floats` feature, non-deterministic encoding keeps
    // the original fast path: no shrinking. (With the feature enabled,
    // `to_vec` shrinks too - that's covered by the `compact_floats` tests.)
    #[cfg(not(feature = "compact_floats"))]
    {
        assert_eq!(hex(&to_vec(&1.5f64).unwrap()), "fb3ff8000000000000");
        assert_eq!(hex(&to_vec(&4.0f32).unwrap()), "fa40800000");
    }
}

#[test]
fn deterministic_mode_canonicalizes_nan_regardless_of_source_bit_pattern() {
    // RFC 8949 §4.2.2: protocols that don't need NaN payloads/signaling bits
    // should pick a single NaN representation (0xf97e00) so output stays
    // reproducible no matter which bit pattern produced the NaN upstream.
    let quiet_nan = f64::NAN;
    let negative_nan = -f64::NAN;
    let payload_nan = f64::from_bits(0x7ff8_0000_0000_0001);
    let signaling_nan = f64::from_bits(0x7ff0_0000_0000_0001);

    for nan in [quiet_nan, negative_nan, payload_nan, signaling_nan] {
        assert_eq!(hex(&to_vec_deterministic(&nan).unwrap()), "f97e00");
        assert_eq!(hex(&to_vec_deterministic(&(nan as f32)).unwrap()), "f97e00");
    }
}

#[test]
fn nested_maps_are_sorted_recursively() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Inner {
        z: i32,
        a: i32,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Outer {
        z: Inner,
        a: Inner,
    }

    let outer = Outer {
        z: Inner { z: 1, a: 2 },
        a: Inner { z: 3, a: 4 },
    };

    let encoded = to_vec_deterministic(&outer).unwrap();
    // Outer sorted: a, z. Each inner also sorted: a, z.
    // {"a": {"a": 4, "z": 3}, "z": {"a": 2, "z": 1}}
    assert_eq!(hex(&encoded), "a26161a2616104617a03617aa2616102617a01");

    let decoded: Outer = from_slice(&encoded).unwrap();
    assert_eq!(decoded, outer);
}
