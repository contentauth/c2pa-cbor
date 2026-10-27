// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Test for newtype struct handling - verifies fix for transparent serialization
//
// Bug: Given a definition like:
//   pub struct TimeStamp(pub HashMap<String, ByteBuf>);
//
// The serde default should be transparent and timestamp should serialize as a map.
// But without fixes, it was being serialized as an array with a map inside it.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[test]
fn test_newtype_hashmap_should_be_map_not_array() {
    // This is the reported bug case: newtype struct wrapping HashMap
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TimeStamp(pub HashMap<String, ByteBuf>);

    let mut map = HashMap::new();
    map.insert("key1".to_string(), ByteBuf::from(vec![1, 2, 3]));
    map.insert("key2".to_string(), ByteBuf::from(vec![4, 5, 6]));

    let timestamp = TimeStamp(map);

    // Serialize to CBOR
    let cbor_bytes = c2pa_cbor::to_vec(&timestamp).expect("serialize");

    // Check the first byte - should be a MAP (major type 5), not ARRAY (major type 4)
    // Major type 5 (map) with 2 entries: 0xA2 = 0b101_00010 = major 5, length 2
    let first_byte = cbor_bytes[0];
    let major_type = first_byte >> 5;

    println!("First byte: 0x{:02x}", first_byte);
    println!("Major type: {}", major_type);
    println!("Full CBOR: {:?}", cbor_bytes);

    // Without transparent serialization, this would be major type 4 (array)
    // With proper transparent handling, it should be major type 5 (map)
    assert_eq!(
        major_type, 5,
        "Expected major type 5 (map), got major type {}. \
         Newtype struct wrapping HashMap should serialize as a map, not as an array containing a map.",
        major_type
    );

    // Also verify round-trip works
    let deserialized: TimeStamp = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");
    assert_eq!(timestamp, deserialized);
}

#[test]
fn test_newtype_hashmap_with_string_values() {
    // Simpler version with String values instead of ByteBuf
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Metadata(pub HashMap<String, String>);

    let mut map = HashMap::new();
    map.insert("author".to_string(), "Alice".to_string());
    map.insert("title".to_string(), "Test Document".to_string());

    let metadata = Metadata(map);

    let cbor_bytes = c2pa_cbor::to_vec(&metadata).expect("serialize");
    let first_byte = cbor_bytes[0];
    let major_type = first_byte >> 5;

    println!("String HashMap - First byte: 0x{:02x}", first_byte);
    println!("String HashMap - Major type: {}", major_type);

    assert_eq!(
        major_type, 5,
        "Newtype wrapping HashMap<String, String> should serialize as map (major type 5), got {}",
        major_type
    );

    let deserialized: Metadata = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");
    assert_eq!(metadata, deserialized);
}

#[test]
fn test_newtype_vec_transparent() {
    // Newtype wrapping Vec should serialize transparently as just the Vec (array)
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Items(pub Vec<String>);

    let items = Items(vec!["item1".to_string(), "item2".to_string()]);

    let cbor_bytes = c2pa_cbor::to_vec(&items).expect("serialize");
    let first_byte = cbor_bytes[0];
    let major_type = first_byte >> 5;

    println!("Vec - First byte: 0x{:02x}", first_byte);
    println!("Vec - Major type: {}", major_type);

    // Newtype wrapping Vec should serialize transparently as just the Vec (array with 2 elements)
    // First byte: 0x82 = array with 2 elements (not 0x81 = array with 1 element containing an array)
    assert_eq!(
        major_type, 4,
        "Newtype wrapping Vec should serialize as array (major type 4), got {}",
        major_type
    );
    assert_eq!(
        first_byte, 0x82,
        "Expected 2-element array (0x82), got 0x{:02x}. \
         Newtype should be transparent, not wrapped in another array.",
        first_byte
    );

    let deserialized: Items = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");
    assert_eq!(items, deserialized);
}

#[test]
fn test_regular_struct_with_hashmap_field() {
    // For comparison: regular struct with HashMap field should be a map with field name as key
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Container {
        data: HashMap<String, String>,
    }

    let mut map = HashMap::new();
    map.insert("key1".to_string(), "value1".to_string());

    let container = Container { data: map };

    let cbor_bytes = c2pa_cbor::to_vec(&container).expect("serialize");
    let first_byte = cbor_bytes[0];
    let major_type = first_byte >> 5;

    // Regular struct should be a map
    assert_eq!(major_type, 5, "Regular struct should be map");

    let deserialized: Container = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");
    assert_eq!(container, deserialized);
}

#[test]
fn test_explicitly_transparent_newtype() {
    // Test that #[serde(transparent)] gives us the desired behavior
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    #[serde(transparent)]
    struct TransparentMap(pub HashMap<String, String>);

    let mut map = HashMap::new();
    map.insert("key1".to_string(), "value1".to_string());

    let transparent = TransparentMap(map);

    let cbor_bytes = c2pa_cbor::to_vec(&transparent).expect("serialize");
    let first_byte = cbor_bytes[0];
    let major_type = first_byte >> 5;

    assert_eq!(major_type, 5, "Transparent newtype should serialize as map");

    let deserialized: TransparentMap = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");
    assert_eq!(transparent, deserialized);
}
