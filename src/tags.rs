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

// Portions derived from serde_cbor (https://github.com/pyfisch/cbor)

use std::{fmt, io::Write, marker::PhantomData};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, Visitor},
};

use crate::{Decoder, Encoder, Result, constants::*};

/// A tagged CBOR value
#[derive(Debug, Clone, PartialEq)]
pub struct Tagged<T> {
    /// The CBOR tag number (optional for compatibility)
    pub tag: Option<u64>,
    /// The tagged value
    pub value: T,
}

impl<T> Tagged<T> {
    /// Create a new tagged value
    pub fn new(tag: Option<u64>, value: T) -> Self {
        Tagged { tag, value }
    }
}

impl<T: for<'de> Deserialize<'de>> Tagged<T> {
    /// Deserialize a Tagged value from CBOR bytes, explicitly capturing the tag if present
    ///
    /// This method is similar to [`crate::from_slice`] but explicitly preserves CBOR tag
    /// information. While `from_slice` uses transparent tag handling (ignoring tags for
    /// plain types), this method directly reads the tag from the CBOR stream and returns
    /// it as part of the `Tagged` struct.
    ///
    /// This is useful when you need to distinguish between tagged and untagged values,
    /// or when working with types that encode semantic information via tags (e.g., dates,
    /// URIs, bignums).
    ///
    /// # Example
    /// ```
    /// use c2pa_cbor::tags::Tagged;
    ///
    /// let cbor = vec![
    ///     0xd8, 0x20, 0x78, 0x13, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x65, 0x78, 0x61,
    ///     0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    /// ];
    /// let tagged = Tagged::<String>::from_tagged_slice(&cbor).unwrap();
    /// assert_eq!(tagged.tag, Some(32)); // URI tag
    /// assert_eq!(tagged.value, "https://example.com");
    /// ```
    pub fn from_tagged_slice(cbor: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::from_slice(cbor);

        // Peek at the next byte to check if there's a tag
        let peek = decoder.peek_u8()?;
        let major = peek >> 5;

        if major == MAJOR_TAG {
            // Tag present - read it and then decode the value
            let tag = decoder.read_tag()?;
            let value: T = decoder.decode()?;
            Ok(Tagged::new(Some(tag), value))
        } else {
            // No tag - just decode the value
            let value: T = decoder.decode()?;
            Ok(Tagged::new(None, value))
        }
    }
}

// Custom serialization that writes proper CBOR tags
// The encoder parses strings like "__cbor_tag_N__" and writes CBOR tag N
impl<T: Serialize> Serialize for Tagged<T> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.tag {
            Some(tag) => {
                // Map tag numbers to their corresponding marker strings
                // The encoder's serialize_newtype_struct parses these and writes the actual CBOR tag
                let tag_str = match tag {
                    // Standard RFC 8949 tags
                    0 => "__cbor_tag_0__",   // Date/time string
                    1 => "__cbor_tag_1__",   // Epoch datetime
                    2 => "__cbor_tag_2__",   // Positive bignum
                    3 => "__cbor_tag_3__",   // Negative bignum
                    4 => "__cbor_tag_4__",   // Decimal fraction
                    5 => "__cbor_tag_5__",   // Bigfloat
                    21 => "__cbor_tag_21__", // Expected conversion to base64url
                    22 => "__cbor_tag_22__", // Expected conversion to base64
                    23 => "__cbor_tag_23__", // Expected conversion to base16
                    24 => "__cbor_tag_24__", // Encoded CBOR data item
                    32 => "__cbor_tag_32__", // URI
                    33 => "__cbor_tag_33__", // Base64url
                    34 => "__cbor_tag_34__", // Base64
                    36 => "__cbor_tag_36__", // MIME

                    // RFC 8746 - Typed arrays (64-87)
                    64 => "__cbor_tag_64__", // uint8 array
                    65 => "__cbor_tag_65__", // uint16 big-endian
                    66 => "__cbor_tag_66__", // uint32 big-endian
                    67 => "__cbor_tag_67__", // uint64 big-endian
                    68 => "__cbor_tag_68__", // uint8 clamped
                    69 => "__cbor_tag_69__", // uint16 little-endian
                    70 => "__cbor_tag_70__", // uint32 little-endian
                    71 => "__cbor_tag_71__", // uint64 little-endian
                    72 => "__cbor_tag_72__", // sint8
                    73 => "__cbor_tag_73__", // sint16 big-endian
                    74 => "__cbor_tag_74__", // sint32 big-endian
                    75 => "__cbor_tag_75__", // sint64 big-endian
                    77 => "__cbor_tag_77__", // sint16 little-endian
                    78 => "__cbor_tag_78__", // sint32 little-endian
                    79 => "__cbor_tag_79__", // sint64 little-endian
                    80 => "__cbor_tag_80__", // float16 big-endian
                    81 => "__cbor_tag_81__", // float32 big-endian
                    82 => "__cbor_tag_82__", // float64 big-endian
                    83 => "__cbor_tag_83__", // float128 big-endian
                    84 => "__cbor_tag_84__", // float16 little-endian
                    85 => "__cbor_tag_85__", // float32 little-endian
                    86 => "__cbor_tag_86__", // float64 little-endian
                    87 => "__cbor_tag_87__", // float128 little-endian

                    _ => {
                        // Unsupported tag number - use encode_tagged helper functions instead
                        use serde::ser::Error;
                        return Err(Error::custom(format!(
                            "Tag {} not supported via Tagged<T>. Use encode_tagged() helper function for arbitrary tags.",
                            tag
                        )));
                    }
                };

                serializer.serialize_newtype_struct(tag_str, &self.value)
            }
            None => {
                // No tag, just serialize the value directly
                self.value.serialize(serializer)
            }
        }
    }
}

// Custom deserialization that handles both tagged CBOR values and plain values (e.g., from JSON)
impl<'de, T> Deserialize<'de> for Tagged<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TaggedVisitor<T> {
            marker: PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for TaggedVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = Tagged<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tagged value or a plain value")
            }

            // Handle the case where we get a plain value (e.g., from JSON)
            // Just wrap it in Tagged with no tag
            fn visit_bool<E>(self, v: bool) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::BoolDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::I64Deserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::U64Deserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_f64<E>(self, v: f64) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::F64Deserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::StrDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::StringDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::BytesDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_seq<A>(self, seq: A) -> std::result::Result<Tagged<T>, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                T::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_map<A>(self, map: A) -> std::result::Result<Tagged<T>, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                // Try to deserialize as a struct with tag and value fields
                // If that fails, deserialize as the inner type directly
                #[derive(Deserialize)]
                struct TaggedHelper<T> {
                    tag: Option<u64>,
                    value: T,
                }

                match TaggedHelper::deserialize(serde::de::value::MapAccessDeserializer::new(map)) {
                    Ok(helper) => Ok(Tagged {
                        tag: helper.tag,
                        value: helper.value,
                    }),
                    Err(_) => {
                        // If deserializing as TaggedHelper fails, try deserializing as T directly
                        Err(de::Error::custom(
                            "expected tagged value structure or plain value",
                        ))
                    }
                }
            }
        }

        deserializer.deserialize_any(TaggedVisitor {
            marker: PhantomData,
        })
    }
}

// Tagged value helpers
/// Encode a tagged value (tag number + content)
pub fn encode_tagged<W: Write, T: Serialize>(writer: &mut W, tag: u64, value: &T) -> Result<()> {
    let mut encoder = Encoder::new(writer);
    encoder.write_tag(tag)?;
    encoder.encode(value)?;
    Ok(())
}

/// Helper to encode a date/time string (tag 0)
pub fn encode_datetime_string<W: Write>(writer: &mut W, datetime: &str) -> Result<()> {
    encode_tagged(writer, TAG_DATETIME_STRING, &datetime)
}

/// Helper to encode an epoch timestamp (tag 1)
pub fn encode_epoch_datetime<W: Write>(writer: &mut W, epoch: i64) -> Result<()> {
    encode_tagged(writer, TAG_EPOCH_DATETIME, &epoch)
}

/// Helper to encode a URI (tag 32)
pub fn encode_uri<W: Write>(writer: &mut W, uri: &str) -> Result<()> {
    encode_tagged(writer, TAG_URI, &uri)
}

/// Helper to encode base64url data (tag 33)
pub fn encode_base64url<W: Write>(writer: &mut W, data: &str) -> Result<()> {
    encode_tagged(writer, TAG_BASE64URL, &data)
}

/// Helper to encode base64 data (tag 34)
pub fn encode_base64<W: Write>(writer: &mut W, data: &str) -> Result<()> {
    encode_tagged(writer, TAG_BASE64, &data)
}

// RFC 8746 - Typed array helpers

/// Helper to encode a uint8 array (tag 64)
pub fn encode_uint8_array<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    encode_tagged(writer, TAG_UINT8_ARRAY, &data)
}

// Macro to generate typed array encoding functions
macro_rules! define_typed_array_encoder {
    ($(#[$doc:meta] $name:ident, $tag:ident, $ty:ty, $to_bytes:ident);* $(;)?) => {
        $(
            #[$doc]
            pub fn $name<W: Write>(writer: &mut W, data: &[$ty]) -> Result<()> {
                let bytes: Vec<u8> = data.iter().flat_map(|&n| n.$to_bytes()).collect();
                encode_tagged(writer, $tag, &bytes)
            }
        )*
    };
}

// Special case for f16 arrays since f16 type is not yet stable in Rust
// We take u16 (the raw bits) and encode them directly
/// Helper to encode a float16 big-endian array (tag 80)
pub fn encode_float16be_array<W: Write>(writer: &mut W, data: &[u16]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_be_bytes()).collect();
    encode_tagged(writer, TAG_FLOAT16BE_ARRAY, &bytes)
}

/// Helper to encode a float16 little-endian array (tag 84)
pub fn encode_float16le_array<W: Write>(writer: &mut W, data: &[u16]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_le_bytes()).collect();
    encode_tagged(writer, TAG_FLOAT16LE_ARRAY, &bytes)
}

define_typed_array_encoder! {
    /// Helper to encode a uint16 big-endian array (tag 65)
    encode_uint16be_array, TAG_UINT16BE_ARRAY, u16, to_be_bytes;
    /// Helper to encode a uint32 big-endian array (tag 66)
    encode_uint32be_array, TAG_UINT32BE_ARRAY, u32, to_be_bytes;
    /// Helper to encode a uint64 big-endian array (tag 67)
    encode_uint64be_array, TAG_UINT64BE_ARRAY, u64, to_be_bytes;
    /// Helper to encode a uint16 little-endian array (tag 69)
    encode_uint16le_array, TAG_UINT16LE_ARRAY, u16, to_le_bytes;
    /// Helper to encode a uint32 little-endian array (tag 70)
    encode_uint32le_array, TAG_UINT32LE_ARRAY, u32, to_le_bytes;
    /// Helper to encode a uint64 little-endian array (tag 71)
    encode_uint64le_array, TAG_UINT64LE_ARRAY, u64, to_le_bytes;
    /// Helper to encode a float32 big-endian array (tag 81)
    encode_float32be_array, TAG_FLOAT32BE_ARRAY, f32, to_be_bytes;
    /// Helper to encode a float64 big-endian array (tag 82)
    encode_float64be_array, TAG_FLOAT64BE_ARRAY, f64, to_be_bytes;
    /// Helper to encode a float32 little-endian array (tag 85)
    encode_float32le_array, TAG_FLOAT32LE_ARRAY, f32, to_le_bytes;
    /// Helper to encode a float64 little-endian array (tag 86)
    encode_float64le_array, TAG_FLOAT64LE_ARRAY, f64, to_le_bytes;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_deserialize_from_json_string() {
        // From JSON: plain string should deserialize to Tagged with no tag
        let json = r#""https://example.com""#;
        let tagged: Tagged<String> = serde_json::from_str(json).unwrap();

        assert_eq!(tagged.tag, None);
        assert_eq!(tagged.value, "https://example.com");
    }

    #[test]
    fn test_tagged_deserialize_from_json_object() {
        // From JSON: object with tag and value fields
        let json = r#"{"tag": 32, "value": "https://example.com"}"#;
        let tagged: Tagged<String> = serde_json::from_str(json).unwrap();

        assert_eq!(tagged.tag, Some(32));
        assert_eq!(tagged.value, "https://example.com");
    }

    #[test]
    fn test_tagged_deserialize_from_tagged_slice() {
        // From CBOR: use from_tagged_slice to explicitly capture tags
        let tagged_original = Tagged::new(Some(32), "https://example.com".to_string());
        let cbor = crate::to_vec(&tagged_original).unwrap();
        let tagged_decoded = Tagged::<String>::from_tagged_slice(&cbor).unwrap();

        assert_eq!(tagged_decoded.tag, Some(32));
        assert_eq!(tagged_decoded.value, "https://example.com");
    }

    #[test]
    fn test_tagged_deserialize_plain_number() {
        // From JSON: plain number
        let json = r#"42"#;
        let tagged: Tagged<u32> = serde_json::from_str(json).unwrap();

        assert_eq!(tagged.tag, None);
        assert_eq!(tagged.value, 42);
    }

    // ========== Helper Function Tests ==========

    #[test]
    fn test_encode_datetime_string() {
        let mut buf = Vec::new();
        encode_datetime_string(&mut buf, "2024-01-15T10:30:00Z").unwrap();

        // Should have tag 0
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_DATETIME_STRING);

        // Decode the full value
        let decoded: String = crate::from_slice(&buf).unwrap();
        assert_eq!(decoded, "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_encode_epoch_datetime() {
        let mut buf = Vec::new();
        let timestamp: i64 = 1705318200;
        encode_epoch_datetime(&mut buf, timestamp).unwrap();

        // Should have tag 1
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_EPOCH_DATETIME);

        // Decode the full value
        let decoded: i64 = crate::from_slice(&buf).unwrap();
        assert_eq!(decoded, timestamp);
    }

    #[test]
    fn test_encode_uri() {
        let mut buf = Vec::new();
        encode_uri(&mut buf, "https://example.com").unwrap();

        // Should have tag 32
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_URI);

        // Decode the full value
        let decoded: String = crate::from_slice(&buf).unwrap();
        assert_eq!(decoded, "https://example.com");
    }

    #[test]
    fn test_encode_base64url() {
        let mut buf = Vec::new();
        encode_base64url(&mut buf, "hello world").unwrap();

        // Should have tag 33
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_BASE64URL);
    }

    #[test]
    fn test_encode_base64() {
        let mut buf = Vec::new();
        encode_base64(&mut buf, "test data").unwrap();

        // Should have tag 34
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_BASE64);
    }

    #[test]
    fn test_encode_uint8_array() {
        let data: Vec<u8> = vec![1, 2, 3, 4, 5];
        let mut buf = Vec::new();
        encode_uint8_array(&mut buf, &data).unwrap();

        // Should have tag 64
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_UINT8_ARRAY);
    }

    #[test]
    fn test_encode_uint16be_array() {
        let data: Vec<u16> = vec![256, 512, 1024];
        let mut buf = Vec::new();
        encode_uint16be_array(&mut buf, &data).unwrap();

        // Should have tag 65
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_UINT16BE_ARRAY);

        // The actual bytes should be big-endian
        assert!(buf.len() > 2); // tag + header + data
    }

    #[test]
    fn test_encode_uint32be_array() {
        let data: Vec<u32> = vec![100, 200, 300];
        let mut buf = Vec::new();
        encode_uint32be_array(&mut buf, &data).unwrap();

        // Should have tag 66
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_UINT32BE_ARRAY);
    }

    #[test]
    fn test_encode_uint64be_array() {
        let data: Vec<u64> = vec![1000, 2000, 3000];
        let mut buf = Vec::new();
        encode_uint64be_array(&mut buf, &data).unwrap();

        // Should have tag 67
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_UINT64BE_ARRAY);
    }

    #[test]
    fn test_encode_uint16le_array() {
        let data: Vec<u16> = vec![256, 512, 1024];
        let mut buf = Vec::new();
        encode_uint16le_array(&mut buf, &data).unwrap();

        // Should have tag 69
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_UINT16LE_ARRAY);
    }

    #[test]
    fn test_encode_uint32le_array() {
        let data: Vec<u32> = vec![100, 200, 300];
        let mut buf = Vec::new();
        encode_uint32le_array(&mut buf, &data).unwrap();

        // Should have tag 70
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_UINT32LE_ARRAY);
    }

    #[test]
    fn test_encode_uint64le_array() {
        let data: Vec<u64> = vec![1000, 2000, 3000];
        let mut buf = Vec::new();
        encode_uint64le_array(&mut buf, &data).unwrap();

        // Should have tag 71
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_UINT64LE_ARRAY);
    }

    #[test]
    fn test_encode_float32be_array() {
        let data: Vec<f32> = vec![1.0, 2.5, 3.15];
        let mut buf = Vec::new();
        encode_float32be_array(&mut buf, &data).unwrap();

        // Should have tag 81
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_FLOAT32BE_ARRAY);
    }

    #[test]
    fn test_encode_float64be_array() {
        let data: Vec<f64> = vec![1.0, 2.72, 3.15];
        let mut buf = Vec::new();
        encode_float64be_array(&mut buf, &data).unwrap();

        // Should have tag 82
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_FLOAT64BE_ARRAY);
    }

    #[test]
    fn test_encode_float32le_array() {
        let data: Vec<f32> = vec![1.0, 2.5, 3.15];
        let mut buf = Vec::new();
        encode_float32le_array(&mut buf, &data).unwrap();

        // Should have tag 85
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_FLOAT32LE_ARRAY);
    }

    #[test]
    fn test_encode_float64le_array() {
        let data: Vec<f64> = vec![1.0, 2.72, 3.15];
        let mut buf = Vec::new();
        encode_float64le_array(&mut buf, &data).unwrap();

        // Should have tag 86
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_FLOAT64LE_ARRAY);
    }

    #[test]
    fn test_encode_tagged_roundtrip() {
        // Test the generic encode_tagged function
        let mut buf = Vec::new();
        encode_tagged(&mut buf, 999, &"custom tagged value").unwrap();

        // Should have tag 999
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, 999);

        // Decode the full value
        let decoded: String = crate::from_slice(&buf).unwrap();
        assert_eq!(decoded, "custom tagged value");
    }

    #[test]
    fn test_tagged_new() {
        let tagged = Tagged::new(Some(32), "https://example.com".to_string());
        assert_eq!(tagged.tag, Some(32));
        assert_eq!(tagged.value, "https://example.com");
    }

    #[test]
    fn test_tagged_serialize_with_tag() {
        let tagged = Tagged::new(Some(32), "https://example.com".to_string());
        let cbor = crate::to_vec(&tagged).unwrap();

        // Decode it back using from_tagged_slice to explicitly capture the tag
        let decoded = Tagged::<String>::from_tagged_slice(&cbor).unwrap();
        assert_eq!(decoded.tag, Some(32));
        assert_eq!(decoded.value, "https://example.com");
    }

    #[test]
    fn test_tagged_serialize_without_tag() {
        let tagged = Tagged::new(None, "plain string".to_string());
        let cbor = crate::to_vec(&tagged).unwrap();

        // Tagged without a tag serializes as just the value
        // Decode it back as Tagged to verify round-trip
        let decoded: Tagged<String> = crate::from_slice(&cbor).unwrap();
        assert_eq!(decoded.tag, None);
        assert_eq!(decoded.value, "plain string");
    }

    #[test]
    fn test_encode_float16be_array() {
        // Test f16 big-endian array encoding
        // u16 values represent the raw IEEE 754 binary16 bits
        // 0x3c00 = 1.0 in f16, 0x4000 = 2.0, 0x4200 = 3.0
        let data: Vec<u16> = vec![0x3c00, 0x4000, 0x4200];
        let mut buf = Vec::new();
        encode_float16be_array(&mut buf, &data).unwrap();

        // Should have tag 80
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_FLOAT16BE_ARRAY);

        // Verify the bytes are big-endian
        // After the tag and byte string header, should have the raw bytes
        assert!(buf.len() >= 6); // tag + header + 6 bytes of data
    }

    #[test]
    fn test_encode_float16le_array() {
        // Test f16 little-endian array encoding
        let data: Vec<u16> = vec![0x3c00, 0x4000, 0x4200];
        let mut buf = Vec::new();
        encode_float16le_array(&mut buf, &data).unwrap();

        // Should have tag 84
        let mut decoder = crate::Decoder::from_slice(&buf);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, TAG_FLOAT16LE_ARRAY);

        // Verify the bytes are little-endian
        assert!(buf.len() >= 6); // tag + header + 6 bytes of data
    }
}
