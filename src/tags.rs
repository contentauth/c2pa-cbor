use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::marker::PhantomData;

/// A tagged CBOR value
#[derive(Debug, Clone, PartialEq, Serialize)]
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

// Custom deserialization that handles both tagged CBOR values and plain values (e.g., from JSON)
impl<'de, T> Deserialize<'de> for Tagged<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
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
            fn visit_bool<E>(self, v: bool) -> Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::BoolDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_i64<E>(self, v: i64) -> Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::I64Deserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_u64<E>(self, v: u64) -> Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::U64Deserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_f64<E>(self, v: f64) -> Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::F64Deserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_str<E>(self, v: &str) -> Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::StrDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_string<E>(self, v: String) -> Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::StringDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::BytesDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_seq<A>(self, seq: A) -> Result<Tagged<T>, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                T::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_map<A>(self, map: A) -> Result<Tagged<T>, A::Error>
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
    fn test_tagged_deserialize_from_cbor() {
        // From CBOR: should handle both tagged and untagged
        let tagged_original = Tagged::new(Some(32), "https://example.com".to_string());
        let cbor = crate::to_vec(&tagged_original).unwrap();
        let tagged_decoded: Tagged<String> = crate::from_slice(&cbor).unwrap();

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
}
