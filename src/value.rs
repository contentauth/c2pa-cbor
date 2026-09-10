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

use std::{collections::BTreeMap, fmt};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};

use crate::tags;

/// Dynamic CBOR value type for working with untyped CBOR data
///
/// This type can represent any CBOR value without knowing its type at compile time.
/// It's useful for working with dynamic data or when you need to inspect CBOR structure.
///
/// # Example
/// ```
/// use std::collections::BTreeMap;
///
/// use c2pa_cbor::{Value, from_slice, to_vec};
///
/// // Create a dynamic value
/// let mut map = BTreeMap::new();
/// map.insert(
///     Value::Text("name".to_string()),
///     Value::Text("Alice".to_string()),
/// );
/// map.insert(Value::Text("age".to_string()), Value::Integer(30));
/// let value = Value::Map(map);
///
/// // Serialize and deserialize
/// let bytes = to_vec(&value).unwrap();
/// let decoded: Value = from_slice(&bytes).unwrap();
/// assert_eq!(value, decoded);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Null value
    Null,
    /// Boolean value
    Bool(bool),
    /// Integer value (signed 64-bit)
    Integer(i64),
    /// Floating point value
    Float(f64),
    /// Byte string
    Bytes(Vec<u8>),
    /// Text string
    Text(String),
    /// Array of values
    Array(Vec<Value>),
    /// Map of values
    Map(BTreeMap<Value, Value>),
    /// Tagged value (tag number, boxed content)
    Tag(u64, Box<Value>),
}

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Value::Null => serializer.serialize_none(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::Integer(i) => serializer.serialize_i64(*i),
            Value::Float(f) => serializer.serialize_f64(*f),
            Value::Bytes(b) => serializer.serialize_bytes(b),
            Value::Text(s) => serializer.serialize_str(s),
            Value::Array(a) => a.serialize(serializer),
            Value::Map(m) => m.serialize(serializer),
            Value::Tag(tag, value) => {
                let _guard = tags::TagGuard::new(*tag);
                serializer.serialize_newtype_struct(tags::TAG_MARKER_NAME, value)
            }
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Wraps a freshly-constructed leaf `Value` in nested `Value::Tag`s for
        // every CBOR tag that was just read for it. The decoder pushes each
        // tag number onto a stack immediately before dispatching to whichever
        // visitor method matches the tagged item's shape (see
        // `Decoder::deserialize_any_impl`'s `MAJOR_TAG` arm), so draining the
        // whole stack here - as the very first thing each visitor method does
        // - always captures exactly the tags that apply to this value, never
        // ones belonging to a parent (already consumed further up the call
        // stack) or a child (not yet read off the wire). A CBOR tag can
        // directly wrap another tag (e.g. `tag(1)(tag(2)(5))`), which is why
        // this drains every pending tag rather than just one: by the time `5`
        // is decoded, both 1 and 2 are pending, outermost pushed first, so
        // re-wrapping in reverse (innermost/last-pushed first) reconstructs
        // `Tag(1, Tag(2, Integer(5)))`.
        fn tagged(value: Value) -> Value {
            wrap_tags(value, tags::take_all_tags())
        }

        fn wrap_tags(mut value: Value, tags: Vec<u64>) -> Value {
            for tag in tags.into_iter().rev() {
                value = Value::Tag(tag, Box::new(value));
            }
            value
        }

        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("any valid CBOR value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
                Ok(tagged(Value::Bool(value)))
            }

            fn visit_i8<E>(self, value: i8) -> Result<Value, E> {
                Ok(tagged(Value::Integer(value as i64)))
            }

            fn visit_i16<E>(self, value: i16) -> Result<Value, E> {
                Ok(tagged(Value::Integer(value as i64)))
            }

            fn visit_i32<E>(self, value: i32) -> Result<Value, E> {
                Ok(tagged(Value::Integer(value as i64)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
                Ok(tagged(Value::Integer(value)))
            }

            fn visit_u8<E>(self, value: u8) -> Result<Value, E> {
                Ok(tagged(Value::Integer(value as i64)))
            }

            fn visit_u16<E>(self, value: u16) -> Result<Value, E> {
                Ok(tagged(Value::Integer(value as i64)))
            }

            fn visit_u32<E>(self, value: u32) -> Result<Value, E> {
                Ok(tagged(Value::Integer(value as i64)))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Value, E>
            where
                E: de::Error,
            {
                // Drain the tags before the fallible check below, so they can
                // never leak into a later, unrelated decode if this errors.
                let tags = tags::take_all_tags();
                if value <= i64::MAX as u64 {
                    Ok(wrap_tags(Value::Integer(value as i64), tags))
                } else {
                    Err(E::custom(format!("u64 value {} too large for i64", value)))
                }
            }

            fn visit_f32<E>(self, value: f32) -> Result<Value, E> {
                Ok(tagged(Value::Float(value as f64)))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
                Ok(tagged(Value::Float(value)))
            }

            fn visit_str<E>(self, value: &str) -> Result<Value, E>
            where
                E: de::Error,
            {
                Ok(tagged(Value::Text(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Value, E> {
                Ok(tagged(Value::Text(value)))
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Value, E>
            where
                E: de::Error,
            {
                Ok(tagged(Value::Bytes(value.to_vec())))
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Value, E> {
                Ok(tagged(Value::Bytes(value)))
            }

            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(tagged(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                // Take the tags before recursing: decoding the wrapped value
                // may itself see (and consume) tags of its own.
                let tags = tags::take_all_tags();
                let inner = Deserialize::deserialize(deserializer)?;
                Ok(wrap_tags(inner, tags))
            }

            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(tagged(Value::Null))
            }

            fn visit_seq<V>(self, mut visitor: V) -> Result<Value, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                // Take the tags before iterating: decoding an element may
                // itself see (and consume) tags of its own.
                let tags = tags::take_all_tags();
                let mut vec = Vec::new();
                while let Some(elem) = visitor.next_element()? {
                    vec.push(elem);
                }
                Ok(wrap_tags(Value::Array(vec), tags))
            }

            fn visit_map<V>(self, mut visitor: V) -> Result<Value, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                // Take the tags before iterating: decoding an entry may
                // itself see (and consume) tags of its own.
                let tags = tags::take_all_tags();
                let mut map = BTreeMap::new();
                while let Some((key, value)) = visitor.next_entry()? {
                    map.insert(key, value);
                }
                Ok(wrap_tags(Value::Map(map), tags))
            }

            // Only reached when the decoder is in tag-capturing mode (see
            // `Value::from_tagged_slice`); the tag number was stashed by the
            // decoder just before this call.
            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let tag = crate::tags::take_tag();
                let inner = deserializer.deserialize_any(self)?;
                Ok(match tag {
                    Some(tag) => Value::Tag(tag, Box::new(inner)),
                    None => inner,
                })
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

impl Value {
    /// Returns true if the value is null
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Returns true if the value is a boolean
    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }

    /// Returns true if the value is an integer
    pub fn is_integer(&self) -> bool {
        matches!(self, Value::Integer(_))
    }

    /// Returns true if the value is a float
    pub fn is_float(&self) -> bool {
        matches!(self, Value::Float(_))
    }

    /// Returns true if the value is bytes
    pub fn is_bytes(&self) -> bool {
        matches!(self, Value::Bytes(_))
    }

    /// Returns true if the value is text
    pub fn is_text(&self) -> bool {
        matches!(self, Value::Text(_))
    }

    /// Returns true if the value is an array
    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }

    /// Returns true if the value is a map
    pub fn is_map(&self) -> bool {
        matches!(self, Value::Map(_))
    }

    /// Returns true if the value is tagged
    pub fn is_tag(&self) -> bool {
        matches!(self, Value::Tag(_, _))
    }

    /// Returns the value as a boolean, if it is one
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the value as an integer, if it is one
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the value as a float, if it is one
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Returns the value as bytes, if it is a byte string
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Returns the value as text, if it is a text string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the value as an array, if it is one
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Returns the value as a map, if it is one
    pub fn as_map(&self) -> Option<&BTreeMap<Value, Value>> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the tag number and inner value, if this is a tagged value
    pub fn as_tag(&self) -> Option<(u64, &Value)> {
        match self {
            Value::Tag(tag, value) => Some((*tag, value)),
            _ => None,
        }
    }

    /// Deserialize CBOR bytes into a `Value`, reconstructing any CBOR tags
    /// (major type 6) as `Value::Tag` instead of transparently dropping them.
    ///
    /// This differs from decoding a `Value` via [`crate::from_slice`], which
    /// intentionally ignores tags so that plain types (`String`, `i64`, ...)
    /// can be decoded straight out of tagged CBOR without a wrapper type.
    /// That transparent behavior is unavailable in this tag-aware mode, so
    /// it's only offered for `Value` specifically, not as a general decoder
    /// option.
    ///
    /// # Example
    /// ```
    /// use c2pa_cbor::{Value, to_vec};
    ///
    /// let tagged = Value::Tag(32, Box::new(Value::Text("https://example.com".to_string())));
    /// let bytes = to_vec(&tagged).unwrap();
    ///
    /// let decoded = Value::from_tagged_slice(&bytes).unwrap();
    /// assert_eq!(decoded, tagged);
    /// ```
    pub fn from_tagged_slice(bytes: &[u8]) -> crate::Result<Value> {
        crate::Decoder::from_slice(bytes)
            .with_capture_tags(true)
            .decode()
    }
}

// Implement Eq, PartialOrd, and Ord for Value to allow it to be used as a map key
impl Eq for Value {}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        use Value::*;

        match (self, other) {
            // Null is only equal to Null
            (Null, Null) => Ordering::Equal,
            (Null, _) => Ordering::Less,
            (_, Null) => Ordering::Greater,

            // Bool comparison
            (Bool(a), Bool(b)) => a.cmp(b),
            (Bool(_), _) => Ordering::Less,
            (_, Bool(_)) => Ordering::Greater,

            // Integer comparison
            (Integer(a), Integer(b)) => a.cmp(b),
            (Integer(_), _) => Ordering::Less,
            (_, Integer(_)) => Ordering::Greater,

            // Float comparison - NaN is treated as equal to NaN for ordering purposes
            (Float(a), Float(b)) => {
                if a.is_nan() && b.is_nan() {
                    Ordering::Equal
                } else if a.is_nan() {
                    Ordering::Greater // NaN sorts last
                } else if b.is_nan() {
                    Ordering::Less
                } else {
                    a.partial_cmp(b).unwrap_or(Ordering::Equal)
                }
            }
            (Float(_), _) => Ordering::Less,
            (_, Float(_)) => Ordering::Greater,

            // Bytes comparison
            (Bytes(a), Bytes(b)) => a.cmp(b),
            (Bytes(_), _) => Ordering::Less,
            (_, Bytes(_)) => Ordering::Greater,

            // Text comparison
            (Text(a), Text(b)) => a.cmp(b),
            (Text(_), _) => Ordering::Less,
            (_, Text(_)) => Ordering::Greater,

            // Array comparison
            (Array(a), Array(b)) => a.cmp(b),
            (Array(_), _) => Ordering::Less,
            (_, Array(_)) => Ordering::Greater,

            // Map comparison
            (Map(a), Map(b)) => {
                // Compare maps by converting to sorted vectors and comparing
                let a_vec: Vec<_> = a.iter().collect();
                let b_vec: Vec<_> = b.iter().collect();
                a_vec.cmp(&b_vec)
            }
            (Map(_), _) => Ordering::Less,
            (_, Map(_)) => Ordering::Greater,

            // Tag comparison
            (Tag(tag_a, val_a), Tag(tag_b, val_b)) => match tag_a.cmp(tag_b) {
                Ordering::Equal => val_a.cmp(val_b),
                other => other,
            },
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Convert a `T` into `Value` which is an enum that can represent any valid CBOR data.
///
/// This conversion can fail if `T`'s implementation of `Serialize` decides to
/// fail, or if `T` contains a map with non-string keys.
///
/// Note: Due to how serde works, `Some(x)` will serialize as just `x`, and `None` as `Null`.
/// This means you cannot distinguish between `Some(T)` and `T` in the resulting `Value`.
pub fn to_value<T>(value: T) -> Result<Value, crate::Error>
where
    T: Serialize,
{
    value.serialize(ValueSerializer)
}

struct ValueSerializer;

impl Serializer for ValueSerializer {
    type Error = crate::Error;
    type Ok = Value;
    type SerializeMap = SerializeMap;
    type SerializeSeq = SerializeVec;
    type SerializeStruct = SerializeMap;
    type SerializeStructVariant = SerializeStructVariant;
    type SerializeTuple = SerializeVec;
    type SerializeTupleStruct = SerializeVec;
    type SerializeTupleVariant = SerializeTupleVariant;

    fn serialize_bool(self, v: bool) -> Result<Value, crate::Error> {
        Ok(Value::Bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_i16(self, v: i16) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_i32(self, v: i32) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_i64(self, v: i64) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v))
    }

    fn serialize_u8(self, v: u8) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_u16(self, v: u16) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_u32(self, v: u32) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_u64(self, v: u64) -> Result<Value, crate::Error> {
        if v <= i64::MAX as u64 {
            Ok(Value::Integer(v as i64))
        } else {
            Err(crate::Error::Encoding(format!(
                "u64 value {} too large for i64",
                v
            )))
        }
    }

    fn serialize_f32(self, v: f32) -> Result<Value, crate::Error> {
        Ok(Value::Float(v as f64))
    }

    fn serialize_f64(self, v: f64) -> Result<Value, crate::Error> {
        Ok(Value::Float(v))
    }

    fn serialize_char(self, v: char) -> Result<Value, crate::Error> {
        Ok(Value::Text(v.to_string()))
    }

    fn serialize_str(self, v: &str) -> Result<Value, crate::Error> {
        Ok(Value::Text(v.to_string()))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Value, crate::Error> {
        Ok(Value::Bytes(v.to_vec()))
    }

    fn serialize_none(self) -> Result<Value, crate::Error> {
        Ok(Value::Null)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Value, crate::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Value, crate::Error> {
        Ok(Value::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value, crate::Error> {
        Ok(Value::Null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Value, crate::Error> {
        Ok(Value::Text(variant.to_string()))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Value, crate::Error> {
        // Check if this is the special CBOR tag marker from Tagged<T>/Value::Tag
        if name == tags::TAG_MARKER_NAME
            && let Some(tag) = tags::take_tag()
        {
            return Ok(Value::Tag(tag, Box::new(value.serialize(self)?)));
        }
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Value, crate::Error> {
        let mut map = BTreeMap::new();
        map.insert(
            Value::Text(variant.to_string()),
            value.serialize(ValueSerializer)?,
        );
        Ok(Value::Map(map))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, crate::Error> {
        Ok(SerializeVec { vec: Vec::new() })
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, crate::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, crate::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, crate::Error> {
        Ok(SerializeTupleVariant {
            name: variant.to_string(),
            vec: Vec::new(),
        })
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, crate::Error> {
        Ok(SerializeMap {
            map: BTreeMap::new(),
            next_key: None,
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, crate::Error> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, crate::Error> {
        Ok(SerializeStructVariant {
            name: variant.to_string(),
            map: BTreeMap::new(),
        })
    }
}

struct SerializeVec {
    vec: Vec<Value>,
}

impl serde::ser::SerializeSeq for SerializeVec {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), crate::Error> {
        self.vec.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Value, crate::Error> {
        Ok(Value::Array(self.vec))
    }
}

impl serde::ser::SerializeTuple for SerializeVec {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), crate::Error> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Value, crate::Error> {
        serde::ser::SerializeSeq::end(self)
    }
}

impl serde::ser::SerializeTupleStruct for SerializeVec {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), crate::Error> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Value, crate::Error> {
        serde::ser::SerializeSeq::end(self)
    }
}

struct SerializeTupleVariant {
    name: String,
    vec: Vec<Value>,
}

impl serde::ser::SerializeTupleVariant for SerializeTupleVariant {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), crate::Error> {
        self.vec.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Value, crate::Error> {
        let mut map = BTreeMap::new();
        map.insert(Value::Text(self.name), Value::Array(self.vec));
        Ok(Value::Map(map))
    }
}

struct SerializeMap {
    map: BTreeMap<Value, Value>,
    next_key: Option<Value>,
}

impl serde::ser::SerializeMap for SerializeMap {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), crate::Error> {
        self.next_key = Some(key.serialize(ValueSerializer)?);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), crate::Error> {
        let key = self.next_key.take().ok_or_else(|| {
            crate::Error::Encoding("serialize_value called before serialize_key".to_string())
        })?;
        self.map.insert(key, value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Value, crate::Error> {
        Ok(Value::Map(self.map))
    }
}

impl serde::ser::SerializeStruct for SerializeMap {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), crate::Error> {
        serde::ser::SerializeMap::serialize_entry(self, key, value)
    }

    fn end(self) -> Result<Value, crate::Error> {
        serde::ser::SerializeMap::end(self)
    }
}

struct SerializeStructVariant {
    name: String,
    map: BTreeMap<Value, Value>,
}

impl serde::ser::SerializeStructVariant for SerializeStructVariant {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), crate::Error> {
        self.map.insert(
            Value::Text(key.to_string()),
            value.serialize(ValueSerializer)?,
        );
        Ok(())
    }

    fn end(self) -> Result<Value, crate::Error> {
        let mut outer_map = BTreeMap::new();
        outer_map.insert(Value::Text(self.name), Value::Map(self.map));
        Ok(Value::Map(outer_map))
    }
}

/// Interpret a `Value` as an instance of type `T`.
///
/// This conversion can fail if the structure of the `Value` does not match the
/// structure expected by `T`, for example if `T` is a struct type but the
/// `Value` contains something other than a CBOR map.
pub fn from_value<T>(value: Value) -> Result<T, crate::Error>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = crate::to_vec(&value)?;
    crate::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{from_slice, to_vec};

    #[test]
    fn test_value_null() {
        let value = Value::Null;
        assert!(value.is_null());

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_bool() {
        let value = Value::Bool(true);
        assert!(value.is_bool());
        assert_eq!(value.as_bool(), Some(true));

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_integer() {
        let value = Value::Integer(42);
        assert!(value.is_integer());
        assert_eq!(value.as_i64(), Some(42));

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_text() {
        let value = Value::Text("hello".to_string());
        assert!(value.is_text());
        assert_eq!(value.as_str(), Some("hello"));

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_array() {
        let value = Value::Array(vec![
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
        ]);
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 3);

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_map() {
        let mut map = BTreeMap::new();
        map.insert(Value::Text("key".to_string()), Value::Integer(42));
        let value = Value::Map(map);
        assert!(value.is_map());

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_bytes() {
        // Note: Value::Bytes serializes as CBOR bytes
        let value = Value::Bytes(vec![1, 2, 3, 4, 5]);
        assert!(value.is_bytes());
        assert_eq!(value.as_bytes(), Some(&[1, 2, 3, 4, 5][..]));

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_float() {
        let value = Value::Float(1.23);
        assert!(value.is_float());
        assert_eq!(value.as_f64(), Some(1.23));

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_float_special() {
        // Test NaN
        let value = Value::Float(f64::NAN);
        assert!(value.is_float());
        assert!(value.as_f64().unwrap().is_nan());

        // Test infinity
        let value = Value::Float(f64::INFINITY);
        assert_eq!(value.as_f64(), Some(f64::INFINITY));

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(decoded.as_f64(), Some(f64::INFINITY));
    }

    #[test]
    fn test_value_from_value() {
        // Test conversion from Value to typed value
        let value = Value::Integer(42);
        let num: i32 = from_value(value).unwrap();
        assert_eq!(num, 42);

        let value = Value::Text("hello".to_string());
        let s: String = from_value(value).unwrap();
        assert_eq!(s, "hello");

        let value = Value::Bool(true);
        let b: bool = from_value(value).unwrap();
        assert!(b);
    }

    #[test]
    fn test_value_to_value() {
        // Test conversion from typed value to Value
        let value = to_value(42i32).unwrap();
        assert_eq!(value, Value::Integer(42));

        let value = to_value("hello").unwrap();
        assert_eq!(value, Value::Text("hello".to_string()));

        let value = to_value(true).unwrap();
        assert_eq!(value, Value::Bool(true));
    }

    #[test]
    fn test_value_complex_nested() {
        let mut inner_map = BTreeMap::new();
        inner_map.insert(Value::Text("nested".to_string()), Value::Bool(true));
        inner_map.insert(Value::Text("count".to_string()), Value::Integer(10));

        let value = Value::Array(vec![
            Value::Map(inner_map),
            Value::Bytes(vec![1, 2, 3]),
            Value::Null,
            Value::Float(2.72),
        ]);

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_nested_arrays() {
        let value = Value::Array(vec![
            Value::Array(vec![Value::Integer(1), Value::Integer(2)]),
            Value::Array(vec![Value::Integer(3), Value::Integer(4)]),
        ]);

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_accessors() {
        // Test all the is_* and as_* methods
        let value = Value::Null;
        assert!(value.is_null());
        assert!(!value.is_bool());
        assert!(!value.is_integer());

        let value = Value::Bool(false);
        assert!(value.is_bool());
        assert_eq!(value.as_bool(), Some(false));

        let value = Value::Integer(-100);
        assert!(value.is_integer());
        assert_eq!(value.as_i64(), Some(-100));

        let value = Value::Float(1.5);
        assert!(value.is_float());
        assert_eq!(value.as_f64(), Some(1.5));

        let value = Value::Bytes(vec![0xab, 0xcd]);
        assert!(value.is_bytes());
        assert_eq!(value.as_bytes(), Some(&[0xab, 0xcd][..]));

        let value = Value::Text("test".to_string());
        assert!(value.is_text());
        assert_eq!(value.as_str(), Some("test"));

        let value = Value::Array(vec![]);
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 0);

        let value = Value::Map(BTreeMap::new());
        assert!(value.is_map());
        assert_eq!(value.as_map().unwrap().len(), 0);
    }

    #[test]
    fn test_value_ordering() {
        // Test that Value implements Ord (for use as BTreeMap keys)
        let mut values = vec![Value::Integer(3), Value::Integer(1), Value::Integer(2)];
        values.sort();
        assert_eq!(
            values,
            vec![Value::Integer(1), Value::Integer(2), Value::Integer(3)]
        );

        // Test NaN handling in ordering
        let v1 = Value::Float(1.0);
        let v2 = Value::Float(f64::NAN);
        let v3 = Value::Float(2.0);
        assert!(v1 < v3);
        // NaN should have consistent ordering
        assert_eq!(v2.cmp(&v2), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_value_struct_serialization() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            name: String,
            count: i32,
            active: bool,
        }

        let test = TestStruct {
            name: "test".to_string(),
            count: 42,
            active: true,
        };

        // Convert to Value and back
        let value = to_value(&test).unwrap();
        assert!(value.is_map());

        let decoded: TestStruct = from_value(value).unwrap();
        assert_eq!(decoded, test);
    }

    #[test]
    fn test_value_serialize_newtype_struct() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Wrapper(String);

        let data = Wrapper("wrapped_value".to_string());
        let value = to_value(&data).unwrap();

        // Newtype structs serialize as their inner value
        assert_eq!(value, Value::Text("wrapped_value".to_string()));

        let decoded: Wrapper = from_value(value).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_value_serialize_tuple_struct() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Point(i32, i32, i32);

        let data = Point(10, 20, 30);
        let value = to_value(&data).unwrap();

        // Tuple structs serialize as arrays
        assert!(value.is_array());
        let arr = value.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], Value::Integer(10));
        assert_eq!(arr[1], Value::Integer(20));
        assert_eq!(arr[2], Value::Integer(30));

        let decoded: Point = from_value(value).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_value_serialize_newtype_variant() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum TestEnum {
            Value(i32),
            Text(String),
        }

        let data = TestEnum::Value(42);
        let value = to_value(&data).unwrap();

        // Newtype variants serialize as {"variant": value}
        assert!(value.is_map());
        let map = value.as_map().unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&Value::Text("Value".to_string())));
        assert_eq!(
            map.get(&Value::Text("Value".to_string())),
            Some(&Value::Integer(42))
        );

        let decoded: TestEnum = from_value(value).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_value_serialize_tuple_variant() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum TestEnum {
            Point(i32, i32),
            Color(u8, u8, u8),
        }

        let data = TestEnum::Point(100, 200);
        let value = to_value(&data).unwrap();

        // Tuple variants serialize as {"variant": [values...]}
        assert!(value.is_map());
        let map = value.as_map().unwrap();
        assert_eq!(map.len(), 1);

        let key = Value::Text("Point".to_string());
        assert!(map.contains_key(&key));

        let inner = map.get(&key).unwrap();
        assert!(inner.is_array());
        let arr = inner.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], Value::Integer(100));
        assert_eq!(arr[1], Value::Integer(200));

        let decoded: TestEnum = from_value(value).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_value_serialize_struct_variant() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum TestEnum {
            Person { name: String, age: u32 },
            Location { city: String, country: String },
        }

        let data = TestEnum::Person {
            name: "Alice".to_string(),
            age: 30,
        };
        let value = to_value(&data).unwrap();

        // Struct variants serialize as {"variant": {"field": value, ...}}
        assert!(value.is_map());
        let outer_map = value.as_map().unwrap();
        assert_eq!(outer_map.len(), 1);

        let key = Value::Text("Person".to_string());
        assert!(outer_map.contains_key(&key));

        let inner = outer_map.get(&key).unwrap();
        assert!(inner.is_map());
        let inner_map = inner.as_map().unwrap();
        assert_eq!(inner_map.len(), 2);
        assert_eq!(
            inner_map.get(&Value::Text("name".to_string())),
            Some(&Value::Text("Alice".to_string()))
        );
        assert_eq!(
            inner_map.get(&Value::Text("age".to_string())),
            Some(&Value::Integer(30))
        );

        let decoded: TestEnum = from_value(value).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_value_serialize_tuple_struct_empty() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Empty();

        let data = Empty();
        let value = to_value(&data).unwrap();

        // Empty tuple struct serializes as empty array
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 0);

        let decoded: Empty = from_value(value).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_value_serialize_tuple_variant_nested() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum Outer {
            Data(Vec<i32>, String),
        }

        let data = Outer::Data(vec![1, 2, 3], "test".to_string());
        let value = to_value(&data).unwrap();

        // Verify nested structures work correctly
        assert!(value.is_map());
        let map = value.as_map().unwrap();
        let inner = map.get(&Value::Text("Data".to_string())).unwrap();
        assert!(inner.is_array());
        let arr = inner.as_array().unwrap();
        assert_eq!(arr.len(), 2);

        // First element is an array
        assert!(arr[0].is_array());
        let inner_arr = arr[0].as_array().unwrap();
        assert_eq!(inner_arr.len(), 3);

        // Second element is a string
        assert_eq!(arr[1], Value::Text("test".to_string()));

        let decoded: Outer = from_value(value).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_value_serialize_struct_variant_complex() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum ComplexEnum {
            Config {
                enabled: bool,
                settings: Vec<String>,
                count: u32,
            },
        }

        let data = ComplexEnum::Config {
            enabled: true,
            settings: vec!["opt1".to_string(), "opt2".to_string()],
            count: 5,
        };
        let value = to_value(&data).unwrap();

        // Verify complex struct variant serialization
        assert!(value.is_map());
        let outer_map = value.as_map().unwrap();
        let inner = outer_map.get(&Value::Text("Config".to_string())).unwrap();
        assert!(inner.is_map());
        let inner_map = inner.as_map().unwrap();

        assert_eq!(
            inner_map.get(&Value::Text("enabled".to_string())),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            inner_map.get(&Value::Text("count".to_string())),
            Some(&Value::Integer(5))
        );

        let settings = inner_map.get(&Value::Text("settings".to_string())).unwrap();
        assert!(settings.is_array());

        let decoded: ComplexEnum = from_value(value).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_value_tag_encodes_actual_cbor_tag() {
        let value = Value::Tag(32, Box::new(Value::Text("https://example.com".to_string())));
        let bytes = to_vec(&value).unwrap();

        // Tag 32 is encoded as 0xd8 0x20, followed by the text string
        assert_eq!(bytes[0], 0xd8);
        assert_eq!(bytes[1], 0x20);
    }

    #[test]
    fn test_value_tag_round_trips_via_plain_from_slice() {
        // Regression test for https://github.com/contentauth/c2pa-cbor/issues/27:
        // Value::Tag previously serialized only its inner value on encode,
        // and decode never reconstructed Value::Tag at all, so the tag was
        // silently dropped in both directions.
        let value = Value::Tag(32, Box::new(Value::Text("https://example.com".to_string())));
        let bytes = to_vec(&value).unwrap();

        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_value_tag_round_trips_via_to_value() {
        // Regression test: ValueSerializer::serialize_newtype_struct ignored
        // the TAG_MARKER_NAME sentinel, so to_value() silently dropped the
        // tag even though the binary Encoder (to_vec) handled it correctly.
        let value = Value::Tag(32, Box::new(Value::Text("https://example.com".to_string())));

        let round_tripped = to_value(value.clone()).unwrap();
        assert_eq!(round_tripped, value);
    }

    #[test]
    fn test_value_distinguishes_structurally_similar_cose_tags() {
        // COSE_Mac0 (17), COSE_Sign1 (18), and COSE_Sign (98) are all "an
        // array of four items" - the tag is the only signal distinguishing
        // them. Before the fix, every tag was dropped, so all three
        // collapsed into the same untagged Value.
        for (bytes, expected_tag) in [
            (vec![0xd1u8, 0x01], 17u64),  // tag 17 COSE_Mac0
            (vec![0xd2, 0x01], 18),       // tag 18 COSE_Sign1
            (vec![0xd8, 0x62, 0x01], 98), // tag 98 COSE_Sign
        ] {
            let decoded: Value = from_slice(&bytes).unwrap();
            assert_eq!(
                decoded,
                Value::Tag(expected_tag, Box::new(Value::Integer(1)))
            );
            assert!(decoded.is_tag());
        }
    }

    #[test]
    fn test_value_tag_nested_round_trips() {
        let value = Value::Array(vec![
            Value::Integer(1),
            Value::Tag(1, Box::new(Value::Integer(1705315800))),
            Value::Tag(
                999,
                Box::new(Value::Map(BTreeMap::from([(
                    Value::Text("k".to_string()),
                    Value::Bool(true),
                )]))),
            ),
        ]);
        let bytes = to_vec(&value).unwrap();

        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_value_tag_does_not_leak_into_sibling_field() {
        // A tag stashed while decoding one field must not bleed into an
        // adjacent field decoded as Value, even though both share the same
        // decoder session (and thus the same tag side-channel).
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Pair {
            a: Value,
            b: Value,
        }

        let pair = Pair {
            a: Value::Tag(1, Box::new(Value::Integer(1))),
            b: Value::Integer(2),
        };
        let bytes = to_vec(&pair).unwrap();
        let decoded: Pair = from_slice(&bytes).unwrap();
        assert_eq!(decoded, pair);
    }

    #[test]
    fn test_value_tag_arbitrary_tag_number() {
        // Previously, only a whitelisted set of tag numbers (0-87ish) could
        // be encoded at all; arbitrary tags now work too.
        let value = Value::Tag(123456, Box::new(Value::Integer(1)));
        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_value_tag_directly_wrapping_tag_round_trips() {
        // Regression test: a CBOR tag can directly wrap another tag (no
        // array/map/option in between), e.g. `tag(1)(tag(2)(5))`. The first
        // cut of tag support only drained one pending tag per decoded value,
        // so the inner tag's `TagGuard` clobbered the outer tag on the
        // thread-local stack before anything ever consumed it, silently
        // dropping it.
        let value = Value::Tag(1, Box::new(Value::Tag(2, Box::new(Value::Integer(5)))));
        let bytes = to_vec(&value).unwrap();
        assert_eq!(bytes, vec![0xc1, 0xc2, 0x05]);

        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_value_tag_triple_nested_round_trips() {
        let value = Value::Tag(
            1,
            Box::new(Value::Tag(
                2,
                Box::new(Value::Tag(3, Box::new(Value::Text("x".to_string())))),
            )),
        );
        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_value_tag_wrapping_tagged_array_round_trips() {
        // A tag directly wraps another tag, which itself wraps an array -
        // exercises the wrap_tags fold inside visit_seq.
        let value = Value::Tag(
            1,
            Box::new(Value::Tag(
                2,
                Box::new(Value::Array(vec![Value::Integer(1), Value::Integer(2)])),
            )),
        );
        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
    }
}
