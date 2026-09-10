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

use std::io::{BufReader, Cursor, Read};

use serde::{Deserialize, de::IntoDeserializer};

use crate::{Error, Result, constants::*, tags};

pub struct Decoder<R: Read> {
    reader: R,
    peeked: Option<u8>,
    max_allocation: Option<usize>,
    recursion_depth: usize,
    max_recursion_depth: usize,
    current_tag: Option<u64>,
    /// When true, `deserialize_any_impl` notifies the visitor of a CBOR tag
    /// via `visit_newtype_struct` instead of transparently skipping past it.
    /// Only safe for a visitor that implements `visit_newtype_struct` (e.g.
    /// `Value`'s); see [`crate::Value::from_tagged_slice`]. Left `false` by
    /// default so plain types keep deserializing straight out of tagged CBOR.
    capture_tags: bool,
}

/// Safely convert u64 to usize, checking for overflow on 32-bit platforms
#[inline]
fn u64_to_usize(val: u64) -> Result<usize> {
    usize::try_from(val).map_err(|_| {
        Error::Syntax(format!(
            "Length {} exceeds maximum supported size on this platform",
            val
        ))
    })
}

/// Hand a CBOR negative integer to `visitor`. Major type 1 encodes the value
/// `-1 - val`, which ranges down to `-2^64` (when `val == u64::MAX`) - wider
/// than `i64` can hold. Values in `i64` range use `visit_i64`; the rest use
/// `visit_i128` (their magnitude always fits `i128`) so an `i128` target
/// decodes correctly and any narrower target gets a clean "invalid type" error
/// instead of the silently wrapped-around `i64` that `-1 - val as i64` produced.
#[inline]
fn visit_negative<'de, V: serde::de::Visitor<'de>>(visitor: V, val: u64) -> Result<V::Value> {
    if val <= i64::MAX as u64 {
        visitor.visit_i64(-1 - val as i64)
    } else {
        visitor.visit_i128(-1i128 - val as i128)
    }
}

impl<R: Read> Decoder<R> {
    /// Create a new CBOR decoder with default limits
    ///
    /// Default limits:
    /// - No allocation limit (relies on `try_reserve` for system-level protection)
    /// - Maximum recursion depth: 128 levels
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    ///
    /// use c2pa_cbor::Decoder;
    ///
    /// let data = vec![0xa0]; // empty map
    /// let decoder = Decoder::new(Cursor::new(&data));
    /// ```
    pub fn new(reader: R) -> Self {
        Decoder {
            reader,
            peeked: None,
            max_allocation: None,
            recursion_depth: 0,
            max_recursion_depth: DEFAULT_MAX_DEPTH,
            current_tag: None,
            capture_tags: false,
        }
    }

    /// Enable tag-capturing mode (builder pattern): notify the visitor of
    /// CBOR tags via `visit_newtype_struct` instead of transparently
    /// skipping past them. Only used internally by
    /// [`crate::Value::from_tagged_slice`].
    pub(crate) fn with_capture_tags(mut self, capture: bool) -> Self {
        self.capture_tags = capture;
        self
    }

    /// Set the maximum allocation size for a single CBOR value (builder pattern)
    ///
    /// This provides defense-in-depth against malicious CBOR with extremely large
    /// length fields. The limit applies to both individual allocations and cumulative
    /// sizes for indefinite-length strings. Even without this limit, `try_reserve`
    /// provides system-level protection.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    ///
    /// use c2pa_cbor::Decoder;
    ///
    /// let data = vec![0xa0];
    /// let decoder = Decoder::new(Cursor::new(&data)).with_max_allocation(1024 * 1024); // 1MB limit
    /// ```
    pub fn with_max_allocation(mut self, max_bytes: usize) -> Self {
        self.max_allocation = Some(max_bytes);
        self
    }

    /// Set the maximum recursion depth for nested structures (builder pattern)
    ///
    /// This prevents stack overflow from deeply nested CBOR structures.
    /// Default is 128 levels, which is sufficient for most use cases.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    ///
    /// use c2pa_cbor::Decoder;
    ///
    /// let data = vec![0xa0];
    /// let decoder = Decoder::new(Cursor::new(&data)).with_max_depth(64); // Max 64 levels of nesting
    /// ```
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_recursion_depth = max_depth;
        self
    }

    fn check_recursion_depth(&self) -> Result<()> {
        if self.recursion_depth >= self.max_recursion_depth {
            return Err(Error::Syntax(format!(
                "CBOR nesting depth {} exceeds maximum {}",
                self.recursion_depth, self.max_recursion_depth
            )));
        }
        Ok(())
    }

    /// Reject a claimed length that exceeds the configured allocation limit.
    ///
    /// This only validates the limit against the *claimed* size - it never
    /// allocates that many bytes up front. Callers read incrementally and let
    /// the buffer grow to the data that actually arrives, so a tiny input
    /// claiming a huge length can't force a large eager allocation.
    fn check_alloc_limit(&self, size: usize) -> Result<()> {
        if let Some(max) = self.max_allocation
            && size > max
        {
            return Err(Error::Syntax(format!(
                "Allocation size {} bytes exceeds maximum {} bytes",
                size, max
            )));
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8> {
        if let Some(byte) = self.peeked.take() {
            return Ok(byte);
        }
        let mut buf = [0u8; 1];
        self.reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.reader.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.reader.read_exact(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }

    fn read_length(&mut self, info: u8) -> Result<Option<u64>> {
        Ok(match info {
            0..=23 => Some(info as u64),
            24 => Some(self.read_u8()? as u64),
            25 => Some(self.read_u16()? as u64),
            26 => Some(self.read_u32()? as u64),
            27 => Some(self.read_u64()?),
            INDEFINITE => None, // Indefinite length
            _ => return Err(Error::Syntax("Invalid CBOR value".to_string())),
        })
    }

    pub(crate) fn peek_u8(&mut self) -> Result<u8> {
        if let Some(byte) = self.peeked {
            return Ok(byte);
        }
        let mut buf = [0u8; 1];
        self.reader.read_exact(&mut buf)?;
        self.peeked = Some(buf[0]);
        Ok(buf[0])
    }

    fn is_break(&mut self) -> Result<bool> {
        let byte = self.peek_u8()?;
        Ok(byte == BREAK)
    }

    fn read_break(&mut self) -> Result<()> {
        let byte = self.read_u8()?;
        if byte != BREAK {
            return Err(Error::Syntax("Expected break marker".to_string()));
        }
        Ok(())
    }

    /// Read a definite-length byte buffer.
    ///
    /// Enforces the allocation limit against the *claimed* length, then reads
    /// incrementally via `take`/`read_to_end` so the buffer only grows to the
    /// bytes that actually arrive. A lying length - a tiny input claiming a
    /// huge string - therefore can't trigger a `len`-sized eager alloc-and-zero
    /// before the read; it just fails with `Eof` once the stream ends short.
    #[inline]
    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        self.check_alloc_limit(len)?;

        let mut buf = Vec::new();
        let read = self
            .reader
            .by_ref()
            .take(len as u64)
            .read_to_end(&mut buf)?;
        if read != len {
            return Err(Error::Eof);
        }
        Ok(buf)
    }

    /// Read a definite-length text string
    #[inline]
    fn read_text(&mut self, len: usize) -> Result<String> {
        let buf = self.read_bytes(len)?;
        String::from_utf8(buf).map_err(|_| Error::InvalidUtf8)
    }

    /// Read indefinite-length byte string by concatenating chunks
    #[inline]
    fn read_indefinite_bytes(&mut self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        loop {
            if self.is_break()? {
                self.read_break()?;
                break;
            }
            let initial = self.read_u8()?;
            let major = initial >> 5;
            let info = initial & 0x1f;
            if major != MAJOR_BYTES {
                return Err(Error::Syntax(
                    "Indefinite byte string chunks must be byte strings".to_string(),
                ));
            }
            let len = self.read_length(info)?.ok_or_else(|| {
                Error::Syntax("Indefinite byte string chunks cannot be indefinite".to_string())
            })?;
            let chunk = self.read_bytes(u64_to_usize(len)?)?;

            // Check cumulative size against max_allocation limit
            let new_size = result.len().saturating_add(chunk.len());
            if let Some(max) = self.max_allocation
                && new_size > max
            {
                return Err(Error::Syntax(format!(
                    "Indefinite byte string total size {} exceeds maximum {} bytes",
                    new_size, max
                )));
            }

            result.extend_from_slice(&chunk);
        }
        Ok(result)
    }

    /// Read indefinite-length text string by concatenating chunks
    #[inline]
    fn read_indefinite_text(&mut self) -> Result<String> {
        let mut result = String::new();
        loop {
            if self.is_break()? {
                self.read_break()?;
                break;
            }
            let initial = self.read_u8()?;
            let major = initial >> 5;
            let info = initial & 0x1f;
            if major != MAJOR_TEXT {
                return Err(Error::Syntax(
                    "Indefinite text string chunks must be text strings".to_string(),
                ));
            }
            let len = self.read_length(info)?.ok_or_else(|| {
                Error::Syntax("Indefinite text string chunks cannot be indefinite".to_string())
            })?;
            let chunk = self.read_text(u64_to_usize(len)?)?;

            // Check cumulative size against max_allocation limit
            let new_size = result.len().saturating_add(chunk.len());
            if let Some(max) = self.max_allocation
                && new_size > max
            {
                return Err(Error::Syntax(format!(
                    "Indefinite text string total size {} exceeds maximum {} bytes",
                    new_size, max
                )));
            }

            result.push_str(&chunk);
        }
        Ok(result)
    }

    pub fn read_tag(&mut self) -> Result<u64> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        if major != MAJOR_TAG {
            return Err(Error::Syntax("Invalid CBOR value".to_string()));
        }

        match self.read_length(info)? {
            Some(tag) => Ok(tag),
            None => Err(Error::Syntax("Tag cannot be indefinite".to_string())),
        }
    }

    pub fn decode<'de, T: Deserialize<'de>>(&mut self) -> Result<T> {
        T::deserialize(&mut *self)
    }

    /// Shared core deserialization logic used by both by-value and by-reference implementations
    #[inline]
    fn deserialize_any_impl<'de, V: serde::de::Visitor<'de>>(
        &mut self,
        visitor: V,
    ) -> Result<V::Value> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        match major {
            MAJOR_UNSIGNED => {
                let val = self.read_length(info)?.ok_or_else(|| {
                    Error::Syntax("Unsigned integer cannot be indefinite".to_string())
                })?;
                visitor.visit_u64(val)
            }
            MAJOR_NEGATIVE => {
                let val = self.read_length(info)?.ok_or_else(|| {
                    Error::Syntax("Negative integer cannot be indefinite".to_string())
                })?;
                visit_negative(visitor, val)
            }
            MAJOR_BYTES => match self.read_length(info)? {
                Some(len) => {
                    let buf = self.read_bytes(u64_to_usize(len)?)?;
                    visitor.visit_byte_buf(buf)
                }
                None => visitor.visit_byte_buf(self.read_indefinite_bytes()?),
            },
            MAJOR_TEXT => match self.read_length(info)? {
                Some(len) => {
                    let s = self.read_text(u64_to_usize(len)?)?;
                    visitor.visit_string(s)
                }
                None => visitor.visit_string(self.read_indefinite_text()?),
            },
            MAJOR_ARRAY => {
                self.check_recursion_depth()?;
                self.recursion_depth += 1;
                match self.read_length(info)? {
                    Some(len) => visitor.visit_seq(SeqAccess {
                        de: self,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_seq(SeqAccess {
                        de: self,
                        remaining: None,
                    }),
                }
                // Note: recursion_depth is decremented in SeqAccess::drop
            }
            MAJOR_MAP => {
                self.check_recursion_depth()?;
                self.recursion_depth += 1;
                match self.read_length(info)? {
                    Some(len) => visitor.visit_map(MapAccess {
                        de: self,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_map(MapAccess {
                        de: self,
                        remaining: None,
                    }),
                }
                // Note: recursion_depth is decremented in MapAccess::drop
            }
            MAJOR_TAG => {
                // Read the tag number
                let tag = self
                    .read_length(info)?
                    .ok_or_else(|| Error::Syntax("Tag cannot be indefinite".to_string()))?;
                // Store the tag
                self.current_tag = Some(tag);

                // For maximum compatibility, decode the inner value
                // transparently using the caller's own visitor (so String,
                // i64, plain structs, etc. work unchanged). The tag is also
                // stashed via a `TagGuard` so a tag-aware visitor - currently
                // just `Value`'s - can reconstruct it without needing a
                // special decode mode; visitors that never call `take_tag`
                // simply never notice it was there, and the guard drains it
                // on drop (even on panic) so it can't leak into an unrelated
                // later decode.
                let _guard = tags::TagGuard::new(tag);
                // A chain of nested tags (e.g. repeated 0xc0 bytes) recurses
                // here just like nested arrays/maps do, so it needs the same
                // depth guard to bound stack usage against malicious input.
                self.check_recursion_depth()?;
                self.recursion_depth += 1;
                let result = serde::Deserializer::deserialize_any(
                    TaggedValueDeserializer { de: self, tag },
                    visitor,
                );
                // Note: recursion_depth is decremented in TaggedValueDeserializer::drop

                // Clear the tag after deserialization
                self.current_tag = None;
                result
            }
            MAJOR_SIMPLE => match info {
                FALSE => visitor.visit_bool(false),
                TRUE => visitor.visit_bool(true),
                NULL => visitor.visit_none(),
                UNDEFINED => visitor.visit_unit(),
                FLOAT16 => {
                    let mut buf = [0u8; 2];
                    self.reader.read_exact(&mut buf)?;
                    // Requires the `half` crate or wait for f16 to be stabilized
                    let f16_value = half::f16::from_be_bytes(buf);
                    visitor.visit_f32(f16_value.to_f32())
                }
                FLOAT32 => {
                    let mut buf = [0u8; 4];
                    self.reader.read_exact(&mut buf)?;
                    visitor.visit_f32(f32::from_be_bytes(buf))
                }
                FLOAT64 => {
                    let mut buf = [0u8; 8];
                    self.reader.read_exact(&mut buf)?;
                    visitor.visit_f64(f64::from_be_bytes(buf))
                }
                _ => Err(Error::Syntax("Invalid CBOR value".to_string())),
            },
            _ => Err(Error::Syntax("Invalid CBOR value".to_string())),
        }
    }

    /// Shared enum deserialization logic used by both by-value and by-reference implementations
    #[inline]
    fn deserialize_enum_impl<'de, V: serde::de::Visitor<'de>>(
        &mut self,
        visitor: V,
    ) -> Result<V::Value> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        match major {
            MAJOR_TEXT => {
                // Unit variant encoded as string
                let len = self.read_length(info)?.ok_or_else(|| {
                    Error::Syntax("Enum variant cannot be indefinite length".to_string())
                })?;
                let s = self.read_text(u64_to_usize(len)?)?;
                visitor.visit_enum(UnitVariantAccess { variant: s })
            }
            MAJOR_MAP => {
                // Variant with data encoded as {"variant": data}
                let len = self.read_length(info)?;
                if len != Some(1) {
                    return Err(Error::Syntax(
                        "Enum variant with data must be single-entry map".to_string(),
                    ));
                }
                visitor.visit_enum(VariantAccess { de: self })
            }
            _ => Err(Error::Syntax("Invalid CBOR type for enum".to_string())),
        }
    }
}

impl<'de> Decoder<&'de [u8]> {
    /// Create a deserializer from a byte slice
    pub fn from_slice(input: &'de [u8]) -> Self {
        Decoder::new(input)
    }
}

impl<'de, R: Read> serde::Deserializer<'de> for Decoder<R> {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct newtype_struct seq tuple
        tuple_struct struct identifier ignored_any
    }

    fn deserialize_option<V: serde::de::Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
        // Peek at next byte to check for null
        let initial = self.read_u8()?;
        if initial == 0xf6 {
            // CBOR null
            visitor.visit_none()
        } else {
            // Not null - process as Some(...)
            let major = initial >> 5;
            let info = initial & 0x1f;

            // Handle the value based on major type
            match major {
                MAJOR_MAP => match self.read_length(info)? {
                    Some(len) => visitor.visit_some(MapDeserializer {
                        de: &mut self,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_some(MapDeserializer {
                        de: &mut self,
                        remaining: None,
                    }),
                },
                MAJOR_ARRAY => match self.read_length(info)? {
                    Some(len) => visitor.visit_some(ArrayDeserializer {
                        de: &mut self,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_some(ArrayDeserializer {
                        de: &mut self,
                        remaining: None,
                    }),
                },
                _ => {
                    // For simple types, deserialize directly
                    visitor.visit_some(PrefetchedDeserializer {
                        de: &mut self,
                        major,
                        info,
                    })
                }
            }
        }
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
        self.deserialize_any_impl(visitor)
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        mut self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_enum_impl(visitor)
    }

    fn deserialize_map<V: serde::de::Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
        // Check for CBOR tag - if present, use TaggedValueDeserializer.deserialize_map
        let peek = self.peek_u8()?;
        let major = peek >> 5;

        if major == MAJOR_TAG {
            // Read the tag
            let initial = self.read_u8()?;
            let info = initial & 0x1f;
            let tag = self
                .read_length(info)?
                .ok_or_else(|| Error::Syntax("Tag cannot be indefinite".to_string()))?;

            self.current_tag = Some(tag);
            self.check_recursion_depth()?;
            self.recursion_depth += 1;
            let result = TaggedValueDeserializer { de: &mut self, tag }.deserialize_map(visitor);
            // Note: recursion_depth is decremented in TaggedValueDeserializer::drop
            self.current_tag = None;
            result
        } else {
            // No tag, process as normal map
            self.deserialize_any_impl(visitor)
        }
    }
}

impl<'de, R: Read> serde::Deserializer<'de> for &mut Decoder<R> {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple
        tuple_struct struct identifier ignored_any
    }

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_option<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        // Peek at next byte - check for CBOR null (0xf6)
        let initial = self.read_u8()?;
        if initial == 0xf6 {
            return visitor.visit_none();
        }

        // Not null - process as Some(...)
        // We've already read the initial byte, so handle it inline
        let major = initial >> 5;
        let info = initial & 0x1f;

        // Handle the value based on major type
        match major {
            MAJOR_MAP => match self.read_length(info)? {
                Some(len) => visitor.visit_some(MapDeserializer {
                    de: self,
                    remaining: Some(u64_to_usize(len)?),
                }),
                None => visitor.visit_some(MapDeserializer {
                    de: self,
                    remaining: None,
                }),
            },
            MAJOR_ARRAY => match self.read_length(info)? {
                Some(len) => visitor.visit_some(ArrayDeserializer {
                    de: self,
                    remaining: Some(u64_to_usize(len)?),
                }),
                None => visitor.visit_some(ArrayDeserializer {
                    de: self,
                    remaining: None,
                }),
            },
            _ => {
                // For simple types, deserialize directly
                // We need to recreate the deserialization with the byte we already read
                visitor.visit_some(PrefetchedDeserializer {
                    de: self,
                    major,
                    info,
                })
            }
        }
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_any_impl(visitor)
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_enum_impl(visitor)
    }

    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        // Newtype structs are serialized transparently (just the inner value)
        // This is serde's standard behavior - the newtype wrapper is not encoded in CBOR
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_map<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        // Check for CBOR tag - if present, use TaggedValueDeserializer.deserialize_map
        let peek = self.peek_u8()?;
        let major = peek >> 5;

        if major == MAJOR_TAG {
            // Read the tag
            let initial = self.read_u8()?;
            let info = initial & 0x1f;
            let tag = self
                .read_length(info)?
                .ok_or_else(|| Error::Syntax("Tag cannot be indefinite".to_string()))?;

            self.current_tag = Some(tag);
            self.check_recursion_depth()?;
            self.recursion_depth += 1;
            let result = TaggedValueDeserializer { de: self, tag }.deserialize_map(visitor);
            // Note: recursion_depth is decremented in TaggedValueDeserializer::drop
            self.current_tag = None;
            result
        } else {
            // No tag, process as normal map
            self.deserialize_any_impl(visitor)
        }
    }
}

// Helper deserializers for Option handling
struct MapDeserializer<'a, R: Read> {
    de: &'a mut Decoder<R>,
    remaining: Option<usize>,
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for MapDeserializer<'a, R> {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_map(MapAccess {
            de: self.de,
            remaining: self.remaining,
        })
    }
}

struct ArrayDeserializer<'a, R: Read> {
    de: &'a mut Decoder<R>,
    remaining: Option<usize>,
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for ArrayDeserializer<'a, R> {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_seq(SeqAccess {
            de: self.de,
            remaining: self.remaining,
        })
    }
}

struct PrefetchedDeserializer<'a, R: Read> {
    de: &'a mut Decoder<R>,
    major: u8,
    info: u8,
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for PrefetchedDeserializer<'a, R> {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.major {
            MAJOR_UNSIGNED => {
                let val = self.de.read_length(self.info)?.ok_or_else(|| {
                    Error::Syntax("Unsigned integer cannot be indefinite".to_string())
                })?;
                visitor.visit_u64(val)
            }
            MAJOR_NEGATIVE => {
                let val = self.de.read_length(self.info)?.ok_or_else(|| {
                    Error::Syntax("Negative integer cannot be indefinite".to_string())
                })?;
                visit_negative(visitor, val)
            }
            MAJOR_TEXT => {
                let len = self.de.read_length(self.info)?.ok_or_else(|| {
                    Error::Syntax("Text in option must be definite length".to_string())
                })?;
                let s = self.de.read_text(u64_to_usize(len)?)?;
                visitor.visit_string(s)
            }
            MAJOR_BYTES => {
                let len = self.de.read_length(self.info)?.ok_or_else(|| {
                    Error::Syntax("Bytes in option must be definite length".to_string())
                })?;
                let buf = self.de.read_bytes(u64_to_usize(len)?)?;
                visitor.visit_byte_buf(buf)
            }
            MAJOR_ARRAY => {
                self.de.check_recursion_depth()?;
                self.de.recursion_depth += 1;
                match self.de.read_length(self.info)? {
                    Some(len) => visitor.visit_seq(SeqAccess {
                        de: self.de,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_seq(SeqAccess {
                        de: self.de,
                        remaining: None,
                    }),
                }
                // Note: recursion_depth is decremented in SeqAccess::drop
            }
            MAJOR_MAP => {
                self.de.check_recursion_depth()?;
                self.de.recursion_depth += 1;
                match self.de.read_length(self.info)? {
                    Some(len) => visitor.visit_map(MapAccess {
                        de: self.de,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_map(MapAccess {
                        de: self.de,
                        remaining: None,
                    }),
                }
                // Note: recursion_depth is decremented in MapAccess::drop
            }
            MAJOR_TAG => {
                // Read the tag number
                let tag = self
                    .de
                    .read_length(self.info)?
                    .ok_or_else(|| Error::Syntax("Tag cannot be indefinite".to_string()))?;
                // Store the tag
                self.de.current_tag = Some(tag);

                // Deserialize the tagged content transparently, using the
                // caller's own visitor. The tag is stashed via a `TagGuard`
                // (same mechanism as the main `deserialize_any_impl` path)
                // so a tag-aware visitor like `Value`'s can reconstruct it;
                // see the comment there.
                let _guard = tags::TagGuard::new(tag);
                self.de.check_recursion_depth()?;
                self.de.recursion_depth += 1;
                let result = serde::Deserializer::deserialize_any(
                    TaggedValueDeserializer { de: self.de, tag },
                    visitor,
                );
                // Note: recursion_depth is decremented in TaggedValueDeserializer::drop

                // Clear the tag after deserialization
                self.de.current_tag = None;
                result
            }
            MAJOR_SIMPLE => match self.info {
                FALSE => visitor.visit_bool(false),
                TRUE => visitor.visit_bool(true),
                UNDEFINED => visitor.visit_unit(),
                FLOAT16 => {
                    let mut buf = [0u8; 2];
                    self.de.reader.read_exact(&mut buf)?;
                    let f16_value = half::f16::from_be_bytes(buf);
                    visitor.visit_f32(f16_value.to_f32())
                }
                FLOAT32 => {
                    let mut buf = [0u8; 4];
                    self.de.reader.read_exact(&mut buf)?;
                    visitor.visit_f32(f32::from_be_bytes(buf))
                }
                FLOAT64 => {
                    let mut buf = [0u8; 8];
                    self.de.reader.read_exact(&mut buf)?;
                    visitor.visit_f64(f64::from_be_bytes(buf))
                }
                _ => Err(Error::Syntax("Invalid simple type in option".to_string())),
            },
            _ => Err(Error::Syntax("Unsupported type in option".to_string())),
        }
    }
}

// Enum access for unit variants (encoded as strings)
struct UnitVariantAccess {
    variant: String,
}

impl<'de> serde::de::EnumAccess<'de> for UnitVariantAccess {
    type Error = crate::Error;
    type Variant = UnitOnly;

    fn variant_seed<V: serde::de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant)> {
        // Deserialize the variant name as a string
        let bytes = crate::to_vec(&self.variant)?;
        let mut decoder = Decoder::new(&bytes[..]);
        let value = seed.deserialize(&mut decoder)?;
        Ok((value, UnitOnly))
    }
}

struct UnitOnly;

impl<'de> serde::de::VariantAccess<'de> for UnitOnly {
    type Error = crate::Error;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T: serde::de::DeserializeSeed<'de>>(
        self,
        _seed: T,
    ) -> Result<T::Value> {
        Err(Error::Syntax("Expected unit variant".to_string()))
    }

    fn tuple_variant<V: serde::de::Visitor<'de>>(
        self,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value> {
        Err(Error::Syntax("Expected unit variant".to_string()))
    }

    fn struct_variant<V: serde::de::Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value> {
        Err(Error::Syntax("Expected unit variant".to_string()))
    }
}

// Enum access for variants with data (encoded as {"variant": data})
struct VariantAccess<'a, R: Read> {
    de: &'a mut Decoder<R>,
}

impl<'de, 'a, R: Read> serde::de::EnumAccess<'de> for VariantAccess<'a, R> {
    type Error = crate::Error;
    type Variant = Self;

    fn variant_seed<V: serde::de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant)> {
        // Read the key (variant name)
        let value = seed.deserialize(&mut *self.de)?;
        Ok((value, self))
    }
}

impl<'de, 'a, R: Read> serde::de::VariantAccess<'de> for VariantAccess<'a, R> {
    type Error = crate::Error;

    fn unit_variant(self) -> Result<()> {
        Err(Error::Syntax("Expected variant with data".to_string()))
    }

    fn newtype_variant_seed<T: serde::de::DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        seed.deserialize(&mut *self.de)
    }

    fn tuple_variant<V: serde::de::Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        serde::de::Deserializer::deserialize_any(&mut *self.de, visitor)
    }

    fn struct_variant<V: serde::de::Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        serde::de::Deserializer::deserialize_any(&mut *self.de, visitor)
    }
}

struct SeqAccess<'a, R: Read> {
    de: &'a mut Decoder<R>,
    remaining: Option<usize>, // None for indefinite-length
}

impl<'a, R: Read> Drop for SeqAccess<'a, R> {
    fn drop(&mut self) {
        self.de.recursion_depth = self.de.recursion_depth.saturating_sub(1);
    }
}

impl<'de, 'a, R: Read> serde::de::SeqAccess<'de> for SeqAccess<'a, R> {
    type Error = crate::Error;

    fn next_element_seed<T: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>> {
        match self.remaining {
            Some(0) => Ok(None),
            Some(ref mut n) => {
                *n -= 1;
                seed.deserialize(&mut *self.de).map(Some)
            }
            None => {
                // Indefinite-length: check for break marker
                if self.de.is_break()? {
                    self.de.read_break()?;
                    Ok(None)
                } else {
                    seed.deserialize(&mut *self.de).map(Some)
                }
            }
        }
    }
}

struct MapAccess<'a, R: Read> {
    de: &'a mut Decoder<R>,
    remaining: Option<usize>, // None for indefinite-length
}

impl<'a, R: Read> Drop for MapAccess<'a, R> {
    fn drop(&mut self) {
        self.de.recursion_depth = self.de.recursion_depth.saturating_sub(1);
    }
}

impl<'de, 'a, R: Read> serde::de::MapAccess<'de> for MapAccess<'a, R> {
    type Error = crate::Error;

    fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>> {
        match self.remaining {
            Some(0) => Ok(None),
            Some(ref mut n) => {
                *n -= 1;
                seed.deserialize(&mut *self.de).map(Some)
            }
            None => {
                // Indefinite-length: check for break marker
                if self.de.is_break()? {
                    self.de.read_break()?;
                    Ok(None)
                } else {
                    seed.deserialize(&mut *self.de).map(Some)
                }
            }
        }
    }

    fn next_value_seed<V: serde::de::DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        seed.deserialize(&mut *self.de)
    }
}

// Helper deserializer that wraps tagged CBOR values
// This provides tag information to Tagged<T> while allowing other types to deserialize normally
struct TaggedValueDeserializer<'a, R: Read> {
    de: &'a mut Decoder<R>,
    tag: u64,
}

// Every construction site increments `recursion_depth` (after checking the
// limit) right before building one of these; this pairs it with a decrement
// so a chain of nested tags is bounded the same way nested arrays/maps are,
// instead of recursing without limit.
impl<'a, R: Read> Drop for TaggedValueDeserializer<'a, R> {
    fn drop(&mut self) {
        self.de.recursion_depth = self.de.recursion_depth.saturating_sub(1);
    }
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for TaggedValueDeserializer<'a, R> {
    type Error = crate::Error;

    // Forward less common types to deserialize_any
    serde::forward_to_deserialize_any! {
        unit unit_struct newtype_struct seq tuple tuple_struct
        enum identifier ignored_any
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        // For deserialize_any, we provide transparent tag handling by default
        // This allows String, i64, etc. to work with tagged CBOR
        self.de.deserialize_any_impl(visitor)
    }

    // Implement specific type deserializations to ignore tags (transparent behavior)
    // This allows plain types like String, i64 to deserialize from tagged CBOR

    fn deserialize_bool<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_i8<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_i16<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_i32<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_i64<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_i128<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_u8<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_u16<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_u32<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_u64<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_u128<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_f32<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_f64<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_char<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_str<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_string<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_bytes<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_byte_buf<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_option<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        // Struct deserialization - pass through to content
        self.de.deserialize_any_impl(visitor)
    }

    fn deserialize_map<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        // When explicitly deserializing as a map, provide the virtual tag map
        // This is for Tagged<T> when it calls deserialize_map
        visitor.visit_map(TaggedMapAccess {
            de: self.de,
            tag: self.tag,
            state: TaggedMapState::BeforeTag,
        })
    }
}

#[derive(Debug)]
enum TaggedMapState {
    BeforeTag,
    AfterTag,
    BeforeValue,
    Done,
}

struct TaggedMapAccess<'a, R: Read> {
    de: &'a mut Decoder<R>,
    tag: u64,
    state: TaggedMapState,
}

impl<'de, 'a, R: Read> serde::de::MapAccess<'de> for TaggedMapAccess<'a, R> {
    type Error = crate::Error;

    fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>> {
        match self.state {
            TaggedMapState::BeforeTag => {
                self.state = TaggedMapState::AfterTag;
                seed.deserialize("tag".into_deserializer()).map(Some)
            }
            TaggedMapState::BeforeValue => {
                self.state = TaggedMapState::Done;
                seed.deserialize("value".into_deserializer()).map(Some)
            }
            TaggedMapState::AfterTag | TaggedMapState::Done => Ok(None),
        }
    }

    fn next_value_seed<V: serde::de::DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        match self.state {
            TaggedMapState::AfterTag => {
                // Return the tag number wrapped in Some for TaggedHelper
                self.state = TaggedMapState::BeforeValue;

                // Create a deserializer that provides Some(tag)
                struct SomeU64Deserializer(u64);
                impl<'de> serde::Deserializer<'de> for SomeU64Deserializer {
                    type Error = crate::Error;

                    serde::forward_to_deserialize_any! {
                        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
                        bytes byte_buf unit unit_struct newtype_struct seq tuple
                        tuple_struct map struct enum identifier ignored_any
                    }

                    fn deserialize_any<V: serde::de::Visitor<'de>>(
                        self,
                        visitor: V,
                    ) -> Result<V::Value> {
                        visitor.visit_some(self.0.into_deserializer())
                    }

                    fn deserialize_option<V: serde::de::Visitor<'de>>(
                        self,
                        visitor: V,
                    ) -> Result<V::Value> {
                        visitor.visit_some(self.0.into_deserializer())
                    }
                }

                seed.deserialize(SomeU64Deserializer(self.tag))
            }
            TaggedMapState::Done => {
                // Return the actual value from the CBOR stream
                seed.deserialize(&mut *self.de)
            }
            _ => Err(Error::Syntax(
                "invalid state in TaggedMapAccess".to_string(),
            )),
        }
    }
}

/// Deserializes a value from CBOR bytes
///
/// Uses Cursor for optimized slice reading performance
pub fn from_slice<'de, T: Deserialize<'de>>(slice: &[u8]) -> Result<T> {
    if slice.is_empty() {
        return Err(Error::Syntax("empty input".to_string()));
    }

    // Use default limit to prevent OOM attacks from malicious CBOR
    // Advanced users can bypass this limit by using Decoder::new() directly
    let mut decoder = Decoder::new(Cursor::new(slice)).with_max_allocation(DEFAULT_MAX_ALLOCATION);
    let value = decoder.decode()?;

    // Check if all bytes were consumed
    let remaining = slice.len() as u64 - decoder.reader.position();
    if remaining > 0 {
        return Err(Error::Syntax(format!(
            "unexpected trailing data: {} bytes remaining",
            remaining
        )));
    }

    Ok(value)
}

/// Deserializes a value from a CBOR reader
///
/// Wraps the reader in a BufReader for optimal performance with small reads.
/// If the reader is already buffered, consider using Decoder::new() directly.
pub fn from_reader<R: Read, T: for<'de> Deserialize<'de>>(reader: R) -> Result<T> {
    // Use default limit to prevent OOM attacks from malicious CBOR
    // Advanced users can bypass this limit by using Decoder::new() directly
    let mut decoder =
        Decoder::new(BufReader::new(reader)).with_max_allocation(DEFAULT_MAX_ALLOCATION);
    decoder.decode()
}

/// Deserializes a value from a CBOR reader with a maximum allocation limit
///
/// This is useful for untrusted input to prevent DoS attacks via extremely
/// large CBOR values. Even without this limit, try_reserve provides system-level
/// protection, but this adds an application-level safety check.
pub fn from_reader_with_limit<R: Read, T: for<'de> Deserialize<'de>>(
    reader: R,
    max_bytes: usize,
) -> Result<T> {
    let mut decoder = Decoder::new(BufReader::new(reader)).with_max_allocation(max_bytes);
    decoder.decode()
}

/// Deserializes a value from CBOR bytes with a maximum allocation limit
///
/// This is useful for untrusted input to prevent DoS attacks via extremely
/// large CBOR values. Even without this limit, try_reserve provides system-level
/// protection, but this adds an application-level safety check.
pub fn from_slice_with_limit<'de, T: Deserialize<'de>>(
    slice: &[u8],
    max_bytes: usize,
) -> Result<T> {
    if slice.is_empty() {
        return Err(Error::Syntax("empty input".to_string()));
    }

    // Wrap in Cursor for better performance with small reads
    let mut decoder = Decoder::new(Cursor::new(slice)).with_max_allocation(max_bytes);
    let value = decoder.decode()?;

    // Check if all bytes were consumed
    let remaining = slice.len() as u64 - decoder.reader.position();
    if remaining > 0 {
        return Err(Error::Syntax(format!(
            "unexpected trailing data: {} bytes remaining",
            remaining
        )));
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Serialize;

    use super::*;
    use crate::{Value, from_slice, from_slice_with_limit, to_vec};

    // ===== deserialize_option =====
    // `Option<T>` routes through `deserialize_option`, which reads the leading
    // byte itself and then hands the rest to `PrefetchedDeserializer` (scalars,
    // tags), `ArrayDeserializer`, or `MapDeserializer`. These cover the arms
    // the existing Some/None round-trip tests don't reach.

    #[test]
    fn option_null_is_none() {
        // 0xf6 is the one byte `deserialize_option` handles directly.
        let decoded: Option<u32> = from_slice(&[0xf6]).unwrap();
        assert_eq!(decoded, None);
    }

    #[test]
    fn option_some_negative_integer() {
        // PrefetchedDeserializer, MAJOR_NEGATIVE arm: 0x20 == -1.
        let decoded: Option<i32> = from_slice(&[0x20]).unwrap();
        assert_eq!(decoded, Some(-1));
    }

    #[test]
    fn option_some_float16() {
        // PrefetchedDeserializer, FLOAT16 arm: 0xf93c00 == 1.0 in half precision.
        let decoded: Option<f32> = from_slice(&[0xf9, 0x3c, 0x00]).unwrap();
        assert_eq!(decoded, Some(1.0));
    }

    #[test]
    fn option_some_float64() {
        // PrefetchedDeserializer, FLOAT64 arm.
        let encoded = to_vec(&Some(2.5f64)).unwrap();
        let decoded: Option<f64> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, Some(2.5));
    }

    #[test]
    fn option_some_indefinite_array() {
        // MAJOR_ARRAY with indefinite length -> ArrayDeserializer { remaining: None }.
        let decoded: Option<Vec<u32>> = from_slice(&[0x9f, 0x01, 0x02, 0xff]).unwrap();
        assert_eq!(decoded, Some(vec![1, 2]));
    }

    #[test]
    fn option_some_indefinite_map() {
        // MAJOR_MAP with indefinite length -> MapDeserializer { remaining: None }.
        let decoded: Option<BTreeMap<String, u32>> =
            from_slice(&[0xbf, 0x61, 0x61, 0x01, 0xff]).unwrap();
        assert_eq!(decoded, Some(BTreeMap::from([("a".to_string(), 1)])));
    }

    #[test]
    fn option_some_tag_is_transparent() {
        // PrefetchedDeserializer, MAJOR_TAG arm: the tag is consumed transparently
        // and the inner value decodes as if untagged. Bytes: tag(0) + "hi".
        let decoded: Option<String> = from_slice(&[0xc0, 0x62, b'h', b'i']).unwrap();
        assert_eq!(decoded, Some("hi".to_string()));
    }

    // ===== deserialize_enum =====
    // `deserialize_enum_impl` only accepts a text string (unit variant) or a
    // single-entry map (variant with data); the happy paths are covered in
    // lib.rs. These exercise its rejection arms, including the MAJOR_TAG hole.

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    enum SampleEnum {
        VariantA,
        Value(u32),
    }

    #[test]
    fn enum_wrapped_in_tag_is_rejected() {
        // KNOWN HOLE: `deserialize_enum` does not unwrap a leading CBOR tag, so a
        // tagged enum encoding is rejected rather than transparently decoded the
        // way `deserialize_any` handles tags. Documented here, not (yet) fixed.
        let mut bytes = to_vec(&SampleEnum::VariantA).unwrap(); // 0x68 "VariantA"
        bytes.insert(0, 0xc0); // prepend tag(0)
        assert!(from_slice::<SampleEnum>(&bytes).is_err());
    }

    #[test]
    fn enum_from_multi_entry_map_is_rejected() {
        // A variant-with-data map must have exactly one entry; a two-entry map
        // is not a valid enum encoding.
        let bytes = [0xa2, 0x61, 0x41, 0x01, 0x61, 0x42, 0x02]; // {"A":1,"B":2}
        assert!(from_slice::<SampleEnum>(&bytes).is_err());
    }

    #[test]
    fn enum_from_indefinite_text_is_rejected() {
        // An indefinite-length text string cannot name a variant.
        assert!(from_slice::<SampleEnum>(&[0x7f]).is_err());
    }

    // ===== deserialize_map =====

    #[test]
    fn map_without_tag_decodes_normally() {
        // Untagged map takes the else-branch straight into deserialize_any_impl.
        let decoded: BTreeMap<String, u32> = from_slice(&[0xa1, 0x61, 0x61, 0x05]).unwrap();
        assert_eq!(decoded, BTreeMap::from([("a".to_string(), 5)]));
    }

    #[test]
    fn tagged_map_projects_to_virtual_tag_value_map() {
        // MAJOR_TAG branch of `deserialize_map`: a tagged value decoded via
        // deserialize_map is projected into a synthetic {"tag", "value"} map
        // (the mechanism behind `Tagged<T>`). Bytes: tag(1) wrapping 5.
        let decoded: BTreeMap<String, Value> = from_slice(&[0xc1, 0x05]).unwrap();
        assert_eq!(
            decoded,
            BTreeMap::from([
                ("tag".to_string(), Value::Integer(1)),
                ("value".to_string(), Value::Integer(5)),
            ])
        );
    }

    // ===== deserialize_any =====
    // Decoding into `Value` exercises `deserialize_any_impl` directly.

    #[test]
    fn any_rejects_indefinite_negative_integer() {
        // MAJOR_NEGATIVE cannot carry an indefinite-length marker.
        assert!(from_slice::<Value>(&[0x3f]).is_err());
    }

    #[test]
    fn any_decodes_undefined_as_null() {
        // MAJOR_SIMPLE / UNDEFINED (0xf7) visits unit, which Value maps to Null.
        assert_eq!(from_slice::<Value>(&[0xf7]).unwrap(), Value::Null);
    }

    #[test]
    fn any_decodes_float16_into_value() {
        // MAJOR_SIMPLE / FLOAT16 widens to f32 then into Value::Float.
        assert_eq!(
            from_slice::<Value>(&[0xf9, 0x3c, 0x00]).unwrap(),
            Value::Float(1.0)
        );
    }

    // ===== negative integers below i64::MIN (regression) =====
    // CBOR major type 1 ranges down to -2^64. The old `-1 - val as i64` silently
    // wrapped anything past i64::MIN (e.g. -2^64 decoded to 0). They now route
    // through visit_i128: correct for i128 targets, a clean error for narrower ones.

    // 0x3b + eight 0xff bytes == -1 - u64::MAX == -2^64.
    const NEG_2_POW_64: [u8; 9] = [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

    #[test]
    fn negative_below_i64_min_decodes_into_i128() {
        let decoded: i128 = from_slice(&NEG_2_POW_64).unwrap();
        assert_eq!(decoded, -(1i128 << 64));
    }

    #[test]
    fn negative_below_i64_min_errors_for_i64_target() {
        // A clean "invalid type" error, not a silently wrapped value.
        assert!(from_slice::<i64>(&NEG_2_POW_64).is_err());
    }

    #[test]
    fn negative_below_i64_min_decodes_into_value() {
        // Regression: this used to silently decode to Value::Integer(0). Now
        // that Value::Integer is i128, -2^64 is represented faithfully.
        assert_eq!(
            from_slice::<Value>(&NEG_2_POW_64).unwrap(),
            Value::Integer(-(1i128 << 64))
        );
    }

    #[test]
    fn negative_just_below_i64_min_decodes_into_i128() {
        // n == i64::MIN - 1; payload val == 2^63, one past the i64 cutoff.
        let bytes = [0x3b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let decoded: i128 = from_slice(&bytes).unwrap();
        assert_eq!(decoded, i64::MIN as i128 - 1);
    }

    #[test]
    fn i64_min_still_round_trips() {
        // Boundary: i64::MIN's payload is i64::MAX, still on the visit_i64 path.
        let bytes = to_vec(&i64::MIN).unwrap();
        assert_eq!(from_slice::<i64>(&bytes).unwrap(), i64::MIN);
    }

    #[test]
    fn u64_above_i64_max_decodes_into_u128() {
        // MAJOR_UNSIGNED already carried the full u64; a u128 target now reaches it.
        let bytes = to_vec(&u64::MAX).unwrap();
        assert_eq!(from_slice::<u128>(&bytes).unwrap(), u64::MAX as u128);
    }

    // ===== read_bytes DoS hardening =====
    // read_bytes no longer eagerly allocates (and zeroes) the *claimed* length
    // before reading; it reads incrementally so a lying length can't force a
    // large allocation from a tiny input.

    #[test]
    fn byte_string_reads_full_body() {
        // Sanity: a well-formed definite-length byte string still decodes fully.
        let value = Value::Bytes(vec![1, 2, 3, 4, 5]);
        let bytes = to_vec(&value).unwrap();
        assert_eq!(from_slice::<Value>(&bytes).unwrap(), value);
    }

    #[test]
    fn byte_string_truncated_body_errors() {
        // Header claims 1000 bytes; only 3 follow -> clean error, not a hang or
        // a 1000-byte allocation.
        let mut bytes = vec![0x59, 0x03, 0xe8]; // byte string, u16 length = 1000
        bytes.extend_from_slice(&[1, 2, 3]);
        assert!(from_slice::<Value>(&bytes).is_err());
    }

    #[test]
    fn byte_string_over_allocation_limit_is_rejected() {
        // Claimed length above the allocation limit is rejected up front,
        // before any read.
        let bytes = [0x5a, 0x00, 0x10, 0x00, 0x00, 0x00]; // byte string, u32 length = 1 MiB
        let err = from_slice_with_limit::<Value>(&bytes, 1024).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn read_bytes_does_not_preallocate_claimed_length() {
        use std::{cell::Cell, io::Read};

        // Records the largest buffer the reader is ever asked to fill. The old
        // read_bytes handed read_exact a full `len`-sized buffer up front; the
        // new one only grows to the bytes that actually arrive.
        struct RecordingReader<'a> {
            data: &'a [u8],
            pos: usize,
            max_buf: &'a Cell<usize>,
        }
        impl Read for RecordingReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.max_buf.set(self.max_buf.get().max(buf.len()));
                let n = (self.data.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }

        // Byte string header claiming 1 MiB, but only 8 bytes of body follow.
        let mut data = vec![0x5a, 0x00, 0x10, 0x00, 0x00]; // byte string, u32 length = 1 MiB
        data.extend_from_slice(&[0u8; 8]);

        let max_buf = Cell::new(0usize);
        let reader = RecordingReader {
            data: &data,
            pos: 0,
            max_buf: &max_buf,
        };
        let mut decoder = Decoder::new(reader);
        let result: Result<Value> = decoder.decode();

        assert!(result.is_err()); // truncated body -> Eof
        assert!(
            max_buf.get() < 100_000,
            "read_bytes handed the reader a {}-byte buffer; it must not pre-size to the claimed length",
            max_buf.get()
        );
    }
}
