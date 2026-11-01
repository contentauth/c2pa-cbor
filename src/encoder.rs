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

use std::io::Write;

use serde::Serialize;

use crate::{Error, Result, constants::*, tags};

// Encoder
pub struct Encoder<W: Write> {
    writer: W,
    /// When true, applies RFC 8949 §4.2.1's Core Deterministic Encoding
    /// Requirements: map and struct entries are buffered and written in the
    /// bytewise-lexicographic order of their encoded keys, and floats are
    /// written in the shortest width (f16/f32/f64) that preserves their
    /// value, with NaNs canonicalized per §4.2.2. Defaults to false,
    /// preserving the original unsorted, unbuffered, full-width fast path.
    deterministic: bool,
    /// When true, floats are written in the shortest width (f16/f32/f64)
    /// that preserves their value, without requiring full deterministic
    /// mode. Deterministic mode already implies this. Defaults to false,
    /// preserving the original width of the input for maximum compatibility
    /// with decoders that don't expect shortened floats.
    compact_floats: bool,
}

impl<W: Write> Encoder<W> {
    pub fn new(writer: W) -> Self {
        Encoder {
            writer,
            deterministic: false,
            compact_floats: false,
        }
    }

    /// Enable RFC 8949 §4.2.1's Core Deterministic Encoding Requirements:
    /// map and struct entries are buffered and written in the
    /// bytewise-lexicographic order of their encoded keys (and duplicate
    /// keys are rejected), regardless of source order (struct field
    /// declaration order, `HashMap` iteration order, etc.); and floats are
    /// written in the shortest width that preserves their value, with NaNs
    /// canonicalized to the standard half-precision NaN (`0xf97e00`).
    ///
    /// C2PA requires this for manifests. It is off by default because it
    /// requires buffering and isn't needed by callers who only care about
    /// round-tripping through this crate.
    pub fn set_deterministic(mut self, deterministic: bool) -> Self {
        self.deterministic = deterministic;
        self
    }

    /// Write floats in the shortest width (f16/f32/f64) that preserves
    /// their value, on the fast non-deterministic path too. [`Self::set_deterministic`]
    /// already implies this; use this separately when shortest-form floats
    /// are wanted without the sorted-key buffering that deterministic mode
    /// also requires.
    ///
    /// Matches RFC 8949's preferred serialization for floats, but may not
    /// round-trip identically through decoders that don't expect shortened
    /// floats.
    pub fn set_compact_floats(mut self, compact_floats: bool) -> Self {
        self.compact_floats = compact_floats;
        self
    }

    /// Consume the encoder and return the inner writer
    pub fn into_inner(self) -> W {
        self.writer
    }

    fn write_type_value(&mut self, major: u8, value: u64) -> Result<()> {
        if value < 24 {
            self.writer.write_all(&[(major << 5) | value as u8])?;
        } else if value < 256 {
            self.writer.write_all(&[(major << 5) | 24, value as u8])?;
        } else if value < 65536 {
            self.writer.write_all(&[(major << 5) | 25])?;
            self.writer.write_all(&(value as u16).to_be_bytes())?;
        } else if value < 4294967296 {
            self.writer.write_all(&[(major << 5) | 26])?;
            self.writer.write_all(&(value as u32).to_be_bytes())?;
        } else {
            self.writer.write_all(&[(major << 5) | 27])?;
            self.writer.write_all(&value.to_be_bytes())?;
        }
        Ok(())
    }

    pub fn write_tag(&mut self, tag: u64) -> Result<()> {
        self.write_type_value(MAJOR_TAG, tag)
    }

    /// Start an indefinite-length array
    pub fn write_array_indefinite(&mut self) -> Result<()> {
        self.writer.write_all(&[(MAJOR_ARRAY << 5) | INDEFINITE])?;
        Ok(())
    }

    /// Start an indefinite-length map
    pub fn write_map_indefinite(&mut self) -> Result<()> {
        self.writer.write_all(&[(MAJOR_MAP << 5) | INDEFINITE])?;
        Ok(())
    }

    /// Write a break marker to end an indefinite-length collection
    pub fn write_break(&mut self) -> Result<()> {
        self.writer.write_all(&[BREAK])?;
        Ok(())
    }

    pub fn encode<T: Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut *self)
    }

    /// Writes `v` in the shortest float width (f16/f32/f64) that preserves
    /// its value, per RFC 8949 §4.2.1's preferred-serialization requirement.
    ///
    /// NaNs are canonicalized to the standard half-precision NaN (0xf97e00)
    /// rather than preserving the input's sign/payload bits: RFC 8949 §4.2.2
    /// notes protocols that don't need NaN payloads or signaling NaNs should
    /// pick a single representation, and C2PA manifests don't rely on either,
    /// so collapsing every NaN to one encoding keeps output reproducible
    /// regardless of which bit pattern produced the NaN upstream.
    fn write_compact_float(&mut self, v: f64) -> Result<()> {
        if v.is_nan() {
            self.writer
                .write_all(&[(MAJOR_SIMPLE << 5) | FLOAT16, 0x7e, 0x00])?;
            return Ok(());
        }

        let f16_val = half::f16::from_f64(v);
        if f16_val.to_f64() == v {
            self.writer.write_all(&[(MAJOR_SIMPLE << 5) | FLOAT16])?;
            self.writer.write_all(&f16_val.to_be_bytes())?;
            return Ok(());
        }

        let f32_val = v as f32;
        if (f32_val as f64) == v {
            self.writer.write_all(&[(MAJOR_SIMPLE << 5) | FLOAT32])?;
            self.writer.write_all(&f32_val.to_be_bytes())?;
            return Ok(());
        }

        self.writer.write_all(&[(MAJOR_SIMPLE << 5) | FLOAT64])?;
        self.writer.write_all(&v.to_be_bytes())?;
        Ok(())
    }
}

/// Wrapper for serializing sequences/maps with optional buffering
///
/// When serde knows the collection length (the common case), this writes directly
/// to the encoder without buffering. When the length is unknown (e.g., due to
/// `#[serde(flatten)]` or custom iterators), it buffers entries in memory and
/// writes them as definite-length once the count is known.
///
/// This ensures compatibility with `serde_transcode` and maintains C2PA's
/// requirement for definite-length encoding while avoiding the need for
/// indefinite-length CBOR support.
pub enum SerializeVec<'a, W: Write> {
    /// Direct mode: length known, writes immediately (zero overhead)
    Direct { encoder: &'a mut Encoder<W> },
    /// Array buffering mode: length unknown, collects elements
    Array {
        encoder: &'a mut Encoder<W>,
        buffer: Vec<Vec<u8>>,
    },
    /// Map buffering mode: length unknown, collects key-value pairs
    Map {
        encoder: &'a mut Encoder<W>,
        buffer: Vec<(Vec<u8>, Vec<u8>)>,
        pending_key: Option<Vec<u8>>,
    },
}

impl<'a, W: Write> serde::Serializer for &'a mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();
    type SerializeMap = SerializeVec<'a, W>;
    type SerializeSeq = SerializeVec<'a, W>;
    type SerializeStruct = SerializeVec<'a, W>;
    type SerializeStructVariant = SerializeStructVariantBuf<'a, W>;
    type SerializeTuple = SerializeVec<'a, W>;
    type SerializeTupleStruct = SerializeVec<'a, W>;
    type SerializeTupleVariant = &'a mut Encoder<W>;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_bool(self, v: bool) -> Result<()> {
        let val = if v { TRUE } else { FALSE };
        self.writer.write_all(&[(MAJOR_SIMPLE << 5) | val])?;
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<()> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i64(self, v: i64) -> Result<()> {
        if v >= 0 {
            self.write_type_value(MAJOR_UNSIGNED, v as u64)
        } else {
            self.write_type_value(MAJOR_NEGATIVE, (-1 - v) as u64)
        }
    }

    fn serialize_i128(self, v: i128) -> Result<()> {
        // CBOR major types 0/1 cover -2^64 ..= 2^64-1. Values inside that range
        // encode as a normal (un)signed integer; anything beyond would require a
        // bignum (tag 2/3), which this crate does not emit.
        if v >= 0 {
            match u64::try_from(v) {
                Ok(u) => self.write_type_value(MAJOR_UNSIGNED, u),
                Err(_) => Err(Error::Encoding(format!(
                    "i128 value {} exceeds CBOR integer range (bignum not supported)",
                    v
                ))),
            }
        } else {
            // Major type 1 encodes -1 - v; it fits u64 exactly when v >= -2^64.
            match u64::try_from(-1 - v) {
                Ok(payload) => self.write_type_value(MAJOR_NEGATIVE, payload),
                Err(_) => Err(Error::Encoding(format!(
                    "i128 value {} exceeds CBOR integer range (bignum not supported)",
                    v
                ))),
            }
        }
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        self.write_type_value(MAJOR_UNSIGNED, v)
    }

    fn serialize_u128(self, v: u128) -> Result<()> {
        match u64::try_from(v) {
            Ok(u) => self.write_type_value(MAJOR_UNSIGNED, u),
            Err(_) => Err(Error::Encoding(format!(
                "u128 value {} exceeds CBOR integer range (bignum not supported)",
                v
            ))),
        }
    }

    fn serialize_f32(self, v: f32) -> Result<()> {
        if self.deterministic || self.compact_floats {
            return self.write_compact_float(v as f64);
        }

        // Encode as CBOR float32 (major type 7, additional info 26)
        self.writer.write_all(&[(MAJOR_SIMPLE << 5) | FLOAT32])?;
        self.writer.write_all(&v.to_be_bytes())?;
        Ok(())
    }

    fn serialize_f64(self, v: f64) -> Result<()> {
        if self.deterministic || self.compact_floats {
            return self.write_compact_float(v);
        }

        // Default: Use full f64 (double precision) for maximum compatibility
        self.writer.write_all(&[(MAJOR_SIMPLE << 5) | FLOAT64])?;
        self.writer.write_all(&v.to_be_bytes())?;
        Ok(())
    }

    fn serialize_char(self, v: char) -> Result<()> {
        self.serialize_str(&v.to_string())
    }

    fn serialize_str(self, v: &str) -> Result<()> {
        self.write_type_value(MAJOR_TEXT, v.len() as u64)?;
        self.writer.write_all(v.as_bytes())?;
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        self.write_type_value(MAJOR_BYTES, v.len() as u64)?;
        self.writer.write_all(v)?;
        Ok(())
    }

    fn serialize_none(self) -> Result<()> {
        self.writer.write_all(&[(MAJOR_SIMPLE << 5) | NULL])?;
        Ok(())
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<()> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<()> {
        self.serialize_none()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<()> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T>(self, name: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // Check if this is the special CBOR tag marker from Tagged<T>/Value::Tag
        if name == tags::TAG_MARKER_NAME {
            if let Some(tag) = tags::take_tag() {
                self.write_tag(tag)?;
            }
            return value.serialize(self);
        }

        // Serialize transparently (just the inner value, not wrapped in an array)
        // This is serde's default behavior for newtype structs
        // Users can still use #[serde(transparent)] for clarity, but it's not required
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<()> {
        self.write_type_value(MAJOR_MAP, 1)?;
        variant.serialize(&mut *self)?;
        value.serialize(self)?;
        Ok(())
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        match len {
            Some(len) => {
                // Fast path: length known, write header immediately (no buffering)
                self.write_type_value(MAJOR_ARRAY, len as u64)?;
                Ok(SerializeVec::Direct { encoder: self })
            }
            None => {
                // Slow path: length unknown (rare), buffer elements until end()
                // Only happens with custom iterators that don't implement ExactSizeIterator
                Ok(SerializeVec::Array {
                    encoder: self,
                    buffer: Vec::new(),
                })
            }
        }
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.write_type_value(MAJOR_MAP, 1)?;
        variant.serialize(&mut *self)?;
        self.write_type_value(MAJOR_ARRAY, len as u64)?;
        Ok(self)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        // Deterministic encoding requires sorting entries by their encoded key
        // bytes, which is only possible once every entry has been serialized,
        // so it always buffers regardless of whether the length is known.
        if !self.deterministic
            && let Some(len) = len
        {
            // Fast path: length known, write header immediately (no buffering)
            self.write_type_value(MAJOR_MAP, len as u64)?;
            return Ok(SerializeVec::Direct { encoder: self });
        }
        // Slow path: buffer key-value pairs until end()
        Ok(SerializeVec::Map {
            encoder: self,
            buffer: Vec::new(),
            pending_key: None,
        })
    }

    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        // Note: len is the declared field count, but skip_serializing_if may skip some fields
        // To handle this properly, we would need to buffer. For now, we write the declared count
        // and rely on the Serialize impl to not use skip_serializing_if, or to use #[serde(transparent)]
        // The proper fix is for users to not mix skip_serializing_if with CBOR serialization,
        // or to use indefinite-length encoding via manual encoding
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.write_type_value(MAJOR_MAP, 1)?;
        variant.serialize(&mut *self)?;
        Ok(SerializeStructVariantBuf {
            encoder: self,
            buffer: Vec::new(),
        })
    }
}

/// Buffers the fields of a struct variant so they can be written in
/// deterministic (sorted-by-key) order once all fields are known, matching
/// the same requirement enforced for plain maps and structs.
pub struct SerializeStructVariantBuf<'a, W: Write> {
    encoder: &'a mut Encoder<W>,
    buffer: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<'a, W: Write> serde::ser::SerializeStructVariant for SerializeStructVariantBuf<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        let deterministic = self.encoder.deterministic;
        let compact_floats = self.encoder.compact_floats;
        let key_bytes =
            SerializeVec::<W>::serialize_to_buffer(&key, deterministic, compact_floats)?;
        let value_bytes =
            SerializeVec::<W>::serialize_to_buffer(value, deterministic, compact_floats)?;
        self.buffer.push((key_bytes, value_bytes));
        Ok(())
    }

    fn end(self) -> Result<()> {
        let SerializeStructVariantBuf {
            encoder,
            mut buffer,
        } = self;
        if encoder.deterministic {
            buffer.sort_by(|a, b| a.0.cmp(&b.0));
            if buffer.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(Error::Encoding(
                    "duplicate map key in deterministic CBOR encoding".to_string(),
                ));
            }
        }
        encoder.write_type_value(MAJOR_MAP, buffer.len() as u64)?;
        for (key_bytes, value_bytes) in buffer {
            SerializeVec::<W>::write_buffered(encoder, &key_bytes)?;
            SerializeVec::<W>::write_buffered(encoder, &value_bytes)?;
        }
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeSeq for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeTuple for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeTupleStruct for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeTupleVariant for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeMap for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<()> {
        key.serialize(&mut **self)
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeStruct for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        key.serialize(&mut **self)?;
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

// Implementations for SerializeVec (handles buffering for unknown-length collections)

impl<'a, W: Write> SerializeVec<'a, W> {
    /// Serialize a value to a buffer for later writing, inheriting the
    /// outer encoder's determinism and float-width settings for any nested
    /// maps/structs
    fn serialize_to_buffer<T>(
        value: &T,
        deterministic: bool,
        compact_floats: bool,
    ) -> Result<Vec<u8>>
    where
        T: ?Sized + Serialize,
    {
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf)
            .set_deterministic(deterministic)
            .set_compact_floats(compact_floats);
        value.serialize(&mut encoder)?;
        Ok(buf)
    }

    /// Write buffered bytes to the encoder's writer
    fn write_buffered(encoder: &mut Encoder<W>, bytes: &[u8]) -> Result<()> {
        encoder.writer.write_all(bytes)?;
        Ok(())
    }
}

impl<'a, W: Write> serde::ser::SerializeSeq for SerializeVec<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        match self {
            SerializeVec::Direct { encoder } => value.serialize(&mut **encoder),
            SerializeVec::Array { encoder, buffer } => {
                buffer.push(Self::serialize_to_buffer(
                    value,
                    encoder.deterministic,
                    encoder.compact_floats,
                )?);
                Ok(())
            }
            SerializeVec::Map { .. } => Err(Error::Encoding(
                "serialize_element called on map serializer".to_string(),
            )),
        }
    }

    fn end(self) -> Result<()> {
        match self {
            SerializeVec::Direct { .. } => Ok(()),
            SerializeVec::Array { encoder, buffer } => {
                // Write definite-length array header now that we know the count
                encoder.write_type_value(MAJOR_ARRAY, buffer.len() as u64)?;
                // Write all buffered elements
                for element_bytes in buffer {
                    Self::write_buffered(encoder, &element_bytes)?;
                }
                Ok(())
            }
            SerializeVec::Map { .. } => {
                Err(Error::Encoding("end called on map serializer".to_string()))
            }
        }
    }
}

impl<'a, W: Write> serde::ser::SerializeTuple for SerializeVec<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<()> {
        serde::ser::SerializeSeq::end(self)
    }
}

impl<'a, W: Write> serde::ser::SerializeTupleStruct for SerializeVec<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<()> {
        serde::ser::SerializeSeq::end(self)
    }
}

impl<'a, W: Write> serde::ser::SerializeMap for SerializeVec<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_key<T>(&mut self, key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        match self {
            SerializeVec::Direct { encoder } => key.serialize(&mut **encoder),
            SerializeVec::Map {
                pending_key,
                encoder,
                ..
            } => {
                *pending_key = Some(Self::serialize_to_buffer(
                    key,
                    encoder.deterministic,
                    encoder.compact_floats,
                )?);
                Ok(())
            }
            SerializeVec::Array { .. } => Err(Error::Encoding(
                "serialize_key called on array serializer".to_string(),
            )),
        }
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        match self {
            SerializeVec::Direct { encoder } => value.serialize(&mut **encoder),
            SerializeVec::Map {
                buffer,
                pending_key,
                encoder,
            } => {
                let value_bytes = Self::serialize_to_buffer(
                    value,
                    encoder.deterministic,
                    encoder.compact_floats,
                )?;
                if let Some(key_bytes) = pending_key.take() {
                    buffer.push((key_bytes, value_bytes));
                    Ok(())
                } else {
                    Err(Error::Encoding(
                        "serialize_value called without serialize_key".to_string(),
                    ))
                }
            }
            SerializeVec::Array { .. } => Err(Error::Encoding(
                "serialize_value called on array serializer".to_string(),
            )),
        }
    }

    fn end(self) -> Result<()> {
        match self {
            SerializeVec::Direct { .. } => Ok(()),
            SerializeVec::Map {
                encoder,
                mut buffer,
                pending_key,
            } => {
                if pending_key.is_some() {
                    return Err(Error::Encoding(
                        "serialize_key called without serialize_value".to_string(),
                    ));
                }
                // RFC 8949 §4.2.1: map keys must be sorted in the bytewise
                // lexicographic order of their encoded bytes. `Vec<u8>`'s
                // `Ord` is already a byte-for-byte lexicographic comparison,
                // so sorting on the encoded key bytes directly satisfies this.
                // The RFC also disallows duplicate keys, so that's only
                // checked in this same deterministic mode.
                if encoder.deterministic {
                    buffer.sort_by(|a, b| a.0.cmp(&b.0));
                    if buffer.windows(2).any(|w| w[0].0 == w[1].0) {
                        return Err(Error::Encoding(
                            "duplicate map key in deterministic CBOR encoding".to_string(),
                        ));
                    }
                }
                // Write definite-length map header now that we know the count
                encoder.write_type_value(MAJOR_MAP, buffer.len() as u64)?;
                // Write all buffered key-value pairs
                for (key_bytes, value_bytes) in buffer {
                    Self::write_buffered(encoder, &key_bytes)?;
                    Self::write_buffered(encoder, &value_bytes)?;
                }
                Ok(())
            }
            SerializeVec::Array { .. } => Err(Error::Encoding(
                "end called on array serializer".to_string(),
            )),
        }
    }
}

impl<'a, W: Write> serde::ser::SerializeStruct for SerializeVec<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        serde::ser::SerializeMap::serialize_entry(self, key, value)
    }

    fn end(self) -> Result<()> {
        serde::ser::SerializeMap::end(self)
    }
}

// Convenience functions
fn to_vec_with<T: Serialize>(value: &T, deterministic: bool) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut encoder = Encoder::new(&mut buf).set_deterministic(deterministic);
    encoder.encode(value)?;
    Ok(buf)
}

/// Serializes a value to a CBOR byte vector, preserving declaration/insertion
/// order for map and struct keys (the original unsorted, unbuffered fast
/// path).
///
/// C2PA manifests require deterministic (sorted-key) encoding; use
/// [`to_vec_deterministic`] or [`Encoder::set_deterministic`] for that.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    to_vec_with(value, false)
}

/// Like [`to_vec`], but map and struct keys are written in the
/// bytewise-lexicographic order of their encoded bytes, per RFC 8949
/// §4.2.1, as required by C2PA.
pub fn to_vec_deterministic<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    to_vec_with(value, true)
}

/// Serializes a value to a CBOR writer, preserving declaration/insertion
/// order for map and struct keys (the original unsorted, unbuffered fast
/// path).
///
/// C2PA manifests require deterministic (sorted-key) encoding; use
/// [`to_writer_deterministic`] or [`Encoder::set_deterministic`] for that.
pub fn to_writer<W: Write, T: Serialize>(writer: W, value: &T) -> Result<()> {
    let mut encoder = Encoder::new(writer);
    encoder.encode(value)?;
    Ok(())
}

/// Like [`to_writer`], but map and struct keys are written in the
/// bytewise-lexicographic order of their encoded bytes, per RFC 8949
/// §4.2.1, as required by C2PA.
pub fn to_writer_deterministic<W: Write, T: Serialize>(writer: W, value: &T) -> Result<()> {
    let mut encoder = Encoder::new(writer).set_deterministic(true);
    encoder.encode(value)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::{Serialize, Serializer, ser::SerializeSeq};

    use super::*;
    use crate::from_slice;

    /// Encode a single float through the private shortest-width helper.
    fn compact_bytes(v: f64) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf);
            enc.write_compact_float(v).unwrap();
        }
        buf
    }

    #[test]
    fn compact_float_picks_half_for_small_exact_values() {
        // Values exactly representable in half precision use FLOAT16 (0xf9) + 2 bytes.
        assert_eq!(compact_bytes(0.0), vec![0xf9, 0x00, 0x00]);
        assert_eq!(compact_bytes(-0.0), vec![0xf9, 0x80, 0x00]);
        assert_eq!(compact_bytes(1.0), vec![0xf9, 0x3c, 0x00]);
        assert_eq!(compact_bytes(1.5), vec![0xf9, 0x3e, 0x00]);
        // 65504 is the largest finite half-precision value.
        assert_eq!(compact_bytes(65504.0), vec![0xf9, 0x7b, 0xff]);
    }

    #[test]
    fn compact_float_encodes_infinities_as_half() {
        assert_eq!(compact_bytes(f64::INFINITY), vec![0xf9, 0x7c, 0x00]);
        assert_eq!(compact_bytes(f64::NEG_INFINITY), vec![0xf9, 0xfc, 0x00]);
    }

    #[test]
    fn compact_float_canonicalizes_every_nan_to_one_encoding() {
        let canonical = vec![0xf9, 0x7e, 0x00];
        assert_eq!(compact_bytes(f64::NAN), canonical);
        // Negative NaN, a quiet NaN with a payload, and a signaling NaN must
        // all collapse to the same bytes (RFC 8949 §4.2.2).
        assert_eq!(
            compact_bytes(f64::from_bits(0xfff8_0000_0000_0000)),
            canonical
        );
        assert_eq!(
            compact_bytes(f64::from_bits(0x7ff8_0000_0000_0001)),
            canonical
        );
        assert_eq!(
            compact_bytes(f64::from_bits(0x7ff0_0000_0000_0001)),
            canonical
        );
    }

    #[test]
    fn compact_float_falls_back_to_single_when_half_is_lossy() {
        // Out of half's range but exactly representable as f32.
        let v = 100_000.0_f64;
        let mut expected = vec![0xfa];
        expected.extend_from_slice(&(v as f32).to_be_bytes());
        assert_eq!(compact_bytes(v), expected);
        assert_eq!(compact_bytes(v).len(), 5);
    }

    #[test]
    fn compact_float_falls_back_to_double_when_single_is_lossy() {
        // 0.1 is not exactly representable in half or single precision.
        let v = 0.1_f64;
        let mut expected = vec![0xfb];
        expected.extend_from_slice(&v.to_be_bytes());
        assert_eq!(compact_bytes(v), expected);
        assert_eq!(compact_bytes(v).len(), 9);
    }

    #[test]
    fn serialize_f64_stays_full_width_unless_asked() {
        // Plain to_vec is neither deterministic nor compact: full FLOAT64.
        let mut expected = vec![0xfb];
        expected.extend_from_slice(&1.5f64.to_be_bytes());
        assert_eq!(to_vec(&1.5f64).unwrap(), expected);
    }

    #[test]
    fn serialize_f64_compacts_in_deterministic_mode() {
        assert_eq!(
            to_vec_deterministic(&1.5f64).unwrap(),
            vec![0xf9, 0x3e, 0x00]
        );
    }

    #[test]
    fn serialize_f32_compacts_when_flag_set() {
        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf).set_compact_floats(true);
            enc.encode(&1.5f32).unwrap();
        }
        assert_eq!(buf, vec![0xf9, 0x3e, 0x00]);
    }

    #[test]
    fn serialize_f32_compact_keeps_single_width_when_needed() {
        // 0.1f32 widened to f64 is still exactly f32-representable, so the
        // shortest lossless width is f32, not f64.
        let v = 0.1_f32;
        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf).set_compact_floats(true);
            enc.encode(&v).unwrap();
        }
        let mut expected = vec![0xfa];
        expected.extend_from_slice(&v.to_be_bytes());
        assert_eq!(buf, expected);
    }

    /// A `Serialize` wrapper that reports no length hint, forcing the encoder
    /// down the buffering path (`SerializeVec::Array` + `serialize_to_buffer`)
    /// instead of the direct fast path.
    struct UnknownLenSeq<T>(Vec<T>);

    impl<T: Serialize> Serialize for UnknownLenSeq<T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
            let mut seq = serializer.serialize_seq(None)?;
            for item in &self.0 {
                seq.serialize_element(item)?;
            }
            seq.end()
        }
    }

    #[test]
    fn buffered_seq_matches_known_length_and_round_trips() {
        let items = vec![1i64, 2, 3];
        let buffered = to_vec(&UnknownLenSeq(items.clone())).unwrap();

        // Buffering resolves to the same definite-length encoding a known
        // length would have produced.
        assert_eq!(buffered, to_vec(&items).unwrap());
        // Definite-length 3-element array header, not indefinite.
        assert_eq!(buffered[0], (MAJOR_ARRAY << 5) | 3);

        let decoded: Vec<i64> = from_slice(&buffered).unwrap();
        assert_eq!(decoded, items);
    }

    #[test]
    fn buffered_seq_inherits_compact_floats() {
        // serialize_to_buffer must thread the outer encoder's compact_floats
        // flag into each buffered element.
        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf).set_compact_floats(true);
            enc.encode(&UnknownLenSeq(vec![1.5f64])).unwrap();
        }
        // 1-element array, then a half-precision 1.5.
        assert_eq!(buf, vec![(MAJOR_ARRAY << 5) | 1, 0xf9, 0x3e, 0x00]);
    }

    #[test]
    fn buffered_seq_inherits_deterministic_key_sorting() {
        #[derive(Serialize)]
        struct Inner {
            b: u8,
            a: u8,
        }

        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf).set_deterministic(true);
            enc.encode(&UnknownLenSeq(vec![Inner { b: 2, a: 1 }]))
                .unwrap();
        }
        // Outer array(1); the buffered inner map has its keys sorted so "a"
        // (0x6161) precedes "b" (0x6162) despite the field declaration order.
        assert_eq!(
            buf,
            vec![
                (MAJOR_ARRAY << 5) | 1, // array(1)
                (MAJOR_MAP << 5) | 2,   // map(2)
                0x61,
                0x61,
                0x01, // "a": 1
                0x61,
                0x62,
                0x02, // "b": 2
            ]
        );
    }

    #[test]
    fn buffered_seq_without_deterministic_keeps_insertion_order() {
        #[derive(Serialize)]
        struct Inner {
            b: u8,
            a: u8,
        }

        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf);
            enc.encode(&UnknownLenSeq(vec![Inner { b: 2, a: 1 }]))
                .unwrap();
        }
        // Without deterministic mode the buffered element keeps declaration
        // order: "b" before "a".
        assert_eq!(
            buf,
            vec![
                (MAJOR_ARRAY << 5) | 1, // array(1)
                (MAJOR_MAP << 5) | 2,   // map(2)
                0x61,
                0x62,
                0x02, // "b": 2
                0x61,
                0x61,
                0x01, // "a": 1
            ]
        );
    }
}
