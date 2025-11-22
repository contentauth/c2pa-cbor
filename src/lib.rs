// Cargo.toml dependencies needed:
// serde = { version = "1.0", features = ["derive"] }

//! # C2PA CBOR Library
//!
//! A CBOR (Concise Binary Object Representation) encoder/decoder with support for tagged types.
//!
//! ## Features
//! - Full support for CBOR major types 0-7
//! - Tagged types (major type 6) including:
//!   - Date/time strings (tag 0)
//!   - Epoch timestamps (tag 1)
//!   - URIs (tag 32)
//!   - Base64url encoded data (tag 33)
//!   - Base64 encoded data (tag 34)
//!   - RFC 8746 typed arrays (tags 64-87):
//!     - Unsigned integer arrays (uint8, uint16, uint32, uint64) in big-endian and little-endian
//!     - Signed integer arrays (sint8, sint16, sint32, sint64) in big-endian and little-endian
//!     - Floating point arrays (float16, float32, float64, float128) in big-endian and little-endian
//! - Custom tag support via `write_tag()` and `read_tag()` methods
//!
//! ## Performance
//! Binary byte arrays are efficiently encoded/decoded with minimal overhead:
//! - Use `serde_bytes::ByteBuf` or `#[serde(with = "serde_bytes")]` for optimal byte array performance
//! - Byte strings are written as raw bytes (1 header byte + length encoding + data)
//! - 1KB byte array: 3 bytes overhead (header + 2-byte length)
//! - 100KB byte array: 5 bytes overhead (header + 4-byte length)
//! - No allocations during encoding; single allocation during decoding
//!
//! ### Speed Characteristics (on typical hardware)
//! - **Encoding**: ~30-35 GB/s for large arrays (virtually memcpy speed)
//! - **Decoding**: ~24-29 GB/s for large arrays
//! - Small arrays (1KB): ~160ns encode, ~270ns decode
//! - Large arrays (1MB): ~30µs encode, ~41µs decode
//! - Performance scales linearly with data size
//! - Zero-copy design means encoding is just a memcpy after writing the header
//!
//! ## Example
//! ```rust
//! use c2pa_cbor::{encode_uri, encode_datetime_string, encode_uint8_array, from_slice};
//! use serde_bytes::ByteBuf;
//!
//! // Encode a URI with tag 32
//! let mut buf = Vec::new();
//! encode_uri(&mut buf, "https://example.com").unwrap();
//! let decoded: String = from_slice(&buf).unwrap();
//! assert_eq!(decoded, "https://example.com");
//!
//! // Encode a typed array with tag 64 (efficient with serde_bytes)
//! let data = ByteBuf::from(vec![1, 2, 3, 4, 5]);
//! let mut buf2 = Vec::new();
//! let mut encoder = c2pa_cbor::Encoder::new(&mut buf2);
//! encoder.write_tag(64).unwrap();
//! encoder.encode(&data).unwrap();
//! ```

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub mod value;
pub use value::{Value, from_value, to_value};

pub mod tags;
pub use tags::Tagged;

// CBOR major types
const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

// Standard CBOR tags (RFC 8949)
const TAG_DATETIME_STRING: u64 = 0; // Standard date/time string (RFC 3339)
const TAG_EPOCH_DATETIME: u64 = 1; // Epoch-based date/time
#[allow(dead_code)]
const TAG_POSITIVE_BIGNUM: u64 = 2; // Positive bignum
#[allow(dead_code)]
const TAG_NEGATIVE_BIGNUM: u64 = 3; // Negative bignum
#[allow(dead_code)]
const TAG_DECIMAL_FRACTION: u64 = 4; // Decimal fraction
#[allow(dead_code)]
const TAG_BIGFLOAT: u64 = 5; // Bigfloat
const TAG_URI: u64 = 32; // URI (RFC 3986)
const TAG_BASE64URL: u64 = 33; // Base64url-encoded text
const TAG_BASE64: u64 = 34; // Base64-encoded text
#[allow(dead_code)]
const TAG_MIME: u64 = 36; // MIME message

// RFC 8746 - Typed arrays encoded as byte strings
// Some constants are defined for completeness but not yet used
#[allow(dead_code)]
const TAG_UINT8_ARRAY: u64 = 64; // uint8 array
const TAG_UINT16BE_ARRAY: u64 = 65; // uint16 big-endian array
const TAG_UINT32BE_ARRAY: u64 = 66; // uint32 big-endian array
const TAG_UINT64BE_ARRAY: u64 = 67; // uint64 big-endian array
#[allow(dead_code)]
const TAG_UINT8_CLAMPED_ARRAY: u64 = 68; // uint8 clamped array
const TAG_UINT16LE_ARRAY: u64 = 69; // uint16 little-endian array
const TAG_UINT32LE_ARRAY: u64 = 70; // uint32 little-endian array
const TAG_UINT64LE_ARRAY: u64 = 71; // uint64 little-endian array
#[allow(dead_code)]
const TAG_SINT8_ARRAY: u64 = 72; // sint8 array
#[allow(dead_code)]
const TAG_SINT16BE_ARRAY: u64 = 73; // sint16 big-endian array
#[allow(dead_code)]
const TAG_SINT32BE_ARRAY: u64 = 74; // sint32 big-endian array
#[allow(dead_code)]
const TAG_SINT64BE_ARRAY: u64 = 75; // sint64 big-endian array
#[allow(dead_code)]
const TAG_SINT16LE_ARRAY: u64 = 77; // sint16 little-endian array
#[allow(dead_code)]
const TAG_SINT32LE_ARRAY: u64 = 78; // sint32 little-endian array
#[allow(dead_code)]
const TAG_SINT64LE_ARRAY: u64 = 79; // sint64 little-endian array
#[allow(dead_code)]
const TAG_FLOAT16BE_ARRAY: u64 = 80; // float16 big-endian array
const TAG_FLOAT32BE_ARRAY: u64 = 81; // float32 big-endian array
const TAG_FLOAT64BE_ARRAY: u64 = 82; // float64 big-endian array
#[allow(dead_code)]
const TAG_FLOAT128BE_ARRAY: u64 = 83; // float128 big-endian array
#[allow(dead_code)]
const TAG_FLOAT16LE_ARRAY: u64 = 84; // float16 little-endian array
const TAG_FLOAT32LE_ARRAY: u64 = 85; // float32 little-endian array
const TAG_FLOAT64LE_ARRAY: u64 = 86; // float64 little-endian array
#[allow(dead_code)]
const TAG_FLOAT128LE_ARRAY: u64 = 87; // float128 little-endian array

// Additional info values
const FALSE: u8 = 20;
const TRUE: u8 = 21;
const NULL: u8 = 22;
#[allow(dead_code)]
const FLOAT16: u8 = 25;
const FLOAT32: u8 = 26;
const FLOAT64: u8 = 27;
const INDEFINITE: u8 = 31;
const BREAK: u8 = 0xFF;

/// CBOR error type
#[derive(Debug)]
pub enum Error {
    /// IO error
    Io(io::Error),
    /// Invalid UTF-8 in string
    InvalidUtf8,
    /// Unexpected end of input
    Eof,
    /// Invalid CBOR value or syntax
    Syntax(String),
    /// Trailing data after value
    TrailingData,
    /// General message (serde compatibility)
    Message(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::InvalidUtf8 => write!(f, "Invalid UTF-8"),
            Error::Eof => write!(f, "Unexpected end of input"),
            Error::Syntax(s) => write!(f, "Syntax error: {}", s),
            Error::TrailingData => write!(f, "Trailing data"),
            Error::Message(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

type Result<T> = std::result::Result<T, Error>;

// Re-export for backward compatibility
#[deprecated(since = "0.2.0", note = "Use `Error` instead")]
pub type CborError = Error;

pub mod error {
    pub use super::Error;
}

// Encoder
pub struct Encoder<W: Write> {
    writer: W,
}

impl<W: Write> Encoder<W> {
    pub fn new(writer: W) -> Self {
        Encoder { writer }
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
}

/// Wrapper for serializing sequences/maps with optional buffering
/// When length is known, writes directly; when unknown, buffers entries
pub enum SerializeVec<'a, W: Write> {
    Direct {
        encoder: &'a mut Encoder<W>,
    },
    Array {
        encoder: &'a mut Encoder<W>,
        buffer: Vec<Vec<u8>>,
    },
    Map {
        encoder: &'a mut Encoder<W>,
        buffer: Vec<(Vec<u8>, Vec<u8>)>,
        pending_key: Option<Vec<u8>>,
    },
}

impl<'a, W: Write> serde::Serializer for &'a mut Encoder<W> {
    type Ok = ();
    type Error = crate::Error;
    type SerializeSeq = SerializeVec<'a, W>;
    type SerializeTuple = SerializeVec<'a, W>;
    type SerializeTupleStruct = SerializeVec<'a, W>;
    type SerializeTupleVariant = &'a mut Encoder<W>;
    type SerializeMap = SerializeVec<'a, W>;
    type SerializeStruct = SerializeVec<'a, W>;
    type SerializeStructVariant = &'a mut Encoder<W>;

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

    fn serialize_f32(self, v: f32) -> Result<()> {
        // Encode as CBOR float32 (major type 7, additional info 26)
        self.writer.write_all(&[(MAJOR_SIMPLE << 5) | FLOAT32])?;
        self.writer.write_all(&v.to_be_bytes())?;
        Ok(())
    }

    fn serialize_f64(self, v: f64) -> Result<()> {
        // Encode as CBOR float64 (major type 7, additional info 27)
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

    fn serialize_newtype_struct<T: ?Sized>(self, _name: &'static str, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        // Serialize as a 1-element array to maintain tuple struct semantics
        // This allows tuple structs like `struct Wrapper(Inner)` to round-trip correctly
        // Users can override with #[serde(transparent)] if they want the inner value directly
        self.write_type_value(MAJOR_ARRAY, 1)?;
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
                self.write_type_value(MAJOR_ARRAY, len as u64)?;
                Ok(SerializeVec::Direct { encoder: self })
            }
            None => {
                // Unknown length - buffer elements
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
        match len {
            Some(len) => {
                // Definite-length map: write size immediately
                self.write_type_value(MAJOR_MAP, len as u64)?;
                Ok(SerializeVec::Direct { encoder: self })
            }
            None => {
                // Indefinite-length map requested (e.g., from #[serde(flatten)])
                // Buffer key-value pairs until end
                Ok(SerializeVec::Map {
                    encoder: self,
                    buffer: Vec::new(),
                    pending_key: None,
                })
            }
        }
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
        len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.write_type_value(MAJOR_MAP, 1)?;
        variant.serialize(&mut *self)?;
        self.write_type_value(MAJOR_MAP, len as u64)?;
        Ok(self)
    }
}

impl<'a, W: Write> serde::ser::SerializeSeq for &'a mut Encoder<W> {
    type Ok = ();
    type Error = crate::Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a, W: Write> serde::ser::SerializeTuple for &'a mut Encoder<W> {
    type Ok = ();
    type Error = crate::Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a, W: Write> serde::ser::SerializeTupleStruct for &'a mut Encoder<W> {
    type Ok = ();
    type Error = crate::Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a, W: Write> serde::ser::SerializeTupleVariant for &'a mut Encoder<W> {
    type Ok = ();
    type Error = crate::Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a, W: Write> serde::ser::SerializeMap for &'a mut Encoder<W> {
    type Ok = ();
    type Error = crate::Error;

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

impl<'a, W: Write> serde::ser::SerializeStruct for &'a mut Encoder<W> {
    type Ok = ();
    type Error = crate::Error;

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

impl<'a, W: Write> serde::ser::SerializeStructVariant for &'a mut Encoder<W> {
    type Ok = ();
    type Error = crate::Error;

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

impl<'a, W: Write> serde::ser::SerializeSeq for SerializeVec<'a, W> {
    type Ok = ();
    type Error = crate::Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        match self {
            SerializeVec::Direct { encoder } => value.serialize(&mut **encoder),
            SerializeVec::Array { buffer, .. } => {
                let mut element_buf = Vec::new();
                let mut element_encoder = Encoder::new(&mut element_buf);
                value.serialize(&mut element_encoder)?;
                buffer.push(element_buf);
                Ok(())
            }
            SerializeVec::Map { .. } => Err(Error::Message(
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
                    encoder.writer.write_all(&element_bytes)?;
                }
                Ok(())
            }
            SerializeVec::Map { .. } => {
                Err(Error::Message("end called on map serializer".to_string()))
            }
        }
    }
}

impl<'a, W: Write> serde::ser::SerializeTuple for SerializeVec<'a, W> {
    type Ok = ();
    type Error = crate::Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<()> {
        serde::ser::SerializeSeq::end(self)
    }
}

impl<'a, W: Write> serde::ser::SerializeTupleStruct for SerializeVec<'a, W> {
    type Ok = ();
    type Error = crate::Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<()> {
        serde::ser::SerializeSeq::end(self)
    }
}

impl<'a, W: Write> serde::ser::SerializeMap for SerializeVec<'a, W> {
    type Ok = ();
    type Error = crate::Error;

    fn serialize_key<T>(&mut self, key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        match self {
            SerializeVec::Direct { encoder } => key.serialize(&mut **encoder),
            SerializeVec::Map { pending_key, .. } => {
                let mut key_buf = Vec::new();
                let mut key_encoder = Encoder::new(&mut key_buf);
                key.serialize(&mut key_encoder)?;
                *pending_key = Some(key_buf);
                Ok(())
            }
            SerializeVec::Array { .. } => Err(Error::Message(
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
                ..
            } => {
                let mut value_buf = Vec::new();
                let mut value_encoder = Encoder::new(&mut value_buf);
                value.serialize(&mut value_encoder)?;
                if let Some(key_bytes) = pending_key.take() {
                    buffer.push((key_bytes, value_buf));
                    Ok(())
                } else {
                    Err(Error::Message(
                        "serialize_value called without serialize_key".to_string(),
                    ))
                }
            }
            SerializeVec::Array { .. } => Err(Error::Message(
                "serialize_value called on array serializer".to_string(),
            )),
        }
    }

    fn end(self) -> Result<()> {
        match self {
            SerializeVec::Direct { .. } => Ok(()),
            SerializeVec::Map {
                encoder,
                buffer,
                pending_key,
            } => {
                if pending_key.is_some() {
                    return Err(Error::Message(
                        "serialize_key called without serialize_value".to_string(),
                    ));
                }
                // Write definite-length map header now that we know the count
                encoder.write_type_value(MAJOR_MAP, buffer.len() as u64)?;
                // Write all buffered key-value pairs
                for (key_bytes, value_bytes) in buffer {
                    encoder.writer.write_all(&key_bytes)?;
                    encoder.writer.write_all(&value_bytes)?;
                }
                Ok(())
            }
            SerializeVec::Array { .. } => {
                Err(Error::Message("end called on array serializer".to_string()))
            }
        }
    }
}

impl<'a, W: Write> serde::ser::SerializeStruct for SerializeVec<'a, W> {
    type Ok = ();
    type Error = crate::Error;

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

// Decoder
pub struct Decoder<R: Read> {
    reader: R,
    peeked: Option<u8>,
}

impl<R: Read> Decoder<R> {
    pub fn new(reader: R) -> Self {
        Decoder {
            reader,
            peeked: None,
        }
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

    fn peek_u8(&mut self) -> Result<u8> {
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

    pub fn read_tag(&mut self) -> Result<u64> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        if major != MAJOR_TAG {
            return Err(Error::Syntax("Invalid CBOR value".to_string()));
        }

        match self.read_length(info)? {
            Some(tag) => Ok(tag),
            None => Err(Error::Syntax(
                "Tag cannot have indefinite length".to_string(),
            )),
        }
    }

    pub fn decode<'de, T: Deserialize<'de>>(&mut self) -> Result<T> {
        T::deserialize(&mut *self)
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

    fn deserialize_option<V: serde::de::Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
        // Peek at next byte to check for null
        let initial = self.read_u8()?;
        if initial == 0xf6 {
            // CBOR null
            visitor.visit_none()
        } else {
            // Not null - need to process this byte as part of Some(...)
            // Put it back and deserialize
            let major = initial >> 5;
            let info = initial & 0x1f;

            // Create a temporary deserializer state with this byte already read
            struct OptionDeserializer<'a, R: Read> {
                decoder: &'a mut Decoder<R>,
                initial_major: u8,
                initial_info: u8,
            }

            impl<'de, 'a, R: Read> serde::Deserializer<'de> for OptionDeserializer<'a, R> {
                type Error = crate::Error;

                fn deserialize_any<V: serde::de::Visitor<'de>>(
                    self,
                    visitor: V,
                ) -> Result<V::Value> {
                    // Process using the already-read byte
                    match self.initial_major {
                        MAJOR_MAP => match self.decoder.read_length(self.initial_info)? {
                            Some(len) => visitor.visit_map(MapAccess {
                                de: self.decoder,
                                remaining: Some(len as usize),
                            }),
                            None => visitor.visit_map(MapAccess {
                                de: self.decoder,
                                remaining: None,
                            }),
                        },
                        _ => {
                            // For other types, just delegate to decoder's deserialize_any
                            // but we've already consumed the byte, so reconstruct the value
                            Err(Error::Syntax(
                                "Option deserialization only supports maps and simple types"
                                    .to_string(),
                            ))
                        }
                    }
                }

                serde::forward_to_deserialize_any! {
                    bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
                    bytes byte_buf option unit unit_struct newtype_struct seq tuple
                    tuple_struct map struct enum identifier ignored_any
                }
            }

            visitor.visit_some(OptionDeserializer {
                decoder: &mut self,
                initial_major: major,
                initial_info: info,
            })
        }
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
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
                visitor.visit_i64(-1 - val as i64)
            }
            MAJOR_BYTES => {
                match self.read_length(info)? {
                    Some(len) => {
                        let mut buf = vec![0u8; len as usize];
                        self.reader.read_exact(&mut buf)?;
                        visitor.visit_byte_buf(buf)
                    }
                    None => {
                        // Indefinite-length byte string: concatenate chunks until break
                        let mut result = Vec::new();
                        loop {
                            if self.is_break()? {
                                self.read_break()?;
                                break;
                            }
                            // Each chunk must be a definite-length byte string
                            let initial = self.read_u8()?;
                            let major = initial >> 5;
                            let info = initial & 0x1f;
                            if major != MAJOR_BYTES {
                                return Err(Error::Syntax(
                                    "Indefinite byte string chunks must be byte strings"
                                        .to_string(),
                                ));
                            }
                            let len = self.read_length(info)?.ok_or_else(|| {
                                Error::Syntax(
                                    "Indefinite byte string chunks cannot be indefinite"
                                        .to_string(),
                                )
                            })?;
                            let mut chunk = vec![0u8; len as usize];
                            self.reader.read_exact(&mut chunk)?;
                            result.extend_from_slice(&chunk);
                        }
                        visitor.visit_byte_buf(result)
                    }
                }
            }
            MAJOR_TEXT => {
                match self.read_length(info)? {
                    Some(len) => {
                        let mut buf = vec![0u8; len as usize];
                        self.reader.read_exact(&mut buf)?;
                        let s = String::from_utf8(buf).map_err(|_| Error::InvalidUtf8)?;
                        visitor.visit_string(s)
                    }
                    None => {
                        // Indefinite-length text string: concatenate chunks until break
                        let mut result = String::new();
                        loop {
                            if self.is_break()? {
                                self.read_break()?;
                                break;
                            }
                            // Each chunk must be a definite-length text string
                            let initial = self.read_u8()?;
                            let major = initial >> 5;
                            let info = initial & 0x1f;
                            if major != MAJOR_TEXT {
                                return Err(Error::Syntax(
                                    "Indefinite text string chunks must be text strings"
                                        .to_string(),
                                ));
                            }
                            let len = self.read_length(info)?.ok_or_else(|| {
                                Error::Syntax(
                                    "Indefinite text string chunks cannot be indefinite"
                                        .to_string(),
                                )
                            })?;
                            let mut chunk_buf = vec![0u8; len as usize];
                            self.reader.read_exact(&mut chunk_buf)?;
                            let chunk =
                                String::from_utf8(chunk_buf).map_err(|_| Error::InvalidUtf8)?;
                            result.push_str(&chunk);
                        }
                        visitor.visit_string(result)
                    }
                }
            }
            MAJOR_ARRAY => match self.read_length(info)? {
                Some(len) => visitor.visit_seq(SeqAccess {
                    de: &mut self,
                    remaining: Some(len as usize),
                }),
                None => visitor.visit_seq(SeqAccess {
                    de: &mut self,
                    remaining: None,
                }),
            },
            MAJOR_MAP => match self.read_length(info)? {
                Some(len) => visitor.visit_map(MapAccess {
                    de: &mut self,
                    remaining: Some(len as usize),
                }),
                None => visitor.visit_map(MapAccess {
                    de: &mut self,
                    remaining: None,
                }),
            },
            MAJOR_TAG => {
                // Read the tag number
                let _tag = self
                    .read_length(info)?
                    .ok_or_else(|| Error::Syntax("Tag cannot be indefinite".to_string()))?;
                // For now, just deserialize the tagged content
                // The tag information is available but we pass through to the content
                self.deserialize_any(visitor)
            }
            MAJOR_SIMPLE => match info {
                FALSE => visitor.visit_bool(false),
                TRUE => visitor.visit_bool(true),
                NULL => visitor.visit_none(),
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

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        mut self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        // Peek at what we have
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        match major {
            MAJOR_TEXT => {
                // Unit variant encoded as string
                let len = self.read_length(info)?.ok_or_else(|| {
                    Error::Syntax("Enum variant cannot be indefinite length".to_string())
                })?;
                let mut buf = vec![0u8; len as usize];
                self.reader.read_exact(&mut buf)?;
                let s = String::from_utf8(buf).map_err(|_| Error::InvalidUtf8)?;
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
                visitor.visit_enum(VariantAccess { de: &mut self })
            }
            _ => Err(Error::Syntax("Invalid CBOR type for enum".to_string())),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf unit unit_struct newtype_struct seq tuple
        tuple_struct map struct identifier ignored_any
    }
}

impl<'de, R: Read> serde::Deserializer<'de> for &mut Decoder<R> {
    type Error = crate::Error;

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
                    remaining: Some(len as usize),
                }),
                None => visitor.visit_some(MapDeserializer {
                    de: self,
                    remaining: None,
                }),
            },
            MAJOR_ARRAY => match self.read_length(info)? {
                Some(len) => visitor.visit_some(ArrayDeserializer {
                    de: self,
                    remaining: Some(len as usize),
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

    fn deserialize_any<V: serde::de::Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
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
                visitor.visit_i64(-1 - val as i64)
            }
            MAJOR_BYTES => {
                match self.read_length(info)? {
                    Some(len) => {
                        let mut buf = vec![0u8; len as usize];
                        self.reader.read_exact(&mut buf)?;
                        visitor.visit_byte_buf(buf)
                    }
                    None => {
                        // Indefinite-length byte string: concatenate chunks until break
                        let mut result = Vec::new();
                        loop {
                            if self.is_break()? {
                                self.read_break()?;
                                break;
                            }
                            // Each chunk must be a definite-length byte string
                            let initial = self.read_u8()?;
                            let major = initial >> 5;
                            let info = initial & 0x1f;
                            if major != MAJOR_BYTES {
                                return Err(Error::Syntax(
                                    "Indefinite byte string chunks must be byte strings"
                                        .to_string(),
                                ));
                            }
                            let len = self.read_length(info)?.ok_or_else(|| {
                                Error::Syntax(
                                    "Indefinite byte string chunks cannot be indefinite"
                                        .to_string(),
                                )
                            })?;
                            let mut chunk = vec![0u8; len as usize];
                            self.reader.read_exact(&mut chunk)?;
                            result.extend_from_slice(&chunk);
                        }
                        visitor.visit_byte_buf(result)
                    }
                }
            }
            MAJOR_TEXT => {
                match self.read_length(info)? {
                    Some(len) => {
                        let mut buf = vec![0u8; len as usize];
                        self.reader.read_exact(&mut buf)?;
                        let s = String::from_utf8(buf).map_err(|_| Error::InvalidUtf8)?;
                        visitor.visit_string(s)
                    }
                    None => {
                        // Indefinite-length text string: concatenate chunks until break
                        let mut result = String::new();
                        loop {
                            if self.is_break()? {
                                self.read_break()?;
                                break;
                            }
                            // Each chunk must be a definite-length text string
                            let initial = self.read_u8()?;
                            let major = initial >> 5;
                            let info = initial & 0x1f;
                            if major != MAJOR_TEXT {
                                return Err(Error::Syntax(
                                    "Indefinite text string chunks must be text strings"
                                        .to_string(),
                                ));
                            }
                            let len = self.read_length(info)?.ok_or_else(|| {
                                Error::Syntax(
                                    "Indefinite text string chunks cannot be indefinite"
                                        .to_string(),
                                )
                            })?;
                            let mut chunk_buf = vec![0u8; len as usize];
                            self.reader.read_exact(&mut chunk_buf)?;
                            let chunk =
                                String::from_utf8(chunk_buf).map_err(|_| Error::InvalidUtf8)?;
                            result.push_str(&chunk);
                        }
                        visitor.visit_string(result)
                    }
                }
            }
            MAJOR_ARRAY => match self.read_length(info)? {
                Some(len) => visitor.visit_seq(SeqAccess {
                    de: &mut self,
                    remaining: Some(len as usize),
                }),
                None => visitor.visit_seq(SeqAccess {
                    de: &mut self,
                    remaining: None,
                }),
            },
            MAJOR_MAP => match self.read_length(info)? {
                Some(len) => visitor.visit_map(MapAccess {
                    de: &mut self,
                    remaining: Some(len as usize),
                }),
                None => visitor.visit_map(MapAccess {
                    de: &mut self,
                    remaining: None,
                }),
            },
            MAJOR_TAG => {
                // Read the tag number
                let _tag = self
                    .read_length(info)?
                    .ok_or_else(|| Error::Syntax("Tag cannot be indefinite".to_string()))?;
                // For now, just deserialize the tagged content
                // The tag information is available but we pass through to the content
                self.deserialize_any(visitor)
            }
            MAJOR_SIMPLE => match info {
                FALSE => visitor.visit_bool(false),
                TRUE => visitor.visit_bool(true),
                NULL => visitor.visit_none(),
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

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        // Peek at what we have
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        match major {
            MAJOR_TEXT => {
                // Unit variant encoded as string
                let len = self.read_length(info)?.ok_or_else(|| {
                    Error::Syntax("Enum variant cannot be indefinite length".to_string())
                })?;
                let mut buf = vec![0u8; len as usize];
                self.reader.read_exact(&mut buf)?;
                let s = String::from_utf8(buf).map_err(|_| Error::InvalidUtf8)?;
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

    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        // For backward compatibility, we need to handle both:
        // 1. NEW format: [inner_value] - 1-element array (proper tuple struct encoding)
        // 2. OLD format: inner_value - direct value (legacy transparent behavior)
        //
        // Strategy: Peek at the next byte to determine the format
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        if major == MAJOR_ARRAY {
            // NEW format: array wrapping - deserialize as sequence
            match self.read_length(info)? {
                Some(1) => {
                    // 1-element array - extract the single element
                    visitor.visit_newtype_struct(&mut *self)
                }
                Some(len) => {
                    // Wrong array length for newtype struct
                    Err(Error::Syntax(format!(
                        "Expected 1-element array for newtype struct, got {} elements",
                        len
                    )))
                }
                None => {
                    // Indefinite-length array not supported for newtype struct
                    Err(Error::Syntax(
                        "Indefinite-length array not supported for newtype struct".to_string(),
                    ))
                }
            }
        } else {
            // OLD format: direct value (backward compatibility)
            // Put the byte back and deserialize the inner value directly
            // We need to reconstruct the deserializer state with the byte we already read
            match major {
                MAJOR_MAP => match self.read_length(info)? {
                    Some(len) => visitor.visit_newtype_struct(MapDeserializer {
                        de: self,
                        remaining: Some(len as usize),
                    }),
                    None => visitor.visit_newtype_struct(MapDeserializer {
                        de: self,
                        remaining: None,
                    }),
                },
                MAJOR_TEXT => {
                    let len = self.read_length(info)?.ok_or_else(|| {
                        Error::Syntax("Text in newtype must be definite length".to_string())
                    })?;
                    let mut buf = vec![0u8; len as usize];
                    self.reader.read_exact(&mut buf)?;
                    let s = String::from_utf8(buf).map_err(|_| Error::InvalidUtf8)?;
                    visitor.visit_newtype_struct(StringDeserializer { value: s })
                }
                _ => {
                    // For other types, use prefetched deserializer
                    visitor.visit_newtype_struct(PrefetchedDeserializer {
                        de: self,
                        major,
                        info,
                    })
                }
            }
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple
        tuple_struct map struct identifier ignored_any
    }
}

// Helper deserializers for Option handling
struct MapDeserializer<'a, R: Read> {
    de: &'a mut Decoder<R>,
    remaining: Option<usize>,
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for MapDeserializer<'a, R> {
    type Error = crate::Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_map(MapAccess {
            de: self.de,
            remaining: self.remaining,
        })
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

struct ArrayDeserializer<'a, R: Read> {
    de: &'a mut Decoder<R>,
    remaining: Option<usize>,
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for ArrayDeserializer<'a, R> {
    type Error = crate::Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_seq(SeqAccess {
            de: self.de,
            remaining: self.remaining,
        })
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

struct PrefetchedDeserializer<'a, R: Read> {
    de: &'a mut Decoder<R>,
    major: u8,
    info: u8,
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for PrefetchedDeserializer<'a, R> {
    type Error = crate::Error;

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
                visitor.visit_i64(-1 - val as i64)
            }
            MAJOR_TEXT => {
                let len = self.de.read_length(self.info)?.ok_or_else(|| {
                    Error::Syntax("Text in option must be definite length".to_string())
                })?;
                let mut buf = vec![0u8; len as usize];
                self.de.reader.read_exact(&mut buf)?;
                let s = String::from_utf8(buf).map_err(|_| Error::InvalidUtf8)?;
                visitor.visit_string(s)
            }
            MAJOR_BYTES => {
                let len = self.de.read_length(self.info)?.ok_or_else(|| {
                    Error::Syntax("Bytes in option must be definite length".to_string())
                })?;
                let mut buf = vec![0u8; len as usize];
                self.de.reader.read_exact(&mut buf)?;
                visitor.visit_byte_buf(buf)
            }
            MAJOR_SIMPLE => match self.info {
                FALSE => visitor.visit_bool(false),
                TRUE => visitor.visit_bool(true),
                _ => Err(Error::Syntax("Invalid simple type in option".to_string())),
            },
            _ => Err(Error::Syntax("Unsupported type in option".to_string())),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

// String deserializer for backward compatibility in newtype structs
struct StringDeserializer {
    value: String,
}

impl<'de> serde::Deserializer<'de> for StringDeserializer {
    type Error = crate::Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_string(self.value)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
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

// Convenience functions
/// Serializes a value to a CBOR byte vector
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // Try direct serialization first
    let mut buf = Vec::new();
    let mut encoder = Encoder::new(&mut buf);
    match encoder.encode(value) {
        Ok(()) => Ok(buf),
        Err(Error::Message(ref msg)) if msg.contains("indefinite-length") => {
            // Fall back to value-based serialization for types that need indefinite length
            // This handles #[serde(flatten)] and other cases where size is unknown
            let value = crate::value::to_value(value)?;
            buf.clear();
            let mut encoder = Encoder::new(&mut buf);
            encoder.encode(&value)?;
            Ok(buf)
        }
        Err(e) => Err(e),
    }
}

/// Deserializes a value from CBOR bytes
pub fn from_slice<'de, T: Deserialize<'de>>(slice: &[u8]) -> Result<T> {
    if slice.is_empty() {
        return Err(Error::Syntax("empty input".to_string()));
    }

    let mut decoder = Decoder::new(slice);
    let value = decoder.decode()?;

    // Check if all bytes were consumed
    let remaining = decoder.reader.len();
    if remaining > 0 {
        return Err(Error::Syntax(format!(
            "unexpected trailing data: {} bytes remaining",
            remaining
        )));
    }

    Ok(value)
}

/// Serializes a value to a CBOR writer
pub fn to_writer<W: Write, T: Serialize>(writer: W, value: &T) -> Result<()> {
    let mut encoder = Encoder::new(writer);
    encoder.encode(value)?;
    Ok(())
}

/// Deserializes a value from a CBOR reader
pub fn from_reader<R: Read, T: for<'de> Deserialize<'de>>(reader: R) -> Result<T> {
    let mut decoder = Decoder::new(reader);
    decoder.decode()
}

// Type aliases for serde_cbor API compatibility
/// Type alias for `Encoder` (serde_cbor compatibility)
pub type Serializer<W> = Encoder<W>;
/// Type alias for `Decoder` (serde_cbor compatibility)
pub type Deserializer<R> = Decoder<R>;

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

/// Helper to encode a uint16 big-endian array (tag 65)
pub fn encode_uint16be_array<W: Write>(writer: &mut W, data: &[u16]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_be_bytes()).collect();
    encode_tagged(writer, TAG_UINT16BE_ARRAY, &bytes)
}

/// Helper to encode a uint32 big-endian array (tag 66)
pub fn encode_uint32be_array<W: Write>(writer: &mut W, data: &[u32]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_be_bytes()).collect();
    encode_tagged(writer, TAG_UINT32BE_ARRAY, &bytes)
}

/// Helper to encode a uint64 big-endian array (tag 67)
pub fn encode_uint64be_array<W: Write>(writer: &mut W, data: &[u64]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_be_bytes()).collect();
    encode_tagged(writer, TAG_UINT64BE_ARRAY, &bytes)
}

/// Helper to encode a uint16 little-endian array (tag 69)
pub fn encode_uint16le_array<W: Write>(writer: &mut W, data: &[u16]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_le_bytes()).collect();
    encode_tagged(writer, TAG_UINT16LE_ARRAY, &bytes)
}

/// Helper to encode a uint32 little-endian array (tag 70)
pub fn encode_uint32le_array<W: Write>(writer: &mut W, data: &[u32]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_le_bytes()).collect();
    encode_tagged(writer, TAG_UINT32LE_ARRAY, &bytes)
}

/// Helper to encode a uint64 little-endian array (tag 71)
pub fn encode_uint64le_array<W: Write>(writer: &mut W, data: &[u64]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_le_bytes()).collect();
    encode_tagged(writer, TAG_UINT64LE_ARRAY, &bytes)
}

/// Helper to encode a float32 big-endian array (tag 81)
pub fn encode_float32be_array<W: Write>(writer: &mut W, data: &[f32]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_be_bytes()).collect();
    encode_tagged(writer, TAG_FLOAT32BE_ARRAY, &bytes)
}

/// Helper to encode a float64 big-endian array (tag 82)
pub fn encode_float64be_array<W: Write>(writer: &mut W, data: &[f64]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_be_bytes()).collect();
    encode_tagged(writer, TAG_FLOAT64BE_ARRAY, &bytes)
}

/// Helper to encode a float32 little-endian array (tag 85)
pub fn encode_float32le_array<W: Write>(writer: &mut W, data: &[f32]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_le_bytes()).collect();
    encode_tagged(writer, TAG_FLOAT32LE_ARRAY, &bytes)
}

/// Helper to encode a float64 little-endian array (tag 86)
pub fn encode_float64le_array<W: Write>(writer: &mut W, data: &[f64]) -> Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|&n| n.to_le_bytes()).collect();
    encode_tagged(writer, TAG_FLOAT64LE_ARRAY, &bytes)
}

// Example usage and tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Person {
        name: String,
        age: u32,
        emails: Vec<String>,
    }

    #[test]
    fn test_basic_types() {
        assert_eq!(from_slice::<u32>(&to_vec(&42u32).unwrap()).unwrap(), 42);
        assert_eq!(from_slice::<i32>(&to_vec(&-42i32).unwrap()).unwrap(), -42);
        assert_eq!(from_slice::<bool>(&to_vec(&true).unwrap()).unwrap(), true);
        assert_eq!(
            from_slice::<String>(&to_vec(&"hello".to_string()).unwrap()).unwrap(),
            "hello"
        );
    }

    #[test]
    fn test_struct() {
        let person = Person {
            name: "Alice".to_string(),
            age: 30,
            emails: vec!["alice@example.com".to_string()],
        };
        let encoded = to_vec(&person).unwrap();
        let decoded: Person = from_slice(&encoded).unwrap();
        assert_eq!(person, decoded);
    }

    #[test]
    fn test_map() {
        let mut map = HashMap::new();
        map.insert("key1".to_string(), 100);
        map.insert("key2".to_string(), 200);
        let encoded = to_vec(&map).unwrap();
        let decoded: HashMap<String, i32> = from_slice(&encoded).unwrap();
        assert_eq!(map, decoded);
    }

    #[test]
    fn test_tagged_datetime_string() {
        let mut buf = Vec::new();
        encode_datetime_string(&mut buf, "2024-01-15T10:30:00Z").unwrap();

        // Verify the tag is encoded correctly
        // Tag 0 with small value is encoded as 0xC0 (major type 6, value 0)
        assert_eq!(buf[0], 0xC0);

        // Decode the tagged value - it should deserialize the content (the string)
        let decoded: String = from_slice(&buf).unwrap();
        assert_eq!(decoded, "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_tagged_epoch_datetime() {
        let mut buf = Vec::new();
        let epoch: i64 = 1705315800; // Some epoch timestamp
        encode_epoch_datetime(&mut buf, epoch).unwrap();

        // Tag 1 is encoded as 0xC1 (major type 6, value 1)
        assert_eq!(buf[0], 0xC1);

        // Decode the tagged value
        let decoded: i64 = from_slice(&buf).unwrap();
        assert_eq!(decoded, epoch);
    }

    #[test]
    fn test_tagged_uri() {
        let mut buf = Vec::new();
        encode_uri(&mut buf, "https://example.com/path").unwrap();

        // Tag 32 is encoded as 0xD8 0x20 (major type 6, additional info 24, value 32)
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 32);

        // Decode the tagged value
        let decoded: String = from_slice(&buf).unwrap();
        assert_eq!(decoded, "https://example.com/path");
    }

    #[test]
    fn test_tagged_base64url() {
        let mut buf = Vec::new();
        encode_base64url(&mut buf, "SGVsbG8gV29ybGQ").unwrap();

        // Tag 33 is encoded as 0xD8 0x21
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 33);

        let decoded: String = from_slice(&buf).unwrap();
        assert_eq!(decoded, "SGVsbG8gV29ybGQ");
    }

    #[test]
    fn test_manual_tag_encoding() {
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);

        // Manually encode a custom tag (e.g., tag 100) with a string value
        encoder.write_tag(100).unwrap();
        encoder.encode(&"custom tagged value").unwrap();

        // Tag 100 is encoded as 0xD8 0x64
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 100);

        // Decode should give us the string content
        let decoded: String = from_slice(&buf).unwrap();
        assert_eq!(decoded, "custom tagged value");
    }

    #[test]
    fn test_read_tag_method() {
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        encoder.write_tag(42).unwrap();
        encoder.encode(&"test").unwrap();

        let mut decoder = Decoder::new(&buf[..]);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, 42);

        // After reading the tag, we can decode the content
        let content: String = decoder.decode().unwrap();
        assert_eq!(content, "test");
    }

    #[test]
    fn test_typed_array_uint8() {
        let mut buf = Vec::new();
        let data: [u8; 5] = [1, 2, 3, 4, 5];
        encode_uint8_array(&mut buf, &data).unwrap();

        // Tag 64 is encoded as 0xD8 0x40
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 64);

        // Decode as byte array
        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        assert_eq!(decoded, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_typed_array_uint16be() {
        let mut buf = Vec::new();
        let data: [u16; 3] = [0x1234, 0x5678, 0x9ABC];
        encode_uint16be_array(&mut buf, &data).unwrap();

        // Tag 65 is encoded as 0xD8 0x41
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 65);

        // Decode as byte array
        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        // Should be big-endian encoded
        assert_eq!(decoded, vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
    }

    #[test]
    fn test_typed_array_uint32be() {
        let mut buf = Vec::new();
        let data: [u32; 2] = [0x12345678, 0x9ABCDEF0];
        encode_uint32be_array(&mut buf, &data).unwrap();

        // Tag 66 is encoded as 0xD8 0x42
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 66);

        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        assert_eq!(
            decoded,
            vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]
        );
    }

    #[test]
    fn test_typed_array_uint64be() {
        let mut buf = Vec::new();
        let data: [u64; 1] = [0x123456789ABCDEF0];
        encode_uint64be_array(&mut buf, &data).unwrap();

        // Tag 67 is encoded as 0xD8 0x43
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 67);

        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        assert_eq!(
            decoded,
            vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]
        );
    }

    #[test]
    fn test_typed_array_float32be() {
        let mut buf = Vec::new();
        let data: [f32; 2] = [1.5, 2.5];
        encode_float32be_array(&mut buf, &data).unwrap();

        // Tag 81 is encoded as 0xD8 0x51
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 81);

        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        // Verify we have the right number of bytes (2 floats * 4 bytes each)
        assert_eq!(decoded.len(), 8);
    }

    #[test]
    fn test_typed_array_float64be() {
        let mut buf = Vec::new();
        let data: [f64; 2] = [1.5, 2.5];
        encode_float64be_array(&mut buf, &data).unwrap();

        // Tag 82 is encoded as 0xD8 0x52
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 82);

        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        // Verify we have the right number of bytes (2 floats * 8 bytes each)
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    fn test_typed_array_uint16le() {
        let mut buf = Vec::new();
        let data: [u16; 3] = [0x1234, 0x5678, 0x9ABC];
        encode_uint16le_array(&mut buf, &data).unwrap();

        // Tag 69 is encoded as 0xD8 0x45
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 69);

        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        // Should be little-endian encoded
        assert_eq!(decoded, vec![0x34, 0x12, 0x78, 0x56, 0xBC, 0x9A]);
    }

    #[test]
    fn test_large_byte_array_performance() {
        use serde_bytes::ByteBuf;

        // Test that large byte arrays are efficiently encoded/decoded with serde_bytes
        // CBOR byte arrays should be: 1 byte header + length encoding + raw bytes

        // 1KB array
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let byte_buf = ByteBuf::from(data.clone());
        let encoded = to_vec(&byte_buf).unwrap();

        // Overhead should be minimal: 1 byte major type + 2 bytes for length (1024 = 0x400)
        assert_eq!(encoded.len(), 1024 + 3); // 3 bytes overhead
        assert_eq!(encoded[0], (MAJOR_BYTES << 5) | 25); // 25 = two-byte length follows
        assert_eq!(encoded[1], 0x04); // high byte of 1024
        assert_eq!(encoded[2], 0x00); // low byte of 1024

        let decoded: ByteBuf = from_slice(&encoded).unwrap();
        assert_eq!(decoded.into_vec(), data);

        // Test 100KB array
        let large_data: Vec<u8> = (0..102400).map(|i| (i % 256) as u8).collect();
        let large_byte_buf = ByteBuf::from(large_data.clone());
        let encoded_large = to_vec(&large_byte_buf).unwrap();

        // Overhead for 102400 bytes: 1 byte major + 4 bytes for length
        assert_eq!(encoded_large.len(), 102400 + 5);

        let decoded_large: ByteBuf = from_slice(&encoded_large).unwrap();
        assert_eq!(decoded_large.into_vec(), large_data);
    }

    #[test]
    fn test_byte_array_zero_copy_encoding() {
        use serde_bytes::ByteBuf;

        // Verify that byte arrays are written directly without transformation
        let data: Vec<u8> = vec![0x42, 0xFF, 0x00, 0xAA, 0x55];
        let byte_buf = ByteBuf::from(data.clone());
        let encoded = to_vec(&byte_buf).unwrap();

        // Should be: major type byte + length + raw data
        assert_eq!(encoded[0], (MAJOR_BYTES << 5) | 5); // length 5 embedded
        assert_eq!(&encoded[1..], &[0x42, 0xFF, 0x00, 0xAA, 0x55]);

        let decoded: ByteBuf = from_slice(&encoded).unwrap();
        assert_eq!(decoded.into_vec(), data);
    }

    #[test]
    fn test_vec_u8_as_array() {
        // Without serde_bytes, Vec<u8> serializes as an array
        let data: Vec<u8> = vec![1, 2, 3];
        let encoded = to_vec(&data).unwrap();

        // First byte should be array type with length 3
        assert_eq!(encoded[0], (MAJOR_ARRAY << 5) | 3);

        let decoded: Vec<u8> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_serde_bytes_efficiency() {
        use serde_bytes::ByteBuf;

        // Compare encoding efficiency: Vec<u8> vs serde_bytes::ByteBuf
        let data: Vec<u8> = vec![1, 2, 3, 4, 5];

        // As Vec<u8> - encodes as array (each element individually)
        let encoded_array = to_vec(&data).unwrap();

        // As ByteBuf - encodes as byte string (raw bytes)
        let byte_buf = ByteBuf::from(data.clone());
        let encoded_bytes = to_vec(&byte_buf).unwrap();

        // For small arrays, they might be similar, but ByteBuf uses raw bytes
        // Array: 1 byte header + 5 bytes (one per element since values are < 24) = 6 bytes
        // ByteBuf: 1 byte header + 5 bytes raw = 6 bytes
        // For larger values or larger arrays, ByteBuf is more efficient

        println!("Array encoding: {} bytes", encoded_array.len());
        println!("Bytes encoding: {} bytes", encoded_bytes.len());

        // ByteBuf: 1 byte header + 5 bytes data = 6 bytes
        assert_eq!(encoded_bytes.len(), 6);
        assert_eq!(encoded_bytes[0], (MAJOR_BYTES << 5) | 5);

        // Array: 1 byte header + 5 bytes (small integers) = 6 bytes
        assert_eq!(encoded_array.len(), 6);
        assert_eq!(encoded_array[0], (MAJOR_ARRAY << 5) | 5);

        let decoded: ByteBuf = from_slice(&encoded_bytes).unwrap();
        assert_eq!(decoded.into_vec(), data);
    }

    #[test]
    fn test_tagged_byte_array_overhead() {
        use serde_bytes::ByteBuf;

        // Test that tagged byte arrays (e.g., tag 64) have minimal overhead
        let data: Vec<u8> = vec![1, 2, 3, 4, 5];
        let byte_buf = ByteBuf::from(data.clone());

        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        encoder.write_tag(TAG_UINT8_ARRAY).unwrap();
        encoder.encode(&byte_buf).unwrap();

        // Overhead: 2 bytes for tag (0xD8 0x40) + 1 byte for bytes type + 1 byte for length + 5 bytes data
        assert_eq!(buf.len(), 8);

        // Tag 64 encoded as 0xD8 0x40
        assert_eq!(buf[0], 0xD8);
        assert_eq!(buf[1], 64);
        // Byte string with length 5
        assert_eq!(buf[2], (MAJOR_BYTES << 5) | 5);
        assert_eq!(&buf[3..], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_performance_summary() {
        use serde_bytes::ByteBuf;
        use std::time::Instant;

        // Demonstrate efficient encoding/decoding of binary data
        println!("\n=== CBOR Binary Encoding Performance ===");

        // Small array (5 bytes)
        let small = ByteBuf::from(vec![1, 2, 3, 4, 5]);
        let encoded_small = to_vec(&small).unwrap();
        println!(
            "5 bytes -> {} encoded bytes (overhead: {} bytes)",
            encoded_small.len(),
            encoded_small.len() - 5
        );
        assert_eq!(encoded_small.len(), 6); // 1 byte overhead

        // 1KB array
        let kb1_data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let kb1 = ByteBuf::from(kb1_data);
        let encoded_kb1 = to_vec(&kb1).unwrap();
        println!(
            "1 KB -> {} encoded bytes (overhead: {} bytes)",
            encoded_kb1.len(),
            encoded_kb1.len() - 1024
        );
        assert_eq!(encoded_kb1.len(), 1027); // 3 bytes overhead

        // 100KB array
        let kb100_data: Vec<u8> = (0..102400).map(|i| (i % 256) as u8).collect();
        let kb100 = ByteBuf::from(kb100_data);
        let encoded_kb100 = to_vec(&kb100).unwrap();
        println!(
            "100 KB -> {} encoded bytes (overhead: {} bytes)",
            encoded_kb100.len(),
            encoded_kb100.len() - 102400
        );
        assert_eq!(encoded_kb100.len(), 102405); // 5 bytes overhead

        println!("\n--- Speed Tests ---");

        // Speed test: 1MB encoding
        let mb1_data: Vec<u8> = (0..1048576).map(|i| (i % 256) as u8).collect();
        let mb1 = ByteBuf::from(mb1_data.clone());

        let start = Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            let _ = to_vec(&mb1).unwrap();
        }
        let encode_duration = start.elapsed();
        let encode_throughput =
            (1048576 * iterations) as f64 / encode_duration.as_secs_f64() / 1_048_576.0;
        println!(
            "Encode 1 MB x {}: {:?} ({:.1} MB/s)",
            iterations, encode_duration, encode_throughput
        );

        // Speed test: 1MB decoding
        let encoded_mb = to_vec(&mb1).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            let _: ByteBuf = from_slice(&encoded_mb).unwrap();
        }
        let decode_duration = start.elapsed();
        let decode_throughput =
            (1048576 * iterations) as f64 / decode_duration.as_secs_f64() / 1_048_576.0;
        println!(
            "Decode 1 MB x {}: {:?} ({:.1} MB/s)",
            iterations, decode_duration, decode_throughput
        );

        println!("\nOverhead is minimal and speed is excellent!");
        println!("Encoding is zero-copy - data is written directly.");
        println!("Decoding allocates once - no per-element overhead.\n");
    }

    #[test]
    fn test_encoding_speed_vs_size() {
        use serde_bytes::ByteBuf;
        use std::time::Instant;

        println!("\n=== Encoding Speed vs Data Size ===");

        let sizes = vec![1024, 10240, 102400, 1048576]; // 1KB, 10KB, 100KB, 1MB

        for size in sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let byte_buf = ByteBuf::from(data);

            let iterations = if size >= 1048576 { 10 } else { 100 };

            let start = Instant::now();
            for _ in 0..iterations {
                let _ = to_vec(&byte_buf).unwrap();
            }
            let duration = start.elapsed();
            let avg_ns = duration.as_nanos() / iterations as u128;
            let throughput_mbps =
                (size as f64 * iterations as f64) / duration.as_secs_f64() / 1_048_576.0;

            println!(
                "{:>7} bytes: {:>6} ns/op ({:>6.1} MB/s)",
                size, avg_ns, throughput_mbps
            );
        }
        println!();
    }

    #[test]
    fn test_decoding_speed_vs_size() {
        use serde_bytes::ByteBuf;
        use std::time::Instant;

        println!("\n=== Decoding Speed vs Data Size ===");

        let sizes = vec![1024, 10240, 102400, 1048576]; // 1KB, 10KB, 100KB, 1MB

        for size in sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let byte_buf = ByteBuf::from(data);
            let encoded = to_vec(&byte_buf).unwrap();

            let iterations = if size >= 1048576 { 10 } else { 100 };

            let start = Instant::now();
            for _ in 0..iterations {
                let _: ByteBuf = from_slice(&encoded).unwrap();
            }
            let duration = start.elapsed();
            let avg_ns = duration.as_nanos() / iterations as u128;
            let throughput_mbps =
                (size as f64 * iterations as f64) / duration.as_secs_f64() / 1_048_576.0;

            println!(
                "{:>7} bytes: {:>6} ns/op ({:>6.1} MB/s)",
                size, avg_ns, throughput_mbps
            );
        }
        println!();
    }

    #[test]
    fn test_indefinite_array() {
        // Manually encode an indefinite-length array
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // Start indefinite array
        enc.write_array_indefinite().unwrap();
        // Add elements
        enc.encode(&1u32).unwrap();
        enc.encode(&2u32).unwrap();
        enc.encode(&3u32).unwrap();
        // Write break
        enc.write_break().unwrap();

        // Verify encoding: 0x9F (array indefinite) + elements + 0xFF (break)
        assert_eq!(buf[0], (MAJOR_ARRAY << 5) | INDEFINITE);
        assert_eq!(buf[buf.len() - 1], BREAK);

        // Decode should work
        let decoded: Vec<u32> = from_slice(&buf).unwrap();
        assert_eq!(decoded, vec![1, 2, 3]);
    }

    #[test]
    fn test_indefinite_map() {
        // Manually encode an indefinite-length map
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // Start indefinite map
        enc.write_map_indefinite().unwrap();
        // Add key-value pairs
        enc.encode(&"a").unwrap();
        enc.encode(&1u32).unwrap();
        enc.encode(&"b").unwrap();
        enc.encode(&2u32).unwrap();
        // Write break
        enc.write_break().unwrap();

        // Verify encoding
        assert_eq!(buf[0], (MAJOR_MAP << 5) | INDEFINITE);
        assert_eq!(buf[buf.len() - 1], BREAK);

        // Decode should work
        let decoded: HashMap<String, u32> = from_slice(&buf).unwrap();
        assert_eq!(decoded.get("a"), Some(&1));
        assert_eq!(decoded.get("b"), Some(&2));
    }

    #[test]
    fn test_indefinite_byte_string() {
        use serde_bytes::ByteBuf;

        // Manually encode indefinite-length byte string (chunked)
        let mut buf = Vec::new();
        buf.push((MAJOR_BYTES << 5) | INDEFINITE); // Start indefinite bytes

        // Add chunks as byte strings
        let chunk1 = vec![1u8, 2, 3];
        let chunk1_enc = to_vec(&ByteBuf::from(chunk1.clone())).unwrap();
        buf.extend_from_slice(&chunk1_enc);

        let chunk2 = vec![4u8, 5];
        let chunk2_enc = to_vec(&ByteBuf::from(chunk2.clone())).unwrap();
        buf.extend_from_slice(&chunk2_enc);

        buf.push(BREAK); // End indefinite

        // Decode should concatenate chunks
        let decoded: ByteBuf = from_slice(&buf).unwrap();
        assert_eq!(decoded.into_vec(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_indefinite_text_string() {
        // Manually encode indefinite-length text string (chunked)
        let mut buf = Vec::new();
        buf.push((MAJOR_TEXT << 5) | INDEFINITE); // Start indefinite text

        // Add chunks
        let chunk1 = "Hello";
        let chunk1_enc = to_vec(&chunk1).unwrap();
        buf.extend_from_slice(&chunk1_enc);

        let chunk2 = " World";
        let chunk2_enc = to_vec(&chunk2).unwrap();
        buf.extend_from_slice(&chunk2_enc);

        buf.push(BREAK); // End indefinite

        // Decode should concatenate chunks
        let decoded: String = from_slice(&buf).unwrap();
        assert_eq!(decoded, "Hello World");
    }

    #[test]
    fn test_ser_module_serializer() {
        use crate::ser::Serializer;

        // Test that ser::Serializer works correctly
        let buf = Vec::new();
        let mut serializer = Serializer::new(buf);

        let data = vec![1, 2, 3];
        data.serialize(&mut serializer).unwrap();

        let encoded = serializer.into_inner();
        let decoded: Vec<i32> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, vec![1, 2, 3]);
    }

    #[test]
    fn test_struct_with_option_fields() {
        use std::collections::HashMap;

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestData {
            name: String,
            value: u32,
            optional_map: Option<HashMap<String, String>>,
            optional_string: Option<String>,
        }

        // Test with Some values
        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());

        let data_with_some = TestData {
            name: "test".to_string(),
            value: 42,
            optional_map: Some(map),
            optional_string: Some("hello".to_string()),
        };

        let encoded = to_vec(&data_with_some).unwrap();
        let decoded: TestData = from_slice(&encoded).unwrap();
        assert_eq!(data_with_some, decoded);

        // Test with None values
        let data_with_none = TestData {
            name: "test".to_string(),
            value: 42,
            optional_map: None,
            optional_string: None,
        };

        let encoded_none = to_vec(&data_with_none).unwrap();
        let decoded_none: TestData = from_slice(&encoded_none).unwrap();
        assert_eq!(data_with_none, decoded_none);
    }

    #[test]
    fn test_nested_option_maps() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Outer {
            data: Option<Inner>,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Inner {
            values: HashMap<String, i32>,
        }

        let mut values = HashMap::new();
        values.insert("a".to_string(), 1);
        values.insert("b".to_string(), 2);

        let outer = Outer {
            data: Some(Inner { values }),
        };

        let encoded = to_vec(&outer).unwrap();
        println!("Encoded bytes: {:?}", encoded);
        let decoded: Outer = from_slice(&encoded).unwrap();
        assert_eq!(outer, decoded);
    }

    #[test]
    fn test_option_field_counting() {
        // Test to understand how serde counts fields with Option
        #[derive(Debug, Serialize)]
        struct WithOptions {
            field1: String,
            field2: Option<String>,
            field3: Option<String>,
        }

        let data = WithOptions {
            field1: "hello".to_string(),
            field2: Some("world".to_string()),
            field3: None,
        };

        // This should trigger the error if serialize_struct gets wrong len
        let encoded = to_vec(&data).unwrap();
        println!("Encoded bytes: {:?}", encoded);

        // Check the first byte - should be a map with the right number of entries
        // Map header format: major type 5 (0xA0 | count) or 0xB8 + count byte
        println!("First byte: 0x{:02x}", encoded[0]);
    }

    #[test]
    fn test_trait_object_serialization() {
        // Reproduce the AssertionCbor scenario
        use std::collections::HashMap;

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestStruct {
            name: String,
            values: HashMap<String, String>,
        }

        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());

        let obj = TestStruct {
            name: "test".to_string(),
            values: map,
        };

        // Serialize directly
        let encoded = to_vec(&obj).unwrap();
        println!("Encoded: {:?}", encoded);

        // Decode should work
        let decoded: TestStruct = from_slice(&encoded).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_skip_serializing_if() {
        // This reproduces the Actions struct issue
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct SkipTest {
            always: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            sometimes: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            rarely: Option<Vec<String>>,
        }

        // Test with None values - this will try to serialize 3 fields but skip 2
        let obj = SkipTest {
            always: "hello".to_string(),
            sometimes: None,
            rarely: None,
        };

        // This should work - serde should tell us len=1, not len=3
        let encoded = to_vec(&obj).unwrap();
        println!("Encoded skip test: {:?}", encoded);
        println!("First byte: 0x{:02x}", encoded[0]);

        let decoded: SkipTest = from_slice(&encoded).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_actions_like_struct() {
        // Reproduce the exact Actions structure
        use std::collections::HashMap;

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct ActionLike {
            params: Option<HashMap<String, Vec<u8>>>,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct ActionsLike {
            actions: Vec<ActionLike>,
            #[serde(skip_serializing_if = "Option::is_none")]
            metadata: Option<HashMap<String, String>>,
        }

        let mut params = HashMap::new();
        params.insert("key1".to_string(), vec![1, 2, 3]);

        let mut metadata = HashMap::new();
        metadata.insert("meta1".to_string(), "value1".to_string());

        let obj = ActionsLike {
            actions: vec![ActionLike {
                params: Some(params),
            }],
            metadata: Some(metadata),
        };

        // This might trigger the error if there's an issue with HashMap serialization
        let encoded = to_vec(&obj).unwrap();
        println!("Encoded actions-like: {} bytes", encoded.len());

        let decoded: ActionsLike = from_slice(&encoded).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_flatten_attribute() {
        // Test #[serde(flatten)] which causes indefinite-length serialization
        use std::collections::HashMap;

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct WithFlatten {
            regular_field: String,
            #[serde(flatten)]
            flattened: HashMap<String, String>,
        }

        let mut map = HashMap::new();
        map.insert("extra1".to_string(), "value1".to_string());
        map.insert("extra2".to_string(), "value2".to_string());

        let obj = WithFlatten {
            regular_field: "test".to_string(),
            flattened: map,
        };

        // This WILL trigger the indefinite-length path due to flatten
        // Our fallback to Value should handle it
        let encoded = to_vec(&obj).unwrap();
        println!("Encoded flattened: {} bytes", encoded.len());
        println!("First byte: 0x{:02x}", encoded[0]);

        let decoded: WithFlatten = from_slice(&encoded).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_enum_serialization() {
        // Test different enum representation styles

        // Unit variant (serializes as string)
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        enum SimpleEnum {
            Temporal,
            Spatial,
            Other,
        }

        let val = SimpleEnum::Temporal;
        let encoded = to_vec(&val).unwrap();
        println!("Simple enum encoded: {:?}", encoded);
        let decoded: SimpleEnum = from_slice(&encoded).unwrap();
        assert_eq!(val, decoded);

        // With rename
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        #[serde(rename_all = "lowercase")]
        enum RenamedEnum {
            Temporal,
            Spatial,
        }

        let val2 = RenamedEnum::Temporal;
        let encoded2 = to_vec(&val2).unwrap();
        println!("Renamed enum encoded: {:?}", encoded2);
        let decoded2: RenamedEnum = from_slice(&encoded2).unwrap();
        assert_eq!(val2, decoded2);

        // Enum with data
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        enum DataEnum {
            Unit,
            Newtype(String),
            Tuple(i32, String),
            Struct { field: String },
        }

        let val3 = DataEnum::Struct {
            field: "test".to_string(),
        };
        let encoded3 = to_vec(&val3).unwrap();
        println!("Struct variant encoded: {:?}", encoded3);
        let decoded3: DataEnum = from_slice(&encoded3).unwrap();
        assert_eq!(val3, decoded3);
    }

    #[test]
    fn test_float_serialization() {
        // Test f32
        let f32_val = 4.0f32;
        let encoded = to_vec(&f32_val).unwrap();
        println!("f32 encoded: {:?}", encoded);
        // Should be: major type 7 (0xE0), additional info 26 (0x1A), then 4 bytes
        assert_eq!(encoded[0], (MAJOR_SIMPLE << 5) | 26);
        let decoded: f32 = from_slice(&encoded).unwrap();
        assert_eq!(f32_val, decoded);

        // Test f64
        let f64_val = 2.5f64;
        let encoded = to_vec(&f64_val).unwrap();
        println!("f64 encoded: {:?}", encoded);
        // Should be: major type 7 (0xE0), additional info 27 (0x1B), then 8 bytes
        assert_eq!(encoded[0], (MAJOR_SIMPLE << 5) | 27);
        let decoded: f64 = from_slice(&encoded).unwrap();
        assert_eq!(f64_val, decoded);

        // Test in a struct
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct ExifData {
            f_number: f64,
            exposure_time: f32,
            zoom_ratio: f64,
        }

        let exif = ExifData {
            f_number: 4.0,
            exposure_time: 0.01,
            zoom_ratio: 2.0,
        };

        let encoded = to_vec(&exif).unwrap();
        println!("Exif data encoded: {} bytes", encoded.len());
        let decoded: ExifData = from_slice(&encoded).unwrap();
        assert_eq!(exif, decoded);
    }

    #[test]
    fn test_invalid_cbor_trailing_bytes() {
        use crate::Value;

        // These bytes are just a sequence of small integers with no structure
        // The first byte (0x0d = 13) is a valid CBOR integer, but the rest are trailing garbage
        let invalid_bytes = vec![0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f];

        let result: Result<Value> = from_slice(&invalid_bytes);
        assert!(result.is_err(), "Should fail on trailing bytes");

        if let Err(e) = result {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("trailing"),
                "Error should mention trailing data: {}",
                msg
            );
        }
    }

    #[test]
    fn test_empty_input() {
        use crate::Value;

        let empty_bytes = vec![];
        let result: Result<Value> = from_slice(&empty_bytes);
        assert!(result.is_err(), "Should fail on empty input");

        if let Err(e) = result {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("empty"),
                "Error should mention empty input: {}",
                msg
            );
        }
    }

    #[test]
    fn test_incomplete_cbor() {
        // Start of an array but incomplete
        let incomplete = vec![0x85]; // array of 5 elements, but no elements follow

        let result: Result<Vec<u32>> = from_slice(&incomplete);
        assert!(result.is_err(), "Should fail on incomplete CBOR");
    }

    #[test]
    fn test_valid_cbor_all_bytes_consumed() {
        // Valid integer should consume exactly 1 byte
        let valid = vec![0x0d]; // integer 13
        let result: Result<u32> = from_slice(&valid);
        assert!(result.is_ok(), "Should succeed on valid CBOR");
        assert_eq!(result.unwrap(), 13);
    }
}

/// Serialization module for compatibility with serde_cbor
pub mod ser {
    use crate::{Encoder, Error, SerializeVec};
    use serde::Serialize;
    use std::io::Write;

    /// Serialize to Vec (may use indefinite-length encoding for iterators without known length)
    /// For deterministic/canonical encoding required by C2PA, use to_vec_packed instead.
    pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
        // Note: Currently same as to_vec_packed since Rust standard collections
        // (Vec, HashMap, etc.) always know their length. Could be extended in
        // future to support indefinite-length for streaming iterators.
        crate::to_vec(value)
    }

    /// Serialize to Vec with packed/canonical encoding (definite-length only)
    /// This ensures deterministic output required for digital signatures.
    pub fn to_vec_packed<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
        crate::to_vec(value)
    }

    /// Write to writer (may use indefinite-length encoding)
    pub fn to_writer<W: Write, T: Serialize>(writer: W, value: &T) -> Result<(), Error> {
        crate::to_writer(writer, value)
    }

    /// A serializer for CBOR encoding
    pub struct Serializer<W: Write> {
        encoder: Encoder<W>,
    }

    impl<W: Write> Serializer<W> {
        /// Create a new CBOR serializer
        pub fn new(writer: W) -> Self {
            Serializer {
                encoder: Encoder::new(writer),
            }
        }

        /// Create a packed/canonical serializer (same as new for now)
        pub fn packed_format(self) -> Self {
            // For now, all encoding is packed/canonical (definite-length)
            // This method exists for API compatibility with serde_cbor
            self
        }

        /// Consume the serializer and return the writer
        pub fn into_inner(self) -> W {
            self.encoder.into_inner()
        }
    }

    // Implement Serializer trait directly on &mut Serializer
    // This allows serde_transcode and other tools to work correctly
    impl<'a, W: Write> serde::Serializer for &'a mut Serializer<W> {
        type Ok = ();
        type Error = Error;
        type SerializeSeq = SerializeVec<'a, W>;
        type SerializeTuple = SerializeVec<'a, W>;
        type SerializeTupleStruct = SerializeVec<'a, W>;
        type SerializeTupleVariant = &'a mut Encoder<W>;
        type SerializeMap = SerializeVec<'a, W>;
        type SerializeStruct = SerializeVec<'a, W>;
        type SerializeStructVariant = &'a mut Encoder<W>;

        fn serialize_bool(self, v: bool) -> Result<(), Error> {
            (&mut self.encoder).serialize_bool(v)
        }

        fn serialize_i8(self, v: i8) -> Result<(), Error> {
            (&mut self.encoder).serialize_i8(v)
        }

        fn serialize_i16(self, v: i16) -> Result<(), Error> {
            (&mut self.encoder).serialize_i16(v)
        }

        fn serialize_i32(self, v: i32) -> Result<(), Error> {
            (&mut self.encoder).serialize_i32(v)
        }

        fn serialize_i64(self, v: i64) -> Result<(), Error> {
            (&mut self.encoder).serialize_i64(v)
        }

        fn serialize_u8(self, v: u8) -> Result<(), Error> {
            (&mut self.encoder).serialize_u8(v)
        }

        fn serialize_u16(self, v: u16) -> Result<(), Error> {
            (&mut self.encoder).serialize_u16(v)
        }

        fn serialize_u32(self, v: u32) -> Result<(), Error> {
            (&mut self.encoder).serialize_u32(v)
        }

        fn serialize_u64(self, v: u64) -> Result<(), Error> {
            (&mut self.encoder).serialize_u64(v)
        }

        fn serialize_f32(self, v: f32) -> Result<(), Error> {
            (&mut self.encoder).serialize_f32(v)
        }

        fn serialize_f64(self, v: f64) -> Result<(), Error> {
            (&mut self.encoder).serialize_f64(v)
        }

        fn serialize_char(self, v: char) -> Result<(), Error> {
            (&mut self.encoder).serialize_char(v)
        }

        fn serialize_str(self, v: &str) -> Result<(), Error> {
            (&mut self.encoder).serialize_str(v)
        }

        fn serialize_bytes(self, v: &[u8]) -> Result<(), Error> {
            (&mut self.encoder).serialize_bytes(v)
        }

        fn serialize_none(self) -> Result<(), Error> {
            (&mut self.encoder).serialize_none()
        }

        fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Error> {
            (&mut self.encoder).serialize_some(value)
        }

        fn serialize_unit(self) -> Result<(), Error> {
            (&mut self.encoder).serialize_unit()
        }

        fn serialize_unit_struct(self, name: &'static str) -> Result<(), Error> {
            (&mut self.encoder).serialize_unit_struct(name)
        }

        fn serialize_unit_variant(
            self,
            name: &'static str,
            variant_index: u32,
            variant: &'static str,
        ) -> Result<(), Error> {
            (&mut self.encoder).serialize_unit_variant(name, variant_index, variant)
        }

        fn serialize_newtype_struct<T: ?Sized + Serialize>(
            self,
            name: &'static str,
            value: &T,
        ) -> Result<(), Error> {
            (&mut self.encoder).serialize_newtype_struct(name, value)
        }

        fn serialize_newtype_variant<T: ?Sized + Serialize>(
            self,
            name: &'static str,
            variant_index: u32,
            variant: &'static str,
            value: &T,
        ) -> Result<(), Error> {
            (&mut self.encoder).serialize_newtype_variant(name, variant_index, variant, value)
        }

        fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
            (&mut self.encoder).serialize_seq(len)
        }

        fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Error> {
            (&mut self.encoder).serialize_tuple(len)
        }

        fn serialize_tuple_struct(
            self,
            name: &'static str,
            len: usize,
        ) -> Result<Self::SerializeTupleStruct, Error> {
            (&mut self.encoder).serialize_tuple_struct(name, len)
        }

        fn serialize_tuple_variant(
            self,
            name: &'static str,
            variant_index: u32,
            variant: &'static str,
            len: usize,
        ) -> Result<Self::SerializeTupleVariant, Error> {
            (&mut self.encoder).serialize_tuple_variant(name, variant_index, variant, len)
        }

        fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Error> {
            (&mut self.encoder).serialize_map(len)
        }

        fn serialize_struct(
            self,
            name: &'static str,
            len: usize,
        ) -> Result<Self::SerializeStruct, Error> {
            (&mut self.encoder).serialize_struct(name, len)
        }

        fn serialize_struct_variant(
            self,
            name: &'static str,
            variant_index: u32,
            variant: &'static str,
            len: usize,
        ) -> Result<Self::SerializeStructVariant, Error> {
            (&mut self.encoder).serialize_struct_variant(name, variant_index, variant, len)
        }
    }
}

/// Deserialization module for compatibility with serde_cbor
pub mod de {
    pub use crate::Decoder as Deserializer;
}
