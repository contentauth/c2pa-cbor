# c2pa_cbor

A fast, lightweight CBOR (Concise Binary Object Representation) encoder/decoder with comprehensive support for tagged types.

## Features

- ✅ Full support for all CBOR major types (0-7)
- ✅ Tagged types (major type 6) with standard tags:
  - Date/time strings (tag 0) and epoch timestamps (tag 1)
  - URIs (tag 32)
  - Base64url and Base64 encoded data (tags 33, 34)
  - RFC 8746 typed arrays (tags 64-87) for efficient binary data
- ✅ Custom tag support via `write_tag()` and `read_tag()` methods
- ✅ Excellent performance with near-zero overhead
- ✅ Serde integration for seamless serialization

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
c2pa_cbor = "0.1"
serde = { version = "1.0", features = ["derive"] }
serde_bytes = "0.11"  # For efficient byte array handling
```

## Quick Start

### Basic Usage

```rust
use c2pa_cbor::{to_vec, from_slice};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Person {
    name: String,
    age: u32,
}

let person = Person {
    name: "Alice".to_string(),
    age: 30,
};

// Encode to CBOR
let encoded = to_vec(&person).unwrap();

// Decode from CBOR
let decoded: Person = from_slice(&encoded).unwrap();
assert_eq!(person, decoded);
```

### Tagged Types

```rust
use c2pa_cbor::{encode_uri, encode_datetime_string, from_slice};

// Encode a URI with tag 32
let mut buf = Vec::new();
encode_uri(&mut buf, "https://example.com").unwrap();
let decoded: String = from_slice(&buf).unwrap();
assert_eq!(decoded, "https://example.com");

// Encode a datetime string with tag 0
let mut buf = Vec::new();
encode_datetime_string(&mut buf, "2024-01-15T10:30:00Z").unwrap();
let decoded: String = from_slice(&buf).unwrap();
```

### Efficient Binary Data

For optimal performance with byte arrays, use `serde_bytes`:

```rust
use c2pa_cbor::{to_vec, from_slice};
use serde_bytes::ByteBuf;

// Efficient byte array encoding
let data = ByteBuf::from(vec![1, 2, 3, 4, 5]);
let encoded = to_vec(&data).unwrap();

// Only 1 byte overhead for small arrays!
assert_eq!(encoded.len(), 6);

let decoded: ByteBuf = from_slice(&encoded).unwrap();
assert_eq!(decoded.into_vec(), vec![1, 2, 3, 4, 5]);
```

### Custom Tags

```rust
use c2pa_cbor::Encoder;

let mut buf = Vec::new();
let mut encoder = Encoder::new(&mut buf);

// Write a custom tag (e.g., tag 100)
encoder.write_tag(100).unwrap();
encoder.encode(&"custom data").unwrap();
```

### Typed Arrays (RFC 8746)

```rust
use c2pa_cbor::{encode_uint8_array, encode_uint32be_array};

let mut buf = Vec::new();

// Encode uint8 array with tag 64
encode_uint8_array(&mut buf, &[1, 2, 3, 4, 5]).unwrap();

// Encode uint32 big-endian array with tag 66
let data: [u32; 3] = [0x12345678, 0x9ABCDEF0, 0x11223344];
encode_uint32be_array(&mut buf, &data).unwrap();
```

## Performance

This implementation is designed for **speed** with binary byte arrays:

### Speed Characteristics
- **Encoding**: ~30-35 GB/s for large arrays (virtually memcpy speed)
- **Decoding**: ~24-29 GB/s for large arrays
- Small arrays (1KB): ~160ns encode, ~270ns decode
- Large arrays (1MB): ~30µs encode, ~41µs decode
- Performance scales linearly with data size
- Zero-copy design means encoding is just a memcpy after writing the header

### Size Overhead
Binary byte arrays have minimal overhead:
- 5 bytes: 1 byte overhead (header only)
- 1 KB: 3 bytes overhead (header + 2-byte length)
- 100 KB: 5 bytes overhead (header + 4-byte length)
- 1 MB: 5 bytes overhead (header + 4-byte length)

### Key Performance Features
- ✅ Zero allocations during encoding
- ✅ Single allocation during decoding
- ✅ No per-element overhead with `serde_bytes`
- ✅ Direct memory writes (no intermediate buffers)
- ✅ Near memory bandwidth performance

## API Overview

### Encoding Functions

- `to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>>` - Encode any serializable value
- `encode_tagged<W, T>(writer, tag, value)` - Encode a tagged value
- `encode_datetime_string(writer, datetime)` - Tag 0
- `encode_epoch_datetime(writer, epoch)` - Tag 1
- `encode_uri(writer, uri)` - Tag 32
- `encode_base64url(writer, data)` - Tag 33
- `encode_base64(writer, data)` - Tag 34
- `encode_uint8_array(writer, data)` - Tag 64
- `encode_uint16be_array(writer, data)` - Tag 65
- `encode_uint32be_array(writer, data)` - Tag 66
- `encode_uint64be_array(writer, data)` - Tag 67
- `encode_uint16le_array(writer, data)` - Tag 69
- `encode_uint32le_array(writer, data)` - Tag 70
- `encode_uint64le_array(writer, data)` - Tag 71
- `encode_float32be_array(writer, data)` - Tag 81
- `encode_float64be_array(writer, data)` - Tag 82
- `encode_float32le_array(writer, data)` - Tag 85
- `encode_float64le_array(writer, data)` - Tag 86

### Decoding Functions

- `from_slice<'de, T: Deserialize<'de>>(slice: &[u8]) -> Result<T>` - Decode any deserializable value

### Low-Level API

```rust
use c2pa_cbor::{Encoder, Decoder};

// Encoding
let mut buf = Vec::new();
let mut encoder = Encoder::new(&mut buf);
encoder.write_tag(42).unwrap();
encoder.encode(&some_value).unwrap();

// Decoding
let mut decoder = Decoder::new(&buf[..]);
let tag = decoder.read_tag().unwrap();
let value: SomeType = decoder.decode().unwrap();
```

## CBOR Compatibility

This implementation follows:
- **RFC 8949** - CBOR specification
- **RFC 8746** - Typed arrays as byte strings
- **RFC 3339** - Date/time format for tag 0
- **RFC 3986** - URI format for tag 32

## Testing

Run the test suite:

```bash
cargo test
```

Run performance tests:

```bash
cargo test performance -- --nocapture
cargo test speed_vs_size -- --nocapture
```

## License

[Add your license here]

## Contributing

[Add contributing guidelines here]
