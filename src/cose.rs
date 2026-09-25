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

//! Minimal `COSE_Sign1` support (RFC 9052 §4.2, RFC 8152 §4.4 `Sig_structure`),
//! built entirely on this crate's own CBOR codec. This is not a general-purpose
//! COSE implementation - it covers only `COSE_Sign1` (no `CoseSign`, `CoseEncrypt`,
//! `CoseMac`, or key structures) and only the header shapes C2PA needs
//! (an algorithm, an optional content type, and arbitrary extension labels).

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
};
use serde_bytes::{ByteBuf, Bytes};

use crate::{Result, Value, tags::Tagged};

/// CBOR tag for a `COSE_Sign1` structure (RFC 9052 §4.2).
const COSE_SIGN1_TAG: u64 = 18;

/// IANA COSE Header Parameters registry label for `alg`.
const LABEL_ALG: i64 = 1;
/// IANA COSE Header Parameters registry label for `content type`.
const LABEL_CONTENT_TYPE: i64 = 3;

/// A COSE header map label: either a registered integer or a private-use text label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Label {
    Int(i64),
    Text(String),
}

/// The `content type` header parameter's value (RFC 9052 §3.1): either a CoAP
/// Content-Format integer or a MIME-type-like text string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentType {
    Text(String),
    Assigned(i64),
}

/// A COSE header map (protected or unprotected).
///
/// `alg` and `content_type` are pulled out as typed fields because callers read
/// them directly; every other header parameter (`x5chain`, `sigTst`/`sigTst2`,
/// `rVals`, the `pad`/`pad2` padding entries, ...) lives in `rest` and is looked
/// up by label, exactly as C2PA's call sites already do.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Header {
    pub alg: Option<i64>,
    pub content_type: Option<ContentType>,
    /// Insertion-order-preserving: encoding this header writes `rest` entries
    /// in this order, which the box-size padding trick in c2pa-rs's `sign.rs`
    /// depends on (it scans for, and in-place replaces, a `"pad"` entry).
    pub rest: Vec<(Label, Value)>,
}

impl Header {
    fn field_count(&self) -> usize {
        self.alg.is_some() as usize + self.content_type.is_some() as usize + self.rest.len()
    }
}

impl Serialize for Header {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(self.field_count()))?;
        if let Some(alg) = self.alg {
            map.serialize_entry(&LABEL_ALG, &alg)?;
        }
        if let Some(content_type) = &self.content_type {
            match content_type {
                ContentType::Text(s) => map.serialize_entry(&LABEL_CONTENT_TYPE, s)?,
                ContentType::Assigned(n) => map.serialize_entry(&LABEL_CONTENT_TYPE, n)?,
            }
        }
        for (label, value) in &self.rest {
            match label {
                Label::Int(i) => map.serialize_entry(i, value)?,
                Label::Text(t) => map.serialize_entry(t, value)?,
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Header {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct HeaderVisitor;

        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = Header;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a COSE header map")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Header, A::Error> {
                let mut header = Header::default();
                while let Some((key, value)) = map.next_entry::<Value, Value>()? {
                    match key {
                        Value::Integer(i) if i == LABEL_ALG => {
                            header.alg = Some(value.as_i64().ok_or_else(|| {
                                de::Error::custom("COSE `alg` header value out of i64 range")
                            })?);
                        }
                        Value::Integer(i) if i == LABEL_CONTENT_TYPE => {
                            header.content_type = Some(match value {
                                Value::Text(s) => ContentType::Text(s),
                                Value::Integer(n) => ContentType::Assigned(n),
                                _ => {
                                    return Err(de::Error::custom(
                                        "COSE `content type` header value must be text or integer",
                                    ));
                                }
                            });
                        }
                        Value::Integer(label) => header.rest.push((Label::Int(label), value)),
                        Value::Text(s) => header.rest.push((Label::Text(s), value)),
                        _ => {
                            return Err(de::Error::custom(
                                "COSE header label must be an integer or text string",
                            ));
                        }
                    }
                }
                Ok(header)
            }
        }

        deserializer.deserialize_map(HeaderVisitor)
    }
}

/// Builder for [`Header`], mirroring the small subset of `coset::HeaderBuilder`
/// that c2pa-rs uses.
#[derive(Default)]
pub struct HeaderBuilder(Header);

impl HeaderBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn algorithm(mut self, alg: i64) -> Self {
        self.0.alg = Some(alg);
        self
    }

    pub fn content_type(mut self, content_type: String) -> Self {
        self.0.content_type = Some(ContentType::Text(content_type));
        self
    }

    pub fn content_format(mut self, format: i64) -> Self {
        self.0.content_type = Some(ContentType::Assigned(format));
        self
    }

    pub fn value(mut self, label: i64, value: Value) -> Self {
        self.0.rest.push((Label::Int(label), value));
        self
    }

    pub fn text_value(mut self, label: String, value: Value) -> Self {
        self.0.rest.push((Label::Text(label), value));
        self
    }

    pub fn build(self) -> Header {
        self.0
    }
}

/// A protected header together with the exact bytes it was (or will be)
/// encoded as.
///
/// RFC 8152 §4.4 defines `Sig_structure` using the protected header's encoded
/// bytes *exactly as they appear in the message*, not a re-derivation from its
/// decoded fields. `original_data` captures those raw bytes when a `CoseSign1`
/// is parsed from the wire, so re-verifying a signature - including one
/// produced by a different COSE implementation - always recomputes the
/// `Sig_structure` from the bytes that were actually signed. When building a
/// fresh signature, `original_data` is `None`: the header is encoded once and
/// that encoding is reused for both the stored bstr and the `Sig_structure`,
/// which is only safe because nothing re-derives it a second time.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProtectedHeader {
    pub header: Header,
    pub original_data: Option<Vec<u8>>,
}

impl ProtectedHeader {
    pub fn new(header: Header) -> Self {
        ProtectedHeader {
            header,
            original_data: None,
        }
    }

    /// The bytes this protected header is (or would be) encoded as: the raw
    /// bytes it was parsed from, if any, otherwise a fresh encoding of `header`.
    fn encoded_bytes(&self) -> Result<Vec<u8>> {
        match &self.original_data {
            Some(bytes) => Ok(bytes.clone()),
            None => crate::to_vec(&self.header),
        }
    }
}

/// A `COSE_Sign1` structure (RFC 9052 §4.2).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CoseSign1 {
    pub protected: ProtectedHeader,
    pub unprotected: Header,
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

type CoseSign1Wire = (ByteBuf, Header, Option<ByteBuf>, ByteBuf);

impl CoseSign1 {
    /// Encode as a CBOR-tagged (tag 18) `COSE_Sign1` structure.
    pub fn to_tagged_vec(&self) -> Result<Vec<u8>> {
        let protected_bytes = self.protected.encoded_bytes()?;
        let wire: CoseSign1Wire = (
            ByteBuf::from(protected_bytes),
            self.unprotected.clone(),
            self.payload.clone().map(ByteBuf::from),
            ByteBuf::from(self.signature.clone()),
        );
        crate::to_vec(&Tagged::new(Some(COSE_SIGN1_TAG), wire))
    }

    /// Decode a CBOR-tagged (tag 18) `COSE_Sign1` structure.
    pub fn from_tagged_slice(bytes: &[u8]) -> Result<Self> {
        let tagged = Tagged::<CoseSign1Wire>::from_tagged_slice(bytes)?;
        if tagged.tag != Some(COSE_SIGN1_TAG) {
            return Err(crate::Error::Syntax(format!(
                "expected COSE_Sign1 tag {COSE_SIGN1_TAG}, found {:?}",
                tagged.tag
            )));
        }
        let (protected_bytes, unprotected, payload, signature) = tagged.value;
        let protected_bytes = protected_bytes.into_vec();
        let header: Header = crate::from_slice(&protected_bytes)?;

        Ok(CoseSign1 {
            protected: ProtectedHeader {
                header,
                original_data: Some(protected_bytes),
            },
            unprotected,
            payload: payload.map(ByteBuf::into_vec),
            signature: signature.into_vec(),
        })
    }

    /// The "to be signed" bytes for this structure: the RFC 8152 §4.4
    /// `Sig_structure`, computed over this structure's own protected header,
    /// `external_aad`, and (if present) its own payload.
    pub fn tbs_data(&self, external_aad: &[u8]) -> Result<Vec<u8>> {
        sig_structure_data(
            &self.protected,
            external_aad,
            self.payload.as_deref().unwrap_or(&[]),
        )
    }
}

/// Builder for [`CoseSign1`], mirroring the small subset of
/// `coset::CoseSign1Builder` that c2pa-rs uses.
#[derive(Default)]
pub struct CoseSign1Builder(CoseSign1);

impl CoseSign1Builder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn protected(mut self, header: Header) -> Self {
        self.0.protected = ProtectedHeader::new(header);
        self
    }

    pub fn unprotected(mut self, header: Header) -> Self {
        self.0.unprotected = header;
        self
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.0.payload = Some(payload);
        self
    }

    pub fn build(self) -> CoseSign1 {
        self.0
    }
}

/// Build the RFC 8152 §4.4 `Sig_structure` bytes for a `COSE_Sign1`:
/// `["Signature1", protected_bstr, external_aad, payload]`, a definite-length
/// 4-element CBOR array.
///
/// Unlike `coset::sig_structure_data`, this only ever builds the `COSE_Sign1`
/// context (c2pa-rs never signs multi-signer `COSE_Sign` structures), so
/// there's no `SignatureContext` or "sign protected" parameter to pass.
pub fn sig_structure_data(
    protected: &ProtectedHeader,
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let protected_bytes = protected.encoded_bytes()?;
    let tuple = (
        "Signature1",
        Bytes::new(&protected_bytes),
        Bytes::new(external_aad),
        Bytes::new(payload),
    );
    crate::to_vec(&tuple)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        HeaderBuilder::new()
            .algorithm(-7) // ES256
            .value(33, Value::Bytes(vec![1, 2, 3])) // x5chain, single cert
            .build()
    }

    #[test]
    fn header_round_trips() {
        let header = sample_header();
        let bytes = crate::to_vec(&header).unwrap();
        let decoded: Header = crate::from_slice(&bytes).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn header_preserves_rest_insertion_order() {
        let header = HeaderBuilder::new()
            .text_value("first".to_string(), Value::Integer(1))
            .text_value("second".to_string(), Value::Integer(2))
            .build();
        let bytes = crate::to_vec(&header).unwrap();
        let decoded: Header = crate::from_slice(&bytes).unwrap();
        assert_eq!(
            decoded.rest,
            vec![
                (Label::Text("first".to_string()), Value::Integer(1)),
                (Label::Text("second".to_string()), Value::Integer(2)),
            ]
        );
    }

    #[test]
    fn content_type_text_round_trips() {
        let header = HeaderBuilder::new()
            .content_type("application/vc".to_string())
            .build();
        let bytes = crate::to_vec(&header).unwrap();
        let decoded: Header = crate::from_slice(&bytes).unwrap();
        assert_eq!(
            decoded.content_type,
            Some(ContentType::Text("application/vc".to_string()))
        );
    }

    #[test]
    fn content_type_assigned_round_trips() {
        let header = HeaderBuilder::new().content_format(50).build();
        let bytes = crate::to_vec(&header).unwrap();
        let decoded: Header = crate::from_slice(&bytes).unwrap();
        assert_eq!(decoded.content_type, Some(ContentType::Assigned(50)));
    }

    #[test]
    fn cose_sign1_round_trips_and_preserves_original_data() {
        let sign1 = CoseSign1Builder::new()
            .protected(sample_header())
            .unprotected(
                HeaderBuilder::new()
                    .text_value("pad".to_string(), Value::Bytes(vec![0; 16]))
                    .build(),
            )
            .payload(b"hello".to_vec())
            .build();
        let mut sign1 = sign1;
        sign1.signature = vec![9, 9, 9];

        let bytes = sign1.to_tagged_vec().unwrap();
        let decoded = CoseSign1::from_tagged_slice(&bytes).unwrap();

        assert_eq!(decoded.protected.header, sign1.protected.header);
        assert_eq!(decoded.unprotected, sign1.unprotected);
        assert_eq!(decoded.payload, sign1.payload);
        assert_eq!(decoded.signature, sign1.signature);
        assert!(decoded.protected.original_data.is_some());
        assert!(sign1.protected.original_data.is_none());
    }

    #[test]
    fn tbs_data_is_four_element_array_of_signature1_context() {
        let protected = ProtectedHeader::new(sample_header());
        let tbs = sig_structure_data(&protected, b"", b"payload").unwrap();

        // Definite-length array of 4 elements.
        assert_eq!(tbs[0], 0x84);
        let decoded: Value = crate::from_slice(&tbs).unwrap();
        let arr = decoded.as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0], Value::Text("Signature1".to_string()));
        assert_eq!(arr[2], Value::Bytes(vec![]));
        assert_eq!(arr[3], Value::Bytes(b"payload".to_vec()));
    }

    #[test]
    fn from_tagged_slice_rejects_wrong_tag() {
        // Tag 17 is COSE_Mac0, not COSE_Sign1.
        let wire: CoseSign1Wire = (
            ByteBuf::from(vec![0xa0]), // empty header map
            Header::default(),
            None,
            ByteBuf::from(vec![]),
        );
        let bytes = crate::to_vec(&Tagged::new(Some(17u64), wire)).unwrap();
        assert!(CoseSign1::from_tagged_slice(&bytes).is_err());
    }

    #[test]
    fn pad_entry_can_be_found_and_replaced_like_coset_header_rest() {
        // Mirrors the padding trick in c2pa-rs's sign.rs: scan `unprotected.rest`
        // for a "pad" label and replace its value in place.
        let mut header = HeaderBuilder::new()
            .text_value("pad".to_string(), Value::Bytes(vec![0u8; 4]))
            .build();

        let found = header
            .rest
            .iter_mut()
            .find(|(label, _)| *label == Label::Text("pad".to_string()));
        assert!(found.is_some());
        found.unwrap().1 = Value::Bytes(vec![0u8; 10]);

        assert_eq!(header.rest[0].1, Value::Bytes(vec![0u8; 10]));
    }
}
