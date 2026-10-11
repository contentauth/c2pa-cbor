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
//!
//! Parsing does not verify signatures, certificates, or algorithm/key policy.
//! Those checks remain the caller's responsibility. Critical headers are rejected
//! because this subset does not implement their processing. Decoding bounds input
//! bytes, individual strings, and nesting, not total decoded heap usage.

use std::{collections::BTreeSet, fmt, io::Cursor};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_bytes::{ByteBuf, Bytes};

use crate::{Decoder, Result, Value, tags::Tagged};

/// CBOR tag for a `COSE_Sign1` structure (RFC 9052 §4.2).
const COSE_SIGN1_TAG: u64 = 18;

/// IANA COSE Header Parameters registry label for `alg`.
const LABEL_ALG: i64 = 1;
/// IANA COSE Header Parameters registry label for `content type`.
const LABEL_CONTENT_TYPE: i64 = 3;

fn reject_pending_tags<E: de::Error>() -> std::result::Result<(), E> {
    if !crate::tags::take_all_tags().is_empty() {
        return Err(E::custom("unexpected tag on COSE structural field"));
    }
    Ok(())
}

/// A COSE header map label: either a registered integer or a private-use text label.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
    fn labels(&self) -> BTreeSet<Label> {
        let mut labels: BTreeSet<_> = self.rest.iter().map(|(label, _)| label.clone()).collect();
        if self.alg.is_some() {
            labels.insert(Label::Int(LABEL_ALG));
        }
        if self.content_type.is_some() {
            labels.insert(Label::Int(LABEL_CONTENT_TYPE));
        }
        labels
    }

    fn validate(&self) -> Result<()> {
        if matches!(self.content_type, Some(ContentType::Assigned(value)) if !(0..=65535).contains(&value))
        {
            return Err(crate::Error::Syntax("invalid COSE content format".into()));
        }
        let mut labels = BTreeSet::new();
        for (label, _) in &self.rest {
            if matches!(label, Label::Int(LABEL_ALG | LABEL_CONTENT_TYPE)) || !labels.insert(label)
            {
                return Err(crate::Error::Syntax(
                    "duplicate or reserved COSE header label".into(),
                ));
            }
        }
        Ok(())
    }

    fn field_count(&self) -> usize {
        self.alg.is_some() as usize + self.content_type.is_some() as usize + self.rest.len()
    }
}

impl Serialize for Header {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        self.validate().map_err(serde::ser::Error::custom)?;
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
                reject_pending_tags()?;
                let mut header = Header::default();
                let mut labels = BTreeSet::new();
                while let Some((key, value)) = map.next_entry::<Value, Value>()? {
                    let label = match &key {
                        Value::Integer(value) => Label::Int(*value),
                        Value::Text(value) => Label::Text(value.clone()),
                        _ => {
                            return Err(de::Error::custom(
                                "COSE header label must be an integer or text string",
                            ));
                        }
                    };
                    if !labels.insert(label) {
                        return Err(de::Error::custom("duplicate COSE header label"));
                    }
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
                header.validate().map_err(de::Error::custom)?;
                Ok(header)
            }
        }

        deserializer.deserialize_any(HeaderVisitor)
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
/// fresh signature, `original_data` is `None`: the same ordered header encoding
/// is used for both the stored bstr and the `Sig_structure`. Do not change the
/// header between constructing signing inputs and storing the signature.
/// Encoding rejects changes to decoded fields that disagree with original bytes.
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
        self.header.validate()?;
        match &self.original_data {
            Some(bytes) => {
                let decoded = decode_protected(bytes)?;
                if crate::to_vec(&decoded)? != crate::to_vec(&self.header)? {
                    return Err(crate::Error::Syntax(
                        "COSE protected header differs from original bytes".into(),
                    ));
                }
                Ok(bytes.clone())
            }
            None if self.header.field_count() == 0 => Ok(Vec::new()),
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

#[derive(Serialize)]
#[serde(transparent)]
struct StrictBytes(ByteBuf);

impl<'de> Deserialize<'de> for StrictBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct BytesVisitor;
        impl Visitor<'_> for BytesVisitor {
            type Value = StrictBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a COSE byte string")
            }

            fn visit_byte_buf<E: de::Error>(
                self,
                bytes: Vec<u8>,
            ) -> std::result::Result<Self::Value, E> {
                reject_pending_tags()?;
                Ok(StrictBytes(ByteBuf::from(bytes)))
            }
        }
        deserializer.deserialize_byte_buf(BytesVisitor)
    }
}

struct StrictPayload(Option<Vec<u8>>);

impl<'de> Deserialize<'de> for StrictPayload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct PayloadVisitor;
        impl Visitor<'_> for PayloadVisitor {
            type Value = StrictPayload;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a COSE payload byte string or null")
            }

            fn visit_byte_buf<E: de::Error>(
                self,
                bytes: Vec<u8>,
            ) -> std::result::Result<Self::Value, E> {
                reject_pending_tags()?;
                Ok(StrictPayload(Some(bytes)))
            }

            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                reject_pending_tags()?;
                Ok(StrictPayload(None))
            }
        }
        deserializer.deserialize_any(PayloadVisitor)
    }
}

struct StrictSign1Wire(StrictBytes, Header, StrictPayload, StrictBytes);

impl<'de> Deserialize<'de> for StrictSign1Wire {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct WireVisitor;
        impl<'de> Visitor<'de> for WireVisitor {
            type Value = StrictSign1Wire;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a four-element COSE_Sign1 array")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                reject_pending_tags()?;
                let protected = sequence
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let unprotected = sequence
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let payload = sequence
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let signature = sequence
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(5, &self));
                }
                Ok(StrictSign1Wire(protected, unprotected, payload, signature))
            }
        }
        deserializer.deserialize_tuple(4, WireVisitor)
    }
}

fn decode_protected(bytes: &[u8]) -> Result<Header> {
    if bytes.is_empty() {
        return Ok(Header::default());
    }
    let mut cursor = Cursor::new(bytes);
    let header = Decoder::new(&mut cursor)
        .with_max_allocation(crate::DEFAULT_MAX_ALLOCATION)
        .decode()?;
    if cursor.position() != bytes.len() as u64 {
        return Err(crate::Error::Syntax(
            "trailing data in COSE protected header".into(),
        ));
    }
    Ok(header)
}

impl CoseSign1 {
    fn validate(&self) -> Result<()> {
        self.protected.header.validate()?;
        self.unprotected.validate()?;
        if !self
            .protected
            .header
            .labels()
            .is_disjoint(&self.unprotected.labels())
        {
            return Err(crate::Error::Syntax(
                "COSE header label appears in both buckets".into(),
            ));
        }
        if self
            .protected
            .header
            .rest
            .iter()
            .chain(&self.unprotected.rest)
            .any(|(label, _)| *label == Label::Int(2))
        {
            return Err(crate::Error::Syntax(
                "critical COSE headers are not supported by this C2PA subset".into(),
            ));
        }
        Ok(())
    }

    /// Encode as a CBOR-tagged (tag 18) `COSE_Sign1` structure.
    pub fn to_tagged_vec(&self) -> Result<Vec<u8>> {
        self.validate()?;
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
        Self::from_tagged_slice_with_limit(bytes, crate::DEFAULT_MAX_ALLOCATION)
    }

    /// Decode with a maximum input length and per-string allocation limit.
    /// This is not a total decoded-memory budget; nesting uses the default limit.
    pub fn from_tagged_slice_with_limit(bytes: &[u8], max_size: usize) -> Result<Self> {
        if bytes.len() > max_size {
            return Err(crate::Error::Syntax(
                "COSE input exceeds maximum size".into(),
            ));
        }
        let mut cursor = Cursor::new(bytes);
        let mut decoder = Decoder::new(&mut cursor).with_max_allocation(max_size);
        let tag = decoder.read_tag()?;
        if tag != COSE_SIGN1_TAG {
            return Err(crate::Error::Syntax(format!(
                "expected COSE_Sign1 tag {COSE_SIGN1_TAG}, found {tag}"
            )));
        }
        let StrictSign1Wire(protected_bytes, unprotected, payload, signature) = decoder.decode()?;
        if cursor.position() != bytes.len() as u64 {
            return Err(crate::Error::Syntax(
                "trailing data after COSE_Sign1".into(),
            ));
        }
        let protected_bytes = protected_bytes.0.into_vec();
        let header = decode_protected(&protected_bytes)?;

        let sign1 = CoseSign1 {
            protected: ProtectedHeader {
                header,
                original_data: Some(protected_bytes),
            },
            unprotected,
            payload: payload.0,
            signature: signature.0.into_vec(),
        };
        sign1.validate()?;
        Ok(sign1)
    }

    /// The "to be signed" bytes for this structure: the RFC 8152 §4.4
    /// `Sig_structure`, computed over this structure's own protected header,
    /// `external_aad`, and (if present) its own payload.
    pub fn tbs_data(&self, external_aad: &[u8]) -> Result<Vec<u8>> {
        self.validate()?;
        sig_structure_data(
            SignatureContext::CoseSign1,
            &self.protected,
            external_aad,
            self.payload.as_deref().ok_or_else(|| {
                crate::Error::Syntax("detached COSE payload requires detached_tbs_data".into())
            })?,
        )
    }

    /// Signing inputs for an explicitly supplied detached payload.
    pub fn detached_tbs_data(&self, external_aad: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        self.validate()?;
        if self.payload.is_some() {
            return Err(crate::Error::Syntax("COSE payload is not detached".into()));
        }
        sig_structure_data(
            SignatureContext::CoseSign1,
            &self.protected,
            external_aad,
            payload,
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

/// The four-element signing contexts used by C2PA (RFC 8152 section 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureContext {
    CoseSign1,
    CounterSignature,
}

impl SignatureContext {
    fn as_str(self) -> &'static str {
        match self {
            SignatureContext::CoseSign1 => "Signature1",
            SignatureContext::CounterSignature => "CounterSignature",
        }
    }
}

/// Build the RFC 8152 §4.4 `Sig_structure` bytes: `[context, protected_bstr,
/// external_aad, payload]`, a definite-length 4-element CBOR array.
/// `CounterSignature` supports only C2PA's form with no signer-protected header.
/// This helper does not implement general countersignature message processing.
pub fn sig_structure_data(
    context: SignatureContext,
    protected: &ProtectedHeader,
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let protected_bytes = protected.encoded_bytes()?;
    let tuple = (
        context.as_str(),
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
        let tbs =
            sig_structure_data(SignatureContext::CoseSign1, &protected, b"", b"payload").unwrap();

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
