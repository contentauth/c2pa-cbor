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

use std::{
    cell::Cell,
    collections::BTreeSet,
    fmt,
    io::{Cursor, Read},
};

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
    /// Look up an extension header by its exact integer or text label.
    /// Algorithm and content type remain available through their typed fields.
    pub fn get(&self, label: &Label) -> Option<&Value> {
        self.rest
            .iter()
            .find(|(key, _)| key == label)
            .map(|(_, value)| value)
    }

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
    pub fn encoded_bytes(&self) -> Result<Vec<u8>> {
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
    /// Check the common C2PA signing requirements, without cryptographic policy checks.
    pub fn validate_c2pa(&self) -> Result<()> {
        self.validate()?;
        self.protected.encoded_bytes()?;
        if self.protected.header.alg.is_none() {
            return Err(crate::Error::Syntax(
                "C2PA requires a protected alg header".into(),
            ));
        }
        if self
            .protected
            .header
            .rest
            .iter()
            .chain(&self.unprotected.rest)
            .any(|(label, _)| *label == Label::Text("alg".into()))
        {
            return Err(crate::Error::Syntax(
                "C2PA alg must use integer label 1".into(),
            ));
        }
        let iat = Label::Text("iat".into());
        if self.unprotected.get(&iat).is_some()
            || self.protected.header.get(&iat).is_some_and(|value| {
                !matches!(value, Value::Integer(_) | Value::Float(_))
                    || matches!(value, Value::Float(number) if !number.is_finite())
            })
        {
            return Err(crate::Error::Syntax(
                "C2PA iat must be an untagged protected NumericDate".into(),
            ));
        }
        Ok(())
    }

    /// Check a claim signature's COSE profile, accepting legacy credential placement.
    /// Does not validate certificates, algorithm policy, or the signature itself.
    pub fn validate_c2pa_claim(&self) -> Result<()> {
        self.validate_c2pa()?;
        if self.payload.is_some() {
            return Err(crate::Error::Syntax(
                "C2PA claims require detached content".into(),
            ));
        }
        self.x5chain()?;
        Ok(())
    }

    /// Check claim generation requirements, including a protected credential.
    /// Prefer integer label 33 when constructing the header.
    pub fn validate_c2pa_claim_for_signing(&self) -> Result<()> {
        self.validate_c2pa_claim()?;
        let label = if self.protected.header.get(&Label::Int(33)).is_some()
            || self.unprotected.get(&Label::Int(33)).is_some()
        {
            Label::Int(33)
        } else {
            Label::Text("x5chain".into())
        };
        if self.protected.header.get(&label).is_none() {
            return Err(crate::Error::Syntax(
                "C2PA claim generators require protected x5chain".into(),
            ));
        }
        if self
            .protected
            .header
            .get(&Label::Text("sigTst".into()))
            .is_some()
            || self
                .unprotected
                .get(&Label::Text("sigTst".into()))
                .is_some()
        {
            return Err(crate::Error::Syntax(
                "C2PA generators must not create v1 timestamps".into(),
            ));
        }
        for name in ["sigTst2", "rVals"] {
            if self
                .protected
                .header
                .get(&Label::Text(name.into()))
                .is_some()
            {
                return Err(crate::Error::Syntax(format!(
                    "C2PA {name} must be unprotected"
                )));
            }
        }
        self.timestamp_token(TimestampVersion::V2)?;
        self.ocsp_responses()?;
        Ok(())
    }

    /// Return the ordered, opaque DER certificates. Integer label 33 takes
    /// precedence over the legacy text label, across both header buckets.
    /// Duplicate labels are rejected even when their values are identical.
    pub fn x5chain(&self) -> Result<Vec<&[u8]>> {
        self.validate()?;
        let find = |label: &Label| {
            self.protected
                .header
                .get(label)
                .or_else(|| self.unprotected.get(label))
        };
        let value = find(&Label::Int(33))
            .or_else(|| find(&Label::Text("x5chain".into())))
            .ok_or_else(|| crate::Error::Syntax("missing C2PA x5chain credential".into()))?;
        byte_strings(value, true)
    }

    /// Retrieve one opaque RFC 3161 response (`sigTst`) or token (`sigTst2`).
    /// A malformed container is an accessor error, not a COSE parsing failure;
    /// callers can ignore it and report the appropriate informational status.
    pub fn timestamp_token(&self, version: TimestampVersion) -> Result<Option<&[u8]>> {
        let label = Label::Text(version.label().into());
        let Some(container) = self.unprotected.get(&label) else {
            return Ok(None);
        };
        let tokens = map_field(container, "tstTokens")?;
        let Value::Array(tokens) = tokens else {
            return Err(crate::Error::Syntax("tstTokens must be an array".into()));
        };
        if tokens.len() != 1 {
            return Err(crate::Error::Syntax(
                "C2PA requires one timestamp token".into(),
            ));
        }
        match map_field(&tokens[0], "val")? {
            Value::Bytes(bytes) => Ok(Some(bytes)),
            _ => Err(crate::Error::Syntax(
                "timestamp val must be a byte string".into(),
            )),
        }
    }

    /// Retrieve opaque stapled OCSP responses without interpreting their DER.
    pub fn ocsp_responses(&self) -> Result<Option<Vec<&[u8]>>> {
        self.unprotected
            .get(&Label::Text("rVals".into()))
            .map(|container| byte_strings(map_field(container, "ocspVals")?, false))
            .transpose()
    }

    /// Encode this signature as a complete CBOR byte string for a newly
    /// generated v2 timestamp. For received messages use
    /// [`Self::signature_bstr_from_tagged_slice`] to preserve wire encoding.
    pub fn signature_bstr(&self) -> Result<Vec<u8>> {
        crate::to_vec(&Bytes::new(&self.signature))
    }

    /// Borrow the exact encoded signature field, including its byte-string
    /// header (and any indefinite-length chunks), from a received message.
    pub fn signature_bstr_from_tagged_slice(bytes: &[u8]) -> Result<&[u8]> {
        Self::from_tagged_slice(bytes)?;
        let position = Cell::new(0);
        let reader = PositionReader {
            bytes,
            position: &position,
        };
        let mut decoder = Decoder::new(reader);
        decoder.read_tag()?;
        let (start, end) = serde::Deserializer::deserialize_tuple(
            &mut decoder,
            4,
            SignatureRangeVisitor(&position),
        )?;
        Ok(&bytes[start..end])
    }

    /// C2PA timestamp inputs, with `CounterSignature` and empty external AAD.
    /// Supply claim bytes for v1, or the complete encoded signature byte string
    /// for v2. This does not hash the result or interpret RFC 3161 content.
    pub fn c2pa_timestamp_tbs_data(&self, payload: &[u8]) -> Result<Vec<u8>> {
        self.validate_c2pa()?;
        sig_structure_data(
            SignatureContext::CounterSignature,
            &self.protected,
            &[],
            payload,
        )
    }

    /// C2PA signing inputs for an embedded payload, with empty external AAD.
    pub fn c2pa_tbs_data(&self) -> Result<Vec<u8>> {
        self.validate_c2pa()?;
        self.tbs_data(&[])
    }

    /// C2PA signing inputs for detached content, with empty external AAD.
    pub fn c2pa_detached_tbs_data(&self, payload: &[u8]) -> Result<Vec<u8>> {
        self.validate_c2pa()?;
        self.detached_tbs_data(&[], payload)
    }

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

/// The two timestamp header formats supported by C2PA 2.4 validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampVersion {
    /// Deprecated RFC 3161 TimeStampResp, with the claim as timestamp payload.
    V1,
    /// RFC 3161 TimeStampToken, with the encoded signature as timestamp payload.
    V2,
}

impl TimestampVersion {
    fn label(self) -> &'static str {
        match self {
            Self::V1 => "sigTst",
            Self::V2 => "sigTst2",
        }
    }
}

fn map_field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    let Value::Map(entries) = value else {
        return Err(crate::Error::Syntax(
            "C2PA header container must be a map".into(),
        ));
    };
    entries
        .get(&Value::Text(name.into()))
        .ok_or_else(|| crate::Error::Syntax(format!("missing {name}")))
}

fn byte_strings(value: &Value, allow_single: bool) -> Result<Vec<&[u8]>> {
    match value {
        Value::Bytes(bytes) if allow_single => Ok(vec![bytes]),
        Value::Array(values) if !values.is_empty() => values
            .iter()
            .map(|value| match value {
                Value::Bytes(bytes) => Ok(bytes.as_slice()),
                _ => Err(crate::Error::Syntax("expected a byte string".into())),
            })
            .collect(),
        _ => Err(crate::Error::Syntax(
            "expected a nonempty byte-string array".into(),
        )),
    }
}

struct PositionReader<'a> {
    bytes: &'a [u8],
    position: &'a Cell<usize>,
}

impl Read for PositionReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.bytes.read(buffer)?;
        self.position.set(self.position.get() + count);
        Ok(count)
    }
}

struct SignatureRangeVisitor<'a>(&'a Cell<usize>);

impl<'de> Visitor<'de> for SignatureRangeVisitor<'_> {
    type Value = (usize, usize);

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a four-element COSE_Sign1 array")
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        for index in 0..3 {
            sequence
                .next_element::<de::IgnoredAny>()?
                .ok_or_else(|| de::Error::invalid_length(index, &self))?;
        }
        let start = self.0.get();
        sequence
            .next_element::<de::IgnoredAny>()?
            .ok_or_else(|| de::Error::invalid_length(3, &self))?;
        let end = self.0.get();
        Ok((start, end))
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

    fn container(name: &str, value: Value) -> Value {
        Value::Map([(Value::Text(name.into()), value)].into_iter().collect())
    }

    fn claim_signature() -> CoseSign1 {
        CoseSign1Builder::new().protected(sample_header()).build()
    }

    #[test]
    fn c2pa_x5chain_label_precedence_and_legacy_placement() {
        let mut sign1 = claim_signature();
        assert_eq!(sign1.x5chain().unwrap(), vec![&[1, 2, 3][..]]);
        assert!(sign1.validate_c2pa_claim_for_signing().is_ok());
        sign1
            .unprotected
            .rest
            .push((Label::Text("x5chain".into()), Value::Bool(false)));
        assert_eq!(sign1.x5chain().unwrap(), vec![&[1, 2, 3][..]]);
        sign1
            .unprotected
            .rest
            .push((Label::Int(33), Value::Bytes(vec![1, 2, 3])));
        assert!(sign1.x5chain().is_err());
        sign1.unprotected.rest.clear();
        sign1.protected.header.rest.clear();
        assert!(sign1.validate_c2pa_claim().is_err());
        sign1.unprotected.rest.push((
            Label::Text("x5chain".into()),
            Value::Array(vec![Value::Bytes(vec![4]), Value::Bytes(vec![5])]),
        ));
        assert_eq!(sign1.x5chain().unwrap(), vec![&[4][..], &[5][..]]);
        assert!(sign1.validate_c2pa_claim().is_ok());
        assert!(sign1.validate_c2pa_claim_for_signing().is_err());
        sign1
            .protected
            .header
            .rest
            .push((Label::Int(33), Value::Bytes(vec![6])));
        assert_eq!(sign1.x5chain().unwrap(), vec![&[6][..]]);
        assert!(sign1.validate_c2pa_claim_for_signing().is_ok());
        sign1.protected.header.rest[0].1 = Value::Array(vec![]);
        assert!(sign1.x5chain().is_err());
        sign1.protected.header.rest[0].1 = Value::Array(vec![Value::Text("not DER bytes".into())]);
        assert!(sign1.x5chain().is_err());
        sign1.protected.header.rest[0] = (Label::Text("x5chain".into()), Value::Bytes(vec![1]));
        assert!(sign1.x5chain().is_err());
        sign1.unprotected.rest[0] = (Label::Int(33), Value::Bytes(vec![7]));
        assert_eq!(sign1.x5chain().unwrap(), vec![&[7][..]]);
        assert!(sign1.validate_c2pa_claim_for_signing().is_err());
    }

    #[test]
    fn c2pa_timestamp_and_ocsp_containers_are_opaque_and_recoverable() {
        let mut sign1 = claim_signature();
        assert_eq!(sign1.timestamp_token(TimestampVersion::V1).unwrap(), None);
        assert_eq!(sign1.timestamp_token(TimestampVersion::V2).unwrap(), None);
        assert_eq!(sign1.ocsp_responses().unwrap(), None);
        let token = container("val", Value::Bytes(vec![0x30, 1]));
        let timestamp = container("tstTokens", Value::Array(vec![token.clone()]));
        sign1.unprotected = HeaderBuilder::new()
            .text_value("sigTst2".into(), timestamp.clone())
            .text_value(
                "rVals".into(),
                container(
                    "ocspVals",
                    Value::Array(vec![Value::Bytes(vec![1]), Value::Bytes(vec![2])]),
                ),
            )
            .build();
        assert_eq!(
            sign1.timestamp_token(TimestampVersion::V2).unwrap(),
            Some(&[0x30, 1][..])
        );
        assert_eq!(
            sign1.ocsp_responses().unwrap(),
            Some(vec![&[1][..], &[2][..]])
        );
        assert!(sign1.validate_c2pa_claim_for_signing().is_ok());
        let wire = sign1.to_tagged_vec().unwrap();
        assert_eq!(
            CoseSign1::from_tagged_slice(&wire).unwrap(),
            sign1_with_original(sign1.clone())
        );
        sign1
            .unprotected
            .rest
            .push((Label::Text("sigTst".into()), timestamp));
        assert_eq!(
            sign1.timestamp_token(TimestampVersion::V1).unwrap(),
            Some(&[0x30, 1][..])
        );
        assert!(sign1.validate_c2pa_claim_for_signing().is_err());
        sign1.unprotected.rest.pop();
        for tokens in [
            vec![],
            vec![token.clone(), token],
            vec![container("val", Value::Text("bad".into()))],
        ] {
            sign1.unprotected.rest[0].1 = container("tstTokens", Value::Array(tokens));
            assert!(sign1.timestamp_token(TimestampVersion::V2).is_err());
            assert!(CoseSign1::from_tagged_slice(&sign1.to_tagged_vec().unwrap()).is_ok());
        }
        sign1.unprotected.rest[1].1 = container("ocspVals", Value::Array(vec![]));
        assert!(sign1.ocsp_responses().is_err());
    }

    fn sign1_with_original(mut sign1: CoseSign1) -> CoseSign1 {
        sign1.protected.original_data = Some(sign1.protected.encoded_bytes().unwrap());
        sign1
    }

    #[test]
    fn c2pa_timestamp_payload_preserves_encoded_signature_field() {
        for signature in [
            vec![0x41, 0xaa],
            vec![0x58, 1, 0xaa],
            vec![0x5f, 0x41, 0xaa, 0xff],
        ] {
            for array in [0x84, 0x9f] {
                let mut wire = vec![0xd2, array, 0x43, 0xa1, 1, 0x26, 0xa0, 0xf6];
                wire.extend_from_slice(&signature);
                if array == 0x9f {
                    wire.push(0xff);
                }
                let encoded = CoseSign1::signature_bstr_from_tagged_slice(&wire).unwrap();
                assert_eq!(encoded, signature);
                let sign1 = CoseSign1::from_tagged_slice(&wire).unwrap();
                assert_eq!(sign1.signature_bstr().unwrap(), vec![0x41, 0xaa]);
                let tbs = sign1.c2pa_timestamp_tbs_data(encoded).unwrap();
                let decoded: Value = crate::from_slice(&tbs).unwrap();
                assert_eq!(
                    decoded,
                    Value::Array(vec![
                        Value::Text("CounterSignature".into()),
                        Value::Bytes(vec![0xa1, 1, 0x26]),
                        Value::Bytes(vec![]),
                        Value::Bytes(signature.clone()),
                    ])
                );
                wire.push(0);
                assert!(CoseSign1::signature_bstr_from_tagged_slice(&wire).is_err());
            }
        }
        let mut sign1 = claim_signature();
        sign1.signature = vec![0xaa; 256];
        assert_eq!(&sign1.signature_bstr().unwrap()[..3], &[0x59, 1, 0]);
        let tbs = sign1.c2pa_timestamp_tbs_data(b"v1 claim").unwrap();
        let decoded: Value = crate::from_slice(&tbs).unwrap();
        assert!(
            matches!(decoded, Value::Array(fields) if fields[3] == Value::Bytes(b"v1 claim".to_vec()))
        );
    }

    #[test]
    fn c2pa_live_video_and_claimed_signing_time_access() {
        let mut sign1 = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(-7)
                    .text_value("iat".into(), Value::Float(123.5))
                    .build(),
            )
            .unprotected(
                HeaderBuilder::new()
                    .value(4, Value::Bytes(b"session".to_vec()))
                    .build(),
            )
            .payload(b"serialized segment-info-map".to_vec())
            .build();
        assert!(sign1.c2pa_tbs_data().is_ok());
        assert!(sign1.validate_c2pa_claim().is_err());
        assert_eq!(
            sign1.unprotected.get(&Label::Int(4)),
            Some(&Value::Bytes(b"session".to_vec()))
        );
        for iat in [Value::Integer(-1), Value::Float(123.5)] {
            sign1.protected.header.rest[0].1 = iat;
            assert!(sign1.validate_c2pa().is_ok());
        }
        for iat in [
            Value::Tag(1, Box::new(Value::Integer(123))),
            Value::Text("123".into()),
            Value::Float(f64::INFINITY),
        ] {
            sign1.protected.header.rest[0].1 = iat;
            assert!(sign1.validate_c2pa().is_err());
        }
        sign1.protected.header.rest.clear();
        sign1
            .unprotected
            .rest
            .push((Label::Text("iat".into()), Value::Integer(123)));
        assert!(sign1.validate_c2pa().is_err());
    }

    #[test]
    fn c2pa_signing_inputs_require_protected_alg_and_empty_aad() {
        let mut sign1 = CoseSign1::default();
        assert!(sign1.c2pa_detached_tbs_data(b"claim").is_err());
        sign1.protected = ProtectedHeader::new(HeaderBuilder::new().algorithm(-7).build());
        let data = sign1.c2pa_detached_tbs_data(b"claim").unwrap();
        let decoded: Value = crate::from_slice(&data).unwrap();
        assert_eq!(
            decoded,
            Value::Array(vec![
                Value::Text("Signature1".into()),
                Value::Bytes(sign1.protected.encoded_bytes().unwrap()),
                Value::Bytes(vec![]),
                Value::Bytes(b"claim".to_vec()),
            ])
        );
        sign1.payload = Some(vec![]);
        assert!(sign1.c2pa_detached_tbs_data(b"claim").is_err());
        assert!(sign1.c2pa_tbs_data().is_ok());
        sign1
            .unprotected
            .rest
            .push((Label::Text("alg".into()), Value::Integer(-7)));
        assert!(sign1.validate_c2pa().is_err());
    }

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
