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

//! Differential tests proving `c2pa_cbor::cose` produces byte-for-byte
//! identical `COSE_Sign1` output to `coset` for the header shapes c2pa-rs
//! actually uses. `coset` is a temporary, `[dev-dependencies]`-only crate here
//! (see Cargo.toml) purely for this comparison; it's not a runtime dependency
//! of `c2pa_cbor` and is expected to be dropped once this file has done its
//! job.
#![cfg(feature = "cose")]

use c2pa_cbor::cose::{
    self as c2pa_cose, ContentType as C2paContentType, HeaderBuilder as C2paHeaderBuilder,
};
use coset::{
    CoseSign1Builder as CosetCoseSign1Builder, HeaderBuilder as CosetHeaderBuilder,
    Label as CosetLabel, TaggedCborSerializable,
    iana::{self, EnumI64},
};

const AAD: &[u8] = b"";
const PAYLOAD: &[u8] = b"hello, c2pa";
const SIGNATURE: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];

/// Build a `coset::CoseSign1` and the equivalent `c2pa_cbor::cose::CoseSign1`
/// from the same protected/unprotected header-builder closures, and assert
/// their tagged encodings and `Sig_structure` bytes match exactly.
fn assert_matches(
    build_coset_protected: impl FnOnce(CosetHeaderBuilder) -> CosetHeaderBuilder,
    build_c2pa_protected: impl FnOnce(C2paHeaderBuilder) -> C2paHeaderBuilder,
    build_coset_unprotected: impl FnOnce(CosetHeaderBuilder) -> CosetHeaderBuilder,
    build_c2pa_unprotected: impl FnOnce(C2paHeaderBuilder) -> C2paHeaderBuilder,
) {
    let coset_protected = build_coset_protected(CosetHeaderBuilder::new()).build();
    let coset_unprotected = build_coset_unprotected(CosetHeaderBuilder::new()).build();
    let mut coset_sign1 = CosetCoseSign1Builder::new()
        .protected(coset_protected)
        .unprotected(coset_unprotected)
        .payload(PAYLOAD.to_vec())
        .build();
    coset_sign1.signature = SIGNATURE.to_vec();

    let c2pa_protected = build_c2pa_protected(C2paHeaderBuilder::new()).build();
    let c2pa_unprotected = build_c2pa_unprotected(C2paHeaderBuilder::new()).build();
    let c2pa_sign1 = c2pa_cose::CoseSign1Builder::new()
        .protected(c2pa_protected)
        .unprotected(c2pa_unprotected)
        .payload(PAYLOAD.to_vec())
        .build();
    let mut c2pa_sign1 = c2pa_sign1;
    c2pa_sign1.signature = SIGNATURE.to_vec();

    // Sig_structure ("to be signed") bytes must match exactly: this is the
    // security-critical piece that both implementations must agree on so a
    // signature produced against one is verifiable against the other.
    let coset_tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        coset_sign1.protected.clone(),
        None,
        AAD,
        PAYLOAD,
    );
    let c2pa_tbs = c2pa_sign1.tbs_data(AAD).unwrap();
    assert_eq!(coset_tbs, c2pa_tbs, "Sig_structure bytes differ");

    // The final tagged (tag 18) COSE_Sign1 wire bytes must also match, so a
    // manifest produced by one implementation decodes identically in the
    // other.
    let coset_bytes = coset_sign1.clone().to_tagged_vec().unwrap();
    let c2pa_bytes = c2pa_sign1.to_tagged_vec().unwrap();
    assert_eq!(coset_bytes, c2pa_bytes, "tagged CoseSign1 bytes differ");

    // And round-tripping c2pa_cbor's own bytes back through coset (and vice
    // versa) must succeed and agree on the to-be-signed bytes, proving actual
    // cross-implementation interop rather than just coincidentally identical
    // byte layout.
    let coset_from_c2pa_bytes = coset::CoseSign1::from_tagged_slice(&c2pa_bytes).unwrap();
    assert_eq!(
        coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            coset_from_c2pa_bytes.protected.clone(),
            None,
            AAD,
            PAYLOAD,
        ),
        coset_tbs
    );

    let c2pa_from_coset_bytes = c2pa_cose::CoseSign1::from_tagged_slice(&coset_bytes).unwrap();
    assert_eq!(c2pa_from_coset_bytes.tbs_data(AAD).unwrap(), c2pa_tbs);
}

#[test]
fn single_cert_x5chain_es256() {
    let cert = vec![0xde, 0xad, 0xbe, 0xef];
    let x5chain_label = iana::HeaderParameter::X5Chain.to_i64();
    let cert_for_coset = cert.clone();
    let cert_for_c2pa = cert.clone();

    assert_matches(
        move |b| {
            b.algorithm(iana::Algorithm::ES256).value(
                x5chain_label,
                coset::cbor::value::Value::Bytes(cert_for_coset),
            )
        },
        move |b| {
            b.algorithm(iana::Algorithm::ES256.to_i64())
                .value(x5chain_label, c2pa_cbor::Value::Bytes(cert_for_c2pa))
        },
        |b| b,
        |b| b,
    );
}

#[test]
fn array_x5chain_es384() {
    let cert1 = vec![0x01, 0x02];
    let cert2 = vec![0x03, 0x04];
    let x5chain_label = iana::HeaderParameter::X5Chain.to_i64();

    let (c1, c2) = (cert1.clone(), cert2.clone());
    let (c1b, c2b) = (cert1, cert2);

    assert_matches(
        move |b| {
            b.algorithm(iana::Algorithm::ES384).value(
                x5chain_label,
                coset::cbor::value::Value::Array(vec![
                    coset::cbor::value::Value::Bytes(c1),
                    coset::cbor::value::Value::Bytes(c2),
                ]),
            )
        },
        move |b| {
            b.algorithm(iana::Algorithm::ES384.to_i64()).value(
                x5chain_label,
                c2pa_cbor::Value::Array(vec![
                    c2pa_cbor::Value::Bytes(c1b),
                    c2pa_cbor::Value::Bytes(c2b),
                ]),
            )
        },
        |b| b,
        |b| b,
    );
}

#[test]
fn content_type_text() {
    assert_matches(
        |b| {
            b.algorithm(iana::Algorithm::EdDSA)
                .content_type("application/vc".to_string())
        },
        |b| {
            b.algorithm(iana::Algorithm::EdDSA.to_i64())
                .content_type("application/vc".to_string())
        },
        |b| b,
        |b| b,
    );
}

#[test]
fn content_type_assigned() {
    let format = iana::CoapContentFormat::Cbor;
    assert_matches(
        move |b| b.algorithm(iana::Algorithm::PS256).content_format(format),
        move |b| {
            b.algorithm(iana::Algorithm::PS256.to_i64())
                .content_format(format.to_i64())
        },
        |b| b,
        |b| b,
    );
}

#[test]
fn sigtst2_and_rvals_in_unprotected_header() {
    // Mirrors sigtst.rs/ocsp.rs: a nested map value under a text label.
    let sigtst2_bytes = vec![0xaa, 0xbb, 0xcc];
    let ocsp_der = vec![0x11, 0x22, 0x33];

    let (s1, s2) = (sigtst2_bytes.clone(), sigtst2_bytes);
    let (o1, o2) = (ocsp_der.clone(), ocsp_der);

    assert_matches(
        |b| b.algorithm(iana::Algorithm::ES256),
        |b| b.algorithm(iana::Algorithm::ES256.to_i64()),
        move |b| {
            b.text_value("sigTst2".to_string(), coset::cbor::value::Value::Bytes(s1))
                .text_value(
                    "rVals".to_string(),
                    coset::cbor::value::Value::Map(vec![(
                        coset::cbor::value::Value::Text("ocspVals".to_string()),
                        coset::cbor::value::Value::Array(vec![coset::cbor::value::Value::Bytes(
                            o1,
                        )]),
                    )]),
                )
        },
        move |b| {
            b.text_value("sigTst2".to_string(), c2pa_cbor::Value::Bytes(s2))
                .text_value(
                    "rVals".to_string(),
                    c2pa_cbor::Value::Map(std::collections::BTreeMap::from([(
                        c2pa_cbor::Value::Text("ocspVals".to_string()),
                        c2pa_cbor::Value::Array(vec![c2pa_cbor::Value::Bytes(o2)]),
                    )])),
                )
        },
    );
}

#[test]
fn pad_then_pad2_padding_entries_preserve_order() {
    // Mirrors the box-size padding trick in c2pa-rs's sign.rs: a "pad" entry
    // followed by a "pad2" entry, added in that order.
    assert_matches(
        |b| b.algorithm(iana::Algorithm::ES256),
        |b| b.algorithm(iana::Algorithm::ES256.to_i64()),
        |b| {
            b.text_value(
                "pad".to_string(),
                coset::cbor::value::Value::Bytes(vec![0u8; 5]),
            )
            .text_value(
                "pad2".to_string(),
                coset::cbor::value::Value::Bytes(vec![0u8; 2]),
            )
        },
        |b| {
            b.text_value("pad".to_string(), c2pa_cbor::Value::Bytes(vec![0u8; 5]))
                .text_value("pad2".to_string(), c2pa_cbor::Value::Bytes(vec![0u8; 2]))
        },
    );
}

/// A protected header parsed from the wire (not freshly built) must reuse its
/// exact original bytes for `Sig_structure`, even if `c2pa_cbor::cose::Header`
/// would re-encode it differently (e.g. a foreign encoder's byte ordering).
/// This is `ProtectedHeader::original_data` earning its keep.
#[test]
fn preserves_original_protected_header_bytes_on_decode() {
    let cert = vec![0xca, 0xfe];
    let x5chain_label = iana::HeaderParameter::X5Chain.to_i64();

    let coset_protected = CosetHeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .value(x5chain_label, coset::cbor::value::Value::Bytes(cert))
        .build();
    let mut coset_sign1 = CosetCoseSign1Builder::new()
        .protected(coset_protected)
        .payload(PAYLOAD.to_vec())
        .build();
    coset_sign1.signature = SIGNATURE.to_vec();

    let coset_tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        coset_sign1.protected.clone(),
        None,
        AAD,
        PAYLOAD,
    );
    let coset_bytes = coset_sign1.to_tagged_vec().unwrap();

    let decoded = c2pa_cose::CoseSign1::from_tagged_slice(&coset_bytes).unwrap();
    assert!(decoded.protected.original_data.is_some());
    assert_eq!(decoded.tbs_data(AAD).unwrap(), coset_tbs);
}

#[test]
fn label_type_matches_coset_label_shape() {
    // Sanity check that our Label enum's Int/Text split lines up with
    // coset::Label's, since c2pa-rs's call sites match on this shape directly
    // (e.g. cert_chain_from_sign1 scanning `protected.header.rest`).
    let int_label = CosetLabel::Int(42);
    let text_label = CosetLabel::Text("custom".to_string());
    match int_label {
        CosetLabel::Int(i) => assert_eq!(i, 42),
        CosetLabel::Text(_) => panic!("unexpected"),
    }
    match text_label {
        CosetLabel::Text(t) => assert_eq!(t, "custom"),
        CosetLabel::Int(_) => panic!("unexpected"),
    }

    let c2pa_int = c2pa_cose::Label::Int(42);
    let c2pa_text = c2pa_cose::Label::Text("custom".to_string());
    assert_eq!(c2pa_int, c2pa_cose::Label::Int(42));
    assert_eq!(c2pa_text, c2pa_cose::Label::Text("custom".to_string()));
    let _: C2paContentType = C2paContentType::Text("x/y".to_string());
}
