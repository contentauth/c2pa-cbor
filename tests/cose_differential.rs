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
//! of `c2pa_cbor`. Keep these fixtures as ongoing interoperability regressions.
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

#[test]
fn empty_headers_and_c2pa_countersignature_match_coset() {
    assert_matches(
        |header| header,
        |header| header,
        |header| header,
        |header| header,
    );
    for algorithm in [None, Some(-7)] {
        let header = c2pa_cose::Header {
            alg: algorithm,
            ..Default::default()
        };
        let protected = c2pa_cose::ProtectedHeader::new(header);
        let mut coset_header = coset::Header::default();
        if algorithm.is_some() {
            coset_header = CosetHeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build();
        }
        let expected = coset::sig_structure_data(
            coset::SignatureContext::CounterSignature,
            coset::ProtectedHeader {
                header: coset_header,
                original_data: None,
            },
            None,
            b"external aad",
            PAYLOAD,
        );
        let actual = c2pa_cose::sig_structure_data(
            c2pa_cose::SignatureContext::CounterSignature,
            &protected,
            b"external aad",
            PAYLOAD,
        )
        .unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn malformed_wire_types_and_lengths_are_rejected() {
    let cases: &[&[u8]] = &[
        &[0xd2, 0x84, 0x81, 0x00, 0xa0, 0xf6, 0x40],
        &[0xd2, 0x84, 0x40, 0xa0, 0x60, 0x40],
        &[0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x60],
        &[0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x80],
        &[0xd2, 0x84, 0x40, 0xa0, 0xc0, 0x40, 0x40],
        &[0xd2, 0xc0, 0x84, 0x40, 0xa0, 0xf6, 0x40],
        &[0xd2, 0x84, 0x42, 0xc0, 0xa0, 0xa0, 0xf6, 0x40],
        &[0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40, 0x00],
        &[0xd2, 0x85, 0x40, 0xa0, 0xf6, 0x40, 0x00],
        &[0xd2, 0x83, 0x40, 0xa0, 0xf6],
        &[0xd2, 0x84, 0x40, 0xc0, 0xa0, 0xf6, 0x40],
        &[0xd2, 0x84, 0x40, 0xa1, 0xc0, 0x01, 0x26, 0xf6, 0x40],
    ];
    for bytes in cases {
        assert!(
            c2pa_cose::CoseSign1::from_tagged_slice(bytes).is_err(),
            "{bytes:02x?}"
        );
        assert!(
            coset::CoseSign1::from_tagged_slice(bytes).is_err(),
            "{bytes:02x?}"
        );
    }
}

#[test]
fn nonpreferred_protected_bytes_are_preserved_and_mutation_is_rejected() {
    let bytes = [
        0xd2, 0x84, 0x45, 0xa1, 0x18, 0x01, 0x38, 0x06, 0xa0, 0x41, 0x61, 0x40,
    ];
    let mut actual = c2pa_cose::CoseSign1::from_tagged_slice(&bytes).unwrap();
    let expected = coset::CoseSign1::from_tagged_slice(&bytes).unwrap();
    assert_eq!(actual.to_tagged_vec().unwrap(), bytes);
    assert_eq!(actual.tbs_data(b"aad").unwrap(), expected.tbs_data(b"aad"));
    actual.protected.header.alg = Some(-35);
    assert!(actual.to_tagged_vec().is_err());
    assert!(actual.tbs_data(b"aad").is_err());
}

#[test]
fn detached_payload_is_explicit_and_matches_coset() {
    let actual = c2pa_cose::CoseSign1::default();
    let expected = coset::CoseSign1::default();
    assert!(actual.tbs_data(b"aad").is_err());
    assert_eq!(
        actual.detached_tbs_data(b"aad", PAYLOAD).unwrap(),
        expected.tbs_detached_data(PAYLOAD, b"aad")
    );
    let attached = c2pa_cose::CoseSign1Builder::new()
        .payload(Vec::new())
        .build();
    assert!(attached.detached_tbs_data(b"aad", PAYLOAD).is_err());
    assert!(attached.tbs_data(b"aad").is_ok());
}

#[test]
fn duplicate_headers_and_unsupported_critical_headers_are_rejected() {
    for bytes in [
        vec![0xa2, 0x01, 0x26, 0x01, 0x38, 0x22],
        vec![0xa2, 0x03, 0x00, 0x03, 0x01],
        vec![0xa2, 0x61, b'x', 0x00, 0x61, b'x', 0x01],
        vec![0xa1, 0x03, 0x20],
        vec![0xa1, 0x03, 0x1a, 0x00, 0x01, 0x00, 0x00],
    ] {
        assert!(c2pa_cbor::from_slice::<c2pa_cose::Header>(&bytes).is_err());
    }
    for label in [1, 3, 33] {
        let header = C2paHeaderBuilder::new()
            .value(label, c2pa_cbor::Value::Integer(0))
            .value(label, c2pa_cbor::Value::Integer(1))
            .build();
        assert!(c2pa_cbor::to_vec(&header).is_err());
    }
    let header = C2paHeaderBuilder::new().algorithm(-7).build();
    let actual = c2pa_cose::CoseSign1Builder::new()
        .protected(header.clone())
        .unprotected(header)
        .payload(Vec::new())
        .build();
    assert!(actual.to_tagged_vec().is_err());
    assert!(actual.tbs_data(b"").is_err());
    let conflicting = [
        0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa1, 0x01, 0x26, 0xf6, 0x40,
    ];
    assert!(c2pa_cose::CoseSign1::from_tagged_slice(&conflicting).is_err());
    let critical = [0xd2, 0x84, 0x44, 0xa1, 0x02, 0x81, 0x01, 0xa0, 0xf6, 0x40];
    assert!(c2pa_cose::CoseSign1::from_tagged_slice(&critical).is_err());
}

#[test]
fn cose_limits_truncation_and_tagged_extensions() {
    assert!(
        c2pa_cose::CoseSign1::from_tagged_slice(&[0xd2, 0x84, 0x40, 0xa0, 0xf7, 0x40]).is_err()
    );
    let valid = [0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40];
    for end in 0..valid.len() {
        assert!(c2pa_cose::CoseSign1::from_tagged_slice(&valid[..end]).is_err());
    }
    assert!(c2pa_cose::CoseSign1::from_tagged_slice_with_limit(&valid, valid.len()).is_ok());
    assert!(c2pa_cose::CoseSign1::from_tagged_slice_with_limit(&valid, valid.len() - 1).is_err());
    let huge = [0xd2, 0x84, 0x5a, 0xff, 0xff, 0xff, 0xff];
    assert!(
        c2pa_cose::CoseSign1::from_tagged_slice_with_limit(&huge, 1024)
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum")
    );
    let header = C2paHeaderBuilder::new()
        .text_value(
            "extension".into(),
            c2pa_cbor::Value::Tag(100, Box::new(c2pa_cbor::Value::Integer(1))),
        )
        .build();
    let actual = c2pa_cose::CoseSign1Builder::new()
        .unprotected(header.clone())
        .build();
    assert_eq!(
        c2pa_cose::CoseSign1::from_tagged_slice(&actual.to_tagged_vec().unwrap())
            .unwrap()
            .unprotected,
        header
    );
    let mut nested = vec![0x81; 150];
    nested.push(0x00);
    let mut protected = vec![0xa1, 0x61, b'x'];
    protected.extend_from_slice(&nested);
    let wire = (
        serde_bytes::ByteBuf::from(protected),
        c2pa_cose::Header::default(),
        Option::<serde_bytes::ByteBuf>::None,
        serde_bytes::ByteBuf::new(),
    );
    let bytes = c2pa_cbor::to_vec(&c2pa_cbor::Tagged::new(Some(18), wire)).unwrap();
    assert!(
        c2pa_cose::CoseSign1::from_tagged_slice(&bytes)
            .unwrap_err()
            .to_string()
            .contains("nesting depth")
    );
}

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
