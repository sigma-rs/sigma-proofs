//! RFC 9380 Appendix J.8.1 test vectors for `secp256k1_XMD:SHA-256_SSWU_RO_`.

use hash2group::{rfc9380::ExpandMsgXmd, FromHash};
use hex_literal::hex;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint};
use sha2::Sha256;

const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

fn check(msg: &[u8], expected_x: [u8; 32], expected_y: [u8; 32]) {
    let p: ProjectivePoint = FromHash::<ExpandMsgXmd<Sha256>>::from_hash(DST, msg);
    let affine: AffinePoint = p.into();
    let encoded = affine.to_encoded_point(false);
    let x: &[u8] = encoded.x().expect("identity point").as_ref();
    let y: &[u8] = encoded.y().expect("identity or compressed").as_ref();
    assert_eq!(x, expected_x, "x mismatch");
    assert_eq!(y, expected_y, "y mismatch");
}

#[test]
fn empty() {
    check(
        b"",
        hex!("c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346"),
        hex!("64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067"),
    );
}

#[test]
fn abc() {
    check(
        b"abc",
        hex!("3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b"),
        hex!("7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"),
    );
}

#[test]
fn abcdef0123456789() {
    check(
        b"abcdef0123456789",
        hex!("bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a"),
        hex!("4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828"),
    );
}

#[test]
fn q128() {
    check(
        b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        hex!("e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9"),
        hex!("f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873"),
    );
}

#[test]
fn a512() {
    check(
        b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        hex!("e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998"),
        hex!("8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6"),
    );
}
