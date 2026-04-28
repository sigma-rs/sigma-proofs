//! RFC 9380 Appendix J.1.1 test vectors for `P256_XMD:SHA-256_SSWU_RO_`.

use hash2group::{rfc9380::ExpandMsgXmd, FromHash};
use hex_literal::hex;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{AffinePoint, ProjectivePoint};
use sha2::Sha256;

const DST: &[u8] = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

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
        hex!("2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4"),
        hex!("8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"),
    );
}

#[test]
fn abc() {
    check(
        b"abc",
        hex!("0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f"),
        hex!("5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"),
    );
}

#[test]
fn abcdef0123456789() {
    check(
        b"abcdef0123456789",
        hex!("65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80"),
        hex!("cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"),
    );
}

#[test]
fn q128() {
    check(
        b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        hex!("4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d"),
        hex!("98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e"),
    );
}

#[test]
fn a512() {
    check(
        b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        hex!("457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5"),
        hex!("ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc"),
    );
}
