use curve25519_dalek::ristretto::RistrettoPoint;
use group::GroupEncoding;
use rand::rngs::OsRng;

use sigma_rs::codec::{r#trait::Codec, shake_codec::ShakeCodec};

pub type ShakeCodecRistretto = ShakeCodec<curve25519_dalek::ristretto::RistrettoPoint>;

#[allow(non_snake_case)]
#[test]
fn shake_codec_ristretto() {
    // Type alias to mirror the Sage naming
    type Codec = ShakeCodecRistretto;

    // Generate some commitments
    let G = RistrettoPoint::random(&mut OsRng);
    let H = RistrettoPoint::random(&mut OsRng);

    let domain_sep = b"test-shake-ristretto";

    // Initialize codec
    let mut binding = Codec::new(domain_sep);
    let mut data = Vec::new();
    for commit in &[G, H] {
        data.extend_from_slice(commit.to_bytes().as_ref());
    }
    let codec = binding.prover_message(&data);

    // Derive challenge
    let challenge = codec.verifier_challenge();

    // Output result
    println!("Challenge: {:?}", challenge);
}
