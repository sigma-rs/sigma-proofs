use rand::rngs::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;

use sigma_rs::toolbox::sigma::transcript::{r#trait::TranscriptCodec, shake_transcript::ShakeTranscript};

pub type KeccakTranscriptRistretto = ShakeTranscript<curve25519_dalek::ristretto::RistrettoPoint>;

#[allow(non_snake_case)]
#[test]
fn keccak_transcript_ristretto() {
    // Type alias to mirror the Sage naming
    type Transcript = KeccakTranscriptRistretto;

    // Generate some commitments
    let G = RistrettoPoint::random(&mut OsRng);
    let H = RistrettoPoint::random(&mut OsRng);

    let domain_sep = b"test-keccak-ristretto";

    // Initialize transcript
    let mut binding = Transcript::new(domain_sep);
    let transcript = binding
        .prover_message(&[G, H]);

    // Derive challenge
    let challenge = transcript.verifier_challenge();

    // Output result
    println!("Challenge: {:?}", challenge);
}
