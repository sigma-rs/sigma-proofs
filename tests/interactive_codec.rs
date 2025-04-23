use rand::rngs::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;

use lox_zkp::toolbox::sigma::transcript::{r#trait::TranscriptCodec, transcriptcodec::KeccakTranscript};

pub type KeccakTranscriptRistretto = KeccakTranscript<curve25519_dalek::ristretto::RistrettoPoint>;

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
    let mut transcript = Transcript::new(domain_sep)
        .prover_message(&[G, H]);

    // Derive challenge
    let challenge = transcript.verifier_challenge();

    // Output result
    println!("Challenge: {:?}", challenge);
}
