use rand::rngs::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use lox_zkp::toolbox::sigma::schnorr_proof::SchnorrProof;
use lox_zkp::toolbox::sigma::transcript::transcriptcodec::KeccakTranscript;
use lox_zkp::toolbox::sigma::fiat_shamir::NISigmaProtocol;

type G = RistrettoPoint;

#[allow(non_snake_case)]
#[test]
fn fiat_shamir_schnorr_proof_ristretto() {
    // Setup
    let mut rng = OsRng;
    let domain_sep = b"test-fiat-shamir-schnorr";

    // Create a Schnorr statement: H = G * w
    let G = RistrettoPoint::random(&mut rng);
    let w = Scalar::random(&mut rng);
    let H = G * w;

    let protocol = SchnorrProof { generator: G, target: H };

    // Fiat-Shamir wrapper
    let mut nizk = NISigmaProtocol::<_, KeccakTranscript<G>, G>::new(domain_sep, protocol);

    // Prove
    let proof_bytes = nizk.prove(&w, &mut rng);

    // Verify
    let verified = nizk.verify(&proof_bytes);

    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
}