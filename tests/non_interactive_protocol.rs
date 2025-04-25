use group::Group;
use rand::rngs::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use lox_zkp::toolbox::sigma::group_mophism::GroupMorphismPreimage;
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

    let morphismp: GroupMorphismPreimage<RistrettoPoint> = GroupMorphismPreimage::new();

    // Scalars and Points bases settings
    morphismp.allocate_scalars(1);
    morphismp.allocate_elements(1);
    morphismp.set_elements(&[(0, G)]);

    // The H = z * G equeation where z is the unique scalar variable
    morphismp.append_equation(H, &[(0, 0)]);

    // The SigmaProtocol induced by morphismp
    let protocol = SchnorrProof { morphismp };

    // Fiat-Shamir wrapper
    let mut nizk = NISigmaProtocol::<_, KeccakTranscript<G>, G>::new(domain_sep, protocol);

    // Prove
    let proof_bytes = nizk.prove(&w, &mut rng);

    // Verify
    let verified = nizk.verify(&proof_bytes);

    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
}