use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

use sigma_rs::{
    NISigmaProtocol,
    GroupMorphismPreimage,
    PointVar,
    ScalarVar,
    SchnorrProof,
    codec::ShakeCodec
};

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

    let mut morphismp: GroupMorphismPreimage<RistrettoPoint> = GroupMorphismPreimage::new();

    // Scalars and Points bases settings
    morphismp.allocate_scalars(1);
    morphismp.allocate_elements(2);
    morphismp.set_elements(&[(PointVar(0), G), (PointVar(1), H)]);

    // Set the witness Vec
    let mut witness = Vec::new();
    witness.push(w);

    // The H = z * G equation where z is the unique scalar variable
    morphismp.append_equation(PointVar(1), &[(ScalarVar(0), PointVar(0))]);

    // The SigmaProtocol induced by morphismp
    let protocol = SchnorrProof(morphismp);

    // Fiat-Shamir wrapper
    let mut nizk =
        NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>, G>::new(domain_sep, protocol);

    // Prove
    let proof_bytes = nizk.prove(&witness, &mut rng);

    // Verify
    let verified = nizk.verify(&proof_bytes).is_ok();

    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
}
