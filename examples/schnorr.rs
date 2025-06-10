//! Example: Schnorr protocol using the sigma-rs framework with the Ristretto group.
//!
//! Proves knowledge of `x` such that `P = x * G`, using the high-level LinearRelation API.

use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use group::{Group, GroupEncoding};
use rand::rngs::OsRng;

use sigma_rs::codec::ShakeCodec;
use sigma_rs::fiat_shamir::NISigmaProtocol;
use sigma_rs::linear_relation::LinearRelation;
use sigma_rs::schnorr_protocol::SchnorrProtocol;

// We should probably have global access to these useful morphism constructing primitives instead of putting them behind tests?
#[allow(non_snake_case)]
pub fn discrete_logarithm<G: Group + GroupEncoding>(
    x: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp: LinearRelation<G> = LinearRelation::new();

    let var_x = morphismp.allocate_scalar();
    let var_G = morphismp.allocate_element();

    let var_X = morphismp.allocate_eq(var_x * var_G);

    morphismp.assign_element(var_G, G::generator());
    morphismp.compute_image(&[x]).unwrap();

    let X = morphismp.morphism.group_elements.get(var_X).unwrap();

    assert_eq!(X, G::generator() * x);
    (morphismp, vec![x])
}

#[allow(non_snake_case)]
fn main() {
    // === Step 1: Setup relation and witness ===

    // Prover's secret: x such that x·G = P
    let x = Scalar::random(&mut OsRng); // Prover's secret
    let (relation, _) = discrete_logarithm(x);

    // === Step 2: Wrap relation in a non-interactive Schnorr protocol ===

    let schnorr = SchnorrProtocol::<RistrettoPoint>::from(relation);
    let ni = NISigmaProtocol::<_, ShakeCodec<RistrettoPoint>>::new(b"schnorr-example", schnorr);
    let witness = vec![x];

    // === Step 3: Prove ===

    let proof = ni.prove(&witness, &mut OsRng).unwrap();

    // === Step 4: Verify ===
    let verified = ni.verify(&proof.0, &proof.1, &proof.2).is_ok();
    println!("Schnorr NIZK proof verified: {verified}");
}
