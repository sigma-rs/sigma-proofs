//! Example: Schnorr protocol using the sigma-rs framework with the Ristretto group.
//!
//! Proves knowledge of `x` such that `P = x * G`, using the high-level LinearRelation API.

use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

use sigma_rs::codec::ShakeCodec;
use sigma_rs::fiat_shamir::NISigmaProtocol;
use sigma_rs::linear_relation::LinearRelation;
use sigma_rs::schnorr_protocol::SchnorrProtocol;

#[allow(non_snake_case)]
fn main() {
    // === Setup: define witness and statement ===
    let x = Scalar::random(&mut OsRng); // Prover's secret
    let G = RISTRETTO_BASEPOINT_POINT; // Public generator
    let P = x * G; // Public statement: P = x * G

    // === Build the relation P = x * G ===
    let mut relation = LinearRelation::new();

    let svar = relation.allocate_scalar(); // Allocate variable for x
    let gvar = relation.allocate_element(); // Variable for G
    let pvar = relation.allocate_element(); // Variable for P

    relation.assign_element(gvar, G); // Assign known base
    relation.assign_element(pvar, P); // Assign public statement

    relation.constrain(pvar, [(svar, gvar)]); // Encode P = x * G

    // === Create Schnorr protocol and wrap with Fiat-Shamir ===
    let schnorr = SchnorrProtocol::from(relation);
    let ni = NISigmaProtocol::<_, ShakeCodec<RistrettoPoint>>::new(b"schnorr-example", schnorr);

    // === Prove ===
    let witness = vec![x];
    let proof = ni.prove(&witness, &mut OsRng).unwrap();

    // === Verify ===
    let verified = ni.verify(&proof.0, &proof.1, &proof.2).is_ok();
    println!("Schnorr NIZK proof verified: {verified}");
}
