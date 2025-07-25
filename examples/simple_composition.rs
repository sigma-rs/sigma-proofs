//! OR-proof composition example.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use group::Group;
use rand::rngs::OsRng;
use sigma_rs::{
    codec::Shake128DuplexSponge,
    composition::{ComposedRelation, ComposedWitness},
    errors::Error,
    LinearRelation, Nizk,
};

type G = RistrettoPoint;
type ProofResult<T> = Result<T, Error>;

/// Create an OR relation between two statements:
/// 1. Knowledge of discrete log: P1 = x1 * G
/// 2. Knowledge of DLEQ: (P2 = x2 * G, Q = x2 * H)
#[allow(non_snake_case)]
fn create_relation(P1: G, P2: G, Q: G, H: G) -> ComposedRelation<G> {
    // First relation: discrete logarithm P1 = x1 * G
    let mut rel1 = LinearRelation::<G>::new();
    let x1 = rel1.allocate_scalar();
    let G1 = rel1.allocate_element();
    let P1_var = rel1.allocate_eq(x1 * G1);
    rel1.set_element(G1, G::generator());
    rel1.set_element(P1_var, P1);

    // Second relation: DLEQ (P2 = x2 * G, Q = x2 * H)
    let mut rel2 = LinearRelation::<G>::new();
    let x2 = rel2.allocate_scalar();
    let G2 = rel2.allocate_element();
    let H_var = rel2.allocate_element();
    let P2_var = rel2.allocate_eq(x2 * G2);
    let Q_var = rel2.allocate_eq(x2 * H_var);
    rel2.set_element(G2, G::generator());
    rel2.set_element(H_var, H);
    rel2.set_element(P2_var, P2);
    rel2.set_element(Q_var, Q);

    // Compose into OR protocol
    let proto1 = ComposedRelation::from(rel1);
    let proto2 = ComposedRelation::from(rel2);
    ComposedRelation::Or(vec![proto1, proto2])
}

/// Prove knowledge of one of the witnesses (we know x2 for the DLEQ)
#[allow(non_snake_case)]
fn prove(P1: G, x2: Scalar, H: G) -> ProofResult<Vec<u8>> {
    // Compute public values
    let P2 = G::generator() * x2;
    let Q = H * x2;

    let instance = create_relation(P1, P2, Q, H);
    let witness = ComposedWitness::Or(1, vec![ComposedWitness::Simple(vec![x2])]);
    let nizk = Nizk::<_, Shake128DuplexSponge<G>>::new(b"or_proof_example", instance);

    nizk.prove_batchable(&witness, &mut OsRng)
}

/// Verify an OR proof given the public values
#[allow(non_snake_case)]
fn verify(P1: G, P2: G, Q: G, H: G, proof: &[u8]) -> ProofResult<()> {
    let protocol = create_relation(P1, P2, Q, H);
    let nizk = Nizk::<_, Shake128DuplexSponge<G>>::new(b"or_proof_example", protocol);

    nizk.verify_batchable(proof)
}

#[allow(non_snake_case)]
fn main() {
    // Setup: We don't know x1, but we do know x2
    let x1 = Scalar::random(&mut OsRng);
    let x2 = Scalar::random(&mut OsRng);
    let H = G::random(&mut OsRng);

    // Compute public values
    let P1 = G::generator() * x1; // We don't actually know x1 in the proof
    let P2 = G::generator() * x2; // We know x2
    let Q = H * x2; // Q = x2 * H

    println!("OR-proof example: Proving knowledge of x1 OR x2");
    println!("(We only know x2, not x1)");

    match prove(P1, x2, H) {
        Ok(proof) => {
            println!("Proof generated successfully");
            println!("Proof (hex): {}", hex::encode(&proof));

            // Verify the proof
            match verify(P1, P2, Q, H, &proof) {
                Ok(()) => println!("✓ Proof verified successfully!"),
                Err(e) => println!("✗ Proof verification failed: {e:?}"),
            }
        }
        Err(e) => println!("✗ Failed to generate proof: {e:?}"),
    }
}
