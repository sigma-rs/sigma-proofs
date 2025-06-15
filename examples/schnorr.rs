//! Example: Schnorr proof of knowledge.
//!
//! This example demonstrates how to prove knowledge of a discrete logarithm using `sigma-rs`.
//! A common use case is authentication: proving you know a secret key without revealing it.
//!
//! The prover convinces a verifier that it knows a secret $x$ such that: $$P = x \cdot G$$
//!
//! where $G$ is a generator of a prime-order group $\mathbb{G}$ and $P$ is a public group element.

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::RistrettoPoint;
use group::Group;
use rand::rngs::OsRng;

use sigma_rs::errors::Error;
use sigma_rs::{LinearRelation, NISigmaProtocol};

type ProofResult<T> = Result<T, Error>;

/// Create a discrete logarithm relation for the given public key P
#[allow(non_snake_case)]
fn create_relation(P: RistrettoPoint) -> LinearRelation<RistrettoPoint> {
    let mut relation = LinearRelation::new();

    // Allocate a variable for the scalar witness `x`
    let var_x = relation.allocate_scalar();

    // Allocate a variable for the group element `G` (the generator)
    let var_G = relation.allocate_element();

    // Create the constraint `P = x * G`
    let var_P = relation.allocate_eq(var_x * var_G);

    // Assign the group generator to the corresponding variable `G`
    relation.set_element(var_G, RistrettoPoint::generator());

    // Assign the public key to the variable `P`
    relation.set_element(var_P, P);

    relation
}

/// Prove knowledge of the discrete logarithm: given witness x and public key P,
/// generate a proof that P = x * G
#[allow(non_snake_case)]
fn prove(x: Scalar, P: RistrettoPoint) -> ProofResult<Vec<u8>> {
    let relation = create_relation(P);
    let nizk: NISigmaProtocol<_, _> = relation.into();

    let witness = vec![x];
    nizk.prove_batchable(&witness, &mut OsRng)
}

/// Verify a proof of knowledge of discrete logarithm for the given public key P
#[allow(non_snake_case)]
fn verify(P: RistrettoPoint, proof: &[u8]) -> ProofResult<()> {
    let relation = create_relation(P);
    let nizk: NISigmaProtocol<_, _> = relation.into();

    nizk.verify_batchable(proof)
}

#[allow(non_snake_case)]
fn main() {
    let x = Scalar::random(&mut OsRng);  // Private key (witness)
    let P = RistrettoPoint::generator() * x;  // Public key (statement)

    println!("Generated new key pair:");
    println!("Public key P: {:?}", hex::encode(P.compress().as_bytes()));

    match prove(x, P) {
        Ok(proof) => {
            println!("Proof generated successfully:");
            println!("Proof (hex): {}", hex::encode(&proof));

            // Verify the proof
            match verify(P, &proof) {
                Ok(()) => println!("✓ Proof verified successfully!"),
                Err(e) => println!("✗ Proof verification failed: {:?}", e),
            }
        }
        Err(e) => println!("✗ Failed to generate proof: {:?}", e),
    }
}
