//! Example: Schnorr proof of knowledge.
//!
//! This example demonstrates how to prove knowledge of a discrete logarithm using `sigma-rs`.
//!
//! The prover convinces a verifier that it knows a secret $x$ such that: $$P = x \cdot G$$
//!
//! where $G$ is a generator of a prime-order group $\mathbb{G}$ and $P$ is a public group element.

use std::process::ExitCode;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::RistrettoPoint;
use group::Group;
use rand::rngs::OsRng;

use sigma_proofs::errors::Error;
use sigma_proofs::linear_relation::{GroupVar, ScalarVar};
use sigma_proofs::LinearRelation;

/// Create a discrete logarithm relation for the given public key P
#[allow(non_snake_case)]
fn create_relation() -> (
    LinearRelation<RistrettoPoint>,
    ScalarVar<RistrettoPoint>,
    GroupVar<RistrettoPoint>,
) {
    let mut relation = LinearRelation::new();

    let x = relation.allocate_scalar();
    let G = relation.allocate_element_with(RistrettoPoint::generator());
    let P = relation.allocate_eq(x * G);

    (relation, x, P)
}

/// Prove knowledge of the discrete logarithm: given witness x and public key P,
/// generate a proof that P = x * G
#[allow(non_snake_case)]
fn prove(x: Scalar) -> Result<Vec<u8>, Error> {
    let (mut relation, x_var, _) = create_relation();
    let witness = [(x_var, x)];
    relation.compute_image(witness)?;
    relation
        .into_nizk(b"sigma-proofs-example")?
        .prove_batchable(witness, &mut OsRng)
}

/// Verify a proof of knowledge of discrete logarithm for the given public key P
#[allow(non_snake_case)]
fn verify(P: RistrettoPoint, proof: &[u8]) -> Result<(), Error> {
    let (mut relation, _, P_var) = create_relation();
    relation.set_element(P_var, P);
    relation
        .into_nizk(b"sigma-proofs-example")?
        .verify_batchable(proof)
}

#[allow(non_snake_case)]
fn main() -> ExitCode {
    let x = Scalar::random(&mut OsRng); // Private key (witness)
    let P = RistrettoPoint::generator() * x; // Public key (statement)

    println!("Generated new key pair:");
    println!("Public key P: {:?}", hex::encode(P.compress().as_bytes()));

    let proof = match prove(x) {
        Ok(proof) => {
            println!("Proof generated successfully:");
            println!("Proof (hex): {}", hex::encode(&proof));
            proof
        }
        Err(e) => {
            println!("✗ Failed to generate proof: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    // Verify the proof
    match verify(P, &proof) {
        Ok(()) => println!("✓ Proof verified successfully!"),
        Err(e) => {
            println!("✗ Proof verification failed: {e:?}");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}
