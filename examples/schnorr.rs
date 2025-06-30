//! Example: Schnorr proof of knowledge.
//!
//! This example demonstrates how to prove knowledge of a discrete logarithm using `sigma-rs`.
//!
//! The prover convinces a verifier that it knows a secret $x$ such that: $$P = x \cdot G$$
//!
//! where $G$ is a generator of a prime-order group $\mathbb{G}$ and $P$ is a public group element.

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::RistrettoPoint;
use group::Group;
use rand::rngs::OsRng;

use sigma_rs::errors::Error;
use sigma_rs::LinearRelation;

type ProofResult<T> = Result<T, Error>;

/// Create a discrete logarithm relation for the given public key P
#[allow(non_snake_case)]
fn create_relation(P: RistrettoPoint) -> LinearRelation<RistrettoPoint> {
    let mut relation = LinearRelation::new();

    let x = relation.allocate_scalar();
    let G = relation.allocate_element();
    let P_var = relation.allocate_eq(x * G);
    relation.set_element(G, RistrettoPoint::generator());
    relation.set_element(P_var, P);

    relation
}

/// Prove knowledge of the discrete logarithm: given witness x and public key P,
/// generate a proof that P = x * G
#[allow(non_snake_case)]
fn prove(x: Scalar, P: RistrettoPoint) -> ProofResult<Vec<u8>> {
    let nizk = create_relation(P).into_nizk(b"sigma-rs::examples");
    nizk.prove_batchable(&vec![x], &mut OsRng)
}

/// Verify a proof of knowledge of discrete logarithm for the given public key P
#[allow(non_snake_case)]
fn verify(P: RistrettoPoint, proof: &[u8]) -> ProofResult<()> {
    let nizk = create_relation(P).into_nizk(b"sigma-rs::examples");
    nizk.verify_batchable(proof)
}

#[allow(non_snake_case)]
fn main() {
    let x = Scalar::random(&mut OsRng); // Private key (witness)
    let P = RistrettoPoint::generator() * x; // Public key (statement)

    println!("Generated new key pair:");
    println!("Public key P: {:?}", hex::encode(P.compress().as_bytes()));

    match prove(x, P) {
        Ok(proof) => {
            println!("Proof generated successfully:");
            println!("Proof (hex): {}", hex::encode(&proof));

            // Verify the proof
            match verify(P, &proof) {
                Ok(()) => println!("✓ Proof verified successfully!"),
                Err(e) => println!("✗ Proof verification failed: {e:?}"),
            }
        }
        Err(e) => println!("✗ Failed to generate proof: {e:?}"),
    }
}
