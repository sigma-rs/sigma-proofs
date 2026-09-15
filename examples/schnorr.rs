//! Compact Schnorr proof of knowledge.
//!
//! The prover convinces a verifier that it knows `x` such that `P = x * G`.

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::RistrettoPoint;
use group::Group;
use sigma_proofs::codec::ScalarCodec;
use sigma_proofs::{prove_compact, verify_compact};
use sigma_proofs::{LinearRelation, ProverRng};

/// The `CMPT` marker separates compact proofs from other NARG flavors.
const TAG: &[u8] = b"sigma-proofs-example CMPT";

/// Create the discrete logarithm relation `P = x * G` for the given public key `P`.
#[allow(non_snake_case)]
fn dlog_relation(P: RistrettoPoint) -> LinearRelation<RistrettoPoint> {
    let mut relation = LinearRelation::new();
    let x = relation.allocate_scalar();
    relation.allocate_eq_with(P, x * relation.generator());
    relation
}

#[allow(non_snake_case)]
fn main() -> anyhow::Result<()> {
    // Private key (witness) and public key (statement).
    let x = Scalar::sample(&mut ProverRng::from_os_entropy());
    let P = RistrettoPoint::generator() * x;
    println!("Public key P: {}", hex::encode(P.compress().as_bytes()));

    // The same compiled statement is what both sides agree on.
    let statement = dlog_relation(P).compile()?;

    let proof = prove_compact(TAG, &statement, &[x])?;
    println!("Proof (hex): {}", hex::encode(&proof));

    verify_compact(TAG, &statement, &proof)?;
    println!("✓ Proof verified successfully!");

    Ok(())
}
