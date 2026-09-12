//! OR-proof composition example.
//!
//! The prover convinces a verifier that it knows *either* $x_1$ with
//! $P_1 = x_1 G$, *or* $x_2$ with $P_2 = x_2 G$ and $Q = x_2 H$ — without
//! revealing which. Here only $x_2$ is known.

use curve25519_dalek::ristretto::RistrettoPoint as G;
use curve25519_dalek::scalar::Scalar;
use group::Group;
use sigma_proofs::codec::ScalarCodec;
use sigma_proofs::{
    composition::{ComposedInstance, ComposedWitness},
    prove_batchable, verify_batchable, LinearRelation, ProverRng,
};

/// The application's tag, carrying the `DSFS` flavor marker required of
/// batchable NARG strings.
const TAG: &[u8] = b"or_proof_example DSFS";

/// The OR of a discrete logarithm `P1 = x1 * G` and a DLEQ `(P2 = x2 * G, Q = x2 * H)`.
#[allow(non_snake_case)]
fn or_relation(P1: G, P2: G, Q: G, H: G) -> anyhow::Result<ComposedInstance<G>> {
    // Left branch: discrete logarithm.
    let mut dlog = LinearRelation::<G>::new();
    let x1 = dlog.allocate_scalar();
    dlog.allocate_eq_with(P1, x1 * dlog.generator());

    // Right branch: equality of discrete logarithms in bases G and H.
    let mut dleq = LinearRelation::<G>::new();
    let x2 = dleq.allocate_scalar();
    let H_var = dleq.allocate_element_with(H);
    dleq.allocate_eq_with(P2, x2 * dleq.generator());
    dleq.allocate_eq_with(Q, x2 * H_var);

    Ok(ComposedInstance::or([dlog.compile()?, dleq.compile()?])?)
}

#[allow(non_snake_case)]
fn main() -> anyhow::Result<()> {
    let mut rng = ProverRng::from_os_entropy();
    let [x1, x2, h] = core::array::from_fn(|_| Scalar::sample(&mut rng));

    let H = G::generator() * h;
    let P1 = G::generator() * x1; // x1 is never handed to the prover
    let P2 = G::generator() * x2;
    let Q = H * x2;

    println!("OR-proof example: proving knowledge of x1 OR x2 (we only know x2)");

    // The same composed statement is what both sides agree on.
    let statement = or_relation(P1, P2, Q, H)?;
    // Branch 1 is the real one; branch 0 is simulated, so its witness slot is
    // an ignored placeholder.
    let witness = ComposedWitness::<G>::or([vec![Scalar::ZERO], vec![x2]]);

    let proof = prove_batchable(TAG, &statement, &witness)?;
    println!("Proof (hex): {}", hex::encode(&proof));

    verify_batchable(TAG, &statement, &proof)?;
    println!("✓ Proof verified successfully!");

    Ok(())
}
