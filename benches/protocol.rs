use std::hint::black_box;

use curve25519_dalek::{RistrettoPoint as G, Scalar};
use divan::Bencher;
use group::Group;
use sigma_proofs::linear_relation::LinearCombination;
use sigma_proofs::{
    derive_session_id, prove_batchable_with, verify_batchable_with, Instance, LinearRelation,
    ProverRng, StdHash,
};

const TERM_COUNTS: &[usize] = &[1, 4, 16, 64];
const TAG: &[u8] = b"sigma-proofs benchmark DSFS";

fn main() {
    divan::main();
}

/// One equation in which a single witness scalar is used with many bases.
///
/// The serialized relation must keep every term, but the evaluator can fold
/// their public coefficients and bases into one effective base before proving.
fn repeated_scalar_relation(terms: usize) -> (Instance<G>, [Scalar; 1]) {
    let mut relation = LinearRelation::<G>::new();
    let x = relation.allocate_scalar();
    let bases = (0..terms)
        .map(|i| {
            let scalar = Scalar::from((i + 2) as u64);
            relation.allocate_element_with(G::generator() * scalar)
        })
        .collect::<Vec<_>>();
    let rhs: LinearCombination<G> = bases.into_iter().map(|base| x * base).collect();
    relation.allocate_eq(rhs);

    let witness = [Scalar::from(42u64)];
    let instance = relation.compile_with_witness(&witness).unwrap();
    (instance, witness)
}

#[divan::bench(args = TERM_COUNTS)]
fn prove_repeated_scalar(bencher: Bencher, terms: usize) {
    let (instance, witness) = repeated_scalar_relation(terms);
    let session_id = derive_session_id::<StdHash>(TAG);
    let mut rng = ProverRng::from_seed([7u8; 32]);
    bencher.counter(terms).bench_local(|| {
        prove_batchable_with::<StdHash, _>(
            &session_id,
            black_box(&instance),
            black_box(&witness),
            &mut rng,
        )
        .unwrap()
    });
}

#[divan::bench(args = TERM_COUNTS)]
fn verify_repeated_scalar(bencher: Bencher, terms: usize) {
    let (instance, witness) = repeated_scalar_relation(terms);
    let session_id = derive_session_id::<StdHash>(TAG);
    let proof = prove_batchable_with::<StdHash, _>(
        &session_id,
        &instance,
        &witness,
        &mut ProverRng::from_seed([7u8; 32]),
    )
    .unwrap();
    bencher.counter(terms).bench(|| {
        verify_batchable_with::<StdHash, _>(
            &session_id,
            black_box(&instance),
            black_box(proof.as_slice()),
        )
        .unwrap()
    });
}
