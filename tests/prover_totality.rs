//! Unsatisfied composed witnesses may produce a NARG string, but must never
//! produce one that verifies. Witness trees with the wrong shape remain an
//! immediate error.

use curve25519_dalek::ristretto::RistrettoPoint as G;
use group::Group;
use sigma_proofs::composition::{ComposedInstance, ComposedWitness};
use sigma_proofs::errors::InvalidWitness;
use sigma_proofs::{prove_batchable, prove_compact, verify_batchable, verify_compact, ProverRng};

#[allow(dead_code)]
mod relations;
use relations::*;

type Scalar = <G as Group>::Scalar;

const TAG: &[u8] = b"prover totality tests DSFS";
const COMPACT_TAG: &[u8] = b"prover totality tests CMPT";

fn invalidate(mut witness: Vec<Scalar>) -> Vec<Scalar> {
    witness[0] += Scalar::from(1u64);
    witness
}

fn assert_never_verifies(relation: &ComposedInstance<G>, witness: &ComposedWitness<G>) {
    if let Ok(proof) = prove_batchable(TAG, relation, witness) {
        assert!(verify_batchable(TAG, relation, &proof).is_err());
    }
    if let Ok(proof) = prove_compact(COMPACT_TAG, relation, witness) {
        assert!(verify_compact(COMPACT_TAG, relation, &proof).is_err());
    }
}

#[test]
fn an_unsatisfiable_or_never_verifies() {
    let mut rng = ProverRng::from_os_entropy();
    let (left, left_witness) = discrete_logarithm::<G>(&mut rng);
    let (right, right_witness) = pedersen_commitment::<G>(&mut rng);
    let relation = ComposedInstance::or([left, right]).unwrap();
    let witness = ComposedWitness::or([invalidate(left_witness), invalidate(right_witness)]);

    assert_never_verifies(&relation, &witness);
}

#[test]
fn a_threshold_short_of_its_quorum_never_verifies() {
    let mut rng = ProverRng::from_os_entropy();
    let (a, a_witness) = discrete_logarithm::<G>(&mut rng);
    let (b, b_witness) = discrete_logarithm::<G>(&mut rng);
    let (c, c_witness) = discrete_logarithm::<G>(&mut rng);
    let relation = ComposedInstance::threshold(3, [a, b, c]).unwrap();
    let witness = ComposedWitness::threshold([a_witness, b_witness, invalidate(c_witness)]);

    assert_never_verifies(&relation, &witness);
}

#[test]
fn empty_false_compositions_never_verify() {
    let cases = [
        (
            ComposedInstance::<G>::or(Vec::<ComposedInstance<G>>::new()).unwrap(),
            ComposedWitness::<G>::or(Vec::<ComposedWitness<G>>::new()),
        ),
        (
            ComposedInstance::<G>::threshold(1, Vec::<ComposedInstance<G>>::new()).unwrap(),
            ComposedWitness::<G>::threshold(Vec::<ComposedWitness<G>>::new()),
        ),
    ];

    for (relation, witness) in cases {
        assert_never_verifies(&relation, &witness);
    }
}

#[test]
fn a_mismatched_witness_tree_is_rejected() {
    let mut rng = ProverRng::from_os_entropy();
    let (relation, witness) = discrete_logarithm::<G>(&mut rng);
    let relation = ComposedInstance::or([relation]).unwrap();
    let witness = ComposedWitness::and([witness]);

    assert!(matches!(
        prove_batchable(TAG, &relation, &witness),
        Err(InvalidWitness)
    ));
}

#[test]
fn ordinary_claim_rejects_empty_composition_witnesses() {
    let relation = ComposedInstance::<G>::claim([(Scalar::from(0u64), G::generator())]).unwrap();
    for witness in [
        ComposedWitness::Or(Vec::new()),
        ComposedWitness::Threshold(Vec::new()),
    ] {
        assert!(matches!(
            prove_batchable(TAG, &relation, &witness),
            Err(InvalidWitness)
        ));
        assert!(matches!(
            prove_compact(COMPACT_TAG, &relation, &witness),
            Err(InvalidWitness)
        ));
    }
}
