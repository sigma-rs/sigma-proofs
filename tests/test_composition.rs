use curve25519_dalek::ristretto::RistrettoPoint as G;
use group::Group;
use sigma_proofs::codec::ScalarCodec;
use sigma_proofs::composition::{ComposedInstance, ComposedWitness};
use sigma_proofs::{prove_batchable, prove_compact, verify_batchable, verify_compact, ProverRng};

#[allow(dead_code)]
mod relations;
use relations::*;

type Scalar = <G as Group>::Scalar;

const BATCH_TAG: &[u8] = b"composition tests DSFS";
const COMPACT_TAG: &[u8] = b"composition tests CMPT";

fn wrong_witness(len: usize, rng: &mut ProverRng) -> Vec<Scalar> {
    (0..len).map(|_| Scalar::sample(rng)).collect()
}

fn assert_proofs_verify(relation: &ComposedInstance<G>, witness: &ComposedWitness<G>) {
    let batchable = prove_batchable(BATCH_TAG, relation, witness).unwrap();
    verify_batchable(BATCH_TAG, relation, &batchable).unwrap();

    let compact = prove_compact(COMPACT_TAG, relation, witness).unwrap();
    verify_compact(COMPACT_TAG, relation, &compact).unwrap();
}

#[test]
fn nested_composition_proves_and_verifies() {
    // And(Or(dleq, pedersen), dlog, And(pedersen, bbs commitment)).
    let mut rng = ProverRng::from_os_entropy();
    let (dleq, dleq_witness) = dleq(&mut rng);
    let (pedersen, pedersen_witness) = pedersen_commitment(&mut rng);
    let (dlog, dlog_witness) = discrete_logarithm(&mut rng);
    let (other_pedersen, other_pedersen_witness) = pedersen_commitment(&mut rng);
    let (bbs, bbs_witness) = bbs_blind_commitment(&mut rng);

    let relation = ComposedInstance::and([
        ComposedInstance::or([dleq, pedersen]).unwrap(),
        dlog.into(),
        ComposedInstance::and([other_pedersen, bbs]).unwrap(),
    ])
    .unwrap();
    let witness = ComposedWitness::and([
        ComposedWitness::or([
            dleq_witness,
            wrong_witness(pedersen_witness.len(), &mut rng),
        ]),
        dlog_witness.into(),
        ComposedWitness::and([other_pedersen_witness, bbs_witness]),
    ]);

    assert_proofs_verify(&relation, &witness);
}

#[test]
fn either_or_branch_can_be_satisfied() {
    let mut rng = ProverRng::from_os_entropy();
    let (left, left_witness) = dleq::<G>(&mut rng);
    let (right, right_witness) = dleq::<G>(&mut rng);
    let wrong_left = wrong_witness(left_witness.len(), &mut rng);
    let wrong_right = wrong_witness(right_witness.len(), &mut rng);
    let relation = ComposedInstance::or([left, right]).unwrap();

    for witness in [
        ComposedWitness::or([left_witness, wrong_right]),
        ComposedWitness::or([wrong_left, right_witness]),
    ] {
        assert_proofs_verify(&relation, &witness);
    }
}

#[test]
fn threshold_with_exact_quorum_proves_and_verifies() {
    let mut rng = ProverRng::from_os_entropy();
    let (a, a_witness) = dleq::<G>(&mut rng);
    let (b, b_witness) = dleq::<G>(&mut rng);
    let (c, c_witness) = dleq::<G>(&mut rng);
    let wrong_c = wrong_witness(c_witness.len(), &mut rng);

    let relation = ComposedInstance::threshold(2, [a, b, c]).unwrap();
    let witness = ComposedWitness::threshold([a_witness, b_witness, wrong_c]);
    assert_proofs_verify(&relation, &witness);
}
