use curve25519_dalek::ristretto::RistrettoPoint as G;
use group::Group;
use sigma_proofs::codec::ScalarCodec;
use sigma_proofs::composition::{ComposedInstance, ComposedWitness};
use sigma_proofs::traits::{SigmaProtocol, SigmaProtocolSimulator};
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

/// The empty AND is the trivially true statement: it proves and verifies at
/// the root with an empty NARG string, and simulates as a branch of an
/// enclosing composition.
#[test]
fn empty_and_is_trivially_true() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = discrete_logarithm::<G>(&mut rng);
    let wrong = wrong_witness(witness.len(), &mut rng);

    let empty = ComposedInstance::<G>::and(Vec::<ComposedInstance<G>>::new()).unwrap();
    let empty_witness = ComposedWitness::<G>::and(Vec::<ComposedWitness<G>>::new());
    assert!(prove_batchable(BATCH_TAG, &empty, &empty_witness)
        .unwrap()
        .is_empty());
    assert_proofs_verify(&empty, &empty_witness);

    // Provable from either side: through the empty AND with no witness for
    // the leaf, or through the leaf with the empty AND simulated.
    let relation = ComposedInstance::or([empty, instance.into()]).unwrap();
    for witness in [
        ComposedWitness::or([empty_witness.clone(), wrong.into()]),
        ComposedWitness::or([empty_witness, witness.into()]),
    ] {
        assert_proofs_verify(&relation, &witness);
    }
}

/// A threshold of zero is trivially true: it proves with no valid witness,
/// alone and as a branch, and the 0-of-0 threshold has an empty NARG string.
#[test]
fn zero_threshold_is_trivially_true() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = discrete_logarithm::<G>(&mut rng);
    let wrong = wrong_witness(witness.len(), &mut rng);

    let empty = ComposedInstance::<G>::threshold(0, Vec::<ComposedInstance<G>>::new()).unwrap();
    let empty_witness = ComposedWitness::<G>::threshold(Vec::<ComposedWitness<G>>::new());
    assert!(prove_batchable(BATCH_TAG, &empty, &empty_witness)
        .unwrap()
        .is_empty());
    assert_proofs_verify(&empty, &empty_witness);

    let one_branch = ComposedInstance::threshold(0, [instance.clone()]).unwrap();
    let one_branch_witness = ComposedWitness::threshold([wrong.clone()]);
    assert_proofs_verify(&one_branch, &one_branch_witness);

    let relation = ComposedInstance::threshold(0, [instance.clone(), instance.clone()]).unwrap();
    let relation_witness = ComposedWitness::threshold([wrong.clone(), wrong.clone()]);
    assert_proofs_verify(&relation, &relation_witness);

    // Provable from either side of an OR: through the zero threshold with
    // no witness at all, or through the leaf with the threshold simulated.
    let relation = ComposedInstance::or([relation, instance.into()]).unwrap();
    for leaf in [wrong, witness] {
        let relation_witness = ComposedWitness::or([relation_witness.clone(), leaf.into()]);
        assert_proofs_verify(&relation, &relation_witness);
    }
}

/// A positive threshold over no branches, and therefore an empty OR, is a
/// false statement. It can still be simulated as a false branch of an OR.
#[test]
fn empty_false_compositions_are_supported() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = discrete_logarithm::<G>(&mut rng);

    let false_threshold =
        ComposedInstance::<G>::threshold(1, Vec::<ComposedInstance<G>>::new()).unwrap();
    let false_threshold_witness = ComposedWitness::<G>::threshold(Vec::<ComposedWitness<G>>::new());
    let batchable = prove_batchable(BATCH_TAG, &false_threshold, &false_threshold_witness).unwrap();
    assert!(!batchable.is_empty());
    assert!(verify_batchable(BATCH_TAG, &false_threshold, &batchable).is_err());
    let compact = prove_compact(COMPACT_TAG, &false_threshold, &false_threshold_witness).unwrap();
    assert!(!compact.is_empty());
    assert!(verify_compact(COMPACT_TAG, &false_threshold, &compact).is_err());

    let threshold_encoding = false_threshold.encode_instance().as_ref().to_vec();
    assert!(threshold_encoding.starts_with(b"sigma-proofs composition THRESHOLD"));
    let other_false_threshold =
        ComposedInstance::<G>::threshold(2, Vec::<ComposedInstance<G>>::new()).unwrap();
    assert_ne!(
        threshold_encoding,
        other_false_threshold.encode_instance().as_ref()
    );

    let relation = ComposedInstance::or([false_threshold, instance.clone().into()]).unwrap();
    let relation_witness = ComposedWitness::or([false_threshold_witness, witness.clone().into()]);
    assert_proofs_verify(&relation, &relation_witness);

    let empty_or = ComposedInstance::<G>::or(Vec::<ComposedInstance<G>>::new()).unwrap();
    let empty_or_encoding = empty_or.encode_instance().as_ref().to_vec();
    assert!(empty_or_encoding.starts_with(b"sigma-proofs composition OR"));
    assert_ne!(threshold_encoding, empty_or_encoding);
    let relation = ComposedInstance::or([empty_or, instance.into()]).unwrap();
    // The public enum variant and the convenience constructor must agree.
    for empty_or_witness in [
        ComposedWitness::<G>::or(Vec::<ComposedWitness<G>>::new()),
        ComposedWitness::Or(Vec::new()),
    ] {
        let relation_witness = ComposedWitness::or([empty_or_witness, witness.clone().into()]);
        assert_proofs_verify(&relation, &relation_witness);
    }
}

#[test]
fn proofs_bind_empty_false_statement_structure() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = discrete_logarithm::<G>(&mut rng);
    let cases = [
        (
            ComposedInstance::<G>::or(Vec::<ComposedInstance<G>>::new()).unwrap(),
            ComposedWitness::Or(Vec::new()),
        ),
        (
            ComposedInstance::<G>::threshold(1, Vec::<ComposedInstance<G>>::new()).unwrap(),
            ComposedWitness::Threshold(Vec::new()),
        ),
        (
            ComposedInstance::<G>::threshold(2, Vec::<ComposedInstance<G>>::new()).unwrap(),
            ComposedWitness::Threshold(Vec::new()),
        ),
        (
            ComposedInstance::claim([(Scalar::from(1u64), G::generator())]).unwrap(),
            ComposedWitness::Claim,
        ),
    ]
    .map(|(branch, branch_witness)| {
        (
            ComposedInstance::or([branch, instance.clone().into()]).unwrap(),
            ComposedWitness::or([branch_witness, witness.clone().into()]),
        )
    });

    for (i, (relation, witness)) in cases.iter().enumerate() {
        let batchable = prove_batchable(BATCH_TAG, relation, witness).unwrap();
        let compact = prove_compact(COMPACT_TAG, relation, witness).unwrap();
        for (j, (other, _)) in cases.iter().enumerate() {
            assert_eq!(
                verify_batchable(BATCH_TAG, other, &batchable).is_ok(),
                i == j
            );
            assert_eq!(verify_compact(COMPACT_TAG, other, &compact).is_ok(), i == j);
        }
    }
}

#[test]
fn empty_threshold_encoding_bounds() {
    let boundary =
        ComposedInstance::<G>::threshold(u32::MAX as usize, Vec::<ComposedInstance<G>>::new())
            .unwrap();
    assert!(boundary
        .encode_instance()
        .as_ref()
        .starts_with(b"sigma-proofs composition THRESHOLD"));
    #[cfg(target_pointer_width = "64")]
    assert!(ComposedInstance::<G>::threshold(
        u32::MAX as usize + 1,
        Vec::<ComposedInstance<G>>::new()
    )
    .is_err());
}

#[test]
fn simulated_transcripts_verify_for_every_node_shape() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, _) = discrete_logarithm::<G>(&mut rng);
    let empty_or = ComposedInstance::<G>::or(Vec::<ComposedInstance<G>>::new()).unwrap();
    let false_threshold =
        ComposedInstance::<G>::threshold(2, Vec::<ComposedInstance<G>>::new()).unwrap();
    let nodes = [
        instance.clone().into(),
        ComposedInstance::and([instance.clone()]).unwrap(),
        ComposedInstance::<G>::and(Vec::<ComposedInstance<G>>::new()).unwrap(),
        ComposedInstance::or([instance.clone()]).unwrap(),
        empty_or.clone(),
        ComposedInstance::threshold(0, [instance.clone()]).unwrap(),
        ComposedInstance::<G>::threshold(0, Vec::<ComposedInstance<G>>::new()).unwrap(),
        ComposedInstance::threshold(1, [instance.clone(), instance.clone()]).unwrap(),
        false_threshold.clone(),
        ComposedInstance::claim([(Scalar::from(0u64), G::generator())]).unwrap(),
        ComposedInstance::claim([(Scalar::from(1u64), G::generator())]).unwrap(),
        ComposedInstance::and([empty_or.clone(), false_threshold.clone()]).unwrap(),
        ComposedInstance::threshold(1, [empty_or, false_threshold, instance.into()]).unwrap(),
    ];
    for node in nodes {
        let (commitment, challenge, response) = node.simulate_transcript(&mut rng).unwrap();
        node.verifier(&commitment, &challenge, &response).unwrap();
    }
}
