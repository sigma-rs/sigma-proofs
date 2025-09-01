use curve25519_dalek::ristretto::RistrettoPoint;
use group::Group;

use super::test_relations::*;
use crate::composition::{ComposedRelation, ComposedWitness};

type G = RistrettoPoint;

#[allow(non_snake_case)]
#[test]
fn test_composition_example() {
    // Composition and verification of proof for the following protocol :
    //
    // And(
    //     Or( dleq, pedersen_commitment ),
    //     Simple( discrete_logarithm ),
    //     And( pedersen_commitment_dleq, bbs_blind_commitment_computation )
    // )
    let domain_sep = b"hello world";

    // definitions of the underlying protocols
    let mut rng = rand::thread_rng();
    let (relation1, witness1) = dleq(&mut rng);
    let (relation2, witness2) = pedersen_commitment(&mut rng);
    let (relation3, witness3) = discrete_logarithm(&mut rng);
    let (relation4, witness4) = pedersen_commitment_dleq(&mut rng);
    let (relation5, witness5) = bbs_blind_commitment(&mut rng);

    let wrong_witness2 = (0..witness2.len())
        .map(|_| <G as Group>::Scalar::random(&mut rng))
        .collect::<Vec<_>>();
    // second layer protocol definitions
    let or_protocol1 = ComposedRelation::<G>::or([relation1, relation2]);
    let or_witness1 = ComposedWitness::or([witness1, wrong_witness2]);

    let and_protocol1 = ComposedRelation::and([relation4, relation5]);
    let and_witness1 = ComposedWitness::and([witness4, witness5]);

    // definition of the final protocol
    let instance = ComposedRelation::and([or_protocol1, relation3.into(), and_protocol1]);
    let witness = ComposedWitness::and([or_witness1, witness3.into(), and_witness1]);

    let nizk = instance.into_nizk(domain_sep);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    assert!(nizk.verify_batchable(&proof_batchable_bytes).is_ok());
    assert!(nizk.verify_compact(&proof_compact_bytes).is_ok());
}

#[allow(non_snake_case)]
#[test]
fn test_or_one_true() {
    // Test composition of a basic OR protocol, with one of the two witnesses being valid.

    // definitions of the underlying protocols
    let mut rng = rand::thread_rng();
    let (relation1, witness1) = dleq::<G, _>(&mut rng);
    let (relation2, witness2) = dleq::<G, _>(&mut rng);

    let wrong_witness1 = (0..witness1.len())
        .map(|_| <G as Group>::Scalar::random(&mut rng))
        .collect::<Vec<_>>();
    let wrong_witness2 = (0..witness2.len())
        .map(|_| <G as Group>::Scalar::random(&mut rng))
        .collect::<Vec<_>>();

    let or_protocol = ComposedRelation::or([relation1, relation2]);

    // Construct two witnesses to the protocol, the first and then the second as the true branch.
    let witness_or_1 = ComposedWitness::or([witness1, wrong_witness2]);
    let witness_or_2 = ComposedWitness::or([wrong_witness1, witness2]);

    let nizk = or_protocol.into_nizk(b"test_or_one_true");

    for witness in [witness_or_1, witness_or_2] {
        // Batchable and compact proofs
        let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
        let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
        // Verify proofs
        assert!(nizk.verify_batchable(&proof_batchable_bytes).is_ok());
        assert!(nizk.verify_compact(&proof_compact_bytes).is_ok());
    }
}

#[allow(non_snake_case)]
#[test]
fn test_or_both_true() {
    // Test composition of a basic OR protocol, with both of the two witnesses being valid.

    // definitions of the underlying protocols
    let mut rng = rand::thread_rng();
    let (relation1, witness1) = dleq::<G, _>(&mut rng);
    let (relation2, witness2) = dleq::<G, _>(&mut rng);

    let or_protocol = ComposedRelation::or([relation1, relation2]);

    let witness = ComposedWitness::or([witness1, witness2]);
    let nizk = or_protocol.into_nizk(b"test_or_both_true");

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    assert!(nizk.verify_batchable(&proof_batchable_bytes).is_ok());
    assert!(nizk.verify_compact(&proof_compact_bytes).is_ok());
}
