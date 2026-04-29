use curve25519_dalek::ristretto::RistrettoPoint as G;

use sigma_proofs::composition::ComposedRelation;
use sigma_proofs::linear_relation::ScalarMap;

mod relations;
pub use relations::*;

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
    let (_relation2, _) = pedersen_commitment(&mut rng);
    let (relation3, witness3) = discrete_logarithm(&mut rng);
    let (relation4, witness4) = pedersen_commitment(&mut rng);
    let (relation5, witness5) = bbs_blind_commitment(&mut rng);

    // second layer protocol definitions
    // OR(relation1, relation2): only relation1 has a valid witness; relation2 is simulated.
    let or_protocol1 = ComposedRelation::<G>::or([relation1, _relation2]);
    let and_protocol1 = ComposedRelation::and([relation4, relation5]);

    // definition of the final protocol
    let instance = ComposedRelation::and([or_protocol1, relation3.into(), and_protocol1]);

    // The flat witness contains only the valid branches; invalid branches are simulated.
    let witness: ScalarMap<G> = witness1
        .iter()
        .chain(witness3.iter())
        .chain(witness4.iter())
        .chain(witness5.iter())
        .collect();

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
    let (relation1, witness1) = dleq::<G>(&mut rng);
    let (relation2, witness2) = dleq::<G>(&mut rng);

    let or_protocol = ComposedRelation::or([relation1, relation2]);
    let nizk = or_protocol.into_nizk(b"test_or_one_true");

    // Construct two witnesses to the protocol, the first and then the second as the true branch.
    // The prover simulates whichever branch lacks a valid witness.
    for witness in [witness1, witness2] {
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
    let (relation1, witness1) = dleq::<G>(&mut rng);
    let (relation2, witness2) = dleq::<G>(&mut rng);

    let or_protocol = ComposedRelation::or([relation1, relation2]);

    let witness: ScalarMap<G> = witness1.iter().chain(witness2.iter()).collect();
    let nizk = or_protocol.into_nizk(b"test_or_both_true");

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    assert!(nizk.verify_batchable(&proof_batchable_bytes).is_ok());
    assert!(nizk.verify_compact(&proof_compact_bytes).is_ok());
}

#[allow(non_snake_case)]
#[test]
fn test_threshold_two_of_three() {
    // Test composition of a 2-out-of-3 threshold protocol.

    let mut rng = rand::thread_rng();
    let (relation1, witness1) = dleq::<G>(&mut rng);
    let (relation2, witness2) = dleq::<G>(&mut rng);
    let (relation3, _) = dleq::<G>(&mut rng);

    let threshold_protocol = ComposedRelation::threshold(2, [relation1, relation2, relation3]);
    // Provide the two valid witnesses; the prover simulates the third branch.
    let witness: ScalarMap<G> = witness1.iter().chain(witness2.iter()).collect();
    let nizk = threshold_protocol.into_nizk(b"test_threshold_two_of_three");

    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();

    assert!(nizk.verify_batchable(&proof_batchable_bytes).is_ok());
    assert!(nizk.verify_compact(&proof_compact_bytes).is_ok());
}

#[allow(non_snake_case)]
#[test]
fn test_threshold_two_of_ten_three_valid() {
    // Test composition of a 2-out-of-10 threshold protocol with three valid witnesses.

    let mut rng = rand::thread_rng();

    let mut relations = Vec::new();
    let mut witnesses = Vec::new();
    for _ in 0..10 {
        let (relation, witness) = dleq::<G>(&mut rng);
        relations.push(relation);
        witnesses.push(witness);
    }

    let threshold_protocol =
        ComposedRelation::threshold(2, relations.into_iter().collect::<Vec<_>>());
    // Combine only the first three valid witnesses; the remaining seven are simulated.
    let witness: ScalarMap<G> = witnesses[..3]
        .iter()
        .flat_map(|w| w.iter())
        .collect();
    let nizk = threshold_protocol.into_nizk(b"test_threshold_two_of_ten_three_valid");

    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();

    assert!(nizk.verify_batchable(&proof_batchable_bytes).is_ok());
    assert!(nizk.verify_compact(&proof_compact_bytes).is_ok());
}
