use curve25519_dalek::ristretto::RistrettoPoint;
use group::Group;
use rand::rngs::OsRng;
use subtle::CtOption;

use super::test_relations::*;
use crate::composition::{ComposedRelation, ComposedWitness};
use crate::schnorr_protocol::SchnorrProof;

type G = RistrettoPoint;

#[allow(non_snake_case)]
#[test]
fn test_composition_correctness() {
    // Composition and verification of proof for the following protocol :
    //
    // And(
    //     Or( dleq, pedersen_commitment ),
    //     Simple( discrete_logarithm ),
    //     And( pedersen_commitment_dleq, bbs_blind_commitment_computation )
    // )
    let domain_sep = b"hello world";

    // definitions of the underlying protocols
    let mut rng = OsRng;
    let (relation1, witness1) = dleq(&mut rng);
    let (relation2, witness2) = pedersen_commitment(&mut rng);
    let (relation3, witness3) = discrete_logarithm(&mut rng);
    let (relation4, witness4) = pedersen_commitment_dleq(&mut rng);
    let (relation5, witness5) = bbs_blind_commitment(&mut rng);

    let wrong_witness2 = (0..witness2.len())
        .map(|_| <G as Group>::Scalar::random(&mut rng))
        .collect::<Vec<_>>();
    // second layer protocol definitions
    let or_protocol1 = ComposedRelation::<G>::Or(vec![
        ComposedRelation::Simple(SchnorrProof(relation1)),
        ComposedRelation::Simple(SchnorrProof(relation2)),
    ]);
    let or_witness1 = ComposedWitness::Or(vec![
        CtOption::new(ComposedWitness::Simple(witness1), 1u8.into()),
        CtOption::new(ComposedWitness::Simple(wrong_witness2), 0u8.into()),
    ]);

    let simple_protocol1 = ComposedRelation::Simple(SchnorrProof(relation3));
    let simple_witness1 = ComposedWitness::Simple(witness3);

    let and_protocol1 = ComposedRelation::And(vec![
        ComposedRelation::Simple(SchnorrProof(relation4)),
        ComposedRelation::Simple(SchnorrProof(relation5)),
    ]);
    let and_witness1 = ComposedWitness::And(vec![
        ComposedWitness::Simple(witness4),
        ComposedWitness::Simple(witness5),
    ]);

    // definition of the final protocol
    let instance = ComposedRelation::And(vec![or_protocol1, simple_protocol1, and_protocol1]);
    let witness = ComposedWitness::And(vec![or_witness1, simple_witness1, and_witness1]);

    let nizk = instance.into_nizk(domain_sep);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut OsRng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut OsRng).unwrap();
    // Verify proofs
    assert!(nizk.verify_batchable(&proof_batchable_bytes).is_ok());
    assert!(nizk.verify_compact(&proof_compact_bytes).is_ok());
}
