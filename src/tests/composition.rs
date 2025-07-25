use curve25519_dalek::ristretto::RistrettoPoint;
use rand::rngs::OsRng;

use super::test_utils::{
    bbs_blind_commitment_computation, discrete_logarithm, dleq, pedersen_commitment,
    pedersen_commitment_dleq,
};
use crate::codec::Shake128DuplexSponge;
use crate::composition::{Protocol, ProtocolWitness};
use crate::fiat_shamir::Nizk;
use crate::schnorr_protocol::SchnorrProof;

type G = RistrettoPoint;

#[allow(non_snake_case)]
#[test]
fn composition_proof_correct() {
    // Composition and verification of proof for the following protocol :
    //
    // And(
    //     Or( dleq, pedersen_commitment ),
    //     Simple( discrete_logarithm ),
    //     And( pedersen_commitment_dleq, bbs_blind_commitment_computation )
    // )
    let domain_sep = b"hello world";

    // definitions of the underlying protocols
    let (relation1, witness1) = dleq::<G>();
    let (relation2, _) = pedersen_commitment::<G>();
    let (relation3, witness3) = discrete_logarithm::<G>();
    let (relation4, witness4) = pedersen_commitment_dleq::<G>();
    let (relation5, witness5) = bbs_blind_commitment_computation::<G>();

    // second layer protocol definitions
    let or_protocol1 = Protocol::Or(vec![
        Protocol::Simple(SchnorrProof(relation1)),
        Protocol::Simple(SchnorrProof(relation2)),
    ]);
    let or_witness1 = ProtocolWitness::Or(0, vec![ProtocolWitness::Simple(witness1)]);

    let simple_protocol1 = Protocol::Simple(SchnorrProof(relation3));
    let simple_witness1 = ProtocolWitness::Simple(witness3);

    let and_protocol1 = Protocol::And(vec![
        Protocol::Simple(SchnorrProof(relation4)),
        Protocol::Simple(SchnorrProof(relation5)),
    ]);
    let and_witness1 = ProtocolWitness::And(vec![
        ProtocolWitness::Simple(witness4),
        ProtocolWitness::Simple(witness5),
    ]);

    // definition of the final protocol
    let protocol = Protocol::And(vec![or_protocol1, simple_protocol1, and_protocol1]);
    let witness = ProtocolWitness::And(vec![or_witness1, simple_witness1, and_witness1]);

    let nizk = Nizk::<Protocol<RistrettoPoint>, Shake128DuplexSponge<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut OsRng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut OsRng).unwrap();
    // Verify proofs
    assert!(nizk.verify_batchable(&proof_batchable_bytes).is_ok());
    assert!(nizk.verify_compact(&proof_compact_bytes).is_ok());
}
