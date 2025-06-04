use curve25519_dalek::ristretto::RistrettoPoint;
use group::Group;
use rand::rngs::OsRng;

use sigma_rs::codec::ShakeCodec;
use sigma_rs::fiat_shamir::NISigmaProtocol;
use sigma_rs::group_morphism::HasGroupMorphism;
use sigma_rs::protocol::{Protocol, ProtocolWitness};
use sigma_rs::schnorr_protocol::SchnorrProtocol;
use sigma_rs::test_utils::{
    bbs_blind_commitment_computation, discrete_logarithm, dleq, pedersen_commitment,
    pedersen_commitment_dleq,
};

type G = RistrettoPoint;

#[allow(non_snake_case)]
#[test]
fn composition_proof_correct() {
    // Composition and verification of proof for the following protocol :
    //
    // protocol = And(
    //     Or( dleq, pedersen_commitment ),
    //     Simple( discrete_logarithm ),
    //     And( pedersen_commitment_dleq, bbs_blind_commitment_computation )
    // )
    let mut rng = OsRng;
    let domain_sep = b"hello world";

    // definitions of the underlying protocols
    let (morph1, witness1) = dleq(<G as Group>::Scalar::random(&mut rng), G::random(&mut rng));
    let (morph2, _) = pedersen_commitment(
        G::random(&mut rng),
        <G as Group>::Scalar::random(&mut rng),
        <G as Group>::Scalar::random(&mut rng),
    );
    let (morph3, witness3) = discrete_logarithm(<G as Group>::Scalar::random(&mut rng));
    let (morph4, witness4) = pedersen_commitment_dleq(
        (0..4)
            .map(|_| G::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..2)
            .map(|_| <G as Group>::Scalar::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );
    let (morph5, witness5) = bbs_blind_commitment_computation(
        (0..4)
            .map(|_| G::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..3)
            .map(|_| <G as Group>::Scalar::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        <G as Group>::Scalar::random(&mut rng),
    );

    // second layer protocol definitions
    let or_protocol1 = Protocol::Or(vec![
        Protocol::Simple(SchnorrProtocol::from(morph1)),
        Protocol::Simple(SchnorrProtocol::from(morph2)),
    ]);
    let or_witness1 =
        sigma_rs::protocol::ProtocolWitness::Or(0, vec![ProtocolWitness::Simple(witness1)]);

    let simple_protocol1 = Protocol::Simple(SchnorrProtocol::from(morph3));
    let simple_witness1 = ProtocolWitness::Simple(witness3);

    let and_protocol1 = Protocol::And(vec![
        Protocol::Simple(SchnorrProtocol::from(morph4)),
        Protocol::Simple(SchnorrProtocol::from(morph5)),
    ]);
    let and_witness1 = ProtocolWitness::And(vec![
        ProtocolWitness::Simple(witness4),
        ProtocolWitness::Simple(witness5),
    ]);

    // definition of the final protocol
    let protocol = Protocol::And(vec![or_protocol1, simple_protocol1, and_protocol1]);
    let witness = ProtocolWitness::And(vec![or_witness1, simple_witness1, and_witness1]);

    let nizk =
        NISigmaProtocol::<Protocol<RistrettoPoint>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();
    assert!(
        verified_batchable & verified_compact,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}

#[allow(non_snake_case)]
#[test]
fn composition_proof_correct_with_morphism_absorption() {
    // Composition and verification of proof for the following protocol :
    //
    // protocol = And(
    //     Or( dleq, pedersen_commitment ),
    //     Simple( discrete_logarithm ),
    //     And( pedersen_commitment_dleq, bbs_blind_commitment_computation )
    // )
    let mut rng = OsRng;
    let domain_sep = b"hello world";

    // definitions of the underlying protocols
    let (morph1, witness1) = dleq(<G as Group>::Scalar::random(&mut rng), G::random(&mut rng));
    let (morph2, _) = pedersen_commitment(
        G::random(&mut rng),
        <G as Group>::Scalar::random(&mut rng),
        <G as Group>::Scalar::random(&mut rng),
    );
    let (morph3, witness3) = discrete_logarithm(<G as Group>::Scalar::random(&mut rng));
    let (morph4, witness4) = pedersen_commitment_dleq(
        (0..4)
            .map(|_| G::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..2)
            .map(|_| <G as Group>::Scalar::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );
    let (morph5, witness5) = bbs_blind_commitment_computation(
        (0..4)
            .map(|_| G::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..3)
            .map(|_| <G as Group>::Scalar::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        <G as Group>::Scalar::random(&mut rng),
    );

    // second layer protocol definitions
    let or_protocol1 = Protocol::Or(vec![
        Protocol::Simple(SchnorrProtocol::from(morph1)),
        Protocol::Simple(SchnorrProtocol::from(morph2)),
    ]);
    let or_witness1 =
        sigma_rs::protocol::ProtocolWitness::Or(0, vec![ProtocolWitness::Simple(witness1)]);

    let simple_protocol1 = Protocol::Simple(SchnorrProtocol::from(morph3));
    let simple_witness1 = ProtocolWitness::Simple(witness3);

    let and_protocol1 = Protocol::And(vec![
        Protocol::Simple(SchnorrProtocol::from(morph4)),
        Protocol::Simple(SchnorrProtocol::from(morph5)),
    ]);
    let and_witness1 = ProtocolWitness::And(vec![
        ProtocolWitness::Simple(witness4),
        ProtocolWitness::Simple(witness5),
    ]);

    // definition of the final protocol
    let protocol = Protocol::And(vec![or_protocol1, simple_protocol1, and_protocol1]);
    let witness = ProtocolWitness::And(vec![or_witness1, simple_witness1, and_witness1]);

    let mut nizk =
        NISigmaProtocol::<Protocol<RistrettoPoint>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Morphism absorption
    nizk.sigmap
        .absorb_morphism_structure(&mut nizk.hash_state)
        .unwrap();

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();
    assert!(
        verified_batchable & verified_compact,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}
