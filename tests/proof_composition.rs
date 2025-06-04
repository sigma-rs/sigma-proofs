use curve25519_dalek::ristretto::RistrettoPoint;
use group::Group;
use rand::rngs::OsRng;

use sigma_rs::schnorr_protocol::SchnorrProtocol;
use sigma_rs::protocol::{Protocol, ProtocolWitness};
use sigma_rs::codec::ShakeCodec;
use sigma_rs::fiat_shamir::NISigmaProtocol;
use sigma_rs::test_utils::{
    bbs_blind_commitment_computation, discrete_logarithm, dleq, pedersen_commitment,
    pedersen_commitment_dleq,
};

type G = RistrettoPoint;

#[allow(non_snake_case)]
#[test]
fn and_proof_correct() {
    let mut rng = OsRng;
    let domain_sep = b"hello world";

    let (morph1, witness1) = dleq(
        <G as Group>::Scalar::random(&mut rng),
        G::random(&mut rng)
    );

    let (morph2, witness2) = pedersen_commitment(
        G::random(&mut rng),
        <G as Group>::Scalar::random(&mut rng),
        <G as Group>::Scalar::random(&mut rng),
    );

    let and_protocol = Protocol::And(vec![
        Protocol::Simple(SchnorrProtocol::from(morph1)),
        Protocol::Simple(SchnorrProtocol::from(morph2)),
    ]);

    let witness = sigma_rs::protocol::ProtocolWitness::And(vec![
        ProtocolWitness::Simple(witness1),
        ProtocolWitness::Simple(witness2),
    ]);

    let nizk = NISigmaProtocol::<Protocol<RistrettoPoint>, ShakeCodec<G>>::new(
        domain_sep,
        and_protocol,
    );

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    // let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    // let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();
    assert!(
        verified_batchable /* & verified_compact */,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}
