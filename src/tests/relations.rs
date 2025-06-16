use bls12_381::{G1Projective as G, Scalar};
use group::{ff::Field, Group};
use rand::rngs::OsRng;

use crate::fiat_shamir::NISigmaProtocol;
use crate::tests::test_utils::{
    bbs_blind_commitment_computation, discrete_logarithm, dleq, pedersen_commitment,
    pedersen_commitment_dleq,
};
use crate::{codec::ShakeCodec, schnorr_protocol::SchnorrProof};

/// This part tests the functioning of morphisms
/// as well as the implementation of LinearRelation
#[test]
fn test_discrete_logarithm() {
    let mut rng = OsRng;
    discrete_logarithm::<G>(Scalar::random(&mut rng));
}

#[test]
fn test_dleq() {
    let mut rng = OsRng;
    dleq(G::random(&mut rng), Scalar::random(&mut rng));
}

#[test]
fn test_pedersen_commitment() {
    let mut rng = OsRng;
    pedersen_commitment(
        G::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
}

#[test]
fn test_pedersen_commitment_dleq() {
    let mut rng = OsRng;
    pedersen_commitment_dleq(
        (0..4)
            .map(|_| G::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..2)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );
}

#[test]
fn test_bbs_blind_commitment_computation() {
    let mut rng = OsRng;
    bbs_blind_commitment_computation(
        (0..4)
            .map(|_| G::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..3)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        Scalar::random(&mut rng),
    );
}

/// This part tests the implementation of the SigmaProtocol trait for the
/// SchnorrProof structure as well as the Fiat-Shamir NISigmaProtocol transform
#[test]
fn noninteractive_discrete_logarithm() {
    let mut rng = OsRng;
    let (morphismp, witness) = discrete_logarithm(Scalar::random(&mut rng));

    // The SigmaProtocol induced by morphismp
    let protocol = SchnorrProof::from(morphismp);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-schnorr";
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();
    assert!(
        verified_batchable,
        "Fiat-Shamir Schnorr proof verification failed"
    );
    assert!(
        verified_compact,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}

#[test]
fn noninteractive_dleq() {
    let mut rng = OsRng;
    let (morphismp, witness) = dleq(G::random(&mut rng), Scalar::random(&mut rng));

    // The SigmaProtocol induced by morphismp
    let protocol = SchnorrProof::from(morphismp);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-DLEQ";
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();
    assert!(
        verified_batchable,
        "Fiat-Shamir Schnorr proof verification failed"
    );
    assert!(
        verified_compact,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}

#[test]
fn noninteractive_pedersen_commitment() {
    let mut rng = OsRng;
    let (morphismp, witness) = pedersen_commitment(
        G::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );

    // The SigmaProtocol induced by morphismp
    let protocol = SchnorrProof::from(morphismp);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-pedersen-commitment";
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();
    assert!(
        verified_batchable,
        "Fiat-Shamir Schnorr proof verification failed"
    );
    assert!(
        verified_compact,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}

#[test]
fn noninteractive_pedersen_commitment_dleq() {
    let mut rng = OsRng;
    let (morphismp, witness) = pedersen_commitment_dleq(
        (0..4)
            .map(|_| G::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..2)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );

    // The SigmaProtocol induced by morphismp
    let protocol = SchnorrProof::from(morphismp);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-pedersen-commitment-DLEQ";
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();
    assert!(
        verified_batchable,
        "Fiat-Shamir Schnorr proof verification failed"
    );
    assert!(
        verified_compact,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}

#[test]
fn noninteractive_bbs_blind_commitment_computation() {
    let mut rng = OsRng;
    let (morphismp, witness) = bbs_blind_commitment_computation(
        (0..4)
            .map(|_| G::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..3)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        Scalar::random(&mut rng),
    );

    // The SigmaProtocol induced by morphismp
    let protocol = SchnorrProof::from(morphismp);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-bbs-blind-commitment-computation";
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();
    assert!(
        verified_batchable,
        "Fiat-Shamir Schnorr proof verification failed"
    );
    assert!(
        verified_compact,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}
