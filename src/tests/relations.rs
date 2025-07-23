use bls12_381::{G1Projective as G, Scalar};
use group::{ff::Field, Group};
use rand::rngs::OsRng;

use crate::fiat_shamir::Nizk;
use crate::tests::test_utils::{
    bbs_blind_commitment_computation, discrete_logarithm, dleq, pedersen_commitment,
    pedersen_commitment_dleq, translated_discrete_logarithm, translated_dleq,
    user_specific_linear_combination,
};
use crate::{codec::ShakeCodec, schnorr_protocol::SchnorrProof};

/// This part tests the functioning of linear maps
/// as well as the implementation of LinearRelation
#[test]
fn test_discrete_logarithm() {
    discrete_logarithm::<G>(Scalar::random(&mut OsRng));
}

#[test]
fn test_translated_discrete_logarithm() {
    translated_discrete_logarithm::<G>(Scalar::random(&mut OsRng));
}

#[test]
fn test_dleq() {
    dleq(G::random(&mut OsRng), Scalar::random(&mut OsRng));
}

#[test]
fn test_translated_dleq() {
    dleq(G::random(&mut OsRng), Scalar::random(&mut OsRng));
}

#[test]
fn test_pedersen_commitment() {
    pedersen_commitment(
        G::random(&mut OsRng),
        Scalar::random(&mut OsRng),
        Scalar::random(&mut OsRng),
    );
}

#[test]
fn test_user_specific_linear_combination() {
    user_specific_linear_combination(G::random(&mut OsRng), Scalar::random(&mut OsRng));
}

#[test]
fn test_pedersen_commitment_dleq() {
    pedersen_commitment_dleq(
        (0..4)
            .map(|_| G::random(&mut OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..2)
            .map(|_| Scalar::random(&mut OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );
}

#[test]
fn test_bbs_blind_commitment_computation() {
    bbs_blind_commitment_computation(
        (0..4)
            .map(|_| G::random(&mut OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..3)
            .map(|_| Scalar::random(&mut OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        Scalar::random(&mut OsRng),
    );
}

/// This part tests the implementation of the SigmaProtocol trait for the
/// SchnorrProof structure as well as the Fiat-Shamir Nizk transform
#[test]
fn noninteractive_discrete_logarithm() {
    let (relation, witness) = discrete_logarithm(Scalar::random(&mut OsRng));

    // The SigmaProtocol induced by relation
    let protocol = SchnorrProof::from(relation);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-schnorr";
    let nizk = Nizk::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut OsRng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut OsRng).unwrap();
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
fn noninteractive_translated_discrete_logarithm() {
    let (relation, witness) = translated_discrete_logarithm(Scalar::random(&mut OsRng));

    // The SigmaProtocol induced by relation
    let protocol = SchnorrProof::from(relation);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-translated-schnorr";
    let nizk = Nizk::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut OsRng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut OsRng).unwrap();
    // Verify proofs
    assert!(
        nizk.verify_batchable(&proof_batchable_bytes).is_ok(),
        "Fiat-Shamir Schnorr proof verification failed"
    );
    assert!(
        nizk.verify_compact(&proof_compact_bytes).is_ok(),
        "Fiat-Shamir Schnorr proof verification failed"
    );
}

#[test]
fn noninteractive_dleq() {
    let (relation, witness) = dleq(G::random(&mut OsRng), Scalar::random(&mut OsRng));

    // The SigmaProtocol induced by relation
    let protocol = SchnorrProof::from(relation);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-DLEQ";
    let nizk = Nizk::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut OsRng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut OsRng).unwrap();
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
fn noninteractive_translated_dleq() {
    let (relation, witness) = translated_dleq(G::random(&mut OsRng), Scalar::random(&mut OsRng));

    // The SigmaProtocol induced by relation
    let protocol = SchnorrProof::from(relation);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-translated-DLEQ";
    let nizk = Nizk::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut OsRng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut OsRng).unwrap();
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
    let (relation, witness) = pedersen_commitment(
        G::random(&mut OsRng),
        Scalar::random(&mut OsRng),
        Scalar::random(&mut OsRng),
    );

    // The SigmaProtocol induced by relation
    let protocol = SchnorrProof::from(relation);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-pedersen-commitment";
    let nizk = Nizk::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut OsRng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut OsRng).unwrap();
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
fn noninteractive_user_specific_linear_combination() {
    let (relation, witness) =
        user_specific_linear_combination(G::random(&mut OsRng), Scalar::random(&mut OsRng));

    // The SigmaProtocol induced by relation
    let protocol = SchnorrProof::from(relation);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-user-specific-linear-combination";
    let nizk = Nizk::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut OsRng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut OsRng).unwrap();
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
    let (relation, witness) = pedersen_commitment_dleq(
        (0..4)
            .map(|_| G::random(&mut OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..2)
            .map(|_| Scalar::random(&mut OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );

    // The SigmaProtocol induced by relation
    let protocol = SchnorrProof::from(relation);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-pedersen-commitment-DLEQ";
    let nizk = Nizk::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut OsRng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut OsRng).unwrap();
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
    let (relation, witness) = bbs_blind_commitment_computation(
        (0..4)
            .map(|_| G::random(&mut OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..3)
            .map(|_| Scalar::random(&mut OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        Scalar::random(&mut OsRng),
    );

    // The SigmaProtocol induced by relation
    let protocol = SchnorrProof::from(relation);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-bbs-blind-commitment-computation";
    let nizk = Nizk::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut OsRng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut OsRng).unwrap();
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
