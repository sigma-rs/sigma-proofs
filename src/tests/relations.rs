use bls12_381::{G1Projective as G, Scalar};
use group::{ff::Field, Group};
use rand::rngs::OsRng;

use crate::fiat_shamir::Nizk;
use crate::tests::test_utils::{
    bbs_blind_commitment_computation, discrete_logarithm, dleq, pedersen_commitment,
    pedersen_commitment_dleq, shifted_discrete_logarithm, shifted_dleq,
    user_specific_linear_combination,
};
use crate::{codec::Shake128DuplexSponge, schnorr_protocol::SchnorrProof, LinearRelation};

/// Generic helper function to test both relation correctness and NIZK functionality
fn test_relation_and_nizk<F>(relation_generator: F, test_name: &str)
where
    F: Fn() -> (LinearRelation<G>, Vec<Scalar>),
{
    let (relation, witness) = relation_generator();

    // Test the relation itself by computing its image
    let image_result = relation.image();
    assert!(image_result.is_ok(), "Failed to compute relation image for {}", test_name);

    // Test the NIZK protocol
    let protocol = SchnorrProof::from(relation);
    let domain_sep = format!("test-fiat-shamir-{}", test_name).as_bytes().to_vec();
    let nizk = Nizk::<SchnorrProof<G>, Shake128DuplexSponge<G>>::new(&domain_sep, protocol);

    // Test both proof types
    let proof_batchable = nizk.prove_batchable(&witness, &mut OsRng)
        .expect(&format!("Failed to create batchable proof for {}", test_name));
    let proof_compact = nizk.prove_compact(&witness, &mut OsRng)
        .expect(&format!("Failed to create compact proof for {}", test_name));

    // Verify both proof types
    assert!(
        nizk.verify_batchable(&proof_batchable).is_ok(),
        "Batchable proof verification failed for {}", test_name
    );
    assert!(
        nizk.verify_compact(&proof_compact).is_ok(),
        "Compact proof verification failed for {}", test_name
    );
}

#[test]
fn test_discrete_logarithm() {
    test_relation_and_nizk(
        || discrete_logarithm(Scalar::random(&mut OsRng)),
        "discrete-logarithm"
    );
}

#[test]
fn test_shifted_discrete_logarithm() {
    test_relation_and_nizk(
        || shifted_discrete_logarithm(Scalar::random(&mut OsRng)),
        "shifted-discrete-logarithm"
    );
}

#[test]
fn test_dleq() {
    test_relation_and_nizk(
        || dleq(G::random(&mut OsRng), Scalar::random(&mut OsRng)),
        "dleq"
    );
}

#[test]
fn test_shifted_dleq() {
    test_relation_and_nizk(
        || shifted_dleq(G::random(&mut OsRng), Scalar::random(&mut OsRng)),
        "shifted-dleq"
    );
}

#[test]
fn test_pedersen_commitment() {
    test_relation_and_nizk(
        || pedersen_commitment(
            G::random(&mut OsRng),
            Scalar::random(&mut OsRng),
            Scalar::random(&mut OsRng),
        ),
        "pedersen-commitment"
    );
}

#[test]
fn test_user_specific_linear_combination() {
    test_relation_and_nizk(
        || user_specific_linear_combination(G::random(&mut OsRng), Scalar::random(&mut OsRng)),
        "user-specific-linear-combination"
    );
}

#[test]
fn test_pedersen_commitment_dleq() {
    test_relation_and_nizk(
        || pedersen_commitment_dleq(
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
        ),
        "pedersen-commitment-dleq"
    );
}

#[test]
fn test_bbs_blind_commitment_computation() {
    test_relation_and_nizk(
        || bbs_blind_commitment_computation(
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
        ),
        "bbs-blind-commitment-computation"
    );
}