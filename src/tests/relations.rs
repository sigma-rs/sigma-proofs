use bls12_381::{G1Projective as G, Scalar};
use rand::rngs::OsRng;

use crate::fiat_shamir::Nizk;
use crate::tests::test_utils::{
    bbs_blind_commitment, discrete_logarithm, dleq, pedersen_commitment, pedersen_commitment_dleq,
    shifted_discrete_logarithm, shifted_dleq, user_specific_linear_combination,
};
use crate::{
    codec::Shake128DuplexSponge, linear_relation::CanonicalLinearRelation,
    schnorr_protocol::SchnorrProof,
};

/// Generic helper function to test both relation correctness and NIZK functionality
fn test_relation_and_nizk<F>(relation_generator: F, test_name: &str)
where
    F: Fn(&mut OsRng) -> (CanonicalLinearRelation<G>, Vec<Scalar>),
{
    let mut rng = OsRng;
    let (canonical_relation, witness) = relation_generator(&mut rng);

    // Test the NIZK protocol
    let protocol = SchnorrProof(canonical_relation);
    let domain_sep = format!("test-fiat-shamir-{}", test_name)
        .as_bytes()
        .to_vec();
    let nizk = Nizk::<SchnorrProof<G>, Shake128DuplexSponge<G>>::new(&domain_sep, protocol);

    // Test both proof types
    let proof_batchable = nizk.prove_batchable(&witness, &mut OsRng).expect(&format!(
        "Failed to create batchable proof for {}",
        test_name
    ));
    let proof_compact = nizk
        .prove_compact(&witness, &mut OsRng)
        .expect(&format!("Failed to create compact proof for {}", test_name));

    // Verify both proof types
    assert!(
        nizk.verify_batchable(&proof_batchable).is_ok(),
        "Batchable proof verification failed for {}",
        test_name
    );
    assert!(
        nizk.verify_compact(&proof_compact).is_ok(),
        "Compact proof verification failed for {}",
        test_name
    );
}

#[test]
fn test_discrete_logarithm() {
    test_relation_and_nizk(|rng| discrete_logarithm::<G, _>(rng), "discrete-logarithm");
}

#[test]
fn test_shifted_discrete_logarithm() {
    test_relation_and_nizk(
        |rng| shifted_discrete_logarithm::<G, _>(rng),
        "shifted-discrete-logarithm",
    );
}

#[test]
fn test_dleq() {
    test_relation_and_nizk(|rng| dleq::<G, _>(rng), "dleq");
}

#[test]
fn test_shifted_dleq() {
    test_relation_and_nizk(|rng| shifted_dleq::<G, _>(rng), "shifted-dleq");
}

#[test]
fn test_pedersen_commitment() {
    test_relation_and_nizk(
        |rng| pedersen_commitment::<G, _>(rng),
        "pedersen-commitment",
    );
}

#[test]
fn test_user_specific_linear_combination() {
    test_relation_and_nizk(
        |rng| user_specific_linear_combination::<G, _>(rng),
        "user-specific-linear-combination",
    );
}

#[test]
fn test_pedersen_commitment_dleq() {
    test_relation_and_nizk(
        |rng| pedersen_commitment_dleq::<G, _>(rng),
        "pedersen-commitment-dleq",
    );
}

#[test]
fn test_bbs_blind_commitment_computation() {
    test_relation_and_nizk(
        |rng| bbs_blind_commitment::<G, _>(rng),
        "bbs-blind-commitment-computation",
    );
}
