use bls12_381::{G1Projective as G, Scalar};
use group::{ff::Field, Group};
use rand::rngs::OsRng;

use crate::fiat_shamir::NISigmaProtocol;
use crate::tests::test_utils::{
    bbs_blind_commitment_computation, discrete_logarithm, dleq, dleq_generalized,
    pedersen_commitment, pedersen_commitment_dleq, pedersen_commitment_generalized,
    pedersen_commitment_multi_equation, pedersen_commitment_multiplication,
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
fn test_diffie_hellman() {
    let mut rng = OsRng;

    let private_key_a = Scalar::random(&mut rng); // Diffie-Hellman private key a is known to prover
    let public_key_b = G::random(&mut rng); // Diffie-Hellman public key B is known to prover, but not its secret key b

    dleq(public_key_b, private_key_a);
}

#[test]
fn test_dleq_generalized() {
    let mut rng = OsRng;

    // Generate a random scalar witness x
    let x = Scalar::random(&mut rng);

    // Generate a vector of random basepoints H_i
    let bases: Vec<G> = (0..4).map(|_| G::random(&mut rng)).collect();

    // Build the generalized DLEQ relation and witness
    dleq_generalized(&bases, x);
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
fn test_pedersen_commitment_generalized() {
    let mut rng = OsRng;

    // Generate random additional basepoints (e.g., 3 Hᵢ)
    let additional_generators: Vec<G> = (0..3).map(|_| G::random(&mut rng)).collect();

    // Generate a random secret and random blindings
    let x = Scalar::random(&mut rng);
    let blindings: Vec<Scalar> = (0..3).map(|_| Scalar::random(&mut rng)).collect();

    // Construct the morphism and witness
    pedersen_commitment_generalized(&additional_generators, x, &blindings);
}

#[test]
fn test_set_of_pedersen_commitments() {
    let mut rng = OsRng;

    let x = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);
    let r3 = Scalar::random(&mut rng);

    let H1 = G::random(&mut rng);
    let H2 = G::random(&mut rng);
    let H3 = G::random(&mut rng);

    let commitment_terms = vec![
        vec![H1, H2], // c1 = x·G + r1·H1 + r2·H2
        vec![H1, H3], // c2 = x·G + r1·H1 + r3·H3
    ];

    pedersen_commitment_multi_equation(G::generator(), &commitment_terms, x, &[r1, r2, r3]);
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
fn test_pedersen_commitment_multiplication() {
    let mut rng = OsRng;

    let G = G::generator();
    let H = G::random(&mut rng);

    // First, commit to `b` via a regular Pedersen commitment to get B = b * G + r_3 * H
    let b = Scalar::random(&mut rng);
    let r3 = Scalar::random(&mut rng);
    let (b_commitment_morphism, b_witness) = pedersen_commitment(H, b, r3);

    // We only need the committed value B = b * G + r_3 * H
    let B = b_commitment_morphism
        .linear_map
        .evaluate(&b_witness)
        .unwrap()[0];

    // Create target commitment values
    let x = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);

    pedersen_commitment_multiplication(G, B, H, x, r1, r2);
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
fn noninteractive_diffie_hellman() {
    let mut rng = OsRng;

    let private_key_a = Scalar::random(&mut rng); // Diffie-Hellman private key a is known to prover
    let public_key_b = G::random(&mut rng); // Diffie-Hellman public key B is known to prover, but not its secret key b

    let (morphismp, witness) = dleq(public_key_b, private_key_a);

    // The SigmaProtocol induced by morphismp
    let protocol = SchnorrProof::from(morphismp);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-diffie-hellman";
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
fn noninteractive_dleq_generalized() {
    let mut rng = OsRng;

    // Sample random scalar witness
    let x = Scalar::random(&mut rng);

    // Generate H₁..Hₙ basepoints
    let bases: Vec<G> = (0..4).map(|_| G::random(&mut rng)).collect();

    // Build the generalized DLEQ relation
    let (morphismp, witness) = dleq_generalized(&bases, x);

    // The SigmaProtocol induced by the morphism
    let protocol = SchnorrProof::from(morphismp);

    // Fiat-Shamir transformation
    let domain_sep = b"test-fiat-shamir-generalized-DLEQ";
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Create both batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();

    // Verify both
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();

    assert!(
        verified_batchable,
        "Fiat-Shamir generalized DLEQ batchable proof verification failed"
    );
    assert!(
        verified_compact,
        "Fiat-Shamir generalized DLEQ compact proof verification failed"
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
fn noninteractive_pedersen_commitment_generalized() {
    let mut rng = OsRng;

    // Generate random basepoints H₁..Hₙ (e.g., 3 here)
    let additional_generators: Vec<G> = (0..3).map(|_| G::random(&mut rng)).collect();

    // Secret x and blindings r₁..rₙ
    let x = Scalar::random(&mut rng);
    let blindings: Vec<Scalar> = (0..3).map(|_| Scalar::random(&mut rng)).collect();

    // Build the morphism and witness vector
    let (morphismp, witness) =
        pedersen_commitment_generalized(&additional_generators, x, &blindings);

    // The SigmaProtocol induced by the morphism
    let protocol = SchnorrProof::from(morphismp);

    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-generalized-pedersen-commitment";
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();

    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();

    assert!(
        verified_batchable,
        "Fiat-Shamir generalized Pedersen proof (batchable) verification failed"
    );
    assert!(
        verified_compact,
        "Fiat-Shamir generalized Pedersen proof (compact) verification failed"
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
fn noninteractive_pedersen_commitment_generalized_multi_equation() {
    let mut rng = OsRng;

    // Secret value and blindings
    let x = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);
    let r3 = Scalar::random(&mut rng);

    // Generators
    let H1 = G::random(&mut rng);
    let H2 = G::random(&mut rng);
    let H3 = G::random(&mut rng);

    // Each inner vec defines one commitment equation
    let commitment_terms = vec![
        vec![H1, H2], // c1 = x·G + r1·H1 + r2·H2
        vec![H1, H3], // c2 = x·G + r1·H1 + r3·H3
    ];

    let (morphismp, witness) =
        pedersen_commitment_multi_equation(G::generator(), &commitment_terms, x, &[r1, r2, r3]);

    // The SigmaProtocol induced by the morphism
    let protocol = SchnorrProof::from(morphismp);

    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-pedersen-multi-equation";
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();

    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();

    assert!(
        verified_batchable,
        "Fiat-Shamir multi-equation Pedersen proof (batchable) verification failed"
    );
    assert!(
        verified_compact,
        "Fiat-Shamir multi-equation Pedersen proof (compact) verification failed"
    );
}

#[test]
fn noninteractive_pedersen_commitment_multiplication() {
    let mut rng = OsRng;

    let G = G::generator();
    let H = G::random(&mut rng);

    // Produce B = b * G + r_3 * H using regular Pedersen commitment
    let b = Scalar::random(&mut rng);
    let r3 = Scalar::random(&mut rng);
    let (b_commitment_morphism, b_witness) = pedersen_commitment(H, b, r3);
    let B = b_commitment_morphism
        .linear_map
        .evaluate(&b_witness)
        .unwrap()[0];

    // Secret values for which we prove relations
    let x = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);

    let (morphismp, witness) = pedersen_commitment_multiplication(G, B, H, x, r1, r2);

    // Wrap in SchnorrProof and Fiat-Shamir
    let protocol = SchnorrProof::from(morphismp);
    let domain_sep = b"test-fiat-shamir-pedersen-multiplication";
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(domain_sep, protocol);

    let proof_batchable = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact = nizk.prove_compact(&witness, &mut rng).unwrap();

    let verified_batchable = nizk.verify_batchable(&proof_batchable).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact).is_ok();

    assert!(
        verified_batchable,
        "Fiat-Shamir multiplication proof (batchable) verification failed"
    );
    assert!(
        verified_compact,
        "Fiat-Shamir multiplication proof (compact) verification failed"
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
