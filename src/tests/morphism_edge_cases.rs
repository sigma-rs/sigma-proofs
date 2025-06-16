use bls12_381::{G1Projective as G, Scalar};
use group::{ff::Field, Group};
use rand::rngs::OsRng;

use crate::{
    codec::ShakeCodec, fiat_shamir::NISigmaProtocol, linear_relation::LinearRelation, schnorr_protocol::SchnorrProof, tests::test_utils::discrete_logarithm
};

/// Test the edge-cases where the witness is zero
#[test]
fn zero_scalar_witness_discrete_log() {
    // Same test as a regular dlog but the witness is set to zero
    let zero_witness = Scalar::ZERO;
    let mut rng = OsRng;
    
    let (morphismp, witness) = discrete_logarithm(zero_witness);
    
    // The SigmaProtocol induced by morphismp
    let protocol = SchnorrProof::from(morphismp);
    // Fiat-Shamir wrapper
    let domain_sep = b"test-fiat-shamir-zero-witness";
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

/// Test the edge-cases where the group generator is the zero
#[test]
fn zero_generator_discrete_log() {
    let mut rng = OsRng;

    // Same test as a regular dlog but the source element is set to zero (additive identity)
    let x = Scalar::random(&mut rng);
    let G = G::identity();

    let (morphismp, witness) = {
        let mut morphismp: LinearRelation<G> = LinearRelation::new();

    let var_x = morphismp.allocate_scalar();
    let var_G = morphismp.allocate_element();

    let var_X = morphismp.allocate_eq(var_x * var_G);

    morphismp.set_element(var_G, G);
    morphismp.compute_image(&[x]).unwrap();

    let X = morphismp.linear_map.group_elements.get(var_X).unwrap();

    assert_eq!(X, G * x);
    (morphismp, vec![x])
    };

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

/// Test the edge-case of a Pedersen commitment where every scalar and group element is zero
#[test]
fn fully_zero_pedersen_commitment() {
    let mut rng = OsRng;

    // Same test as a regular pedersen commitment but both scalars and both group elements are set to zero (additive identity)
    let x = Scalar::ZERO;
    let r = Scalar::ZERO;
    let G = Group::identity();
    let H = Group::identity();


    let (morphismp, witness) = {
        let mut cs: LinearRelation<G> = LinearRelation::new();

        let [var_x, var_r] = cs.allocate_scalars();
        let [var_G, var_H] = cs.allocate_elements();

        let var_C = cs.allocate_eq(var_x * var_G + var_r * var_H);

        cs.set_elements([(var_H, H), (var_G, G)]);
        cs.compute_image(&[x, r]).unwrap();

        let C = cs.linear_map.group_elements.get(var_C).unwrap();

        let witness = vec![x, r];
        assert_eq!(C, G * x + H * r);
        (cs, witness)
    };

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

/// Test the edge-case of a Pedersen commitment where the second group element is zero (functionally the commitment becomes x * G + 0)
#[test]
fn partial_zero_pedersen_commitment() {
    let mut rng = OsRng;

    // Same test as a regular pedersen commitment except the second group element is zero (additive identity)
    let x = Scalar::random(&mut rng);
    let r = Scalar::random(&mut rng);
    let G = Group::generator();
    let H = Group::identity();


    let (morphismp, witness) = {
        let mut cs: LinearRelation<G> = LinearRelation::new();

        let [var_x, var_r] = cs.allocate_scalars();
        let [var_G, var_H] = cs.allocate_elements();

        let var_C = cs.allocate_eq(var_x * var_G + var_r * var_H);

        cs.set_elements([(var_H, H), (var_G, G)]);
        cs.compute_image(&[x, r]).unwrap();

        let C = cs.linear_map.group_elements.get(var_C).unwrap();

        let witness = vec![x, r];
        assert_eq!(C, G * x + H * r);
        (cs, witness)
    };

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
