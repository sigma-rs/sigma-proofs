use ff::Field;

use sigma_proofs::codec::Shake128DuplexSponge;
use sigma_proofs::linear_relation::{CanonicalLinearRelation, LinearRelation, ScalarMap};
use sigma_proofs::{Allocator, Nizk};

mod relations;
use relations::*;

#[test]
#[allow(non_snake_case)]
fn test_cmz_wallet_with_fee() {
    use group::Group;
    type G = bls12_381::G1Projective;

    let mut rng = rand::thread_rng();

    // This version should fail with InvalidInstanceWitnessPair
    // because it uses a scalar constant directly in the equation
    let P_W = G::random(&mut rng);
    let A = G::random(&mut rng);

    let n_balance = <G as Group>::Scalar::random(&mut rng);
    let i_price = <G as Group>::Scalar::random(&mut rng);
    let _fee = <G as Group>::Scalar::from(5u64);
    let z_w_balance = <G as Group>::Scalar::random(&mut rng);

    let mut relation = LinearRelation::<G>::new();

    let var_n_balance = relation.allocate_scalar();
    let var_i_price = relation.allocate_scalar();
    let var_z_w_balance = relation.allocate_scalar();

    let var_P_W = relation.allocate_element();
    let var_A = relation.allocate_element();

    // This equation has a scalar constant (fee) which causes the error
    let _var_C = relation.allocate_eq(
        (var_n_balance + var_i_price + <G as Group>::Scalar::from(5)) * var_P_W
            + var_z_w_balance * var_A,
    );

    let witness = ScalarMap::from_iter([
        (var_n_balance, n_balance),
        (var_i_price, i_price),
        (var_z_w_balance, z_w_balance),
    ]);

    relation.assign_elements([(var_P_W, P_W), (var_A, A)]);
    relation.compute_image(&witness).unwrap();

    // Try to convert to CanonicalLinearRelation - this should fail
    let nizk = relation.into_nizk(b"session_identifier").unwrap();
    let result = nizk.prove_batchable(witness, &mut rng);
    assert!(result.is_ok());
    let proof = result.unwrap();
    let verify_result = nizk.verify_batchable(&proof);
    assert!(verify_result.is_ok());
}

/// Generic helper function to test both relation correctness and NIZK functionality
#[test]
fn test_relations() {
    type G = bls12_381::G1Projective;

    let instance_generators: Vec<(_, &'static dyn Fn(&mut _) -> _)> = vec![
        ("dlog", &discrete_logarithm),
        ("shifted_dlog", &shifted_dlog),
        ("dleq", &dleq),
        ("shifted_dleq", &shifted_dleq),
        ("pedersen_commitment", &pedersen_commitment),
        ("twisted_pedersen_commitment", &twisted_pedersen_commitment),
        ("pedersen_commitment_dleq", &pedersen_commitment_equality),
        ("bbs_blind_commitment", &bbs_blind_commitment),
        ("test_range", &test_range),
        ("weird_linear_combination", &weird_linear_combination),
        ("simple_subtractions", &simple_subtractions),
        ("subtractions_with_shift", &subtractions_with_shift),
        ("cmz_wallet_spend_relation", &cmz_wallet_spend_relation),
        ("nested_affine_relation", &nested_affine_relation),
        ("elgamal_public_subtract", &elgamal_subtraction),
    ];

    for (relation_name, relation_sampler) in instance_generators.iter() {
        let mut rng = rand::thread_rng();
        let (canonical_relation, witness) = relation_sampler(&mut rng);

        // Test the NIZK protocol
        let domain_sep = format!("test-fiat-shamir-{relation_name}")
            .as_bytes()
            .to_vec();
        let nizk = Nizk::<CanonicalLinearRelation<G>, Shake128DuplexSponge<G>>::new(
            &domain_sep,
            canonical_relation,
        );

        // Test both proof types
        let proof_batchable = nizk
            .prove_batchable(witness.clone(), &mut rng)
            .unwrap_or_else(|_| panic!("Failed to create batchable proof for {relation_name}"));
        let proof_compact = nizk
            .prove_compact(witness, &mut rng)
            .unwrap_or_else(|_| panic!("Failed to create compact proof for {relation_name}"));

        // Verify both proof types
        assert!(
            nizk.verify_batchable(&proof_batchable).is_ok(),
            "Batchable proof verification failed for {relation_name}"
        );
        assert!(
            nizk.verify_compact(&proof_compact).is_ok(),
            "Compact proof verification failed for {relation_name}"
        );
    }
}
