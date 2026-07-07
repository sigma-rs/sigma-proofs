mod relations;

use bls12_381::G1Projective as G;
use relations::*;
use sigma_proofs::linear_relation::CanonicalLinearRelation;

// Empty batches are valid, per the spec.
#[test]
fn test_batch_verify_empty() {
    assert!(CanonicalLinearRelation::<G>::verify_batch(&[]).is_ok());
}

#[test]
fn test_batch_verify_different_instances() {
    let mut rng = rand::thread_rng();

    let relation_samplers: Vec<&'static dyn Fn(&mut _) -> _> = vec![
        &discrete_logarithm,
        &shifted_dlog,
        &dleq,
        &shifted_dleq,
        &pedersen_commitment,
        &twisted_pedersen_commitment,
        &pedersen_commitment_equality,
        &bbs_blind_commitment,
        &test_range,
        &weird_linear_combination,
        &simple_subtractions,
        &subtractions_with_shift,
        &cmz_wallet_spend_relation,
        &nested_affine_relation,
        &elgamal_subtraction,
    ];

    let proof_data = relation_samplers
        .iter()
        .enumerate()
        .map(|(i, relation_sampler)| {
            let (relation, witness) = relation_sampler(&mut rng);
            let nizk = relation.into_nizk(b"session_identifier").unwrap();
            // Two proofs for the first instance, so that the batch also
            // covers repeated instances.
            let proofs = (0..if i == 0 { 2 } else { 1 })
                .map(|_| nizk.prove_batchable(&witness, &mut rng).unwrap())
                .collect::<Vec<_>>();
            (nizk, proofs)
        })
        .collect::<Vec<_>>();

    let proofs = proof_data
        .iter()
        .flat_map(|(nizk, proofs)| proofs.iter().map(move |p| (nizk, p.as_slice())))
        .collect::<Vec<_>>();
    CanonicalLinearRelation::<G>::verify_batch(&proofs).unwrap();
}

// Batch verification must agree with individual verification, on both valid
// and corrupted proofs.
#[test]
fn test_batch_verify_agrees_with_individual() {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let samplers: Vec<&'static dyn Fn(&mut _) -> _> = vec![
        &discrete_logarithm,
        &dleq,
        &pedersen_commitment,
        &bbs_blind_commitment,
        &cmz_wallet_spend_relation,
        &nested_affine_relation,
    ];

    for sampler in &samplers {
        let (relation, witness) = sampler(&mut rng);
        let nizk = relation.into_nizk(b"diff-test").unwrap();

        for _ in 0..10 {
            let good = nizk.prove_batchable(&witness, &mut rng).unwrap();
            let mut bad = nizk.prove_batchable(&witness, &mut rng).unwrap();
            let position = rng.gen_range(0..bad.len());
            bad[position] ^= rng.gen_range(1..=u8::MAX);

            let individual_ok = nizk.verify_batchable(&bad).is_ok();
            let batch = [(&nizk, good.as_slice()), (&nizk, bad.as_slice())];
            let batch_ok = CanonicalLinearRelation::<G>::verify_batch(&batch).is_ok();
            assert_eq!(individual_ok, batch_ok);
        }
    }
}
