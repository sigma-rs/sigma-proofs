mod relations;

use bls12_381::G1Projective as G;
use relations::*;
use sigma_proofs::linear_relation::CanonicalLinearRelation;

#[test]
fn test_batch_verify_empty() {
    assert!(CanonicalLinearRelation::<G>::verify_batch(&[]).is_ok());
}

#[test]
fn test_batch_verify_matches_individual() {
    let mut rng = rand::thread_rng();
    let (relation, witness) = discrete_logarithm(&mut rng);
    let nizk = relation.into_nizk(b"batch-test").unwrap();

    let proofs = (0..5)
        .map(|_| nizk.prove_batchable(&witness, &mut rng).unwrap())
        .collect::<Vec<_>>();
    let proof_refs: Vec<_> = proofs.iter().map(|p| (&nizk, p.as_slice())).collect();

    CanonicalLinearRelation::<G>::verify_batch(&proof_refs).unwrap();

    for proof in &proofs {
        assert!(nizk.verify_batchable(proof).is_ok());
    }
}

#[test]
fn test_batch_verify_multi_constraint() {
    let mut rng = rand::thread_rng();
    let (relation, witness) = dleq(&mut rng);
    let nizk = relation.into_nizk(b"batch-dleq").unwrap();

    let proofs = (0..4)
        .map(|_| nizk.prove_batchable(&witness, &mut rng).unwrap())
        .collect::<Vec<_>>();
    let proof_refs: Vec<_> = proofs.iter().map(|p| (&nizk, p.as_slice())).collect();

    CanonicalLinearRelation::<G>::verify_batch(&proof_refs).unwrap();
}

#[test]
fn test_batch_verify_different_instances() {
    let mut rng = rand::thread_rng();

    let relation_samplers: Vec<(_, &'static dyn Fn(&mut _) -> _)> = vec![
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
        ("elgamal_subtraction", &elgamal_subtraction),
    ];

    let proof_data = relation_samplers
        .iter()
        .map(|(_, relation_sampler)| {
            let (relation, witness) = relation_sampler(&mut rng);
            let nizk = relation.into_nizk(b"session_identifier").unwrap();
            let proof = nizk.prove_batchable(&witness, &mut rng).unwrap();
            (nizk, proof)
        })
        .collect::<Vec<_>>();

    let proofs = proof_data
        .iter()
        .map(|(nizk, proof)| (nizk, proof.as_slice()))
        .collect::<Vec<_>>();
    CanonicalLinearRelation::<G>::verify_batch(&proofs).unwrap();
}
