mod relations;

use bls12_381::G1Projective as G;
use relations::*;
use sigma_proofs::linear_relation::CanonicalLinearRelation;

#[test]
fn test_batch_verify_empty() {
    assert!(CanonicalLinearRelation::<G>::verify_batch(&[]).is_ok());
}

#[test]
fn test_batch_verify_same_instance() {
    let mut rng = rand::thread_rng();
    let (relation, witness) = discrete_logarithm(&mut rng);
    let nizk = relation.into_nizk(b"batch-test").unwrap();

    let proofs = (0..5)
        .map(|_| nizk.prove_batchable(&witness, &mut rng).unwrap())
        .collect::<Vec<_>>();
    let proof_refs: Vec<_> = proofs.iter().map(|p| (&nizk, p.as_slice())).collect();

    CanonicalLinearRelation::<G>::verify_batch(&proof_refs).unwrap();
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
        .map(|relation_sampler| {
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

// A single corrupted proof must invalidate the whole batch.
#[test]
fn test_batch_verify_rejects_tampered_proof() {
    let mut rng = rand::thread_rng();
    let (relation, witness) = dleq(&mut rng);
    let nizk = relation.into_nizk(b"batch-neg").unwrap();

    let proofs = (0..3)
        .map(|_| nizk.prove_batchable(&witness, &mut rng).unwrap())
        .collect::<Vec<_>>();

    for position in [5, proofs[1].len() - 1] {
        let mut tampered = proofs.clone();
        tampered[1][position] ^= 1;
        let proof_refs: Vec<_> = tampered.iter().map(|p| (&nizk, p.as_slice())).collect();
        assert!(CanonicalLinearRelation::<G>::verify_batch(&proof_refs).is_err());
    }
}

// A proof made under one session identifier must not verify under another.
#[test]
fn test_batch_verify_rejects_wrong_session() {
    let mut rng = rand::thread_rng();
    let (relation, witness) = discrete_logarithm::<G>(&mut rng);
    let nizk_a = relation.clone().into_nizk(b"session-a").unwrap();
    let nizk_b = relation.into_nizk(b"session-b").unwrap();

    let proof_a = nizk_a.prove_batchable(&witness, &mut rng).unwrap();
    let proof_b = nizk_b.prove_batchable(&witness, &mut rng).unwrap();

    let batch = [(&nizk_b, proof_a.as_slice()), (&nizk_b, proof_b.as_slice())];
    assert!(CanonicalLinearRelation::<G>::verify_batch(&batch).is_err());
}

// A valid proof for one instance must not verify as a proof for another
// instance of the same shape.
#[test]
fn test_batch_verify_rejects_cross_instance_proof() {
    let mut rng = rand::thread_rng();
    let (relation_a, witness_a) = discrete_logarithm::<G>(&mut rng);
    let (relation_b, _) = discrete_logarithm::<G>(&mut rng);
    let nizk_a = relation_a.into_nizk(b"same-session").unwrap();
    let nizk_b = relation_b.into_nizk(b"same-session").unwrap();

    let proof_a = nizk_a.prove_batchable(&witness_a, &mut rng).unwrap();
    let batch = [(&nizk_b, proof_a.as_slice())];
    assert!(CanonicalLinearRelation::<G>::verify_batch(&batch).is_err());
}

// Trailing bytes after a well-formed proof must be rejected.
#[test]
fn test_batch_verify_rejects_trailing_bytes() {
    let mut rng = rand::thread_rng();
    let (relation, witness) = discrete_logarithm::<G>(&mut rng);
    let nizk = relation.into_nizk(b"batch-eof").unwrap();

    let mut proof = nizk.prove_batchable(&witness, &mut rng).unwrap();
    proof.push(0u8);
    let batch = [(&nizk, proof.as_slice())];
    assert!(CanonicalLinearRelation::<G>::verify_batch(&batch).is_err());
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
