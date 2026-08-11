#[allow(dead_code)]
mod relations;

use bls12_381::G1Projective as G;
use relations::*;
use sigma_proofs::linear_relation::Instance;
use sigma_proofs::{
    derive_session_id, prove_batchable, verify_batch, verify_batchable, ProverRng, StdHash,
};

const TAG: &[u8] = b"batch verification tests DSFS";

#[test]
fn empty_batch_verifies() {
    assert!(verify_batch::<G>(&[]).is_ok());
}

#[test]
fn mixed_batch_verifies() {
    let mut rng = ProverRng::from_os_entropy();
    let samplers: [&dyn Fn(&mut _) -> _; 4] = [
        &discrete_logarithm,
        &dleq,
        &pedersen_commitment,
        &nested_affine_relation,
    ];
    let session_id = derive_session_id::<StdHash>(TAG);
    let proof_data = samplers
        .iter()
        .flat_map(|sample| {
            let (instance, witness): (Instance<G>, _) = sample(&mut rng);
            (0..2).map(move |_| {
                let proof = prove_batchable(TAG, &instance, &witness).unwrap();
                (instance.clone(), proof)
            })
        })
        .collect::<Vec<_>>();
    let batch = proof_data
        .iter()
        .map(|(instance, proof)| (&session_id, instance, proof.as_slice()))
        .collect::<Vec<_>>();

    verify_batch(&batch).unwrap();
}

#[test]
fn batch_and_individual_verification_reject_the_same_tampering() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness): (Instance<G>, _) = dleq(&mut rng);
    let session_id = derive_session_id::<StdHash>(TAG);
    let good = prove_batchable(TAG, &instance, &witness).unwrap();
    let mut tampered = good.clone();
    tampered[0] ^= 1;

    assert!(verify_batchable(TAG, &instance, &tampered).is_err());
    assert!(verify_batch(&[
        (&session_id, &instance, good.as_slice()),
        (&session_id, &instance, tampered.as_slice()),
    ])
    .is_err());
}

#[test]
fn batch_rejects_a_proof_with_the_wrong_session_or_instance() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = discrete_logarithm::<G>(&mut rng);
    let (other_instance, _) = discrete_logarithm::<G>(&mut rng);
    let proof = prove_batchable(TAG, &instance, &witness).unwrap();
    let session_id = derive_session_id::<StdHash>(TAG);
    let other_session_id = derive_session_id::<StdHash>(b"other batch verification tag DSFS");

    assert!(verify_batch(&[(&other_session_id, &instance, proof.as_slice())]).is_err());
    assert!(verify_batch(&[(&session_id, &other_instance, proof.as_slice())]).is_err());
}

#[test]
fn batch_rejects_trailing_bytes() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = discrete_logarithm::<G>(&mut rng);
    let session_id = derive_session_id::<StdHash>(TAG);
    let mut proof = prove_batchable(TAG, &instance, &witness).unwrap();
    proof.push(0);

    assert!(verify_batch(&[(&session_id, &instance, proof.as_slice())]).is_err());
}
