use bls12_381::G1Projective as Bls12381G1;
use group::prime::PrimeGroup;
use p256::ProjectivePoint as P256ProjectivePoint;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};
use subtle::ConstantTimeEq;

use sigma_proofs::{
    linear_relation::{CanonicalLinearRelation, ScalarMap},
    MultiScalarMul, Nizk,
};

mod spec;
use spec::{rng::proof_generation_rng, vectors::TestVector};

#[test]
fn test_spec_vectors_p256() {
    testvectors::<P256ProjectivePoint>(include_str!(
        "./spec/testdata/sigma-proofs_Shake128_P256.json"
    ));
}

#[test]
fn test_spec_vectors_bls12381() {
    testvectors::<Bls12381G1>(include_str!(
        "./spec/testdata/sigma-proofs_Shake128_BLS12381.json"
    ));
}

fn decode_scalars<G>(bytes: &[u8]) -> Vec<G::Scalar>
where
    G: PrimeGroup,
    G::Scalar: NargDeserialize,
{
    let mut cursor = bytes;
    let mut scalars = Vec::new();
    while !cursor.is_empty() {
        scalars.push(
            G::Scalar::deserialize_from_narg(&mut cursor).expect("failed to deserialize scalar"),
        );
    }
    scalars
}

fn testvectors<G>(vectors_json: &str)
where
    G: PrimeGroup
        + ConstantTimeEq
        + Encoding<[u8]>
        + NargSerialize
        + NargDeserialize
        + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let test_vectors: Vec<TestVector> = serde_json::from_str(vectors_json)
        .map_err(|e| format!("JSON parsing error: {e}"))
        .unwrap();

    for vector in test_vectors {
        let test_name = vector.relation;
        let parsed_instance = CanonicalLinearRelation::<G>::from_label(&vector.statement.0)
            .expect("failed to parse statement");

        let witness_vec = decode_scalars::<G>(&vector.witness.0);
        assert_eq!(
            witness_vec.len(),
            parsed_instance.scalar_vars.len(),
            "witness length doesn't match instance scalars",
        );
        let witness: ScalarMap<G> = itertools::zip_eq(
            parsed_instance.scalar_vars.iter().copied(),
            witness_vec.iter().copied(),
        )
        .collect();

        assert_eq!(
            parsed_instance.label(),
            vector.statement.0,
            "parsed statement doesn't match original for {test_name}"
        );

        let nizk = Nizk::new(&vector.session_id.0, parsed_instance);

        assert!(
            nizk.verify_batchable(&vector.batchable_proof.0).is_ok(),
            "batchable proof from vectors did not verify for {test_name}"
        );
        assert!(
            nizk.verify_compact(&vector.proof.0).is_ok(),
            "compact proof from vectors did not verify for {test_name}"
        );

        let mut proof_rng = proof_generation_rng::<G>(2 * witness.len());
        let batchable_proof = nizk.prove_batchable(&witness, &mut proof_rng).unwrap();
        assert_eq!(
            batchable_proof, vector.batchable_proof.0,
            "batchable proof bytes do not match for {test_name}"
        );

        let compact_proof = nizk.prove_compact(&witness, &mut proof_rng).unwrap();
        assert_eq!(
            compact_proof, vector.proof.0,
            "compact proof bytes do not match for {test_name}"
        );
    }
}
