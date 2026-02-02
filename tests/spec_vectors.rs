use bls12_381::G1Projective;
use group::{ff::PrimeField, prime::PrimeGroup};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::{linear_relation::CanonicalLinearRelation, Nizk};

mod spec;
use spec::{rng::MockPRNG, vectors::TestVector};

#[test]
fn test_spec_testvectors() {
    type G = G1Projective;
    let vectors_json = include_str!("./spec/testdata/sigma_Keccak1600_BLS12381.json");
    testvectors::<G>(vectors_json);
}

fn testvectors<G>(vectors_json: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let test_vectors: Vec<TestVector> = serde_json::from_str(vectors_json)
        .map_err(|e| format!("JSON parsing error: {e}"))
        .unwrap();

    for vector in test_vectors {
        let test_name = vector.protocol;
        // Parse the statement from the test vector
        let parsed_instance = CanonicalLinearRelation::<G>::from_label(&vector.statement.0)
            .expect("Failed to parse statement");

        // Decode the witness from the test vector
        let witness: Vec<G::Scalar> = vector
            .witness
            .iter()
            .map(|h| {
                let mut scalar = <G::Scalar as PrimeField>::Repr::default();
                scalar.as_mut().copy_from_slice(&h.0);
                <G::Scalar as PrimeField>::from_repr(scalar).unwrap()
            })
            .collect();
        assert_eq!(
            witness.len(),
            parsed_instance.num_scalars,
            "witness length doesn't match instance scalars"
        );

        // Verify the parsed instance can be re-serialized to the same label
        assert_eq!(
            parsed_instance.label(),
            vector.statement.0,
            "parsed statement doesn't match original for {test_name}"
        );

        // Create NIZK with the session_id from the test vector
        let nizk = Nizk::new(&vector.session_id.0, parsed_instance);

        // Verify that the computed IV matches the test vector IV
        // Ensure the provided test vector proof verifies.
        let verification_result = nizk.verify_batchable(&vector.proof_batchable.0);
        assert!(
            verification_result.is_ok(),
            "Fiat-Shamir Schnorr proof from vectors did not verify for {test_name}: {verification_result:?}"
        );

        // Generate proof with the proof generation RNG
        let randomness = vector.randomness.into_iter().map(|h| h.0);
        let mut proof_rng = MockPRNG(randomness);
        let proof_batchable = nizk.prove_batchable(&witness, &mut proof_rng).unwrap();

        // Verify the proof matches
        assert_eq!(
            proof_batchable, vector.proof_batchable.0,
            "proof bytes for test vector {test_name} do not match"
        );

        // Verify the proof is valid
        let verified = nizk.verify_batchable(&proof_batchable).is_ok();
        assert!(
            verified,
            "Fiat-Shamir Schnorr proof verification failed for {test_name}"
        );
    }
}
