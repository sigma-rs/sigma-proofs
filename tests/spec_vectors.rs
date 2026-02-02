use bls12_381::G1Projective as BLS12381_Group;
use group::prime::PrimeGroup;
use p256::ProjectivePoint as P256_Group;
use spongefish::{Codec, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::{linear_relation::CanonicalLinearRelation, MultiScalarMul, Nizk};

mod spec;
use spec::{rng::MockScalarRng, vectors::TestVector};

#[test]
fn test_spec_testvectors_bls12381() {
    let vectors_json = include_str!("./spec/testdata/Schnorr_KeccakDuplexSponge_Bls12381.json");
    testvectors::<BLS12381_Group>(vectors_json);
}

#[test]
fn test_spec_testvectors_bls12381_rust() {
    let vectors_json =
        include_str!("./spec/testdata/rust_Schnorr_KeccakDuplexSponge_Bls12381.json");
    testvectors::<BLS12381_Group>(vectors_json);
}

#[test]
fn test_spec_testvectors_p256() {
    let vectors_json = include_str!("./spec/testdata/Schnorr_KeccakDuplexSponge_P256.json");
    testvectors::<P256_Group>(vectors_json);
}

#[test]
fn test_spec_testvectors_p256_rust() {
    let vectors_json = include_str!("./spec/testdata/rust_Schnorr_KeccakDuplexSponge_P256.json");
    testvectors::<P256_Group>(vectors_json);
}

fn testvectors<G>(vectors_json: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Codec,
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
            .map(|h| G::Scalar::deserialize_from_narg(&mut h.0.as_slice()).unwrap())
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

        // Commitment_response format
        {
            // Verify that the computed IV matches the test vector IV
            // Ensure the provided test vector proof verifies.
            let verification_result = nizk.verify_batchable(&vector.proof_comm_resp.0);
            assert!(
                verification_result.is_ok(),
                "Fiat-Shamir Schnorr proof from vectors did not verify for {test_name}: {verification_result:?}"
            );

            // Generate proof with the proof generation RNG
            let randomness_comm_resp = vector.randomness_comm_resp.into_iter().map(|h| h.0);
            let mut proof_rng_comm_resp = MockScalarRng(randomness_comm_resp);
            let proof_batchable = nizk
                .prove_batchable(&witness, &mut proof_rng_comm_resp)
                .unwrap();

            // Verify the proof matches
            assert_eq!(
                proof_batchable, vector.proof_comm_resp.0,
                "proof bytes for test vector {test_name} do not match"
            );

            // Verify the proof is valid
            let verified = nizk.verify_batchable(&proof_batchable).is_ok();
            assert!(
                verified,
                "Fiat-Shamir Schnorr proof verification failed for {test_name}"
            );
        }

        // Challenge_response format
        {
            // Verify that the computed IV matches the test vector IV
            // Ensure the provided test vector proof verifies.
            let verification_result = nizk.verify_compact(&vector.proof_chal_resp.0);
            assert!(
            verification_result.is_ok(),
                "Fiat-Shamir Schnorr proof from vectors did not verify for {test_name}: {verification_result:?}"
            );

            // Generate proof with the proof generation RNG
            let randomness_chal_resp = vector.randomness_chal_resp.into_iter().map(|h| h.0);
            let mut proof_rng_chal_resp = MockScalarRng(randomness_chal_resp);
            let proof_compact = nizk
                .prove_compact(&witness, &mut proof_rng_chal_resp)
                .unwrap();

            // Verify the proof matches
            assert_eq!(
                hex::encode(&proof_compact),
                hex::encode(vector.proof_chal_resp.0),
                "proof bytes for test vector {test_name} do not match"
            );

            // Verify the proof is valid
            let verified = nizk.verify_compact(&proof_compact).is_ok();
            assert!(
                verified,
                "Fiat-Shamir Schnorr proof verification failed for {test_name}"
            );
        }
    }
}
