use std::fs::File;

use bls12_381::G1Projective as BLS12381_Group;
use group::prime::PrimeGroup;
use p256::ProjectivePoint as P256_Group;
use sigma_proofs::{linear_relation::CanonicalLinearRelation, Nizk};
use spongefish::{Codec, Encoding, NargDeserialize, NargSerialize};

mod spec;
use spec::{
    rng::{SeededScalarRng, TracingScalarRng},
    vectors::{Hex, TestVector},
};

mod relations;
use relations::*;

const TEST_VECTOR_PATH: &str = "./tests/spec/testdata/";

#[allow(clippy::type_complexity)]
#[allow(non_snake_case)]
#[test]
fn test_spec_create_testvectors() {
    const ENV_VAR: &str = "GENERATE_TEST_VECTORS";
    if !std::env::var(ENV_VAR).is_ok_and(|x| x == "true") {
        println!("Set environment variable {ENV_VAR}=true to generate test vectors");
        return;
    }

    create_testvectors::<BLS12381_Group>("Schnorr_KeccakDuplexSponge_Bls12381");
    create_testvectors::<P256_Group>("Schnorr_KeccakDuplexSponge_P256");
}

fn create_testvectors<G>(ciphersuite: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Codec,
{
    let instance_generation_rng_seed = b"instance_witness_generation_seed";
    let proof_chal_resp_seed = b"proving-method-challenge-response-format";
    let proof_comm_resp_seed = b"proving-method-commitment-response-format";
    let session_id = b"session_identifier";

    let instance_generators: Vec<(_, &'static dyn Fn(&mut _) -> _)> = vec![
        ("discrete_logarithm", &discrete_logarithm),
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
    let mut test_vectors = Vec::new();

    for (name, generator_fn) in instance_generators {
        let instance_rng = &mut SeededScalarRng::from_seed(instance_generation_rng_seed);
        let (statement, witness) = generator_fn(instance_rng);
        let nizk = Nizk::<CanonicalLinearRelation<G>>::new(session_id, statement.clone());

        let (randomness_chal_resp, proof_chal_resp) = {
            let mut proof_chal_resp_rng =
                TracingScalarRng::new(SeededScalarRng::from_seed(proof_chal_resp_seed));
            let proof_chal_resp = nizk
                .prove_compact(&witness, &mut proof_chal_resp_rng)
                .unwrap();
            let is_valid = nizk.verify_compact(&proof_chal_resp).is_ok();
            assert!(is_valid);
            let randomness_chal_resp = proof_chal_resp_rng.collect().into_iter().map(Hex).collect();

            (randomness_chal_resp, Hex(proof_chal_resp))
        };

        let (randomness_comm_resp, proof_comm_resp) = {
            let mut proof_comm_resp_rng =
                TracingScalarRng::new(SeededScalarRng::from_seed(proof_comm_resp_seed));
            let proof_comm_resp = nizk
                .prove_batchable(&witness, &mut proof_comm_resp_rng)
                .unwrap();
            let is_valid = nizk.verify_batchable(&proof_comm_resp).is_ok();
            assert!(is_valid);
            let randomness_comm_resp = proof_comm_resp_rng.collect().into_iter().map(Hex).collect();

            (randomness_comm_resp, Hex(proof_comm_resp))
        };

        test_vectors.push(TestVector {
            protocol: name.into(),
            ciphersuite: ciphersuite.into(),
            hash: "KeccakDuplexSponge".to_string(),
            session_id: Hex(session_id.to_vec()),
            statement: Hex(statement.label()),
            witness: witness
                .into_iter()
                .map(|w| w.encode().as_ref().to_vec())
                .map(Hex)
                .collect(),
            randomness_chal_resp,
            proof_chal_resp,
            randomness_comm_resp,
            proof_comm_resp,
        });
    }

    let filename = format!("{TEST_VECTOR_PATH}/rust_{ciphersuite}.json");
    let file = File::create(filename).unwrap();
    serde_json::to_writer_pretty(file, &test_vectors).unwrap();
}
