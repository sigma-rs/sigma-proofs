use std::fs::File;

use bls12_381::G1Projective;
use group::{ff::PrimeField, prime::PrimeGroup};
use rand_core::SeedableRng;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::{linear_relation::CanonicalLinearRelation, Nizk};

mod spec;
use spec::{
    rng::{Shake128PRNG, TracingPRNG},
    vectors::{Hex, TestVector},
};

mod relations;
use relations::*;

#[allow(clippy::type_complexity)]
#[allow(non_snake_case)]
#[test]
fn test_spec_create_testvectors() {
    const ENV_VAR: &str = "GENERATE_TEST_VECTORS";
    if !std::env::var(ENV_VAR).is_ok_and(|x| x == "true") {
        println!("Set environment variable {ENV_VAR}=true to generate test vectors");
        return;
    }

    type G = G1Projective;
    create_testvectors::<G>("./tests/spec/testdata/sigma_Keccak1600_BLS12381.json");
}

fn create_testvectors<G>(filename: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let instance_generation_rng_seed = *b"secure_instance_generation_seed_";
    let proof_generation_rng_seed = *b"batchable_proof_generation_seed_";
    let ciphersuite = "sigma/OWKeccak1600+Bls12381";
    let session_id = b"session_id";

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
    let mut test_vectors = Vec::new();

    for (name, generator_fn) in instance_generators {
        let instance_rng = &mut Shake128PRNG::from_seed(instance_generation_rng_seed);
        let (statement, witness) = generator_fn(instance_rng);
        let nizk = Nizk::<CanonicalLinearRelation<G>>::new(session_id, statement.clone());

        let proof_rng = Shake128PRNG::from_seed(proof_generation_rng_seed);
        let mut tracing_rng = TracingPRNG::new(proof_rng);
        let proof_batchable = nizk.prove_batchable(&witness, &mut tracing_rng).unwrap();
        let is_valid = nizk.verify_batchable(&proof_batchable).is_ok();
        assert!(is_valid);

        test_vectors.push(TestVector {
            protocol: name.into(),
            session_id: Hex(session_id.to_vec()),
            ciphersuite: ciphersuite.into(),
            statement: Hex(statement.label()),
            witness: witness
                .into_iter()
                .map(|w| w.to_repr().as_ref().to_vec())
                .map(Hex)
                .collect(),
            randomness: tracing_rng.collect().into_iter().map(Hex).collect(),
            proof_batchable: Hex(proof_batchable),
        });
    }

    let file = File::create(filename).unwrap();
    serde_json::to_writer_pretty(file, &test_vectors).unwrap();
}
