use bls12_381::G1Projective as G;
use core::str;
use hex::FromHex;
use json::JsonValue;
use std::collections::HashMap;
use std::fs;

use crate::codec::KeccakByteSchnorrCodec;
use crate::fiat_shamir::Nizk;
use crate::linear_relation::CanonicalLinearRelation;
use crate::tests::spec::{custom_schnorr_protocol::DeterministicSchnorrProof, rng::TestDRNG};

type SchnorrNizk = Nizk<DeterministicSchnorrProof<G>, KeccakByteSchnorrCodec<G>>;

#[derive(Debug)]
struct TestVector {
    ciphersuite: String,
    session_id: Vec<u8>,
    statement: Vec<u8>,
    witness: Vec<u8>,
    iv: Vec<u8>,
    proof: Vec<u8>,
}

#[allow(clippy::type_complexity)]
#[allow(non_snake_case)]
#[test]
fn test_spec_testvectors() {
    let proof_generation_rng_seed = b"proof_generation_seed";
    let vectors = extract_vectors_new("src/tests/spec/vectors/testSigmaProtocols.json").unwrap();

    // Define supported ciphersuites
    let mut supported_ciphersuites = HashMap::new();
    supported_ciphersuites.insert(
        "sigma/OWKeccak1600+Bls12381".to_string(),
        "BLS12-381 with Keccak-based sponge",
    );

    // Order of test names to match JSON vector order
    let test_names = [
        "bbs_blind_commitment_computation",
        "discrete_logarithm",
        "dleq",
        "pedersen_commitment",
        "pedersen_commitment_dleq",
    ];

    for test_name in test_names.iter() {
        let vector = &vectors[*test_name];

        // Verify the ciphersuite is supported
        assert!(
            supported_ciphersuites.contains_key(&vector.ciphersuite),
            "Unsupported ciphersuite '{}' in test vector {}",
            vector.ciphersuite,
            test_name
        );

        // Parse the statement from the test vector
        let parsed_instance = CanonicalLinearRelation::<G>::from_label(&vector.statement)
            .expect("Failed to parse statement");

        // Decode the witness from the test vector
        let witness = crate::serialization::deserialize_scalars::<G>(
            &vector.witness,
            parsed_instance.num_scalars,
        )
        .expect("Failed to deserialize witness");

        // Verify the parsed instance can be re-serialized to the same label
        assert_eq!(
            parsed_instance.label(),
            vector.statement,
            "parsed statement doesn't match original for {}",
            test_name
        );

        // Create NIZK with the session_id from the test vector
        let protocol = DeterministicSchnorrProof::from(parsed_instance.clone());
        let nizk = SchnorrNizk::new(&vector.session_id, protocol);

        // Verify that the computed IV matches the test vector IV
        let protocol_id = b"draft-zkproof-fiat-shamir";
        let instance_label = parsed_instance.label();
        let computed_iv = crate::codec::compute_iv::<crate::codec::KeccakDuplexSponge>(
            protocol_id,
            &vector.session_id,
            &instance_label,
        );
        assert_eq!(
            computed_iv,
            vector.iv.as_slice(),
            "Computed IV doesn't match test vector IV for {}",
            test_name
        );

        // Generate proof with the proof generation RNG
        let mut proof_rng = TestDRNG::new(proof_generation_rng_seed);
        let proof_bytes = nizk.prove_batchable(&witness, &mut proof_rng).unwrap();

        // Verify the proof matches
        assert_eq!(
            proof_bytes, vector.proof,
            "proof bytes for test vector {} do not match",
            test_name
        );

        // Verify the proof is valid
        let verified = nizk.verify_batchable(&proof_bytes).is_ok();
        assert!(
            verified,
            "Fiat-Shamir Schnorr proof verification failed for {}",
            test_name
        );
    }
}

fn extract_vectors_new(path: &str) -> Result<HashMap<String, TestVector>, String> {
    use std::collections::HashMap;

    let content =
        fs::read_to_string(path).map_err(|e| format!("Unable to read JSON file: {}", e))?;
    let root: JsonValue =
        json::parse(&content).map_err(|e| format!("JSON parsing error: {}", e))?;

    let mut vectors = HashMap::new();

    for (name, obj) in root.entries() {
        let ciphersuite = obj["Ciphersuite"]
            .as_str()
            .ok_or_else(|| format!("Ciphersuite field not found for {}", name))?
            .to_string();

        let session_id = Vec::from_hex(
            obj["SessionId"]
                .as_str()
                .ok_or_else(|| format!("SessionId field not found for {}", name))?,
        )
        .map_err(|e| format!("Invalid hex in SessionId for {}: {}", name, e))?;

        let statement = Vec::from_hex(
            obj["Statement"]
                .as_str()
                .ok_or_else(|| format!("Statement field not found for {}", name))?,
        )
        .map_err(|e| format!("Invalid hex in Statement for {}: {}", name, e))?;

        let witness = Vec::from_hex(
            obj["Witness"]
                .as_str()
                .ok_or_else(|| format!("Witness field not found for {}", name))?,
        )
        .map_err(|e| format!("Invalid hex in Witness for {}: {}", name, e))?;

        let iv = Vec::from_hex(
            obj["IV"]
                .as_str()
                .ok_or_else(|| format!("IV field not found for {}", name))?,
        )
        .map_err(|e| format!("Invalid hex in IV for {}: {}", name, e))?;

        let proof = Vec::from_hex(
            obj["Proof"]
                .as_str()
                .ok_or_else(|| format!("Proof field not found for {}", name))?,
        )
        .map_err(|e| format!("Invalid hex in Proof for {}: {}", name, e))?;

        vectors.insert(
            name.to_string(),
            TestVector {
                ciphersuite,
                session_id,
                statement,
                witness,
                iv,
                proof,
            },
        );
    }

    Ok(vectors)
}
