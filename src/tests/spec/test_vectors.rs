use bls12_381::{G1Projective as G, Scalar};
use core::str;
use hex::FromHex;
use json::JsonValue;
use std::fs;

use crate::codec::KeccakByteSchnorrCodec;
use crate::fiat_shamir::Nizk;
use crate::tests::spec::{custom_schnorr_protocol::DeterministicSchnorrProof, rng::TestDRNG};
use crate::traits::SigmaProtocol;
use group::GroupEncoding;

type SchnorrNizk = Nizk<DeterministicSchnorrProof<G>, KeccakByteSchnorrCodec<G>>;

use crate::tests::test_utils::{
    bbs_blind_commitment_computation, discrete_logarithm, dleq, pedersen_commitment,
    pedersen_commitment_dleq,
};

/// Macro to generate non-interactive sigma protocols test functions with IV
macro_rules! generate_ni_function_iv {
    ($name:ident, $test_fn:ident) => {
        #[allow(non_snake_case)]
        fn $name(seed: &[u8], iv: [u8; 32]) -> (Vec<Scalar>, Vec<u8>) {
            let mut rng = TestDRNG::new(seed);
            let (instance, witness) = $test_fn(&mut rng);

            let protocol = DeterministicSchnorrProof::from(instance);
            let nizk = SchnorrNizk::from_iv(iv, protocol);

            let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
            let verified = nizk.verify_batchable(&proof_bytes).is_ok();
            assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
            (witness, proof_bytes)
        }
    };
}

/// Macro to generate non-interactive sigma protocols test functions with session ID
macro_rules! generate_ni_function_session {
    ($name:ident, $test_fn:ident) => {
        #[allow(non_snake_case)]
        fn $name(seed: &[u8], session_id: &[u8]) -> (Vec<Scalar>, Vec<u8>, Vec<u8>) {
            let mut rng = TestDRNG::new(seed);
            let (instance, witness) = $test_fn(&mut rng);

            let statement = instance.label();
            let protocol = DeterministicSchnorrProof::from(instance);
            let nizk = SchnorrNizk::new(session_id, protocol);

            let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
            let verified = nizk.verify_batchable(&proof_bytes).is_ok();
            assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
            (witness, proof_bytes, statement)
        }
    };

    (@arg $rng:ident, $type:ident) => {
        G::$type(&mut $rng)
    };
    (@arg $rng:ident, [$type:ident; $count:expr]) => {
        (0..$count)
            .map(|_| G::$type(&mut $rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    };
}

generate_ni_function_iv!(NI_discrete_logarithm_iv, discrete_logarithm);
generate_ni_function_iv!(NI_dleq_iv, dleq);
generate_ni_function_iv!(NI_pedersen_commitment_iv, pedersen_commitment);
generate_ni_function_iv!(NI_pedersen_commitment_dleq_iv, pedersen_commitment_dleq);
generate_ni_function_iv!(
    NI_bbs_blind_commitment_computation_iv,
    bbs_blind_commitment_computation
);

generate_ni_function_session!(NI_discrete_logarithm_session, discrete_logarithm);
generate_ni_function_session!(NI_dleq_session, dleq);
generate_ni_function_session!(NI_pedersen_commitment_session, pedersen_commitment);
generate_ni_function_session!(
    NI_pedersen_commitment_dleq_session,
    pedersen_commitment_dleq
);
generate_ni_function_session!(
    NI_bbs_blind_commitment_computation_session,
    bbs_blind_commitment_computation
);

#[allow(clippy::type_complexity)]
#[allow(non_snake_case)]
#[test]
fn test_spec_testvectors() {
    let seed = b"hello world";
    let iv = *b"yellow submarineyellow submarine";
    let vectors = extract_vectors_iv("src/tests/spec/vectors/allVectors.json").unwrap();

    // Order functions to match JSON vector order:
    // allVectors.json order is: bbs, discrete_log, dleq, pedersen_commitment, pedersen_commitment_dleq
    let functions: [fn(&[u8], [u8; 32]) -> (Vec<Scalar>, Vec<u8>); 5] = [
        NI_bbs_blind_commitment_computation_iv,
        NI_discrete_logarithm_iv,
        NI_dleq_iv,
        NI_pedersen_commitment_iv,
        NI_pedersen_commitment_dleq_iv,
    ];

    for (i, f) in functions.iter().enumerate() {
        let (_, proof_bytes) = f(seed, iv);
        assert_eq!(
            iv.as_slice(),
            vectors[i].0.as_slice(),
            "context for test vector {i} does not match"
        );
        assert_eq!(
            proof_bytes, vectors[i].1,
            "proof bytes for test vector {i} does not match"
        );
    }
}

#[allow(clippy::type_complexity)]
#[allow(non_snake_case)]
#[test]
fn test_spec_testvectors_with_fixed_label() {
    let seed = b"hello world";
    let session_id = b"hello world";
    let vectors = extract_vectors_session("src/tests/spec/vectors/fixedLabelVectors.json").unwrap();

    let functions: [fn(&[u8], &[u8]) -> (Vec<Scalar>, Vec<u8>, Vec<u8>); 5] = [
        NI_bbs_blind_commitment_computation_session,
        NI_discrete_logarithm_session,
        NI_dleq_session,
        NI_pedersen_commitment_dleq_session,
        NI_pedersen_commitment_session,
    ];

    for (i, f) in functions.iter().enumerate() {
        let (_, proof_bytes, statement) = f(seed, session_id);

        // Debug output to understand what's different
        if i == 0 {
            println!("DEBUG: Function {i}");
            println!("  Actual proof length: {}", proof_bytes.len());
            println!("  Expected proof length: {}", vectors[i].1.len());
            println!("  Actual statement length: {}", statement.len());
            println!("  Expected statement length: {}", vectors[i].2.len());

            // Find first differing byte
            for (j, (actual, expected)) in proof_bytes.iter().zip(vectors[i].1.iter()).enumerate() {
                if actual != expected {
                    println!("  First diff at byte {j}: actual={actual}, expected={expected}");
                    break;
                }
            }
        }

        assert_eq!(
            session_id.as_slice(),
            vectors[i].0.as_slice(),
            "session id for test vector {i} does not match"
        );
        assert_eq!(
            proof_bytes, vectors[i].1,
            "proof bytes for test vector {i} does not match"
        );
        assert_eq!(
            statement, vectors[i].2,
            "statement for test vector {i} does not match"
        );
    }
}

fn extract_vectors_iv(path: &str) -> json::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let content = fs::read_to_string(path).expect("Unable to read JSON file");
    let root: JsonValue = json::parse(&content).expect("JSON parsing error");
    root.entries()
        .map(|(_, obj)| {
            let context_hex = obj["Context"]
                .as_str()
                .expect("Context field not found or not a string");
            let proof_hex = obj["Proof"]
                .as_str()
                .expect("Proof field not found or not a string");
            Ok((
                Vec::from_hex(context_hex).unwrap(),
                Vec::from_hex(proof_hex).unwrap(),
            ))
        })
        .collect()
}

#[allow(clippy::type_complexity)]
#[test]
fn debug_discrete_logarithm_components() {
    let seed = b"hello world";
    let iv = *b"yellow submarineyellow submarine";
    let mut rng = TestDRNG::new(seed);

    // Generate the instance and witness
    let (instance, witness) = discrete_logarithm(&mut rng);

    println!("=== INSTANCE ANALYSIS ===");
    println!("Instance label length: {}", instance.label().len());
    println!("Instance label (hex): {}", hex::encode(&instance.label()));
    println!("Witness length: {}", witness.len());

    // Create protocol for label inspection
    {
        let protocol = DeterministicSchnorrProof::from(instance.clone());
        let protocol_label = protocol.instance_label();
        let protocol_label_bytes = protocol_label.as_ref().to_vec();
        println!("Protocol instance label length: {}", protocol_label_bytes.len());
        println!("Protocol instance label (hex): {}", hex::encode(&protocol_label_bytes));

        // Check if labels match
        let instance_label = instance.label();
        println!("Labels match: {}", instance_label == protocol_label_bytes);
    }

    // Create NIZK
    let protocol = DeterministicSchnorrProof::from(instance.clone());
    let nizk = SchnorrNizk::from_iv(iv, protocol);

    // Reset RNG to same state for deterministic proof
    let mut rng = TestDRNG::new(seed);
    let (_, _) = discrete_logarithm::<G, TestDRNG>(&mut rng); // Consume same amount as before

    // Test manual protocol execution to see where the difference is
    println!("\n=== MANUAL PROTOCOL EXECUTION ===");
    let protocol_debug = DeterministicSchnorrProof::from(instance.clone());
    let (commitment, _state) = protocol_debug.prover_commit(&witness, &mut rng).unwrap();
    println!("Commitment length: {}", commitment.len());
    println!("Commitment bytes: {:?}", &commitment[0].to_bytes().as_ref()[..16.min(commitment[0].to_bytes().as_ref().len())]);

    // Reset RNG again for nizk proof
    let mut rng = TestDRNG::new(seed);
    let (_, _) = discrete_logarithm::<G, TestDRNG>(&mut rng); // Consume same amount as before

    // Generate proof step by step
    println!("\n=== PROOF GENERATION ===");
    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    println!("Proof length: {}", proof_bytes.len());
    println!("Proof bytes (first 32): {:?}", &proof_bytes[..32.min(proof_bytes.len())]);

    // Expected from test vectors (first test)
    let expected = [128, 61, 93, 79, 219, 49, 25, 103, 131, 39, 88, 174, 116, 2, 208, 51, 4, 181, 112, 249, 124, 7, 86, 229, 56, 90, 80, 98, 45, 10, 199, 181];
    println!("Expected bytes (first 32): {:?}", expected);
    println!("First 32 bytes match: {}", &proof_bytes[..32] == expected);

    if proof_bytes.len() > 32 {
        println!("Actual bytes (32-64): {:?}", &proof_bytes[32..64.min(proof_bytes.len())]);
        let expected_32_64 = [222, 135, 254, 20, 209, 80, 65, 177, 86, 75, 164, 137, 58, 17, 135, 48, 44, 37, 134, 223, 206, 241, 5, 211, 244, 55, 210, 209, 9, 91, 231, 230];
        println!("Expected bytes (32-64): {:?}", expected_32_64);
        println!("Bytes 32-64 match: {}", &proof_bytes[32..64] == expected_32_64);
    }
}

fn extract_vectors_session(path: &str) -> json::Result<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>> {
    let content = fs::read_to_string(path).expect("Unable to read JSON file");
    let root: JsonValue = json::parse(&content).expect("JSON parsing error");
    root.entries()
        .map(|(_, obj)| {
            let context_hex = obj["Context"]
                .as_str()
                .expect("Context field not found or not a string");
            let proof_hex = obj["Proof"]
                .as_str()
                .expect("Proof field not found or not a string");
            let statement_hex = obj["Statement"]
                .as_str()
                .expect("Statement field not found or not a string");
            Ok((
                Vec::from_hex(context_hex).unwrap(),
                Vec::from_hex(proof_hex).unwrap(),
                Vec::from_hex(statement_hex).unwrap(),
            ))
        })
        .collect()
}
