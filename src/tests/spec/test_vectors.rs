use bls12_381::{G1Projective as G, Scalar};
use core::str;
use hex::FromHex;
use json::JsonValue;
use std::fs;

use crate::codec::KeccakByteSchnorrCodec;
use crate::fiat_shamir::NISigmaProtocol;
use crate::tests::spec::{
    custom_schnorr_protocol::SchnorrProtocolCustom, random::SRandom, rng::TestDRNG,
};
use crate::tests::test_utils::{
    bbs_blind_commitment_computation, discrete_logarithm, dleq, pedersen_commitment,
    pedersen_commitment_dleq,
};

type NIProtocol = NISigmaProtocol<SchnorrProtocolCustom<G>, KeccakByteSchnorrCodec<G>>;

/// Macro to generate non-interactive sigma protocols test functions with IV
macro_rules! generate_ni_function_iv {
    ($name:ident, $test_fn:ident, $($param:tt),*) => {
        #[allow(non_snake_case)]
        fn $name(seed: &[u8], iv: [u8; 32]) -> (Vec<Scalar>, Vec<u8>) {
            let mut rng = TestDRNG::new(seed);
            let (instance, witness) = $test_fn($(generate_ni_function_iv!(@arg rng, $param)),*);

            let protocol = SchnorrProtocolCustom::from(instance);
            let nizk = NIProtocol::from_iv(iv, protocol);

            let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
            let verified = nizk.verify_batchable(&proof_bytes).is_ok();
            assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
            (witness, proof_bytes)
        }
    };

    (@arg $rng:ident, $type:ident) => {
        G::$type(&mut $rng)
    };
    (@arg $rng:ident, [$type:ident; $count:expr]) => {
        (0..$count).map(|_| G::$type(&mut $rng)).collect::<Vec<_>>().try_into().unwrap()
    };
}

/// Macro to generate non-interactive sigma protocols test functions with session ID
macro_rules! generate_ni_function_session {
    ($name:ident, $test_fn:ident, $($param:tt),*) => {
        #[allow(non_snake_case)]
        fn $name(seed: &[u8], session_id: &[u8]) -> (Vec<Scalar>, Vec<u8>, Vec<u8>) {
            let mut rng = TestDRNG::new(seed);
            let (instance, witness) = $test_fn($(generate_ni_function_session!(@arg rng, $param)),*);

            let statement = instance.label();
            let protocol = SchnorrProtocolCustom::from(instance);
            let nizk = NIProtocol::new(session_id, protocol);

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
        (0..$count).map(|_| G::$type(&mut $rng)).collect::<Vec<_>>().try_into().unwrap()
    };
}

generate_ni_function_iv!(NI_discrete_logarithm_iv, discrete_logarithm, srandom);
generate_ni_function_iv!(NI_dleq_iv, dleq, prandom, srandom);
generate_ni_function_iv!(
    NI_pedersen_commitment_iv,
    pedersen_commitment,
    prandom,
    srandom,
    srandom
);
generate_ni_function_iv!(
    NI_pedersen_commitment_dleq_iv,
    pedersen_commitment_dleq,
    [prandom; 4],
    [srandom; 2]
);
generate_ni_function_iv!(
    NI_bbs_blind_commitment_computation_iv,
    bbs_blind_commitment_computation,
    [prandom; 4],
    [srandom; 3],
    srandom
);

generate_ni_function_session!(NI_discrete_logarithm_session, discrete_logarithm, srandom);
generate_ni_function_session!(NI_dleq_session, dleq, prandom, srandom);
generate_ni_function_session!(
    NI_pedersen_commitment_session,
    pedersen_commitment,
    prandom,
    srandom,
    srandom
);
generate_ni_function_session!(
    NI_pedersen_commitment_dleq_session,
    pedersen_commitment_dleq,
    [prandom; 4],
    [srandom; 2]
);
generate_ni_function_session!(
    NI_bbs_blind_commitment_computation_session,
    bbs_blind_commitment_computation,
    [prandom; 4],
    [srandom; 3],
    srandom
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

    // Order functions to match JSON vector order:
    // 0: bbs_blind_commitment_computation_with_session_ID
    // 1: discrete_logarithm_with_session_ID
    // 2: dleq_with_session_ID
    // 3: pedersen_commitment_dleq_with_session_ID
    // 4: pedersen_commitment_with_session_ID
    let functions: [fn(&[u8], &[u8]) -> (Vec<Scalar>, Vec<u8>, Vec<u8>); 5] = [
        NI_bbs_blind_commitment_computation_session,
        NI_discrete_logarithm_session,
        NI_dleq_session,
        NI_pedersen_commitment_dleq_session,
        NI_pedersen_commitment_session,
    ];

    for (i, f) in functions.iter().enumerate() {
        let (_, proof_bytes, statement) = f(seed, session_id);
        assert_eq!(
            session_id.as_slice(),
            vectors[i].0.as_slice(),
            "context for test vector {i} does not match"
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
