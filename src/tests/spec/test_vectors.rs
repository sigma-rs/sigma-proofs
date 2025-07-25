use bls12_381::{G1Projective as G, Scalar};
use core::str;
use hex::FromHex;
use json::JsonValue;
use std::fs;

use crate::codec::KeccakByteSchnorrCodec;
use crate::fiat_shamir::Nizk;
use crate::linear_relation::CanonicalLinearRelation;
use crate::tests::spec::{
    custom_schnorr_protocol::SchnorrProtocolCustom, random::SRandom, rng::TestDRNG,
};
use crate::LinearRelation;

type SchnorrNizk = Nizk<SchnorrProtocolCustom<G>, KeccakByteSchnorrCodec<G>>;

// Wrapper functions that take parameters and return LinearRelation for compatibility with test vectors
#[allow(non_snake_case)]
fn discrete_logarithm_wrapper(x: Scalar) -> (LinearRelation<G>, Vec<Scalar>) {
    // Create a relation manually to match the old signature
    let mut relation = LinearRelation::new();
    let var_x = relation.allocate_scalar();
    let var_G = relation.allocate_element();
    let _var_X = relation.allocate_eq(var_x * var_G);
    relation.set_element(var_G, G::generator());
    relation.compute_image(&[x]).unwrap();
    (relation, vec![x])
}

#[allow(non_snake_case)]
fn dleq_wrapper(H: G, x: Scalar) -> (LinearRelation<G>, Vec<Scalar>) {
    let mut relation = LinearRelation::new();
    let var_x = relation.allocate_scalar();
    let [var_G, var_H] = relation.allocate_elements();
    let _var_X = relation.allocate_eq(var_x * var_G);
    let _var_Y = relation.allocate_eq(var_x * var_H);
    relation.set_elements([(var_G, G::generator()), (var_H, H)]);
    relation.compute_image(&[x]).unwrap();
    (relation, vec![x])
}

#[allow(non_snake_case)]
fn pedersen_commitment_wrapper(H: G, x: Scalar, r: Scalar) -> (LinearRelation<G>, Vec<Scalar>) {
    let mut relation = LinearRelation::new();
    let [var_x, var_r] = relation.allocate_scalars();
    let [var_G, var_H] = relation.allocate_elements();
    let _var_C = relation.allocate_eq(var_x * var_G + var_r * var_H);
    relation.set_elements([(var_H, H), (var_G, G::generator())]);
    relation.compute_image(&[x, r]).unwrap();
    (relation, vec![x, r])
}

#[allow(non_snake_case)]
fn pedersen_commitment_dleq_wrapper(
    generators: [G; 4],
    witness: [Scalar; 2],
) -> (LinearRelation<G>, Vec<Scalar>) {
    use crate::linear_relation::msm_pr;
    let mut relation = LinearRelation::new();
    let X = msm_pr::<G>(&witness, &[generators[0], generators[1]]);
    let Y = msm_pr::<G>(&witness, &[generators[2], generators[3]]);
    let [var_x, var_r] = relation.allocate_scalars();
    let var_Gs = relation.allocate_elements::<4>();
    let var_X = relation.allocate_eq(var_x * var_Gs[0] + var_r * var_Gs[1]);
    let var_Y = relation.allocate_eq(var_x * var_Gs[2] + var_r * var_Gs[3]);
    relation.set_elements([
        (var_Gs[0], generators[0]),
        (var_Gs[1], generators[1]),
        (var_Gs[2], generators[2]),
        (var_Gs[3], generators[3]),
    ]);
    relation.set_elements([(var_X, X), (var_Y, Y)]);
    (relation, witness.to_vec())
}

#[allow(non_snake_case)]
fn bbs_blind_commitment_computation_wrapper(
    [Q_2, J_1, J_2, J_3]: [G; 4],
    [msg_1, msg_2, msg_3]: [Scalar; 3],
    secret_prover_blind: Scalar,
) -> (LinearRelation<G>, Vec<Scalar>) {
    let mut relation = LinearRelation::new();
    let C = Q_2 * secret_prover_blind + J_1 * msg_1 + J_2 * msg_2 + J_3 * msg_3;
    let [var_secret_prover_blind, var_msg_1, var_msg_2, var_msg_3] = relation.allocate_scalars();
    let [var_Q_2, var_J_1, var_J_2, var_J_3] = relation.allocate_elements();
    let var_C = relation.allocate_element();
    relation.append_equation(
        var_C,
        var_secret_prover_blind * var_Q_2
            + var_msg_1 * var_J_1
            + var_msg_2 * var_J_2
            + var_msg_3 * var_J_3,
    );
    relation.set_elements([
        (var_Q_2, Q_2),
        (var_J_1, J_1),
        (var_J_2, J_2),
        (var_J_3, J_3),
        (var_C, C),
    ]);
    let witness = vec![secret_prover_blind, msg_1, msg_2, msg_3];
    (relation, witness)
}

/// Macro to generate non-interactive sigma protocols test functions with IV
macro_rules! generate_ni_function_iv {
    ($name:ident, $test_fn:ident, $($param:tt),*) => {
        #[allow(non_snake_case)]
        fn $name(seed: &[u8], iv: [u8; 32]) -> (Vec<Scalar>, Vec<u8>) {
            let mut rng = TestDRNG::new(seed);
            let (instance, witness) = $test_fn($(generate_ni_function_iv!(@arg rng, $param)),*);

            let protocol = SchnorrProtocolCustom(instance);
            let nizk = SchnorrNizk::from_iv(iv, protocol);

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

            let statement = CanonicalLinearRelation::try_from(&instance).unwrap().label();
            let protocol = SchnorrProtocolCustom(instance);
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
        (0..$count).map(|_| G::$type(&mut $rng)).collect::<Vec<_>>().try_into().unwrap()
    };
}

generate_ni_function_iv!(
    NI_discrete_logarithm_iv,
    discrete_logarithm_wrapper,
    random_scalar_elt
);
generate_ni_function_iv!(
    NI_dleq_iv,
    dleq_wrapper,
    random_group_elt,
    random_scalar_elt
);
generate_ni_function_iv!(
    NI_pedersen_commitment_iv,
    pedersen_commitment_wrapper,
    random_group_elt,
    random_scalar_elt,
    random_scalar_elt
);
generate_ni_function_iv!(
    NI_pedersen_commitment_dleq_iv,
    pedersen_commitment_dleq_wrapper,
    [random_group_elt; 4],
    [random_scalar_elt; 2]
);
generate_ni_function_iv!(
    NI_bbs_blind_commitment_computation_iv,
    bbs_blind_commitment_computation_wrapper,
    [random_group_elt; 4],
    [random_scalar_elt; 3],
    random_scalar_elt
);

generate_ni_function_session!(
    NI_discrete_logarithm_session,
    discrete_logarithm_wrapper,
    random_scalar_elt
);
generate_ni_function_session!(
    NI_dleq_session,
    dleq_wrapper,
    random_group_elt,
    random_scalar_elt
);
generate_ni_function_session!(
    NI_pedersen_commitment_session,
    pedersen_commitment_wrapper,
    random_group_elt,
    random_scalar_elt,
    random_scalar_elt
);
generate_ni_function_session!(
    NI_pedersen_commitment_dleq_session,
    pedersen_commitment_dleq_wrapper,
    [random_group_elt; 4],
    [random_scalar_elt; 2]
);
generate_ni_function_session!(
    NI_bbs_blind_commitment_computation_session,
    bbs_blind_commitment_computation_wrapper,
    [random_group_elt; 4],
    [random_scalar_elt; 3],
    random_scalar_elt
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
