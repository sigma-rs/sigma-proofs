use bls12_381::{G1Projective, Scalar};
use core::str;
use group::{Group, GroupEncoding};
use hex::FromHex;
use json::JsonValue;
use rand::{CryptoRng, Rng};
use std::fs;

use sigma_rs::{
    codec::{ByteSchnorrCodec, KeccakDuplexSponge},
    group_morphism::msm_pr,
    GroupMorphismPreimage, NISigmaProtocol,
};

use crate::{custom_schnorr_protocol::SchnorrProtocolCustom, random::SRandom, test_drng::TestDRNG};

type Preimage<G> = GroupMorphismPreimage<G>;

type Gp = G1Projective;
type Codec = ByteSchnorrCodec<Gp, KeccakDuplexSponge>;
type SigmaP = SchnorrProtocolCustom<Gp>;
type NISigmaP = NISigmaProtocol<SigmaP, Codec, Gp>;

#[allow(non_snake_case)]
#[test]
fn sage_test_vectors() {
    let seed = b"hello world";
    let context = b"yellow submarineyellow submarine";

    let vectors = extract_vectors("tests/spec/allVectors.json").unwrap();

    let functions: [fn(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>); 5] = [
        NI_discrete_logarithm,
        NI_dleq,
        NI_pedersen_commitment,
        NI_pedersen_commitment_dleq,
        NI_bbs_blind_commitment_computation,
    ];

    for (i, f) in functions.iter().enumerate() {
        let (_, proof_bytes) = f(seed, context);
        assert!(context.to_vec() == vectors[i].0);
        assert!(proof_bytes == vectors[i].1);
    }
}

fn extract_vectors(path: &str) -> json::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let content = fs::read_to_string(path).expect("Unable to read JSON file");

    let root: JsonValue = json::parse(&content).expect("JSON parsing error");

    let mut vectors: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    for (_, obj) in root.entries() {
        let context_hex = obj["Context"]
            .as_str()
            .expect("Context field not found or not a string");
        let proof_hex = obj["Proof"]
            .as_str()
            .expect("Context field not found or not a string");

        vectors.push((
            Vec::from_hex(context_hex).unwrap(),
            Vec::from_hex(proof_hex).unwrap(),
        ));
    }
    Ok(vectors)
}

#[allow(non_snake_case)]
fn discrete_logarithm<G: SRandom + Group + GroupEncoding>(
    rng: &mut (impl Rng + CryptoRng),
) -> (Preimage<G>, Vec<G::Scalar>) {
    let mut morphismp: Preimage<G> = Preimage::new();

    let scalars = morphismp.allocate_scalars(1);
    let var_x = scalars[0];

    let points = morphismp.allocate_elements(2);
    let (var_G, var_X) = (points[0], points[1]);

    morphismp.append_equation(var_X, &[(var_x, var_G)]);

    let G = G::generator();
    morphismp.assign_elements(&[(var_G, G)]);

    let x = G::srandom(rng);
    let X = G * x;
    assert!(vec![X] == morphismp.morphism.evaluate(&[x]));
    morphismp.assign_elements(&[(var_X, X)]);
    (morphismp, vec![x])
}

#[allow(non_snake_case)]
fn dleq<G: Group + GroupEncoding + SRandom>(
    rng: &mut (impl Rng + CryptoRng),
) -> (Preimage<G>, Vec<G::Scalar>) {
    let mut morphismp: Preimage<G> = Preimage::new();

    let G = G::generator();
    let x = G::srandom(rng);
    let H = G::prandom(rng);
    let X = G * x;
    let Y = H * x;

    let scalars = morphismp.allocate_scalars(1);
    let var_x = scalars[0];

    let points = morphismp.allocate_elements(4);
    let (var_G, var_H, var_X, var_Y) = (points[0], points[1], points[2], points[3]);

    morphismp.assign_elements(&[(var_G, G), (var_H, H), (var_X, X), (var_Y, Y)]);
    morphismp.append_equation(var_X, &[(var_x, var_G)]);
    morphismp.append_equation(var_Y, &[(var_x, var_H)]);

    assert!(vec![X, Y] == morphismp.morphism.evaluate(&[x]));
    (morphismp, vec![x])
}

#[allow(non_snake_case)]
fn pedersen_commitment<G: Group + GroupEncoding + SRandom>(
    rng: &mut (impl Rng + CryptoRng),
) -> (Preimage<G>, Vec<G::Scalar>) {
    let mut morphismp: Preimage<G> = Preimage::new();

    let G = G::generator();
    let H = G::prandom(rng);
    let x = G::srandom(rng);
    let r = G::srandom(rng);
    let witness = vec![x, r];

    let C = G * x + H * r;

    let scalars = morphismp.allocate_scalars(2);
    let (var_x, var_r) = (scalars[0], scalars[1]);

    let points = morphismp.allocate_elements(3);
    let (var_G, var_H, var_C) = (points[0], points[1], points[2]);

    morphismp.assign_elements(&[(var_H, H), (var_G, G), (var_C, C)]);
    morphismp.append_equation(var_C, &[(var_x, var_G), (var_r, var_H)]);

    assert!(vec![C] == morphismp.morphism.evaluate(&witness));
    (morphismp, witness)
}

#[allow(non_snake_case)]
fn pedersen_commitment_dleq<G: Group + GroupEncoding + SRandom>(
    rng: &mut (impl Rng + CryptoRng),
) -> (Preimage<G>, Vec<G::Scalar>) {
    let mut morphismp: Preimage<G> = Preimage::new();

    let mut generators = Vec::<G>::new();
    generators.push(G::prandom(rng));
    generators.push(G::prandom(rng));
    generators.push(G::prandom(rng));
    generators.push(G::prandom(rng));

    let mut witness = Vec::<G::Scalar>::new();
    witness.push(G::srandom(rng));
    witness.push(G::srandom(rng));

    let X = msm_pr::<G>(&witness, &[generators[0], generators[1]]);
    let Y = msm_pr::<G>(&witness, &[generators[2], generators[3]]);

    let scalars = morphismp.allocate_scalars(2);
    let (var_x, var_r) = (scalars[0], scalars[1]);

    let points = morphismp.allocate_elements(6);
    let var_Gs = (points[0], points[1], points[2], points[3]);
    let (var_X, var_Y) = (points[4], points[5]);

    morphismp.assign_elements(&[
        (var_Gs.0, generators[0]),
        (var_Gs.1, generators[1]),
        (var_Gs.2, generators[2]),
        (var_Gs.3, generators[3]),
    ]);
    morphismp.assign_elements(&[(var_X, X), (var_Y, Y)]);

    morphismp.append_equation(var_X, &[(var_x, var_Gs.0), (var_r, var_Gs.1)]);
    morphismp.append_equation(var_Y, &[(var_x, var_Gs.2), (var_r, var_Gs.3)]);

    assert!(vec![X, Y] == morphismp.morphism.evaluate(&witness));
    (morphismp, witness)
}

#[allow(non_snake_case)]
fn bbs_blind_commitment_computation<G: Group + GroupEncoding + SRandom>(
    rng: &mut (impl Rng + CryptoRng),
) -> (Preimage<G>, Vec<G::Scalar>) {
    let mut morphismp: Preimage<G> = Preimage::new();

    // length (committed_messages)
    let M = 3;
    // BBS.create_generators(M + 1, "BLIND_" || api_id)
    let (Q_2, J_1, J_2, J_3) = (
        G::prandom(rng),
        G::prandom(rng),
        G::prandom(rng),
        G::prandom(rng),
    );
    // BBS.messages_to_scalars(committed_messages,  api_id)
    let (msg_1, msg_2, msg_3) = (G::srandom(rng), G::srandom(rng), G::srandom(rng));

    // these are computed before the proof in the specification
    let secret_prover_blind = G::srandom(rng);
    let C = Q_2 * secret_prover_blind + J_1 * msg_1 + J_2 * msg_2 + J_3 * msg_3;

    // This is the part that needs to be changed in the specification of blind bbs.
    let scalars = morphismp.allocate_scalars(M + 1);
    let (var_secret_prover_blind, var_msg_1, var_msg_2, var_msg_3) =
        (scalars[0], scalars[1], scalars[2], scalars[3]);

    let points = morphismp.allocate_elements(M + 2);
    let (var_Q_2, var_J_1, var_J_2, var_J_3) = (points[0], points[1], points[2], points[3]);
    let var_C = points[M + 1];

    morphismp.assign_elements(&[
        (var_Q_2, Q_2),
        (var_J_1, J_1),
        (var_J_2, J_2),
        (var_J_3, J_3),
        (var_C, C),
    ]);

    morphismp.append_equation(
        var_C,
        &[
            (var_secret_prover_blind, var_Q_2),
            (var_msg_1, var_J_1),
            (var_msg_2, var_J_2),
            (var_msg_3, var_J_3),
        ],
    );

    let witness = vec![secret_prover_blind, msg_1, msg_2, msg_3];

    assert!(vec![C] == morphismp.morphism.evaluate(&witness));
    (morphismp, witness)
}

/// This part tests the implementation of the SigmaProtocol trait for the
/// SchnorrProtocol structure as well as the Fiat-Shamir NISigmaProtocol transform
#[allow(non_snake_case)]
fn NI_discrete_logarithm(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = discrete_logarithm::<Gp>(&mut rng);

    let protocol = SchnorrProtocolCustom(morphismp);
    let domain_sep: Vec<u8> = context.to_vec();
    let mut nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_dleq(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = dleq::<Gp>(&mut rng);

    let protocol = SchnorrProtocolCustom(morphismp);
    let domain_sep: Vec<u8> = context.to_vec();
    let mut nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_pedersen_commitment(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = pedersen_commitment::<Gp>(&mut rng);

    let protocol = SchnorrProtocolCustom(morphismp);
    let domain_sep: Vec<u8> = context.to_vec();
    let mut nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_pedersen_commitment_dleq(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = pedersen_commitment_dleq::<Gp>(&mut rng);

    let protocol = SchnorrProtocolCustom(morphismp);
    let domain_sep: Vec<u8> = context.to_vec();
    let mut nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_bbs_blind_commitment_computation(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = bbs_blind_commitment_computation::<Gp>(&mut rng);

    let protocol = SchnorrProtocolCustom(morphismp);
    let domain_sep: Vec<u8> = context.to_vec();
    let mut nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    (witness, proof_bytes)
}
