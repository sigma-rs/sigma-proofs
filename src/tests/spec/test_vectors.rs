use bls12_381::{G1Projective as G, Scalar};
use core::str;
use hex::FromHex;
use json::JsonValue;
use std::fs;

use crate::codec::{ByteSchnorrCodec, KeccakDuplexSponge};
use crate::fiat_shamir::NISigmaProtocol;
use crate::tests::test_utils::{
    bbs_blind_commitment_computation, discrete_logarithm, dleq, pedersen_commitment,
    pedersen_commitment_dleq,
};

use crate::tests::spec::{
    custom_schnorr_protocol::SchnorrProtocolCustom, random::SRandom, rng::TestDRNG,
};

type Codec = ByteSchnorrCodec<G, KeccakDuplexSponge>;
type SigmaP = SchnorrProtocolCustom<G>;
type NISigmaP = NISigmaProtocol<SigmaP, Codec>;

#[allow(clippy::type_complexity)]
#[allow(non_snake_case)]
#[test]
fn sage_test_vectors() {
    let seed = b"hello world";
    let context = b"yellow submarineyellow submarine";

    let vectors = extract_vectors("src/tests/spec/allVectors.json").unwrap();

    let functions: [fn(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>); 5] = [
        NI_discrete_logarithm,
        NI_dleq,
        NI_pedersen_commitment,
        NI_pedersen_commitment_dleq,
        NI_bbs_blind_commitment_computation,
    ];

    for (i, f) in functions.iter().enumerate() {
        let (_, proof_bytes) = f(seed, context);
        assert_eq!(
            context.to_vec(),
            vectors[i].0,
            "context for test vector {i} does not match"
        );
        assert_eq!(
            proof_bytes, vectors[i].1,
            "proof bytes for test vector {i} does not match"
        );
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

/// This part tests the implementation of the SigmaProtocol trait for the
/// SchnorrProtocol structure as well as the Fiat-Shamir NISigmaProtocol transform
#[allow(non_snake_case)]
fn NI_discrete_logarithm(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = discrete_logarithm(G::srandom(&mut rng));

    let protocol = SchnorrProtocolCustom(morphismp);
    let domain_sep: Vec<u8> = context.to_vec();
    let nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_dleq(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = dleq(G::srandom(&mut rng), G::prandom(&mut rng));

    let protocol = SchnorrProtocolCustom(morphismp);
    let domain_sep: Vec<u8> = context.to_vec();
    let nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_pedersen_commitment(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = pedersen_commitment(
        G::prandom(&mut rng),
        G::srandom(&mut rng),
        G::srandom(&mut rng),
    );

    let protocol = SchnorrProtocolCustom(morphismp);
    let domain_sep: Vec<u8> = context.to_vec();
    let nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_pedersen_commitment_dleq(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = pedersen_commitment_dleq(
        (0..4)
            .map(|_| G::prandom(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..2)
            .map(|_| G::srandom(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );

    let protocol = SchnorrProtocolCustom(morphismp);
    let domain_sep: Vec<u8> = context.to_vec();
    let nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_bbs_blind_commitment_computation(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = bbs_blind_commitment_computation(
        (0..4)
            .map(|_| G::prandom(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        (0..3)
            .map(|_| G::srandom(&mut rng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        G::srandom(&mut rng),
    );

    let protocol = SchnorrProtocolCustom(morphismp);
    let domain_sep: Vec<u8> = context.to_vec();
    let nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    (witness, proof_bytes)
}
