//! Regenerates spec test vector JSON files after a protocol identifier change.
//! Run with: cargo run --example update_vectors --features "bls12_381,p256,std"
//! Delete this file after use.

use std::fs;

use bls12_381::G1Projective as Bls12381G1;
use group::{ff::PrimeField, prime::PrimeGroup, Group};
use p256::ProjectivePoint as P256ProjectivePoint;
use serde::{Deserialize, Serialize};
use serde_with::{hex, serde_as};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::{linear_relation::CanonicalLinearRelation, traits::ScalarRng, MultiScalarMul, Nizk};

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
struct Hex(#[serde_as(as = "hex::Hex")] Vec<u8>);

#[derive(Debug, Default, Serialize, Deserialize)]
struct TestVector {
    #[serde(rename = "Relation")]
    relation: String,
    #[serde(rename = "Ciphersuite")]
    ciphersuite: String,
    #[serde(rename = "SessionId")]
    session_id: Hex,
    #[serde(rename = "Statement")]
    statement: Hex,
    #[serde(rename = "Witness")]
    witness: Hex,
    #[serde(rename = "Proof")]
    proof: Hex,
    #[serde(rename = "Batchable Proof")]
    batchable_proof: Hex,
}

// --- deterministic RNG matching proof_generation_rng in spec/rng.rs ---

struct TestDrng {
    state: sha3::Shake128,
    squeeze_offset: usize,
}

impl TestDrng {
    fn from_seed(seed_label: &[u8]) -> Self {
        let mut initial_block = [0u8; 168];
        let domain = b"sigma-proofs/TestDRNG/SHAKE128";
        initial_block[..domain.len()].copy_from_slice(domain);

        let mut state = sha3::Shake128::default();
        state.update(&initial_block);
        state.update(&fixed_seed(seed_label));
        Self {
            state,
            squeeze_offset: 0,
        }
    }

    fn random_scalar_bytes<G>(&mut self) -> Vec<u8>
    where
        G: PrimeGroup,
        G::Scalar: Decoding<[u8]>,
    {
        let mut repr = <G::Scalar as Decoding<[u8]>>::Repr::default();
        let uniform_bytes = self.squeeze(repr.as_mut().len());
        repr.as_mut().copy_from_slice(&uniform_bytes);
        let scalar = G::Scalar::decode(repr);
        scalar.to_repr().as_ref().to_vec()
    }

    fn squeeze(&mut self, length: usize) -> Vec<u8> {
        let end = self.squeeze_offset + length;
        let mut full = vec![0u8; end];
        self.state.clone().finalize_xof().read(&mut full);
        let out = full[self.squeeze_offset..end].to_vec();
        self.squeeze_offset = end;
        out
    }
}

fn fixed_seed(label: &[u8]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..label.len()].copy_from_slice(label);
    seed
}

struct MockScalarRng(std::vec::IntoIter<Vec<u8>>);

impl MockScalarRng {
    fn next<G: Group>(&mut self) -> G::Scalar
    where
        G::Scalar: PrimeField,
    {
        let bytes = self.0.next().expect("rng exhausted");
        let mut repr = <G::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        G::Scalar::from_repr(repr).expect("invalid scalar")
    }
}

impl ScalarRng for MockScalarRng {
    fn random_scalars<G: Group, const N: usize>(&mut self) -> [G::Scalar; N]
    where
        G::Scalar: PrimeField,
    {
        std::array::from_fn(|_| self.next::<G>())
    }

    fn random_scalars_vec<G: Group>(&mut self, n: usize) -> Vec<G::Scalar>
    where
        G::Scalar: PrimeField,
    {
        (0..n).map(|_| self.next::<G>()).collect()
    }
}

fn proof_generation_rng<G>(count: usize) -> MockScalarRng
where
    G: PrimeGroup,
    G::Scalar: Decoding<[u8]>,
{
    let mut drng = TestDrng::from_seed(b"proof_generation_seed");
    let scalars: Vec<Vec<u8>> = (0..count).map(|_| drng.random_scalar_bytes::<G>()).collect();
    MockScalarRng(scalars.into_iter())
}

fn decode_scalars<G>(bytes: &[u8]) -> Vec<G::Scalar>
where
    G: PrimeGroup,
    G::Scalar: NargDeserialize,
{
    let mut cursor = bytes;
    let mut out = Vec::new();
    while !cursor.is_empty() {
        out.push(G::Scalar::deserialize_from_narg(&mut cursor).expect("deserialize scalar"));
    }
    out
}

fn update_file<G>(path: &str, new_ciphersuite: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let json = fs::read_to_string(path).expect("read json");
    let mut vectors: Vec<TestVector> = serde_json::from_str(&json).expect("parse json");

    for v in &mut vectors {
        let instance = CanonicalLinearRelation::<G>::from_label(&v.statement.0).expect("from_label");
        let witness = decode_scalars::<G>(&v.witness.0);
        let nizk = Nizk::new(&v.session_id.0, instance);

        // Must use a single RNG: batchable consumes the first N scalars,
        // compact uses the next N — matching how spec_vectors.rs runs them.
        let mut rng = proof_generation_rng::<G>(2 * witness.len());
        let batchable = nizk.prove_batchable(&witness, &mut rng).expect("prove_batchable");
        let compact = nizk.prove_compact(&witness, &mut rng).expect("prove_compact");

        v.batchable_proof = Hex(batchable);
        v.proof = Hex(compact);
        v.ciphersuite = new_ciphersuite.to_string();

        println!("  updated: {}", v.relation);
    }

    let new_json = serde_json::to_string_pretty(&vectors).expect("serialize");
    fs::write(path, new_json + "\n").expect("write json");
    println!("wrote {path}");
}

fn main() {
    println!("Updating BLS12-381 vectors...");
    update_file::<Bls12381G1>(
        "tests/spec/testdata/sigma-proofs_Shake128_BLS12381.json",
        "sigma-proofs/linear-relation/BLS12381",
    );

    println!("Updating P256 vectors...");
    update_file::<P256ProjectivePoint>(
        "tests/spec/testdata/sigma-proofs_Shake128_P256.json",
        "sigma-proofs/linear-relation/P256",
    );
}
