use bls12_381::G1Projective as Bls12381G1;
use group::prime::PrimeGroup;
use p256::ProjectivePoint as P256ProjectivePoint;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::{linear_relation::Instance, MultiScalarMul, Nizk};

mod spec;
use spec::{rng::TestDrng, vectors::TestVector};

#[test]
fn test_spec_vectors_p256() {
    testvectors::<P256ProjectivePoint>(include_str!(
        "./spec/testdata/sigma-proofs_Shake128_P256.json"
    ));
}

#[test]
fn test_spec_vectors_bls12381() {
    testvectors::<Bls12381G1>(include_str!(
        "./spec/testdata/sigma-proofs_Shake128_BLS12381.json"
    ));
}

fn decode_scalars<G>(bytes: &[u8]) -> Vec<G::Scalar>
where
    G: PrimeGroup,
    G::Scalar: NargDeserialize,
{
    let mut cursor = bytes;
    let mut scalars = Vec::new();
    while !cursor.is_empty() {
        scalars.push(
            G::Scalar::deserialize_from_narg(&mut cursor).expect("failed to deserialize scalar"),
        );
    }
    scalars
}

fn testvectors<G>(vectors_json: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let test_vectors: Vec<TestVector> = serde_json::from_str(vectors_json)
        .map_err(|e| format!("JSON parsing error: {e}"))
        .unwrap();

    for vector in test_vectors {
        let test_name = vector.relation;
        let parsed_instance = Instance::<G>::deserialize(&vector.statement.0)
            .expect("failed to parse statement");

        let witness = decode_scalars::<G>(&vector.witness.0);
        assert_eq!(
            witness.len(),
            parsed_instance.num_scalars(),
            "witness length doesn't match instance scalars",
        );

        assert_eq!(
            parsed_instance.serialize(),
            vector.statement.0,
            "parsed statement doesn't match original for {test_name}"
        );

        let nizk = Nizk::new(&vector.session_id.0, parsed_instance);

        assert!(
            nizk.verify_batchable(&vector.batchable_proof.0).is_ok(),
            "batchable proof from vectors did not verify for {test_name}"
        );
        assert!(
            nizk.verify_compact(&vector.proof.0).is_ok(),
            "compact proof from vectors did not verify for {test_name}"
        );

        // The vectors are generated with the spec's seeded test DRNG,
        // initialized with the vector's tag. The relation builder draws the
        // instance/witness scalars from the same stream before the prover
        // nonces, and the two NARG flavors share one transcript — so each
        // regeneration starts a fresh stream, skips the builder draws, and
        // then draws the same nonces.
        let builder_draws = builder_scalar_draws(&test_name);

        let mut proof_rng = TestDrng::new(&vector.session_id.0);
        proof_rng.skip_scalars::<G>(builder_draws);
        let batchable_proof = nizk.prove_batchable(&witness, &mut proof_rng).unwrap();
        assert_eq!(
            batchable_proof, vector.batchable_proof.0,
            "batchable proof bytes do not match for {test_name}"
        );

        let mut proof_rng = TestDrng::new(&vector.session_id.0);
        proof_rng.skip_scalars::<G>(builder_draws);
        let compact_proof = nizk.prove_compact(&witness, &mut proof_rng).unwrap();
        assert_eq!(
            compact_proof, vector.proof.0,
            "compact proof bytes do not match for {test_name}"
        );
    }
}

/// Number of scalars the vector generator's relation builder draws from the
/// test DRNG (auxiliary generators and witness scalars, in order) before the
/// prover draws its commitment nonces. See `poc/sigma_vectors.py` in the
/// specification repository.
fn builder_scalar_draws(relation: &str) -> usize {
    match relation {
        "discrete_logarithm" => 1,
        "dleq" | "dleq_derived_element" => 2,
        "pedersen_commitment" => 3,
        "elgamal_decryption" => 3,
        "pedersen_commitment_dleq" => 6,
        "bbs_blind_commitment_computation" => 8,
        other => panic!("unknown relation in vector file: {other}"),
    }
}

/// When the specification repository is checked out next to this one, the
/// vendored vector files must be byte-identical to its copies (the vectors'
/// single source of truth is the spec repo's `poc/vectors/`).
#[test]
fn vendored_vectors_are_fresh() {
    let spec_vectors = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../draft-irtf-cfrg-sigma-protocols/poc/vectors");
    if !spec_vectors.is_dir() {
        eprintln!("spec repo not present; skipping freshness check");
        return;
    }
    for name in [
        "sigma-proofs_Shake128_P256.json",
        "sigma-proofs_Shake128_BLS12381.json",
    ] {
        let vendored =
            std::fs::read_to_string(format!("{}/tests/spec/testdata/{name}", env!("CARGO_MANIFEST_DIR")))
                .unwrap_or_else(|e| panic!("cannot read vendored {name}: {e}"));
        let spec_copy = std::fs::read_to_string(spec_vectors.join(name))
            .unwrap_or_else(|e| panic!("cannot read spec copy of {name}: {e}"));
        assert_eq!(vendored, spec_copy, "{name} drifted from the spec repository; re-vendor it");
    }
}
