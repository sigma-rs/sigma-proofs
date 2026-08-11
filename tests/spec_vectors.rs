//! The test-vector suite of the specification's "Test Vectors" appendix.
//!
//! For each valid vector the relation is rebuilt programmatically from the
//! seeded PRNG, its serialization is checked against the vendored instance
//! bytes, the vendored NARG string is verified, and the proof is regenerated
//! byte-exactly. Each adversarial vector is checked to reject while its
//! `BaseId` baseline accepts. Batch verification accepts the set of valid
//! batchable proofs and rejects any contaminated batch.

use group::prime::PrimeGroup;
use spongefish::{instantiations::Shake128, NargReader};

use sigma_proofs::codec::ScalarCodec;
use sigma_proofs::linear_relation::Instance;
use sigma_proofs::{
    derive_session_id, prove_batchable_with, prove_compact_with, verify_batch_with,
    verify_batchable_with, verify_compact_with, LinearRelation,
};

mod spec;
use spec::{rng::TestDrng, vectors::TestVector};

#[test]
fn test_spec_vectors_p256() {
    run_suite::<p256::ProjectivePoint>(
        include_str!("./spec/testdata/sigma-proofs_Shake128_P256.json"),
        include_str!("./spec/testdata/sigma-proofs-invalid_Shake128_P256.json"),
    );
}

#[test]
fn test_spec_vectors_bls12381() {
    run_suite::<bls12_381::G1Projective>(
        include_str!("./spec/testdata/sigma-proofs_Shake128_BLS12381.json"),
        include_str!("./spec/testdata/sigma-proofs-invalid_Shake128_BLS12381.json"),
    );
}

/// Builds the named relation, drawing the auxiliary-generator and witness
/// scalars from `rng` in the order pinned by the specification's generator.
#[allow(non_snake_case)]
fn build_relation<G>(name: &str, rng: &mut TestDrng) -> (Instance<G>, Vec<G::Scalar>)
where
    G: PrimeGroup + sigma_proofs::MultiScalarMul + sigma_proofs::codec::GroupCodec,
    G::Scalar: ScalarCodec,
{
    let mut lr = LinearRelation::<G>::new();
    let generator = lr.generator();
    match name {
        // X = x * G
        "discrete_logarithm" => {
            let x = lr.allocate_scalar();
            lr.allocate_eq(x * generator);
            let [x_val] = core::array::from_fn(|_| <G as group::Group>::Scalar::sample(rng));
            let witness = vec![x_val];
            let instance = lr.compile_with_witness(&witness).unwrap();
            (instance, witness)
        }
        // X = x * G, Y = x * H
        "dleq" | "dleq_derived_element" => {
            let [h] = core::array::from_fn(|_| <G as group::Group>::Scalar::sample(rng));
            let [x_val] = core::array::from_fn(|_| <G as group::Group>::Scalar::sample(rng));
            let x = lr.allocate_scalar();
            lr.allocate_eq(x * generator);
            let var_H = lr.allocate_element();
            lr.allocate_eq(x * var_H);
            lr.set_element(var_H, G::generator() * h);
            let witness = vec![x_val];
            let instance = lr.compile_with_witness(&witness).unwrap();
            (instance, witness)
        }
        // C = x * G + r * H
        "pedersen_commitment" => {
            let [h, x_val, r_val] =
                core::array::from_fn(|_| <G as group::Group>::Scalar::sample(rng));
            let [x, r] = lr.allocate_scalars();
            let var_H = lr.allocate_element();
            lr.allocate_eq(x * generator + r * var_H);
            lr.set_element(var_H, G::generator() * h);
            let witness = vec![x_val, r_val];
            let instance = lr.compile_with_witness(&witness).unwrap();
            (instance, witness)
        }
        // X = x0 * G0 + x1 * G1, Y = x0 * G2 + x1 * G3
        "pedersen_commitment_dleq" => {
            let gens =
                core::array::from_fn::<_, 4, _>(|_| <G as group::Group>::Scalar::sample(rng));
            let [x0_val, x1_val] =
                core::array::from_fn(|_| <G as group::Group>::Scalar::sample(rng));
            let [x0, x1] = lr.allocate_scalars();
            let [var_G0, var_G1] = lr.allocate_elements();
            lr.allocate_eq(x0 * var_G0 + x1 * var_G1);
            let [var_G2, var_G3] = lr.allocate_elements();
            lr.allocate_eq(x0 * var_G2 + x1 * var_G3);
            for (var, h) in itertools::zip_eq([var_G0, var_G1, var_G2, var_G3], gens) {
                lr.set_element(var, G::generator() * h);
            }
            let witness = vec![x0_val, x1_val];
            let instance = lr.compile_with_witness(&witness).unwrap();
            (instance, witness)
        }
        // C = blind * Q2 + msg_1 * J1 + msg_2 * J2 + msg_3 * J3
        "bbs_blind_commitment_computation" => {
            let gens =
                core::array::from_fn::<_, 4, _>(|_| <G as group::Group>::Scalar::sample(rng));
            let [m1, m2, m3] = core::array::from_fn(|_| <G as group::Group>::Scalar::sample(rng));
            let [blind_val] = core::array::from_fn(|_| <G as group::Group>::Scalar::sample(rng));
            let [blind, v1, v2, v3] = lr.allocate_scalars();
            let [var_Q2, var_J1, var_J2, var_J3] = lr.allocate_elements();
            lr.allocate_eq(blind * var_Q2 + v1 * var_J1 + v2 * var_J2 + v3 * var_J3);
            for (var, h) in itertools::zip_eq([var_Q2, var_J1, var_J2, var_J3], gens) {
                lr.set_element(var, G::generator() * h);
            }
            let witness = vec![blind_val, m1, m2, m3];
            let instance = lr.compile_with_witness(&witness).unwrap();
            (instance, witness)
        }
        // X = x * G, M + E1 = x * E0
        "elgamal_decryption" => {
            let [x_val, r, m] = core::array::from_fn(|_| <G as group::Group>::Scalar::sample(rng));
            let x = lr.allocate_scalar();
            let var_X = lr.allocate_eq(x * generator);
            let [var_E0, var_E1, var_M] = lr.allocate_elements();
            lr.append_equation(var_M, x * var_E0 - var_E1);
            let X = G::generator() * x_val;
            let E0 = G::generator() * r;
            let M = G::generator() * m;
            lr.set_element(var_X, X);
            lr.set_element(var_E0, E0);
            lr.set_element(var_E1, X * r - M);
            lr.set_element(var_M, M);
            (lr.compile().unwrap(), vec![x_val])
        }
        other => panic!("unknown relation in vector file: {other}"),
    }
}

fn decode_scalars<F: ScalarCodec>(bytes: &[u8]) -> Vec<F> {
    let mut reader = NargReader::new(bytes);
    let mut scalars = Vec::new();
    while !reader.is_empty() {
        scalars.push(F::deserialize_scalar(&mut reader).expect("invalid witness scalar"));
    }
    scalars
}

/// Runs a vector as a verifier would: parse the instance, then verify the
/// NARG string under the vector's tag. Any rejection point counts.
fn record_verifies<G>(record: &TestVector) -> bool
where
    G: PrimeGroup + sigma_proofs::MultiScalarMul + sigma_proofs::codec::GroupCodec,
    G::Scalar: ScalarCodec,
{
    let Ok(instance) = Instance::<G>::deserialize(&record.instance.0) else {
        return false;
    };
    let session_id = derive_session_id::<Shake128>(record.tag.as_bytes());
    match record.flavor.as_str() {
        "batchable" => {
            verify_batchable_with::<Shake128, _>(&session_id, &instance, &record.narg_string.0)
                .is_ok()
        }
        "compact" => {
            verify_compact_with::<Shake128, _>(&session_id, &instance, &record.narg_string.0)
                .is_ok()
        }
        other => panic!("unknown flavor {other}"),
    }
}

fn run_suite<G>(valid_json: &str, invalid_json: &str)
where
    G: PrimeGroup + sigma_proofs::MultiScalarMul + sigma_proofs::codec::GroupCodec,
    G::Scalar: ScalarCodec,
{
    let valid: Vec<TestVector> = serde_json::from_str(valid_json).unwrap();
    let invalid: Vec<TestVector> = serde_json::from_str(invalid_json).unwrap();

    for record in &valid {
        assert_eq!(record.expected, "accept", "{}", record.id);
        let suite = &record.ciphersuite;
        let relation = record.relation.as_deref().unwrap();

        // Rebuild the instance and witness from the seeded PRNG.
        let mut rng = crate::spec::rng::instance_stream(suite, relation);
        let (instance, witness) = build_relation::<G>(relation, &mut rng);
        assert_eq!(
            instance.serialize(),
            record.instance.0,
            "instance serialization mismatch for {}",
            record.id
        );
        assert_eq!(
            witness,
            decode_scalars::<G::Scalar>(&record.witness.as_ref().unwrap().0),
            "witness mismatch for {}",
            record.id
        );

        let session_id = derive_session_id::<Shake128>(record.tag.as_bytes());
        assert_eq!(
            session_id.as_bytes().as_slice(),
            record.session_id.as_ref().unwrap().0,
            "session id mismatch for {}",
            record.id
        );

        // The vendored NARG string verifies, and regenerating the proof with
        // the flavor's nonce stream reproduces it byte-exactly.
        match record.flavor.as_str() {
            "batchable" => {
                verify_batchable_with::<Shake128, _>(&session_id, &instance, &record.narg_string.0)
                    .unwrap_or_else(|e| panic!("{} did not verify: {e:?}", record.id));
                let mut nonce_rng = crate::spec::rng::nonce_stream("DSFS", suite, relation);
                let regenerated = prove_batchable_with::<Shake128, _>(
                    &session_id,
                    &instance,
                    &witness,
                    &mut nonce_rng,
                )
                .unwrap();
                assert_eq!(regenerated, record.narg_string.0, "{}", record.id);
            }
            "compact" => {
                verify_compact_with::<Shake128, _>(&session_id, &instance, &record.narg_string.0)
                    .unwrap_or_else(|e| panic!("{} did not verify: {e:?}", record.id));
                let mut nonce_rng = crate::spec::rng::nonce_stream("CMPT", suite, relation);
                let regenerated = prove_compact_with::<Shake128, _>(
                    &session_id,
                    &instance,
                    &witness,
                    &mut nonce_rng,
                )
                .unwrap();
                assert_eq!(regenerated, record.narg_string.0, "{}", record.id);
            }
            other => panic!("unknown flavor {other}"),
        }
    }

    // Adversarial vectors: every reject rejects while its BaseId baseline
    // accepts (a verifier that rejects everything must fail this pairing);
    // accept entries are baselines themselves.
    for record in &invalid {
        let verifies = record_verifies::<G>(record);
        match record.expected.as_str() {
            "accept" => assert!(verifies, "{} must accept", record.id),
            "reject" => {
                assert!(!verifies, "{} must reject", record.id);
                let base_id = record.base_id.as_ref().unwrap();
                let baseline = valid
                    .iter()
                    .find(|r| &r.id == base_id)
                    .unwrap_or_else(|| panic!("{}: baseline {base_id} not found", record.id));
                assert!(
                    record_verifies::<G>(baseline),
                    "baseline {base_id} must accept"
                );
            }
            other => panic!("unknown expectation {other}"),
        }
    }

    // Batch verification: the set of valid batchable proofs accepts, and a
    // batch contaminated with any rejecting batchable vector rejects.
    let batchable: Vec<_> = valid
        .iter()
        .filter(|r| r.flavor == "batchable")
        .map(|r| {
            (
                derive_session_id::<Shake128>(r.tag.as_bytes()),
                Instance::<G>::deserialize(&r.instance.0).unwrap(),
                r.narg_string.0.as_slice(),
            )
        })
        .collect();
    let batch: Vec<_> = batchable
        .iter()
        .map(|(sid, instance, narg)| (sid, instance, *narg))
        .collect();
    verify_batch_with::<Shake128, G>(&batch).expect("batch of valid batchable proofs must verify");

    let (sid0, instance0, narg0) = &batchable[0];
    for record in &invalid {
        if record.flavor != "batchable" || record.expected != "reject" {
            continue;
        }
        let rejected = match Instance::<G>::deserialize(&record.instance.0) {
            Err(_) => true,
            Ok(instance) => {
                let sid = derive_session_id::<Shake128>(record.tag.as_bytes());
                verify_batch_with::<Shake128, G>(&[
                    (sid0, instance0, narg0),
                    (&sid, &instance, &record.narg_string.0),
                ])
                .is_err()
            }
        };
        assert!(
            rejected,
            "contaminated batch with {} must reject",
            record.id
        );
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
        "sigma-proofs-invalid_Shake128_P256.json",
        "sigma-proofs-invalid_Shake128_BLS12381.json",
    ] {
        let vendored = std::fs::read_to_string(format!(
            "{}/tests/spec/testdata/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap_or_else(|e| panic!("cannot read vendored {name}: {e}"));
        let spec_copy = std::fs::read_to_string(spec_vectors.join(name))
            .unwrap_or_else(|e| panic!("cannot read spec copy of {name}: {e}"));
        assert_eq!(
            vendored, spec_copy,
            "{name} drifted from the spec repository; re-vendor it"
        );
    }
}
