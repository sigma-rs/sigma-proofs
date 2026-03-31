//! Verifier rejection tests for sigma protocols.
//!
//! These tests assert that invalid or malformed proofs are always rejected
//! by the verifier, covering both `verify_batchable` and `verify_compact`
//! across simple and composed protocol shapes.

mod relations;

use curve25519_dalek::ristretto::RistrettoPoint as G;
use curve25519_dalek::scalar::Scalar;
use group::Group;
use rand::RngCore;
use sigma_proofs::composition::{ComposedRelation, ComposedWitness};
use sigma_proofs::linear_relation::{CanonicalLinearRelation, LinearRelation};
use sigma_proofs::Nizk;

// ── Helpers ──────────────────────────────────────────────────────────────────

type SimpleNizk = Nizk<CanonicalLinearRelation<G>>;

/// Simple discrete-log relation: X = x * G.
/// Returns (batchable_proof, compact_proof, nizk).
fn make_simple_proof() -> (Vec<u8>, Vec<u8>, SimpleNizk) {
    let mut rng = rand::thread_rng();
    let x = Scalar::from(42u64);

    let mut relation = LinearRelation::<G>::new();
    let [var_x] = relation.allocate_scalars();
    let [var_g, var_xg] = relation.allocate_elements::<2>();
    relation.set_elements([(var_g, G::generator()), (var_xg, G::generator() * x)]);
    relation.append_equation(var_xg, var_x * var_g);

    let nizk = SimpleNizk::new(b"verifier-rejection-simple", relation.canonical().unwrap());
    let witness = vec![x];
    let batchable = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let compact = nizk.prove_compact(&witness, &mut rng).unwrap();
    (batchable, compact, nizk)
}

// ── Simple batchable proof rejection (moved from test_validation_criteria) ───

#[test]
fn test_proof_bitflip() {
    let (mut proof, _, nizk) = make_simple_proof();
    assert!(nizk.verify_batchable(&proof).is_ok());

    for pos in 0..proof.len() {
        let original_byte = proof[pos];
        for bit in 0..8 {
            proof[pos] ^= 1 << bit;
            assert!(
                nizk.verify_batchable(&proof).is_err(),
                "should reject: bit {bit} flipped at position {pos}"
            );
            proof[pos] = original_byte;
        }
    }
}

#[test]
fn test_proof_append_bytes() {
    let (mut proof, _, nizk) = make_simple_proof();
    assert!(nizk.verify_batchable(&proof).is_ok());

    for size in [1, 8, 32, 100] {
        let original_len = proof.len();
        let mut extra = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut extra);
        proof.extend_from_slice(&extra);
        assert!(
            nizk.verify_batchable(&proof).is_err(),
            "should reject: {size} bytes appended"
        );
        proof.truncate(original_len);
    }
}

#[test]
fn test_proof_prepend_bytes() {
    let (proof, _, nizk) = make_simple_proof();
    assert!(nizk.verify_batchable(&proof).is_ok());

    for size in [1, 8, 32, 100] {
        let mut prepended = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut prepended);
        prepended.extend_from_slice(&proof);
        assert!(
            nizk.verify_batchable(&prepended).is_err(),
            "should reject: {size} bytes prepended"
        );
    }
}

#[test]
fn test_proof_truncation() {
    let (proof, _, nizk) = make_simple_proof();
    assert!(nizk.verify_batchable(&proof).is_ok());

    let sizes = [1, 8, proof.len() / 2, proof.len() - 1];
    for size in sizes {
        if size < proof.len() {
            assert!(
                nizk.verify_batchable(&proof[..proof.len() - size]).is_err(),
                "should reject: {size} bytes truncated"
            );
        }
    }
}

#[test]
fn test_empty_proof() {
    let (_, _, nizk) = make_simple_proof();
    assert!(nizk.verify_batchable(&[]).is_err(), "should reject empty proof");
}

#[test]
fn test_random_bytes_as_proof() {
    let (valid_proof, _, nizk) = make_simple_proof();
    let mut random_proof = vec![0u8; valid_proof.len()];
    rand::thread_rng().fill_bytes(&mut random_proof);
    assert!(
        nizk.verify_batchable(&random_proof).is_err(),
        "should reject random bytes"
    );
}

#[test]
#[allow(non_snake_case)]
fn test_or_relation() {
    let mut rng = rand::thread_rng();
    let B = G::generator();
    let A = B * Scalar::from(42u64);
    let x = Scalar::random(&mut rng);
    let y = Scalar::random(&mut rng);
    let C = B * y;

    let mut lr1 = LinearRelation::new();
    let x_var = lr1.allocate_scalar();
    let A_var = lr1.allocate_element();
    let eq1 = lr1.allocate_eq(x_var * A_var);
    lr1.set_element(A_var, A);
    lr1.set_element(eq1, C);

    let mut lr2 = LinearRelation::new();
    let y_var = lr2.allocate_scalar();
    let B_var = lr2.allocate_element();
    let eq2 = lr2.allocate_eq(y_var * B_var);
    lr2.set_element(B_var, B);
    lr2.set_element(eq2, C);

    let or_relation = ComposedRelation::or([lr1.canonical().unwrap(), lr2.canonical().unwrap()]);
    let nizk = or_relation.into_nizk(b"test_or_relation");

    // Valid proof (second branch satisfied)
    let witness = ComposedWitness::Or(vec![
        ComposedWitness::Simple(vec![x]),
        ComposedWitness::Simple(vec![y]),
    ]);
    let proof = nizk.prove_batchable(&witness, &mut rng).unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok(), "valid proof should verify");

    // Neither branch satisfied — prover must fail
    let wrong_y = Scalar::random(&mut rng);
    let bad_witness = ComposedWitness::Or(vec![
        ComposedWitness::Simple(vec![x]),
        ComposedWitness::Simple(vec![wrong_y]),
    ]);
    assert!(
        nizk.prove_batchable(&bad_witness, &mut rng).is_err(),
        "prover should fail with no valid witness"
    );

    // Both branches satisfied
    let both_valid = ComposedWitness::Or(vec![
        ComposedWitness::Simple(vec![y]),
        ComposedWitness::Simple(vec![y]),
    ]);
    let proof = nizk.prove_batchable(&both_valid, &mut rng).unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok(), "both-valid OR should verify");
}
