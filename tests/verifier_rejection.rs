//! Verifier rejection tests for sigma protocols.
//!
//! These tests assert that invalid or malformed proofs are always rejected
//! by the verifier, covering both `verify_batchable` and `verify_compact`
//! across simple and composed protocol shapes.

// Not all relations are used in this test
#[allow(unused)]
mod relations;

use std::ops::Bound;

use curve25519_dalek::ristretto::RistrettoPoint as G;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use sigma_proofs::composition::{ComposedRelation, ComposedWitness};
use sigma_proofs::linear_relation::CanonicalLinearRelation;
use sigma_proofs::Nizk;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Returns a clone of `data` with bit `bit` flipped (global bit index, LSB-first within each byte).
fn bitflip(data: &[u8], bit: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out[bit / 8] ^= 1 << (bit % 8);
    out
}

/// Returns `data` with `n` random bytes appended.
fn append_random_bytes(data: &[u8], n: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    let start = out.len();
    out.resize(start + n, 0);
    rand::thread_rng().fill_bytes(&mut out[start..]);
    out
}

/// Returns `data` with `n` random bytes prepended.
fn prepend_random_bytes(data: &[u8], n: usize) -> Vec<u8> {
    let mut prefix = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut prefix);
    prefix.extend_from_slice(data);
    prefix
}

/// Returns a clone of `data` with the bytes in `range` removed.
///
/// - `remove_bytes(&buf, 10..)` removes everything from index 10 to the end.
/// - `remove_bytes(&buf, ..10)` removes the first 10 bytes.
/// - `remove_bytes(&buf, 3..7)` removes bytes at indices 3, 4, 5, 6.
fn remove_bytes(data: &[u8], range: impl std::ops::RangeBounds<usize>) -> Vec<u8> {
    // Translate the bound for excluding bytes into what bytes are included.
    let start = match range.start_bound() {
        Bound::Included(&n) => Bound::Excluded(n),
        Bound::Excluded(&n) => Bound::Included(n),
        Bound::Unbounded => Bound::Excluded(0),
    };
    let end = match range.end_bound() {
        Bound::Included(&n) => Bound::Excluded(n),
        Bound::Excluded(&n) => Bound::Included(n),
        Bound::Unbounded => Bound::Included(data.len()),
    };
    let mut out = data[(Bound::Unbounded, start)].to_vec();
    out.extend_from_slice(&data[(end, Bound::Unbounded)]);
    out
}

const SIMPLE_SESSION_ID: &[u8] = b"verifier-rejection-simple";

/// Simple discrete-log relation.
/// Returns (witness, nizk).
fn make_simple_nizk() -> (Vec<Scalar>, Nizk<CanonicalLinearRelation<G>>) {
    let mut rng = rand::thread_rng();
    let (instance, witness) = relations::dleq::<G>(&mut rng);
    (witness, Nizk::new(SIMPLE_SESSION_ID, instance))
}

// ── Simple batchable proof rejection ─────────────────────────────────────────

#[test]
fn batchable_bitflip() {
    let (witness, nizk) = make_simple_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for i in 0..proof.len() * 8 {
        assert!(
            nizk.verify_batchable(&bitflip(&proof, i)).is_err(),
            "should reject: bit {i} flipped"
        );
    }
}

#[test]
fn batchable_append_bytes() {
    let (witness, nizk) = make_simple_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for size in [1, 8, 32, 100] {
        assert!(
            nizk.verify_batchable(&append_random_bytes(&proof, size))
                .is_err(),
            "should reject: {size} bytes appended"
        );
    }
}

#[test]
fn batchable_prepend_bytes() {
    let (witness, nizk) = make_simple_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for size in [1, 8, 32, 100] {
        assert!(
            nizk.verify_batchable(&prepend_random_bytes(&proof, size))
                .is_err(),
            "should reject: {size} bytes prepended"
        );
    }
}

#[test]
fn batchable_truncation() {
    let (witness, nizk) = make_simple_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for size in [1, 8, proof.len() / 2, proof.len() - 1] {
        if size < proof.len() {
            assert!(
                nizk.verify_batchable(&remove_bytes(&proof, (proof.len() - size)..))
                    .is_err(),
                "should reject: {size} bytes truncated"
            );
        }
    }
}

#[test]
fn batchable_empty_proof() {
    let (_, nizk) = make_simple_nizk();
    assert!(
        nizk.verify_batchable(&[]).is_err(),
        "should reject empty proof"
    );
}

#[test]
fn batchable_random_bytes_as_proof() {
    let (witness, nizk) = make_simple_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    let mut random_proof = vec![0u8; proof.len()];
    rand::thread_rng().fill_bytes(&mut random_proof);
    assert!(
        nizk.verify_batchable(&random_proof).is_err(),
        "should reject random bytes"
    );
}

// ── Simple compact proof rejection ───────────────────────────────────────────

#[test]
fn compact_bitflip() {
    let (witness, nizk) = make_simple_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for i in 0..proof.len() * 8 {
        assert!(
            nizk.verify_compact(&bitflip(&proof, i)).is_err(),
            "should reject: bit {i} flipped"
        );
    }
}

#[test]
fn compact_append_bytes() {
    let (witness, nizk) = make_simple_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for size in [1, 8, 32, 100] {
        assert!(
            nizk.verify_compact(&append_random_bytes(&proof, size))
                .is_err(),
            "should reject: {size} bytes appended"
        );
    }
}

#[test]
fn compact_prepend_bytes() {
    let (witness, nizk) = make_simple_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for size in [1, 8, 32, 100] {
        assert!(
            nizk.verify_compact(&prepend_random_bytes(&proof, size))
                .is_err(),
            "should reject: {size} bytes prepended"
        );
    }
}

#[test]
fn compact_truncation() {
    let (witness, nizk) = make_simple_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for size in [1, 8, proof.len() / 2, proof.len() - 1] {
        if size < proof.len() {
            assert!(
                nizk.verify_compact(&remove_bytes(&proof, (proof.len() - size)..))
                    .is_err(),
                "should reject: {size} bytes truncated"
            );
        }
    }
}

#[test]
fn compact_empty() {
    let (_, nizk) = make_simple_nizk();
    assert!(
        nizk.verify_compact(&[]).is_err(),
        "should reject empty compact proof"
    );
}

#[test]
fn compact_random_bytes() {
    let (witness, nizk) = make_simple_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    let mut random_proof = vec![0u8; proof.len()];
    rand::thread_rng().fill_bytes(&mut random_proof);
    assert!(
        nizk.verify_compact(&random_proof).is_err(),
        "should reject random bytes as compact proof"
    );
}

// ── Cross-instance and session-ID mismatch ────────────────────────────────────

#[test]
fn batchable_wrong_session_id() {
    let mut rng = rand::thread_rng();
    let (instance, witness) = relations::dleq::<G>(&mut rng);
    let nizk = Nizk::new(b"some-session-id", instance.clone());
    let wrong_session = Nizk::new(b"different-session-id", instance);
    let proof = nizk.prove_batchable(&witness, &mut rng).unwrap();
    assert!(
        wrong_session.verify_batchable(&proof).is_err(),
        "should reject batchable proof with wrong session ID"
    );
}

#[test]
fn compact_wrong_session_id() {
    let mut rng = rand::thread_rng();
    let (instance, witness) = relations::dleq::<G>(&mut rng);
    let nizk = Nizk::new(b"some-session-id", instance.clone());
    let wrong_session = Nizk::new(b"different-session-id", instance);
    let proof = nizk.prove_compact(&witness, &mut rng).unwrap();
    assert!(
        wrong_session.verify_compact(&proof).is_err(),
        "should reject compact proof with wrong session ID"
    );
}

#[test]
fn batchable_wrong_instance() {
    let mut rng = rand::thread_rng();
    // NOTE: Each call to relations::dleq results in a different instance.
    let (instance_a, witness_a) = relations::dleq::<G>(&mut rng);
    let (instance_b, _) = relations::dleq::<G>(&mut rng);
    let nizk_a = Nizk::new(SIMPLE_SESSION_ID, instance_a);
    let nizk_b = Nizk::new(SIMPLE_SESSION_ID, instance_b);
    let proof = nizk_a.prove_batchable(&witness_a, &mut rng).unwrap();
    assert!(
        nizk_b.verify_batchable(&proof).is_err(),
        "should reject batchable proof for different instance"
    );
}

#[test]
fn compact_wrong_instance() {
    let mut rng = rand::thread_rng();
    let (instance_a, witness_a) = relations::dleq::<G>(&mut rng);
    let (instance_b, _) = relations::dleq::<G>(&mut rng);
    let nizk_a = Nizk::new(SIMPLE_SESSION_ID, instance_a);
    let nizk_b = Nizk::new(SIMPLE_SESSION_ID, instance_b);
    let proof = nizk_a.prove_compact(&witness_a, &mut rng).unwrap();
    assert!(
        nizk_b.verify_compact(&proof).is_err(),
        "should reject compact proof for different instance"
    );
}

// ── Composed AND rejection tests ─────────────────────────────────────────────

/// AND(dleq, pedersen_commitment) with valid witnesses.
/// Returns (witness, nizk).
fn make_and_nizk() -> (ComposedWitness<G>, Nizk<ComposedRelation<G>>) {
    let mut rng = rand::thread_rng();
    let (rel1, wit1) = relations::dleq::<G>(&mut rng);
    let (rel2, wit2) = relations::pedersen_commitment::<G>(&mut rng);
    let and_relation = ComposedRelation::<G>::and([rel1, rel2]);
    let nizk = and_relation.into_nizk(b"verifier-rejection-and");
    let witness =
        ComposedWitness::and([ComposedWitness::Simple(wit1), ComposedWitness::Simple(wit2)]);
    (witness, nizk)
}

#[test]
fn and_batchable_bitflip() {
    let (witness, nizk) = make_and_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for i in 0..proof.len() * 8 {
        assert!(
            nizk.verify_batchable(&bitflip(&proof, i)).is_err(),
            "AND batchable: bit {i} flipped"
        );
    }
}

#[test]
fn and_compact_bitflip() {
    let (witness, nizk) = make_and_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for i in 0..proof.len() * 8 {
        assert!(
            nizk.verify_compact(&bitflip(&proof, i)).is_err(),
            "AND compact: bit {i} flipped"
        );
    }
}

#[test]
fn and_batchable_append() {
    let (witness, nizk) = make_and_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for size in [1, 8, 32, 100] {
        assert!(
            nizk.verify_batchable(&append_random_bytes(&proof, size))
                .is_err(),
            "AND batchable: {size} bytes appended"
        );
    }
}

#[test]
fn and_compact_append() {
    let (witness, nizk) = make_and_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for size in [1, 8, 32, 100] {
        assert!(
            nizk.verify_compact(&append_random_bytes(&proof, size))
                .is_err(),
            "AND compact: {size} bytes appended"
        );
    }
}

#[test]
fn and_batchable_truncation() {
    let (witness, nizk) = make_and_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for size in [1, 8, proof.len() / 2, proof.len() - 1] {
        if size < proof.len() {
            assert!(
                nizk.verify_batchable(&remove_bytes(&proof, (proof.len() - size)..))
                    .is_err(),
                "AND batchable: {size} bytes truncated"
            );
        }
    }
}

#[test]
fn and_compact_truncation() {
    let (witness, nizk) = make_and_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for size in [1, 8, proof.len() / 2, proof.len() - 1] {
        if size < proof.len() {
            assert!(
                nizk.verify_compact(&remove_bytes(&proof, (proof.len() - size)..))
                    .is_err(),
                "AND compact: {size} bytes truncated"
            );
        }
    }
}

#[test]
fn and_batchable_empty() {
    let (_, nizk) = make_and_nizk();
    assert!(
        nizk.verify_batchable(&[]).is_err(),
        "should reject empty AND batchable proof"
    );
}

#[test]
fn and_compact_empty() {
    let (_, nizk) = make_and_nizk();
    assert!(
        nizk.verify_compact(&[]).is_err(),
        "should reject empty AND compact proof"
    );
}

#[test]
fn and_one_wrong_witness() {
    let mut rng = rand::thread_rng();
    let (rel1, wit1) = relations::dleq::<G>(&mut rng);
    let (rel2, _) = relations::pedersen_commitment::<G>(&mut rng);

    let and_relation = ComposedRelation::<G>::and([rel1, rel2]);
    let nizk = and_relation.into_nizk(b"verifier-rejection-and");

    // Second witness is wrong (random scalars, not a valid opening of rel2)
    let bad_wit2: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut rng)).collect();
    let witness = ComposedWitness::and([
        ComposedWitness::Simple(wit1),
        ComposedWitness::Simple(bad_wit2),
    ]);
    // The prover doesn't validate the witness; the verifier must reject the resulting proof.
    let proof = nizk.prove_batchable(&witness, &mut rng).unwrap();
    assert!(
        nizk.verify_batchable(&proof).is_err(),
        "AND verifier should reject proof produced with one invalid witness"
    );
}

// ── Composed OR rejection tests ──────────────────────────────────────────────

/// OR(dleq, dleq) with one valid witness (second branch).
/// Returns (witness, nizk).
fn make_or_nizk() -> (ComposedWitness<G>, Nizk<ComposedRelation<G>>) {
    let mut rng = rand::thread_rng();
    let (rel1, _) = relations::dleq::<G>(&mut rng);
    let (rel2, wit2) = relations::dleq::<G>(&mut rng);

    let or_relation = ComposedRelation::<G>::or([rel1, rel2]);
    let nizk = or_relation.into_nizk(b"verifier-rejection-or");

    // Provide a dummy (zero) witness for the first branch and valid for the second.
    // For OR, all branches must have a witness slot — only one needs to be valid.
    let dummy_wit1: Vec<Scalar> = wit2.iter().map(|_| Scalar::ZERO).collect();
    let witness = ComposedWitness::or([
        ComposedWitness::Simple(dummy_wit1),
        ComposedWitness::Simple(wit2),
    ]);
    (witness, nizk)
}

#[test]
fn or_batchable_bitflip() {
    let (witness, nizk) = make_or_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for i in 0..proof.len() * 8 {
        assert!(
            nizk.verify_batchable(&bitflip(&proof, i)).is_err(),
            "OR batchable: bit {i} flipped"
        );
    }
}

#[test]
fn or_compact_bitflip() {
    let (witness, nizk) = make_or_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for i in 0..proof.len() * 8 {
        assert!(
            nizk.verify_compact(&bitflip(&proof, i)).is_err(),
            "OR compact: bit {i} flipped"
        );
    }
}

#[test]
fn or_batchable_append() {
    let (witness, nizk) = make_or_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for size in [1, 8, 32, 100] {
        assert!(
            nizk.verify_batchable(&append_random_bytes(&proof, size))
                .is_err(),
            "OR batchable: {size} bytes appended"
        );
    }
}

#[test]
fn or_compact_append() {
    let (witness, nizk) = make_or_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for size in [1, 8, 32, 100] {
        assert!(
            nizk.verify_compact(&append_random_bytes(&proof, size))
                .is_err(),
            "OR compact: {size} bytes appended"
        );
    }
}

#[test]
fn or_batchable_truncation() {
    let (witness, nizk) = make_or_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for size in [1, 8, proof.len() / 2, proof.len() - 1] {
        if size < proof.len() {
            assert!(
                nizk.verify_batchable(&remove_bytes(&proof, (proof.len() - size)..))
                    .is_err(),
                "OR batchable: {size} bytes truncated"
            );
        }
    }
}

#[test]
fn or_compact_truncation() {
    let (witness, nizk) = make_or_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for size in [1, 8, proof.len() / 2, proof.len() - 1] {
        if size < proof.len() {
            assert!(
                nizk.verify_compact(&remove_bytes(&proof, (proof.len() - size)..))
                    .is_err(),
                "OR compact: {size} bytes truncated"
            );
        }
    }
}

#[test]
fn or_batchable_empty() {
    let (_, nizk) = make_or_nizk();
    assert!(
        nizk.verify_batchable(&[]).is_err(),
        "should reject empty OR batchable proof"
    );
}

#[test]
fn or_compact_empty() {
    let (_, nizk) = make_or_nizk();
    assert!(
        nizk.verify_compact(&[]).is_err(),
        "should reject empty OR compact proof"
    );
}

#[test]
fn or_no_valid_witness() {
    let mut rng = rand::thread_rng();
    let (rel1, _) = relations::dleq::<G>(&mut rng);
    let (rel2, wit2) = relations::dleq::<G>(&mut rng);

    let or_relation = ComposedRelation::<G>::or([rel1, rel2]);
    let nizk = or_relation.into_nizk(b"verifier-rejection-or");

    // Both witnesses are wrong (random scalars satisfy neither branch)
    let bad_wit1: Vec<Scalar> = wit2.iter().map(|_| Scalar::random(&mut rng)).collect();
    let bad_wit2: Vec<Scalar> = wit2.iter().map(|_| Scalar::random(&mut rng)).collect();
    let witness = ComposedWitness::or([
        ComposedWitness::Simple(bad_wit1),
        ComposedWitness::Simple(bad_wit2),
    ]);
    assert!(
        nizk.prove_batchable(&witness, &mut rng).is_err(),
        "OR prover should fail when no branch has a valid witness"
    );
}

// ── Composed Threshold rejection tests ──────────────────────────────────────

/// Threshold(2, [dleq, dleq, dleq]) with 2 valid witnesses and 1 wrong.
/// Returns (witness, nizk).
fn make_threshold_nizk() -> (ComposedWitness<G>, Nizk<ComposedRelation<G>>) {
    let mut rng = rand::thread_rng();
    let (rel1, wit1) = relations::dleq::<G>(&mut rng);
    let (rel2, wit2) = relations::dleq::<G>(&mut rng);
    let (rel3, wit3) = relations::dleq::<G>(&mut rng);

    // Third witness is intentionally wrong
    let wrong_wit3: Vec<Scalar> = wit3.iter().map(|_| Scalar::random(&mut rng)).collect();

    let threshold_relation = ComposedRelation::<G>::threshold(2, [rel1, rel2, rel3]);
    let nizk = threshold_relation.into_nizk(b"verifier-rejection-threshold");

    let witness = ComposedWitness::threshold([wit1, wit2, wrong_wit3]);
    (witness, nizk)
}

#[test]
fn threshold_batchable_bitflip() {
    let (witness, nizk) = make_threshold_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for i in 0..proof.len() * 8 {
        assert!(
            nizk.verify_batchable(&bitflip(&proof, i)).is_err(),
            "threshold batchable: bit {i} flipped"
        );
    }
}

#[test]
fn threshold_compact_bitflip() {
    let (witness, nizk) = make_threshold_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for i in 0..proof.len() * 8 {
        assert!(
            nizk.verify_compact(&bitflip(&proof, i)).is_err(),
            "threshold compact: bit {i} flipped"
        );
    }
}

#[test]
fn threshold_batchable_append() {
    let (witness, nizk) = make_threshold_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for size in [1, 8, 32, 100] {
        assert!(
            nizk.verify_batchable(&append_random_bytes(&proof, size))
                .is_err(),
            "threshold batchable: {size} bytes appended"
        );
    }
}

#[test]
fn threshold_compact_append() {
    let (witness, nizk) = make_threshold_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for size in [1, 8, 32, 100] {
        assert!(
            nizk.verify_compact(&append_random_bytes(&proof, size))
                .is_err(),
            "threshold compact: {size} bytes appended"
        );
    }
}

#[test]
fn threshold_batchable_truncation() {
    let (witness, nizk) = make_threshold_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for size in [1, 8, proof.len() / 2, proof.len() - 1] {
        if size < proof.len() {
            assert!(
                nizk.verify_batchable(&remove_bytes(&proof, (proof.len() - size)..))
                    .is_err(),
                "threshold batchable: {size} bytes truncated"
            );
        }
    }
}

#[test]
fn threshold_compact_truncation() {
    let (witness, nizk) = make_threshold_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for size in [1, 8, proof.len() / 2, proof.len() - 1] {
        if size < proof.len() {
            assert!(
                nizk.verify_compact(&remove_bytes(&proof, (proof.len() - size)..))
                    .is_err(),
                "threshold compact: {size} bytes truncated"
            );
        }
    }
}

#[test]
fn threshold_batchable_empty() {
    let (_, nizk) = make_threshold_nizk();
    assert!(
        nizk.verify_batchable(&[]).is_err(),
        "should reject empty threshold batchable proof"
    );
}

#[test]
fn threshold_compact_empty() {
    let (_, nizk) = make_threshold_nizk();
    assert!(
        nizk.verify_compact(&[]).is_err(),
        "should reject empty threshold compact proof"
    );
}

#[test]
fn threshold_insufficient_witnesses() {
    let mut rng = rand::thread_rng();
    let (rel1, wit1) = relations::dleq::<G>(&mut rng);
    let (rel2, wit2) = relations::dleq::<G>(&mut rng);
    let (rel3, _) = relations::dleq::<G>(&mut rng);

    // Only 1 valid witness in a 2-of-3 threshold: prover should fail.
    let wrong_wit2: Vec<Scalar> = wit2.iter().map(|_| Scalar::random(&mut rng)).collect();
    let wrong_wit3: Vec<Scalar> = wit2.iter().map(|_| Scalar::random(&mut rng)).collect();

    let threshold_relation = ComposedRelation::<G>::threshold(2, [rel1, rel2, rel3]);
    let nizk = threshold_relation.into_nizk(b"verifier-rejection-threshold");

    let witness = ComposedWitness::threshold([wit1, wrong_wit2, wrong_wit3]);
    assert!(
        nizk.prove_batchable(&witness, &mut rng).is_err(),
        "threshold prover should fail with only 1 of 2 required witnesses"
    );
}

// ── Nested composition rejection tests ──────────────────────────────────────

/// AND(OR(dleq, dleq), Simple(pedersen_commitment)) with valid witnesses.
/// Returns (witness, nizk).
fn make_nested_nizk() -> (ComposedWitness<G>, Nizk<ComposedRelation<G>>) {
    let mut rng = rand::thread_rng();

    // OR branch: prove second dleq
    let (dleq1, _) = relations::dleq::<G>(&mut rng);
    let (dleq2, wit_dleq2) = relations::dleq::<G>(&mut rng);
    let dummy_wit1: Vec<Scalar> = wit_dleq2.iter().map(|_| Scalar::ZERO).collect();
    let or_branch = ComposedRelation::<G>::or([dleq1, dleq2]);
    let or_witness = ComposedWitness::or([
        ComposedWitness::Simple(dummy_wit1),
        ComposedWitness::Simple(wit_dleq2),
    ]);

    // Simple Pedersen commitment branch
    let (pedersen, wit_pedersen) = relations::pedersen_commitment::<G>(&mut rng);

    let nested = ComposedRelation::<G>::and([or_branch, ComposedRelation::Simple(pedersen)]);
    let nizk = nested.into_nizk(b"verifier-rejection-nested");

    let witness = ComposedWitness::and([or_witness, ComposedWitness::Simple(wit_pedersen)]);
    (witness, nizk)
}

#[test]
fn nested_batchable_empty() {
    let (_, nizk) = make_nested_nizk();
    assert!(
        nizk.verify_batchable(&[]).is_err(),
        "should reject empty nested batchable proof"
    );
}

#[test]
fn nested_compact_empty() {
    let (_, nizk) = make_nested_nizk();
    assert!(
        nizk.verify_compact(&[]).is_err(),
        "should reject empty nested compact proof"
    );
}

#[test]
fn nested_batchable_bitflip() {
    let (witness, nizk) = make_nested_nizk();
    let proof = nizk
        .prove_batchable(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
    for i in 0..proof.len() * 8 {
        assert!(
            nizk.verify_batchable(&bitflip(&proof, i)).is_err(),
            "nested batchable: bit {i} flipped"
        );
    }
}

#[test]
fn nested_compact_bitflip() {
    let (witness, nizk) = make_nested_nizk();
    let proof = nizk
        .prove_compact(&witness, &mut rand::thread_rng())
        .unwrap();
    assert!(nizk.verify_compact(&proof).is_ok());
    for i in 0..proof.len() * 8 {
        assert!(
            nizk.verify_compact(&bitflip(&proof, i)).is_err(),
            "nested compact: bit {i} flipped"
        );
    }
}
