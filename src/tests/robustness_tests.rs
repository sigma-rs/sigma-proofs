use bls12_381::{G1Projective as G, Scalar};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use group::ff::Field;
use group::Group;
use rand::rngs::OsRng;

use crate::fiat_shamir::NISigmaProtocol;
use crate::tests::test_utils::{discrete_logarithm, pedersen_commitment};
use crate::{codec::ShakeCodec, schnorr_protocol::SchnorrProof};

/// Flips every bit of the proof one-by-one and asserts verification fails each time.
#[test]
fn test_proof_dlog_bitflips_bls() {
    let mut rng = OsRng;
    let (morphismp, witness) = discrete_logarithm(Scalar::random(&mut rng));
    let protocol = SchnorrProof::from(morphismp);
    let nizk =
        NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(b"test-proof-bitflips", protocol);

    let proof = nizk.prove_compact(&witness, &mut rng).unwrap();

    // Valid proof should verify
    assert!(nizk.verify_compact(&proof).is_ok());

    for i in 0..proof.len() {
        for bit in 0..8 {
            let mut tampered = proof.clone();
            tampered[i] ^= 1 << bit;
            assert!(
                nizk.verify_compact(&tampered).is_err(),
                "Proof bitflip at byte {i}, bit {bit} was incorrectly accepted"
            );
        }
    }
}

/// Flips every bit of the proof one-by-one and asserts verification fails each time.
#[test]
fn test_proof_pedersen_bitflips_bls() {
    let mut rng = OsRng;


    let (morphismp, witness) = pedersen_commitment(G::random(&mut rng), Scalar::random(&mut rng),Scalar::random(&mut rng));
    let protocol = SchnorrProof::from(morphismp);
    let nizk =
        NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(b"test-proof-bitflips", protocol);

    let proof = nizk.prove_compact(&witness, &mut rng).unwrap();

    // Valid proof should verify
    assert!(nizk.verify_compact(&proof).is_ok());

    for i in 0..proof.len() {
        for bit in 0..8 {
            let mut tampered = proof.clone();
            tampered[i] ^= 1 << bit;
            assert!(
                nizk.verify_compact(&tampered).is_err(),
                "Proof bitflip at byte {i}, bit {bit} was incorrectly accepted"
            );
        }
    }
}

/// Flips every bit of the proof one-by-one and asserts verification fails each time.
#[test]
fn test_proof_bitflips_ristretto() {
    let mut rng = OsRng;
    let (morphismp, witness) = discrete_logarithm(DalekScalar::random(&mut rng));
    let protocol = SchnorrProof::from(morphismp);
    let nizk =
        NISigmaProtocol::<SchnorrProof<RistrettoPoint>, ShakeCodec<RistrettoPoint>>::new(b"test-proof-bitflips", protocol);

    let proof = nizk.prove_compact(&witness, &mut rng).unwrap();

    // Valid proof should verify
    assert!(nizk.verify_compact(&proof).is_ok());

    for i in 0..proof.len() {
        for bit in 0..8 {
            let mut tampered = proof.clone();
            tampered[i] ^= 1 << bit;
            assert!(
                nizk.verify_compact(&tampered).is_err(),
                "Proof bitflip at byte {i}, bit {bit} was incorrectly accepted"
            );
        }
    }
}

/// Inserts extra bytes before, after, and in the middle of the proof, and asserts verification fails.
#[test]
fn test_proof_extra_bytes_bls() {
    let mut rng = OsRng;
    let (morphismp, witness) = discrete_logarithm(Scalar::random(&mut rng));
    let protocol = SchnorrProof::from(morphismp);
    let nizk =
        NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(b"test-proof-extra-bytes", protocol);

    let proof = nizk.prove_compact(&witness, &mut rng).unwrap();

    // Valid proof should verify
    assert!(nizk.verify_compact(&proof).is_ok());

    let insertion_points = [0, proof.len() / 2, proof.len()];
    let injected_bytes = [0x00, 0xFF, 0x42];

    for &pos in &insertion_points {
        for &byte in &injected_bytes {
            let mut tampered = proof.clone();
            tampered.insert(pos, byte);
            assert!(
                nizk.verify_compact(&tampered).is_err(),
                "Proof with extra byte 0x{byte:02x} at position {pos} was incorrectly accepted"
            );
        }
    }
}

/// Inserts extra bytes before, after, and in the middle of the proof, and asserts verification fails.
#[test]
fn test_proof_extra_bytes_ristretto() {
    let mut rng = OsRng;
    let (morphismp, witness) = discrete_logarithm(DalekScalar::random(&mut rng));
    let protocol = SchnorrProof::from(morphismp);
    let nizk =
        NISigmaProtocol::<SchnorrProof<RistrettoPoint>, ShakeCodec<RistrettoPoint>>::new(b"test-proof-extra-bytes", protocol);

    let proof = nizk.prove_compact(&witness, &mut rng).unwrap();

    // Valid proof should verify
    assert!(nizk.verify_compact(&proof).is_ok());

    let insertion_points = [0, proof.len() / 2, proof.len()];
    let injected_bytes = [0x00, 0xFF, 0x42];

    for &pos in &insertion_points {
        for &byte in &injected_bytes {
            let mut tampered = proof.clone();
            tampered.insert(pos, byte);
            assert!(
                nizk.verify_compact(&tampered).is_err(),
                "Proof with extra byte 0x{byte:02x} at position {pos} was incorrectly accepted"
            );
        }
    }
}

#[test]
fn discrete_log_invalid_witness_should_fail() {
    let mut rng = OsRng;

    // Correct secret and group generator
    let real_x = Scalar::random(&mut rng);
    let (morphismp, _correct_witness) = discrete_logarithm::<G>(real_x);

    // Create protocol from the valid relation
    let protocol = SchnorrProof::from(morphismp);
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(
        b"test-dlog-invalid-witness",
        protocol,
    );

    // Malicious or incorrect prover gives wrong witness
    let fake_x = Scalar::random(&mut rng);
    assert_ne!(fake_x, real_x, "Fake witness must differ from real witness");

    // Proof generation should fail
    let proof_batchable = nizk.prove_batchable(&vec![fake_x], &mut rng);
    assert!(
        proof_batchable.is_err(),
        "Prover should not be able to generate proof from invalid witness"
    );

    let proof_compact = nizk.prove_compact(&vec![fake_x], &mut rng);
    assert!(
        proof_compact.is_err(),
        "Compact proof should not be generated from invalid witness"
    );
}
