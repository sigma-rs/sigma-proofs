use bls12_381::{G1Projective as G, Scalar};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use group::ff::Field;
use group::{Group, GroupEncoding};
use rand::rngs::OsRng;

use crate::fiat_shamir::NISigmaProtocol;
use crate::tests::test_utils::{discrete_logarithm, pedersen_commitment};
use crate::{codec::ShakeCodec, schnorr_protocol::SchnorrProof};

/// This test checks that flipping a single low-order bit in the proof causes verification to fail.
#[test]
fn tampered_bitflip_proof() {
    let mut rng = OsRng;

    let (morphismp, witness) = discrete_logarithm(Scalar::random(&mut rng));
    let protocol = SchnorrProof::from(morphismp);
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(
        b"tamper-test-bitflip-LSB",
        protocol,
    );

    let proof_compact = nizk.prove_compact(&witness, &mut rng).unwrap();
    let proof_batchable = nizk.prove_batchable(&witness, &mut rng).unwrap();

    // Flip the least significant bit of the first byte
    let mut tampered_compact = proof_compact.clone();
    let mut tampered_batchable = proof_batchable.clone();
    tampered_compact[0] ^= 0b00000001;
    tampered_batchable[0] ^= 0b00000001;

    // Valid proofs should verify
    assert!(nizk.verify_compact(&proof_compact).is_ok());
    assert!(nizk.verify_batchable(&proof_batchable).is_ok());

    // Tampered proofs should be rejected
    assert!(
        nizk.verify_compact(&tampered_compact).is_err(),
        "Compact proof with bitflip was incorrectly accepted"
    );
    assert!(
        nizk.verify_batchable(&tampered_batchable).is_err(),
        "Batchable proof with bitflip was incorrectly accepted"
    );
}

/// This test checks that appending an extra byte invalidates the proof.
#[test]
fn tampered_extra_byte_proof() {
    let mut rng = OsRng;

    let (morphismp, witness) = discrete_logarithm(Scalar::random(&mut rng));
    let protocol = SchnorrProof::from(morphismp);
    let nizk =
        NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(b"tamper-test-extra-byte", protocol);

    let proof_compact = nizk.prove_compact(&witness, &mut rng).unwrap();
    let proof_batchable = nizk.prove_batchable(&witness, &mut rng).unwrap();

    // Append a null byte at the end of the proof
    let mut tampered_compact = proof_compact.clone();
    let mut tampered_batchable = proof_batchable.clone();
    tampered_compact.push(0x00);
    tampered_batchable.push(0x00);

    // Valid proofs should verify
    assert!(nizk.verify_compact(&proof_compact).is_ok());
    assert!(nizk.verify_batchable(&proof_batchable).is_ok());

    // Tampered proofs should be rejected due to unexpected length
    assert!(
        nizk.verify_compact(&tampered_compact).is_err(),
        "Compact proof with extra byte was incorrectly accepted"
    );
    assert!(
        nizk.verify_batchable(&tampered_batchable).is_err(),
        "Batchable proof with extra byte was incorrectly accepted"
    );
}

/// This test checks that flipping the high bit in a group encoding breaks the proof (Bls12_381 backend).
#[test]
fn tampered_flip_high_bit_in_group_element() {
    let mut rng = OsRng;

    let (morphismp, witness) = discrete_logarithm(Scalar::random(&mut rng));
    let protocol = SchnorrProof::from(morphismp);
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(
        b"tamper-test-curve-encoding",
        protocol,
    );

    let proof_compact = nizk.prove_compact(&witness, &mut rng).unwrap();
    let proof_batchable = nizk.prove_batchable(&witness, &mut rng).unwrap();

    let mut tampered_compact = proof_compact.clone();
    let mut tampered_batchable = proof_batchable.clone();

    // Determine size of a compressed group element (48 bytes for BLS12-381 G1)
    let point_size = <G as GroupEncoding>::Repr::default().as_ref().len();

    // Flip the most significant bit of the last byte in the first group element
    tampered_batchable[point_size - 1] ^= 0b10000000;

    // Flip the MSB of the first byte in the scalar challenge
    tampered_compact[0] ^= 0b10000000;

    // Valid proofs should verify
    assert!(nizk.verify_compact(&proof_compact).is_ok());
    assert!(nizk.verify_batchable(&proof_batchable).is_ok());

    // Tampered proofs should fail due to invalid group or scalar encoding
    assert!(
        nizk.verify_compact(&tampered_compact).is_err(),
        "Compact proof with MSB flipped was incorrectly accepted"
    );
    assert!(
        nizk.verify_batchable(&tampered_batchable).is_err(),
        "Batchable proof with MSB flipped was incorrectly accepted"
    );
}

/// This test checks that flipping the high bit in a group encoding breaks the proof (Ristretto backend).
#[test]
fn tampered_flip_high_bit_in_group_element_ristretto() {
    let mut rng = OsRng;

    let (morphismp, witness) = discrete_logarithm(DalekScalar::random(&mut rng));
    let protocol = SchnorrProof::from(morphismp);
    let nizk = NISigmaProtocol::<SchnorrProof<RistrettoPoint>, ShakeCodec<RistrettoPoint>>::new(
        b"tamper-ristretto-msb",
        protocol,
    );

    let proof_compact = nizk.prove_compact(&witness, &mut rng).unwrap();
    let proof_batchable = nizk.prove_batchable(&witness, &mut rng).unwrap();

    // Clone for tampering
    let mut tampered_compact = proof_compact.clone();
    let mut tampered_batchable = proof_batchable.clone();

    // Ristretto group encoding size is 32 bytes
    let point_size = <RistrettoPoint as GroupEncoding>::Repr::default()
        .as_ref()
        .len();

    // Tamper: Flip MSB of last byte in first group element
    tampered_batchable[point_size - 1] ^= 0b10000000;

    // Tamper: Flip MSB of first byte of scalar
    tampered_compact[0] ^= 0b10000000;

    // Check original proofs still pass
    assert!(nizk.verify_compact(&proof_compact).is_ok());
    assert!(nizk.verify_batchable(&proof_batchable).is_ok());

    // Check tampered proofs fail due to invalid encoding
    assert!(
        nizk.verify_compact(&tampered_compact).is_err(),
        "Compact Ristretto proof with MSB flipped was incorrectly accepted"
    );
    assert!(
        nizk.verify_batchable(&tampered_batchable).is_err(),
        "Batchable Ristretto proof with MSB flipped was incorrectly accepted"
    );
}

#[test]
fn tampered_bitflip_pedersen_proof() {
    let mut rng = OsRng;

    let (morphismp, witness) = pedersen_commitment(
        G::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
    let protocol = SchnorrProof::from(morphismp);
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(
        b"tamper-pedersen-bitflip",
        protocol,
    );

    let proof_compact = nizk.prove_compact(&witness, &mut rng).unwrap();
    let proof_batchable = nizk.prove_batchable(&witness, &mut rng).unwrap();

    // Tampering: Flip 1 LSB in the first byte
    let mut tampered_compact = proof_compact.clone();
    let mut tampered_batchable = proof_batchable.clone();
    tampered_compact[0] ^= 0b00000001;
    tampered_batchable[0] ^= 0b00000001;

    assert!(nizk.verify_compact(&proof_compact).is_ok());
    assert!(nizk.verify_batchable(&proof_batchable).is_ok());

    assert!(
        nizk.verify_compact(&tampered_compact).is_err(),
        "Bit-flipped compact Pedersen proof was incorrectly accepted"
    );
    assert!(
        nizk.verify_batchable(&tampered_batchable).is_err(),
        "Bit-flipped batchable Pedersen proof was incorrectly accepted"
    );
}

#[test]
fn tampered_extra_byte_pedersen_proof() {
    let mut rng = OsRng;

    let (morphismp, witness) = pedersen_commitment(
        G::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
    let protocol = SchnorrProof::from(morphismp);
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(
        b"tamper-pedersen-extra-byte",
        protocol,
    );

    let proof_compact = nizk.prove_compact(&witness, &mut rng).unwrap();
    let proof_batchable = nizk.prove_batchable(&witness, &mut rng).unwrap();

    // Tampering: Add a trailing null byte
    let mut tampered_compact = proof_compact.clone();
    let mut tampered_batchable = proof_batchable.clone();
    tampered_compact.push(0x00);
    tampered_batchable.push(0x00);

    assert!(nizk.verify_compact(&proof_compact).is_ok());
    assert!(nizk.verify_batchable(&proof_batchable).is_ok());

    assert!(
        nizk.verify_compact(&tampered_compact).is_err(),
        "Compact Pedersen proof with extra byte was incorrectly accepted"
    );
    assert!(
        nizk.verify_batchable(&tampered_batchable).is_err(),
        "Batchable Pedersen proof with extra byte was incorrectly accepted"
    );
}

#[test]
fn tampered_flip_high_bit_in_pedersen_group_element() {
    let mut rng = OsRng;

    let (morphismp, witness) = pedersen_commitment(
        G::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
    let protocol = SchnorrProof::from(morphismp);
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(
        b"tamper-pedersen-msb-flip",
        protocol,
    );

    let proof_compact = nizk.prove_compact(&witness, &mut rng).unwrap();
    let proof_batchable = nizk.prove_batchable(&witness, &mut rng).unwrap();

    // Tampering: Flip MSB of one group element and one scalar
    let mut tampered_compact = proof_compact.clone();
    let mut tampered_batchable = proof_batchable.clone();

    let point_size = <G as GroupEncoding>::Repr::default().as_ref().len();
    tampered_batchable[point_size - 1] ^= 0b10000000;
    tampered_compact[0] ^= 0b10000000;

    assert!(nizk.verify_compact(&proof_compact).is_ok());
    assert!(nizk.verify_batchable(&proof_batchable).is_ok());

    assert!(
        nizk.verify_compact(&tampered_compact).is_err(),
        "Compact Pedersen proof with MSB flipped was incorrectly accepted"
    );
    assert!(
        nizk.verify_batchable(&tampered_batchable).is_err(),
        "Batchable Pedersen proof with MSB flipped was incorrectly accepted"
    );
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
