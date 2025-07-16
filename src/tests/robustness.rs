use bls12_381::{G1Projective as G, Scalar};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use group::ff::Field;
use group::{Group, GroupEncoding};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};

use crate::fiat_shamir::NISigmaProtocol;
use crate::tests::test_utils::{discrete_logarithm, pedersen_commitment};
use crate::{codec::ShakeCodec, schnorr_protocol::SchnorrProof};

/// Asserts that flipping any bit of a valid (compact/batchable) proof causes verification to fail.
fn assert_proof_resists_bitflips<G, R>(
    rng: &mut R,
    tag: &'static [u8],
    protocol: SchnorrProof<G>,
    witness: Vec<<G as Group>::Scalar>,
) where
    G: Group + GroupEncoding + Clone,
    R: RngCore + CryptoRng,
{
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(tag, protocol);

    let compact = nizk.prove_compact(&witness, rng).unwrap();
    let batchable = nizk.prove_batchable(&witness, rng).unwrap();

    // Sanity checks: both must verify correctly
    assert!(
        nizk.verify_compact(&compact).is_ok(),
        "compact proof sanity check failed"
    );
    assert!(
        nizk.verify_batchable(&batchable).is_ok(),
        "batchable proof sanity check failed"
    );

    // Bit-flip tampering for compact proof
    for i in 0..compact.len() {
        for bit in 0..8 {
            let mut tampered = compact.clone();
            tampered[i] ^= 1 << bit;
            assert!(
                nizk.verify_compact(&tampered).is_err(),
                "compact proof bit-flip at byte {i}, bit {bit} was incorrectly accepted"
            );
        }
    }

    // Bit-flip tampering for batchable proof
    for i in 0..batchable.len() {
        for bit in 0..8 {
            let mut tampered = batchable.clone();
            tampered[i] ^= 1 << bit;
            assert!(
                nizk.verify_batchable(&tampered).is_err(),
                "batchable proof bit-flip at byte {i}, bit {bit} was incorrectly accepted"
            );
        }
    }
}

/// Asserts that inserting extra bytes into a (compact/batchable) proof causes verification to fail.
fn assert_proof_resists_extra_bytes<G, R>(
    rng: &mut R,
    tag: &'static [u8],
    protocol: SchnorrProof<G>,
    witness: Vec<<G as Group>::Scalar>,
) where
    G: Group + GroupEncoding + Clone,
    R: RngCore + CryptoRng,
{
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(tag, protocol);

    let compact = nizk.prove_compact(&witness, rng).unwrap();
    let batchable = nizk.prove_batchable(&witness, rng).unwrap();

    // Sanity checks: both must verify correctly
    assert!(
        nizk.verify_compact(&compact).is_ok(),
        "compact proof sanity check failed"
    );
    assert!(
        nizk.verify_batchable(&batchable).is_ok(),
        "batchable proof sanity check failed"
    );

    let insertion_points = [0, compact.len() / 2, compact.len()];
    let injected_bytes = [0x00, 0xFF, 0x42];

    // Byte tampering for compact proof
    for &pos in &insertion_points {
        for &byte in &injected_bytes {
            let mut tampered = compact.clone();
            tampered.insert(pos, byte);
            assert!(
                nizk.verify_compact(&tampered).is_err(),
                "compact proof with extra byte 0x{byte:02x} at position {pos} was incorrectly accepted"
            );
        }
    }

    // Byte tampering for batchable proof
    for &pos in &insertion_points {
        for &byte in &injected_bytes {
            let mut tampered = batchable.clone();
            tampered.insert(pos, byte);
            assert!(
                nizk.verify_batchable(&tampered).is_err(),
                "batchable proof with extra byte 0x{byte:02x} at position {pos} was incorrectly accepted"
            );
        }
    }
}

/// Tries to prove with a bogus witness and asserts that (compact/batchable) proof generation fails.
fn assert_invalid_witness_fails<G, R, Setup>(rng: &mut R, tag: &'static [u8], setup: Setup)
where
    G: Group + GroupEncoding + Clone,
    R: RngCore + CryptoRng,
    Setup: FnOnce(&mut R) -> (SchnorrProof<G>, Vec<<G as Group>::Scalar>),
{
    // Build a valid protocol instance and its correct witness
    let (protocol, correct_witness) = setup(rng);
    let nizk = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>>::new(tag, protocol);

    // Forge a bogus witness of the same length (retry until different)
    let mut fake_witness: Vec<<G as Group>::Scalar> = (0..correct_witness.len())
        .map(|_| <G as Group>::Scalar::random(&mut *rng))
        .collect();
    while fake_witness == correct_witness {
        // extremely unlikely, but be safe
        for x in &mut fake_witness {
            *x = <G as Group>::Scalar::random(&mut *rng);
        }
    }

    // Proof generation **must** fail with the bogus witness
    let err_batch = nizk.prove_batchable(&fake_witness, rng);
    assert!(
        err_batch.is_err(),
        "batchable proof SHOULD fail with invalid witness but succeeded"
    );

    let err_compact = nizk.prove_compact(&fake_witness, rng);
    assert!(
        err_compact.is_err(),
        "compact proof SHOULD fail with invalid witness but succeeded"
    );
}

/// Flips every bit of the proof one-by-one and asserts verification fails each time.
/// This test is done for combinations of:
/// - BLS/Ristretto
/// - dlog/pedersen commitments
#[test]
fn proof_dlog_bitflips_bls() {
    let mut rng = OsRng;

    let (morph, witness) = discrete_logarithm::<G>(Scalar::random(&mut rng));
    let protocol = SchnorrProof::from(morph);

    assert_proof_resists_bitflips::<G, _>(&mut rng, b"dlog-bitflips-bls", protocol, witness);
}

#[test]
fn proof_dlog_bitflips_ristretto() {
    let mut rng = OsRng;

    let (morph, witness) = discrete_logarithm::<RistrettoPoint>(DalekScalar::random(&mut rng));
    let protocol = SchnorrProof::from(morph);

    assert_proof_resists_bitflips::<RistrettoPoint, _>(
        &mut rng,
        b"dlog-bitflips-ristretto",
        protocol,
        witness,
    );
}

#[test]
fn proof_pedersen_bitflips_bls() {
    let mut rng = OsRng;

    let (morph, witness) = pedersen_commitment(
        G::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
    let protocol = SchnorrProof::from(morph);

    assert_proof_resists_bitflips::<G, _>(
        &mut rng,
        b"pedersen-bitflips-ristretto",
        protocol,
        witness,
    );
}

#[test]
fn proof_pedersen_bitflips_ristretto() {
    let mut rng = OsRng;

    let (morph, witness) = pedersen_commitment(
        RistrettoPoint::random(&mut rng),
        DalekScalar::random(&mut rng),
        DalekScalar::random(&mut rng),
    );
    let protocol = SchnorrProof::from(morph);

    assert_proof_resists_bitflips::<RistrettoPoint, _>(
        &mut rng,
        b"pedersen-bitflips-bls",
        protocol,
        witness,
    );
}

/// Inserts extra bytes before, after, and in the middle of the proof, and asserts verification fails.
/// This test is done for combinations of:
/// - BLS/Ristretto
/// - dlog/pedersen commitments
#[test]
fn proof_dlog_extra_bytes_bls() {
    let mut rng = OsRng;

    let (morph, witness) = discrete_logarithm::<G>(Scalar::random(&mut rng));
    let protocol = SchnorrProof::from(morph);

    assert_proof_resists_extra_bytes::<G, _>(&mut rng, b"dlog-extra-bytes-bls", protocol, witness);
}

#[test]
fn proof_dlog_extra_bytes_ristretto() {
    let mut rng = OsRng;

    let (morph, witness) = discrete_logarithm::<RistrettoPoint>(DalekScalar::random(&mut rng));
    let protocol = SchnorrProof::from(morph);

    assert_proof_resists_extra_bytes::<RistrettoPoint, _>(
        &mut rng,
        b"dlog-extra-bytes-ristretto",
        protocol,
        witness,
    );
}

#[test]
fn proof_pedersen_extra_bytes_bls() {
    let mut rng = OsRng;

    let (morph, witness) = pedersen_commitment(
        G::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
    let protocol = SchnorrProof::from(morph);

    assert_proof_resists_extra_bytes::<G, _>(
        &mut rng,
        b"pedersen-extra-bytes-bls",
        protocol,
        witness,
    );
}

#[test]
fn proof_pedersen_extra_bytes_ristretto() {
    let mut rng = OsRng;

    let (morph, witness) = pedersen_commitment(
        RistrettoPoint::random(&mut rng),
        DalekScalar::random(&mut rng),
        DalekScalar::random(&mut rng),
    );
    let protocol = SchnorrProof::from(morph);

    assert_proof_resists_extra_bytes::<RistrettoPoint, _>(
        &mut rng,
        b"pedersen-extra-bytes-ristretto",
        protocol,
        witness,
    );
}

/// Tamper with the witness provided to the proof generator of a given instance.
/// This test is done for combinations of:
/// - BLS/Ristretto
/// - dlog/pedersen commitments
#[test]
fn dlog_invalid_witness_bls() {
    let mut rng = OsRng;
    assert_invalid_witness_fails::<G, _, _>(&mut rng, b"dlog-invalid-bls", |rng: &mut _| {
        let secret = Scalar::random(rng);
        let (morph, witness) = discrete_logarithm::<G>(secret);
        (SchnorrProof::from(morph), witness)
    });
}

#[test]
fn dlog_invalid_witness_ristretto() {
    let mut rng = OsRng;
    assert_invalid_witness_fails::<RistrettoPoint, _, _>(
        &mut rng,
        b"dlog-invalid-ristretto",
        |rng: &mut _| {
            let secret = DalekScalar::random(rng);
            let (morph, witness) = discrete_logarithm::<RistrettoPoint>(secret);
            (SchnorrProof::from(morph), witness)
        },
    );
}

#[test]
fn pedersen_invalid_witness_bls() {
    let mut rng = OsRng;
    assert_invalid_witness_fails::<G, _, _>(&mut rng, b"pedersen-invalid-bls", |rng: &mut _| {
        let (morph, witness) = pedersen_commitment(
            G::random(&mut *rng),
            Scalar::random(&mut *rng),
            Scalar::random(&mut *rng),
        );
        (SchnorrProof::from(morph), witness)
    });
}

#[test]
fn pedersen_invalid_witness_ristretto() {
    let mut rng = OsRng;
    assert_invalid_witness_fails::<RistrettoPoint, _, _>(
        &mut rng,
        b"pedersen-invalid-ristretto",
        |rng: &mut _| {
            let (morph, witness) = pedersen_commitment(
                RistrettoPoint::random(rng),
                DalekScalar::random(rng),
                DalekScalar::random(rng),
            );
            (SchnorrProof::from(morph), witness)
        },
    );
}
