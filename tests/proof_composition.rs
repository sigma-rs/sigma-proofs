use curve25519_dalek::ristretto::RistrettoPoint;
use ff::Field;
use group::{Group, GroupEncoding};
use rand::{rngs::OsRng, CryptoRng, Rng};

use sigma_rs::codec::ShakeCodec;
use sigma_rs::fiat_shamir::NISigmaProtocol;
use sigma_rs::group_morphism::GroupMorphismPreimage;
use sigma_rs::proof_composition::{AndProtocol, OrProtocol};
use sigma_rs::schnorr_protocol::SchnorrProtocol;

type G = RistrettoPoint;

#[allow(non_snake_case)]
fn DL_protocol<G: Group + GroupEncoding>(
    rng: &mut (impl Rng + CryptoRng),
) -> (SchnorrProtocol<G>, Vec<G::Scalar>) {
    let G = G::generator();

    let mut preimage: GroupMorphismPreimage<G> = GroupMorphismPreimage::new();

    let x = <G as Group>::Scalar::random(rng);

    let var_x = preimage.allocate_scalar();
    let [var_G, var_xG] = preimage.allocate_elements();

    preimage.constrain(var_xG, [(var_x, var_G)]);
    preimage.assign_element(var_G, G);
    preimage.assign_element(var_xG, G * x);

    assert!(vec![G * x] == preimage.morphism.evaluate(&[x]).unwrap());
    (SchnorrProtocol::from(preimage), vec![x])
}

#[allow(non_snake_case)]
fn pedersen_protocol<G: Group + GroupEncoding>(
    rng: &mut (impl Rng + CryptoRng),
) -> (SchnorrProtocol<G>, Vec<G::Scalar>) {
    let mut preimage: GroupMorphismPreimage<G> = GroupMorphismPreimage::new();

    let G = G::generator();
    let H = G::random(&mut *rng);
    let x = G::Scalar::random(&mut *rng);
    let r = G::Scalar::random(&mut *rng);
    let witness = vec![x, r];

    let C = G * x + H * r;

    let scalars = preimage.allocate_scalars::<2>();
    let points = preimage.allocate_elements::<3>();

    preimage.assign_elements([(points[1], H), (points[0], G), (points[2], C)]);
    preimage.constrain(
        points[2],
        [(scalars[0], points[0]), (scalars[1], points[1])],
    );

    assert!(vec![C] == preimage.morphism.evaluate(&witness).unwrap());
    (SchnorrProtocol::from(preimage), witness)
}

#[allow(non_snake_case)]
#[test]
fn and_proof_correct() {
    let mut rng = OsRng;
    let domain_sep = b"hello world";

    let (p1, x1) = DL_protocol::<G>(&mut rng);
    let (p2, x2) = pedersen_protocol::<G>(&mut rng);

    let mut and_protocol = AndProtocol::<G>::new();
    and_protocol.append_protocol(p1);
    and_protocol.append_protocol(p2);

    let mut witness = Vec::new();
    witness.extend(&x1);
    witness.extend(&x2);

    let mut nizk = NISigmaProtocol::<AndProtocol<RistrettoPoint>, ShakeCodec<G>, G>::new(
        domain_sep,
        and_protocol,
    );

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();
    assert!(
        verified_batchable & verified_compact,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}

#[allow(non_snake_case)]
#[test]
fn and_proof_incorrect() {
    let mut rng = OsRng;
    let domain_sep = b"hello world";

    let (p1, _) = DL_protocol::<G>(&mut rng);
    let (p2, x2) = pedersen_protocol::<G>(&mut rng);

    let mut and_protocol = AndProtocol::<G>::new();
    and_protocol.append_protocol(p1);
    and_protocol.append_protocol(p2);

    let mut witness = Vec::new();
    let fake_x = <RistrettoPoint as Group>::Scalar::random(&mut rng);
    witness.push(fake_x);
    witness.extend(x2);

    let mut nizk = NISigmaProtocol::<AndProtocol<RistrettoPoint>, ShakeCodec<G>, G>::new(
        domain_sep,
        and_protocol,
    );

    // Prove (and local verification)
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).is_err();
    assert!(
        proof_batchable_bytes,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}

#[allow(non_snake_case)]
#[test]
fn or_proof_correct() {
    let mut rng = OsRng;
    let domain_sep = b"hello world";

    let (p0, _) = DL_protocol::<G>(&mut rng);
    let (p1, x1) = DL_protocol::<G>(&mut rng);
    let (p2, _) = pedersen_protocol::<G>(&mut rng);
    let (p3, _) = pedersen_protocol::<G>(&mut rng);

    let mut or_protocol = OrProtocol::<G>::new();
    or_protocol.append_protocol(p0);
    or_protocol.append_protocol(p1);
    or_protocol.append_protocol(p2);
    or_protocol.append_protocol(p3);

    let witness = (1, x1);

    let mut nizk = NISigmaProtocol::<OrProtocol<RistrettoPoint>, ShakeCodec<G>, G>::new(
        domain_sep,
        or_protocol,
    );

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    let proof_compact_bytes = nizk.prove_compact(&witness, &mut rng).unwrap();
    println!("batchable : {:?}", proof_batchable_bytes);
    println!("compact : {:?}", proof_compact_bytes);
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    let verified_compact = nizk.verify_compact(&proof_compact_bytes).is_ok();
    assert!(
        verified_batchable & verified_compact,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}

#[allow(non_snake_case)]
#[test]
fn or_proof_incorrect() {
    let mut rng = OsRng;
    let domain_sep = b"hello world";

    let (p1, _) = DL_protocol::<G>(&mut rng);
    let (p2, _) = pedersen_protocol::<G>(&mut rng);

    let mut or_protocol = OrProtocol::<G>::new();
    or_protocol.append_protocol(p1);
    or_protocol.append_protocol(p2);

    let witness = (0, vec![<G as Group>::Scalar::random(&mut rng)]);

    let mut nizk = NISigmaProtocol::<OrProtocol<RistrettoPoint>, ShakeCodec<G>, G>::new(
        domain_sep,
        or_protocol,
    );

    // Local verification
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).is_err();
    assert!(
        proof_batchable_bytes,
        "Fiat-Shamir Schnorr proof verification failed"
    );
}
