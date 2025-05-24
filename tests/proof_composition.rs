use curve25519_dalek::ristretto::RistrettoPoint;
use ff::Field;
use group::{Group, GroupEncoding};
use rand::{rngs::OsRng, CryptoRng, Rng};

use sigma_rs::{
    codec::ShakeCodec, AndProtocol, GroupMorphismPreimage, NISigmaProtocol, OrProtocol,
    SchnorrProtocol,
};

type G = RistrettoPoint;

#[allow(non_snake_case)]
fn DL_protocol<G: Group + GroupEncoding>(
    rng: &mut (impl Rng + CryptoRng),
) -> (SchnorrProtocol<G>, Vec<G::Scalar>) {
    let G = G::generator();

    let mut preimage: GroupMorphismPreimage<G> = GroupMorphismPreimage::new();

    let x = <G as Group>::Scalar::random(rng);

    let scalars = preimage.allocate_scalars(1);
    let points = preimage.allocate_elements(2);

    preimage.append_equation(points[1], &[(scalars[0], points[0])]);
    preimage.set_elements(&[(points[0], G)]);
    preimage.set_elements(&[(points[1], G * x)]);

    assert!(vec![G * x] == preimage.morphism.evaluate(&[x]));
    (SchnorrProtocol::from_preimage(preimage), vec![x])
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

    let scalars = preimage.allocate_scalars(2);
    let points = preimage.allocate_elements(3);

    preimage.set_elements(&[(points[1], H), (points[0], G), (points[2], C)]);
    preimage.append_equation(
        points[2],
        &[(scalars[0], points[0]), (scalars[1], points[1])],
    );

    assert!(vec![C] == preimage.morphism.evaluate(&witness));
    (SchnorrProtocol::from_preimage(preimage), witness)
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
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    assert!(
        verified_batchable,
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

    let (p1, x1) = DL_protocol::<G>(&mut rng);
    let (p2, _) = pedersen_protocol::<G>(&mut rng);

    let mut or_protocol = OrProtocol::<G>::new();
    or_protocol.append_protocol(p1);
    or_protocol.append_protocol(p2);

    let witness = (0, x1);

    let mut nizk = NISigmaProtocol::<OrProtocol<RistrettoPoint>, ShakeCodec<G>, G>::new(
        domain_sep,
        or_protocol,
    );

    // Batchable and compact proofs
    let proof_batchable_bytes = nizk.prove_batchable(&witness, &mut rng).unwrap();
    // Verify proofs
    let verified_batchable = nizk.verify_batchable(&proof_batchable_bytes).is_ok();
    assert!(
        verified_batchable,
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
