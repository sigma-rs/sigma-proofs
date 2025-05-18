use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use ff::Field;
use group::{Group, GroupEncoding};
use rand::{rngs::OsRng, CryptoRng, Rng};

use sigma_rs::{
    AndProtocol, GroupMorphismPreimage, OrEnum, OrProtocol, SchnorrProtocol, SigmaProtocol,
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
    (SchnorrProtocol(preimage), vec![x])
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
    (SchnorrProtocol(preimage), witness)
}

#[allow(non_snake_case)]
#[test]
fn and_proof_correct() {
    let mut rng = OsRng;

    let (p1, x1) = DL_protocol::<G>(&mut rng);
    let (p2, x2) = pedersen_protocol::<G>(&mut rng);

    let and_proof = AndProtocol::new(p1, p2);

    // Commitment phase
    let witnesses = (x1, x2);
    let (commitment, states) = and_proof.prover_commit(&witnesses, &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let response = and_proof.prover_response(states, &challenge);
    // Serialization of the proof
    let proof_bytes = and_proof
        .serialize_batchable(&commitment, &challenge, &response)
        .unwrap();
    // Deserialization of the proof
    let (commitment_des, response_des) = and_proof.deserialize_batchable(&proof_bytes).unwrap();
    // Verifier checks
    let result = and_proof.verifier(&commitment_des, &challenge, &response_des);
    assert!(result.is_ok());
}

#[allow(non_snake_case)]
#[test]
fn and_proof_incorrect() {
    let mut rng = OsRng;

    let (p1, _) = DL_protocol::<G>(&mut rng);
    let (p2, x2) = pedersen_protocol::<G>(&mut rng);
    let fake_witness = Scalar::random(&mut rng);

    let and_proof = AndProtocol::new(p1, p2);

    // Commitment phase
    let witnesses = (vec![fake_witness], x2);
    let (commitment, states) = and_proof.prover_commit(&witnesses, &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let response = and_proof.prover_response(states, &challenge);
    // Serialization of the proof
    let proof_bytes = and_proof
        .serialize_batchable(&commitment, &challenge, &response)
        .unwrap();
    // Deserialization of the proof
    let (commitment_des, response_des) = and_proof.deserialize_batchable(&proof_bytes).unwrap();
    // Verifier checks
    let result = and_proof.verifier(&commitment_des, &challenge, &response_des);
    assert!(!result.is_ok());
}

#[allow(non_snake_case)]
#[test]
fn or_proof_correct() {
    let mut rng = OsRng;

    let (p1, x1) = DL_protocol::<G>(&mut rng);
    let (p2, _) = pedersen_protocol::<G>(&mut rng);

    let or_proof = OrProtocol::new(p1, p2);

    // Commitment phase
    let witnesses = (0, OrEnum::Left(x1));
    let (commitment, states) = or_proof.prover_commit(&witnesses, &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let response = or_proof.prover_response(states, &challenge);
    // Serialization of the proof
    let proof_bytes = or_proof
        .serialize_batchable(&commitment, &challenge, &response)
        .unwrap();
    // Deserialization of the proof
    let (commitment_des, response_des) = or_proof.deserialize_batchable(&proof_bytes).unwrap();
    // Verifier checks
    let result = or_proof.verifier(&commitment_des, &challenge, &response_des);
    assert!(result.is_ok());
}

#[allow(non_snake_case)]
#[test]
fn or_proof_incorrect() {
    let mut rng = OsRng;

    let (p1, _) = DL_protocol::<G>(&mut rng);
    let (p2, _) = pedersen_protocol::<G>(&mut rng);
    let fake_witness = Scalar::random(&mut rng);

    let or_proof = OrProtocol::new(p1, p2);

    // Commitment phase
    let witnesses = (0, OrEnum::Left(vec![fake_witness]));
    let (commitment, states) = or_proof.prover_commit(&witnesses, &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let response = or_proof.prover_response(states, &challenge);
    // Serialization of the proof
    let proof_bytes = or_proof
        .serialize_batchable(&commitment, &challenge, &response)
        .unwrap();
    // Deserialization of the proof
    let (commitment_des, response_des) = or_proof.deserialize_batchable(&proof_bytes).unwrap();
    // Verifier checks
    let result = or_proof.verifier(&commitment_des, &challenge, &response_des);
    assert!(!result.is_ok());
}
