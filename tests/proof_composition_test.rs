use std::ops::Not;

use rand::{rngs::OsRng, CryptoRng, Rng};
use lox_zkp::toolbox::sigma::{SigmaProtocol, AndProof, OrProof};
use group::Group;
use bls12_381::{G1Projective, Scalar};
use ff::Field;

pub struct LokZkpSchnorr {
    pub generator: G1Projective,
    pub target: G1Projective
}

#[allow(non_snake_case)]
impl SigmaProtocol<G1Projective> for LokZkpSchnorr {
    type Witness = Scalar;
    type Commitment = G1Projective;
    type ProverState = (Scalar, Scalar);
    type Response = Scalar;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        let r = Scalar::random(rng);
        let R = r * self.generator;
        (R, (r, *witness))
    }

    fn prover_response(
            &self,
            state: &Self::ProverState,
            challenge: &Scalar,
        ) -> Self::Response {
        let (r,x) = *state ;
        challenge * x + r
    }

    fn verifier(
            &self,
            commitment: &Self::Commitment,
            challenge: &Scalar,
            response: &Self::Response,
        ) -> bool {
        response * self.generator == challenge * self.target + commitment
    }

    fn simulate_proof(
            &self, 
            challenge: &Scalar,
            rng: &mut (impl Rng + CryptoRng)
        ) -> (Self::Commitment, Self::Response) {
        let z = Scalar::random(rng);
        let R = z * self.generator - challenge * self.target;
        (R,z)
    }
}

#[allow(non_snake_case)]
#[test]
fn andproof_schnorr_correct() {
    let mut rng = OsRng;

    // Setup: two different Schnorr instances with known witnesses
    let G1 = G1Projective::random(&mut rng);
    let G2 = G1Projective::random(&mut rng);

    let w1 = Scalar::random(&mut rng);
    let w2 = Scalar::random(&mut rng);

    let H1 = w1 * G1;
    let H2 = w2 * G2;

    let p1 = LokZkpSchnorr { generator: G1, target: H1 };
    let p2 = LokZkpSchnorr { generator: G2, target: H2 };

    let and_proof = AndProof::new(vec![p1, p2]);

    // Commitment phase
    let witnesses = vec![w1, w2];
    let (commitments, states) = and_proof.prover_commit(&witnesses, &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let responses = and_proof.prover_response(&states, &challenge);

    // Verifier checks
    let result = and_proof.verifier(&commitments, &challenge, &responses);

    assert!(result);
}

#[allow(non_snake_case)]
#[test]
fn andproof_schnorr_incorrect() {
    let mut rng = OsRng;

    // Setup: two different Schnorr instances with known witnesses
    let G1 = G1Projective::random(&mut rng);
    let G2 = G1Projective::random(&mut rng);

    let w1 = Scalar::random(&mut rng);
    let w2 = Scalar::random(&mut rng); // This witness is not actually known by the prover
    let w_fake = Scalar::random(&mut rng); // The prover tries a random witness for w2

    let H1 = w1 * G1;
    let H2 = w2 * G2;

    let p1 = LokZkpSchnorr { generator: G1, target: H1 };
    let p2 = LokZkpSchnorr { generator: G2, target: H2 };

    let and_proof = AndProof::new(vec![p1, p2]);

    // Commitment phase
    let witnesses = vec![w1, w_fake];
    let (commitments, states) = and_proof.prover_commit(&witnesses, &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let responses = and_proof.prover_response(&states, &challenge);

    // Verifier checks
    let result = and_proof.verifier(&commitments, &challenge, &responses);

    assert!(result.not());
}

#[allow(non_snake_case)]
#[test]
fn orproof_schnorr_correct() {
    let mut rng = OsRng;

    // Setup: two different Schnorr instances with known witnesses
    let G1 = G1Projective::random(&mut rng);
    let G2 = G1Projective::random(&mut rng);

    let w1 = Scalar::random(&mut rng);
    let w2 = Scalar::random(&mut rng); // This witness is actually unknown

    let H1 = w1 * G1;
    let H2 = w2 * G2; // The witness for this point is unknown

    let p1 = LokZkpSchnorr { generator: G1, target: H1 };
    let p2 = LokZkpSchnorr { generator: G2, target: H2 };

    let or_proof = OrProof::new([p1, p2]);

    // Commitment phase
    let witness = w1;
    let (commitments, states) = or_proof.prover_commit(&(0, witness), &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let responses = or_proof.prover_response(&states, &challenge);

    // Verifier checks
    let result = or_proof.verifier(&commitments, &challenge, &responses);

    assert!(result);
}

#[allow(non_snake_case)]
#[test]
fn orproof_schnorr_incorrect() {
    let mut rng = OsRng;

    // Setup: two different Schnorr instances with known witnesses
    let G1 = G1Projective::random(&mut rng);
    let G2 = G1Projective::random(&mut rng);

    let w1 = Scalar::random(&mut rng); // This witness is actually unknown
    let w2 = Scalar::random(&mut rng); // This witness is actually unknown
    let w_fake = Scalar::random(&mut rng); // The prover tries a random witness for w1

    let H1 = w1 * G1; // The witness for this point is unknown
    let H2 = w2 * G2; // The witness for this point is unknown

    let p1 = LokZkpSchnorr { generator: G1, target: H1 };
    let p2 = LokZkpSchnorr { generator: G2, target: H2 };

    let or_proof = OrProof::new([p1, p2]);

    // Commitment phase
    let witness = w_fake;
    let (commitments, states) = or_proof.prover_commit(&(0, witness), &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let responses = or_proof.prover_response(&states, &challenge);

    // Verifier checks
    let result = or_proof.verifier(&commitments, &challenge, &responses);

    assert!(result.not());
}