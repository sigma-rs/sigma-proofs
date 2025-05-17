use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::{rngs::OsRng, CryptoRng, Rng};

use sigma_rs::{
    AndProtocol, OrEnum, OrProtocol, ProofError, SigmaProtocol, SigmaProtocolSimulator,
};

pub struct SchnorrZkp {
    pub generator: RistrettoPoint,
    pub target: RistrettoPoint,
}

#[allow(non_snake_case)]
impl SigmaProtocol for SchnorrZkp {
    type Witness = Scalar;
    type Commitment = RistrettoPoint;
    type ProverState = (Scalar, Scalar);
    type Response = Scalar;
    type Challenge = Scalar;

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
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Self::Response {
        let (r, x) = state;
        challenge * x + r
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ProofError> {
        match response * self.generator == challenge * self.target + commitment {
            true => Ok(()),
            false => Err(ProofError::VerificationFailure),
        }
    }

    fn serialize_batchable(
        &self,
        _commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        _response: &Self::Response,
    ) -> Vec<u8> {
        todo!()
    }

    fn deserialize_batchable(&self, _data: &[u8]) -> Option<(Self::Commitment, Self::Response)> {
        todo!()
    }
}

#[allow(non_snake_case)]
impl SigmaProtocolSimulator for SchnorrZkp {
    fn simulate_proof(
        &self,
        challenge: &Self::Challenge,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::Response) {
        let z = Scalar::random(rng);
        let R = z * self.generator - challenge * self.target;
        (R, z)
    }

    fn simulate_transcript(
        &self,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::Challenge, Self::Response) {
        let challenge = Scalar::random(rng);
        let (commitment, response) = self.simulate_proof(&challenge, rng);
        (commitment, challenge, response)
    }
}

//  Proof calculation and verification in an AND-protocol in the case where:
//  both protocols are SchnorrZkp and the proof is correct
#[allow(non_snake_case)]
#[test]
fn andproof_schnorr_correct() {
    let mut rng = OsRng;

    // Setup: two different Schnorr instances with known witnesses
    let G1 = RistrettoPoint::random(&mut rng);
    let G2 = RistrettoPoint::random(&mut rng);

    let w1 = Scalar::random(&mut rng);
    let w2 = Scalar::random(&mut rng);

    let H1 = w1 * G1;
    let H2 = w2 * G2;

    let p1 = SchnorrZkp {
        generator: G1,
        target: H1,
    };
    let p2 = SchnorrZkp {
        generator: G2,
        target: H2,
    };

    let and_proof = AndProtocol::new(p1, p2);

    // Commitment phase
    let witnesses = (w1, w2);
    let (commitments, states) = and_proof.prover_commit(&witnesses, &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let responses = and_proof.prover_response(states, &challenge);

    // Verifier checks
    let result = and_proof.verifier(&commitments, &challenge, &responses);

    assert!(result.is_ok());
}

//  Proof calculation and verification in an AND-protocol in the case where:
//  both protocols are SchnorrZkp and the proof is incorrect
#[allow(non_snake_case)]
#[test]
fn andproof_schnorr_incorrect() {
    let mut rng = OsRng;

    // Setup: two different Schnorr instances with known witnesses
    let G1 = RistrettoPoint::random(&mut rng);
    let G2 = RistrettoPoint::random(&mut rng);

    let w1 = Scalar::random(&mut rng);
    let w2 = Scalar::random(&mut rng); // This witness is not actually known by the prover
    let w_fake = Scalar::random(&mut rng); // The prover tries a random witness for w2

    let H1 = w1 * G1;
    let H2 = w2 * G2;

    let p1 = SchnorrZkp {
        generator: G1,
        target: H1,
    };
    let p2 = SchnorrZkp {
        generator: G2,
        target: H2,
    };

    let and_proof = AndProtocol::new(p1, p2);

    // Commitment phase
    let witnesses = (w1, w_fake);
    let (commitments, states) = and_proof.prover_commit(&witnesses, &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let responses = and_proof.prover_response(states, &challenge);

    // Verifier checks
    let result = and_proof.verifier(&commitments, &challenge, &responses);

    assert!(!result.is_ok());
}

//  Proof calculation and verification in an OR-protocol in the case where:
//  both protocols are SchnorrZkp and the proof is correct
#[allow(non_snake_case)]
#[test]
fn orproof_schnorr_correct() {
    let mut rng = OsRng;

    // Setup: two different Schnorr instances with known witnesses
    let G1 = RistrettoPoint::random(&mut rng);
    let G2 = RistrettoPoint::random(&mut rng);

    let w1 = Scalar::random(&mut rng);

    let H1 = w1 * G1;
    let H2 = RistrettoPoint::random(&mut rng); // The witness for this point is unknown

    let p1 = SchnorrZkp {
        generator: G1,
        target: H1,
    };
    let p2 = SchnorrZkp {
        generator: G2,
        target: H2,
    };

    let or_proof = OrProtocol::new(p1, p2);

    // Commitment phase
    let witness: (usize, OrEnum<Scalar, Scalar>) = (0, OrEnum::Left(w1));
    let (commitments, states) = or_proof.prover_commit(&witness, &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let responses = or_proof.prover_response(states, &challenge);

    // Verifier checks
    let result = or_proof.verifier(&commitments, &challenge, &responses);

    assert!(result.is_ok());
}

//  Proof calculation and verification in an OR-protocol in the case where:
//  both protocols are SchnorrZkp and the proof is incorrect
#[allow(non_snake_case)]
#[test]
fn orproof_schnorr_incorrect() {
    let mut rng = OsRng;

    // Setup: two different Schnorr instances with known witnesses
    let G1 = RistrettoPoint::random(&mut rng);
    let G2 = RistrettoPoint::random(&mut rng);

    let w_fake = Scalar::random(&mut rng); // The prover tries a random witness for w1

    let H1 = RistrettoPoint::random(&mut rng); // The witness for this point is unknown
    let H2 = RistrettoPoint::random(&mut rng); // The witness for this point is unknown

    let p1 = SchnorrZkp {
        generator: G1,
        target: H1,
    };
    let p2 = SchnorrZkp {
        generator: G2,
        target: H2,
    };

    let or_proof = OrProtocol::new(p1, p2);

    // Commitment phase
    let witness: (usize, OrEnum<Scalar, Scalar>) = (0, OrEnum::Left(w_fake));
    let (commitments, states) = or_proof.prover_commit(&witness, &mut rng);

    // Fiat-Shamir challenge (dummy for now)
    let challenge = Scalar::random(&mut rng);

    // Prover computes responses
    let responses = or_proof.prover_response(states, &challenge);

    // Verifier checks
    let result = or_proof.verifier(&commitments, &challenge, &responses);

    assert!(!result.is_ok());
}
