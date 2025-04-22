use std::ops::Not;

use rand::{rngs::OsRng, CryptoRng, Rng};
use lox_zkp::toolbox::sigma::{fiat_shamir::{prove_fiat_shamir, verify_fiat_shamir}, proof_composition::OrEnum, AndProtocol, OrProtocol, SigmaProtocol};
use curve25519_dalek::{scalar::Scalar, RistrettoPoint};

/// A basic Schnorr protocol implementation for dalek
struct Schnorr {
    pub generator: RistrettoPoint,
    pub target: RistrettoPoint,
}

#[allow(non_snake_case)]
impl SigmaProtocol for Schnorr {
    type Witness = Scalar;
    type Commitment = RistrettoPoint;
    type ProverState = (Scalar, Scalar); // (r, witness)
    type Response = Scalar;
    type Challenge = Scalar;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        let r = Scalar::random(rng);
        let R = self.generator * r;
        (R, (r, *witness))
    }

    fn prover_response(
        &self,
        state: &Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Self::Response {
        let (r, w) = *state;
        r + challenge * w
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> bool {
        let lhs = self.generator * *response;
        let rhs = commitment + self.target * *challenge;
        lhs == rhs
    }

    fn simulate_proof(
        &self,
        challenge: &Self::Challenge,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> (Self::Commitment, Self::Response) {
        let z = Scalar::random(rng);
        let R = self.generator * z - self.target * *challenge;
        (R, z)
    }

    fn simulate_transcription(
        &self, rng: &mut (impl Rng + CryptoRng)
    ) -> (Self::Commitment, Self::Challenge, Self::Response) {
        let challenge = Scalar::random(rng);
        let (commitment, response) = self.simulate_proof(&challenge, rng);
        (commitment, challenge, response)
    }
}

#[test]
#[allow(non_snake_case)]
fn fiat_shamir_schnorr() {
    let mut rng = OsRng;

    // Generate generator and witness
    let generator = RistrettoPoint::random(&mut rng);
    let witness = Scalar::random(&mut rng);
    let target = generator * witness;

    let protocol = Schnorr { generator, target };

    // Prove using Fiat-Shamir
    let domain_sep = b"test-fiat-shamir";
    let (commitment, _challenge, response) = prove_fiat_shamir::<_, 64>(
        &protocol,
        &witness,
        domain_sep,
        &mut rng,
        &|c: &RistrettoPoint| c.compress().as_bytes().to_vec(), // Serialize as &[u8]
    );

    // Verify using Fiat-Shamir
    let verified = verify_fiat_shamir::<_, 64>(
        &protocol,
        &commitment,
        &response,
        domain_sep,
        &|c: &RistrettoPoint| c.compress().as_bytes().to_vec(), // Serialize as &[u8]
    );

    assert!(verified);
}

#[test]
#[allow(non_snake_case)]
fn fiat_shamir_and_protocol_correct() {
    let mut rng = OsRng;

    // Generate 2 independent Schnorr protocols
    let G1 = RistrettoPoint::random(&mut rng);
    let G2 = RistrettoPoint::random(&mut rng);

    let w1 = Scalar::random(&mut rng);
    let w2 = Scalar::random(&mut rng);

    let H1 = G1 * w1;
    let H2 = G2 * w2;

    let protocol1 = Schnorr { generator: G1, target: H1};
    let protocol2 = Schnorr { generator: G2, target: H2};

    let and_protocol = AndProtocol::new(protocol1, protocol2);

    // Prove using Fiat-Shamir with 2 witnesses
    let witness = (w1, w2);
    let domain_sep = b"test-fiat-shamir-and-correct";

    let (commitment, _challenge, response) = prove_fiat_shamir::<_, 64>(
        &and_protocol,
        &witness,
        domain_sep,
        &mut rng,
        &|c: &(RistrettoPoint, RistrettoPoint)| {
            let mut bytes = c.0.compress().as_bytes().to_vec();
            bytes.extend_from_slice(c.1.compress().as_bytes());
            bytes
        },
    );

    // Verify using Fiat-Shamir
    let verified = verify_fiat_shamir::<_, 64>(
        &and_protocol,
        &commitment,
        &response,
        domain_sep,
        &|c: &(RistrettoPoint, RistrettoPoint)| {
            let mut bytes = c.0.compress().as_bytes().to_vec();
            bytes.extend_from_slice(c.1.compress().as_bytes());
            bytes
        },
    );

    assert!(verified);
}

#[test]
#[allow(non_snake_case)]
fn fiat_shamir_and_protocol_incorrect() {
    let mut rng = OsRng;

    // Generate 2 independent Schnorr protocols
    let G1 = RistrettoPoint::random(&mut rng);
    let G2 = RistrettoPoint::random(&mut rng);

    let w1 = Scalar::random(&mut rng);
    let w2 = Scalar::random(&mut rng); // Witness actually now known by the Prover
    let w_fake = Scalar::random(&mut rng); // The Prover tries a random witness instead

    let H1 = G1 * w1;
    let H2 = G2 * w2;

    let protocol1 = Schnorr { generator: G1, target: H1};
    let protocol2 = Schnorr { generator: G2, target: H2};

    let and_protocol = AndProtocol::new(protocol1, protocol2);

    // Prove using Fiat-Shamir with 1 true witness and 1 fake witness
    let witness = (w1, w_fake);
    let domain_sep = b"test-fiat-shamir-and-incorrect";

    let (commitment, _challenge, response) = prove_fiat_shamir::<_, 64>(
        &and_protocol,
        &witness,
        domain_sep,
        &mut rng,
        &|c: &(RistrettoPoint, RistrettoPoint)| {
            let mut bytes = c.0.compress().as_bytes().to_vec();
            bytes.extend_from_slice(c.1.compress().as_bytes());
            bytes
        },
    );

    // Verify using Fiat-Shamir
    let verified = verify_fiat_shamir::<_, 64>(
        &and_protocol,
        &commitment,
        &response,
        domain_sep,
        &|c: &(RistrettoPoint, RistrettoPoint)| {
            let mut bytes = c.0.compress().as_bytes().to_vec();
            bytes.extend_from_slice(c.1.compress().as_bytes());
            bytes
        },
    );

    assert!(verified.not());
}

#[test]
#[allow(non_snake_case)]
fn fiat_shamir_or_protocol_correct() {
    let mut rng = OsRng;

    // Generate 2 independent Schnorr protocols
    let G1 = RistrettoPoint::random(&mut rng);
    let G2 = RistrettoPoint::random(&mut rng);

    let w1 = Scalar::random(&mut rng);

    let H1 = G1 * w1;
    let H2 = RistrettoPoint::random(&mut rng); // The witness for this point in unknown

    let protocol1 = Schnorr { generator: G1, target: H1};
    let protocol2 = Schnorr { generator: G2, target: H2};

    let or_protocol = OrProtocol::new(protocol1, protocol2);

    // Prove using Fiat-Shamir with a single correct witness
    let witness: (usize, OrEnum<Scalar, Scalar>) = (0, OrEnum::Left(w1));
    let domain_sep = b"test-fiat-shamir-or-correct";

    let (commitment, _challenge, response) = prove_fiat_shamir::<_, 64>(
        &or_protocol,
        &witness,
        domain_sep,
        &mut rng,
        &|c: &(RistrettoPoint, RistrettoPoint)| {
            let mut bytes = c.0.compress().as_bytes().to_vec();
            bytes.extend_from_slice(c.1.compress().as_bytes());
            bytes
        }
        ,
    );

    // Verify using Fiat-Shamir
    let verified = verify_fiat_shamir::<_, 64>(
        &or_protocol,
        &commitment,
        &response,
        domain_sep,
        &|c: &(RistrettoPoint, RistrettoPoint)| {
            let mut bytes = c.0.compress().as_bytes().to_vec();
            bytes.extend_from_slice(c.1.compress().as_bytes());
            bytes
        }
        ,
    );

    assert!(verified);
}

#[test]
#[allow(non_snake_case)]
fn fiat_shamir_or_protocol_incorrect() {
    let mut rng = OsRng;

    // Generate 2 independent Schnorr protocols
    let G1 = RistrettoPoint::random(&mut rng);
    let G2 = RistrettoPoint::random(&mut rng);

    let w_fake = Scalar::random(&mut rng); // Prover tries a random witness

    let H1 = RistrettoPoint::random(&mut rng); // The witness for this point in unknown
    let H2 = RistrettoPoint::random(&mut rng); // The witness for this point in unknown

    let protocol1 = Schnorr { generator: G1, target: H1};
    let protocol2 = Schnorr { generator: G2, target: H2};

    let or_protocol = OrProtocol::new(protocol1, protocol2);

    // Prove using Fiat-Shamir with no correct witness
    let witness: (usize, OrEnum<Scalar, Scalar>) = (0, OrEnum::Left(w_fake));
    let domain_sep = b"test-fiat-shamir-or-incorrect";

    let (commitment, _challenge, response) = prove_fiat_shamir::<_, 64>(
        &or_protocol,
        &witness,
        domain_sep,
        &mut rng,
        &|c: &(RistrettoPoint, RistrettoPoint)| {
            let mut bytes = c.0.compress().as_bytes().to_vec();
            bytes.extend_from_slice(c.1.compress().as_bytes());
            bytes
        }
        ,
    );

    // Verify using Fiat-Shamir
    let verified = verify_fiat_shamir::<_, 64>(
        &or_protocol,
        &commitment,
        &response,
        domain_sep,
        &|c: &(RistrettoPoint, RistrettoPoint)| {
            let mut bytes = c.0.compress().as_bytes().to_vec();
            bytes.extend_from_slice(c.1.compress().as_bytes());
            bytes
        }
        ,
    );

    assert!(verified.not());
}