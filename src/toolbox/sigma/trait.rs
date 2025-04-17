use curve25519_dalek::{ristretto::{CompressedRistretto, RistrettoBasepointTable}, RistrettoPoint, Scalar};
use rand::{Rng, CryptoRng};

pub trait SigmaProtocol {
    type Commitment;
    type ProverState;
    type Response;
    type Witness;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState);

    fn prover_response(
        &self,
        state: &Self::ProverState,
        challenge: &Scalar,
    ) -> Self::Response;

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Scalar,
        response: &Self::Response,
    ) -> bool;

    fn simulate_proof(
        &self, 
        challenge: &Scalar,
        rng: &mut (impl Rng + CryptoRng)
    ) -> (Self::Commitment, Self::Response) {
        panic!("simulatable_proof not implemented for this protocol")
    }
}