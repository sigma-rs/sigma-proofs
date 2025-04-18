use group::Group;
use rand::{Rng, CryptoRng};

pub trait SigmaProtocol<G: Group> {
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
        challenge: &G::Scalar,
    ) -> Self::Response;

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &G::Scalar,
        response: &Self::Response,
    ) -> bool;

    fn simulate_proof(
        &self, 
        _challenge: &G::Scalar,
        _rng: &mut (impl Rng + CryptoRng)
    ) -> (Self::Commitment, Self::Response) {
        panic!("simulatable_proof not implemented for this protocol")
    }
}