use rand::{Rng, CryptoRng};

/// A trait for generic sigma protocols behaviour
pub trait SigmaProtocol {
    type Commitment;
    type ProverState;
    type Response;
    type Witness;
    type Challenge;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState);

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Self::Response;

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ()>;

    fn serialize_batchable(
        &self,
        _commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        _response: &Self::Response
    ) -> Vec<u8> {
        panic!("serialize_batchable not implemented for this protocol")
    }

    fn deserialize_batchable(
        &self, _data: &[u8]
    ) -> Option<(Self::Commitment, Self::Response)> {
        panic!("deserialize_batchable not implemented for this protocol")
    }
}


pub trait SigmaProtocolSimulator
where Self: SigmaProtocol {

    fn simulate_proof(
        &self, 
        _challenge: &Self::Challenge,
        _rng: &mut (impl Rng + CryptoRng)
    ) -> (Self::Commitment, Self::Response) {
        panic!("simulatable_proof not implemented for this protocol")
    }
    
    fn simulate_transcription(
        &self, _rng: &mut (impl Rng + CryptoRng)
    ) -> (Self::Commitment, Self::Challenge, Self::Response) {
        panic!("simulatable_transcription not implemented for this protocol")
    }
}