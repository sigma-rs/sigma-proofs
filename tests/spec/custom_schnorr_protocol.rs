use group::prime::PrimeGroup;
use rand::{CryptoRng, Rng};

use sigma_proofs::errors::Error;
use sigma_proofs::linear_relation::{
    Allocator, CanonicalLinearRelation, LinearRelation, ScalarMap,
};
use sigma_proofs::traits::{SigmaProtocol, SigmaProtocolSimulator};

use super::random::SRandom;

pub struct DeterministicSchnorrProof<G: PrimeGroup>(pub CanonicalLinearRelation<G>);

impl<G: PrimeGroup, A: Allocator<G = G>> TryFrom<LinearRelation<G, A>>
    for DeterministicSchnorrProof<G>
{
    type Error = Error;

    fn try_from(linear_relation: LinearRelation<G, A>) -> Result<Self, Self::Error> {
        let relation = CanonicalLinearRelation::try_from(&linear_relation)?;
        Ok(Self(relation))
    }
}

impl<G: PrimeGroup> From<CanonicalLinearRelation<G>> for DeterministicSchnorrProof<G> {
    fn from(canonical_relation: CanonicalLinearRelation<G>) -> Self {
        Self(canonical_relation)
    }
}

impl<G: SRandom + PrimeGroup> SigmaProtocol for DeterministicSchnorrProof<G> {
    type Commitment = <CanonicalLinearRelation<G> as SigmaProtocol>::Commitment;
    type ProverState = <CanonicalLinearRelation<G> as SigmaProtocol>::ProverState;
    type Response = <CanonicalLinearRelation<G> as SigmaProtocol>::Response;
    type Witness = <CanonicalLinearRelation<G> as SigmaProtocol>::Witness;
    type Challenge = <CanonicalLinearRelation<G> as SigmaProtocol>::Challenge;

    fn prover_commit(
        &self,
        witness: Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), Error> {
        let nonces = witness
            .vars()
            .map(|var| (var, <G as SRandom>::random_scalar_elt(rng)))
            .collect::<ScalarMap<G>>();
        let commitment = self.0.evaluate(&nonces);
        let prover_state = (nonces, witness.clone());
        Ok((commitment, prover_state))
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, Error> {
        self.0.prover_response(state, challenge)
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), Error> {
        self.0.verifier(commitment, challenge, response)
    }

    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8> {
        self.0.serialize_commitment(commitment)
    }

    fn serialize_challenge(&self, challenge: &Self::Challenge) -> Vec<u8> {
        self.0.serialize_challenge(challenge)
    }

    fn serialize_response(&self, response: &Self::Response) -> Vec<u8> {
        self.0.serialize_response(response)
    }

    fn deserialize_commitment(&self, data: &[u8]) -> Result<Self::Commitment, Error> {
        self.0.deserialize_commitment(data)
    }

    fn deserialize_challenge(&self, data: &[u8]) -> Result<Self::Challenge, Error> {
        self.0.deserialize_challenge(data)
    }

    fn deserialize_response(&self, data: &[u8]) -> Result<Self::Response, Error> {
        self.0.deserialize_response(data)
    }
    fn instance_label(&self) -> impl AsRef<[u8]> {
        self.0.instance_label()
    }

    fn protocol_identifier(&self) -> [u8; 64] {
        self.0.protocol_identifier()
    }
}

impl<G: SRandom + PrimeGroup> SigmaProtocolSimulator for DeterministicSchnorrProof<G> {
    fn simulate_response<R: Rng + CryptoRng>(&self, rng: &mut R) -> Self::Response {
        self.0.simulate_response(rng)
    }

    fn simulate_transcript<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Commitment, Self::Challenge, Self::Response), Error> {
        self.0.simulate_transcript(rng)
    }

    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, Error> {
        self.0.simulate_commitment(challenge, response)
    }
}
