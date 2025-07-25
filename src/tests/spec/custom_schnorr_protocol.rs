use group::prime::PrimeGroup;
use rand::{CryptoRng, Rng};

use crate::errors::Error;
use crate::linear_relation::{CanonicalLinearRelation, LinearRelation};
use crate::schnorr_protocol::SchnorrProof;
use crate::tests::spec::random::SRandom;
use crate::traits::{SigmaProtocol, SigmaProtocolSimulator};

pub struct DeterministicSchnorrProof<G: PrimeGroup>(pub SchnorrProof<G>);

impl<G: PrimeGroup> TryFrom<LinearRelation<G>> for DeterministicSchnorrProof<G> {
    type Error = Error;

    fn try_from(linear_relation: LinearRelation<G>) -> Result<Self, Self::Error> {
        let schnorr_proof = SchnorrProof::try_from(linear_relation)?;
        Ok(Self(schnorr_proof))
    }
}

impl<G: PrimeGroup> From<CanonicalLinearRelation<G>> for DeterministicSchnorrProof<G> {
    fn from(canonical_relation: CanonicalLinearRelation<G>) -> Self {
        Self(SchnorrProof(canonical_relation))
    }
}

impl<G: PrimeGroup> DeterministicSchnorrProof<G> {}

impl<G: SRandom + PrimeGroup> SigmaProtocol for DeterministicSchnorrProof<G> {
    type Commitment = Vec<G>;
    type ProverState = (Vec<G::Scalar>, Vec<G::Scalar>);
    type Response = Vec<G::Scalar>;
    type Witness = Vec<G::Scalar>;
    type Challenge = G::Scalar;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), Error> {
        let mut nonces: Vec<G::Scalar> = Vec::new();
        for _i in 0..self.0.witness_length() {
            nonces.push(<G as SRandom>::random_scalar_elt(rng));
        }
        self.0.commit_with_nonces(witness, &nonces)
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

    fn protocol_identifier(&self) -> impl AsRef<[u8]> {
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
