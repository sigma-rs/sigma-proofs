use group::prime::PrimeGroup;
use rand::{CryptoRng, Rng};

use sigma_proofs::errors::Error;
use sigma_proofs::linear_relation::{CanonicalLinearRelation, LinearRelation};
use sigma_proofs::traits::{SigmaProtocol, SigmaProtocolSimulator};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

pub struct DeterministicSchnorrProof<G: PrimeGroup>(pub CanonicalLinearRelation<G>);

impl<G: PrimeGroup> TryFrom<LinearRelation<G>> for DeterministicSchnorrProof<G> {
    type Error = Error;

    fn try_from(linear_relation: LinearRelation<G>) -> Result<Self, Self::Error> {
        let relation = CanonicalLinearRelation::try_from(&linear_relation)?;
        Ok(Self(relation))
    }
}

impl<G: PrimeGroup> From<CanonicalLinearRelation<G>> for DeterministicSchnorrProof<G> {
    fn from(canonical_relation: CanonicalLinearRelation<G>) -> Self {
        Self(canonical_relation)
    }
}

impl<G> SigmaProtocol for DeterministicSchnorrProof<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    type Commitment = <CanonicalLinearRelation<G> as SigmaProtocol>::Commitment;
    type ProverState = <CanonicalLinearRelation<G> as SigmaProtocol>::ProverState;
    type Response = <CanonicalLinearRelation<G> as SigmaProtocol>::Response;
    type Witness = <CanonicalLinearRelation<G> as SigmaProtocol>::Witness;
    type Challenge = <CanonicalLinearRelation<G> as SigmaProtocol>::Challenge;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<(Vec<Self::Commitment>, Self::ProverState), Error> {
        self.0.prover_commit(witness, rng)
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Vec<Self::Response>, Error> {
        self.0.prover_response(state, challenge)
    }

    fn verifier(
        &self,
        commitment: &[Self::Commitment],
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<(), Error> {
        self.0.verifier(commitment, challenge, response)
    }

    fn commitment_len(&self) -> usize {
        self.0.commitment_len()
    }

    fn response_len(&self) -> usize {
        self.0.response_len()
    }

    fn instance_label(&self) -> impl AsRef<[u8]> {
        self.0.instance_label()
    }

    fn protocol_identifier(&self) -> [u8; 64] {
        self.0.protocol_identifier()
    }
}

impl<G> SigmaProtocolSimulator for DeterministicSchnorrProof<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    fn simulate_response<R: Rng + CryptoRng>(&self, rng: &mut R) -> Vec<Self::Response> {
        self.0.simulate_response(rng)
    }

    fn simulate_transcript<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Vec<Self::Commitment>, Self::Challenge, Vec<Self::Response>), Error> {
        self.0.simulate_transcript(rng)
    }

    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<Vec<Self::Commitment>, Error> {
        self.0.simulate_commitment(challenge, response)
    }
}
