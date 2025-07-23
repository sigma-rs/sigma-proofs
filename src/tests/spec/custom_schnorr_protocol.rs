use group::{Group, GroupEncoding};
use rand::{CryptoRng, Rng};

use crate::errors::Error;
use crate::linear_relation::LinearRelation;
use crate::serialization::{
    deserialize_elements, deserialize_scalars, serialize_elements, serialize_scalars,
};
use crate::tests::spec::random::SRandom;
use crate::traits::{SigmaProtocol, SigmaProtocolSimulator};

pub struct SchnorrProtocolCustom<G: SRandom + GroupEncoding>(pub LinearRelation<G>);

impl<G> From<LinearRelation<G>> for SchnorrProtocolCustom<G>
where
    G: SRandom + GroupEncoding,
{
    fn from(value: LinearRelation<G>) -> Self {
        Self(value)
    }
}

impl<G: SRandom + GroupEncoding> SchnorrProtocolCustom<G> {
    pub fn witness_len(&self) -> usize {
        self.0.linear_map.num_scalars
    }
}

impl<G> SigmaProtocol for SchnorrProtocolCustom<G>
where
    G: SRandom + GroupEncoding,
{
    type Commitment = Vec<G>;
    type ProverState = (Vec<<G as Group>::Scalar>, Vec<<G as Group>::Scalar>);
    type Response = Vec<<G as Group>::Scalar>;
    type Witness = Vec<<G as Group>::Scalar>;
    type Challenge = <G as Group>::Scalar;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), Error> {
        if witness.len() != self.witness_len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let mut nonces: Vec<G::Scalar> = Vec::new();
        for _i in 0..self.0.linear_map.num_scalars {
            nonces.push(<G as SRandom>::srandom(rng));
        }
        let prover_state = (nonces.clone(), witness.clone());
        let commitment = self.0.linear_map.evaluate(&nonces)?;
        Ok((commitment, prover_state))
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, Error> {
        if state.0.len() != self.witness_len() || state.1.len() != self.witness_len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let mut responses = Vec::new();
        for i in 0..self.0.linear_map.num_scalars {
            responses.push(state.0[i] + *challenge * state.1[i]);
        }
        Ok(responses)
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), Error> {
        let lhs = self.0.linear_map.evaluate(response)?;

        let mut rhs = Vec::new();
        for (i, g) in commitment
            .iter()
            .enumerate()
            .take(self.0.linear_map.num_constraints())
        {
            rhs.push({
                let image_var = self.0.image[i];
                *g + self.0.linear_map.group_elements.get(image_var)? * *challenge
            });
        }

        match lhs == rhs {
            true => Ok(()),
            false => Err(Error::VerificationFailure),
        }
    }

    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8> {
        serialize_elements(&commitment[..self.0.linear_map.num_constraints()])
    }

    fn serialize_challenge(&self, challenge: &Self::Challenge) -> Vec<u8> {
        serialize_scalars::<G>(&[*challenge])
    }

    fn serialize_response(&self, response: &Self::Response) -> Vec<u8> {
        serialize_scalars::<G>(&response[..self.0.linear_map.num_scalars])
    }

    fn deserialize_commitment(&self, data: &[u8]) -> Result<Self::Commitment, Error> {
        deserialize_elements::<G>(data, self.0.linear_map.num_constraints())
            .ok_or(Error::VerificationFailure)
    }

    fn deserialize_challenge(&self, data: &[u8]) -> Result<Self::Challenge, Error> {
        let scalars = deserialize_scalars::<G>(data, 1).ok_or(Error::VerificationFailure)?;
        Ok(scalars[0])
    }

    fn deserialize_response(&self, data: &[u8]) -> Result<Self::Response, Error> {
        deserialize_scalars::<G>(data, self.0.linear_map.num_scalars)
            .ok_or(Error::VerificationFailure)
    }
    fn instance_label(&self) -> impl AsRef<[u8]> {
        self.0.label()
    }

    fn protocol_identifier(&self) -> impl AsRef<[u8]> {
        b"draft-zkproof-fiat-shamir"
    }
}

impl<G: SRandom + GroupEncoding> SigmaProtocolSimulator for SchnorrProtocolCustom<G> {
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, Error> {
        if response.len() != self.0.linear_map.num_scalars {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let response_image = self.0.linear_map.evaluate(response)?;
        let image = self.0.image()?;

        let mut commitment = Vec::new();
        for i in 0..image.len() {
            commitment.push(response_image[i] - image[i] * challenge);
        }
        Ok(commitment)
    }

    fn simulate_response<R: Rng + CryptoRng>(&self, rng: &mut R) -> Self::Response {
        (0..self.0.linear_map.num_scalars)
            .map(|_| <G as SRandom>::srandom(rng))
            .collect()
    }

    fn simulate_transcript<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Commitment, Self::Challenge, Self::Response), Error> {
        let challenge = <G as SRandom>::srandom(rng);
        let response = self.simulate_response(rng);
        let commitment = self.simulate_commitment(&challenge, &response)?;
        Ok((commitment, challenge, response))
    }
}
