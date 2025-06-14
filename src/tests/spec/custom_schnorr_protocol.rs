use ff::PrimeField;
use group::{Group, GroupEncoding};
use rand::{CryptoRng, Rng};

use crate::errors::Error;
use crate::group_serialization::*;
use crate::linear_relation::LinearRelation;
use crate::tests::spec::random::SRandom;
use crate::traits::SigmaProtocol;

pub struct SchnorrProtocolCustom<G: SRandom + GroupEncoding>(pub LinearRelation<G>);

impl<G: SRandom + GroupEncoding> SchnorrProtocolCustom<G> {
    pub fn witness_len(&self) -> usize {
        self.0.morphism.num_scalars
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
            return Err(Error::ProofSizeMismatch);
        }

        let mut nonces: Vec<G::Scalar> = Vec::new();
        for _i in 0..self.0.morphism.num_scalars {
            nonces.push(<G as SRandom>::srandom(&mut *rng));
        }
        let prover_state = (nonces.clone(), witness.clone());
        let commitment = self.0.morphism.evaluate(&nonces)?;
        Ok((commitment, prover_state))
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, Error> {
        if state.0.len() != self.witness_len() || state.1.len() != self.witness_len() {
            return Err(Error::ProofSizeMismatch);
        }

        let mut responses = Vec::new();
        for i in 0..self.0.morphism.num_scalars {
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
        let lhs = self.0.morphism.evaluate(response)?;

        let mut rhs = Vec::new();
        for (i, g) in commitment
            .iter()
            .enumerate()
            .take(self.0.morphism.constraints.len())
        {
            rhs.push({
                let image_var = self.0.image[i];
                *g + self.0.morphism.group_elements.get(image_var)? * *challenge
            });
        }

        match lhs == rhs {
            true => Ok(()),
            false => Err(Error::VerificationFailure),
        }
    }

    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8> {
        let mut bytes = Vec::new();
        let point_nb = self.0.morphism.constraints.len();
        for commit in commitment.iter().take(point_nb) {
            bytes.extend_from_slice(&serialize_element(commit));
        }
        bytes
    }

    fn serialize_challenge(&self, challenge: &Self::Challenge) -> Vec<u8> {
        serialize_scalar::<G>(challenge)
    }

    fn serialize_response(&self, response: &Self::Response) -> Vec<u8> {
        let mut bytes = Vec::new();
        let scalar_nb = self.0.morphism.num_scalars;
        for response in response.iter().take(scalar_nb) {
            bytes.extend_from_slice(&serialize_scalar::<G>(response));
        }
        bytes
    }

    fn deserialize_commitment(&self, data: &[u8]) -> Result<Self::Commitment, Error> {
        let point_nb = self.0.morphism.constraints.len();
        let point_size = G::generator().to_bytes().as_ref().len();
        let expected_len = point_nb * point_size;

        if data.len() < expected_len {
            return Err(Error::ProofSizeMismatch);
        }

        let mut commitments: Self::Commitment = Vec::new();
        for i in 0..point_nb {
            let start = i * point_size;
            let end = start + point_size;
            let slice = &data[start..end];
            let elem = deserialize_element(slice)?;
            commitments.push(elem);
        }

        Ok(commitments)
    }

    fn deserialize_challenge(&self, data: &[u8]) -> Result<Self::Challenge, Error> {
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();
        if data.len() < scalar_size {
            return Err(Error::ProofSizeMismatch);
        }
        deserialize_scalar::<G>(&data[..scalar_size])
    }

    fn deserialize_response(&self, data: &[u8]) -> Result<Self::Response, Error> {
        let scalar_nb = self.0.morphism.num_scalars;
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();
        let expected_len = scalar_nb * scalar_size;

        if data.len() < expected_len {
            return Err(Error::ProofSizeMismatch);
        }

        let mut responses: Self::Response = Vec::new();
        for i in 0..scalar_nb {
            let start = i * scalar_size; // No offset needed - data contains only responses
            let end = start + scalar_size;
            let slice = &data[start..end];
            let scalar = deserialize_scalar::<G>(slice)?;
            responses.push(scalar);
        }

        Ok(responses)
    }

    fn get_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, Error> {
        if response.len() != self.0.morphism.num_scalars {
            return Err(Error::ProofSizeMismatch);
        }

        let response_image = self.0.morphism.evaluate(response)?;
        let image = self.0.image()?;

        let mut commitment = Vec::new();
        for i in 0..image.len() {
            commitment.push(response_image[i] - image[i] * challenge);
        }
        Ok(commitment)
    }
}
