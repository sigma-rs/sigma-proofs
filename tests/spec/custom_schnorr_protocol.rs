use ff::PrimeField;
use group::{Group, GroupEncoding};
use rand::{CryptoRng, Rng};

use crate::random::SRandom;
use sigma_rs::errors::Error;
use sigma_rs::group_morphism::GroupMorphismPreimage;
use sigma_rs::group_serialization::*;
use sigma_rs::traits::SigmaProtocol;

pub struct SchnorrProtocolCustom<G: SRandom + GroupEncoding>(pub GroupMorphismPreimage<G>);

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
        let commitment = self.0.morphism.evaluate(&nonces);
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
        let lhs = self.0.morphism.evaluate(response);

        let mut rhs = Vec::new();
        for (i, g) in commitment
            .iter()
            .enumerate()
            .take(self.0.morphism.num_statements())
        {
            rhs.push(*g + self.0.morphism.group_elements[self.0.image[i].index()] * *challenge);
        }

        match lhs == rhs {
            true => Ok(()),
            false => Err(Error::VerificationFailure),
        }
    }

    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        let scalar_nb = self.0.morphism.num_scalars;
        let point_nb = self.0.morphism.num_statements();

        for commit in commitment.iter().take(point_nb) {
            bytes.extend_from_slice(&serialize_element(commit));
        }

        for response in response.iter().take(scalar_nb) {
            let scalar_bytes = serialize_scalar::<G>(response);
            bytes.extend_from_slice(&scalar_bytes);
        }
        Ok(bytes)
    }

    fn deserialize_batchable(
        &self,
        data: &[u8],
    ) -> Result<(Self::Commitment, Self::Response), Error> {
        let scalar_nb = self.0.morphism.num_scalars;
        let point_nb = self.0.morphism.num_statements();

        let point_size = G::generator().to_bytes().as_ref().len();
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        let expected_len = scalar_nb * scalar_size + point_nb * point_size;
        if data.len() != expected_len {
            return Err(Error::ProofSizeMismatch);
        }

        let mut commitments: Self::Commitment = Vec::new();
        let mut responses: Self::Response = Vec::new();

        for i in 0..point_nb {
            let start = i * point_size;
            let end = start + point_size;

            let slice = &data[start..end];
            let elem = deserialize_element(slice)?;
            commitments.push(elem);
        }

        for i in 0..scalar_nb {
            let start = point_nb * point_size + i * scalar_size;
            let end = start + scalar_size;

            let slice = data[start..end].to_vec();
            let scalar = deserialize_scalar::<G>(&slice)?;
            responses.push(scalar);
        }

        Ok((commitments, responses))
    }
}
