use rand::{CryptoRng, Rng};
use group::{Group, GroupEncoding};
use ff::PrimeField;

use sigma_rs::{
    GroupMorphismPreimage, 
    SigmaProtocol, 
    GroupSerialisation, 
    ProofError
};

use crate::random::SRandom;

pub struct SchnorrProofCustom<G>
where
    G: SRandom + GroupEncoding + GroupSerialisation
{
    pub morphismp: GroupMorphismPreimage<G>
}

impl<G> SigmaProtocol for SchnorrProofCustom<G>
where
    G: SRandom + GroupEncoding + GroupSerialisation
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
    ) -> (Self::Commitment, Self::ProverState) {
        let mut nonces: Vec<G::Scalar> = Vec::new();
        for _i in 0..self.morphismp.morphism.num_scalars {
            nonces.push(<G as SRandom>::srandom(&mut *rng));
        }
        let prover_state = (nonces.clone(), witness.clone());
        let commitment = self.morphismp.morphism.evaluate(&nonces);
        (commitment, prover_state)
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Self::Response {
        let mut responses = Vec::new();
        for i in 0..self.morphismp.morphism.num_scalars {
            responses.push(state.0[i] + *challenge * state.1[i]);
        }
        responses
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ProofError> {
        let lhs = self.morphismp.morphism.evaluate(response);

        let mut rhs = Vec::new();
        for (i, g) in commitment.iter().enumerate().take(self.morphismp.morphism.num_statements()) {
            rhs.push(*g + self.morphismp.morphism.group_elements[self.morphismp.image[i].0] * *challenge);
        }

        match lhs == rhs {
            true => Ok(()),
            false => Err(ProofError::VerificationFailure),
        }
    }

    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        response: &Self::Response
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        let scalar_nb = self.morphismp.morphism.num_scalars;
        let point_nb = self.morphismp.morphism.num_statements();

        for commit in commitment.iter().take(point_nb) {
            bytes.extend_from_slice(&G::serialize_element(commit));
        }

        for response in response.iter().take(scalar_nb) {
            let mut scalar_bytes = G::serialize_scalar(response);
            scalar_bytes.reverse();
            bytes.extend_from_slice(&scalar_bytes);
        }
        bytes
    }

    fn deserialize_batchable(&self,
        data: &[u8],
    ) -> Option<(Self::Commitment, Self::Response)>
    {
        let scalar_nb = self.morphismp.morphism.num_scalars;
        let point_nb = self.morphismp.morphism.num_statements();

        let point_size = G::generator().to_bytes().as_ref().len();
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default().as_ref().len();

        let expected_len = scalar_nb * scalar_size + point_nb * point_size;
        if data.len() != expected_len {
            return None;
        }

        let mut commitments: Self::Commitment = Vec::new();
        let mut responses: Self::Response = Vec::new();

        for i in 0..point_nb {
            let start = i * point_size;
            let end = start + point_size;

            let slice = &data[start..end];
            let elem = G::deserialize_element(slice)?;
            commitments.push(elem);
        }

        for i in 0..scalar_nb {
            let start = point_nb * point_size + i * scalar_size;
            let end = start + scalar_size;

            let mut slice = data[start..end].to_vec();
            slice.reverse();
            let scalar = G::deserialize_scalar(&slice)?;
            responses.push(scalar);
        }

        Some((commitments, responses))
    }
}