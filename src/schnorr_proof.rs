//! Implementation of the generic Schnorr Sigma Protocol over a group `G`.
//!
//! This module defines the [`SchnorrProof`] structure, which implements
//! a Sigma protocol proving different types of discrete logarithm relations (eg. Schnorr, Pedersen's commitments)
//! through a group morphism abstraction (see Maurer09).

use crate::{
    GroupMorphismPreimage,
    GroupSerialisation, 
    SigmaProtocol,
    ProofError,
};

use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use rand::{CryptoRng, Rng};

/// A Schnorr protocol proving knowledge some discrete logarithm relation.
///
/// The specific proof instance is defined by a [`GroupMorphismPreimage`] over a group `G`.
pub struct SchnorrProof<G: Group + GroupEncoding + GroupSerialisation>(pub GroupMorphismPreimage<G>);

impl<G> SigmaProtocol for SchnorrProof<G>
where
    G: Group + GroupEncoding + GroupSerialisation,
{
    type Commitment = Vec<G>;
    type ProverState = (Vec<<G as Group>::Scalar>, Vec<<G as Group>::Scalar>);
    type Response = Vec<<G as Group>::Scalar>;
    type Witness = Vec<<G as Group>::Scalar>;
    type Challenge = <G as Group>::Scalar;

    /// Prover's first message: generates a random commitment based on random nonces.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        mut rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        let nonces: Vec<G::Scalar> =  (0..self.0.morphism.num_scalars).map(|_| G::Scalar::random(&mut rng)).collect();
        let prover_state = (nonces.clone(), witness.clone());
        let commitment = self.0.morphism.evaluate(&nonces);
        (commitment, prover_state)
    }

    /// Prover's last message: computes the response to a given challenge.
    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Self::Response {
        let mut responses = Vec::new();
        for i in 0..self.0.morphism.num_scalars {
            responses.push(state.0[i] + state.1[i] * challenge);
        }
        responses
    }

    /// Verifier checks that the provided response satisfies the verification equations.
    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ProofError> {
        let lhs = self.0.morphism.evaluate(response);

        let mut rhs = Vec::new();
        for (i, g) in commitment
            .iter()
            .enumerate()
            .take(self.0.morphism.num_statements())
        {
            rhs.push(
                self.0.morphism.group_elements[self.0.image[i].0] * challenge + g,
            );
        }

        match lhs == rhs {
            true => Ok(()),
            false => Err(ProofError::VerificationFailure),
        }
    }

    /// Serializes the proof (`commitment`, `response`) into a batchable format for transmission.
    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        let scalar_nb = self.0.morphism.num_scalars;
        let point_nb = self.0.morphism.num_statements();

        // Serialize commitments
        for commit in commitment.iter().take(point_nb) {
            bytes.extend_from_slice(&G::serialize_element(commit));
        }

        // Serialize responses
        for response in response.iter().take(scalar_nb) {
            bytes.extend_from_slice(&G::serialize_scalar(response));
        }
        bytes
    }

    /// Deserializes a batchable proof format back into (`commitment`, `response`).
    fn deserialize_batchable(&self, data: &[u8]) -> Option<(Self::Commitment, Self::Response)> {
        let scalar_nb = self.0.morphism.num_scalars;
        let point_nb = self.0.morphism.num_statements();

        let point_size = G::generator().to_bytes().as_ref().len();
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

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

            let slice = &data[start..end];
            let scalar = G::deserialize_scalar(slice)?;
            responses.push(scalar);
        }

        Some((commitments, responses))
    }
}
