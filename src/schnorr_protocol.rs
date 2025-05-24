//! Implementation of the generic Schnorr Sigma Protocol over a group `G`.
//!
//! This module defines the [`SchnorrProtocol`] structure, which implements
//! a Sigma protocol proving different types of discrete logarithm relations (eg. Schnorr, Pedersen's commitments)
//! through a group morphism abstraction (see Maurer09).

use crate::{
    group_serialization::*, CompactProtocol, GroupMorphismPreimage, PointVar, ProofError,
    ScalarVar, SigmaProtocol, SigmaProtocolSimulator,
};

use core::iter;
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use rand::{CryptoRng, RngCore};

/// A Schnorr protocol proving knowledge some discrete logarithm relation.
///
/// The specific proof instance is defined by a [`GroupMorphismPreimage`] over a group `G`.
pub struct SchnorrProtocol<G: Group + GroupEncoding>(GroupMorphismPreimage<G>);

impl<G: Group + GroupEncoding> SchnorrProtocol<G> {
    pub fn new() -> Self {
        SchnorrProtocol(GroupMorphismPreimage::<G>::new())
    }

    pub fn from_preimage(preimage: GroupMorphismPreimage<G>) -> Self {
        SchnorrProtocol(preimage)
    }

    pub fn scalars_nb(&self) -> usize {
        self.0.morphism.num_scalars
    }

    pub fn points_nb(&self) -> usize {
        self.0.morphism.num_statements()
    }

    pub fn append_equation(&mut self, lhs: PointVar, rhs: &[(ScalarVar, PointVar)]) {
        self.0.append_equation(lhs, rhs);
    }

    pub fn allocate_scalars(&mut self, n: usize) -> Vec<ScalarVar> {
        self.0.allocate_scalars(n)
    }

    pub fn allocate_elements(&mut self, n: usize) -> Vec<PointVar> {
        self.0.allocate_elements(n)
    }

    pub fn set_elements(&mut self, elements: &[(PointVar, G)]) {
        self.0.set_elements(elements);
    }

    pub fn image(&self) -> Vec<G> {
        self.0.image()
    }
}

impl<G> SigmaProtocol for SchnorrProtocol<G>
where
    G: Group + GroupEncoding,
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
        mut rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), ProofError> {
        if witness.len() != self.scalars_nb() {
            return Err(ProofError::Other);
        }

        let nonces: Vec<G::Scalar> = (0..self.0.morphism.num_scalars)
            .map(|_| G::Scalar::random(&mut rng))
            .collect();
        let prover_state = (nonces.clone(), witness.clone());
        let commitment = self.0.morphism.evaluate(&nonces);
        Ok((commitment, prover_state))
    }

    /// Prover's last message: computes the response to a given challenge.
    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, ProofError> {
        if state.0.len() != self.scalars_nb() || state.1.len() != self.scalars_nb() {
            return Err(ProofError::Other);
        }

        let mut responses = Vec::new();
        for i in 0..self.0.morphism.num_scalars {
            responses.push(state.0[i] + state.1[i] * challenge);
        }
        Ok(responses)
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
            rhs.push(self.0.morphism.group_elements[self.0.image[i].index()] * challenge + g);
        }

        match lhs == rhs {
            true => Ok(()),
            false => Err(ProofError::VerificationFailure),
        }
    }

    /// Serializes the proof into a batchable (`commitment`, `response`) format for transmission.
    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, ProofError> {
        let mut bytes = Vec::new();
        let commit_nb = self.0.morphism.num_statements();
        let response_nb = self.0.morphism.num_scalars;

        // Serialize commitments
        for commit in commitment.iter().take(commit_nb) {
            bytes.extend_from_slice(&serialize_element(commit));
        }

        // Serialize responses
        for response in response.iter().take(response_nb) {
            bytes.extend_from_slice(&serialize_scalar::<G>(response));
        }
        Ok(bytes)
    }

    /// Deserializes a batchable proof format back into (`commitment`, `response`).
    fn deserialize_batchable(
        &self,
        data: &[u8],
    ) -> Result<(Self::Commitment, Self::Response), ProofError> {
        let commit_nb = self.0.morphism.num_statements();
        let response_nb = self.0.morphism.num_scalars;

        let commit_size = G::generator().to_bytes().as_ref().len();
        let response_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        let expected_len = response_nb * response_size + commit_nb * commit_size;
        if data.len() != expected_len {
            return Err(ProofError::BatchSizeMismatch);
        }

        let mut commitments: Self::Commitment = Vec::new();
        let mut responses: Self::Response = Vec::new();

        for i in 0..commit_nb {
            let start = i * commit_size;
            let end = start + commit_size;

            let slice = &data[start..end];
            let elem = deserialize_element(slice).ok_or(ProofError::GroupSerializationFailure)?;
            commitments.push(elem);
        }

        for i in 0..response_nb {
            let start = commit_nb * commit_size + i * response_size;
            let end = start + response_size;

            let slice = &data[start..end];
            let scalar =
                deserialize_scalar::<G>(slice).ok_or(ProofError::GroupSerializationFailure)?;
            responses.push(scalar);
        }

        Ok((commitments, responses))
    }
}

impl<G> CompactProtocol for SchnorrProtocol<G>
where
    G: Group + GroupEncoding,
{
    fn get_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, ProofError> {
        if response.len() != self.scalars_nb() {
            return Err(ProofError::Other);
        }

        let response_image = self.0.morphism.evaluate(response);
        let image = self.0.image();

        let mut commitment = Vec::new();
        for i in 0..image.len() {
            commitment.push(response_image[i] - image[i] * challenge);
        }
        Ok(commitment)
    }

    /// Serializes the proof into a compact (`challenge`, `response`) format for transmission.
    fn serialize_compact(
        &self,
        _commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, ProofError> {
        let mut bytes = Vec::new();
        let response_nb = self.0.morphism.num_scalars;

        // Serialize challenge
        bytes.extend_from_slice(&serialize_scalar::<G>(challenge));

        // Serialize responses
        for response in response.iter().take(response_nb) {
            bytes.extend_from_slice(&serialize_scalar::<G>(response));
        }
        Ok(bytes)
    }

    /// Deserializes a compact proof format back into (`challenge`, `response`).
    fn deserialize_compact(
        &self,
        data: &[u8],
    ) -> Result<(Self::Challenge, Self::Response), ProofError> {
        let response_nb = self.0.morphism.num_scalars;
        let response_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        let expected_len = (response_nb + 1) * response_size;

        if data.len() != expected_len {
            return Err(ProofError::BatchSizeMismatch);
        }

        let mut responses: Self::Response = Vec::new();

        let slice = &data[0..response_size];
        let challenge =
            deserialize_scalar::<G>(slice).ok_or(ProofError::GroupSerializationFailure)?;

        for i in 0..response_nb {
            let start = (i + 1) * response_size;
            let end = start + response_size;

            let slice = &data[start..end];
            let scalar =
                deserialize_scalar::<G>(slice).ok_or(ProofError::GroupSerializationFailure)?;
            responses.push(scalar);
        }

        Ok((challenge, responses))
    }
}

impl<G> SigmaProtocolSimulator for SchnorrProtocol<G>
where
    G: Group + GroupEncoding,
{
    fn simulate_proof(
        &self,
        challenge: &Self::Challenge,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (Self::Commitment, Self::Response) {
        let mut response = Vec::new();
        response.extend(iter::repeat(G::Scalar::random(rng)).take(self.0.morphism.num_scalars));
        let commitment = self.get_commitment(challenge, &response).unwrap();
        (commitment, response)
    }

    fn simulate_transcript(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (Self::Commitment, Self::Challenge, Self::Response) {
        let challenge = G::Scalar::random(&mut *rng);
        let (commitment, response) = self.simulate_proof(&challenge, &mut *rng);
        (commitment, challenge, response)
    }
}
