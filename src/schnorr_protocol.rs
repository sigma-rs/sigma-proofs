//! Implementation of the generic Schnorr Sigma Protocol over a group `G`.
//!
//! This module defines the [`SchnorrProtocol`] structure, which implements
//! a Sigma protocol proving different types of discrete logarithm relations (eg. Schnorr, Pedersen's commitments)
//! through a group morphism abstraction (see Maurer09).

use crate::codec::Codec;
use crate::errors::Error;
use crate::fiat_shamir::{FiatShamir, HasGroupMorphism};
use crate::group_morphism::GroupMorphismPreimage;
use crate::{
    group_serialization::*,
    traits::{CompactProtocol, SigmaProtocol, SigmaProtocolSimulator},
};

use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use rand::{CryptoRng, RngCore};

/// A Schnorr protocol proving knowledge of a witness for a linear group relation.
///
/// This implementation generalizes Schnorr’s discrete logarithm proof by using
/// a [`GroupMorphismPreimage`], representing an abstract linear relation over the group.
///
/// # Type Parameters
/// - `G`: A cryptographic group implementing [`Group`] and [`GroupEncoding`].
#[derive(Clone, Default, Debug)]
pub struct SchnorrProtocol<G: Group + GroupEncoding>(pub GroupMorphismPreimage<G>);

impl<G: Group + GroupEncoding> SchnorrProtocol<G> {
    pub fn scalars_nb(&self) -> usize {
        self.0.morphism.num_scalars
    }

    pub fn statements_nb(&self) -> usize {
        self.0.morphism.constraints.len()
    }
}

impl<G> From<GroupMorphismPreimage<G>> for SchnorrProtocol<G>
where
    G: Group + GroupEncoding,
{
    fn from(value: GroupMorphismPreimage<G>) -> Self {
        Self(value)
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

    /// Prover's first message: generates a commitment using random nonces.
    ///
    /// # Parameters
    /// - `witness`: A vector of scalars that satisfy the morphism relation.
    /// - `rng`: A cryptographically secure random number generator.
    ///
    /// # Returns
    /// - A tuple containing:
    ///     - The commitment (a vector of group elements).
    ///     - The prover state (random nonces and witness) used to compute the response.
    ///
    /// # Errors
    /// -`ProofError::ProofSizeMismatch` if the witness vector length is incorrect.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        mut rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), Error> {
        if witness.len() != self.scalars_nb() {
            return Err(Error::ProofSizeMismatch);
        }

        let nonces: Vec<G::Scalar> = (0..self.scalars_nb())
            .map(|_| G::Scalar::random(&mut rng))
            .collect();
        let prover_state = (nonces.clone(), witness.clone());
        let commitment = self.0.morphism.evaluate(&nonces)?;
        Ok((commitment, prover_state))
    }

    /// Computes the prover's response (second message) using the challenge.
    ///
    /// # Parameters
    /// - `state`: The prover state returned by `prover_commit`, typically containing randomness and witness components.
    /// - `challenge`: The verifier's challenge scalar.
    ///
    /// # Returns
    /// - A vector of scalars forming the prover's response.
    ///
    /// # Errors
    /// - Returns `ProofError::ProofSizeMismatch` if the prover state vectors have incorrect lengths.
    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, Error> {
        if state.0.len() != self.scalars_nb() || state.1.len() != self.scalars_nb() {
            return Err(Error::ProofSizeMismatch);
        }

        let mut responses = Vec::new();
        for i in 0..self.scalars_nb() {
            responses.push(state.0[i] + state.1[i] * challenge);
        }
        Ok(responses)
    }
    /// Verifies the correctness of the proof.
    ///
    /// # Parameters
    /// - `commitment`: The prover's commitment vector (group elements).
    /// - `challenge`: The challenge scalar.
    /// - `response`: The prover's response vector.
    ///
    /// # Returns
    /// - `Ok(())` if the proof is valid.
    /// - `Err(ProofError::VerificationFailure)` if the proof is invalid.
    /// - `Err(ProofError::ProofSizeMismatch)` if the lengths of commitment or response do not match the expected counts.
    ///
    /// # Errors
    /// -`Err(ProofError::VerificationFailure)` if the computed relation
    /// does not hold for the provided challenge and response, indicating proof invalidity.
    /// -`Err(ProofError::ProofSizeMismatch)` if the commitment or response length is incorrect.
    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), Error> {
        if commitment.len() != self.statements_nb() || response.len() != self.scalars_nb() {
            return Err(Error::ProofSizeMismatch);
        }

        let lhs = self.0.morphism.evaluate(response)?;
        let mut rhs = Vec::new();
        for (i, g) in commitment.iter().enumerate().take(self.statements_nb()) {
            rhs.push({
                let image_var = self.0.image[i];
                self.0.morphism.group_elements.get(image_var)? * challenge + g
            });
        }
        match lhs == rhs {
            true => Ok(()),
            false => Err(Error::VerificationFailure),
        }
    }

    /// Serializes the proof into a batchable format: commitments followed by responses.
    ///
    /// # Parameters
    /// - `commitment`: A vector of group elements (typically sent in the first round).
    /// - `_challenge`: The verifier’s challenge (omitted from batchable format).
    /// - `response`: A vector of scalars forming the prover’s response.
    ///
    /// # Returns
    /// - A byte vector representing the serialized batchable proof.
    ///
    /// # Errors
    /// - `ProofError::ProofSizeMismatch` if the commitment or response length is incorrect.
    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, Error> {
        let commit_nb = self.statements_nb();
        let response_nb = self.scalars_nb();
        if commitment.len() != commit_nb || response.len() != response_nb {
            return Err(Error::ProofSizeMismatch);
        }

        let mut bytes = Vec::new();
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

    /// Deserializes a batchable proof into a commitment vector and response vector.
    ///
    /// # Parameters
    /// - `data`: A byte slice containing the serialized proof.
    ///
    /// # Returns
    /// - A tuple `(commitment, response)` where
    ///   * `commitment` is a vector of group elements (one per statement), and
    ///   * `response`   is a vector of scalars (one per witness).
    ///
    /// # Errors
    /// - `ProofError::ProofSizeMismatch` if the input length is not the exact number of bytes
    ///   expected for `commit_nb` commitments plus `response_nb` responses.
    /// - `ProofError::GroupSerializationFailure` if any group element or scalar fails to
    ///   deserialize (propagated from `deserialize_element` or `deserialize_scalar`).
    fn deserialize_batchable(
        &self,
        data: &[u8],
    ) -> Result<((Self::Commitment, Self::Response), usize), Error> {
        let commit_nb = self.statements_nb();
        let response_nb = self.scalars_nb();

        let commit_size = G::generator().to_bytes().as_ref().len();
        let response_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        let expected_len = response_nb * response_size + commit_nb * commit_size;
        if data.len() < expected_len {
            return Err(Error::ProofSizeMismatch);
        }

        let mut commitments: Self::Commitment = Vec::new();
        let mut responses: Self::Response = Vec::new();

        for i in 0..commit_nb {
            let start = i * commit_size;
            let end = start + commit_size;

            let slice = &data[start..end];
            let elem = deserialize_element(slice)?;
            commitments.push(elem);
        }

        for i in 0..response_nb {
            let start = commit_nb * commit_size + i * response_size;
            let end = start + response_size;

            let slice = &data[start..end];
            let scalar = deserialize_scalar::<G>(slice)?;
            responses.push(scalar);
        }

        Ok(((commitments, responses), expected_len))
    }
}

impl<G> CompactProtocol for SchnorrProtocol<G>
where
    G: Group + GroupEncoding,
{
    /// Recomputes the commitment from the challenge and response (used in compact proofs).
    ///
    /// # Parameters
    /// - `challenge`: The challenge scalar issued by the verifier or derived via Fiat–Shamir.
    /// - `response`: The prover’s response vector.
    ///
    /// # Returns
    /// - A vector of group elements representing the recomputed commitment (one per linear constraint).
    ///
    /// # Errors
    /// - `ProofError::ProofSizeMismatch` if the response length does not match the expected number of scalars.
    fn get_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, Error> {
        if response.len() != self.scalars_nb() {
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

    fn serialize_response(&self, response: &Self::Response) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        let response_nb = self.scalars_nb();
        if response.len() != response_nb {
            return Err(Error::ProofSizeMismatch);
        }

        // Serialize responses
        for response in response.iter().take(response_nb) {
            bytes.extend_from_slice(&serialize_scalar::<G>(response));
        }
        Ok(bytes)
    }

    fn deserialize_response(&self, data: &[u8]) -> Result<(Self::Response, usize), Error> {
        let response_nb = self.scalars_nb();
        let response_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();
        let expected_size = response_nb * response_size;
        if data.len() < expected_size {
            return Err(Error::ProofSizeMismatch);
        }

        let mut responses: Self::Response = Vec::new();
        for i in 0..response_nb {
            let start = i * response_size;
            let end = start + response_size;

            let slice = &data[start..end];
            let scalar = deserialize_scalar::<G>(slice)?;
            responses.push(scalar);
        }
        Ok((responses, expected_size))
    }

    /// Serializes a compact transcript: challenge followed by responses.
    /// # Parameters
    /// - `_commitment`: Omitted in compact format (reconstructed during verification).
    /// - `challenge`: The challenge scalar.
    /// - `response`: The prover’s response.
    ///
    /// # Returns
    /// - A byte vector representing the compact proof.
    ///
    /// # Errors
    /// - `ProofError::ProofSizeMismatch` if the response length does not match the expected number of scalars.
    fn serialize_compact(
        &self,
        _commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();

        // Serialize challenge
        bytes.extend_from_slice(&serialize_scalar::<G>(challenge));

        // Serialize responses
        bytes.extend_from_slice(&self.serialize_response(response)?);
        Ok(bytes)
    }

    /// Deserializes a compact proof into a challenge and response.
    ///
    /// # Parameters
    /// - `data`: A byte slice encoding the compact proof.
    ///
    /// # Returns
    /// - A tuple `(challenge, response)`.
    ///
    /// # Errors
    /// - `ProofError::ProofSizeMismatch` if the input data length does not match the expected size.
    /// - `ProofError::GroupSerializationFailure` if scalar deserialization fails.
    fn deserialize_compact(&self, data: &[u8]) -> Result<(Self::Challenge, Self::Response), Error> {
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        let slice = &data[0..scalar_size];
        let challenge = deserialize_scalar::<G>(slice)?;
        let (responses, _) = self.deserialize_response(&data[scalar_size..])?;

        Ok((challenge, responses))
    }
}

impl<G> SigmaProtocolSimulator for SchnorrProtocol<G>
where
    G: Group + GroupEncoding,
{
    /// Simulates a valid transcript for a given challenge without a witness.
    ///
    /// # Parameters
    /// - `challenge`: A scalar value representing the challenge.
    /// - `rng`: A cryptographically secure RNG.
    ///
    /// # Returns
    /// - A commitment and response forming a valid proof for the given challenge.
    fn simulate_proof(
        &self,
        challenge: &Self::Challenge,
        mut rng: &mut (impl RngCore + CryptoRng),
    ) -> (Self::Commitment, Self::Response) {
        let response = (0..self.scalars_nb()).map(|_| G::Scalar::random(&mut rng)).collect();
        let commitment = self.get_commitment(challenge, &response).unwrap();
        (commitment, response)
    }

    /// Simulates a full proof transcript using a randomly generated challenge.
    ///
    /// # Parameters
    /// - `rng`: A cryptographically secure RNG.
    ///
    /// # Returns
    /// - A tuple `(commitment, challenge, response)` forming a valid proof.
    fn simulate_transcript(
        &self,
        mut rng: &mut (impl RngCore + CryptoRng),
    ) -> (Self::Commitment, Self::Challenge, Self::Response) {
        let challenge = G::Scalar::random(&mut rng);
        let (commitment, response) = self.simulate_proof(&challenge, rng);
        (commitment, challenge, response)
    }
}

impl<G, C> FiatShamir<C> for SchnorrProtocol<G>
where
    C: Codec<Challenge = <G as Group>::Scalar>,
    G: Group + GroupEncoding,
{
    /// Absorbs commitments into the codec for future use of the codec
    ///
    /// # Parameters
    /// - `codec`: the Codec that absorbs commitments
    /// - `commitment`: a commitment of SchnorrProtocol
    fn push_commitment(&self, codec: &mut C, commitment: &Self::Commitment) {
        let mut data = Vec::new();
        for commit in commitment {
            data.extend_from_slice(commit.to_bytes().as_ref());
        }
        codec.prover_message(&data);
    }

    /// Generates a challenge from the codec that absorbed the commitments
    ///
    /// # Parameters
    /// - `codec`: the Codec from which the challenge is generated
    ///
    /// # Returns
    /// - A `challenge`` that can be used during a non-interactive protocol
    fn get_challenge(&self, codec: &mut C) -> Result<Self::Challenge, Error> {
        Ok(codec.verifier_challenge())
    }
}

impl<G: Group + GroupEncoding> HasGroupMorphism for SchnorrProtocol<G> {
    fn absorb_morphism_structure<C: Codec>(&self, codec: &mut C) -> Result<(), Error> {
        for lc in &self.0.morphism.constraints {
            for term in lc.terms() {
                let mut buf = [0u8; 16];
                buf[..8].copy_from_slice(&(term.scalar().index() as u64).to_le_bytes());
                buf[8..].copy_from_slice(&(term.elem().index() as u64).to_le_bytes());
                codec.prover_message(&buf);
            }
        }
        Ok(())
    }
}
