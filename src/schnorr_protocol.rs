//! Implementation of the generic Schnorr Sigma Protocol over a [`Group`].
//!
//! This module defines the [`SchnorrProof`] structure, which implements
//! a Sigma protocol proving different types of discrete logarithm relations (eg. Schnorr, Pedersen's commitments)
//! through a group morphism abstraction (see [Maurer09](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf)).

use crate::errors::Error;
use crate::linear_relation::LinearRelation;
use crate::{
    serialization::{
        deserialize_element, deserialize_scalar, scalar_byte_size, serialize_element,
        serialize_scalar,
    },
    traits::{SigmaProtocol, SigmaProtocolSimulator},
};

use ff::Field;
use group::{Group, GroupEncoding};
use rand::{CryptoRng, RngCore};

/// A Schnorr protocol proving knowledge of a witness for a linear group relation.
///
/// This implementation generalizes Schnorr’s discrete logarithm proof by using
/// a [`LinearRelation`], representing an abstract linear relation over the group.
///
/// # Type Parameters
/// - `G`: A cryptographic group implementing [`Group`] and [`GroupEncoding`].
#[derive(Clone, Default, Debug)]
pub struct SchnorrProof<G: Group + GroupEncoding>(pub LinearRelation<G>);

impl<G: Group + GroupEncoding> SchnorrProof<G> {
    pub fn witness_length(&self) -> usize {
        self.0.linear_map.num_scalars
    }

    pub fn commitment_length(&self) -> usize {
        self.0.linear_map.num_constraints()
    }
}

impl<G> From<LinearRelation<G>> for SchnorrProof<G>
where
    G: Group + GroupEncoding,
{
    fn from(value: LinearRelation<G>) -> Self {
        Self(value)
    }
}

impl<G> SigmaProtocol for SchnorrProof<G>
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
    /// -[`Error::ProofSizeMismatch`] if the witness vector length is incorrect.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        mut rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), Error> {
        if witness.len() != self.witness_length() {
            return Err(Error::ProofSizeMismatch);
        }

        let nonces: Vec<G::Scalar> = (0..self.witness_length())
            .map(|_| G::Scalar::random(&mut rng))
            .collect();
        let prover_state = (nonces.clone(), witness.clone());
        let commitment = self.0.linear_map.evaluate(&nonces)?;
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
    /// - Returns [`Error::ProofSizeMismatch`] if the prover state vectors have incorrect lengths.
    fn prover_response(
        &self,
        prover_state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, Error> {
        let (nonces, witness) = prover_state;

        if nonces.len() != self.witness_length() || witness.len() != self.witness_length() {
            return Err(Error::ProofSizeMismatch);
        }

        let mut responses = Vec::new();
        for i in 0..self.witness_length() {
            responses.push(nonces[i] + witness[i] * challenge);
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
    /// - `Err(Error::VerificationFailure)` if the proof is invalid.
    /// - `Err(Error::ProofSizeMismatch)` if the lengths of commitment or response do not match the expected counts.
    ///
    /// # Errors
    /// -[`Error::VerificationFailure`] if the computed relation
    /// does not hold for the provided challenge and response, indicating proof invalidity.
    /// -[`Error::ProofSizeMismatch`] if the commitment or response length is incorrect.
    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), Error> {
        if commitment.len() != self.commitment_length() || response.len() != self.witness_length() {
            return Err(Error::ProofSizeMismatch);
        }

        let lhs = self.0.linear_map.evaluate(response)?;
        let mut rhs = Vec::new();
        for (i, g) in commitment.iter().enumerate().take(self.commitment_length()) {
            rhs.push({
                let image_var = self.0.image[i];
                self.0.linear_map.group_elements.get(image_var)? * challenge + g
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
    /// - [`Error::ProofSizeMismatch`] if the commitment or response length is incorrect.
    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8> {
        let mut bytes = Vec::new();
        for commit in commitment {
            bytes.extend_from_slice(&serialize_element(commit));
        }
        bytes
    }

    fn serialize_challenge(&self, challenge: &Self::Challenge) -> Vec<u8> {
        serialize_scalar::<G>(challenge)
    }

    fn serialize_response(&self, response: &Self::Response) -> Vec<u8> {
        let mut bytes = Vec::new();
        for resp in response {
            bytes.extend_from_slice(&serialize_scalar::<G>(resp));
        }
        bytes
    }

    /// Deserializes a batchable proof into a commitment vector and response vector.
    ///
    /// # Parameters
    /// - `data`: A byte slice containing the serialized proof.
    ///
    /// # Returns
    /// - A tuple `(commitment, response)` where
    ///   * `commitment` is a vector of group elements, and
    ///   * `response` is a vector of scalars.
    ///
    /// # Errors
    /// - [`Error::ProofSizeMismatch`] if the input length is not the exact number of bytes
    ///   expected for `commit_nb` commitments plus `response_nb` responses.
    /// - [`Error::VerificationFailure`] if any group element or scalar fails to
    ///   deserialize (invalid encoding).
    fn deserialize_commitment(&self, data: &[u8]) -> Result<Self::Commitment, Error> {
        let commit_nb = self.commitment_length();
        let commit_size = G::generator().to_bytes().as_ref().len();
        let expected_len = commit_nb * commit_size;

        if data.len() < expected_len {
            return Err(Error::ProofSizeMismatch);
        }

        let mut commitments: Self::Commitment = Vec::new();
        for i in 0..commit_nb {
            let start = i * commit_size;
            let end = start + commit_size;
            let slice = &data[start..end];
            let elem = deserialize_element(slice).ok_or(Error::VerificationFailure)?;
            commitments.push(elem);
        }

        Ok(commitments)
    }

    fn deserialize_challenge(&self, data: &[u8]) -> Result<Self::Challenge, Error> {
        let scalar_size = scalar_byte_size::<G::Scalar>();
        if data.len() < scalar_size {
            return Err(Error::ProofSizeMismatch);
        }
        let challenge = deserialize_scalar::<G>(&data[..scalar_size]).ok_or(Error::VerificationFailure)?;
        Ok(challenge)
    }

    fn deserialize_response(&self, data: &[u8]) -> Result<Self::Response, Error> {
        let response_nb = self.witness_length();
        let response_size = scalar_byte_size::<G::Scalar>();
        let expected_len = response_nb * response_size;

        if data.len() < expected_len {
            return Err(Error::ProofSizeMismatch);
        }

        let mut responses: Self::Response = Vec::new();
        for i in 0..response_nb {
            let start = i * response_size;
            let end = start + response_size;
            let slice = &data[start..end];
            let scalar = deserialize_scalar::<G>(slice).ok_or(Error::VerificationFailure)?;
            responses.push(scalar);
        }

        Ok(responses)
    }

    /// Recomputes the commitment from the challenge and response (used in compact proofs).
    ///
    /// # Parameters
    /// - `challenge`: The challenge scalar issued by the verifier or derived via Fiat–Shamir.
    /// - `response`: The prover's response vector.
    ///
    /// # Returns
    /// - A vector of group elements representing the simulated commitment (one per linear constraint).
    ///
    /// # Errors
    /// - [`Error::ProofSizeMismatch`] if the response length does not match the expected number of scalars.
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, Error> {
        if response.len() != self.witness_length() {
            return Err(Error::ProofSizeMismatch);
        }

        let response_image = self.0.linear_map.evaluate(response)?;
        let image = self.0.image()?;

        let mut commitment = Vec::new();
        for i in 0..image.len() {
            commitment.push(response_image[i] - image[i] * challenge);
        }
        Ok(commitment)
    }
}

impl<G> SigmaProtocolSimulator for SchnorrProof<G>
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
        let response: Vec<G::Scalar> = (0..self.witness_length())
            .map(|_| G::Scalar::random(&mut rng))
            .collect();

        // Use simulate_commitment to compute the commitment
        let commitment = self.simulate_commitment(challenge, &response).unwrap();

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
