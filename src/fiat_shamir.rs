//! Fiat-Shamir transformation for [`SigmaProtocol`]s.
//!
//! This module defines [`Nizk`], a generic non-interactive Sigma protocol wrapper,
//! based on applying the Fiat-Shamir heuristic using a codec.
//!
//! It transforms an interactive [`SigmaProtocol`] into a non-interactive one,
//! by deriving challenges deterministically from previous protocol messages
//! via a cryptographic sponge function (Codec).
//!
//! # Usage
//! This struct is generic over:
//! - `P`: the underlying Sigma protocol ([`SigmaProtocol`] trait).
//! - `C`: the codec ([`Codec`] trait).

use alloc::vec::Vec;
use crate::errors::Error;
use crate::traits::SigmaProtocol;
use crate::{codec::Codec, traits::SigmaProtocolSimulator};

#[cfg(feature = "std")]
use rand::{CryptoRng, RngCore};
#[cfg(not(feature = "std"))]
use rand_core::{CryptoRng, RngCore};

type Transcript<P> = (
    <P as SigmaProtocol>::Commitment,
    <P as SigmaProtocol>::Challenge,
    <P as SigmaProtocol>::Response,
);

/// A Fiat-Shamir transformation of a [`SigmaProtocol`] into a non-interactive proof.
///
/// [`Nizk`] wraps an interactive Sigma protocol `P`
/// and a hash-based codec `C`, to produce non-interactive proofs.
///
/// It manages the domain separation, codec reset,
/// proof generation, and proof verification.
///
/// # Type Parameters
/// - `P`: the Sigma protocol implementation.
/// - `C`: the codec used for Fiat-Shamir.
#[derive(Debug)]
pub struct Nizk<P, C>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    C: Codec<Challenge = P::Challenge>,
{
    /// Current codec state.
    pub hash_state: C,
    /// Underlying interactive proof.
    pub interactive_proof: P,
}

impl<P, C> Nizk<P, C>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    C: Codec<Challenge = P::Challenge> + Clone,
{
    /// Constructs a new [`Nizk`] instance.
    ///
    /// # Parameters
    /// - `iv`: Domain separation tag for the hash function (e.g., protocol name or context).
    /// - `instance`: An instance of the interactive Sigma protocol.
    ///
    /// # Returns
    /// A new [`Nizk`] that can generate and verify non-interactive proofs.
    pub fn new(session_identifier: &[u8], interactive_proof: P) -> Self {
        let hash_state = C::new(
            interactive_proof.protocol_identifier().as_ref(),
            session_identifier,
            interactive_proof.instance_label().as_ref(),
        );
        Self {
            hash_state,
            interactive_proof,
        }
    }

    pub fn from_iv(iv: [u8; 32], interactive_proof: P) -> Self {
        let hash_state = C::from_iv(iv);
        Self {
            hash_state,
            interactive_proof,
        }
    }

    /// Generates a non-interactive proof for a witness.
    ///
    /// Executes the interactive protocol steps (commit, derive challenge via hash, respond),
    /// and checks the result locally for consistency.
    ///
    /// # Parameters
    /// - `witness`: The secret witness for the Sigma protocol.
    /// - `rng`: A cryptographically secure random number generator.
    ///
    /// # Returns
    /// A [`Result`] containing a `Transcript<P>` on success. The `Transcript` includes:
    /// - `P::Commitment`: The prover's commitment(s).
    /// - `P::Challenge`: The challenge derived via Fiat-Shamir.
    /// - `P::Response`: The prover's response.
    ///
    /// # Panics
    /// Panics if local verification fails.
    fn prove(
        &self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transcript<P>, Error> {
        let mut hash_state = self.hash_state.clone();

        let (commitment, prover_state) = self.interactive_proof.prover_commit(witness, rng)?;
        // Fiat Shamir challenge
        let serialized_commitment = self.interactive_proof.serialize_commitment(&commitment);
        hash_state.prover_message(&serialized_commitment);
        let challenge = hash_state.verifier_challenge();
        // Prover's response
        let response = self
            .interactive_proof
            .prover_response(prover_state, &challenge)?;

        Ok((commitment, challenge, response))
    }

    /// Verifies a non-interactive proof using the Fiat-Shamir transformation.
    ///
    /// # Parameters
    /// - `commitment`: The commitment(s) sent by the prover.
    /// - `challenge`: The challenge allegedly derived via Fiat-Shamir.
    /// - `response`: The prover's response to the challenge.
    ///
    /// # Returns
    /// - `Ok(())` if the proof is valid.
    /// - `Err(Error::VerificationFailure)` if the challenge is invalid or the response fails to verify.
    ///
    /// # Errors
    /// - Returns [`Error::VerificationFailure`] if:
    ///   - The challenge doesn't match the recomputed one from the commitment.
    ///   - The response fails verification under the Sigma protocol.
    fn verify(
        &self,
        commitment: &P::Commitment,
        challenge: &P::Challenge,
        response: &P::Response,
    ) -> Result<(), Error> {
        let mut hash_state = self.hash_state.clone();

        // Recompute the challenge
        let serialized_commitment = self.interactive_proof.serialize_commitment(commitment);
        hash_state.prover_message(&serialized_commitment);
        let expected_challenge = hash_state.verifier_challenge();
        // Verification of the proof
        match *challenge == expected_challenge {
            true => self
                .interactive_proof
                .verifier(commitment, challenge, response),
            false => Err(Error::VerificationFailure),
        }
    }
    /// Generates a batchable, serialized non-interactive proof.
    ///
    /// # Parameters
    /// - `witness`: The secret witness.
    /// - `rng`: A cryptographically secure random number generator.
    ///
    /// # Returns
    /// A serialized proof suitable for batch verification.
    ///
    /// # Panics
    /// Panics if serialization fails (should not happen under correct implementation).
    pub fn prove_batchable(
        &self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, Error> {
        let (commitment, _challenge, response) = self.prove(witness, rng)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.interactive_proof.serialize_commitment(&commitment));
        bytes.extend_from_slice(&self.interactive_proof.serialize_response(&response));
        Ok(bytes)
    }

    /// Verifies a batchable non-interactive proof.
    ///
    /// # Parameters
    /// - `proof`: A serialized batchable proof.
    ///
    /// # Returns
    /// - `Ok(())` if the proof is valid.
    /// - `Err(Error)` if deserialization or verification fails.
    ///
    /// # Errors
    /// - Returns [`Error::VerificationFailure`] if:
    ///   - The challenge doesn't match the recomputed one from the commitment.
    ///   - The response fails verification under the Sigma protocol.
    pub fn verify_batchable(&self, proof: &[u8]) -> Result<(), Error> {
        let commitment = self.interactive_proof.deserialize_commitment(proof)?;
        let commitment_size = self
            .interactive_proof
            .serialize_commitment(&commitment)
            .len();
        let response = self
            .interactive_proof
            .deserialize_response(&proof[commitment_size..])?;
        let response_size = self.interactive_proof.serialize_response(&response).len();

        // Proof size check
        if proof.len() != commitment_size + response_size {
            return Err(Error::VerificationFailure);
        }

        // Assert correct proof size
        let total_expected_len =
            commitment_size + self.interactive_proof.serialize_response(&response).len();
        if proof.len() != total_expected_len {
            return Err(Error::VerificationFailure);
        }

        let mut hash_state = self.hash_state.clone();

        // Recompute the challenge
        let serialized_commitment = self.interactive_proof.serialize_commitment(&commitment);
        hash_state.prover_message(&serialized_commitment);
        let challenge = hash_state.verifier_challenge();
        // Verification of the proof
        self.interactive_proof
            .verifier(&commitment, &challenge, &response)
    }
}

impl<P, C> Nizk<P, C>
where
    P: SigmaProtocol + SigmaProtocolSimulator,
    P::Challenge: PartialEq,
    C: Codec<Challenge = P::Challenge> + Clone,
{
    /// Generates a compact serialized proof.
    ///
    /// Uses a more space-efficient representation compared to batchable proofs.
    ///
    /// # Parameters
    /// - `witness`: The secret witness.
    /// - `rng`: A cryptographically secure random number generator.
    ///
    /// # Returns
    /// A compact, serialized proof.
    ///
    /// # Panics
    /// Panics if serialization fails.
    pub fn prove_compact(
        &self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, Error> {
        let (_commitment, challenge, response) = self.prove(witness, rng)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.interactive_proof.serialize_challenge(&challenge));
        bytes.extend_from_slice(&self.interactive_proof.serialize_response(&response));
        Ok(bytes)
    }

    /// Verifies a compact proof.
    ///
    /// Recomputes the commitment from the challenge and response, then verifies it.
    ///
    /// # Parameters
    /// - `proof`: A compact serialized proof.
    ///
    /// # Returns
    /// - `Ok(())` if the proof is valid.
    /// - `Err(Error)` if deserialization or verification fails.
    ///
    /// # Errors
    /// - Returns [`Error::VerificationFailure`] if:
    ///   - Deserialization fails.
    ///   - The recomputed commitment or response is invalid under the Sigma protocol.
    pub fn verify_compact(&self, proof: &[u8]) -> Result<(), Error> {
        // Deserialize challenge and response from compact proof
        let challenge = self.interactive_proof.deserialize_challenge(proof)?;
        let challenge_size = self.interactive_proof.serialize_challenge(&challenge).len();
        let response = self
            .interactive_proof
            .deserialize_response(&proof[challenge_size..])?;
        let response_size = self.interactive_proof.serialize_response(&response).len();

        // Proof size check
        if proof.len() != challenge_size + response_size {
            return Err(Error::VerificationFailure);
        }

        // Assert correct proof size
        let total_expected_len =
            challenge_size + self.interactive_proof.serialize_response(&response).len();
        if proof.len() != total_expected_len {
            return Err(Error::VerificationFailure);
        }

        // Compute the commitments
        let commitment = self
            .interactive_proof
            .simulate_commitment(&challenge, &response)?;
        // Verify the proof
        self.verify(&commitment, &challenge, &response)
    }
}
