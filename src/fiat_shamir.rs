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

use crate::errors::Error;
use crate::traits::SigmaProtocol;
use crate::traits::SigmaProtocolSimulator;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use rand::{CryptoRng, RngCore};
#[cfg(not(feature = "std"))]
use rand_core::{CryptoRng, RngCore};
use spongefish::{ProverState, VerifierState};

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
pub struct Nizk<P>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
{
    pub session_id: Vec<u8>,
    /// Underlying interactive proof.
    pub interactive_proof: P,
}

impl<P> Nizk<P>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
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
        Self {
            session_id: session_identifier.to_vec(),
            interactive_proof,
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
        let mut prover_state = ProverState::new_std(
            self.interactive_proof.protocol_identifier(),
            &self.session_id,
        );

        let (commitment, ip_state) = self.interactive_proof.prover_commit(witness, rng)?;
        prover_state.prover_messages(&commitment);
        let challenge = prover_state.verifier_message::<P::Challenge>();
        let response = self
            .interactive_proof
            .prover_response(ip_state, &challenge)?;
        prover_state.prover_messages(&response);
        Ok(prover_state.narg_string().to_vec())
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
    pub fn verify_batchable(&self, narg_string: &[u8]) -> Result<(), Error> {
        let mut verifier_state = VerifierState::new_std(
            self.interactive_proof.protocol_identifier(),
            &self.session_id,
            narg_string,
        );
        // xxx
        let commitment_len = self.interactive_proof.commitment_len();
        let response_len = self.interactive_proof.response_len();
        let commitment = verifier_state.prover_messages_vec(commitment_len)?;
        let challenge = verifier_state.verifier_message::<P::Challenge>();
        let response = verifier_state.prover_messages_vec(response_len)?;
        self.interactive_proof
            .verifier(&commitment, &challenge, &response)
    }
}

impl<P> Nizk<P>
where
    P: SigmaProtocol + SigmaProtocolSimulator,
    P::Challenge: PartialEq,
{
    // /// Generates a compact serialized proof.
    // ///
    // /// Uses a more space-efficient representation compared to batchable proofs.
    // ///
    // /// # Parameters
    // /// - `witness`: The secret witness.
    // /// - `rng`: A cryptographically secure random number generator.
    // ///
    // /// # Returns
    // /// A compact, serialized proof.
    // ///
    // /// # Panics
    // /// Panics if serialization fails.
    // pub fn prove_compact(
    //     &self,
    //     witness: &P::Witness,
    //     rng: &mut (impl RngCore + CryptoRng),
    // ) -> Result<Vec<u8>, Error> {
    //     let (_commitment, challenge, response) = self.prove(witness, rng)?;
    //     let mut bytes = Vec::new();
    //     bytes.extend_from_slice(&self.interactive_proof.serialize_challenge(&challenge));
    //     bytes.extend_from_slice(&self.interactive_proof.serialize_response(&response));
    //     Ok(bytes)
    // }

    // /// Verifies a compact proof.
    // ///
    // /// Recomputes the commitment from the challenge and response, then verifies it.
    // ///
    // /// # Parameters
    // /// - `proof`: A compact serialized proof.
    // ///
    // /// # Returns
    // /// - `Ok(())` if the proof is valid.
    // /// - `Err(Error)` if deserialization or verification fails.
    // ///
    // /// # Errors
    // /// - Returns [`Error::VerificationFailure`] if:
    // ///   - Deserialization fails.
    // ///   - The recomputed commitment or response is invalid under the Sigma protocol.
    // pub fn verify_compact(&self, proof: &[u8]) -> Result<(), Error> {
    //     // Deserialize challenge and response from compact proof
    //     let challenge = self.interactive_proof.deserialize_challenge(proof)?;
    //     let challenge_size = self.interactive_proof.serialize_challenge(&challenge).len();
    //     let response = self
    //         .interactive_proof
    //         .deserialize_response(&proof[challenge_size..])?;
    //     let response_size = self.interactive_proof.serialize_response(&response).len();

    //     // Proof size check
    //     if proof.len() != challenge_size + response_size {
    //         return Err(Error::VerificationFailure);
    //     }

    //     // Assert correct proof size
    //     let total_expected_len =
    //         challenge_size + self.interactive_proof.serialize_response(&response).len();
    //     if proof.len() != total_expected_len {
    //         return Err(Error::VerificationFailure);
    //     }

    //     // Compute the commitments
    //     let commitment = self
    //         .interactive_proof
    //         .simulate_commitment(&challenge, &response)?;
    //     // Verify the proof
    //     self.verify(&commitment, &challenge, &response)
    // }
}
