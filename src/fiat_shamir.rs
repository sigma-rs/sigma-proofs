//! Fiat-Shamir transformation for [`SigmaProtocol`]s.
//!
//! This module defines [`NISigmaProtocol`], a generic non-interactive Sigma protocol wrapper,
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

use crate::codec::Codec;
use crate::errors::Error;
use crate::traits::{CompactProtocol, SigmaProtocol};

use rand::{CryptoRng, RngCore};

/// A trait that allows sigma protocols to have a Fiat-Shamir transform to have a
/// deterministic challenge generation function.
///
/// Challenge generation occurs in two stages:
/// - `absorb_statement_and_commitment`: absorbs commitments to feed the codec.
/// - `get_challenge`: extracts the challenge from the codec.
///
/// # Type Parameters
/// - `C`: the codec used for encoding/decoding messages to/from the IP space.
pub trait FiatShamir<C: Codec>: SigmaProtocol {
    fn push_commitment(&self, codec: &mut C, commitment: &Self::Commitment);

    fn get_challenge(&self, codec: &mut C) -> Result<Self::Challenge, Error>;
}

type Transcript<P> = (
    <P as SigmaProtocol>::Commitment,
    <P as SigmaProtocol>::Challenge,
    <P as SigmaProtocol>::Response,
);

/// A Fiat-Shamir transformation of a [`SigmaProtocol`] into a non-interactive proof.
///
/// [`NISigmaProtocol`] wraps an interactive Sigma protocol `P`
/// and a hash-based codec `C`, to produce non-interactive proofs.
///
/// It manages the domain separation, codec reset,
/// proof generation, and proof verification.
///
/// # Type Parameters
/// - `P`: the Sigma protocol implementation.
/// - `C`: the codec used for Fiat-Shamir.
#[derive(Debug)]
pub struct NISigmaProtocol<P, C>
where
    P: SigmaProtocol<Challenge: PartialEq> + FiatShamir<C>,
    C: Codec<Challenge = P::Challenge>,
{
    /// Current codec state.
    pub hash_state: C,
    /// Underlying Sigma protocol.
    pub sigmap: P,
}

impl<P, C> NISigmaProtocol<P, C>
where
    P: SigmaProtocol<Challenge: PartialEq> + FiatShamir<C>,
    C: Codec<Challenge = P::Challenge> + Clone,
{
    /// Constructs a new [`NISigmaProtocol`] instance.
    ///
    /// # Parameters
    /// - `iv`: Domain separation tag for the hash function (e.g., protocol name or context).
    /// - `instance`: An instance of the interactive Sigma protocol.
    ///
    /// # Returns
    /// A new [`NISigmaProtocol`] that can generate and verify non-interactive proofs.
    pub fn new(iv: &[u8], instance: P) -> Self {
        let hash_state = C::new(iv);
        Self {
            hash_state,
            sigmap: instance,
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
    pub fn prove(
        &self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transcript<P>, Error> {
        let mut codec = self.hash_state.clone();

        let (commitment, prover_state) = self.sigmap.prover_commit(witness, rng)?;
        // Fiat Shamir challenge
        self.sigmap.push_commitment(&mut codec, &commitment);
        let challenge = self.sigmap.get_challenge(&mut codec)?;
        // Prover's response
        let response = self.sigmap.prover_response(prover_state, &challenge)?;
        // Local verification of the proof
        self.sigmap.verifier(&commitment, &challenge, &response)?;
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
    pub fn verify(
        &self,
        commitment: &P::Commitment,
        challenge: &P::Challenge,
        response: &P::Response,
    ) -> Result<(), Error> {
        let mut codec = self.hash_state.clone();

        // Recompute the challenge
        self.sigmap
            .push_commitment(&mut codec, commitment);
        let expected_challenge = self.sigmap.get_challenge(&mut codec)?;
        // Verification of the proof
        match *challenge == expected_challenge {
            true => self.sigmap.verifier(commitment, challenge, response),
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
        let (commitment, challenge, response) = self.prove(witness, rng)?;
        Ok(self
            .sigmap
            .serialize_batchable(&commitment, &challenge, &response)
            .unwrap())
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
        let ((commitment, response), _) = self.sigmap.deserialize_batchable(proof).unwrap();

        let mut codec = self.hash_state.clone();

        // Recompute the challenge
        self.sigmap
            .push_commitment(&mut codec, &commitment);
        let challenge = self.sigmap.get_challenge(&mut codec)?;
        // Verification of the proof
        self.sigmap.verifier(&commitment, &challenge, &response)
    }
}

impl<P, C> NISigmaProtocol<P, C>
where
    P: SigmaProtocol<Challenge: PartialEq> + CompactProtocol + FiatShamir<C>,
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
        let (commitment, challenge, response) = self.prove(witness, rng)?;
        Ok(self
            .sigmap
            .serialize_compact(&commitment, &challenge, &response)
            .unwrap())
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
        let (challenge, response) = self.sigmap.deserialize_compact(proof).unwrap();
        // Compute the commitments
        let commitment = self.sigmap.get_commitment(&challenge, &response)?;
        // Verify the proof
        self.verify(&commitment, &challenge, &response)
    }
}
