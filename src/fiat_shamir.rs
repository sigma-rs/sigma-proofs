//! Fiat-Shamir transformation for Sigma protocols.
//!
//! This module defines [`NISigmaProtocol`], a generic non-interactive Sigma protocol wrapper,
//! based on applying the Fiat-Shamir heuristic using a codec.
//!
//! It transforms an interactive Sigma protocol into a non-interactive one,
//! by deriving challenges deterministically from previous protocol messages
//! via a cryptographic sponge function (Codec).
//!
//! # Usage
//! This struct is generic over:
//! - `P`: the underlying Sigma protocol ([`SigmaProtocol`] trait).
//! - `C`: the codec ([`Codec`] trait).
//! - `G`: the group used for commitments and operations ([`Group`] trait).

use crate::codec::Codec;
use crate::errors::Error;
use crate::traits::{CompactProtocol, SigmaProtocol};

use group::{Group, GroupEncoding};
use rand::{CryptoRng, RngCore};

type Transcript<P> = (
    <P as SigmaProtocol>::Commitment,
    <P as SigmaProtocol>::Challenge,
    <P as SigmaProtocol>::Response,
);

/// A Fiat-Shamir transformation of a Sigma protocol into a non-interactive proof.
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
/// - `G`: the group on which the protocol operates.
pub struct NISigmaProtocol<P, C, G>
where
    G: Group + GroupEncoding,
    P: SigmaProtocol<Commitment = Vec<G>, Challenge = <G as Group>::Scalar>,
    C: Codec<Challenge = <G as Group>::Scalar>,
{
    /// Current codec state.
    pub hash_state: C,
    /// Underlying Sigma protocol.
    pub sigmap: P,
}

// QUESTION: Is the morphism supposed to be written to the transcript? I don't see that here.
impl<P, C, G> NISigmaProtocol<P, C, G>
where
    G: Group + GroupEncoding,
    P: SigmaProtocol<Commitment = Vec<G>, Challenge = <G as Group>::Scalar>,
    C: Codec<Challenge = <G as Group>::Scalar> + Clone,
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
    /// A tuple of:
    /// - `P::Commitment`: The prover's commitment(s).
    /// - `P::Challenge`: The challenge derived via Fiat-Shamir.
    /// - `P::Response`: The prover's response.
    ///
    /// # Panics
    /// Panics if local verification fails.
    pub fn prove(
        &mut self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transcript<P>, Error> {
        // QUESTION: Why is the self mutable? It's unclear whether the intention is to have a
        // single NISigmaProtocol be used multiple times, or not. E.g. is the intention that
        // someone might call `proto.verify(commit1, chal1, res1); proto.verify(commit2, chal2, res2)`
        // both operations to contribute to the same transcript? If so, then why is the hash_state
        // cloned here? And if not, why make the receiver mutable? Another option is to have the
        // receiver take ownership of self, if the intention is to _enforce_ non-reuse.
        let mut codec = self.hash_state.clone();

        let (commitment, prover_state) = self.sigmap.prover_commit(witness, rng)?;
        // Commitment data for challenge generation
        let mut data = Vec::new();
        for commit in &commitment {
            data.extend_from_slice(commit.to_bytes().as_ref());
        }
        // Fiat Shamir challenge
        let challenge = codec.prover_message(&data).verifier_challenge();
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
    /// - `Err(ProofError::VerificationFailure)` if the challenge is invalid or the response fails to verify.
    ///
    /// # Errors
    /// - Returns `ProofError::VerificationFailure` if:
    ///   - The challenge doesn't match the recomputed one from the commitment.
    ///   - The response fails verification under the Sigma protocol.
    pub fn verify(
        &mut self,
        commitment: &P::Commitment,
        challenge: &P::Challenge,
        response: &P::Response,
    ) -> Result<(), Error> {
        let mut codec = self.hash_state.clone();

        // Commitment data for expected challenge generation
        let mut data = Vec::new();
        for commit in commitment {
            data.extend_from_slice(commit.to_bytes().as_ref());
        }
        // Recompute the challenge
        let expected_challenge = codec.prover_message(&data).verifier_challenge();
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
        &mut self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, Error> {
        // NOTE: Returning the commitments as part of a serialized proof might be a barrier in that
        // the commitment is often provided by the verifier, linked to some external message. E.g.
        // it might be a commitment that to a prior state (e.g. balance of a wallet prior to a
        // transaction) for which the prover is showing knowledge of an opening, or it might be
        // calculated as a linear function of other commitments (e.g. subtracting the current
        // timestamp from an issuance timestamp to compute a commitment to the age of a
        // credential).
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
    /// - `Err(ProofError)` if deserialization or verification fails.
    ///
    /// # Errors
    /// - Returns `ProofError::VerificationFailure` if:
    ///   - The challenge doesn't match the recomputed one from the commitment.
    ///   - The response fails verification under the Sigma protocol.
    pub fn verify_batchable(&mut self, proof: &[u8]) -> Result<(), Error> {
        let (commitment, response) = self.sigmap.deserialize_batchable(proof).unwrap();

        let mut codec = self.hash_state.clone();

        // Commitment data for expected challenge generation
        let mut data = Vec::new();
        for commit in &commitment {
            data.extend_from_slice(commit.to_bytes().as_ref());
        }
        // Recompute the challenge
        let challenge = codec.prover_message(&data).verifier_challenge();
        // Verification of the proof
        self.sigmap.verifier(&commitment, &challenge, &response)
    }
}

impl<P, C, G> NISigmaProtocol<P, C, G>
where
    G: Group + GroupEncoding,
    P: SigmaProtocol<Commitment = Vec<G>, Challenge = <G as Group>::Scalar> + CompactProtocol,
    C: Codec<Challenge = <G as Group>::Scalar> + Clone,
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
        &mut self,
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
    /// - `Err(ProofError)` if deserialization or verification fails.
    ///
    /// # Errors
    /// - Returns `ProofError::VerificationFailure` if:
    ///   - Deserialization fails.
    ///   - The recomputed commitment or response is invalid under the Sigma protocol.
    pub fn verify_compact(&mut self, proof: &[u8]) -> Result<(), Error> {
        let (challenge, response) = self.sigmap.deserialize_compact(proof).unwrap();
        // Compute the commitments
        let commitment = self.sigmap.get_commitment(&challenge, &response)?;
        // Verify the proof
        self.verify(&commitment, &challenge, &response)
    }
}
