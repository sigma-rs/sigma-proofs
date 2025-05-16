//! Fiat-Shamir transformation for Sigma protocols.
//!
//! This module defines `NISigmaProtocol`, a generic non-interactive Sigma protocol wrapper,
//! based on applying the Fiat-Shamir heuristic using a codec.
//!
//! It transforms an interactive Sigma protocol into a non-interactive one,
//! by deriving challenges deterministically from previous protocol messages
//! via a cryptographic sponge function (Codec).
//!
//! # Usage
//! This struct is generic over:
//! - `P`: the underlying Sigma protocol (`SigmaProtocol` trait).
//! - `C`: the codec (`Codec` trait).
//! - `G`: the group used for commitments and operations (`Group` trait).

use crate::{
    codec::Codec, CompactProtocol, ProofError, SigmaProtocol
};

use group::{Group, GroupEncoding};
use rand::{CryptoRng, RngCore};

/// A Fiat-Shamir transformation of a Sigma protocol into a non-interactive proof.
///
/// `NISigmaProtocol` wraps an interactive Sigma protocol `P`
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
    /// Domain separation string for the Fiat-Shamir transform.
    pub domain_sep: Vec<u8>,
    /// Current codec state.
    pub hash_state: C,
    /// Underlying Sigma protocol.
    pub sigmap: P,
}

impl<P, C, G> NISigmaProtocol<P, C, G>
where
    G: Group + GroupEncoding,
    P: SigmaProtocol<Commitment = Vec<G>, Challenge = <G as Group>::Scalar>,
    C: Codec<Challenge = <G as Group>::Scalar> + Clone,
{
    /// Creates a new non-interactive Sigma protocol, identified by a domain separator (usually fixed per protocol instantiation), and an initialized Sigma protocol instance.
    pub fn new(iv: &[u8], instance: P) -> Self {
        let domain_sep = iv.to_vec();
        let hash_state = C::new(iv);
        Self {
            domain_sep,
            hash_state,
            sigmap: instance,
        }
    }

    /// Produces a non-interactive proof for a witness.
    pub fn prove(
        &mut self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng)
    ) -> (P::Commitment, P::Challenge, P::Response) {
        let mut codec = self.hash_state.clone();

        let (commitment, prover_state) = self.sigmap.prover_commit(witness, rng);
        // Commitment data for challenge generation
        let mut data = Vec::new();
        for commit in &commitment {
            data.extend_from_slice(commit.to_bytes().as_ref());
        }
        // Fiat Shamir challenge
        let challenge = codec
            .prover_message(&data)
            .verifier_challenge();
        // Prover's response
        let response = self.sigmap.prover_response(prover_state, &challenge);
        // Local verification of the proof
        assert!(self
            .sigmap
            .verifier(&commitment, &challenge, &response)
            .is_ok());
        (commitment, challenge, response)
    }

    /// Verify a non-interactive proof and returns a Result: `Ok(())` if the proof verifies successfully, `Err(())` otherwise.
    pub fn verify(
        &mut self,
        commitment: &P::Commitment,
        challenge: &P::Challenge,
        response: &P::Response
    ) -> Result<(), ProofError> {
        let mut codec = self.hash_state.clone();

        // Commitment data for expected challenge generation
        let mut data = Vec::new();
        for commit in commitment {
            data.extend_from_slice(commit.to_bytes().as_ref());
        }
        // Recompute the challenge
        let expected_challenge = codec
            .prover_message(&data)
            .verifier_challenge();
        // Verification of the proof
        match *challenge == expected_challenge {
            true => self.sigmap.verifier(commitment, challenge, response),
            false => Err(ProofError::VerificationFailure),
        }
    }

    pub fn prove_batchable(
        &mut self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng)
    ) -> Vec<u8> {
        let (commitment, challenge, response) = self.prove(witness, rng);
        self.sigmap
            .serialize_batchable(&commitment, &challenge, &response)
    }

    pub fn verify_batchable(
        &mut self,
        proof: &[u8]
    ) -> Result<(), ProofError> {
        let (commitment, response) = self.sigmap.deserialize_batchable(proof).unwrap();

        let mut codec = self.hash_state.clone();

        // Commitment data for expected challenge generation
        let mut data = Vec::new();
        for commit in &commitment {
            data.extend_from_slice(commit.to_bytes().as_ref());
        }
        // Recompute the challenge
        let challenge = codec
            .prover_message(&data)
            .verifier_challenge();
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
    pub fn prove_compact(
        &mut self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng)
    ) -> Vec<u8> {
        let (commitment, challenge, response) = self.prove(witness, rng);
        self.sigmap
            .serialize_compact(&commitment, &challenge, &response)
    }

    pub fn verify_compact(
        &mut self,
        proof: &[u8]
    ) -> Result<(), ProofError> {
        let (challenge, response) = self.sigmap.deserialize_compact(proof).unwrap();
        // Compute the commitments
        let commitment = self.sigmap.get_commitment(&challenge, &response);
        // Verify the proof
        self.verify(&commitment, &challenge, &response)
    }
}