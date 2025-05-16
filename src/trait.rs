//! Sigma Protocol Trait
//!
//! This module defines the `SigmaProtocol` trait, a generic interface for 3-message Sigma protocols.

use crate::ProofError;
use rand::{CryptoRng, Rng};

/// A trait defining the behavior of a generic Sigma protocol.
///
/// A Sigma protocol is a 3-message proof protocol where a prover can convince
/// a verifier of knowledge of a witness for a given public statement
/// without revealing the witness.
///
/// ## Associated Types
/// - `Commitment`: The prover's initial commitment.
/// - `ProverState`: The prover's internal state needed to compute a response.
/// - `Response`: The prover's response to a verifier's challenge.
/// - `Witness`: The prover's secret knowledge.
/// - `Challenge`: The verifier's challenge value.
///
/// ## Minimal Implementation
/// Types implementing `SigmaProtocol` must define:
/// - `prover_commit`
/// - `prover_response`
/// - `verifier`
pub trait SigmaProtocol {
    type Commitment;
    type ProverState;
    type Response;
    type Witness;
    type Challenge;

    /// Generates a prover commitment given a witness and randomness.
    ///
    /// Returns a tuple containing:
    /// - The public commitment sent to the verifier.
    /// - The internal prover state needed for the response.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState);

    /// Computes the prover's response to a challenge based on the prover state.
    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Self::Response;

    /// Verifies a Sigma protocol transcript.
    ///
    /// Returns:
    /// - `Ok(())` if the verification succeeds.
    /// - `Err(())` if the verification fails.
    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ProofError>;

    /// Serializes a proof transcript (commitment, challenge, response) to bytes for batching.
    ///
    /// # Panics
    /// Panics if serialization is not supported for this protocol.
    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Vec<u8>;

    /// Deserializes a proof transcript from bytes.
    ///
    /// Returns `Some((commitment, response))` if parsing is successful, otherwise `None`.
    ///
    /// # Panics
    /// Panics if deserialization is not supported for this protocol.
    fn deserialize_batchable(&self, _data: &[u8]) -> Option<(Self::Commitment, Self::Response)>;
}

pub trait CompactProtocol: SigmaProtocol {
    fn get_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response
    ) -> Self::Commitment;

    fn serialize_compact(
        &self,
        _commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        _response: &Self::Response,
    ) -> Vec<u8> {
        panic!("serialize_compact not implemented for this protocol")
    }

    fn deserialize_compact(
        &self,
        _data: &[u8]
    ) -> Option<(Self::Challenge, Self::Response)> {
        panic!("deserialize_compact not implemented for this protocol")
    }
}

/// A trait defining the behavior of a Sigma protocol for which simulation of transcripts is necessary.
///
/// All Sigma protocols can technically simulate a valid transcript, but this mostly serve to prove the security of the protocol and is not used in the real protocol execution.
/// However, some protocols (like OR protocols that prove the truth of one-out-of-two statements) require them during for the real execution.
///
/// ## Minimal Implementation
/// Types implementing `SigmaProtocolSimulator` must define:
/// - `simulate_proof`
/// - `simulate_transcription`
pub trait SigmaProtocolSimulator: SigmaProtocol {
    /// Simulates a protocol transcript given a challenge.
    ///
    /// This serves to create zero-knowledge simulations without access to a witness.
    ///
    /// # Panics
    /// Panics if simulation is not implemented for this protocol.
    fn simulate_proof(
        &self,
        _challenge: &Self::Challenge,
        _rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::Response);

    /// Simulates an entire protocol transcript including a random challenge.
    ///
    /// # Panics
    /// Panics if simulation is not implemented for this protocol.
    fn simulate_transcription(
        &self,
        _rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::Challenge, Self::Response);
}