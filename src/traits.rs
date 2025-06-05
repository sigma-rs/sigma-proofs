//! Sigma Protocol Trait
//!
//! This module defines the [`SigmaProtocol`] trait, a generic interface for 3-message Sigma protocols.

use crate::errors::Error;
use rand::{CryptoRng, Rng};

type BatchableProofResult<C, R> = Result<((C, R), usize), Error>;
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
/// Types implementing [`SigmaProtocol`] must define:
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
    ) -> Result<(Self::Commitment, Self::ProverState), Error>;

    /// Computes the prover's response to a challenge based on the prover state.
    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, Error>;

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
    ) -> Result<(), Error>;

    /// Serializes a proof transcript (commitment, challenge, response) to bytes batchable proof.
    fn serialize_batchable(
        &self,
        _commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        _response: &Self::Response,
    ) -> Result<Vec<u8>, Error>;

    /// Deserializes a batchable proof from bytes.
    ///
    /// Returns `Ok(((commitment, response), proof_size))` if parsing is successful, otherwise `Err(Error)`.
    fn deserialize_batchable(
        &self,
        _data: &[u8],
    ) -> BatchableProofResult<Self::Commitment, Self::Response>;
}

/// A feature defining the behavior of a protocol for which it is possible to compact the proofs by omitting the commitments.
///
/// This is possible if it is possible to retrieve the commitments from the challenge and responses.
/// This is what the get_commitment function is for.
///
/// ## Minimal Implementation
/// Types implementing [`CompactProtocol`] must define:
/// - `get_commitment`
pub trait CompactProtocol: SigmaProtocol {
    /// Returns the commitment for which ('commitment', 'challenge', 'response') is a valid transcript.
    ///
    /// This function allows to omit commitment in compact proofs of the type ('challenge', 'response').
    fn get_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, Error>;

    /// Serializes a proof response to bytes.
    fn serialize_response(&self, response: &Self::Response) -> Result<Vec<u8>, Error>;

    /// Deserializes a proof response from bytes.
    fn deserialize_response(&self, _data: &[u8]) -> Result<(Self::Response, usize), Error>;

    /// Serializes a proof transcript (commitment, challenge, response) to bytes compact proof.
    fn serialize_compact(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, Error>;

    /// Deserializes a compact proof from bytes.
    ///
    /// Returns `Ok((challenge, response))` if parsing is successful, otherwise `Err(Error)`.
    fn deserialize_compact(&self, _data: &[u8])
    -> Result<(Self::Challenge, Self::Response), Error>;
}

/// A trait defining the behavior of a Sigma protocol for which simulation of transcripts is necessary.
///
/// All Sigma protocols can technically simulate a valid transcript, but this mostly serve to prove the security of the protocol and is not used in the real protocol execution.
/// However, some protocols (like OR protocols that prove the truth of one-out-of-two statements) require them during for the real execution.
///
/// ## Minimal Implementation
/// Types implementing [`SigmaProtocolSimulator`] must define:
/// - `simulate_proof`
/// - `simulate_transcript`
pub trait SigmaProtocolSimulator: SigmaProtocol {
    /// Simulates a protocol transcript given a challenge.
    ///
    /// This serves to create zero-knowledge simulations without access to a witness.
    fn simulate_proof(
        &self,
        challenge: &Self::Challenge,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::Response);

    /// Simulates an entire protocol transcript.
    fn simulate_transcript(
        &self,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::Challenge, Self::Response);
}
