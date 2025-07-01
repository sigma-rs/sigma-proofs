//! Generic interface for 3-message Sigma protocols.
//!
//! This module defines the [`SigmaProtocol`] and [`SigmaProtocolSimulator`] traits,
//! used to describe interactive zero-knowledge proofs of knowledge,
//! such as Schnorr proofs, that follow the 3-message Sigma protocol structure.

use crate::errors::Error;
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
///  ## Minimal Implementation
/// Types implementing [`SigmaProtocol`] must define:
/// - `prover_commit` — Generates a commitment and internal state.
/// - `prover_response` — Computes a response to a challenge.
/// - `verifier` — Verifies a full transcript `(commitment, challenge, response)`.
///
/// ## Serialization
/// Implementors must also provide methods for serialization and deserialization
/// of each component of the proof.
/// Required methods:
/// - `serialize_commitment` / `deserialize_commitment`
/// - `serialize_challenge` / `deserialize_challenge`
/// - `serialize_response` / `deserialize_response`
///
/// These functions should encode/decode each component into/from a compact binary format.
///
/// ## Identification
/// To allow transcript hash binding and protocol distinction,
/// implementors must provide:
/// - `protocol_identifier` — A fixed byte identifier of the protocol.
/// - `instance_label` — A label specific to the instance being proven.
pub trait SigmaProtocol {
    type Commitment;
    type ProverState;
    type Response;
    type Witness;
    type Challenge;

    /// First step of the protocol. Given the witness and RNG, this generates:
    /// - A public commitment to send to the verifier.
    /// - The internal state to use when computing the response.
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

    /// Final step of the protocol: checks that the commitment, challenge, and response form a valid transcript.
    ///
    /// Returns:
    /// - `Ok(())` if the transcript is valid.
    /// - `Err(())` otherwise.
    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), Error>;

    /// Serializes a commitment to bytes.
    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8>;

    /// Serializes a challenge to bytes.
    fn serialize_challenge(&self, challenge: &Self::Challenge) -> Vec<u8>;

    /// Serializes a response to bytes.
    fn serialize_response(&self, response: &Self::Response) -> Vec<u8>;

    /// Deserializes a commitment from bytes.
    fn deserialize_commitment(&self, data: &[u8]) -> Result<Self::Commitment, Error>;

    /// Deserializes a challenge from bytes.
    fn deserialize_challenge(&self, data: &[u8]) -> Result<Self::Challenge, Error>;

    /// Deserializes a response from bytes.
    fn deserialize_response(&self, data: &[u8]) -> Result<Self::Response, Error>;

    fn protocol_identifier(&self) -> impl AsRef<[u8]>;

    fn instance_label(&self) -> impl AsRef<[u8]>;
}

/// A trait defining the behavior of a Sigma protocol for which simulation of transcripts is necessary.
///
/// Every Sigma protocol can be simulated, but in practice, this is primarily used
/// for proving security properties (zero-knowledge, soundness, etc.).
///
/// Some protocols (e.g. OR compositions) require simulation capabilities during actual proof generation.
///
/// ## Minimal Implementation
/// Types implementing [`SigmaProtocolSimulator`] must define:
/// - `simulate_proof`
/// - `simulate_transcript`
#[allow(clippy::type_complexity)]
pub trait SigmaProtocolSimulator: SigmaProtocol {
    /// Generates a random response (e.g. for simulation or OR composition).
    ///
    /// Typically used to simulate a proof without a witness.
    fn simulate_response<R: Rng + CryptoRng>(&self, rng: &mut R) -> Self::Response;

    /// Simulates a commitment for which ('commitment', 'challenge', 'response') is a valid transcript.
    ///
    /// This function allows to omit commitment in compact proofs of the type ('challenge', 'response').
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, Error>;

    /// Generates a full simulated proof transcript (commitment, challenge, response)
    /// without requiring knowledge of a witness.
    fn simulate_transcript<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Commitment, Self::Challenge, Self::Response), Error>;
}
