//! Generic interface for 3-message Sigma protocols.
//!
//! This module defines the [`SigmaProtocol`] and [`SigmaProtocolSimulator`] traits,
//! used to describe interactive zero-knowledge proofs of knowledge,
//! such as Schnorr proofs, that follow the 3-message Sigma protocol structure.

use crate::errors::Result;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use rand::{CryptoRng, Rng};
#[cfg(not(feature = "std"))]
use rand_core::{CryptoRng, RngCore as Rng};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

pub type Transcript<P> = (
    Vec<<P as SigmaProtocol>::Commitment>,
    <P as SigmaProtocol>::Challenge,
    Vec<<P as SigmaProtocol>::Response>,
);

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
    type Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize;
    type Challenge: Decoding<[u8]>;
    type Response: Encoding<[u8]> + NargSerialize + NargDeserialize;
    type ProverState;
    type Witness;

    /// First step of the protocol. Given the witness and RNG, this generates:
    /// - A public commitment to send to the verifier.
    /// - The internal state to use when computing the response.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<(Vec<Self::Commitment>, Self::ProverState)>;

    /// Computes the prover's response to a challenge based on the prover state.
    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Vec<Self::Response>>;

    /// Final step of the protocol: checks that the commitment, challenge, and response form a valid transcript.
    ///
    /// Returns:
    /// - `Ok(())` if the transcript is valid.
    /// - `Err(())` otherwise.
    fn verifier(
        &self,
        commitment: &[Self::Commitment],
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<()>;

    fn commitment_len(&self) -> usize;

    fn response_len(&self) -> usize;

    fn protocol_identifier(&self) -> [u8; 64];

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
pub trait SigmaProtocolSimulator: SigmaProtocol {
    /// Generates a random response (e.g. for simulation or OR composition).
    ///
    /// Typically used to simulate a proof without a witness.
    fn simulate_response<R: Rng + CryptoRng>(&self, rng: &mut R) -> Vec<Self::Response>;

    /// Simulates a commitment for which ('commitment', 'challenge', 'response') is a valid transcript.
    ///
    /// This function allows to omit commitment in compact proofs of the type ('challenge', 'response').
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<Vec<Self::Commitment>>;

    /// Generates a full simulated proof transcript (commitment, challenge, response)
    /// without requiring knowledge of a witness.
    fn simulate_transcript<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<Transcript<Self>>;
}
