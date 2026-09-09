//! Generic interface for Sigma Protocols.
//!
//! This module defines the [`SigmaProtocol`] and [`SigmaProtocolSimulator`]
//! traits, 3-message interactive proof systems with special soundness and
//! special honest-verifier zero-knowledge.

use crate::errors::{InvalidWitness, VerificationResult};
use spongefish::{DuplexSpongeInit, PrivateRng};

pub type Transcript<P> = (
    <P as SigmaProtocol>::Commitment,
    <P as SigmaProtocol>::Challenge,
    <P as SigmaProtocol>::Response,
);

/// A trait defining the behavior of a generic Sigma protocol.
pub trait SigmaProtocol {
    /// The prover's commitment.
    type Commitment;
    /// The verifier challenge.
    type Challenge;
    /// The prover's response.
    type Response;
    /// The prover's (private) internal state.
    type ProverState;
    /// Taken by reference throughout, so it may be unsized.
    type Witness: ?Sized;

    /// The commitment message of the Sigma Protocol. It generates:
    ///
    /// - A public commitment to send to the verifier.
    /// - The internal state to use when computing the response.
    ///
    /// A non-interactive codec may reject a negligible subset of this
    /// distribution and ask the prover to sample again.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> core::result::Result<(Self::Commitment, Self::ProverState), InvalidWitness>;

    /// The response message of the Sigma Protocol.
    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> core::result::Result<Self::Response, InvalidWitness>;

    /// The verifier of the Sigma Protocol.
    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> VerificationResult<()>;

    /// The verifier with one extra challenge for statistical verification.
    ///
    /// When checking several independent equations, the verifier may collapse
    /// them into a single random linear combination. By default this just runs
    /// the verifier.
    ///
    /// # Safety
    ///
    /// For verification to be secure, the `_randomness` input MUST be drawn uniformly at random by the verifier,
    /// after seeing all the transcript.
    fn verifier_with_randomness(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
        _randomness: &Self::Challenge,
    ) -> VerificationResult<()> {
        self.verifier(commitment, challenge, response)
    }

    fn encode_instance(&self) -> impl AsRef<[u8]>;
}

/// The simulator for the Sigma Protocol.
///
/// An extension trait for a [`SigmaProtocol`] that is used by OR composition
/// and compact proof verification.
pub trait SigmaProtocolSimulator: SigmaProtocol {
    /// Similate a response message.
    fn simulate_response(
        &self,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> Self::Response;

    /// Simulates a commitment message.
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> VerificationResult<Self::Commitment>;

    /// Simulates a full Sigma Protocol transcript.
    fn simulate_transcript(
        &self,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> VerificationResult<Transcript<Self>>;
}
