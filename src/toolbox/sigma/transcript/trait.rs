//! TranscriptCodec Trait
//!
//! This module defines the `TranscriptCodec` trait, a generic interface to manage transcripts of a protocol execution.

use group::Group;

pub trait DuplexSpongeInterface {
    fn new(iv: &[u8]) -> Self;

    fn absorb(&mut self, input: &[u8]);

    fn squeeze(&mut self, length: usize) -> Vec<u8>;
}
/// A trait defining the behavior of a domain-separated transcript hashing, which is typically used for Sigma Protocols.
///
/// A domain-separated hashing transcript is a transcript, identified by a domain, which is incremented with successive messages ("absorb"). The transcript can then output a bit stream of any length, which is typically used to generate a challenge unique to the given transcript ("squeeze"). (See Sponge Construction).
///
/// The output is deterministic for a given set of input. Thus, both Prover and Verifier can generate the transcript on their sides and ensure the same inputs have been used in both side of the protocol.
///
/// ## Minimal Implementation
/// Types implementing `TranscriptCodec` must define:
/// - `new`
/// - `prover_message`
/// - `verifier_challenge`
pub trait TranscriptCodec<G: Group> {
    /// Generates an empty transcript that can be identified by a domain separator.
    fn new(domain_sep: &[u8]) -> Self;

    /// Absorbs a list of group elements (e.g., commitments) into the transcript.
    fn prover_message(&mut self, elems: &[G]) -> &mut Self
    where
        Self: Sized;

    /// Produces a scalar that can be used as a challenge from the transcript.
    fn verifier_challenge(&mut self) -> G::Scalar;
}
