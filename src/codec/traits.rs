//! Codec Trait
//!
//! This module defines the [`Codec`] trait, a generic interface to manage codecs of a protocol execution.

pub trait DuplexSpongeInterface {
    fn new(iv: &[u8]) -> Self;

    fn absorb(&mut self, input: &[u8]);

    fn squeeze(&mut self, length: usize) -> Vec<u8>;
}

/// A trait defining the behavior of a domain-separated codec hashing, which is typically used for Sigma Protocols.
///
/// A domain-separated hashing codec is a codec, identified by a domain, which is incremented with successive messages ("absorb"). The codec can then output a bit stream of any length, which is typically used to generate a challenge unique to the given codec ("squeeze"). (See Sponge Construction).
///
/// The output is deterministic for a given set of input. Thus, both Prover and Verifier can generate the codec on their sides and ensure the same inputs have been used in both side of the protocol.
///
/// ## Minimal Implementation
/// Types implementing [`Codec`] must define:
/// - `new`
/// - `prover_message`
/// - `verifier_challenge`
pub trait Codec {
    type Challenge;

    /// Generates an empty codec that can be identified by a domain separator.
    fn new(domain_sep: &[u8]) -> Self;

    /// Absorbs data into the codec.
    fn prover_message(&mut self, data: &[u8]) -> &mut Self
    where
        Self: Sized;

    /// Produces a scalar that can be used as a challenge from the codec.
    fn verifier_challenge(&mut self) -> Self::Challenge;
}
