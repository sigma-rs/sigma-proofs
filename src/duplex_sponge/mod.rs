//! Duplex Sponge Interface
//!
//! This module defines the [`DuplexSpongeInterface`] trait, which provides
//! a generic interface for cryptographic sponge functions that support
//! duplex operations: alternating absorb and squeeze phases.

pub mod keccak;
pub mod shake;

/// A trait defining the behavior of a duplex sponge construction.
///
/// A duplex sponge allows for:
/// - **Absorbing** input data into the sponge state
/// - **Squeezing** output data from the sponge state
///
/// This is the core primitive used for building cryptographic codecs.
pub trait DuplexSpongeInterface {
    /// Creates a new sponge instance with a given initialization vector (IV).
    ///
    /// The IV enables domain separation and reproducibility between parties.
    fn new(iv: [u8; 32]) -> Self;

    /// Absorbs input data into the sponge state.
    fn absorb(&mut self, input: &[u8]);

    /// Squeezes output data from the sponge state.
    fn squeeze(&mut self, length: usize) -> Vec<u8>;

    /// Applies a state ratcheting mechanism to prevent backtracking attacks.
    fn ratchet(&mut self);
}
