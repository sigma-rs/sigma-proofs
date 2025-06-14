//! Duplex Sponge Interface
//!
//! This module defines the [`DuplexSpongeInterface`] trait, which provides
//! a generic interface for cryptographic sponge functions that support
//! duplex operation (absorb and squeeze phases).

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
    /// Creates a new sponge instance with an initialization vector.
    fn new(iv: &[u8]) -> Self;

    /// Absorbs input data into the sponge state.
    fn absorb(&mut self, input: &[u8]);

    /// Squeezes output data from the sponge state.
    fn squeeze(&mut self, length: usize) -> Vec<u8>;
}
