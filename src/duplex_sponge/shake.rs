//! SHAKE-based duplex sponge implementation
//!
//! This module implements a duplex sponge construction using SHAKE128.

use crate::duplex_sponge::DuplexSpongeInterface;
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update},
};

/// Duplex sponge construction using SHAKE128.
#[derive(Clone, Debug)]
pub struct ShakeDuplexSponge {
    /// Internal SHAKE128 hasher state.
    hasher: Shake128,
}

impl DuplexSpongeInterface for ShakeDuplexSponge {
    fn new(iv: &[u8]) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(iv);
        Self { hasher }
    }

    fn absorb(&mut self, input: &[u8]) {
        self.hasher.update(input);
    }

    fn squeeze(&mut self, length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        self.hasher.clone().finalize_xof_into(&mut output);
        output
    }
}