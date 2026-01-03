//! SHAKE-based duplex sponge implementation
//!
//! This module implements a duplex sponge construction using SHAKE128.

use crate::duplex_sponge::DuplexSpongeInterface;
use alloc::vec;
use alloc::vec::Vec;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update};

/// Duplex sponge construction using SHAKE128.
#[derive(Clone, Debug)]
pub struct ShakeDuplexSponge(Shake128);

impl DuplexSpongeInterface for ShakeDuplexSponge {
    fn new(iv: [u8; 64]) -> Self {
        let mut hasher = Shake128::default();
        let initial_block = [iv.to_vec(), vec![0u8; 168 - 64]].concat();
        hasher.update(&initial_block);
        Self(hasher)
    }

    fn absorb(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    fn squeeze(&mut self, length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        self.0.clone().finalize_xof_into(&mut output);
        output
    }
}
