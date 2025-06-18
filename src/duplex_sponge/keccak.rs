//! Keccak-based duplex sponge implementation
//!
//! This module implements a duplex sponge construction using the Keccak-f[1600] permutation.
//! It is designed to match test vectors from the original Sage implementation.

use crate::duplex_sponge::DuplexSpongeInterface;
use zerocopy::IntoBytes;

const RATE: usize = 136;
const LENGTH: usize = 136 + 64;

/// Low-level Keccak-f[1600] state representation.
#[derive(Clone, Default)]
pub struct KeccakPermutationState([u64; LENGTH / 8]);

impl KeccakPermutationState {
    pub fn new(iv: [u8; 32]) -> Self {
        let mut state = Self::default();
        state.as_mut()[RATE..RATE + 32].copy_from_slice(&iv);
        state
    }

    pub fn permute(&mut self) {
        keccak::f1600(&mut self.0);
    }
}

impl AsRef<[u8]> for KeccakPermutationState {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsMut<[u8]> for KeccakPermutationState {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_bytes()
    }
}

/// Duplex sponge construction using Keccak-f[1600].
#[derive(Clone)]
pub struct KeccakDuplexSponge {
    state: KeccakPermutationState,
    absorb_index: usize,
    squeeze_index: usize,
}

impl KeccakDuplexSponge {
    pub fn new(iv: [u8; 32]) -> Self {
        let state = KeccakPermutationState::new(iv);
        KeccakDuplexSponge {
            state,
            absorb_index: 0,
            squeeze_index: RATE,
        }
    }
}

impl DuplexSpongeInterface for KeccakDuplexSponge {
    fn new(iv: [u8; 32]) -> Self {
        KeccakDuplexSponge::new(iv)
    }

    fn absorb(&mut self, mut input: &[u8]) {
        self.squeeze_index = RATE;

        while !input.is_empty() {
            if self.absorb_index == RATE {
                self.state.permute();
                self.absorb_index = 0;
            }

            let chunk_size = usize::min(RATE - self.absorb_index, input.len());
            let dest = &mut self.state.as_mut()[self.absorb_index..self.absorb_index + chunk_size];
            dest.copy_from_slice(&input[..chunk_size]);
            self.absorb_index += chunk_size;
            input = &input[chunk_size..];
        }
    }

    fn squeeze(&mut self, mut length: usize) -> Vec<u8> {
        self.absorb_index = RATE;

        let mut output = Vec::new();
        while length != 0 {
            if self.squeeze_index == RATE {
                self.state.permute();
                self.squeeze_index = 0;
            }

            let chunk_size = usize::min(RATE - self.squeeze_index, length);
            output.extend_from_slice(
                &self.state.as_mut()[self.squeeze_index..self.squeeze_index + chunk_size],
            );
            self.squeeze_index += chunk_size;
            length -= chunk_size;
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duplex_sponge::DuplexSpongeInterface;

    #[test]
    fn test_keccak_duplex_sponge() {
        let mut sponge = KeccakDuplexSponge::new([0u8; 32]);

        let input = b"Hello, World!";
        sponge.absorb(input);
        let output = sponge.squeeze(64);

        assert_eq!(output, hex::decode("30b74a98221dd643d0814095c212d663a67945c6a582ef8f71bd2a14607ebade3f16e5975ad13d313d9aa0aa97ad29f7df5cff249fa633d3a7ac70d8587bec90").unwrap());
    }
}
