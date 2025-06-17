//! Keccak-based duplex sponge implementation
//!
//! This module implements a duplex sponge construction using the Keccak-f[1600] permutation.
//! It is designed to match test vectors from the original Sage implementation.

use crate::duplex_sponge::DuplexSpongeInterface;
use std::convert::TryInto;
use tiny_keccak::keccakf;

const R: usize = 136;
const N: usize = 136 + 64;

/// Low-level Keccak-f[1600] state representation.
#[derive(Clone)]
pub struct KeccakPermutationState {
    pub state: [u8; 200],
    pub rate: usize,
    pub capacity: usize,
}

impl Default for KeccakPermutationState {
    fn default() -> Self {
        Self::new([0u8; 32])
    }
}

impl KeccakPermutationState {
    pub fn new(iv: [u8; 32]) -> Self {
        let rate = 136;
        let mut state = [0u8; N];
        state[rate..rate + 32].copy_from_slice(&iv);

        KeccakPermutationState {
            state,
            rate,
            capacity: 64,
        }
    }

    fn bytes_to_flat_state(&self) -> [u64; 25] {
        let mut flat = [0u64; 25];
        for (i, item) in flat.iter_mut().enumerate() {
            let start = i * 8;
            *item = u64::from_le_bytes(self.state[start..start + 8].try_into().unwrap());
        }
        flat
    }

    fn flat_state_to_bytes(&mut self, flat: [u64; 25]) {
        for (i, item) in flat.iter().enumerate() {
            let bytes = item.to_le_bytes();
            let start = i * 8;
            self.state[start..start + 8].copy_from_slice(&bytes);
        }
    }

    pub fn permute(&mut self) {
        let mut flat = self.bytes_to_flat_state();
        keccakf(&mut flat);
        self.flat_state_to_bytes(flat);
    }
}

/// Duplex sponge construction using Keccak-f[1600].
#[derive(Clone)]
pub struct KeccakDuplexSponge {
    pub state: KeccakPermutationState,
    pub rate: usize,
    pub capacity: usize,
    absorb_index: usize,
    squeeze_index: usize,
}

impl KeccakDuplexSponge {
    pub fn new(iv: &[u8]) -> Self {
        let hashed_iv = {
            let mut tmp = KeccakDuplexSponge::from_iv(&[0u8; 32]);
            tmp.absorb(iv);
            tmp.squeeze(32)
        };
        KeccakDuplexSponge::from_iv(&hashed_iv)
    }

    pub fn from_iv(iv: &[u8]) -> Self {
        assert_eq!(iv.len(), 32);

        let state = KeccakPermutationState::new(iv.try_into().unwrap());
        let rate = R;
        let capacity = N - R;
        KeccakDuplexSponge {
            state,
            rate,
            capacity,
            absorb_index: 0,
            squeeze_index: rate,
        }
    }
}

impl DuplexSpongeInterface for KeccakDuplexSponge {
    fn new(iv: &[u8]) -> Self {
        KeccakDuplexSponge::new(iv)
    }

    fn absorb(&mut self, mut input: &[u8]) {
        self.squeeze_index = self.rate;

        while !input.is_empty() {
            if self.absorb_index == self.rate {
                self.state.permute();
                self.absorb_index = 0;
            }

            let chunk_size = usize::min(self.rate - self.absorb_index, input.len());
            let dest = &mut self.state.state[self.absorb_index..self.absorb_index + chunk_size];
            dest.copy_from_slice(&input[..chunk_size]);
            self.absorb_index += chunk_size;
            input = &input[chunk_size..];
        }
    }

    fn squeeze(&mut self, mut length: usize) -> Vec<u8> {
        self.absorb_index = self.rate;

        let mut output = Vec::new();
        while length != 0 {
            if self.squeeze_index == self.rate {
                self.state.permute();
                self.squeeze_index = 0;
            }

            let chunk_size = usize::min(self.rate - self.squeeze_index, length);
            output.extend_from_slice(
                &self.state.state[self.squeeze_index..self.squeeze_index + chunk_size],
            );
            self.squeeze_index += chunk_size;
            length -= chunk_size;
        }

        output
    }
}
