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
        let mut output = Vec::new();
        while length != 0 {
            if self.squeeze_index == RATE {
                self.state.permute();
                self.squeeze_index = 0;
                self.absorb_index = 0;
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
    use hex_literal::hex;

    fn assert_sponge_output(tag: &[u8; 32], input: &[u8], expected: &[u8]) {
        let mut sponge = KeccakDuplexSponge::new(*tag);
        sponge.absorb(input);
        let output = sponge.squeeze(expected.len());
        assert_eq!(output, expected);
    }

    const TEST_TAG: &[u8; 32] = b"unit_tests_keccak_tag___________";
    const HELLO_WORLD_OUTPUT: &[u8] = &hex!("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c");

    #[test]
    fn test_keccak_duplex_sponge() {
        assert_sponge_output(TEST_TAG, b"Hello, World!", HELLO_WORLD_OUTPUT);
    }

    #[test]
    fn test_absorb_empty_before_does_not_break() {
        let mut sponge = KeccakDuplexSponge::new(*TEST_TAG);
        sponge.absorb(b"");
        sponge.absorb(b"Hello, World!");
        sponge.squeeze(0);
        assert_eq!(sponge.squeeze(64), HELLO_WORLD_OUTPUT);
    }
    #[test]
    fn test_absorb_empty_after_does_not_break() {
        let mut sponge = KeccakDuplexSponge::new(*TEST_TAG);
        sponge.absorb(b"Hello, World!");
        sponge.absorb(b"");
        sponge.squeeze(0);
        assert_eq!(sponge.squeeze(64), HELLO_WORLD_OUTPUT);
    }

    #[test]
    fn test_squeeze_zero_before_behavior() {
        let mut sponge = KeccakDuplexSponge::new(*TEST_TAG);
        sponge.squeeze(0);
        sponge.absorb(b"Hello, World!");
        assert_eq!(sponge.squeeze(64), HELLO_WORLD_OUTPUT);
    }

    #[test]
    fn test_squeeze_zero_after_behavior() {
        let mut sponge = KeccakDuplexSponge::new(*TEST_TAG);
        sponge.absorb(b"Hello, World!");
        sponge.squeeze(0);
        assert_eq!(sponge.squeeze(64), HELLO_WORLD_OUTPUT);
    }

    #[test]
    fn test_absorb_squeeze_absorb_consistency() {
        let tag = *b"edge-case-test-domain-absorb0000";

        let mut sponge = KeccakDuplexSponge::new(tag);
        sponge.absorb(b"first");
        sponge.squeeze(32);
        sponge.absorb(b"second");
        let output = sponge.squeeze(32);

        assert_eq!(
            output,
            hex!("20ce6da64ffc09df8de254222c068358da39d23ec43e522ceaaa1b82b90c8b9a")
        );
    }
    #[test]
    fn test_associativity_of_absorb() {
        let expected_output =
            hex!("7dfada182d6191e106ce287c2262a443ce2fb695c7cc5037a46626e88889af58");
        let tag = *b"absorb-associativity-domain-----";

        // Absorb all at once
        let mut sponge1 = KeccakDuplexSponge::new(tag);
        sponge1.absorb(b"hello world");
        let out1 = sponge1.squeeze(32);

        // Absorb in two parts
        let mut sponge2 = KeccakDuplexSponge::new(tag);
        sponge2.absorb(b"hello");
        sponge2.absorb(b" world");
        let out2 = sponge2.squeeze(32);

        assert_eq!(out1, expected_output);
        assert_eq!(out2, expected_output);
    }

    #[test]
    fn test_tag_affects_output() {
        assert_sponge_output(
            b"domain-one-differs-here-00000000",
            b"input",
            &hex!("2ecad63584ec0ff7f31edb822530762e5cb4b7dc1a62b1ffe02c43f3073a61b8"),
        );
        assert_sponge_output(
            b"domain-two-differs-here-00000000",
            b"input",
            &hex!("6310fa0356e1bab0442fa19958e1c4a6d1dcc565b2b139b6044d1a809f531825"),
        );
    }

    #[test]
    fn test_multiple_blocks_absorb_squeeze() {
        assert_sponge_output(
            b"multi-block-absorb-test_________",
            &vec![0xABu8; 3 * 200],
            &hex!("606310f839e763f4f37ce4c9730da92d4d293109de06abee8a7b40577125bcbfca331b97aee104d03139247e801d8b1a5f6b028b8e51fd643de790416819780a1235357db153462f78c150e34f29a303288f07f854e229aed41c786313119a1cee87402006ab5102271576542e5580be1927af773b0f1b46ce5c78c15267d3729928909192ea0115fcb9475b38a1ff5004477bbbb1b1f5c6a5c90c29b245a83324cb108133efc82216d33da9866051d93baab3bdf0fe02b007d4eb94885a42fcd02a9acdd47b71b6eeac17f5946367d6c69c95cbb80ac91d75e22c9862cf5fe10c7e121368e8a8cd9ff8eebe21071ff014e053725bcc624cd9f31818c4d049e70c14a22e5d3062a553ceca6157315ef2bdb3619c970c9c3d60817ee68291dcd17a282ed1b33cb3afb79c8247cd46de13add88da4418278c8b6b919914be5379daa823b036da008718c1d2a4a0768ecdf032e2b93c344ff65768c8a383a8747a1dcc13b5569b4e15cab9cc8f233fb28b13168284c8a998be6f8fa05389ff9c1d90c5845060d2df3fe0a923be8603abbd2b6f6dd6a5c09c81afe7c06bec789db87185297d6f7261f1e5637f2d140ff3b306df77f42cceffe769545ea8b011022387cd9e3d4f2c97feff5099139715f72301799fcfd59aa30f997e26da9eb7d86ee934a3f9c116d4a9e1012d795db35e1c61d27cd74bb6002f463fc129c1f9c4f25bc8e79c051ac2f1686e393d670f8d1e4cea12acfbff5a135623615d69a88f390569f17a0fc65f5886e2df491615155d5c3eb871209a5c7b0439585ad1a0acbede2e1a8d5aad1d8f3a033267e12185c5f2bbab0f2f1769247"),
        );
    }
}
