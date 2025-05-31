//! # Keccak-based Fiat-Shamir Codec for vector tests
//!
//! This module implements a **Fiat-Shamir codec** using the Keccak-f\[1600\] permutation
//! in a duplex sponge construction
//!
//! It includes:
//! - A custom `KeccakPermutationState` and `KeccakDuplexSponge`
//! - A [`ByteSchnorrCodec`] codec based on this sponge
//!
//! ## Purpose
//! This module exists to **match test vectors** generated in the original Sage implementation
//! of Sigma protocols. It uses a byte-level Keccak-based Fiat-Shamir transformation that mirrors
//! Sage's Keccak-duplex usage.
//!
//! ## Notes
//! - **Not intended for production use**.
//! - The `verifier_challenge` logic performs SHAKE-style domain separation and modulus reduction via `num-bigint`.
//!
//! ## Components
//! - `KeccakPermutationState`: Low-level Keccak-f\[1600\] state representation
//! - `KeccakDuplexSponge`: Duplex sponge over 200-byte state buffer
//! - `ByteSchnorrCodec`: Fiat-Shamir codec compatible with Sage Schnorr proofs
use crate::codec::r#trait::{Codec, DuplexSpongeInterface};
use ff::PrimeField;
use group::{Group, GroupEncoding};
use num_bigint::BigUint;
use num_traits::identities::One;
use std::convert::TryInto;
use tiny_keccak::keccakf;

const R: usize = 136;
const N: usize = 136 + 64;

#[derive(Clone)]
pub struct KeccakPermutationState {
    pub state: [u8; 200],
    pub rate: usize,
    pub capacity: usize,
}

impl Default for KeccakPermutationState {
    fn default() -> Self {
        Self::new()
    }
}

impl KeccakPermutationState {
    pub fn new() -> Self {
        KeccakPermutationState {
            state: [0u8; 200],
            rate: 136,
            capacity: 64,
        }
    }

    fn _bytes_to_keccak_state(&self) -> [[u64; 5]; 5] {
        let mut flat: [u64; 25] = [0u64; 25];
        for (i, item) in flat.iter_mut().enumerate() {
            let start = i * 8;
            *item = u64::from_le_bytes(self.state[start..start + 8].try_into().unwrap());
        }
        let mut matrix = [[0u64; 5]; 5];
        for y in 0..5 {
            for x in 0..5 {
                matrix[x][y] = flat[5 * y + x];
            }
        }
        matrix
    }

    fn _keccak_state_to_bytes(&mut self, state: [[u64; 5]; 5]) {
        let mut flat: [u64; 25] = [0; 25];
        for y in 0..5 {
            for x in 0..5 {
                flat[5 * y + x] = state[x][y];
            }
        }
        for (i, item) in flat.iter().enumerate() {
            let bytes = item.to_le_bytes();
            let start = i * 8;
            self.state[start..start + 8].copy_from_slice(&bytes);
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
        assert_eq!(iv.len(), 32);
        let state = KeccakPermutationState::new();
        let rate = R;
        let capacity = N - R;
        KeccakDuplexSponge {
            state,
            rate,
            capacity,
            absorb_index: 0,
            squeeze_index: 0,
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
            self.squeeze_index += chunk_size;
            length -= chunk_size;
            output.extend_from_slice(
                &self.state.state[self.squeeze_index..self.squeeze_index + chunk_size],
            );
        }

        output
    }
}

fn cardinal<F: PrimeField>() -> BigUint {
    let bytes = (F::ZERO - F::ONE).to_repr();
    BigUint::from_bytes_le(bytes.as_ref()) + BigUint::one()
}

#[derive(Clone)]
pub struct ByteSchnorrCodec<G, H>
where
    G: Group + GroupEncoding,
    H: DuplexSpongeInterface,
{
    hasher: H,
    _marker: core::marker::PhantomData<G>,
}

impl<G, H> Codec for ByteSchnorrCodec<G, H>
where
    G: Group + GroupEncoding,
    H: DuplexSpongeInterface,
{
    type Challenge = <G as Group>::Scalar;

    fn new(domain_sep: &[u8]) -> Self {
        let hasher = H::new(domain_sep);
        Self {
            hasher,
            _marker: Default::default(),
        }
    }

    fn prover_message(&mut self, data: &[u8]) -> &mut Self {
        self.hasher.absorb(data);
        /* for elem in elems {
            self.hasher.absorb(&G::serialize_element(elem));
        } */
        self
    }

    fn verifier_challenge(&mut self) -> G::Scalar {
        let scalar_byte_length = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        let uniform_bytes = self.hasher.squeeze(scalar_byte_length + 16);
        let scalar = BigUint::from_bytes_be(&uniform_bytes);
        let reduced = scalar % cardinal::<G::Scalar>();

        let mut bytes = vec![0u8; scalar_byte_length];
        let reduced_bytes = reduced.to_bytes_be();
        let start = bytes.len() - reduced_bytes.len();
        bytes[start..].copy_from_slice(&reduced_bytes);
        bytes.reverse();

        let mut repr = <<G as Group>::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);

        <<G as Group>::Scalar as PrimeField>::from_repr(repr).expect("Error")
    }
}
