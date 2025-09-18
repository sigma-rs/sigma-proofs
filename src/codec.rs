//! Encoding and decoding utilities for Fiat-Shamir and group operations.

use crate::duplex_sponge::DuplexSpongeInterface;
pub use crate::duplex_sponge::{keccak::KeccakDuplexSponge, shake::ShakeDuplexSponge};
use alloc::vec;
use ff::PrimeField;
use group::prime::PrimeGroup;
use num_bigint::BigUint;
use num_traits::identities::One;

/// A trait defining the behavior of a domain-separated codec hashing, which is typically used for [`crate::traits::SigmaProtocol`]s.
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
    fn new(protocol_identifier: &[u8], session_identifier: &[u8], instance_label: &[u8]) -> Self;

    /// Allows for precomputed initialization of the codec with a specific IV.
    fn from_iv(iv: [u8; 64]) -> Self;

    /// Absorbs data into the codec.
    fn prover_message(&mut self, data: &[u8]);

    /// Produces a scalar that can be used as a challenge from the codec.
    fn verifier_challenge(&mut self) -> Self::Challenge;
}

fn cardinal<F: PrimeField>() -> BigUint {
    let bytes = (F::ZERO - F::ONE).to_repr();
    BigUint::from_bytes_le(bytes.as_ref()) + BigUint::one()
}

/// A byte-level Schnorr codec that works with any duplex sponge.
///
/// This codec is generic over both the group `G` and the hash function `H`.
/// It can be used with different duplex sponge implementations.
#[derive(Clone)]
pub struct ByteSchnorrCodec<G, H>
where
    G: PrimeGroup,
    H: DuplexSpongeInterface,
{
    hasher: H,
    _marker: core::marker::PhantomData<G>,
}

const WORD_SIZE: usize = 4;

fn length_to_bytes(x: usize) -> [u8; WORD_SIZE] {
    (x as u32).to_be_bytes()
}

/// Compute the initialization vector (IV) for a protocol instance.
///
/// This function computes a deterministic IV from the protocol identifier,
/// session identifier, and instance label using the specified duplex sponge.
pub fn compute_iv<H: DuplexSpongeInterface>(
    protocol_id: &[u8],
    session_id: &[u8],
    instance_label: &[u8],
) -> [u8; 64] {
    let mut tmp = H::new([0u8; 64]);
    tmp.absorb(&length_to_bytes(protocol_id.len()));
    tmp.absorb(protocol_id);
    tmp.absorb(&length_to_bytes(session_id.len()));
    tmp.absorb(session_id);
    tmp.absorb(&length_to_bytes(instance_label.len()));
    tmp.absorb(instance_label);
    tmp.squeeze(64).try_into().unwrap()
}

impl<G, H> Codec for ByteSchnorrCodec<G, H>
where
    G: PrimeGroup,
    H: DuplexSpongeInterface,
{
    type Challenge = G::Scalar;

    fn new(protocol_id: &[u8], session_id: &[u8], instance_label: &[u8]) -> Self {
        let iv = compute_iv::<H>(protocol_id, session_id, instance_label);
        Self::from_iv(iv)
    }

    fn from_iv(iv: [u8; 64]) -> Self {
        Self {
            hasher: H::new(iv),
            _marker: core::marker::PhantomData,
        }
    }

    fn prover_message(&mut self, data: &[u8]) {
        self.hasher.absorb(data);
    }

    fn verifier_challenge(&mut self) -> Self::Challenge {
        #[allow(clippy::manual_div_ceil)]
        let scalar_byte_length = (G::Scalar::NUM_BITS as usize + 7) / 8;

        let uniform_bytes = self.hasher.squeeze(scalar_byte_length + 16);
        let scalar = BigUint::from_bytes_be(&uniform_bytes);
        let reduced = scalar % cardinal::<G::Scalar>();

        let mut bytes = vec![0u8; scalar_byte_length];
        let reduced_bytes = reduced.to_bytes_be();
        let start = bytes.len() - reduced_bytes.len();
        bytes[start..].copy_from_slice(&reduced_bytes);
        bytes.reverse();

        let mut repr = <G::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);

        <G::Scalar as PrimeField>::from_repr(repr).expect("Error")
    }
}

/// Type alias for a Keccak-based ByteSchnorrCodec.
/// This is the codec used for matching test vectors from Sage.
pub type KeccakByteSchnorrCodec<G> = ByteSchnorrCodec<G, KeccakDuplexSponge>;

/// Type alias for a SHAKE-based ByteSchnorrCodec.
pub type Shake128DuplexSponge<G> = ByteSchnorrCodec<G, ShakeDuplexSponge>;
