//! Encoding and decoding utilities for Fiat-Shamir and group operations.

pub use crate::duplex_sponge::keccak::KeccakDuplexSponge;
use crate::duplex_sponge::{shake::ShakeDuplexSponge, DuplexSpongeInterface};
use ff::PrimeField;
use group::{Group, GroupEncoding};
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
    fn new(domain_sep: &[u8]) -> Self;

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

    fn prover_message(&mut self, data: &[u8]) {
        self.hasher.absorb(data);
    }

    fn verifier_challenge(&mut self) -> G::Scalar {
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

        let mut repr = <<G as Group>::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);

        <<G as Group>::Scalar as PrimeField>::from_repr(repr).expect("Error")
    }
}

/// Type alias for a Keccak-based ByteSchnorrCodec.
/// This is the codec used for matching test vectors from Sage.
pub type KeccakByteSchnorrCodec<G> = ByteSchnorrCodec<G, KeccakDuplexSponge>;

/// Type alias for a SHAKE-based ByteSchnorrCodec.
pub type ShakeCodec<G> = ByteSchnorrCodec<G, ShakeDuplexSponge>;
