//! Encoding and decoding utilities for Fiat-Shamir and group operations.

use crate::duplex_sponge::DuplexSpongeInterface;
use crate::duplex_sponge::{keccak::KeccakDuplexSponge, shake::ShakeDuplexSponge};
use group::prime::PrimeGroup;
use spongefish::Decoding;

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
    fn new(
        protocol_identifier: &[u8; 64],
        session_identifier: &[u8],
        instance_label: &[u8],
    ) -> Self;

    /// Absorbs data into the codec.
    fn prover_message(&mut self, data: &[u8]);

    /// Produces a scalar that can be used as a challenge from the codec.
    fn verifier_challenge(&mut self) -> Self::Challenge;
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

pub(crate) fn pad_identifier(identifier: &[u8]) -> [u8; 64] {
    assert!(
        identifier.len() <= 64,
        "identifier must fit within 64 bytes"
    );

    let mut padded = [0u8; 64];
    padded[..identifier.len()].copy_from_slice(identifier);
    padded
}

pub(crate) fn derive_session_id<H: DuplexSpongeInterface>(session: &[u8]) -> [u8; 64] {
    let mut session_state = H::new(pad_identifier(b"fiat-shamir/session-id"));
    session_state.absorb(session);

    let mut session_id = [0u8; 64];
    session_id[32..].copy_from_slice(&session_state.squeeze(32));
    session_id
}

/// Compute the initialization vector (IV) for a protocol instance.
///
/// This function computes a deterministic IV from the protocol identifier,
/// session identifier, and instance label using the specified duplex sponge.
pub fn compute_iv<H: DuplexSpongeInterface>(
    protocol_id: &[u8; 64],
    session_id: &[u8],
    instance_label: &[u8],
) -> [u8; 64] {
    let mut tmp = H::new(*protocol_id);
    tmp.absorb(&derive_session_id::<H>(session_id));
    tmp.absorb(instance_label);
    tmp.squeeze(64).try_into().unwrap()
}

impl<G, H> Codec for ByteSchnorrCodec<G, H>
where
    G: PrimeGroup,
    H: DuplexSpongeInterface,
    G::Scalar: Decoding<[u8]>,
{
    type Challenge = G::Scalar;

    fn new(protocol_id: &[u8; 64], session_id: &[u8], instance_label: &[u8]) -> Self {
        let mut hasher = H::new(*protocol_id);
        hasher.absorb(&derive_session_id::<H>(session_id));
        hasher.absorb(instance_label);
        Self {
            hasher,
            _marker: core::marker::PhantomData,
        }
    }

    fn prover_message(&mut self, data: &[u8]) {
        self.hasher.absorb(data);
    }

    fn verifier_challenge(&mut self) -> Self::Challenge {
        let mut repr = <G::Scalar as Decoding<[u8]>>::Repr::default();
        let uniform_bytes = self.hasher.squeeze(repr.as_mut().len());
        repr.as_mut().copy_from_slice(&uniform_bytes);
        G::Scalar::decode(repr)
    }
}

/// Type alias for a Keccak-based ByteSchnorrCodec.
pub type KeccakByteSchnorrCodec<G> = ByteSchnorrCodec<G, KeccakDuplexSponge>;

/// Type alias for a SHAKE-based ByteSchnorrCodec.
pub type Shake128DuplexSponge<G> = ByteSchnorrCodec<G, ShakeDuplexSponge>;
