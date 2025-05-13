//! Implementation of a Fiat-Shamir transcript codec using SHAKE128 (Keccak)
//!
//! This module defines `KeccakTranscript`, a concrete implementation of the `TranscriptCodec`
//! trait. It uses the SHAKE128 extendable output function (XOF) from the Keccak family
//! to generate Fiat-Shamir challenges for Sigma protocols.
//!
//! It allows commitments (group elements) to be absorbed into a transcript,
//! and produces scalar challenges by squeezing bytes from the hash state.
//!
//! # Usage
//! - The prover and verifier absorb the same messages into identical `KeccakTranscript` instances.
//! - The prover and the verifier then squeeze the hash to generate a challenge scalar for the protocol. The verifier can check that the prover used the challenge output by the transcript because he owns an identical transcript.

use ff::PrimeField;
use group::{Group, GroupEncoding};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

use crate::transcript::r#trait::TranscriptCodec;

/// A Fiat-Shamir transcript over a group `G`, using SHAKE128 (Keccak).
///
/// This struct manages the state of the hash function and produces
/// deterministic, random-looking scalars for use in Sigma protocols.
///
/// The transcript is initialized with a domain separator and absorbs serialized
/// group elements. It outputs challenges compatible with the group’s scalar field.
pub struct ShakeTranscript<G: Group> {
    /// Internal SHAKE128 hasher state.
    hasher: Shake128,
    /// Marker to bind this transcript to a specific group `G`.
    _marker: core::marker::PhantomData<G>,
}

impl<G> TranscriptCodec<G> for ShakeTranscript<G>
where
    G: Group + GroupEncoding,
    G::Scalar: PrimeField,
{
    /// Initializes the transcript with a domain separation label, to avoid cross-protocol collisions.
    fn new(domain_sep: &[u8]) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(domain_sep);
        Self {
            hasher,
            _marker: Default::default(),
        }
    }

    /// Absorbs a slice of group elements into the transcript. Each element is serialized and fed into the hasher.
    fn prover_message(&mut self, elems: &[G]) -> &mut Self {
        for elem in elems {
            self.hasher.update(elem.to_bytes().as_ref());
        }
        self
    }

    /// Produce a random-looking challenge scalar from the transcript.
    ///
    /// The method reads from the finalized SHAKE128 state until it finds
    /// a valid scalar (i.e., one within the field).
    fn verifier_challenge(&mut self) -> G::Scalar {
        let mut reader = self.hasher.clone().finalize_xof();
        let mut buf = [0u8; 64];
        reader.read(&mut buf);

        let challenge_len = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        loop {
            // This loop is used to ensure that the reader outputs an element that can be interpreted as a G::Scalar with ::from_repr. If a candidate can't be turned into a Scalar, a new candidate is picked.
            reader.read(&mut buf);
            let mut repr = <<G as Group>::Scalar as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&buf[..challenge_len]);
            let candidate = G::Scalar::from_repr(repr);
            if bool::from(candidate.is_some()) {
                break candidate.unwrap();
            }
        }
    }
}
