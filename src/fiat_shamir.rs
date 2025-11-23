//! Fiat-Shamir transformation for [`SigmaProtocol`]s.
//!
//! This module defines [`Nizk`], a generic non-interactive Sigma protocol wrapper,
//! based on applying the Fiat-Shamir heuristic using a codec.
//!
//! It transforms an interactive [`SigmaProtocol`] into a non-interactive one,
//! by deriving challenges deterministically from previous protocol messages
//! via a cryptographic sponge function (Codec).
//!
//! # Usage
//! This struct is generic over:
//! - `P`: the underlying Sigma protocol ([`SigmaProtocol`] trait).

use crate::duplex_sponge::keccak::KeccakDuplexSponge;
use crate::duplex_sponge::DuplexSpongeInterface;
use crate::errors::Error;
use crate::traits::SigmaProtocol;
use crate::traits::SigmaProtocolSimulator;
use alloc::vec::Vec;
use ff::PrimeField;
use num_bigint::BigUint;
use num_traits::identities::One;
#[cfg(feature = "std")]
use rand::{CryptoRng, RngCore};
#[cfg(not(feature = "std"))]
use rand_core::{CryptoRng, RngCore};
use spongefish::{Encoding, NargDeserialize, NargSerialize};

/// A Fiat-Shamir transformation of a [`SigmaProtocol`] into a non-interactive proof.
///
/// [`Nizk`] wraps an interactive Sigma protocol `P`
/// and a hash-based codec `C`, to produce non-interactive proofs.
///
/// It manages the domain separation, codec reset,
/// proof generation, and proof verification.
///
/// # Type Parameters
/// - `P`: the Sigma protocol implementation.
/// - `C`: the codec used for Fiat-Shamir.
#[derive(Debug)]
pub struct Nizk<P>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
{
    pub session_id: Vec<u8>,
    /// Underlying interactive proof.
    pub interactive_proof: P,
}

impl<P> Nizk<P>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq + PrimeField,
    P::Commitment: NargSerialize + NargDeserialize + Encoding,
    P::Response: NargSerialize + NargDeserialize + Encoding,
{
    /// Constructs a new [`Nizk`] instance.
    ///
    /// # Parameters
    /// - `iv`: Domain separation tag for the hash function (e.g., protocol name or context).
    /// - `instance`: An instance of the interactive Sigma protocol.
    ///
    /// # Returns
    /// A new [`Nizk`] that can generate and verify non-interactive proofs.
    pub fn new(session_identifier: &[u8], interactive_proof: P) -> Self {
        Self {
            session_id: session_identifier.to_vec(),
            interactive_proof,
        }
    }

    /// Generates a batchable, serialized non-interactive proof.
    ///
    /// # Parameters
    /// - `witness`: The secret witness.
    /// - `rng`: A cryptographically secure random number generator.
    ///
    /// # Returns
    /// A serialized proof suitable for batch verification.
    ///
    /// # Panics
    /// Panics if serialization fails (should not happen under correct implementation).
    pub fn prove_batchable(
        &self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, Error> {
        let protocol_id = self.interactive_proof.protocol_identifier();
        let instance_label = self.interactive_proof.instance_label();
        let instance_label = instance_label.as_ref();
        let mut keccak = initialize_sponge(protocol_id, &self.session_id, instance_label);
        let (commitment, ip_state) = self.interactive_proof.prover_commit(witness, rng)?;
        let commitment_bytes = serialize_messages(&commitment);
        keccak.absorb(&commitment_bytes);
        let challenge = derive_challenge::<P::Challenge>(&mut keccak);
        let response = self
            .interactive_proof
            .prover_response(ip_state, &challenge)?;
        let mut proof = commitment_bytes;
        serialize_messages_into(&response, &mut proof);
        Ok(proof)
    }

    /// Verifies a batchable non-interactive proof.
    ///
    /// # Parameters
    /// - `proof`: A serialized batchable proof.
    ///
    /// # Returns
    /// - `Ok(())` if the proof is valid.
    /// - `Err(Error)` if deserialization or verification fails.
    ///
    /// # Errors
    /// - Returns [`Error::VerificationFailure`] if:
    ///   - The challenge doesn't match the recomputed one from the commitment.
    ///   - The response fails verification under the Sigma protocol.
    pub fn verify_batchable(&self, narg_string: &[u8]) -> Result<(), Error> {
        let protocol_id = self.interactive_proof.protocol_identifier();
        let instance_label = self.interactive_proof.instance_label();
        let instance_label = instance_label.as_ref();
        let commitment_len = self.interactive_proof.commitment_len();
        let response_len = self.interactive_proof.response_len();
        let mut cursor = narg_string;
        let commitment = deserialize_messages(commitment_len, &mut cursor)?;
        let commitment_bytes_len = narg_string.len().saturating_sub(cursor.len());
        let mut keccak = initialize_sponge(protocol_id, &self.session_id, instance_label);
        keccak.absorb(&narg_string[..commitment_bytes_len]);
        let challenge = derive_challenge::<P::Challenge>(&mut keccak);
        let response = deserialize_messages(response_len, &mut cursor)?;
        if !cursor.is_empty() {
            return Err(Error::VerificationFailure);
        }
        self.interactive_proof
            .verifier(&commitment, &challenge, &response)
    }
}

impl<P> Nizk<P>
where
    P: SigmaProtocol + SigmaProtocolSimulator,
    P::Challenge: PartialEq,
{
    // /// Generates a compact serialized proof.
    // ///
    // /// Uses a more space-efficient representation compared to batchable proofs.
    // ///
    // /// # Parameters
    // /// - `witness`: The secret witness.
    // /// - `rng`: A cryptographically secure random number generator.
    // ///
    // /// # Returns
    // /// A compact, serialized proof.
    // ///
    // /// # Panics
    // /// Panics if serialization fails.
    // pub fn prove_compact(
    //     &self,
    //     witness: &P::Witness,
    //     rng: &mut (impl RngCore + CryptoRng),
    // ) -> Result<Vec<u8>, Error> {
    //     let (_commitment, challenge, response) = self.prove(witness, rng)?;
    //     let mut bytes = Vec::new();
    //     bytes.extend_from_slice(&self.interactive_proof.serialize_challenge(&challenge));
    //     bytes.extend_from_slice(&self.interactive_proof.serialize_response(&response));
    //     Ok(bytes)
    // }

    // /// Verifies a compact proof.
    // ///
    // /// Recomputes the commitment from the challenge and response, then verifies it.
    // ///
    // /// # Parameters
    // /// - `proof`: A compact serialized proof.
    // ///
    // /// # Returns
    // /// - `Ok(())` if the proof is valid.
    // /// - `Err(Error)` if deserialization or verification fails.
    // ///
    // /// # Errors
    // /// - Returns [`Error::VerificationFailure`] if:
    // ///   - Deserialization fails.
    // ///   - The recomputed commitment or response is invalid under the Sigma protocol.
    // pub fn verify_compact(&self, proof: &[u8]) -> Result<(), Error> {
    //     // Deserialize challenge and response from compact proof
    //     let challenge = self.interactive_proof.deserialize_challenge(proof)?;
    //     let challenge_size = self.interactive_proof.serialize_challenge(&challenge).len();
    //     let response = self
    //         .interactive_proof
    //         .deserialize_response(&proof[challenge_size..])?;
    //     let response_size = self.interactive_proof.serialize_response(&response).len();

    //     // Proof size check
    //     if proof.len() != challenge_size + response_size {
    //         return Err(Error::VerificationFailure);
    //     }

    //     // Assert correct proof size
    //     let total_expected_len =
    //         challenge_size + self.interactive_proof.serialize_response(&response).len();
    //     if proof.len() != total_expected_len {
    //         return Err(Error::VerificationFailure);
    //     }

    //     // Compute the commitments
    //     let commitment = self
    //         .interactive_proof
    //         .simulate_commitment(&challenge, &response)?;
    //     // Verify the proof
    //     self.verify(&commitment, &challenge, &response)
    // }
}

fn length_to_bytes(x: usize) -> [u8; 4] {
    (x as u32).to_be_bytes()
}

fn absorb_len_prefixed(sponge: &mut KeccakDuplexSponge, data: &[u8]) {
    sponge.absorb(&length_to_bytes(data.len()));
    sponge.absorb(data);
}

fn initialize_sponge(
    protocol_id: [u8; 64],
    session_id: &[u8],
    instance_label: &[u8],
) -> KeccakDuplexSponge {
    let mut sponge = KeccakDuplexSponge::new(protocol_id);
    absorb_len_prefixed(&mut sponge, session_id);
    absorb_len_prefixed(&mut sponge, instance_label);
    sponge
}

fn field_cardinality<F: PrimeField>() -> BigUint {
    let bytes = (F::ZERO - F::ONE).to_repr();
    BigUint::from_bytes_le(bytes.as_ref()) + BigUint::one()
}

fn derive_challenge<F: PrimeField>(sponge: &mut KeccakDuplexSponge) -> F {
    let scalar_byte_length = (F::NUM_BITS as usize).div_ceil(8);
    let uniform_bytes = sponge.squeeze(scalar_byte_length + 16);
    let scalar = BigUint::from_bytes_be(&uniform_bytes);
    let reduced = scalar % field_cardinality::<F>();

    let mut bytes = vec![0u8; scalar_byte_length];
    let reduced_bytes = reduced.to_bytes_be();
    let start = bytes.len().saturating_sub(reduced_bytes.len());
    bytes[start..start + reduced_bytes.len()].copy_from_slice(&reduced_bytes);
    bytes.reverse();

    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    F::from_repr(repr).expect("challenge reduction should not fail")
}

fn serialize_messages_into<T: NargSerialize>(messages: &[T], out: &mut Vec<u8>) {
    for message in messages {
        message.serialize_into_narg(out);
    }
}

fn serialize_messages<T: NargSerialize>(messages: &[T]) -> Vec<u8> {
    let mut out = Vec::new();
    serialize_messages_into(messages, &mut out);
    out
}

fn deserialize_messages<T: NargDeserialize>(len: usize, buf: &mut &[u8]) -> Result<Vec<T>, Error> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(T::deserialize_from_narg(buf).map_err(|_| Error::VerificationFailure)?);
    }
    Ok(out)
}
