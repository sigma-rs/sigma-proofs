//! Fiat-Shamir transformation for [`SigmaProtocol`]s.
//!
//! This module defines [`Nizk`], a generic non-interactive Sigma protocol wrapper,
//! based on applying the Fiat-Shamir heuristic using a cryptographic sponge function.
//!
//! It transforms an interactive [`SigmaProtocol`] into a non-interactive one,
//! by deriving challenges deterministically from previous protocol messages.
//!
//! # Usage
//! This struct is generic over:
//! - `P`: the underlying Sigma protocol ([`SigmaProtocol`] trait).

use crate::errors::Error;
use crate::traits::SigmaProtocol;
use crate::traits::SigmaProtocolSimulator;
use alloc::vec::Vec;
use rand_core::CryptoRngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use spongefish::{
    DomainSeparator, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState,
};

/// A Fiat-Shamir transformation of a [`SigmaProtocol`] into a non-interactive proof.
///
/// [`Nizk`] wraps an interactive Sigma protocol `P`
/// to produce non-interactive proofs by deriving verifier challenges from a
/// cryptographic sponge state.
///
/// # Type Parameters
/// - `P`: the Sigma protocol implementation.
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
    P::Challenge: PartialEq,
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
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let protocol_id = self.interactive_proof.protocol_identifier();
        let instance_label = self.interactive_proof.instance_label();
        let mut transcript =
            initialize_prover_state(protocol_id, &self.session_id, instance_label.as_ref());
        let (commitment, ip_state) = self.interactive_proof.prover_commit(witness, rng)?;
        transcript.prover_messages(&commitment);
        let challenge = transcript.verifier_message::<P::Challenge>();
        let response = self
            .interactive_proof
            .prover_response(ip_state, &challenge)?;
        transcript.prover_messages(&response);
        Ok(transcript.narg_string().to_vec())
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
        let commitment_len = self.interactive_proof.commitment_len();
        let response_len = self.interactive_proof.response_len();
        let mut transcript = initialize_verifier_state(
            protocol_id,
            &self.session_id,
            instance_label.as_ref(),
            narg_string,
        );
        let commitment = transcript.prover_messages_vec::<P::Commitment>(commitment_len)?;
        let challenge = transcript.verifier_message::<P::Challenge>();
        let response = transcript.prover_messages_vec::<P::Response>(response_len)?;
        transcript.check_eof()?;
        self.interactive_proof
            .verifier(&commitment, &challenge, &response)
    }
}

impl<P> Nizk<P>
where
    P: SigmaProtocol + SigmaProtocolSimulator,
    P::Challenge: PartialEq + NargDeserialize + NargSerialize,
{
    /// Generates a compact serialized proof.
    ///
    /// Uses a more space-efficient representation compared to batchable proofs.
    ///
    /// # Parameters
    /// - `witness`: The secret witness.
    /// - `rng`: A cryptographically secure random number generator.
    ///
    /// # Returns
    /// A compact, serialized proof.
    ///
    /// # Panics
    /// Panics if serialization fails.
    pub fn prove_compact(
        &self,
        witness: &P::Witness,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let protocol_id = self.interactive_proof.protocol_identifier();
        let instance_label = self.interactive_proof.instance_label();
        let mut transcript =
            initialize_prover_state(protocol_id, &self.session_id, instance_label.as_ref());
        let (commitment, ip_state) = self.interactive_proof.prover_commit(witness, rng)?;
        let commitment_bytes = serialize_messages(&commitment);
        transcript.public_message(commitment_bytes.as_slice());
        let challenge = transcript.verifier_message::<P::Challenge>();
        let response = self
            .interactive_proof
            .prover_response(ip_state, &challenge)?;

        // Serialize the compact proof string.
        let mut proof = Vec::new();
        challenge.serialize_into_narg(&mut proof);
        serialize_messages_into(&response, &mut proof);
        Ok(proof)
    }

    /// Verifies a compact proof.
    ///
    /// Recomputes the commitment from the challenge and response, then verifies it.
    ///
    /// # Parameters
    /// - `proof`: A compact serialized proof.
    ///
    /// # Returns
    /// - `Ok(())` if the proof is valid.
    /// - `Err(Error)` if deserialization or verification fails.
    ///
    /// # Errors
    /// - Returns [`Error::VerificationFailure`] if:
    ///   - Deserialization fails.
    ///   - The recomputed commitment or response is invalid under the Sigma protocol.
    pub fn verify_compact(&self, proof: &[u8]) -> Result<(), Error> {
        // Deserialize challenge and response from compact proof
        let mut cursor = proof;
        let protocol_id = self.interactive_proof.protocol_identifier();
        let instance_label = self.interactive_proof.instance_label();
        let challenge = P::Challenge::deserialize_from_narg(&mut cursor)?;
        let response_len = self.interactive_proof.response_len();
        let response = deserialize_messages(response_len, &mut cursor)?;

        // Proof size check
        if !cursor.is_empty() {
            return Err(Error::VerificationFailure);
        }

        // Compute the commitments
        let commitment = self
            .interactive_proof
            .simulate_commitment(&challenge, &response)?;

        // Re-compute the challenge and ensure it's the same as the one
        // we received
        let commitment_bytes = serialize_messages(&commitment);
        let mut transcript =
            initialize_verifier_state(protocol_id, &self.session_id, instance_label.as_ref(), &[]);
        transcript.public_message(commitment_bytes.as_slice());
        let recomputed_challenge = transcript.verifier_message::<P::Challenge>();
        if challenge != recomputed_challenge {
            return Err(Error::VerificationFailure);
        }

        // At this point, checking
        // self.interactive_proof.verifier(&commitment, &challenge,
        // &response) is redundant, because we know that commitment =
        // simulate_commitment(challenge, response), and that challenge
        // is the output of the appropriate hash, so the signature is
        // valid.
        Ok(())
    }
}

fn initialize_prover_state(
    protocol_id: [u8; 64],
    session_id: &[u8],
    instance_label: &[u8],
) -> ProverState {
    let instance_label = instance_label.to_vec();
    DomainSeparator::new(protocol_id)
        .session(derive_session_id(session_id))
        .instance(&instance_label)
        .std_prover()
}

fn initialize_verifier_state<'a>(
    protocol_id: [u8; 64],
    session_id: &[u8],
    instance_label: &[u8],
    narg_string: &'a [u8],
) -> VerifierState<'a> {
    let instance_label = instance_label.to_vec();
    DomainSeparator::new(protocol_id)
        .session(derive_session_id(session_id))
        .instance(&instance_label)
        .std_verifier(narg_string)
}

fn derive_session_id(session_id: &[u8]) -> [u8; 64] {
    const RATE: usize = 168;
    const DOMAIN: &[u8] = b"fiat-shamir/session-id";

    let mut initial_block = [0u8; RATE];
    initial_block[..DOMAIN.len()].copy_from_slice(DOMAIN);

    let mut shake = sha3::Shake128::default();
    shake.update(&initial_block);
    shake.update(session_id);

    let mut reader = shake.finalize_xof();
    let mut derived = [0u8; 64];
    reader.read(&mut derived[32..]);
    derived
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
    let mut out = Vec::new();
    for _ in 0..len {
        out.push(T::deserialize_from_narg(buf).map_err(|_| Error::VerificationFailure)?);
    }
    Ok(out)
}
