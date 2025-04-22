//! Fiat-Shamir Transformation Utilities
//!
//! This module provides generic, stateless helpers to perform the Fiat-Shamir
//! transformation, allowing interactive Sigma protocols to be converted into
//! non-interactive ones. It uses SHAKE128 for challenge derivation, and reduces
//! output modulo the target field using the `FromUniformBytes` trait. They're compatible with
//! any `SigmaProtocol` where the commitment can be serialized and the challenge scalar
//! supports deterministic hashing.

use rand::{CryptoRng, Rng};
use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};
use group::ff::FromUniformBytes;

use super::SigmaProtocol;

/// Compute a Fiat-Shamir challenge using SHAKE128 over domain-separated input.
/// Reduces the result modulo the group scalar field.
pub fn fiat_shamir_challenge<C: FromUniformBytes<N>, const N: usize>(
    input: &[u8],
    domain_sep: &[u8],
) -> C
{
    let mut hasher = Shake128::default();
    hasher.update(domain_sep);
    hasher.update(input);

    let mut reader = hasher.finalize_xof();
    let mut buf = [0u8; N];
    reader.read(&mut buf);

    C::from_uniform_bytes(&buf)
}

/// Run the full Fiat-Shamir prover logic: commit, derive challenge, respond.
/// - `serialize_commitment`: Function to convert a commitment to bytes (e.g., using compression or serialization).
pub fn prove_fiat_shamir<P, const N: usize>(
    protocol: &P,
    witness: &P::Witness,
    domain_sep: &[u8],
    rng: &mut (impl Rng + CryptoRng),
    serialize_commitment: impl Fn(&P::Commitment) -> Vec<u8> // TODO(trait): Replace closure with a `ToBytes` trait for better type safety and reuse.
) -> (P::Commitment, P::Challenge, P::Response)
where 
    P: SigmaProtocol,
    P::Challenge: FromUniformBytes<N>
{
    // Generate a commitment for the NIZK
    let (commitment, state) = protocol.prover_commit(witness, rng);

    // Generate the challenge using Fiat-Shamir
    let input_bytes = serialize_commitment(&commitment);
    let challenge = fiat_shamir_challenge::<P::Challenge, N>(&input_bytes, domain_sep);

    let response = protocol.prover_response(&state, &challenge);

    (commitment, challenge, response)
}

/// Verify a Fiat-Shamir proof by recomputing the challenge and checking the response.
/// - `serialize_commitment`: Function to convert a commitment to bytes (e.g., using compression or serialization).
pub fn verify_fiat_shamir<P, const N: usize>(
    protocol: &P,
    commitment: &P::Commitment,
    response: &P::Response,
    domain_sep: &[u8],
    serialize_commitment: impl Fn(&P::Commitment) -> Vec<u8> // TODO(trait): Replace closure with a `ToBytes` trait for better type safety and reuse.
) -> bool
where 
    P: SigmaProtocol,
    P::Challenge: FromUniformBytes<N>
{
    // Generate the challenge with the outputs provided by the prover
    let input_bytes = serialize_commitment(commitment);
    let challenge = fiat_shamir_challenge::<P::Challenge, N>(&input_bytes, domain_sep);

    protocol.verifier(commitment, &challenge, response)
}