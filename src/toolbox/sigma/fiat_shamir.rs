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
use group::{Group, ff::FromUniformBytes};

use super::SigmaProtocol;

/// Compute a Fiat-Shamir challenge using SHAKE128 over domain-separated input.
/// Reduces the result modulo the group scalar field.
pub fn fiat_shamir_challenge<G, const N: usize>(
    input: &[u8],
    domain_sep: &[u8],
) -> G::Scalar
where
    G: Group,
    G::Scalar: FromUniformBytes<N>,
{
    let mut hasher = Shake128::default();
    hasher.update(domain_sep);
    hasher.update(input);

    let mut reader = hasher.finalize_xof();
    let mut buf = [0u8; N];
    reader.read(&mut buf);

    G::Scalar::from_uniform_bytes(&buf)
}

/// Run the full Fiat-Shamir prover logic: commit, derive challenge, respond.
pub fn prove_fiat_shamir<P, G, const N: usize>(
    protocol: &P,
    witness: &P::Witness,
    domain_sep: &[u8],
    rng: &mut (impl Rng + CryptoRng)
) -> (P::Commitment, G::Scalar, P::Response)
where 
    P: SigmaProtocol<G>,
    P::Commitment: AsRef<[u8]>,
    G: Group,
    G::Scalar: FromUniformBytes<N>
{
    // Generate a commitment for the NIZK
    let (commitment, state) = protocol.prover_commit(witness, rng);

    // Generate the challenge using Fiat-Shamir
    let challenge = fiat_shamir_challenge::<G, N>(commitment.as_ref(), domain_sep);

    let response = protocol.prover_response(&state, &challenge);

    (commitment, challenge, response)
}

/// Verify a Fiat-Shamir proof by recomputing the challenge and checking the response.
pub fn verify_fiat_shamir<P, G, const N: usize>(
    protocol: &P,
    commitment: &P::Commitment,
    response: &P::Response,
    domain_sep: &[u8]
) -> bool
where 
    P: SigmaProtocol<G>, 
    G: Group,
    P::Commitment: AsRef<[u8]>,
    G::Scalar: FromUniformBytes<N>
{
    // Generate the challenge with the outputs provided by the prover
    let challenge = fiat_shamir_challenge::<G, N>(commitment.as_ref(), domain_sep);

    protocol.verifier(commitment, &challenge, &response)
}