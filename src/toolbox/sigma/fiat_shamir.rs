//! Fiat-Shamir transformation for Sigma protocols.
//!
//! This module defines `NISigmaProtocol`, a generic non-interactive Sigma protocol wrapper,
//! based on applying the Fiat-Shamir heuristic using a transcript codec.
//!
//! It transforms an interactive Sigma protocol into a non-interactive one,
//! by deriving challenges deterministically from previous protocol messages
//! via a cryptographic sponge function (transcript).
//!
//! # Usage
//! This struct is generic over:
//! - `P`: the underlying Sigma protocol (`SigmaProtocol` trait).
//! - `C`: the transcript codec (`TranscriptCodec` trait).
//! - `G`: the group used for commitments and operations (`Group` trait).

use rand::{RngCore, CryptoRng};
use crate::toolbox::sigma::SigmaProtocol;
use crate::toolbox::sigma::transcript::TranscriptCodec;
use group::Group;

/// A Fiat-Shamir transformation of a Sigma protocol into a non-interactive proof.
///
/// `NISigmaProtocol` wraps an interactive Sigma protocol `P`
/// and a hash-based transcript `C`, to produce non-interactive proofs.
/// 
/// It manages the domain separation, transcript reset,
/// proof generation, and proof verification.
///
/// # Type Parameters
/// - `P`: the Sigma protocol implementation.
/// - `C`: the transcript codec used for Fiat-Shamir.
/// - `G`: the group on which the protocol operates.
pub struct NISigmaProtocol<P, C, G>
where
    G: Group,
    P: SigmaProtocol<Commitment = Vec<G>, Challenge = <G as Group>::Scalar>,
    C: TranscriptCodec<G>,
{
    /// Domain separation string for the Fiat-Shamir transform.
    domain_sep: Vec<u8>,
    /// Current transcript state.
    hash_state: C,
    /// Underlying Sigma protocol.
    sigmap: P,
}

impl<P, C, G> NISigmaProtocol<P, C, G>
where
    G: Group,
    P: SigmaProtocol<Commitment = Vec<G>, Challenge = <G as Group>::Scalar>,
    C: TranscriptCodec<G>,
{
    /// Creates a new non-interactive Sigma protocol, identified by a domain separator (usually fixed per protocol instantiation), and an initialized Sigma protocol instance.
    pub fn new(iv: &[u8], instance: P) -> Self {
        let domain_sep = iv.to_vec();
        let hash_state = C::new(iv);
        Self { domain_sep, hash_state, sigmap: instance }
    }

    /// Produces a non-interactive proof for a witness and serializes it as a vector of bytes.
    pub fn prove(
        &mut self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Vec<u8> {
        self.hash_state = C::new(&self.domain_sep);

        let (commitment, prover_state) = self.sigmap.prover_commit(witness, rng);
        // Fiat Shamir challenge
        let challenge = self
            .hash_state
            .prover_message(&commitment)
            .verifier_challenge();
        println!("Prover's challenge : {:?}", challenge);
        // Prouver's response
        let response = self.sigmap.prover_response(prover_state, &challenge);
        // Local verification of the proof
        assert!(self.sigmap.verifier(&commitment, &challenge, &response) == Ok(()));
        self.sigmap.serialize_batchable(&commitment, &challenge, &response)
    }

    /// Verify a non-interactive serialized proof and returns a Result: `Ok(())` if the proof verifies successfully, `Err(())` otherwise.
    pub fn verify(&mut self, proof: &Vec<u8>) -> Result<(), ()> {
        self.hash_state = C::new(&self.domain_sep);

        let (commitment, response) = self.sigmap.deserialize_batchable(proof).unwrap();
        // Recompute the challenge
        let challenge = self
            .hash_state
            .prover_message(&commitment)
            .verifier_challenge();
        println!("Verifier's challenge : {:?}", challenge);
        // Verification of the proof
        self.sigmap.verifier(&commitment, &challenge, &response)

    }
}