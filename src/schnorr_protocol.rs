//! Implementation of the generic Schnorr Sigma Protocol over a [`group::Group`].
//!
//! This module defines the [`SchnorrProof`] structure, which implements
//! a Sigma protocol proving different types of discrete logarithm relations (eg. Schnorr, Pedersen's commitments)
//! through a group morphism abstraction (see [Maurer09](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf)).

use crate::errors::{Error, Result};
use crate::linear_relation::CanonicalLinearRelation;
use crate::traits::{SigmaProtocol, SigmaProtocolSimulator, Transcript};
use crate::{LinearRelation, Nizk};
use alloc::vec::Vec;

use ff::Field;
use group::prime::PrimeGroup;
#[cfg(feature = "std")]
use rand::{CryptoRng, Rng, RngCore};
#[cfg(not(feature = "std"))]
use rand_core::{CryptoRng, RngCore, RngCore as Rng};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

impl<G> SigmaProtocol for CanonicalLinearRelation<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    type Commitment = G;
    type ProverState = (Vec<G::Scalar>, Vec<G::Scalar>);
    type Response = G::Scalar;
    type Witness = Vec<G::Scalar>;
    type Challenge = G::Scalar;

    /// Prover's first message: generates a commitment using random nonces.
    ///
    /// # Parameters
    /// - `witness`: A vector of scalars that satisfy the linear map relation.
    /// - `rng`: A cryptographically secure random number generator.
    ///
    /// # Returns
    /// - A tuple containing:
    ///     - The commitment (a vector of group elements).
    ///     - The prover state (random nonces and witness) used to compute the response.
    ///
    /// # Errors
    ///
    /// -[`Error::InvalidInstanceWitnessPair`] if the witness vector length is less than the number of scalar variables.
    /// If the witness vector is larger, extra variables are ignored.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Vec<Self::Commitment>, Self::ProverState)> {
        if witness.len() < self.num_scalars {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let nonces = (0..self.num_scalars)
            .map(|_| G::Scalar::random(&mut *rng))
            .collect::<Vec<_>>();

        let commitment = self.evaluate(&nonces);
        let prover_state = (nonces.to_vec(), witness.to_vec());
        Ok((commitment, prover_state))
    }

    /// Computes the prover's response (second message) using the challenge.
    ///
    /// # Parameters
    /// - `state`: The prover state returned by `prover_commit`, typically containing randomness and witness components.
    /// - `challenge`: The verifier's challenge scalar.
    ///
    /// # Returns
    /// - A vector of scalars forming the prover's response.
    ///
    /// # Errors
    /// - Returns [`Error::InvalidInstanceWitnessPair`] if the prover state vectors have incorrect lengths.
    fn prover_response(
        &self,
        prover_state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Vec<Self::Response>> {
        let (nonces, witness) = prover_state;

        let responses = nonces
            .into_iter()
            .zip(witness)
            .map(|(r, w)| r + w * challenge)
            .collect();
        Ok(responses)
    }
    /// Verifies the correctness of the proof.
    ///
    /// # Parameters
    /// - `commitment`: The prover's commitment vector (group elements).
    /// - `challenge`: The challenge scalar.
    /// - `response`: The prover's response vector.
    ///
    /// # Returns
    /// - `Ok(())` if the proof is valid.
    /// - `Err(Error::VerificationFailure)` if the proof is invalid.
    /// - `Err(Error::InvalidInstanceWitnessPair)` if the lengths of commitment or response do not match the expected counts.
    ///
    /// # Errors
    /// -[`Error::VerificationFailure`] if the computed relation
    /// does not hold for the provided challenge and response, indicating proof invalidity.
    /// -[`Error::InvalidInstanceWitnessPair`] if the commitment or response length is incorrect.
    fn verifier(
        &self,
        commitment: &[Self::Commitment],
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<()> {
        if commitment.len() != self.image.len() || response.len() != self.num_scalars {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let lhs = self.evaluate(response);
        let mut rhs = Vec::new();
        for (img, g) in self.image_elements().zip(commitment) {
            rhs.push(img * challenge + g);
        }
        if lhs == rhs {
            Ok(())
        } else {
            Err(Error::VerificationFailure)
        }
    }
    fn commitment_len(&self) -> usize {
        self.image.len()
    }

    fn response_len(&self) -> usize {
        self.num_scalars
    }

    fn instance_label(&self) -> impl AsRef<[u8]> {
        self.label()
    }

    fn protocol_identifier(&self) -> [u8; 64] {
        let mut id = [0u8; 64];
        id[..32].clone_from_slice(b"ietf sigma proof linear relation");
        id
    }
}

impl<G> CanonicalLinearRelation<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    /// Convert this LinearRelation into a non-interactive zero-knowledge protocol
    /// using the ShakeCodec and a specified context/domain separator.
    ///
    /// # Parameters
    /// - `context`: Domain separator bytes for the Fiat-Shamir transform
    ///
    /// # Returns
    /// A `Nizk` instance ready for proving and verification
    ///
    /// # Example
    /// ```
    /// # use sigma_proofs::{LinearRelation, Nizk};
    /// # use curve25519_dalek::RistrettoPoint as G;
    /// # use curve25519_dalek::scalar::Scalar;
    /// # use rand::rngs::OsRng;
    /// # use group::Group;
    ///
    /// let mut relation = LinearRelation::<G>::new();
    /// let x_var = relation.allocate_scalar();
    /// let g_var = relation.allocate_element();
    /// let p_var = relation.allocate_eq(x_var * g_var);
    ///
    /// relation.set_element(g_var, G::generator());
    /// let x = Scalar::random(&mut OsRng);
    /// relation.compute_image(&[x]).unwrap();
    ///
    /// // Convert to NIZK with custom context
    /// let nizk = relation.into_nizk(b"my-protocol-v1").unwrap();
    /// let proof = nizk.prove_batchable(&vec![x], &mut OsRng).unwrap();
    /// assert!(nizk.verify_batchable(&proof).is_ok());
    /// ```
    pub fn into_nizk(self, session_identifier: &[u8]) -> Result<Nizk<CanonicalLinearRelation<G>>> {
        Ok(Nizk::new(session_identifier, self))
    }
}

impl<G> LinearRelation<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    /// Convert this LinearRelation into a non-interactive zero-knowledge protocol
    /// using the Fiat-Shamir transform.
    ///
    /// This is a convenience method that combines `.canonical()` and `.into_nizk()`.
    ///
    /// # Parameters
    /// - `session_identifier`: Domain separator bytes for the Fiat-Shamir transform
    ///
    /// # Returns
    /// A `Nizk` instance ready for proving and verification
    ///
    /// # Example
    /// ```
    /// # use sigma_proofs::{LinearRelation, Nizk};
    /// # use curve25519_dalek::RistrettoPoint as G;
    /// # use curve25519_dalek::scalar::Scalar;
    /// # use rand::rngs::OsRng;
    /// # use group::Group;
    ///
    /// let mut relation = LinearRelation::<G>::new();
    /// let x_var = relation.allocate_scalar();
    /// let g_var = relation.allocate_element();
    /// let p_var = relation.allocate_eq(x_var * g_var);
    ///
    /// relation.set_element(g_var, G::generator());
    /// let x = Scalar::random(&mut OsRng);
    /// relation.compute_image(&[x]).unwrap();
    ///
    /// // Convert to NIZK directly
    /// let nizk = relation.into_nizk(b"my-protocol-v1").unwrap();
    /// let proof = nizk.prove_batchable(&vec![x], &mut OsRng).unwrap();
    /// assert!(nizk.verify_batchable(&proof).is_ok());
    /// ```
    pub fn into_nizk(
        self,
        session_identifier: &[u8],
    ) -> crate::errors::Result<crate::Nizk<CanonicalLinearRelation<G>>>
    where
        G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
        G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
    {
        self.canonical()
            .map_err(|_| crate::errors::Error::InvalidInstanceWitnessPair)?
            .into_nizk(session_identifier)
    }
}
impl<G> SigmaProtocolSimulator for CanonicalLinearRelation<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    /// Simulates a valid transcript for a given challenge without a witness.
    ///
    /// # Parameters
    /// - `challenge`: A scalar value representing the challenge.
    /// - `rng`: A cryptographically secure RNG.
    ///
    /// # Returns
    /// - A commitment and response forming a valid proof for the given challenge.
    fn simulate_response<R: Rng + CryptoRng>(&self, rng: &mut R) -> Vec<Self::Response> {
        (0..self.num_scalars)
            .map(|_| G::Scalar::random(&mut *rng))
            .collect()
    }

    /// Simulates a full proof transcript using a randomly generated challenge.
    ///
    /// # Parameters
    /// - `rng`: A cryptographically secure RNG.
    ///
    /// # Returns
    /// - A tuple `(commitment, challenge, response)` forming a valid proof.
    fn simulate_transcript<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<Transcript<Self>> {
        let challenge = G::Scalar::random(&mut *rng);
        let response = self.simulate_response(&mut *rng);
        let commitment = self.simulate_commitment(&challenge, &response)?;
        Ok((commitment, challenge, response))
    }

    /// Recomputes the commitment from the challenge and response (used in compact proofs).
    ///
    /// # Parameters
    /// - `challenge`: The challenge scalar issued by the verifier or derived via Fiat–Shamir.
    /// - `response`: The prover's response vector.
    ///
    /// # Returns
    /// - A vector of group elements representing the simulated commitment (one per linear constraint).
    ///
    /// # Errors
    /// - [`Error::InvalidInstanceWitnessPair`] if the response length does not match the expected number of scalars.
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<Vec<Self::Commitment>> {
        if response.len() != self.num_scalars {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let response_image = self.evaluate(response);
        let commitment = response_image
            .iter()
            .zip(self.image_elements())
            .map(|(res, img)| *res - img * challenge)
            .collect::<Vec<_>>();
        Ok(commitment)
    }
}
