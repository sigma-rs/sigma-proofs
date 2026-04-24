//! Implementation of the generic Schnorr Sigma Protocol over a [`group::Group`].
//!
//! This module defines the [`SchnorrProof`] structure, which implements
//! a Sigma protocol proving different types of discrete logarithm relations (eg. Schnorr, Pedersen's commitments)
//! through a group morphism abstraction (see [Maurer09](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf)).

use crate::errors::{Error, Result};
use crate::linear_relation::{CanonicalLinearRelation, ScalarMap};
use crate::traits::{ScalarRng, SigmaProtocol, SigmaProtocolSimulator, Transcript};
use crate::{LinearRelation, MultiScalarMul, Nizk};
use alloc::vec::Vec;
use itertools::Itertools;

use group::prime::PrimeGroup;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};
use subtle::{Choice, ConstantTimeEq};

fn protocol_identifier_for_group<G>() -> [u8; 64] {
    let _ = core::marker::PhantomData::<G>;

    #[cfg(feature = "p256")]
    if core::any::type_name::<G>() == core::any::type_name::<p256::ProjectivePoint>() {
        return pad_identifier(b"sigma-proofs_Shake128_P256");
    }

    #[cfg(feature = "bls12_381")]
    if core::any::type_name::<G>() == core::any::type_name::<bls12_381::G1Projective>() {
        return pad_identifier(b"sigma-proofs_Shake128_BLS12381");
    }

    pad_identifier(b"ietf sigma proof linear relation")
}

fn pad_identifier(identifier: &[u8]) -> [u8; 64] {
    assert!(
        identifier.len() <= 64,
        "identifier must fit within 64 bytes"
    );

    let mut padded = [0u8; 64];
    padded[..identifier.len()].copy_from_slice(identifier);
    padded
}

impl<G> SigmaProtocol for CanonicalLinearRelation<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    type Commitment = G;
    type Challenge = G::Scalar;
    /// Prover response to the challenge.
    type Response = G::Scalar;
    /// Prover state is a pair of (nonces, witness). Each scalar in the witness has a nonce.
    type ProverState = (ScalarMap<G>, ScalarMap<G>);
    type Witness = ScalarMap<G>;

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
    /// -[`Error::InvalidInstanceWitnessPair`] if the witness vector length is not equal to the number of scalar variables.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut impl ScalarRng,
    ) -> Result<(Vec<Self::Commitment>, Self::ProverState)> {
        // Collect the scalars from the witness for variables in this relation.
        // NOTE: The witness may have additional assignments e.g. in the case of composition.
        // TODO: Should we be permissive in this way, or more restrictive?
        let witness_state = self
            .scalar_vars
            .iter()
            .map(|&var| Ok((var, witness.get(var)?)))
            .collect::<Result<ScalarMap<G>>>()?;

        // Create a random nonce for each scalar variable in the relation.
        let nonces = self
            .scalar_vars
            .iter()
            .map(|&var| (var, rng.random_scalar::<G>()))
            .collect();

        let commitment = self.evaluate(&nonces);
        let prover_state = (nonces, witness_state);
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

        let responses = self
            .scalar_vars
            .iter()
            .map(|&var| {
                let r = nonces.get(var)?;
                let w = witness.get(var)?;
                Ok(r + w * challenge)
            })
            .collect::<Result<_>>()?;
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
        if commitment.len() != self.image.len() || response.len() != self.scalar_vars.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        // TODO: This allocation does feel a little wasteful, since evaluate _could_ match up the
        // variables to slice positions internally.
        let response_map: ScalarMap<G> = self
            .scalar_vars
            .iter()
            .copied()
            .zip_eq(response.iter().copied())
            .collect();

        let lhs = self.evaluate(response_map);
        let mut rhs = Vec::new();
        for (img, g) in self.image_elements().zip_eq(commitment) {
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
        self.scalar_vars.len()
    }

    fn instance_label(&self) -> impl AsRef<[u8]> {
        self.label()
    }

    fn protocol_identifier(&self) -> [u8; 64] {
        protocol_identifier_for_group::<G>()
    }
}

impl<G> CanonicalLinearRelation<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
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
    /// # #[cfg(feature = "curve25519-dalek")] {
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
    /// # }
    /// ```
    pub fn into_nizk(self, session_identifier: &[u8]) -> Result<Nizk<CanonicalLinearRelation<G>>> {
        Ok(Nizk::new(session_identifier, self))
    }
}

impl<G> LinearRelation<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
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
    /// # #[cfg(feature = "curve25519-dalek")] {
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
    /// # }
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
    // TODO: Should we split out `is_witness_valid` to avoid the ConstantTimeEq bound?
    G: PrimeGroup
        + Encoding<[u8]>
        + NargSerialize
        + NargDeserialize
        + MultiScalarMul
        + ConstantTimeEq,
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
    fn simulate_response(&self, rng: &mut impl ScalarRng) -> Vec<Self::Response> {
        rng.random_scalars_vec::<G>(self.scalar_vars.len())
    }

    /// Simulates a full proof transcript using a randomly generated challenge.
    ///
    /// # Parameters
    /// - `rng`: A cryptographically secure RNG.
    ///
    /// # Returns
    /// - A tuple `(commitment, challenge, response)` forming a valid proof.
    fn simulate_transcript(&self, rng: &mut impl ScalarRng) -> Result<Transcript<Self>> {
        let [challenge] = rng.random_scalars::<G, _>();
        let response = self.simulate_response(rng);
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
        if response.len() != self.scalar_vars.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        // TODO: This allocation does feel a little wasteful, since evaluate _could_ match up the
        // variables to slice positions internally.
        let response_map: ScalarMap<G> = self
            .scalar_vars
            .iter()
            .copied()
            .zip_eq(response.iter().copied())
            .collect();

        // Evaluate the constraint linear combinations using the response scalars.
        // NOTE: This does not use CanonicalLinearRelation::evaluate because we also want to
        // include the multiplication of the response image by the challenge in the same MSM.
        let commitment = itertools::zip_eq(&self.linear_combinations, self.image_elements())
            .map(|(constraint, img)| {
                let scalars = constraint
                    .iter()
                    .map(|(scalar_var, _)| response_map.get(*scalar_var).unwrap())
                    .chain(core::iter::once(-*challenge))
                    .collect::<Vec<_>>();
                let bases = constraint
                    .iter()
                    .map(|(_, group_var)| self.group_elements.get(*group_var).unwrap())
                    .chain(core::iter::once(img))
                    .collect::<Vec<_>>();
                MultiScalarMul::msm(&scalars, &bases)
            })
            .collect();

        Ok(commitment)
    }

    fn is_witness_valid(&self, witness: &Self::Witness) -> Choice {
        let got = self.evaluate(witness);
        self.image_elements()
            .zip_eq(got)
            .fold(Choice::from(1), |acc, (lhs, rhs)| acc & lhs.ct_eq(&rhs))
    }
}
