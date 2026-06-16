//! Implementation of the generic Schnorr Sigma Protocol over a [`group::Group`].
//!
//! This module defines the [`SchnorrProof`] structure, which implements
//! a Sigma protocol proving different types of discrete logarithm relations (eg. Schnorr, Pedersen's commitments)
//! through a group morphism abstraction (see [Maurer09](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf)).

use crate::errors::{Error, Result};
use crate::linear_relation::{CanonicalLinearRelation, GroupVar, ScalarVar};
use crate::traits::{ScalarRng, SigmaProtocol, SigmaProtocolSimulator, Transcript};
use crate::{LinearRelation, MultiScalarMul, Nizk};
use alloc::{vec, vec::Vec};
use ff::Field;
use itertools::Itertools;

use group::prime::PrimeGroup;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

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

fn batch_powers<G: PrimeGroup>(mu: G::Scalar, count: usize) -> Vec<G::Scalar>
where
    G::Scalar: Field,
{
    let mut powers = Vec::with_capacity(count);
    let mut power = G::Scalar::ONE;
    for _ in 0..count {
        powers.push(power);
        power *= mu;
    }
    powers
}

fn verify_batch_constraint<G>(
    relation: &CanonicalLinearRelation<G>,
    constraint_index: usize,
    linear_combination: &[(ScalarVar<G>, GroupVar<G>)],
    image: G,
    transcripts: &[&(Vec<G>, G::Scalar, Vec<G::Scalar>)],
    powers: &[G::Scalar],
) -> bool
where
    G: PrimeGroup + MultiScalarMul,
    G::Scalar: Field,
{
    let mut scalars = Vec::new();
    let mut bases = Vec::new();

    for (scalar_var, group_var) in linear_combination {
        let mut weight = G::Scalar::ZERO;
        for (transcript, power) in itertools::zip_eq(transcripts, powers) {
            let (_, _, response) = *transcript;
            weight += *power * response[scalar_var.index()];
        }
        scalars.push(weight);
        bases.push(relation.group_elements.get(*group_var).unwrap());
    }

    let mut challenge_weight = G::Scalar::ZERO;
    for (transcript, power) in itertools::zip_eq(transcripts, powers) {
        let (_, challenge, _) = *transcript;
        challenge_weight += *power * challenge;
    }
    scalars.push(-challenge_weight);
    bases.push(image);

    for (transcript, power) in itertools::zip_eq(transcripts, powers) {
        let (commitment, _, _) = *transcript;
        scalars.push(-*power);
        bases.push(commitment[constraint_index]);
    }

    G::msm(&scalars, &bases) == G::identity()
}

impl<G> SigmaProtocol for CanonicalLinearRelation<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
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
    /// -[`Error::InvalidInstanceWitnessPair`] if the witness vector length is not equal to the number of scalar variables.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut impl ScalarRng,
    ) -> Result<(Vec<Self::Commitment>, Self::ProverState)> {
        if witness.len() != self.num_scalars {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let nonces = rng.random_scalars_vec::<G>(self.num_scalars);
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
        if witness.len() != self.num_scalars || nonces.len() != self.num_scalars {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let responses = nonces
            .into_iter()
            .zip_eq(witness)
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
        self.num_scalars
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

    /// Batch-verifies multiple batchable non-interactive proofs.
    ///
    /// # Parameters
    /// - `proofs`: Pairs of `(nizk_instance, serialized_proof)`.
    ///
    /// # Returns
    /// - `Ok(())` if all proofs are valid.
    /// - `Err(Error)` if any proof is malformed or invalid.
    pub fn verify_batch(proofs: &[(&Nizk<Self>, &[u8])]) -> Result<()> {
        if proofs.is_empty() {
            return Ok(());
        }

        let (mu, transcripts) = Nizk::parse_batch_for_verification(proofs)?;
        let powers = batch_powers::<G>(mu, proofs.len());

        let mut groups: Vec<(Vec<u8>, Vec<usize>)> = Vec::new();
        for (index, (nizk, _)) in proofs.iter().enumerate() {
            let label = nizk.interactive_proof.label();
            if let Some((_, indices)) = groups.iter_mut().find(|(existing, _)| existing == &label) {
                indices.push(index);
            } else {
                groups.push((label, vec![index]));
            }
        }

        for (_, indices) in groups {
            let relation = &proofs[indices[0]].0.interactive_proof;
            let group_transcripts: Vec<_> = indices.iter().map(|&i| &transcripts[i]).collect();
            let group_powers: Vec<_> = indices.iter().map(|&i| powers[i]).collect();

            for transcript in &group_transcripts {
                let (commitment, _, response) = *transcript;
                if commitment.len() != relation.image.len()
                    || response.len() != relation.num_scalars
                {
                    return Err(Error::InvalidInstanceWitnessPair);
                }
            }

            for (constraint_index, linear_combination) in
                relation.linear_combinations.iter().enumerate()
            {
                let image = relation
                    .group_elements
                    .get(relation.image[constraint_index])
                    .unwrap();
                if !verify_batch_constraint(
                    relation,
                    constraint_index,
                    linear_combination,
                    image,
                    &group_transcripts,
                    &group_powers,
                ) {
                    return Err(Error::VerificationFailure);
                }
            }
        }

        Ok(())
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
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
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
        rng.random_scalars_vec::<G>(self.num_scalars)
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
        if response.len() != self.num_scalars {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        // Evaluate the constraint linear combinations using the response scalars.
        // NOTE: This does not use CanonicalLinearRelation::evaluate because we also want to
        // include the multiplication of the response image by the challenge in the same MSM.
        let commitment = itertools::zip_eq(&self.linear_combinations, self.image_elements())
            .map(|(constraint, img)| {
                let scalars = constraint
                    .iter()
                    .map(|(scalar_var, _)| response[scalar_var.index()])
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
}
