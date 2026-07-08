//! The Sigma Protocol for preimages of linear maps over a [`group::Group`]
//! (draft-irtf-cfrg-sigma-protocols, Section "The Sigma Protocol").
//!
//! This module implements [`SigmaProtocol`] for the validated [`Instance`],
//! proving knowledge of a witness for linear group relations (Schnorr,
//! Pedersen commitments, DLEQ, ...) through the group-morphism abstraction
//! of [Maurer09](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf).

use crate::errors::{Error, Result};
use crate::linear_relation::Instance;
use crate::traits::{ScalarRng, SigmaProtocol, SigmaProtocolSimulator, Transcript};
use crate::{LinearRelation, MultiScalarMul, Nizk};
use alloc::vec::Vec;
use itertools::Itertools;

use group::prime::PrimeGroup;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

impl<G> SigmaProtocol for Instance<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    type Commitment = G;
    type ProverState = (Vec<G::Scalar>, Vec<G::Scalar>);
    type Response = G::Scalar;
    type Witness = Vec<G::Scalar>;
    type Challenge = G::Scalar;

    /// `ProverCommitment` of the specification: sample one nonce per witness
    /// scalar and evaluate the linear map at the nonces.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInstanceWitnessPair`] if the witness length does not
    /// match `num_scalars(instance)` (a mismatch cannot yield a valid proof
    /// and may otherwise leak the witness).
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut impl ScalarRng,
    ) -> Result<(Vec<Self::Commitment>, Self::ProverState)> {
        if witness.len() != self.num_scalars() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let nonces = rng.random_scalars_vec::<G>(self.num_scalars());
        let commitment = self.map(&nonces);
        let prover_state = (nonces, witness.clone());
        Ok((commitment, prover_state))
    }

    /// `ProverResponse` of the specification:
    /// `response[i] = nonces[i] + witness[i] * challenge`.
    fn prover_response(
        &self,
        prover_state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Vec<Self::Response>> {
        let (nonces, witness) = prover_state;
        if witness.len() != self.num_scalars() || nonces.len() != self.num_scalars() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let responses = nonces
            .into_iter()
            .zip_eq(witness)
            .map(|(r, w)| r + w * challenge)
            .collect();
        Ok(responses)
    }

    /// `Verifier` of the specification: checks
    /// `map(instance, response) == commitment + challenge * image(instance)`.
    ///
    /// Instance validity (step 1 of the specification's verifier) is enforced
    /// by construction: an [`Instance`] can only be built through
    /// `ValidateInstance`.
    fn verifier(
        &self,
        commitment: &[Self::Commitment],
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<()> {
        if commitment.len() != self.num_equations() || response.len() != self.num_scalars() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let expected = self.map(response);
        let got: Vec<G> = self
            .image()
            .into_iter()
            .zip_eq(commitment)
            .map(|(img, com)| img * challenge + com)
            .collect();
        if got == expected {
            Ok(())
        } else {
            Err(Error::VerificationFailure)
        }
    }

    fn commitment_len(&self) -> usize {
        self.num_equations()
    }

    fn response_len(&self) -> usize {
        self.num_scalars()
    }

    /// The encoded instance (`SerializeLinearRelation`).
    fn instance_label(&self) -> impl AsRef<[u8]> {
        self.serialize()
    }

    /// Rejects the identity element in commitment messages, maintaining
    /// consistency with group deserialization.
    fn check_commitment(&self, commitment: &[Self::Commitment]) -> Result<()> {
        match commitment.iter().any(|c| c.is_identity().into()) {
            true => Err(Error::VerificationFailure),
            false => Ok(()),
        }
    }
}

impl<G> Instance<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    /// Wrap this instance in a non-interactive argument for the given `tag`
    /// (see [`Nizk::new`] for the tag's requirements).
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "curve25519-dalek")] {
    /// # use sigma_proofs::{LinearRelation, ProofRng};
    /// # use curve25519_dalek::RistrettoPoint as G;
    /// # use group::Group;
    ///
    /// let mut rng = ProofRng::from_os_entropy();
    /// let mut relation = LinearRelation::<G>::new();
    /// let x_var = relation.allocate_scalar();
    /// let p_var = relation.allocate_eq(x_var * relation.generator());
    ///
    /// let x = rng.sample();
    /// relation.compute_image(&[x]).unwrap();
    ///
    /// let nizk = relation.compile().unwrap().into_nizk(b"my-protocol-v1");
    /// let proof = nizk.prove_batchable(&vec![x], &mut rng).unwrap();
    /// assert!(nizk.verify_batchable(&proof).is_ok());
    /// # }
    /// ```
    pub fn into_nizk(self, tag: &[u8]) -> Nizk<Instance<G>> {
        Nizk::new(tag, self)
    }
}

impl<G> LinearRelation<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    /// Compile this relation ([`LinearRelation::compile`]) and wrap it in a
    /// non-interactive argument for the given `tag`.
    pub fn into_nizk(self, tag: &[u8]) -> crate::errors::Result<Nizk<Instance<G>>> {
        Ok(self.compile()?.into_nizk(tag))
    }
}

impl<G> SigmaProtocolSimulator for Instance<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    /// `SimulateResponse`: a vector of `num_scalars(instance)` uniformly
    /// random scalars.
    fn simulate_response(&self, rng: &mut impl ScalarRng) -> Vec<Self::Response> {
        rng.random_scalars_vec::<G>(self.num_scalars())
    }

    /// Simulates a full transcript using a randomly generated challenge.
    fn simulate_transcript(&self, rng: &mut impl ScalarRng) -> Result<Transcript<Self>> {
        let [challenge] = rng.random_scalars::<G, _>();
        let response = self.simulate_response(rng);
        let commitment = self.simulate_commitment(&challenge, &response)?;
        Ok((commitment, challenge, response))
    }

    /// `SimulateCommitment` of the specification: solves the verification
    /// equation for the commitment,
    /// `commitment[i] = map(instance, response)[i] - challenge * image(instance)[i]`.
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<Vec<Self::Commitment>> {
        if response.len() != self.num_scalars() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        // A single MSM per equation: the response terms plus the negated
        // challenge times the image terms.
        let commitment = self
            .equations()
            .iter()
            .map(|equation| {
                let scalars = equation
                    .terms
                    .iter()
                    .map(|&(s, _, coeff)| coeff * response[s as usize])
                    .chain(
                        equation
                            .image
                            .iter()
                            .map(|&(_, coeff)| -(coeff * challenge)),
                    )
                    .collect::<Vec<_>>();
                let bases = equation
                    .terms
                    .iter()
                    .map(|&(_, e, _)| self.elements()[e as usize])
                    .chain(
                        equation
                            .image
                            .iter()
                            .map(|&(e, _)| self.elements()[e as usize]),
                    )
                    .collect::<Vec<_>>();
                MultiScalarMul::msm(&scalars, &bases)
            })
            .collect();

        Ok(commitment)
    }
}
