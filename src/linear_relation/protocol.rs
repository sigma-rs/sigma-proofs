//! The Sigma Protocol for preimages of linear maps over a [`group::Group`]
//! (draft-irtf-cfrg-sigma-protocols, Section "The Sigma Protocol").
//!
//! This module implements [`SigmaProtocol`] for the validated [`Instance`],
//! proving knowledge of a witness for linear group relations (Schnorr,
//! Pedersen commitments, DLEQ, ...) through the group-morphism abstraction
//! of [Maurer09](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf).

use crate::codec::{GroupCodec, ScalarCodec};
use crate::errors::{InvalidWitness, ProverResult, VerificationError, VerificationResult};
use crate::linear_relation::Instance;
use crate::traits::{SigmaProtocol, SigmaProtocolSimulator, Transcript};
use crate::MultiScalarMul;
use alloc::vec::Vec;
use itertools::Itertools;
use spongefish::{DuplexSpongeInit, Encoding, PrivateRng};

use group::prime::PrimeGroup;

/// The prover's secrets between the two prover moves.
pub struct ProverState<G: PrimeGroup>
where
    G::Scalar: ScalarCodec,
{
    nonces: Vec<G::Scalar>,
    witness: Vec<G::Scalar>,
}

// `Vec::zeroize` rather than a `for` loop assigning `ZERO`, as `zeroize` performs volatile
// writes with a fence that it may not remove.
impl<G: PrimeGroup> Drop for ProverState<G>
where
    G::Scalar: ScalarCodec,
{
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.nonces);
        zeroize::Zeroize::zeroize(&mut self.witness);
    }
}

impl<G> SigmaProtocol for Instance<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    type Commitment = Vec<G>;
    type ProverState = ProverState<G>;
    type Response = Vec<G::Scalar>;
    type Witness = [G::Scalar];
    type Challenge = G::Scalar;

    /// `ProverCommitment` of the specification: sample one nonce per witness
    /// scalar and evaluate the linear map at the nonces.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> ProverResult<(Self::Commitment, Self::ProverState)> {
        if witness.len() != self.num_scalars() {
            return Err(InvalidWitness);
        }

        let nonces: Vec<G::Scalar> = (0..self.num_scalars())
            .map(|_| G::Scalar::sample(rng))
            .collect();
        let commitment = self.map(&nonces);
        let prover_state = ProverState {
            nonces,
            witness: witness.to_vec(),
        };
        Ok((commitment, prover_state))
    }

    /// `ProverResponse` of the specification:
    /// `response[i] = nonces[i] + witness[i] * challenge`.
    fn prover_response(
        &self,
        prover_state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> ProverResult<Self::Response> {
        let (nonces, witness) = (&prover_state.nonces, &prover_state.witness);
        if witness.len() != self.num_scalars() || nonces.len() != self.num_scalars() {
            return Err(InvalidWitness);
        }
        Ok(itertools::zip_eq(nonces.iter(), witness.iter())
            .map(|(r, w)| *r + *w * challenge)
            .collect())
    }

    /// `Verifier` of the specification: checks
    /// `map(instance, response) == commitment + challenge * image(instance)`.
    ///
    /// Instance validity (step 1 of the specification's verifier) is enforced
    /// by construction: an [`Instance`] can only be built through
    /// `ValidateInstance`.
    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> VerificationResult<()> {
        if commitment.len() != self.num_equations() || response.len() != self.num_scalars() {
            return Err(VerificationError);
        }

        if self.simulate_commitment(challenge, response)? == *commitment {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }

    /// [`SigmaProtocol::verifier`] as one multi-scalar multiplication.
    ///
    /// Equation `j` accepts exactly when
    /// `E[j] = map(response)[j] - challenge * image[j] - commitment[j]` is the
    /// identity.
    ///
    /// This function checks the single random linear combination
    /// `sum over j of randomness^j * E[j] == identity`.
    ///
    /// # Safety
    ///
    /// Security relies on `randomness` being sampled uniformly after seeing the protocol transcript.
    fn verifier_with_randomness(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
        randomness: &Self::Challenge,
    ) -> VerificationResult<()> {
        use ff::Field;

        if commitment.len() != self.num_equations() || response.len() != self.num_scalars() {
            return Err(VerificationError);
        }
        // With one equation there is nothing to combine, and folding the
        // commitment into the MSM costs a base that the direct check does not
        // pay for.
        if self.num_equations() == 1 {
            return self.verifier(commitment, challenge, response);
        }

        // `weights[e]`: the coefficient element `e` ends up with once every
        // equation has been folded in with its power of `randomness`.
        let mut weights = alloc::vec![G::Scalar::ZERO; self.num_elements()];
        let mut scalars = Vec::with_capacity(self.num_elements() + commitment.len());
        let mut bases = Vec::with_capacity(self.num_elements() + commitment.len());

        // Signs are those of `commitment + challenge * image - map(response)`,
        // so the first commitment's coefficient is exactly `ONE` and the MSM
        // skips its windows.
        let mut power = G::Scalar::ONE;
        for (equation, &com) in self.equations().iter().zip_eq(commitment) {
            equation.accumulate_weights(power, challenge, response, &mut weights);
            // The commitment is the one base of the equation that the instance
            // does not already carry.
            scalars.push(power);
            bases.push(com);
            power *= randomness;
        }
        self.push_weighted_elements(&weights, &mut scalars, &mut bases);

        match bool::from(G::msm_vartime(&scalars, &bases).is_identity()) {
            true => Ok(()),
            false => Err(VerificationError),
        }
    }

    /// The encoded instance (`SerializeLinearRelation`).
    fn encode_instance(&self) -> impl AsRef<[u8]> {
        self.encode()
    }
}

impl<G> SigmaProtocolSimulator for Instance<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    /// `SimulateResponse`: a vector of `num_scalars(instance)` uniformly
    /// random scalars.
    fn simulate_response(
        &self,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> Self::Response {
        (0..self.num_scalars())
            .map(|_| G::Scalar::sample(rng))
            .collect::<Vec<_>>()
    }

    /// Simulates a full transcript using a randomly generated challenge.
    fn simulate_transcript(
        &self,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> VerificationResult<Transcript<Self>> {
        let response = self.simulate_response(rng);
        let challenge = G::Scalar::sample(rng);
        let commitment = self.simulate_commitment(&challenge, &response)?;
        Ok((commitment, challenge, response))
    }

    /// `SimulateCommitment` of the specification: solves the verification
    /// equation for the commitment,
    /// `commitment[i] = map(instance, response)[i] - challenge * image(instance)[i]`.
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> VerificationResult<Self::Commitment> {
        if response.len() != self.num_scalars() {
            return Err(VerificationError);
        }

        // A single MSM per equation over the compiled effective bases plus the
        // negated challenge times the cached image. Vartime is sound here:
        // challenge and responses appear in the published transcript (even
        // for simulated composition branches), so their timing leaks no
        // secret. Public coefficients were folded into each effective base at
        // instance construction, making repeated uses of one scalar one MSM
        // term rather than one term per wire-format triple.
        let commitment = self
            .equations()
            .iter()
            .enumerate()
            .zip_eq(self.image())
            .map(|((equation_index, _), &image)| {
                let (mut scalars, mut bases) = self.evaluation_pairs(equation_index, response);
                scalars.push(-*challenge);
                bases.push(image);
                MultiScalarMul::msm_vartime(&scalars, &bases)
            })
            .collect();

        Ok(commitment)
    }
}
