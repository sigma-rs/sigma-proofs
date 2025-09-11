//! # Protocol Composition with AND/OR Logic
//!
//! This module defines the [`ComposedRelation`] enum, which generalizes the [`CanonicalLinearRelation`]
//! by enabling compositional logic between multiple proof instances.
//!
//! Specifically, it supports:
//! - Simple atomic proofs (e.g., discrete logarithm, Pedersen commitments)
//! - Conjunctions (`And`) of multiple sub-protocols
//! - Disjunctions (`Or`) of multiple sub-protocols
//!
//! ## Example Composition
//!
//! ```ignore
//! And(
//!    Or(dleq, pedersen_commitment),
//!    Simple(discrete_logarithm),
//!    And(pedersen_commitment_dleq, bbs_blind_commitment_computation)
//! )
//! ```

use alloc::vec::Vec;
use ff::{Field, PrimeField};
use group::prime::PrimeGroup;
#[cfg(feature = "std")]
use rand::{CryptoRng, Rng};
#[cfg(not(feature = "std"))]
use rand_core::{CryptoRng, RngCore as Rng};
use sha3::{Digest, Sha3_256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::errors::InvalidInstance;
use crate::group::serialization::{deserialize_scalars, serialize_scalars};
use crate::{
    codec::Shake128DuplexSponge,
    errors::Error,
    fiat_shamir::Nizk,
    linear_relation::{CanonicalLinearRelation, LinearRelation},
    traits::{SigmaProtocol, SigmaProtocolSimulator},
};

/// A protocol proving knowledge of a witness for a composition of linear relations.
///
/// This implementation generalizes [`CanonicalLinearRelation`] by using AND/OR links.
///
/// # Type Parameters
/// - `G`: A cryptographic group implementing [`group::Group`] and [`group::GroupEncoding`].
#[derive(Clone)]
pub enum ComposedRelation<G: PrimeGroup> {
    Simple(CanonicalLinearRelation<G>),
    And(Vec<ComposedRelation<G>>),
    Or(Vec<ComposedRelation<G>>),
}

impl<G: PrimeGroup + ConstantTimeEq + ConditionallySelectable> ComposedRelation<G> {
    /// Create a [ComposedRelation] for an AND relation from the given list of relations.
    pub fn and<T: Into<ComposedRelation<G>>>(witness: impl IntoIterator<Item = T>) -> Self {
        Self::And(witness.into_iter().map(|x| x.into()).collect())
    }

    /// Create a [ComposedRelation] for an OR relation from the given list of relations.
    pub fn or<T: Into<ComposedRelation<G>>>(witness: impl IntoIterator<Item = T>) -> Self {
        Self::Or(witness.into_iter().map(|x| x.into()).collect())
    }
}

impl<G: PrimeGroup> From<CanonicalLinearRelation<G>> for ComposedRelation<G> {
    fn from(value: CanonicalLinearRelation<G>) -> Self {
        ComposedRelation::Simple(value)
    }
}

impl<G: PrimeGroup> TryFrom<LinearRelation<G>> for ComposedRelation<G> {
    type Error = InvalidInstance;

    fn try_from(value: LinearRelation<G>) -> Result<Self, Self::Error> {
        Ok(Self::Simple(CanonicalLinearRelation::try_from(value)?))
    }
}

// Structure representing the Commitment type of Protocol as SigmaProtocol
#[derive(Clone)]
pub enum ComposedCommitment<G: PrimeGroup> {
    Simple(<CanonicalLinearRelation<G> as SigmaProtocol>::Commitment),
    And(Vec<ComposedCommitment<G>>),
    Or(Vec<ComposedCommitment<G>>),
}

impl<G: PrimeGroup> ComposedCommitment<G>
where
    G: ConditionallySelectable,
{
    /// Conditionally select between two ComposedCommitment values.
    /// This function performs constant-time selection of the commitment values.
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        match (a, b) {
            (ComposedCommitment::Simple(a_elements), ComposedCommitment::Simple(b_elements)) => {
                // Both vectors must have the same length for this to work
                debug_assert_eq!(a_elements.len(), b_elements.len());
                let selected: Vec<G> = a_elements
                    .iter()
                    .zip(b_elements.iter())
                    .map(|(a, b)| G::conditional_select(a, b, choice))
                    .collect();
                ComposedCommitment::Simple(selected)
            }
            (ComposedCommitment::And(a_commitments), ComposedCommitment::And(b_commitments)) => {
                debug_assert_eq!(a_commitments.len(), b_commitments.len());
                let selected: Vec<ComposedCommitment<G>> = a_commitments
                    .iter()
                    .zip(b_commitments.iter())
                    .map(|(a, b)| ComposedCommitment::conditional_select(a, b, choice))
                    .collect();
                ComposedCommitment::And(selected)
            }
            (
                ComposedCommitment::Or(a_commitments),
                ComposedCommitment::Or(b_commitments),
            ) => {
                debug_assert_eq!(a_commitments.len(), b_commitments.len());
                let selected: Vec<ComposedCommitment<G>> = a_commitments
                    .iter()
                    .zip(b_commitments.iter())
                    .map(|(a, b)| ComposedCommitment::conditional_select(a, b, choice))
                    .collect();
                ComposedCommitment::Or(selected)
            }
            _ => {
                unreachable!("Mismatched ComposedCommitment variants in conditional_select");
            }
        }
    }
}

// Structure representing the ProverState type of Protocol as SigmaProtocol
pub enum ComposedProverState<G: PrimeGroup + ConstantTimeEq> {
    Simple(<CanonicalLinearRelation<G> as SigmaProtocol>::ProverState),
    And(Vec<ComposedProverState<G>>),
    Or(ComposedOrProverState<G>),
}

pub type ComposedOrProverState<G> = Vec<ComposedOrProverStateEntry<G>>;
pub struct ComposedOrProverStateEntry<G: PrimeGroup + ConstantTimeEq>(
    Choice,
    ComposedProverState<G>,
    ComposedChallenge<G>,
    ComposedResponse<G>,
);

// Structure representing the Response type of Protocol as SigmaProtocol
#[derive(Clone)]
pub enum ComposedResponse<G: PrimeGroup> {
    Simple(<CanonicalLinearRelation<G> as SigmaProtocol>::Response),
    And(Vec<ComposedResponse<G>>),
    Or(Vec<ComposedChallenge<G>>, Vec<ComposedResponse<G>>),
}

impl<G: PrimeGroup> ComposedResponse<G> {
    /// Conditionally select between two ComposedResponse values.
    /// This function performs constant-time selection of the response values.
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        match (a, b) {
            (ComposedResponse::Simple(a_scalars), ComposedResponse::Simple(b_scalars)) => {
                // Both vectors must have the same length for this to work
                debug_assert_eq!(a_scalars.len(), b_scalars.len());
                let selected: Vec<G::Scalar> = a_scalars
                    .iter()
                    .zip(b_scalars.iter())
                    .map(|(a, b)| G::Scalar::conditional_select(a, b, choice))
                    .collect();
                ComposedResponse::Simple(selected)
            }
            (ComposedResponse::And(a_responses), ComposedResponse::And(b_responses)) => {
                debug_assert_eq!(a_responses.len(), b_responses.len());
                let selected: Vec<ComposedResponse<G>> = a_responses
                    .iter()
                    .zip(b_responses.iter())
                    .map(|(a, b)| ComposedResponse::conditional_select(a, b, choice))
                    .collect();
                ComposedResponse::And(selected)
            }
            (
                ComposedResponse::Or(a_challenges, a_responses),
                ComposedResponse::Or(b_challenges, b_responses),
            ) => {
                debug_assert_eq!(a_challenges.len(), b_challenges.len());
                debug_assert_eq!(a_responses.len(), b_responses.len());

                let selected_challenges: Vec<ComposedChallenge<G>> = a_challenges
                    .iter()
                    .zip(b_challenges.iter())
                    .map(|(a, b)| G::Scalar::conditional_select(a, b, choice))
                    .collect();

                let selected_responses: Vec<ComposedResponse<G>> = a_responses
                    .iter()
                    .zip(b_responses.iter())
                    .map(|(a, b)| ComposedResponse::conditional_select(a, b, choice))
                    .collect();

                ComposedResponse::Or(selected_challenges, selected_responses)
            }
            _ => {
                unreachable!("Mismatched ComposedResponse variants in conditional_select");
            }
        }
    }
}

// Structure representing the Witness type of Protocol as SigmaProtocol
#[derive(Clone)]
pub enum ComposedWitness<G: PrimeGroup> {
    Simple(<CanonicalLinearRelation<G> as SigmaProtocol>::Witness),
    And(Vec<ComposedWitness<G>>),
    Or(Vec<ComposedWitness<G>>),
}

impl<G: PrimeGroup> ComposedWitness<G> {
    /// Create a [ComposedWitness] for an AND relation from the given list of witnesses.
    pub fn and<T: Into<ComposedWitness<G>>>(witness: impl IntoIterator<Item = T>) -> Self {
        Self::And(witness.into_iter().map(|x| x.into()).collect())
    }

    /// Create a [ComposedWitness] for an OR relation from the given list of witnesses.
    pub fn or<T: Into<ComposedWitness<G>>>(witness: impl IntoIterator<Item = T>) -> Self {
        Self::Or(witness.into_iter().map(|x| x.into()).collect())
    }
}

impl<G: PrimeGroup> From<<CanonicalLinearRelation<G> as SigmaProtocol>::Witness>
    for ComposedWitness<G>
{
    fn from(value: <CanonicalLinearRelation<G> as SigmaProtocol>::Witness) -> Self {
        Self::Simple(value)
    }
}

type ComposedChallenge<G> = <CanonicalLinearRelation<G> as SigmaProtocol>::Challenge;

const fn composed_challenge_size<G: PrimeGroup>() -> usize {
    (G::Scalar::NUM_BITS as usize).div_ceil(8)
}

impl<G: PrimeGroup + ConstantTimeEq + ConditionallySelectable> ComposedRelation<G> {
    fn is_witness_valid(&self, witness: &ComposedWitness<G>) -> Choice {
        match (self, witness) {
            (ComposedRelation::Simple(instance), ComposedWitness::Simple(witness)) => {
                instance.is_witness_valid(witness)
            }
            (ComposedRelation::And(instances), ComposedWitness::And(witnesses)) => instances
                .iter()
                .zip(witnesses)
                .fold(Choice::from(1), |bit, (instance, witness)| {
                    bit & instance.is_witness_valid(witness)
                }),
            (ComposedRelation::Or(instances), ComposedWitness::Or(witnesses)) => instances
                .iter()
                .zip(witnesses)
                .fold(Choice::from(0), |bit, (instance, witness)| {
                    bit | instance.is_witness_valid(witness)
                }),
            _ => Choice::from(0),
        }
    }

    fn prover_commit_simple(
        protocol: &CanonicalLinearRelation<G>,
        witness: &<CanonicalLinearRelation<G> as SigmaProtocol>::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<(ComposedCommitment<G>, ComposedProverState<G>), Error> {
        protocol.prover_commit(witness, rng).map(|(c, s)| {
            (
                ComposedCommitment::Simple(c),
                ComposedProverState::Simple(s),
            )
        })
    }

    fn prover_response_simple(
        instance: &CanonicalLinearRelation<G>,
        state: <CanonicalLinearRelation<G> as SigmaProtocol>::ProverState,
        challenge: &<CanonicalLinearRelation<G> as SigmaProtocol>::Challenge,
    ) -> Result<ComposedResponse<G>, Error> {
        instance
            .prover_response(state, challenge)
            .map(ComposedResponse::Simple)
    }

    fn prover_commit_and(
        protocols: &[ComposedRelation<G>],
        witnesses: &[ComposedWitness<G>],
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<(ComposedCommitment<G>, ComposedProverState<G>), Error> {
        if protocols.len() != witnesses.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let mut commitments = Vec::with_capacity(protocols.len());
        let mut prover_states = Vec::with_capacity(protocols.len());

        for (p, w) in protocols.iter().zip(witnesses.iter()) {
            let (c, s) = p.prover_commit(w, rng)?;
            commitments.push(c);
            prover_states.push(s);
        }

        Ok((
            ComposedCommitment::And(commitments),
            ComposedProverState::And(prover_states),
        ))
    }

    fn prover_response_and(
        instances: &[ComposedRelation<G>],
        prover_state: Vec<ComposedProverState<G>>,
        challenge: &ComposedChallenge<G>,
    ) -> Result<ComposedResponse<G>, Error> {
        if instances.len() != prover_state.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let responses: Result<Vec<_>, _> = instances
            .iter()
            .zip(prover_state)
            .map(|(p, s)| p.prover_response(s, challenge))
            .collect();

        Ok(ComposedResponse::And(responses?))
    }

    fn prover_commit_or(
        instances: &[ComposedRelation<G>],
        witnesses: &[ComposedWitness<G>],
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<(ComposedCommitment<G>, ComposedProverState<G>), Error>
    where
        G: ConditionallySelectable,
    {
        if instances.len() != witnesses.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let mut commitments = Vec::new();
        let mut prover_states = Vec::new();

        // Selector value set when the first valid witness is found.
        let mut valid_witness_found = Choice::from(0);
        for (i, w) in witnesses.iter().enumerate() {
            let (commitment, prover_state) = instances[i].prover_commit(w, rng)?;
            let (simulated_commitment, simulated_challenge, simulated_response) =
                instances[i].simulate_transcript(rng)?;

            let valid_witness = instances[i].is_witness_valid(w) & !valid_witness_found;
            let select_witness = valid_witness ;

            let commitment = ComposedCommitment::conditional_select(
                &simulated_commitment,
                &commitment,
                select_witness,
            );

            commitments.push(commitment);
            prover_states.push(ComposedOrProverStateEntry(
                select_witness,
                prover_state,
                simulated_challenge,
                simulated_response,
            ));

            valid_witness_found |= valid_witness;
        }

        if valid_witness_found.unwrap_u8() == 0 {
            Err(Error::InvalidInstanceWitnessPair)
        } else {
            Ok((
                ComposedCommitment::Or(commitments),
                ComposedProverState::Or(prover_states),
            ))
        }
    }

    fn prover_response_or(
        instances: &[ComposedRelation<G>],
        prover_state: ComposedOrProverState<G>,
        challenge: &ComposedChallenge<G>,
    ) -> Result<ComposedResponse<G>, Error> {
        let mut result_challenges = Vec::with_capacity(instances.len());
        let mut result_responses = Vec::with_capacity(instances.len());

        let mut witness_challenge = *challenge;
        for ComposedOrProverStateEntry(
            valid_witness,
            _prover_state,
            simulated_challenge,
            _simulated_response,
        ) in &prover_state
        {
            let c = G::Scalar::conditional_select(
                simulated_challenge,
                &G::Scalar::ZERO,
                *valid_witness,
            );
            witness_challenge -= c;
        }
        for (
            instance,
            ComposedOrProverStateEntry(
                valid_witness,
                prover_state,
                simulated_challenge,
                simulated_response,
            ),
        ) in instances.iter().zip(prover_state)
        {
            let challenge_i = G::Scalar::conditional_select(
                &simulated_challenge,
                &witness_challenge,
                valid_witness,
            );

            let response = instance.prover_response(prover_state, &challenge_i)?;
            let response = ComposedResponse::conditional_select(
                &simulated_response,
                &response,
                valid_witness,
            );

            result_challenges.push(challenge_i);
            result_responses.push(response.clone());
        }

        result_challenges.pop();
        Ok(ComposedResponse::Or(result_challenges, result_responses))
    }
}

impl<G: PrimeGroup + ConstantTimeEq + ConditionallySelectable> SigmaProtocol for ComposedRelation<G> {
    type Commitment = ComposedCommitment<G>;
    type ProverState = ComposedProverState<G>;
    type Response = ComposedResponse<G>;
    type Witness = ComposedWitness<G>;
    type Challenge = ComposedChallenge<G>;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), Error> {
        match (self, witness) {
            (ComposedRelation::Simple(p), ComposedWitness::Simple(w)) => {
                Self::prover_commit_simple(p, w, rng)
            }
            (ComposedRelation::And(ps), ComposedWitness::And(ws)) => {
                Self::prover_commit_and(ps, ws, rng)
            }
            (ComposedRelation::Or(ps), ComposedWitness::Or(witnesses)) => {
                Self::prover_commit_or(ps, witnesses, rng)
            }
            _ => Err(Error::InvalidInstanceWitnessPair),
        }
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, Error> {
        match (self, state) {
            (ComposedRelation::Simple(instance), ComposedProverState::Simple(state)) => {
                Self::prover_response_simple(instance, state, challenge)
            }
            (ComposedRelation::And(instances), ComposedProverState::And(prover_state)) => {
                Self::prover_response_and(instances, prover_state, challenge)
            }
            (ComposedRelation::Or(instances), ComposedProverState::Or(prover_state)) => {
                Self::prover_response_or(instances, prover_state, challenge)
            }
            _ => Err(Error::InvalidInstanceWitnessPair),
        }
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), Error> {
        match (self, commitment, response) {
            (
                ComposedRelation::Simple(p),
                ComposedCommitment::Simple(c),
                ComposedResponse::Simple(r),
            ) => p.verifier(c, challenge, r),
            (
                ComposedRelation::And(ps),
                ComposedCommitment::And(commitments),
                ComposedResponse::And(responses),
            ) => ps
                .iter()
                .zip(commitments)
                .zip(responses)
                .try_for_each(|((p, c), r)| p.verifier(c, challenge, r)),
            (
                ComposedRelation::Or(ps),
                ComposedCommitment::Or(commitments),
                ComposedResponse::Or(challenges, responses),
            ) => {
                let last_challenge = *challenge - challenges.iter().sum::<G::Scalar>();
                ps.iter()
                    .zip(commitments)
                    .zip(challenges.iter().chain(&Some(last_challenge)))
                    .zip(responses)
                    .try_for_each(|(((p, commitment), challenge), response)| {
                        p.verifier(commitment, challenge, response)
                    })
            }
            _ => Err(Error::InvalidInstanceWitnessPair),
        }
    }

    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8> {
        match (self, commitment) {
            (ComposedRelation::Simple(p), ComposedCommitment::Simple(c)) => {
                p.serialize_commitment(c)
            }
            (ComposedRelation::And(ps), ComposedCommitment::And(commitments))
            | (ComposedRelation::Or(ps), ComposedCommitment::Or(commitments)) => ps
                .iter()
                .zip(commitments)
                .flat_map(|(p, c)| p.serialize_commitment(c))
                .collect(),
            _ => unreachable!(),
        }
    }

    fn serialize_challenge(&self, challenge: &Self::Challenge) -> Vec<u8> {
        serialize_scalars::<G>(&[*challenge])
    }

    fn instance_label(&self) -> impl AsRef<[u8]> {
        match self {
            ComposedRelation::Simple(p) => {
                let label = p.instance_label();
                label.as_ref().to_vec()
            }
            ComposedRelation::And(ps) => {
                let mut bytes = Vec::new();
                for p in ps {
                    bytes.extend(p.instance_label().as_ref());
                }
                bytes
            }
            ComposedRelation::Or(ps) => {
                let mut bytes = Vec::new();
                for p in ps {
                    bytes.extend(p.instance_label().as_ref());
                }
                bytes
            }
        }
    }

    fn protocol_identifier(&self) -> impl AsRef<[u8]> {
        let mut hasher = Sha3_256::new();

        match self {
            ComposedRelation::Simple(p) => {
                // take the digest of the simple protocol id
                hasher.update([0u8; 32]);
                hasher.update(p.protocol_identifier());
            }
            ComposedRelation::And(protocols) => {
                let mut hasher = Sha3_256::new();
                hasher.update([1u8; 32]);
                for p in protocols {
                    hasher.update(p.protocol_identifier());
                }
            }
            ComposedRelation::Or(protocols) => {
                let mut hasher = Sha3_256::new();
                hasher.update([2u8; 32]);
                for p in protocols {
                    hasher.update(p.protocol_identifier());
                }
            }
        }

        hasher.finalize()
    }

    fn serialize_response(&self, response: &Self::Response) -> Vec<u8> {
        match (self, response) {
            (ComposedRelation::Simple(p), ComposedResponse::Simple(r)) => p.serialize_response(r),
            (ComposedRelation::And(ps), ComposedResponse::And(responses)) => {
                let mut bytes = Vec::new();
                for (i, p) in ps.iter().enumerate() {
                    bytes.extend(p.serialize_response(&responses[i]));
                }
                bytes
            }
            (ComposedRelation::Or(instances), ComposedResponse::Or(challenges, responses)) => {
                let mut bytes = Vec::new();

                // write challenges first
                for (x, c) in instances.iter().zip(challenges) {
                    bytes.extend(x.serialize_challenge(c));
                }

                for (x, r) in instances.iter().zip(responses) {
                    bytes.extend(x.serialize_response(r));
                }

                bytes
            }
            _ => unreachable!(),
        }
    }

    fn deserialize_commitment(&self, data: &[u8]) -> Result<Self::Commitment, Error> {
        match self {
            ComposedRelation::Simple(p) => {
                let c = p.deserialize_commitment(data)?;
                Ok(ComposedCommitment::Simple(c))
            }
            ComposedRelation::And(ps) | ComposedRelation::Or(ps) => {
                let mut cursor = 0;
                let mut commitments = Vec::with_capacity(ps.len());

                for p in ps {
                    let c = p.deserialize_commitment(&data[cursor..])?;
                    let size = p.serialize_commitment(&c).len();
                    cursor += size;
                    commitments.push(c);
                }

                Ok(match self {
                    ComposedRelation::And(_) => ComposedCommitment::And(commitments),
                    ComposedRelation::Or(_) => ComposedCommitment::Or(commitments),
                    _ => unreachable!(),
                })
            }
        }
    }

    fn deserialize_challenge(&self, data: &[u8]) -> Result<Self::Challenge, Error> {
        let scalars = deserialize_scalars::<G>(data, 1).ok_or(Error::VerificationFailure)?;
        Ok(scalars[0])
    }

    fn deserialize_response(&self, data: &[u8]) -> Result<Self::Response, Error> {
        match self {
            ComposedRelation::Simple(p) => {
                let r = p.deserialize_response(data)?;
                Ok(ComposedResponse::Simple(r))
            }
            ComposedRelation::And(ps) => {
                let mut cursor = 0;
                let mut responses = Vec::with_capacity(ps.len());
                for p in ps {
                    let r = p.deserialize_response(&data[cursor..])?;
                    let size = p.serialize_response(&r).len();
                    cursor += size;
                    responses.push(r);
                }
                Ok(ComposedResponse::And(responses))
            }
            ComposedRelation::Or(ps) => {
                let ch_bytes_len = composed_challenge_size::<G>();
                let challenges_size = (ps.len() - 1) * ch_bytes_len;
                let challenges_bytes = &data[..challenges_size];
                let response_bytes = &data[challenges_size..];
                let challenges = deserialize_scalars::<G>(challenges_bytes, ps.len() - 1)
                    .ok_or(Error::VerificationFailure)?;

                let mut cursor = 0;
                let mut responses = Vec::with_capacity(ps.len());
                for p in ps {
                    let r = p.deserialize_response(&response_bytes[cursor..])?;
                    let size = p.serialize_response(&r).len();
                    cursor += size;
                    responses.push(r);
                }
                Ok(ComposedResponse::Or(challenges, responses))
            }
        }
    }
}

impl<G: PrimeGroup + ConstantTimeEq + ConditionallySelectable> SigmaProtocolSimulator for ComposedRelation<G> {
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, Error> {
        match (self, response) {
            (ComposedRelation::Simple(p), ComposedResponse::Simple(r)) => Ok(
                ComposedCommitment::Simple(p.simulate_commitment(challenge, r)?),
            ),
            (ComposedRelation::And(ps), ComposedResponse::And(rs)) => {
                let commitments = ps
                    .iter()
                    .zip(rs)
                    .map(|(p, r)| p.simulate_commitment(challenge, r))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ComposedCommitment::And(commitments))
            }
            (ComposedRelation::Or(ps), ComposedResponse::Or(challenges, rs)) => {
                let last_challenge = *challenge - challenges.iter().sum::<G::Scalar>();
                let commitments = ps
                    .iter()
                    .zip(challenges.iter().chain(&Some(last_challenge)))
                    .zip(rs)
                    .map(|((p, ch), r)| p.simulate_commitment(ch, r))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ComposedCommitment::Or(commitments))
            }
            _ => unreachable!(),
        }
    }

    fn simulate_response<R: Rng + CryptoRng>(&self, rng: &mut R) -> Self::Response {
        match self {
            ComposedRelation::Simple(p) => ComposedResponse::Simple(p.simulate_response(rng)),
            ComposedRelation::And(ps) => {
                ComposedResponse::And(ps.iter().map(|p| p.simulate_response(rng)).collect())
            }
            ComposedRelation::Or(ps) => {
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());
                for _ in 0..ps.len() {
                    challenges.push(G::Scalar::random(&mut *rng));
                }
                for p in ps.iter() {
                    responses.push(p.simulate_response(&mut *rng));
                }
                ComposedResponse::Or(challenges, responses)
            }
        }
    }

    fn simulate_transcript<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Commitment, Self::Challenge, Self::Response), Error> {
        match self {
            ComposedRelation::Simple(p) => {
                let (c, ch, r) = p.simulate_transcript(rng)?;
                Ok((
                    ComposedCommitment::Simple(c),
                    ch,
                    ComposedResponse::Simple(r),
                ))
            }
            ComposedRelation::And(ps) => {
                let challenge = G::Scalar::random(&mut *rng);
                let mut responses = Vec::with_capacity(ps.len());
                for p in ps.iter() {
                    responses.push(p.simulate_response(&mut *rng));
                }
                let commitments = ps
                    .iter()
                    .enumerate()
                    .map(|(i, p)| p.simulate_commitment(&challenge, &responses[i]))
                    .collect::<Result<Vec<_>, Error>>()?;

                Ok((
                    ComposedCommitment::And(commitments),
                    challenge,
                    ComposedResponse::And(responses),
                ))
            }
            ComposedRelation::Or(ps) => {
                let mut commitments = Vec::with_capacity(ps.len());
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());

                for p in ps.iter() {
                    let (c, ch, r) = p.simulate_transcript(rng)?;
                    commitments.push(c);
                    challenges.push(ch);
                    responses.push(r);
                }
                let challenge = challenges.iter().sum();
                Ok((
                    ComposedCommitment::Or(commitments),
                    challenge,
                    ComposedResponse::Or(challenges, responses),
                ))
            }
        }
    }
}

impl<G: PrimeGroup + ConstantTimeEq + ConditionallySelectable> ComposedRelation<G> {
    /// Convert this Protocol into a non-interactive zero-knowledge proof
    /// using the Shake128DuplexSponge codec and a specified session identifier.
    ///
    /// This method provides a convenient way to create a NIZK from a Protocol
    /// without exposing the specific codec type to the API caller.
    ///
    /// # Parameters
    /// - `session_identifier`: Domain separator bytes for the Fiat-Shamir transform
    ///
    /// # Returns
    /// A `Nizk` instance ready for proving and verification
    pub fn into_nizk(
        self,
        session_identifier: &[u8],
    ) -> Nizk<ComposedRelation<G>, Shake128DuplexSponge<G>> {
        Nizk::new(session_identifier, self)
    }
}
