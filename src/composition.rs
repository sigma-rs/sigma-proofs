//! # Protocol Composition with AND/OR Logic
//!
//! This module defines the [`ComposedRelation`] enum, which generalizes the [`CanonicalLinearRelation`]
//! by enabling compositional logic between multiple proof instances.
//!
//! Specifically, it supports:
//! - Simple atomic proofs (e.g., discrete logarithm, Pedersen commitments)
//! - Conjunctions (`And`) of multiple sub-protocols
//! - Disjunctions (`Or`) of multiple sub-protocols
//! - Thresholds (`Threshold`) over multiple sub-protocols
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
    Threshold(usize, Vec<ComposedRelation<G>>),
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

    /// Create a [ComposedRelation] for a threshold relation from the given list of relations.
    pub fn threshold<T: Into<ComposedRelation<G>>>(
        threshold: usize,
        witness: impl IntoIterator<Item = T>,
    ) -> Self {
        Self::Threshold(threshold, witness.into_iter().map(|x| x.into()).collect())
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
    Threshold(Vec<ComposedCommitment<G>>),
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
            (ComposedCommitment::Or(a_commitments), ComposedCommitment::Or(b_commitments)) => {
                debug_assert_eq!(a_commitments.len(), b_commitments.len());
                let selected: Vec<ComposedCommitment<G>> = a_commitments
                    .iter()
                    .zip(b_commitments.iter())
                    .map(|(a, b)| ComposedCommitment::conditional_select(a, b, choice))
                    .collect();
                ComposedCommitment::Or(selected)
            }
            (
                ComposedCommitment::Threshold(a_commitments),
                ComposedCommitment::Threshold(b_commitments),
            ) => {
                debug_assert_eq!(a_commitments.len(), b_commitments.len());
                let selected: Vec<ComposedCommitment<G>> = a_commitments
                    .iter()
                    .zip(b_commitments.iter())
                    .map(|(a, b)| ComposedCommitment::conditional_select(a, b, choice))
                    .collect();
                ComposedCommitment::Threshold(selected)
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
    Threshold(ComposedThresholdProverState<G>),
}

pub type ComposedOrProverState<G> = Vec<ComposedOrProverStateEntry<G>>;
pub struct ComposedOrProverStateEntry<G: PrimeGroup + ConstantTimeEq>(
    Choice,
    ComposedProverState<G>,
    ComposedChallenge<G>,
    ComposedResponse<G>,
);

pub type ComposedThresholdProverState<G> = Vec<ComposedThresholdProverStateEntry<G>>;
pub struct ComposedThresholdProverStateEntry<G: PrimeGroup + ConstantTimeEq> {
    valid_witness: Choice,
    seeded_share: Choice,
    seeded_challenge: ComposedChallenge<G>,
    prover_state: ComposedProverState<G>,
    simulated_challenge: ComposedChallenge<G>,
    simulated_response: ComposedResponse<G>,
}

// Structure representing the Response type of Protocol as SigmaProtocol
#[derive(Clone)]
pub enum ComposedResponse<G: PrimeGroup> {
    Simple(<CanonicalLinearRelation<G> as SigmaProtocol>::Response),
    And(Vec<ComposedResponse<G>>),
    Or(Vec<ComposedChallenge<G>>, Vec<ComposedResponse<G>>),
    Threshold(Vec<ComposedChallenge<G>>, Vec<ComposedResponse<G>>),
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
            (
                ComposedResponse::Threshold(a_challenges, a_responses),
                ComposedResponse::Threshold(b_challenges, b_responses),
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

                ComposedResponse::Threshold(selected_challenges, selected_responses)
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
    Threshold(Vec<ComposedWitness<G>>),
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

    /// Create a [ComposedWitness] for a threshold relation from the given list of witnesses.
    pub fn threshold<T: Into<ComposedWitness<G>>>(
        witness: impl IntoIterator<Item = T>,
    ) -> Self {
        Self::Threshold(witness.into_iter().map(|x| x.into()).collect())
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

fn threshold_x<G: PrimeGroup>(index: usize) -> G::Scalar {
    G::Scalar::from((index + 1) as u64)
}

fn poly_mul_linear<G: PrimeGroup>(coeffs: &[G::Scalar], constant: G::Scalar) -> Vec<G::Scalar> {
    let mut out = vec![G::Scalar::ZERO; coeffs.len() + 1];
    for (i, coeff) in coeffs.iter().enumerate() {
        out[i] += *coeff * constant;
        out[i + 1] += *coeff;
    }
    out
}

fn interpolate_polynomial<G: PrimeGroup>(
    points: &[(G::Scalar, G::Scalar)],
) -> Result<Vec<G::Scalar>, Error> {
    if points.is_empty() {
        return Err(Error::InvalidInstanceWitnessPair);
    }

    let mut coeffs = vec![G::Scalar::ZERO; points.len()];

    for (i, (x_i, y_i)) in points.iter().enumerate() {
        let mut basis = vec![G::Scalar::ONE];
        let mut denom = G::Scalar::ONE;

        for (j, (x_j, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            denom *= *x_i - *x_j;
            basis = poly_mul_linear::<G>(&basis, -*x_j);
        }

        let denom_inv = denom.invert();
        if denom_inv.is_none().into() {
            return Err(Error::InvalidInstanceWitnessPair);
        }
        let scale = *y_i * denom_inv.unwrap_or(G::Scalar::ZERO);
        for (coeff, basis_coeff) in coeffs.iter_mut().zip(basis.iter()) {
            *coeff += *basis_coeff * scale;
        }
    }

    Ok(coeffs)
}

fn evaluate_polynomial<G: PrimeGroup>(coeffs: &[G::Scalar], x: G::Scalar) -> G::Scalar {
    coeffs
        .iter()
        .rev()
        .fold(G::Scalar::ZERO, |acc, coeff| acc * x + coeff)
}

fn expand_threshold_challenges<G: PrimeGroup>(
    threshold: usize,
    total: usize,
    challenge: G::Scalar,
    compressed_challenges: &[G::Scalar],
) -> Result<Vec<G::Scalar>, Error> {
    if threshold == 0 || threshold > total {
        return Err(Error::InvalidInstanceWitnessPair);
    }

    let degree = total - threshold;
    if compressed_challenges.len() != degree {
        return Err(Error::InvalidInstanceWitnessPair);
    }

    let mut points = Vec::with_capacity(degree + 1);
    points.push((G::Scalar::ZERO, challenge));
    for (index, share) in compressed_challenges.iter().enumerate() {
        points.push((threshold_x::<G>(index), *share));
    }

    let coeffs = interpolate_polynomial::<G>(&points)?;
    let mut challenges = Vec::with_capacity(total);
    for index in 0..total {
        challenges.push(evaluate_polynomial::<G>(&coeffs, threshold_x::<G>(index)));
    }

    Ok(challenges)
}

#[derive(Clone, Copy)]
struct ThresholdPoint<G: PrimeGroup> {
    x: G::Scalar,
    challenge: G::Scalar,
}

impl<G: PrimeGroup> ConditionallySelectable for ThresholdPoint<G>
where
    G::Scalar: ConditionallySelectable,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ThresholdPoint {
            x: G::Scalar::conditional_select(&a.x, &b.x, choice),
            challenge: G::Scalar::conditional_select(&a.challenge, &b.challenge, choice),
        }
    }
}

fn conditional_swap_point<G: PrimeGroup + ConditionallySelectable>(
    points: &mut [ThresholdPoint<G>],
    left: usize,
    right: usize,
    swap: Choice,
) {
    if left == right {
        return;
    }
    if left < right {
        let (head, tail) = points.split_at_mut(right);
        ThresholdPoint::conditional_swap(&mut head[left], &mut tail[0], swap);
    } else {
        let (head, tail) = points.split_at_mut(left);
        ThresholdPoint::conditional_swap(&mut tail[0], &mut head[right], swap);
    }
}

fn oroffcompact_points<G: PrimeGroup + ConditionallySelectable>(
    points: &mut [ThresholdPoint<G>],
    marks: &[Choice],
    offset: usize,
) {
    let n = points.len();
    if n <= 1 {
        return;
    }
    debug_assert_eq!(n, marks.len());
    debug_assert!(n.is_power_of_two());

    let half = n / 2;
    let mut m = 0usize;
    for mark in &marks[..half] {
        m += mark.unwrap_u8() as usize;
    }

    if n == 2 {
        let z = Choice::from((offset & 1) as u8);
        let b = ((!marks[0]) & marks[1]) ^ z;
        conditional_swap_point(points, 0, 1, b);
        return;
    }

    let offset_mod = offset % half;
    oroffcompact_points(&mut points[..half], &marks[..half], offset_mod);
    let offset_plus_m_mod = (offset + m) % half;
    oroffcompact_points(
        &mut points[half..],
        &marks[half..],
        offset_plus_m_mod,
    );

    let s = Choice::from(((offset_mod + m) >= half) as u8)
        ^ Choice::from((offset >= half) as u8);
    for i in 0..half {
        let b = s ^ Choice::from((i >= offset_plus_m_mod) as u8);
        conditional_swap_point(points, i, i + half, b);
    }
}

fn orcompact_points<G: PrimeGroup + ConditionallySelectable>(
    points: &mut [ThresholdPoint<G>],
    marks: &[Choice],
) {
    let n = points.len();
    if n == 0 {
        return;
    }
    debug_assert_eq!(n, marks.len());

    let n1 = 1usize << (usize::BITS as usize - 1 - n.leading_zeros() as usize);
    let n2 = n - n1;
    let mut m = 0usize;
    for mark in &marks[..n2] {
        m += mark.unwrap_u8() as usize;
    }

    if n2 > 0 {
        orcompact_points(&mut points[..n2], &marks[..n2]);
    }
    oroffcompact_points(&mut points[n2..], &marks[n2..], (n1 - n2 + m) % n1);

    for i in 0..n2 {
        let b = Choice::from((i >= m) as u8);
        conditional_swap_point(points, i, i + n1, b);
    }
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
            (ComposedRelation::Threshold(threshold, instances), ComposedWitness::Threshold(witnesses)) => {
                if *threshold == 0 || instances.len() != witnesses.len() {
                    return Choice::from(0);
                }
                let mut count = 0usize;
                for (instance, witness) in instances.iter().zip(witnesses) {
                    if instance.is_witness_valid(witness).unwrap_u8() == 1 {
                        count += 1;
                    }
                }
                Choice::from((count >= *threshold) as u8)
            }
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
            let select_witness = valid_witness;

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
            let response =
                ComposedResponse::conditional_select(&simulated_response, &response, valid_witness);

            result_challenges.push(challenge_i);
            result_responses.push(response.clone());
        }

        result_challenges.pop();
        Ok(ComposedResponse::Or(result_challenges, result_responses))
    }

    fn prover_commit_threshold(
        threshold: usize,
        instances: &[ComposedRelation<G>],
        witnesses: &[ComposedWitness<G>],
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<(ComposedCommitment<G>, ComposedProverState<G>), Error>
    where
        G: ConditionallySelectable,
    {
        if instances.len() != witnesses.len() || threshold == 0 || threshold > instances.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }
        let degree = instances.len() - threshold;

        let mut commitments = Vec::with_capacity(instances.len());
        let mut prover_states = Vec::with_capacity(instances.len());
        let mut invalid_count = 0usize;

        for (instance, witness) in instances.iter().zip(witnesses.iter()) {
            let (commitment, prover_state) = instance.prover_commit(witness, rng)?;
            let (sim_commitment, sim_challenge, sim_response) =
                instance.simulate_transcript(rng)?;

            let valid_witness = instance.is_witness_valid(witness);
            invalid_count += (!valid_witness).unwrap_u8() as usize;

            let commitment = ComposedCommitment::conditional_select(
                &sim_commitment,
                &commitment,
                valid_witness,
            );

            commitments.push(commitment);
            prover_states.push(ComposedThresholdProverStateEntry {
                valid_witness,
                seeded_share: Choice::from(0),
                seeded_challenge: G::Scalar::ZERO,
                prover_state,
                simulated_challenge: sim_challenge,
                simulated_response: sim_response,
            });
        }

        // Degree-(t-1) interpolation can only satisfy t fixed points.
        if invalid_count > degree {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let remaining_seeds = degree - invalid_count;
        let mut seeded_count = 0usize;
        for entry in prover_states.iter_mut() {
            let should_seed = Choice::from((seeded_count < remaining_seeds) as u8)
                & entry.valid_witness;
            let random_challenge = G::Scalar::random(&mut *rng);
            entry.seeded_share = should_seed;
            entry.seeded_challenge = G::Scalar::conditional_select(
                &entry.seeded_challenge,
                &random_challenge,
                should_seed,
            );
            seeded_count += should_seed.unwrap_u8() as usize;
        }

        Ok((
            ComposedCommitment::Threshold(commitments),
            ComposedProverState::Threshold(prover_states),
        ))
    }

    fn prover_response_threshold(
        threshold: usize,
        instances: &[ComposedRelation<G>],
        prover_state: ComposedThresholdProverState<G>,
        challenge: &ComposedChallenge<G>,
    ) -> Result<ComposedResponse<G>, Error> {
        if threshold == 0 || threshold > instances.len() || instances.len() != prover_state.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }
        let degree = instances.len() - threshold;
        let required_points = degree + 1;

        let mut points: Vec<ThresholdPoint<G>> = Vec::with_capacity(instances.len());
        let mut marks = Vec::with_capacity(instances.len());
        let mut marked_count = 0usize;

        for (index, entry) in prover_state.iter().enumerate() {
            let x = threshold_x::<G>(index);
            let use_simulated = !entry.valid_witness;
            let use_seeded = entry.seeded_share;
            let mark = use_simulated | use_seeded;
            let challenge = G::Scalar::conditional_select(
                &entry.seeded_challenge,
                &entry.simulated_challenge,
                use_simulated,
            );
            points.push(ThresholdPoint { x, challenge });
            marks.push(mark);
            marked_count += mark.unwrap_u8() as usize;
        }

        if marked_count != degree {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        orcompact_points(&mut points, &marks);

        let mut points = points
            .into_iter()
            .take(degree)
            .map(|point| (point.x, point.challenge))
            .collect::<Vec<_>>();
        points.insert(0, (G::Scalar::ZERO, *challenge));

        if points.len() != required_points {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let coeffs = interpolate_polynomial::<G>(&points)?;

        let mut challenges = Vec::with_capacity(instances.len());
        let mut responses = Vec::with_capacity(instances.len());

        for (index, (instance, entry)) in instances.iter().zip(prover_state).enumerate() {
            let x = threshold_x::<G>(index);
            let challenge_i = if entry.valid_witness.unwrap_u8() == 0 {
                entry.simulated_challenge
            } else if entry.seeded_share.unwrap_u8() == 1 {
                entry.seeded_challenge
            } else {
                evaluate_polynomial::<G>(&coeffs, x)
            };

            let response = instance.prover_response(entry.prover_state, &challenge_i)?;
            let response = ComposedResponse::conditional_select(
                &entry.simulated_response,
                &response,
                entry.valid_witness,
            );

            challenges.push(challenge_i);
            responses.push(response);
        }

        let degree = instances.len() - threshold;
        let compressed_challenges = challenges[..degree].to_vec();

        Ok(ComposedResponse::Threshold(
            compressed_challenges,
            responses,
        ))
    }
}

impl<G: PrimeGroup + ConstantTimeEq + ConditionallySelectable> SigmaProtocol
    for ComposedRelation<G>
{
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
            (ComposedRelation::Threshold(threshold, ps), ComposedWitness::Threshold(witnesses)) => {
                Self::prover_commit_threshold(*threshold, ps, witnesses, rng)
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
            (
                ComposedRelation::Threshold(threshold, instances),
                ComposedProverState::Threshold(prover_state),
            ) => Self::prover_response_threshold(*threshold, instances, prover_state, challenge),
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
            (
                ComposedRelation::Threshold(threshold, ps),
                ComposedCommitment::Threshold(commitments),
                ComposedResponse::Threshold(challenges, responses),
            ) => {
                if *threshold == 0
                    || *threshold > ps.len()
                    || commitments.len() != ps.len()
                    || challenges.len() != ps.len() - *threshold
                    || responses.len() != ps.len()
                {
                    return Err(Error::InvalidInstanceWitnessPair);
                }

                let full_challenges = expand_threshold_challenges::<G>(
                    *threshold,
                    ps.len(),
                    *challenge,
                    challenges,
                )?;

                ps.iter()
                    .zip(commitments)
                    .zip(full_challenges.iter())
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
            | (ComposedRelation::Or(ps), ComposedCommitment::Or(commitments))
            | (ComposedRelation::Threshold(_, ps), ComposedCommitment::Threshold(commitments)) => {
                ps.iter()
                    .zip(commitments)
                    .flat_map(|(p, c)| p.serialize_commitment(c))
                    .collect()
            }
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
            ComposedRelation::Threshold(threshold, ps) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&((*threshold as u64).to_le_bytes()));
                for p in ps {
                    bytes.extend(p.instance_label().as_ref());
                }
                bytes
            }
        }
    }

    fn protocol_identifier(&self) -> [u8; 64] {
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
                    hasher.update(p.protocol_identifier().as_ref());
                }
            }
            ComposedRelation::Or(protocols) => {
                let mut hasher = Sha3_256::new();
                hasher.update([2u8; 32]);
                for p in protocols {
                    hasher.update(p.protocol_identifier().as_ref());
                }
            }
            ComposedRelation::Threshold(threshold, protocols) => {
                hasher.update([3u8; 32]);
                hasher.update(((*threshold as u64).to_le_bytes()).as_ref());
                for p in protocols {
                    hasher.update(p.protocol_identifier().as_ref());
                }
            }
        }

        let mut protocol_id = [0u8; 64];
        protocol_id[..32].clone_from_slice(&hasher.finalize());
        protocol_id
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
            (
                ComposedRelation::Threshold(_, instances),
                ComposedResponse::Threshold(challenges, responses),
            ) => {
                let mut bytes = Vec::new();

                for (x, c) in instances.iter().take(challenges.len()).zip(challenges) {
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
            ComposedRelation::And(ps)
            | ComposedRelation::Or(ps)
            | ComposedRelation::Threshold(_, ps) => {
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
                    ComposedRelation::Threshold(_, _) => ComposedCommitment::Threshold(commitments),
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
            ComposedRelation::Threshold(threshold, ps) => {
                let ch_bytes_len = composed_challenge_size::<G>();
                let challenges_size = (ps.len().saturating_sub(*threshold)) * ch_bytes_len;
                let challenges_bytes = &data[..challenges_size];
                let response_bytes = &data[challenges_size..];
                let challenges =
                    deserialize_scalars::<G>(
                        challenges_bytes,
                        ps.len().saturating_sub(*threshold),
                    )
                        .ok_or(Error::VerificationFailure)?;

                let mut cursor = 0;
                let mut responses = Vec::with_capacity(ps.len());
                for p in ps {
                    let r = p.deserialize_response(&response_bytes[cursor..])?;
                    let size = p.serialize_response(&r).len();
                    cursor += size;
                    responses.push(r);
                }
                Ok(ComposedResponse::Threshold(challenges, responses))
            }
        }
    }
}

impl<G: PrimeGroup + ConstantTimeEq + ConditionallySelectable> SigmaProtocolSimulator
    for ComposedRelation<G>
{
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
            (
                ComposedRelation::Threshold(threshold, ps),
                ComposedResponse::Threshold(challenges, rs),
            ) => {
                if rs.len() != ps.len() || challenges.len() != ps.len() - threshold {
                    return Err(Error::InvalidInstanceWitnessPair);
                }
                let full_challenges = expand_threshold_challenges::<G>(
                    *threshold,
                    ps.len(),
                    *challenge,
                    challenges,
                )?;
                let commitments = ps
                    .iter()
                    .zip(full_challenges.iter())
                    .zip(rs)
                    .map(|((p, ch), r)| p.simulate_commitment(ch, r))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ComposedCommitment::Threshold(commitments))
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
            ComposedRelation::Threshold(threshold, ps) => {
                if *threshold == 0 || *threshold > ps.len() {
                    return ComposedResponse::Threshold(Vec::new(), Vec::new());
                }

                let degree = ps.len() - *threshold;
                let coeffs = (0..(degree + 1))
                    .map(|_| G::Scalar::random(&mut *rng))
                    .collect::<Vec<_>>();
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());
                for index in 0..ps.len() {
                    challenges.push(evaluate_polynomial::<G>(
                        &coeffs,
                        threshold_x::<G>(index),
                    ));
                }
                for p in ps.iter() {
                    responses.push(p.simulate_response(&mut *rng));
                }
                let compressed_challenges = challenges[..degree].to_vec();
                ComposedResponse::Threshold(compressed_challenges, responses)
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
            ComposedRelation::Threshold(threshold, ps) => {
                let response = self.simulate_response(rng);
                let (compressed_challenges, responses) = match &response {
                    ComposedResponse::Threshold(challenges, responses) => {
                        (challenges, responses)
                    }
                    _ => unreachable!(),
                };

                if *threshold == 0
                    || *threshold > ps.len()
                    || compressed_challenges.len() != ps.len() - *threshold
                {
                    return Err(Error::InvalidInstanceWitnessPair);
                }

                let challenge = G::Scalar::random(&mut *rng);
                let full_challenges = expand_threshold_challenges::<G>(
                    *threshold,
                    ps.len(),
                    challenge,
                    compressed_challenges,
                )?;
                let commitments = ps
                    .iter()
                    .zip(full_challenges.iter())
                    .zip(responses.iter())
                    .map(|((p, ch), r)| p.simulate_commitment(ch, r))
                    .collect::<Result<Vec<_>, Error>>()?;
                Ok((
                    ComposedCommitment::Threshold(commitments),
                    challenge,
                    response,
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
