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

use alloc::{vec, vec::Vec};
use ff::{Field, PrimeField};
use group::prime::PrimeGroup;
#[cfg(feature = "std")]
use rand::{CryptoRng, Rng};
#[cfg(not(feature = "std"))]
use rand_core::{CryptoRng, RngCore as Rng};
use sha3::{Digest, Sha3_256};
use spongefish::{
    Decoding, Encoding, NargDeserialize, NargSerialize, VerificationError, VerificationResult,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::errors::InvalidInstance;
use crate::{
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
pub enum ComposedCommitment<G>
where
    G: PrimeGroup + ConditionallySelectable + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
    Simple(Vec<G>),
    And(Vec<ComposedCommitment<G>>),
    Or(Vec<ComposedCommitment<G>>),
    Threshold(Vec<ComposedCommitment<G>>),
}

impl<G: PrimeGroup> ComposedCommitment<G>
where
    G: ConditionallySelectable + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
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
pub enum ComposedProverState<G>
where
    G: PrimeGroup
        + ConstantTimeEq
        + ConditionallySelectable
        + Encoding<[u8]>
        + NargSerialize
        + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
    Simple(<CanonicalLinearRelation<G> as SigmaProtocol>::ProverState),
    And(Vec<ComposedProverState<G>>),
    Or(ComposedOrProverState<G>),
    Threshold(ComposedThresholdProverState<G>),
}

pub type ComposedOrProverState<G> = Vec<ComposedOrProverStateEntry<G>>;
pub struct ComposedOrProverStateEntry<G>(
    Choice,
    ComposedProverState<G>,
    ComposedChallenge<G>,
    ComposedResponse<G>,
)
where
    G: PrimeGroup
        + ConstantTimeEq
        + ConditionallySelectable
        + Encoding<[u8]>
        + NargSerialize
        + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable;

pub type ComposedThresholdProverState<G> = Vec<ComposedThresholdProverStateEntry<G>>;
pub struct ComposedThresholdProverStateEntry<G>
where
    G: PrimeGroup
        + ConstantTimeEq
        + ConditionallySelectable
        + Encoding<[u8]>
        + NargSerialize
        + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
    use_simulator: Choice,
    prover_state: ComposedProverState<G>,
    simulated_challenge: ComposedChallenge<G>,
    simulated_response: ComposedResponse<G>,
}

// Structure representing the Response type of Protocol as SigmaProtocol
#[derive(Clone)]
pub enum ComposedResponse<G>
where
    G: PrimeGroup + ConditionallySelectable + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
    Simple(Vec<<CanonicalLinearRelation<G> as SigmaProtocol>::Response>),
    And(Vec<ComposedResponse<G>>),
    Or(Vec<ComposedChallenge<G>>, Vec<ComposedResponse<G>>),
    Threshold(Vec<ComposedChallenge<G>>, Vec<ComposedResponse<G>>),
}

const TAG_SIMPLE: u8 = 0;
const TAG_AND: u8 = 1;
const TAG_OR: u8 = 2;
const TAG_THRESHOLD: u8 = 3;

fn read_u32(buf: &mut &[u8]) -> VerificationResult<u32> {
    if buf.len() < 4 {
        return Err(VerificationError);
    }
    let (head, tail) = buf.split_at(4);
    *buf = tail;
    Ok(u32::from_le_bytes(head.try_into().unwrap()))
}

fn write_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u32).to_le_bytes());
}

impl<G> Encoding<[u8]> for ComposedCommitment<G>
where
    G: PrimeGroup + ConditionallySelectable + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut out = Vec::new();
        match self {
            ComposedCommitment::Simple(elems) => {
                out.push(TAG_SIMPLE);
                write_len(&mut out, elems.len());
                for elem in elems {
                    elem.serialize_into_narg(&mut out);
                }
            }
            ComposedCommitment::And(cs) => {
                out.push(TAG_AND);
                write_len(&mut out, cs.len());
                for c in cs {
                    c.serialize_into_narg(&mut out);
                }
            }
            ComposedCommitment::Or(cs) => {
                out.push(TAG_OR);
                write_len(&mut out, cs.len());
                for c in cs {
                    c.serialize_into_narg(&mut out);
                }
            }
            ComposedCommitment::Threshold(cs) => {
                out.push(TAG_THRESHOLD);
                write_len(&mut out, cs.len());
                for c in cs {
                    c.serialize_into_narg(&mut out);
                }
            }
        }
        out
    }
}

impl<G> NargDeserialize for ComposedCommitment<G>
where
    G: PrimeGroup + ConditionallySelectable + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.is_empty() {
            return Err(VerificationError);
        }
        let (tag_bytes, rest) = buf.split_at(1);
        *buf = rest;
        match tag_bytes[0] {
            TAG_SIMPLE => {
                let len = read_u32(buf)? as usize;
                let mut elems = Vec::with_capacity(len);
                for _ in 0..len {
                    elems.push(G::deserialize_from_narg(buf)?);
                }
                Ok(ComposedCommitment::Simple(elems))
            }
            TAG_AND => {
                let len = read_u32(buf)? as usize;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    entries.push(ComposedCommitment::deserialize_from_narg(buf)?);
                }
                Ok(ComposedCommitment::And(entries))
            }
            TAG_OR => {
                let len = read_u32(buf)? as usize;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    entries.push(ComposedCommitment::deserialize_from_narg(buf)?);
                }
                Ok(ComposedCommitment::Or(entries))
            }
            TAG_THRESHOLD => {
                let len = read_u32(buf)? as usize;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    entries.push(ComposedCommitment::deserialize_from_narg(buf)?);
                }
                Ok(ComposedCommitment::Threshold(entries))
            }
            _ => Err(VerificationError),
        }
    }
}

impl<G> Encoding<[u8]> for ComposedResponse<G>
where
    G: PrimeGroup + ConditionallySelectable + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut out = Vec::new();
        match self {
            ComposedResponse::Simple(responses) => {
                out.push(TAG_SIMPLE);
                write_len(&mut out, responses.len());
                for r in responses {
                    r.serialize_into_narg(&mut out);
                }
            }
            ComposedResponse::And(entries) => {
                out.push(TAG_AND);
                write_len(&mut out, entries.len());
                for r in entries {
                    r.serialize_into_narg(&mut out);
                }
            }
            ComposedResponse::Or(challenges, responses) => {
                out.push(TAG_OR);
                write_len(&mut out, challenges.len());
                for c in challenges {
                    c.serialize_into_narg(&mut out);
                }
                write_len(&mut out, responses.len());
                for r in responses {
                    r.serialize_into_narg(&mut out);
                }
            }
            ComposedResponse::Threshold(challenges, responses) => {
                out.push(TAG_THRESHOLD);
                write_len(&mut out, challenges.len());
                for c in challenges {
                    c.serialize_into_narg(&mut out);
                }
                write_len(&mut out, responses.len());
                for r in responses {
                    r.serialize_into_narg(&mut out);
                }
            }
        }
        out
    }
}

impl<G> NargDeserialize for ComposedResponse<G>
where
    G: PrimeGroup + ConditionallySelectable + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
    fn deserialize_from_narg(buf: &mut &[u8]) -> VerificationResult<Self> {
        if buf.is_empty() {
            return Err(VerificationError);
        }
        let (tag_bytes, rest) = buf.split_at(1);
        *buf = rest;
        match tag_bytes[0] {
            TAG_SIMPLE => {
                let len = read_u32(buf)? as usize;
                let mut elems = Vec::with_capacity(len);
                for _ in 0..len {
                    elems.push(G::Scalar::deserialize_from_narg(buf)?);
                }
                Ok(ComposedResponse::Simple(elems))
            }
            TAG_AND => {
                let len = read_u32(buf)? as usize;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    entries.push(ComposedResponse::deserialize_from_narg(buf)?);
                }
                Ok(ComposedResponse::And(entries))
            }
            TAG_OR => {
                let ch_len = read_u32(buf)? as usize;
                let mut challenges = Vec::with_capacity(ch_len);
                for _ in 0..ch_len {
                    challenges.push(G::Scalar::deserialize_from_narg(buf)?);
                }
                let resp_len = read_u32(buf)? as usize;
                let mut responses = Vec::with_capacity(resp_len);
                for _ in 0..resp_len {
                    responses.push(ComposedResponse::deserialize_from_narg(buf)?);
                }
                Ok(ComposedResponse::Or(challenges, responses))
            }
            TAG_THRESHOLD => {
                let ch_len = read_u32(buf)? as usize;
                let mut challenges = Vec::with_capacity(ch_len);
                for _ in 0..ch_len {
                    challenges.push(G::Scalar::deserialize_from_narg(buf)?);
                }
                let resp_len = read_u32(buf)? as usize;
                let mut responses = Vec::with_capacity(resp_len);
                for _ in 0..resp_len {
                    responses.push(ComposedResponse::deserialize_from_narg(buf)?);
                }
                Ok(ComposedResponse::Threshold(challenges, responses))
            }
            _ => Err(VerificationError),
        }
    }
}

impl<G> ComposedResponse<G>
where
    G: PrimeGroup + ConditionallySelectable + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
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
pub enum ComposedWitness<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    Simple(<CanonicalLinearRelation<G> as SigmaProtocol>::Witness),
    And(Vec<ComposedWitness<G>>),
    Or(Vec<ComposedWitness<G>>),
    Threshold(Vec<ComposedWitness<G>>),
}

impl<G> ComposedWitness<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    /// Create a [ComposedWitness] for an AND relation from the given list of witnesses.
    pub fn and<T: Into<ComposedWitness<G>>>(witness: impl IntoIterator<Item = T>) -> Self {
        Self::And(witness.into_iter().map(|x| x.into()).collect())
    }

    /// Create a [ComposedWitness] for an OR relation from the given list of witnesses.
    pub fn or<T: Into<ComposedWitness<G>>>(witness: impl IntoIterator<Item = T>) -> Self {
        Self::Or(witness.into_iter().map(|x| x.into()).collect())
    }

    /// Create a [ComposedWitness] for a threshold relation from the given list of witnesses.
    pub fn threshold<T: Into<ComposedWitness<G>>>(witness: impl IntoIterator<Item = T>) -> Self {
        Self::Threshold(witness.into_iter().map(|x| x.into()).collect())
    }
}

impl<G> From<<CanonicalLinearRelation<G> as SigmaProtocol>::Witness> for ComposedWitness<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
    fn from(value: <CanonicalLinearRelation<G> as SigmaProtocol>::Witness) -> Self {
        Self::Simple(value)
    }
}

type ComposedChallenge<G> = <CanonicalLinearRelation<G> as SigmaProtocol>::Challenge;
fn threshold_x<F: PrimeField>(index: usize) -> F {
    F::from((index + 1) as u64)
}

fn poly_mul_linear<F: Field>(coeffs: &[F], constant: F) -> Vec<F> {
    let mut out = vec![F::ZERO; coeffs.len() + 1];
    for (i, coeff) in coeffs.iter().enumerate() {
        out[i] += *coeff * constant;
        out[i + 1] += *coeff;
    }
    out
}

fn interpolate_polynomial<F: Field>(points: &[Evaluation<F>]) -> Result<Vec<F>, Error> {
    if points.is_empty() {
        return Err(Error::InvalidInstanceWitnessPair);
    }

    let mut coeffs = vec![F::ZERO; points.len()];

    for (i, point_i) in points.iter().enumerate() {
        let mut basis = vec![F::ONE];
        let mut denom = F::ONE;

        for (j, point_j) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            denom *= point_i.x - point_j.x;
            basis = poly_mul_linear::<F>(&basis, -point_j.x);
        }

        let denom_inv = denom.invert();
        if denom_inv.is_none().into() {
            return Err(Error::InvalidInstanceWitnessPair);
        }
        let scale = point_i.y * denom_inv.unwrap_or(F::ZERO);
        for (coeff, basis_coeff) in coeffs.iter_mut().zip(basis.iter()) {
            *coeff += *basis_coeff * scale;
        }
    }

    Ok(coeffs)
}

fn evaluate_polynomial<F: Field>(coeffs: &[F], x: F) -> F {
    coeffs
        .iter()
        .rev()
        .fold(F::ZERO, |acc, coeff| acc * x + coeff)
}

fn expand_threshold_challenges<F: PrimeField>(
    threshold: usize,
    total: usize,
    challenge: F,
    compressed_challenges: &[F],
) -> Result<Vec<F>, Error> {
    if threshold == 0 || threshold > total {
        return Err(Error::InvalidInstanceWitnessPair);
    }

    let degree = total - threshold;
    if compressed_challenges.len() != degree {
        return Err(Error::InvalidInstanceWitnessPair);
    }

    let mut points = Vec::with_capacity(degree + 1);
    points.push(Evaluation {
        x: F::ZERO,
        y: challenge,
    });
    for (index, share) in compressed_challenges.iter().enumerate() {
        points.push(Evaluation {
            x: threshold_x::<F>(index),
            y: *share,
        });
    }

    let coeffs = interpolate_polynomial::<F>(&points)?;
    let mut challenges = Vec::with_capacity(total);
    for index in 0..total {
        challenges.push(evaluate_polynomial::<F>(&coeffs, threshold_x::<F>(index)));
    }

    Ok(challenges)
}

fn count_choices(choices: &[Choice]) -> usize {
    let mut sum: u32 = 0;
    for choice in choices {
        let inc = sum.wrapping_add(1);
        sum = u32::conditional_select(&sum, &inc, *choice);
    }
    sum as usize
}

#[derive(Clone, Copy)]
struct Evaluation<T> {
    x: T,
    y: T,
}

impl<T: ConditionallySelectable> ConditionallySelectable for Evaluation<T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Evaluation {
            x: T::conditional_select(&a.x, &b.x, choice),
            y: T::conditional_select(&a.y, &b.y, choice),
        }
    }
}

impl<T> From<(T, T)> for Evaluation<T> {
    fn from(value: (T, T)) -> Self {
        Evaluation {
            x: value.0,
            y: value.1,
        }
    }
}

fn conditional_swap_point<T: ConditionallySelectable>(
    points: &mut [T],
    left: usize,
    right: usize,
    swap: Choice,
) {
    if left == right {
        return;
    }
    if left < right {
        let (head, tail) = points.split_at_mut(right);
        T::conditional_swap(&mut head[left], &mut tail[0], swap);
    } else {
        let (head, tail) = points.split_at_mut(left);
        T::conditional_swap(&mut tail[0], &mut head[right], swap);
    }
}

fn oroffcompact_points<T: ConditionallySelectable>(
    points: &mut [T],
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
    oroffcompact_points(&mut points[half..], &marks[half..], offset_plus_m_mod);

    let s = Choice::from(((offset_mod + m) >= half) as u8) ^ Choice::from((offset >= half) as u8);
    for i in 0..half {
        let b = s ^ Choice::from((i >= offset_plus_m_mod) as u8);
        conditional_swap_point(points, i, i + half, b);
    }
}

fn oblivious_compact_points<T: ConditionallySelectable>(points: &mut [T], marks: &[Choice]) {
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
        oblivious_compact_points(&mut points[..n2], &marks[..n2]);
    }
    oroffcompact_points(&mut points[n2..], &marks[n2..], (n1 - n2 + m) % n1);

    for i in 0..n2 {
        let b = Choice::from((i >= m) as u8);
        conditional_swap_point(points, i, i + n1, b);
    }
}

impl<G> ComposedRelation<G>
where
    G: PrimeGroup
        + ConstantTimeEq
        + ConditionallySelectable
        + Encoding<[u8]>
        + NargSerialize
        + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
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
            (
                ComposedRelation::Threshold(threshold, instances),
                ComposedWitness::Threshold(witnesses),
            ) => {
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
            let (mut c, s) = p.prover_commit(w, rng)?;
            let commitment = c.pop().ok_or(Error::InvalidInstanceWitnessPair)?;
            if !c.is_empty() {
                return Err(Error::InvalidInstanceWitnessPair);
            }
            commitments.push(commitment);
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
            .map(|(p, s)| {
                let mut res = p.prover_response(s, challenge)?;
                res.pop().ok_or(Error::InvalidInstanceWitnessPair)
            })
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
            let (mut commitment_vec, prover_state) = instances[i].prover_commit(w, rng)?;
            let commitment = commitment_vec
                .pop()
                .ok_or(Error::InvalidInstanceWitnessPair)?;
            if !commitment_vec.is_empty() {
                return Err(Error::InvalidInstanceWitnessPair);
            }

            let (mut simulated_commitment_vec, simulated_challenge, mut simulated_response_vec) =
                instances[i].simulate_transcript(rng)?;
            let simulated_commitment = simulated_commitment_vec
                .pop()
                .ok_or(Error::InvalidInstanceWitnessPair)?;
            if !simulated_commitment_vec.is_empty() {
                return Err(Error::InvalidInstanceWitnessPair);
            }
            let simulated_response = simulated_response_vec
                .pop()
                .ok_or(Error::InvalidInstanceWitnessPair)?;
            if !simulated_response_vec.is_empty() {
                return Err(Error::InvalidInstanceWitnessPair);
            }

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

            let mut response_vec = instance.prover_response(prover_state, &challenge_i)?;
            let response = response_vec
                .pop()
                .ok_or(Error::InvalidInstanceWitnessPair)?;
            if !response_vec.is_empty() {
                return Err(Error::InvalidInstanceWitnessPair);
            }
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

        let valid_witnesses = instances
            .iter()
            .zip(witnesses.iter())
            .map(|(x, w)| x.is_witness_valid(w))
            .collect::<Vec<Choice>>();

        // Degree-(t-1) interpolation can only satisfy t fixed points.
        let invalid_count = instances.len() - count_choices(&valid_witnesses);
        if invalid_count > degree {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let mut remaining_seeds = (degree - invalid_count) as u32;
        let mut commitments = Vec::with_capacity(instances.len());
        let mut prover_states = Vec::with_capacity(instances.len());
        for (i, (instance, witness)) in instances.iter().zip(witnesses.iter()).enumerate() {
            let (mut commitment_vec, prover_state) = instance.prover_commit(witness, rng)?;
            let commitment = commitment_vec
                .pop()
                .ok_or(Error::InvalidInstanceWitnessPair)?;
            if !commitment_vec.is_empty() {
                return Err(Error::InvalidInstanceWitnessPair);
            }

            let (mut simulated_commitments, simulated_challenge, mut simulated_responses) =
                instance.simulate_transcript(rng)?;
            let simulated_commitment = simulated_commitments
                .pop()
                .ok_or(Error::InvalidInstanceWitnessPair)?;
            if !simulated_commitments.is_empty() {
                return Err(Error::InvalidInstanceWitnessPair);
            }
            let simulated_response = simulated_responses
                .pop()
                .ok_or(Error::InvalidInstanceWitnessPair)?;
            if !simulated_responses.is_empty() {
                return Err(Error::InvalidInstanceWitnessPair);
            }

            let valid_witness = valid_witnesses[i];
            let should_seed = valid_witness & Choice::from((remaining_seeds != 0) as u8);
            remaining_seeds = remaining_seeds.wrapping_sub(should_seed.unwrap_u8() as u32);
            let use_simulator = (!valid_witness) | should_seed;
            let commitment = ComposedCommitment::conditional_select(
                &commitment,
                &simulated_commitment,
                use_simulator,
            );
            commitments.push(commitment);
            prover_states.push(ComposedThresholdProverStateEntry {
                use_simulator,
                prover_state,
                simulated_challenge,
                simulated_response,
            });
        }

        Ok((
            ComposedCommitment::Threshold(commitments),
            ComposedProverState::Threshold(prover_states),
        ))
    }

    fn prover_response_threshold(
        threshold: usize,
        instances: &[ComposedRelation<G>],
        prover_states: ComposedThresholdProverState<G>,
        challenge: &ComposedChallenge<G>,
    ) -> Result<ComposedResponse<G>, Error> {
        if threshold == 0 || threshold > instances.len() || instances.len() != prover_states.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }
        let degree = instances.len() - threshold;

        let marks = prover_states
            .iter()
            .map(|entry| entry.use_simulator)
            .collect::<Vec<_>>();
        debug_assert_eq!(count_choices(&marks), degree);

        let mut points = prover_states
            .iter()
            .enumerate()
            .map(|(i, entry)| Evaluation {
                x: threshold_x::<G::Scalar>(i),
                y: entry.simulated_challenge,
            })
            .collect::<Vec<Evaluation<G::Scalar>>>();
        oblivious_compact_points(&mut points, &marks);
        points.drain(degree..);

        let mut full_points = Vec::with_capacity(degree + 1);
        full_points.push(Evaluation {
            x: G::Scalar::ZERO,
            y: *challenge,
        });
        full_points.extend_from_slice(&points);

        let coeffs = interpolate_polynomial::<G::Scalar>(&full_points)?;
        let mut compressed_challenges = Vec::with_capacity(degree);
        for index in 0..degree {
            compressed_challenges.push(evaluate_polynomial::<G::Scalar>(
                &coeffs,
                threshold_x::<G::Scalar>(index),
            ));
        }

        let expanded_challenges = expand_threshold_challenges::<G::Scalar>(
            threshold,
            instances.len(),
            *challenge,
            &compressed_challenges,
        )?;

        let mut responses = Vec::with_capacity(instances.len());

        for (i, (instance, prover_state)) in instances.iter().zip(prover_states).enumerate() {
            let poly_challenge = expanded_challenges[i];
            let challenge = G::Scalar::conditional_select(
                &poly_challenge,
                &prover_state.simulated_challenge,
                prover_state.use_simulator,
            );

            let mut response_vec =
                instance.prover_response(prover_state.prover_state, &challenge)?;
            let response = response_vec
                .pop()
                .ok_or(Error::InvalidInstanceWitnessPair)?;
            if !response_vec.is_empty() {
                return Err(Error::InvalidInstanceWitnessPair);
            }
            let response = ComposedResponse::conditional_select(
                &response,
                &prover_state.simulated_response,
                prover_state.use_simulator,
            );

            responses.push(response);
        }

        Ok(ComposedResponse::Threshold(
            compressed_challenges,
            responses,
        ))
    }
}

impl<G> SigmaProtocol for ComposedRelation<G>
where
    G: PrimeGroup
        + ConstantTimeEq
        + ConditionallySelectable
        + Encoding<[u8]>
        + NargSerialize
        + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
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
    ) -> Result<(Vec<Self::Commitment>, Self::ProverState), Error> {
        let (commitment, state) = match (self, witness) {
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
        }?;
        Ok((vec![commitment], state))
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Vec<Self::Response>, Error> {
        let response = match (self, state) {
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
        }?;
        Ok(vec![response])
    }

    fn verifier(
        &self,
        commitment: &[Self::Commitment],
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<(), Error> {
        let (commitment, response) = match (commitment.first(), response.first()) {
            (Some(c), Some(r)) => (c, r),
            _ => return Err(Error::InvalidInstanceWitnessPair),
        };

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
            ) => {
                if ps.len() != commitments.len() || commitments.len() != responses.len() {
                    return Err(Error::InvalidInstanceWitnessPair);
                }
                ps.iter()
                    .zip(commitments)
                    .zip(responses)
                    .try_for_each(|((p, c), r)| {
                        p.verifier(
                            core::slice::from_ref(c),
                            challenge,
                            core::slice::from_ref(r),
                        )
                    })
            }
            (
                ComposedRelation::Or(ps),
                ComposedCommitment::Or(commitments),
                ComposedResponse::Or(challenges, responses),
            ) => {
                if ps.len() != commitments.len() || commitments.len() != responses.len() {
                    return Err(Error::InvalidInstanceWitnessPair);
                }
                let last_challenge = *challenge - challenges.iter().sum::<G::Scalar>();
                ps.iter()
                    .zip(commitments)
                    .zip(challenges.iter().chain(&Some(last_challenge)))
                    .zip(responses)
                    .try_for_each(|(((p, commitment), challenge), response)| {
                        p.verifier(
                            core::slice::from_ref(commitment),
                            challenge,
                            core::slice::from_ref(response),
                        )
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

                let full_challenges = expand_threshold_challenges::<G::Scalar>(
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
                        p.verifier(
                            core::slice::from_ref(commitment),
                            challenge,
                            core::slice::from_ref(response),
                        )
                    })
            }
            _ => Err(Error::InvalidInstanceWitnessPair),
        }
    }

    fn commitment_len(&self) -> usize {
        1
    }

    fn response_len(&self) -> usize {
        1
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
                hasher.update([1u8; 32]);
                for p in protocols {
                    hasher.update(p.protocol_identifier().as_ref());
                }
            }
            ComposedRelation::Or(protocols) => {
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
}

impl<G> SigmaProtocolSimulator for ComposedRelation<G>
where
    G: PrimeGroup
        + ConstantTimeEq
        + ConditionallySelectable
        + Encoding<[u8]>
        + NargSerialize
        + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<Vec<Self::Commitment>, Error> {
        let response = response.first().ok_or(Error::InvalidInstanceWitnessPair)?;
        let commitment = match (self, response) {
            (ComposedRelation::Simple(p), ComposedResponse::Simple(r)) => {
                ComposedCommitment::Simple(p.simulate_commitment(challenge, r)?)
            }
            (ComposedRelation::And(ps), ComposedResponse::And(rs)) => {
                let commitments = ps
                    .iter()
                    .zip(rs)
                    .map(|(p, r)| {
                        p.simulate_commitment(challenge, core::slice::from_ref(r))
                            .and_then(|mut c| c.pop().ok_or(Error::InvalidInstanceWitnessPair))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                ComposedCommitment::And(commitments)
            }
            (ComposedRelation::Or(ps), ComposedResponse::Or(challenges, rs)) => {
                let last_challenge = *challenge - challenges.iter().sum::<G::Scalar>();
                let commitments = ps
                    .iter()
                    .zip(challenges.iter().chain(&Some(last_challenge)))
                    .zip(rs)
                    .map(|((p, ch), r)| {
                        p.simulate_commitment(ch, core::slice::from_ref(r))
                            .and_then(|mut c| c.pop().ok_or(Error::InvalidInstanceWitnessPair))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                ComposedCommitment::Or(commitments)
            }
            (
                ComposedRelation::Threshold(threshold, ps),
                ComposedResponse::Threshold(challenges, rs),
            ) => {
                if rs.len() != ps.len() || challenges.len() != ps.len() - threshold {
                    return Err(Error::InvalidInstanceWitnessPair);
                }

                let full_challenges = expand_threshold_challenges::<G::Scalar>(
                    *threshold,
                    ps.len(),
                    *challenge,
                    challenges,
                )?;
                let commitments = ps
                    .iter()
                    .zip(full_challenges.iter())
                    .zip(rs)
                    .map(|((p, ch), r)| {
                        p.simulate_commitment(ch, core::slice::from_ref(r))
                            .and_then(|mut c| c.pop().ok_or(Error::InvalidInstanceWitnessPair))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                ComposedCommitment::Threshold(commitments)
            }
            _ => unreachable!(),
        };

        Ok(vec![commitment])
    }

    fn simulate_response<R: Rng + CryptoRng>(&self, rng: &mut R) -> Vec<Self::Response> {
        let response = match self {
            ComposedRelation::Simple(p) => ComposedResponse::Simple(p.simulate_response(rng)),
            ComposedRelation::And(ps) => {
                let responses = ps
                    .iter()
                    .map(|p| {
                        let mut r = p.simulate_response(rng);
                        r.pop().ok_or(Error::InvalidInstanceWitnessPair)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .expect("simulate_response invariant");
                ComposedResponse::And(responses)
            }
            ComposedRelation::Or(ps) => {
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());
                for _ in 0..ps.len() {
                    challenges.push(G::Scalar::random(&mut *rng));
                }
                for p in ps.iter() {
                    let mut r = p.simulate_response(&mut *rng);
                    let resp = r
                        .pop()
                        .expect("simulate_response should return at least one element");
                    responses.push(resp);
                }
                ComposedResponse::Or(challenges, responses)
            }
            ComposedRelation::Threshold(threshold, ps) => {
                if *threshold == 0 || *threshold > ps.len() {
                    return vec![ComposedResponse::Threshold(Vec::new(), Vec::new())];
                }

                let degree = ps.len() - *threshold;
                let mut compressed_challenges = Vec::with_capacity(degree);
                let mut responses = Vec::with_capacity(ps.len());
                for _ in 0..degree {
                    compressed_challenges.push(G::Scalar::random(&mut *rng));
                }
                for p in ps.iter() {
                    let mut r = p.simulate_response(&mut *rng);
                    let response = r
                        .pop()
                        .expect("simulate_response should return at least one element");
                    responses.push(response);
                }
                ComposedResponse::Threshold(compressed_challenges, responses)
            }
        };
        vec![response]
    }

    fn simulate_transcript<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Vec<Self::Commitment>, Self::Challenge, Vec<Self::Response>), Error> {
        match self {
            ComposedRelation::Simple(p) => {
                let (c, ch, r) = p.simulate_transcript(rng)?;
                Ok((
                    vec![ComposedCommitment::Simple(c)],
                    ch,
                    vec![ComposedResponse::Simple(r)],
                ))
            }
            ComposedRelation::And(ps) => {
                let challenge = G::Scalar::random(&mut *rng);
                let mut responses = Vec::with_capacity(ps.len());
                for p in ps.iter() {
                    let mut resp = p.simulate_response(&mut *rng);
                    let response = resp.pop().ok_or(Error::InvalidInstanceWitnessPair)?;
                    if !resp.is_empty() {
                        return Err(Error::InvalidInstanceWitnessPair);
                    }
                    responses.push(response);
                }
                let commitments = ps
                    .iter()
                    .enumerate()
                    .map(|(i, p)| {
                        p.simulate_commitment(&challenge, &[responses[i].clone()])
                            .and_then(|mut c| {
                                let first = c.pop().ok_or(Error::InvalidInstanceWitnessPair)?;
                                if !c.is_empty() {
                                    return Err(Error::InvalidInstanceWitnessPair);
                                }
                                Ok(first)
                            })
                    })
                    .collect::<Result<Vec<_>, Error>>()?;

                Ok((
                    vec![ComposedCommitment::And(commitments)],
                    challenge,
                    vec![ComposedResponse::And(responses)],
                ))
            }
            ComposedRelation::Or(ps) => {
                let mut challenges = Vec::with_capacity(ps.len() - 1);
                let mut responses = Vec::with_capacity(ps.len());
                for _ in 0..ps.len() - 1 {
                    challenges.push(G::Scalar::random(&mut *rng));
                }
                for p in ps.iter() {
                    let mut resp = p.simulate_response(&mut *rng);
                    let response = resp.pop().ok_or(Error::InvalidInstanceWitnessPair)?;
                    if !resp.is_empty() {
                        return Err(Error::InvalidInstanceWitnessPair);
                    }
                    responses.push(response);
                }

                let mut commitments = Vec::with_capacity(ps.len());
                for i in 0..ps.len() {
                    let mut commitment = ps[i].simulate_commitment(
                        &if i == ps.len() - 1 {
                            challenges.iter().fold(G::Scalar::ZERO, |acc, x| acc - x)
                        } else {
                            challenges[i]
                        },
                        &[responses[i].clone()],
                    )?;
                    let commitment = commitment.pop().ok_or(Error::InvalidInstanceWitnessPair)?;
                    commitments.push(commitment);
                }

                Ok((
                    vec![ComposedCommitment::Or(commitments)],
                    challenges.iter().sum::<G::Scalar>(),
                    vec![ComposedResponse::Or(challenges, responses)],
                ))
            }
            ComposedRelation::Threshold(threshold, ps) => {
                if *threshold == 0 || *threshold > ps.len() {
                    return Err(Error::InvalidInstanceWitnessPair);
                }

                let degree = ps.len() - *threshold;
                let mut compressed_challenges = Vec::with_capacity(degree);
                for _ in 0..degree {
                    compressed_challenges.push(G::Scalar::random(&mut *rng));
                }

                let mut responses = Vec::with_capacity(ps.len());
                for p in ps.iter() {
                    let mut resp = p.simulate_response(&mut *rng);
                    let response = resp.pop().ok_or(Error::InvalidInstanceWitnessPair)?;
                    if !resp.is_empty() {
                        return Err(Error::InvalidInstanceWitnessPair);
                    }
                    responses.push(response);
                }

                let challenge = G::Scalar::random(&mut *rng);
                let full_challenges = expand_threshold_challenges(
                    *threshold,
                    ps.len(),
                    challenge,
                    &compressed_challenges,
                )?;
                let commitments = ps
                    .iter()
                    .zip(full_challenges.iter())
                    .zip(responses.iter())
                    .map(|((p, ch), r)| {
                        p.simulate_commitment(ch, core::slice::from_ref(r))
                            .and_then(|mut c| {
                                let first = c.pop().ok_or(Error::InvalidInstanceWitnessPair)?;
                                if !c.is_empty() {
                                    return Err(Error::InvalidInstanceWitnessPair);
                                }
                                Ok(first)
                            })
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                Ok((
                    vec![ComposedCommitment::Threshold(commitments)],
                    challenge,
                    vec![ComposedResponse::Threshold(
                        compressed_challenges,
                        responses,
                    )],
                ))
            }
        }
    }
}

impl<G> ComposedRelation<G>
where
    G: PrimeGroup
        + ConstantTimeEq
        + ConditionallySelectable
        + Encoding<[u8]>
        + NargSerialize
        + NargDeserialize,
    G::Scalar:
        Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]> + ConditionallySelectable,
{
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
    pub fn into_nizk(self, session_identifier: &[u8]) -> Nizk<ComposedRelation<G>> {
        Nizk::new(session_identifier, self)
    }
}
