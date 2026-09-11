//! # Protocol Composition with AND, OR, and Threshold.
//!
//! This module defines [`ComposedInstance`], which generalizes
//! [`Instance`].
//!
//! See `examples/simple_composition.rs` for an end-to-end example.

use alloc::vec::Vec;
use group::prime::PrimeGroup;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use self::ct::select_each;
use crate::codec::{GroupCodec, ScalarCodec};
use crate::errors::InvalidInstance;
use crate::linear_relation::{Instance, LinearRelation};
use crate::traits::SigmaProtocol;
use crate::MultiScalarMul;

mod ct;
mod poly;
mod protocol;

/// A protocol proving knowledge of a witness for a composition of linear
/// relations, generalizing [`Instance`] with AND/OR links.
///
/// Composition nodes are validated when they are constructed: an OR node
/// contains at least one branch, a threshold node with `n` branches has a
/// threshold in `0..=n`, and a claim node carries at least one term. An AND
/// node may be empty: the empty conjunction is true, like the empty relation,
/// and every branch of it is simulatable. The representation is private so
/// those invariants also hold recursively and cannot be bypassed with an enum
/// variant constructor.
#[derive(Clone)]
pub struct ComposedInstance<G: PrimeGroup>(InstanceNode<G>);

#[derive(Clone)]
pub(super) enum InstanceNode<G: PrimeGroup> {
    Simple(Instance<G>),
    And(Vec<ComposedInstance<G>>),
    Or(Vec<ComposedInstance<G>>),
    Threshold(usize, Vec<ComposedInstance<G>>),
    /// A publicly-evaluable claim `sum(coeff * elem) == identity` over
    /// `(coeff, elem)` pairs from the instance. Outside the specification's
    /// wire format: a claim branch contributes one commitment point and no
    /// response scalars, identically whether the claim is true or false, so
    /// proof shape and prover work never depend on the public values.
    Claim(Vec<(G::Scalar, G)>),
}

impl<G: PrimeGroup + ConstantTimeEq + ConditionallySelectable> ComposedInstance<G> {
    /// The AND of the given relations.
    ///
    /// The empty AND is the trivially true statement; it is accepted, and
    /// its proofs carry no commitment and no response.
    pub fn and<T: Into<ComposedInstance<G>>>(
        relations: impl IntoIterator<Item = T>,
    ) -> Result<Self, InvalidInstance> {
        let branches = relations.into_iter().map(Into::into).collect();
        Ok(Self(InstanceNode::And(branches)))
    }

    /// The OR of the given relations.
    ///
    /// Returns an error if the iterator is empty.
    pub fn or<T: Into<ComposedInstance<G>>>(
        relations: impl IntoIterator<Item = T>,
    ) -> Result<Self, InvalidInstance> {
        let branches = Self::nonempty_branches("OR", relations)?;
        Ok(Self(InstanceNode::Or(branches)))
    }

    /// The threshold relation over the given relations.
    ///
    /// For `n` branches, the threshold must be in `0..=n`. A threshold of
    /// zero is trivially true, whatever the branches; its proofs simulate
    /// every branch and transmit every branch challenge. In particular the
    /// 0-of-0 threshold, like the empty AND, has an empty NARG string.
    pub fn threshold<T: Into<ComposedInstance<G>>>(
        threshold: usize,
        relations: impl IntoIterator<Item = T>,
    ) -> Result<Self, InvalidInstance> {
        let branches = relations.into_iter().map(Into::into).collect::<Vec<_>>();
        if threshold > branches.len() {
            return Err(InvalidInstance::new(
                "threshold must not exceed the number of branches",
            ));
        }
        Ok(Self(InstanceNode::Threshold(threshold, branches)))
    }

    /// The public claim `sum(coeff * elem) == identity` over the given
    /// `(coeff, elem)` pairs.
    ///
    /// Returns an error if the iterator is empty: the empty sum is the
    /// identity, so such a branch would hold whatever the public values are.
    pub fn claim(pairs: impl IntoIterator<Item = (G::Scalar, G)>) -> Result<Self, InvalidInstance> {
        let pairs = pairs.into_iter().collect::<Vec<_>>();
        if pairs.is_empty() {
            return Err(InvalidInstance::new(
                "claim relation must have at least one term",
            ));
        }
        Ok(Self(InstanceNode::Claim(pairs)))
    }

    fn nonempty_branches<T: Into<ComposedInstance<G>>>(
        kind: &str,
        relations: impl IntoIterator<Item = T>,
    ) -> Result<Vec<Self>, InvalidInstance> {
        let branches = relations.into_iter().map(Into::into).collect::<Vec<_>>();
        if branches.is_empty() {
            return Err(InvalidInstance::new(alloc::format!(
                "{kind} relation must have at least one branch"
            )));
        }
        Ok(branches)
    }

    pub(super) fn node(&self) -> &InstanceNode<G> {
        &self.0
    }
}

impl<G: PrimeGroup> From<Instance<G>> for ComposedInstance<G> {
    fn from(value: Instance<G>) -> Self {
        ComposedInstance(InstanceNode::Simple(value))
    }
}

impl<G> TryFrom<LinearRelation<G>> for ComposedInstance<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    type Error = InvalidInstance;

    fn try_from(value: LinearRelation<G>) -> Result<Self, Self::Error> {
        Ok(Self(InstanceNode::Simple(value.compile()?)))
    }
}

/// The prover's commitment, shaped like the relation that produced it.
///
/// AND, OR, and threshold nodes commit identically — one commitment per
/// branch, in branch order — so they share a variant. Nothing reads the node
/// kind off a commitment: the relation directs every walk over this tree, and
/// carrying a tag would only create a disagreement that cannot arise.
#[derive(Clone)]
pub enum ComposedCommitment<G>
where
    G: PrimeGroup + ConditionallySelectable,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    Simple(Vec<G>),
    /// One commitment per branch of an AND, OR, or threshold node.
    Branches(Vec<ComposedCommitment<G>>),
    Claim(G),
}

impl<G: PrimeGroup> ComposedCommitment<G>
where
    G: ConditionallySelectable,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    /// Selects between two [`ComposedCommitment`] values in constant time.
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        match (a, b) {
            (ComposedCommitment::Simple(a), ComposedCommitment::Simple(b)) => {
                ComposedCommitment::Simple(select_each(a, b, choice, G::conditional_select))
            }
            (ComposedCommitment::Branches(a), ComposedCommitment::Branches(b)) => {
                ComposedCommitment::Branches(select_each(a, b, choice, Self::conditional_select))
            }
            (ComposedCommitment::Claim(a), ComposedCommitment::Claim(b)) => {
                ComposedCommitment::Claim(G::conditional_select(a, b, choice))
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
    G: PrimeGroup + ConstantTimeEq + ConditionallySelectable + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    Simple(<Instance<G> as SigmaProtocol>::ProverState),
    And(Vec<ComposedProverState<G>>),
    /// The branches of an OR or threshold node, which share out the challenge
    /// and so hold a simulated transcript beside the real one.
    Shares(Vec<ComposedBranchProverState<G>>),
    Claim,
}

/// One branch of an OR or threshold node, as the prover holds it between its
/// two moves.
///
/// Both nodes keep the same thing per branch: a real transcript begun by
/// `prover_commit_tolerant`, a whole simulated one, and the bit choosing
/// between them. They differ only in how the bit is decided — the first valid
/// witness for an OR, `ct::simulator_flags` for a threshold
/// — so the response move selects with the same polarity in both.
pub struct ComposedBranchProverState<G>
where
    G: PrimeGroup + ConstantTimeEq + ConditionallySelectable + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    /// Set when this branch's published transcript is the simulated one.
    use_simulator: Choice,
    prover_state: ComposedProverState<G>,
    simulated_challenge: ComposedChallenge<G>,
    simulated_response: ComposedResponse<G>,
}

/// The prover's response, shaped like the relation that produced it.
///
/// OR and threshold nodes both transmit challenge shares ahead of their branch
/// responses — `n - 1` of them for an OR, `n - t` for a threshold — and differ
/// only in how many, which the relation says. An AND node transmits none, so
/// it keeps a variant of its own rather than an always-empty share vector.
#[derive(Clone)]
pub enum ComposedResponse<G>
where
    G: PrimeGroup + ConditionallySelectable + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    Simple(<Instance<G> as SigmaProtocol>::Response),
    And(Vec<ComposedResponse<G>>),
    /// The transmitted challenge shares of an OR or threshold node, then one
    /// response per branch.
    Shares(Vec<ComposedChallenge<G>>, Vec<ComposedResponse<G>>),
    Claim,
}

impl<G> ComposedResponse<G>
where
    G: PrimeGroup + ConditionallySelectable + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    /// Selects between two [`ComposedResponse`] values in constant time.
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        match (a, b) {
            (ComposedResponse::Simple(a), ComposedResponse::Simple(b)) => {
                ComposedResponse::Simple(select_each(a, b, choice, G::Scalar::conditional_select))
            }
            (ComposedResponse::And(a), ComposedResponse::And(b)) => {
                ComposedResponse::And(select_each(a, b, choice, Self::conditional_select))
            }
            (
                ComposedResponse::Shares(a_challenges, a_responses),
                ComposedResponse::Shares(b_challenges, b_responses),
            ) => ComposedResponse::Shares(
                select_each(
                    a_challenges,
                    b_challenges,
                    choice,
                    G::Scalar::conditional_select,
                ),
                select_each(a_responses, b_responses, choice, Self::conditional_select),
            ),
            (ComposedResponse::Claim, ComposedResponse::Claim) => ComposedResponse::Claim,
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
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    Simple(Vec<G::Scalar>),
    And(Vec<ComposedWitness<G>>),
    Or(Vec<ComposedWitness<G>>),
    Threshold(Vec<ComposedWitness<G>>),
    /// The empty witness of a branch built with [`ComposedInstance::claim`].
    Claim,
}

impl<G> ComposedWitness<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    /// The witness for an AND of the given relations.
    pub fn and<T: Into<ComposedWitness<G>>>(witness: impl IntoIterator<Item = T>) -> Self {
        Self::And(witness.into_iter().map(|x| x.into()).collect())
    }

    /// The witness for an OR of the given relations.
    pub fn or<T: Into<ComposedWitness<G>>>(witness: impl IntoIterator<Item = T>) -> Self {
        Self::Or(witness.into_iter().map(|x| x.into()).collect())
    }

    /// The witness for a threshold relation over the given relations.
    pub fn threshold<T: Into<ComposedWitness<G>>>(witness: impl IntoIterator<Item = T>) -> Self {
        Self::Threshold(witness.into_iter().map(|x| x.into()).collect())
    }
}

impl<G> From<Vec<G::Scalar>> for ComposedWitness<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    fn from(value: Vec<G::Scalar>) -> Self {
        Self::Simple(value)
    }
}

type ComposedChallenge<G> = <Instance<G> as SigmaProtocol>::Challenge;
