//! The Sigma protocol and simulator implementations for composed relations.
//!
//! The non-interactive layer is not repeated here: [`ComposedInstance`]
//! implements [`NargCodec`], and the NARG flavors in
//! [`crate::fiat_shamir`] are generic over it.

use alloc::vec::Vec;
use ff::Field;
use group::prime::PrimeGroup;
use itertools::Itertools;
use spongefish::{DuplexSpongeInit, PrivateRng};
use spongefish::{NargReader, VerificationError};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::ct::{count_choices, oblivious_compact_points, simulator_flags, Evaluation};
use super::poly::{
    evaluate_polynomial, expand_threshold_challenges, interpolate_polynomial, threshold_x,
};
use super::{
    ComposedBranchProverState, ComposedChallenge, ComposedCommitment, ComposedInstance,
    ComposedProverState, ComposedResponse, ComposedWitness, InstanceNode,
};
use crate::codec::{
    deserialize_scalars, repr_is_le, serialize_scalar_le, serialize_scalars_into, GroupCodec,
    ScalarCodec,
};
use crate::errors::InvalidWitness;
use crate::fiat_shamir::NargCodec;
use crate::linear_relation::Instance;
use crate::traits::{SigmaProtocol, SigmaProtocolSimulator};
use crate::MultiScalarMul;

/// The variant labels opening a composed instance encoding. They share the
/// `sigma-proofs composition ` prefix and their suffixes start on five
/// distinct bytes, so no label is a prefix of another and the label is
/// self-delimiting: the encoding stays prefix-free without a length prefix on
/// the label itself. `labels_are_prefix_free` pins this.
const LABEL_SIMPLE: &[u8] = b"sigma-proofs composition SIMPLE";
const LABEL_AND: &[u8] = b"sigma-proofs composition AND";
const LABEL_OR: &[u8] = b"sigma-proofs composition OR";
const LABEL_THRESHOLD: &[u8] = b"sigma-proofs composition THRESHOLD";
const LABEL_CLAIM: &[u8] = b"sigma-proofs composition CLAIM";

impl<G> ComposedInstance<G>
where
    G: PrimeGroup + ConstantTimeEq + ConditionallySelectable + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    /// Serializes a commitment by walking the message tree: no shape
    /// information is written to the proof bytes.
    ///
    /// The relation is not consulted. It used to be, to check that the two
    /// trees agreed, but every commitment reaching here was built by walking
    /// this same relation — by `prover_commit`, or by `simulate_commitment`
    /// over a response that `deserialize_response_tree` shaped from the
    /// relation — so the check could not fire. Dropping it is what makes the
    /// encoding total.
    fn serialize_commitment_tree(commitment: &ComposedCommitment<G>, out: &mut Vec<u8>) {
        match commitment {
            ComposedCommitment::Simple(elems) => {
                G::serialize_elements_allowing_identity(elems, out);
            }
            ComposedCommitment::Branches(cs) => {
                for c in cs {
                    Self::serialize_commitment_tree(c, out);
                }
            }
            ComposedCommitment::Claim(elem) => elem.serialize_element_allowing_identity(out),
        }
    }

    /// The inverse of [`ComposedInstance::serialize_commitment_tree`]: the
    /// verifier knows the shape, so nothing shape-related is read from the
    /// untrusted bytes and recursion is bounded by the relation tree.
    fn deserialize_commitment_tree(
        &self,
        reader: &mut NargReader<'_>,
    ) -> Result<ComposedCommitment<G>, VerificationError> {
        let branches = match self.node() {
            InstanceNode::Simple(instance) => {
                let elems = (0..instance.num_equations())
                    .map(|_| G::deserialize_element(reader))
                    .collect::<Result<Vec<_>, VerificationError>>()?;
                return Ok(ComposedCommitment::Simple(elems));
            }
            InstanceNode::Claim(_) => {
                return Ok(ComposedCommitment::Claim(G::deserialize_element(reader)?));
            }
            InstanceNode::And(ps) | InstanceNode::Or(ps) => ps,
            InstanceNode::Threshold(_, ps) => ps,
        };
        Ok(ComposedCommitment::Branches(
            branches
                .iter()
                .map(|p| p.deserialize_commitment_tree(reader))
                .collect::<Result<Vec<_>, VerificationError>>()?,
        ))
    }

    /// Serializes a response by walking the message tree: OR nodes carry their
    /// first `n - 1` challenge shares, threshold nodes their `n - threshold`
    /// compressed shares, each via the scalar codec.
    ///
    /// Total for the same reason
    /// [`serialize_commitment_tree`][Self::serialize_commitment_tree] is, and
    /// one more: scalars have no unencodable value.
    fn serialize_response_tree(response: &ComposedResponse<G>, out: &mut Vec<u8>) {
        match response {
            ComposedResponse::Simple(scalars) => serialize_scalars_into(scalars, out),
            ComposedResponse::And(rs) => {
                for r in rs {
                    Self::serialize_response_tree(r, out);
                }
            }
            ComposedResponse::Shares(challenges, rs) => {
                serialize_scalars_into(challenges, out);
                for r in rs {
                    Self::serialize_response_tree(r, out);
                }
            }
            ComposedResponse::Claim => {}
        }
    }

    /// The inverse of [`ComposedInstance::serialize_response_tree`].
    fn deserialize_response_tree(
        &self,
        reader: &mut NargReader<'_>,
    ) -> Result<ComposedResponse<G>, VerificationError> {
        // As in `deserialize_commitment_tree`, the branch-carrying variants
        // share one walk. `AND` carries no challenge shares of its own; `OR`
        // and `THRESHOLD` differ only in how many they carry, and those come
        // first on the wire.
        let (branches, challenge_count) = match self.node() {
            InstanceNode::Simple(instance) => {
                let scalars = deserialize_scalars(reader, instance.num_scalars())?;
                return Ok(ComposedResponse::Simple(scalars));
            }
            InstanceNode::Claim(_) => return Ok(ComposedResponse::Claim),
            InstanceNode::And(ps) => {
                let responses = Self::deserialize_branch_responses(ps, reader)?;
                return Ok(ComposedResponse::And(responses));
            }
            InstanceNode::Or(ps) => (ps, ps.len().checked_sub(1).ok_or(VerificationError)?),
            InstanceNode::Threshold(threshold, ps) => match *threshold {
                0 => return Err(VerificationError),
                t => (ps, ps.len().checked_sub(t).ok_or(VerificationError)?),
            },
        };
        let challenges = deserialize_scalars(reader, challenge_count)?;
        let responses = Self::deserialize_branch_responses(branches, reader)?;
        Ok(ComposedResponse::Shares(challenges, responses))
    }

    /// One response per branch, in branch order.
    fn deserialize_branch_responses(
        branches: &[Self],
        reader: &mut NargReader<'_>,
    ) -> Result<Vec<ComposedResponse<G>>, VerificationError> {
        branches
            .iter()
            .map(|p| p.deserialize_response_tree(reader))
            .collect()
    }
}

/// A composed relation's commitment and response are the roots of the two
/// trees, so the tree codecs above are the whole wire format.
impl<G> NargCodec for ComposedInstance<G>
where
    G: PrimeGroup + ConstantTimeEq + ConditionallySelectable + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    /// Every canonically encoded group element is a valid commitment.
    fn is_valid_commitment(&self, _commitment: &ComposedCommitment<G>) -> bool {
        true
    }

    fn serialize_commitment(&self, commitment: &ComposedCommitment<G>) -> Vec<u8> {
        let mut out = Vec::new();
        Self::serialize_commitment_tree(commitment, &mut out);
        out
    }

    fn serialize_response(&self, response: &ComposedResponse<G>) -> Vec<u8> {
        let mut out = Vec::new();
        Self::serialize_response_tree(response, &mut out);
        out
    }

    fn deserialize_commitment(
        &self,
        reader: &mut NargReader<'_>,
    ) -> Result<ComposedCommitment<G>, VerificationError> {
        self.deserialize_commitment_tree(reader)
    }

    fn deserialize_response(
        &self,
        reader: &mut NargReader<'_>,
    ) -> Result<ComposedResponse<G>, VerificationError> {
        self.deserialize_response_tree(reader)
    }
}

impl<G> ComposedInstance<G>
where
    G: PrimeGroup + ConstantTimeEq + ConditionallySelectable + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    /// One simulated response per branch, in branch order — the walk every
    /// composite arm of the simulator starts from.
    fn simulate_branch_responses<H: DuplexSpongeInit<U = u8>>(
        branches: &[Self],
        rng: &mut PrivateRng<H>,
    ) -> Vec<ComposedResponse<G>> {
        branches
            .iter()
            .map(|branch| branch.simulate_response(&mut *rng))
            .collect()
    }

    /// The transmitted challenge shares of a simulated OR or threshold node.
    fn sample_shares<H: DuplexSpongeInit<U = u8>>(
        count: usize,
        rng: &mut PrivateRng<H>,
    ) -> Vec<ComposedChallenge<G>> {
        (0..count).map(|_| G::Scalar::sample(rng)).collect()
    }

    /// The per-branch challenges of an OR or threshold node, recovered from
    /// the shares its NARG string carries and the challenge the node was given.
    ///
    /// The two sharings differ, and this is the only place that difference is
    /// written: an OR shares additively, so the untransmitted last share is
    /// whatever the others leave over, and a threshold shares through the
    /// degree-`(n - t)` polynomial pinned at `P(0) = challenge`. Both reject a
    /// share count the relation does not call for — which is the whole of what
    /// the callers used to check for themselves, in two spellings that had
    /// drifted (only one of them rejected a zero threshold).
    ///
    /// Public data throughout: these are the transmitted shares.
    fn expand_shares(
        &self,
        challenge: &ComposedChallenge<G>,
        shares: &[ComposedChallenge<G>],
    ) -> Result<Vec<ComposedChallenge<G>>, VerificationError> {
        match self.node() {
            InstanceNode::Or(branches) => {
                if branches.len().checked_sub(1) != Some(shares.len()) {
                    return Err(VerificationError);
                }
                let last = *challenge - shares.iter().sum::<G::Scalar>();
                Ok(shares.iter().copied().chain(Some(last)).collect())
            }
            InstanceNode::Threshold(threshold, branches) => {
                expand_threshold_challenges::<G::Scalar>(
                    *threshold,
                    branches.len(),
                    *challenge,
                    shares,
                )
            }
            _ => Err(VerificationError),
        }
    }

    /// The public image `sum(coeff * elem)` of a claim; the claim is true
    /// iff it is the identity. Vartime: claim data is public.
    fn claim_image(pairs: &[(G::Scalar, G)]) -> G {
        let (coeffs, bases): (Vec<_>, Vec<_>) = pairs.iter().copied().unzip();
        G::msm_vartime(&coeffs, &bases)
    }

    fn is_witness_valid(&self, witness: &ComposedWitness<G>) -> Choice {
        match (self.node(), witness) {
            (InstanceNode::Simple(instance), ComposedWitness::Simple(witness)) => {
                // `prover_must_abort` reaches this before `prover_commit_tolerant`
                // runs the arity check, and `Instance::map` indexes the witness
                // unguarded. The specification requires the prover to *fail* on a
                // length mismatch, so report the pair invalid rather than panic.
                if witness.len() != instance.num_scalars() {
                    return Choice::from(0);
                }
                instance.is_witness_valid(witness)
            }
            (InstanceNode::Claim(pairs), ComposedWitness::Claim) => {
                Self::claim_image(pairs).is_identity()
            }
            (InstanceNode::And(instances), ComposedWitness::And(witnesses)) => {
                if instances.len() != witnesses.len() {
                    return Choice::from(0);
                }
                instances
                    .iter()
                    .zip_eq(witnesses)
                    .fold(Choice::from(1), |bit, (instance, witness)| {
                        bit & instance.is_witness_valid(witness)
                    })
            }
            (InstanceNode::Or(instances), ComposedWitness::Or(witnesses)) => {
                if instances.len() != witnesses.len() {
                    return Choice::from(0);
                }
                instances
                    .iter()
                    .zip_eq(witnesses)
                    .fold(Choice::from(0), |bit, (instance, witness)| {
                        bit | instance.is_witness_valid(witness)
                    })
            }
            (
                InstanceNode::Threshold(threshold, instances),
                ComposedWitness::Threshold(witnesses),
            ) => {
                if *threshold == 0 || instances.len() != witnesses.len() {
                    return Choice::from(0);
                }
                let valid_witnesses = instances
                    .iter()
                    .zip_eq(witnesses)
                    .map(|(instance, witness)| instance.is_witness_valid(witness))
                    .collect::<Vec<Choice>>();
                Choice::from((count_choices(&valid_witnesses) >= *threshold) as u8)
            }
            _ => Choice::from(0),
        }
    }

    /// Returns 1 if the witness does not have the shape described by the relation.
    ///
    /// Validity of the witness is deliberately not tested in this function.
    fn prover_must_abort(&self, witness: &ComposedWitness<G>) -> Choice {
        match (self.node(), witness) {
            (InstanceNode::Simple(_), ComposedWitness::Simple(_))
            | (InstanceNode::Claim(_), ComposedWitness::Claim) => Choice::from(0),
            (InstanceNode::And(ps), ComposedWitness::And(ws)) => {
                if ps.len() != ws.len() {
                    return Choice::from(1);
                }
                ps.iter()
                    .zip_eq(ws)
                    .fold(Choice::from(0), |acc, (p, w)| acc | p.prover_must_abort(w))
            }
            (InstanceNode::Or(_), ComposedWitness::Or(_))
            | (InstanceNode::Threshold(_, _), ComposedWitness::Threshold(_)) => Choice::from(0),
            _ => Choice::from(1),
        }
    }

    /// [`SigmaProtocol::prover_commit`] for a nested branch.
    fn prover_commit_tolerant(
        &self,
        witness: &ComposedWitness<G>,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> core::result::Result<(ComposedCommitment<G>, ComposedProverState<G>), InvalidWitness> {
        match (self.node(), witness) {
            (InstanceNode::Simple(p), ComposedWitness::Simple(w)) => {
                Self::prover_commit_simple(p, w, rng)
            }
            (InstanceNode::And(ps), ComposedWitness::And(ws)) => {
                Self::prover_commit_and(ps, ws, rng)
            }
            (InstanceNode::Or(ps), ComposedWitness::Or(ws)) => Self::prover_commit_or(ps, ws, rng),
            (InstanceNode::Threshold(threshold, ps), ComposedWitness::Threshold(ws)) => {
                Self::prover_commit_threshold(*threshold, ps, ws, rng)
            }
            // A claim's real commitment is the identity.
            (InstanceNode::Claim(_), ComposedWitness::Claim) => Ok((
                ComposedCommitment::Claim(G::identity()),
                ComposedProverState::Claim,
            )),
            _ => Err(InvalidWitness),
        }
    }

    fn prover_commit_simple(
        protocol: &Instance<G>,
        witness: &[G::Scalar],
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> core::result::Result<(ComposedCommitment<G>, ComposedProverState<G>), InvalidWitness> {
        protocol.prover_commit(witness, rng).map(|(c, s)| {
            (
                ComposedCommitment::Simple(c),
                ComposedProverState::Simple(s),
            )
        })
    }

    fn prover_response_simple(
        instance: &Instance<G>,
        state: <Instance<G> as SigmaProtocol>::ProverState,
        challenge: &<Instance<G> as SigmaProtocol>::Challenge,
    ) -> core::result::Result<ComposedResponse<G>, InvalidWitness> {
        instance
            .prover_response(state, challenge)
            .map(ComposedResponse::Simple)
    }

    fn prover_commit_and(
        protocols: &[ComposedInstance<G>],
        witnesses: &[ComposedWitness<G>],
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> core::result::Result<(ComposedCommitment<G>, ComposedProverState<G>), InvalidWitness> {
        if protocols.len() != witnesses.len() {
            return Err(InvalidWitness);
        }

        let mut commitments = Vec::with_capacity(protocols.len());
        let mut prover_states = Vec::with_capacity(protocols.len());

        for (p, w) in protocols.iter().zip_eq(witnesses.iter()) {
            let (commitment, s) = p.prover_commit_tolerant(w, rng)?;
            commitments.push(commitment);
            prover_states.push(s);
        }

        Ok((
            ComposedCommitment::Branches(commitments),
            ComposedProverState::And(prover_states),
        ))
    }

    fn prover_response_and(
        instances: &[ComposedInstance<G>],
        prover_state: Vec<ComposedProverState<G>>,
        challenge: &ComposedChallenge<G>,
    ) -> core::result::Result<ComposedResponse<G>, InvalidWitness> {
        if instances.len() != prover_state.len() {
            return Err(InvalidWitness);
        }

        let responses: core::result::Result<Vec<_>, InvalidWitness> = instances
            .iter()
            .zip_eq(prover_state)
            .map(|(p, s)| p.prover_response(s, challenge))
            .collect();

        Ok(ComposedResponse::And(responses?))
    }

    fn prover_commit_or(
        instances: &[ComposedInstance<G>],
        witnesses: &[ComposedWitness<G>],
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> core::result::Result<(ComposedCommitment<G>, ComposedProverState<G>), InvalidWitness>
    where
        G: ConditionallySelectable,
    {
        if instances.is_empty() || instances.len() != witnesses.len() {
            return Err(InvalidWitness);
        }

        let mut commitments = Vec::with_capacity(instances.len());
        let mut prover_states = Vec::with_capacity(instances.len());

        // Exactly one branch is proved for real: the first whose witness is
        // valid. Every other branch is simulated, and if no witness is valid,
        // all of them are.
        let mut valid_witness_found = Choice::from(0);
        for (instance, witness) in instances.iter().zip_eq(witnesses) {
            let (commitment, prover_state) = instance.prover_commit_tolerant(witness, rng)?;

            let (simulated_commitment, simulated_challenge, simulated_response) = instance
                .simulate_transcript(rng)
                .map_err(|_| InvalidWitness)?;

            let use_simulator = !(instance.is_witness_valid(witness) & !valid_witness_found);
            valid_witness_found |= !use_simulator;

            commitments.push(ComposedCommitment::conditional_select(
                &commitment,
                &simulated_commitment,
                use_simulator,
            ));
            prover_states.push(ComposedBranchProverState {
                use_simulator,
                prover_state,
                simulated_challenge,
                simulated_response,
            });
        }

        Ok((
            ComposedCommitment::Branches(commitments),
            ComposedProverState::Shares(prover_states),
        ))
    }

    fn prover_response_or(
        instances: &[ComposedInstance<G>],
        prover_states: Vec<ComposedBranchProverState<G>>,
        challenge: &ComposedChallenge<G>,
    ) -> core::result::Result<ComposedResponse<G>, InvalidWitness> {
        let mut result_challenges = Vec::with_capacity(instances.len());
        let mut result_responses = Vec::with_capacity(instances.len());

        if instances.is_empty() || instances.len() != prover_states.len() {
            return Err(InvalidWitness);
        }

        // The real branch gets whatever the simulated shares leave over.
        let mut witness_challenge = *challenge;
        for entry in &prover_states {
            witness_challenge -= G::Scalar::conditional_select(
                &G::Scalar::ZERO,
                &entry.simulated_challenge,
                entry.use_simulator,
            );
        }
        for (instance, entry) in instances.iter().zip_eq(prover_states) {
            let branch_challenge = G::Scalar::conditional_select(
                &witness_challenge,
                &entry.simulated_challenge,
                entry.use_simulator,
            );

            let response = instance.prover_response(entry.prover_state, &branch_challenge)?;
            let response = ComposedResponse::conditional_select(
                &response,
                &entry.simulated_response,
                entry.use_simulator,
            );

            result_challenges.push(branch_challenge);
            result_responses.push(response);
        }

        // The last share is the one the verifier recomputes.
        result_challenges.pop();
        Ok(ComposedResponse::Shares(
            result_challenges,
            result_responses,
        ))
    }

    fn prover_commit_threshold(
        threshold: usize,
        instances: &[ComposedInstance<G>],
        witnesses: &[ComposedWitness<G>],
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> core::result::Result<(ComposedCommitment<G>, ComposedProverState<G>), InvalidWitness>
    where
        G: ConditionallySelectable,
    {
        if instances.len() != witnesses.len() || threshold == 0 || threshold > instances.len() {
            return Err(InvalidWitness);
        }

        let valid_witnesses = instances
            .iter()
            .zip_eq(witnesses.iter())
            .map(|(x, w)| x.is_witness_valid(w))
            .collect::<Vec<Choice>>();

        // A degree-`(n - t)` polynomial is fixed by the global challenge and
        // `n - t` simulated branch points, leaving exactly `t = threshold`
        // branches to commit as real. Prefer simulation for invalid
        // witnesses. With fewer than `threshold` valid witnesses the flags
        // still come out well-formed (some invalid witnesses are marked real):
        // that only happens on a branch an enclosing composition simulates
        // (which discards this output), since the root rejects unprovable
        // statements in `prover_commit`. Every selection is oblivious to
        // witness validity.
        let use_simulator_flags = simulator_flags(&valid_witnesses, threshold);

        let mut commitments = Vec::with_capacity(instances.len());
        let mut prover_states = Vec::with_capacity(instances.len());
        for (i, (instance, witness)) in instances.iter().zip_eq(witnesses.iter()).enumerate() {
            let (commitment, prover_state) = instance.prover_commit_tolerant(witness, rng)?;

            let (simulated_commitment, simulated_challenge, simulated_response) = instance
                .simulate_transcript(rng)
                .map_err(|_| InvalidWitness)?;

            let use_simulator = use_simulator_flags[i];
            let commitment = ComposedCommitment::conditional_select(
                &commitment,
                &simulated_commitment,
                use_simulator,
            );
            commitments.push(commitment);
            prover_states.push(ComposedBranchProverState {
                use_simulator,
                prover_state,
                simulated_challenge,
                simulated_response,
            });
        }

        Ok((
            ComposedCommitment::Branches(commitments),
            ComposedProverState::Shares(prover_states),
        ))
    }

    fn prover_response_threshold(
        threshold: usize,
        instances: &[ComposedInstance<G>],
        prover_states: Vec<ComposedBranchProverState<G>>,
        challenge: &ComposedChallenge<G>,
    ) -> core::result::Result<ComposedResponse<G>, InvalidWitness> {
        if threshold == 0 || threshold > instances.len() || instances.len() != prover_states.len() {
            return Err(InvalidWitness);
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

        let coeffs =
            interpolate_polynomial::<G::Scalar>(&full_points).map_err(|_| InvalidWitness)?;
        // We already have the polynomial whose evaluations are the branch
        // challenges.  The wire format carries its first `degree`
        // evaluations, but expanding those again would interpolate the very
        // polynomial we just computed: cubic work in `degree`, plus a second
        // pass of evaluations.  Evaluate the existing coefficients once for
        // every branch and take the transmitted prefix from that same vector.
        // This is byte-for-byte equivalent because a polynomial of degree at
        // most `degree` is uniquely determined by P(0) and P(1)..P(degree).
        let expanded_challenges = (0..instances.len())
            .map(|index| evaluate_polynomial::<G::Scalar>(&coeffs, threshold_x::<G::Scalar>(index)))
            .collect::<Vec<_>>();
        let compressed_challenges = expanded_challenges
            .iter()
            .take(degree)
            .copied()
            .collect::<Vec<_>>();

        let mut responses = Vec::with_capacity(instances.len());

        for (i, (instance, prover_state)) in instances.iter().zip_eq(prover_states).enumerate() {
            let poly_challenge = expanded_challenges[i];
            let challenge = G::Scalar::conditional_select(
                &poly_challenge,
                &prover_state.simulated_challenge,
                prover_state.use_simulator,
            );

            let response = instance.prover_response(prover_state.prover_state, &challenge)?;
            let response = ComposedResponse::conditional_select(
                &response,
                &prover_state.simulated_response,
                prover_state.use_simulator,
            );

            responses.push(response);
        }

        Ok(ComposedResponse::Shares(compressed_challenges, responses))
    }
}

impl<G> SigmaProtocol for ComposedInstance<G>
where
    G: PrimeGroup + ConstantTimeEq + ConditionallySelectable + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    type Commitment = ComposedCommitment<G>;
    type ProverState = ComposedProverState<G>;
    type Response = ComposedResponse<G>;
    type Witness = ComposedWitness<G>;
    type Challenge = ComposedChallenge<G>;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> core::result::Result<(Self::Commitment, Self::ProverState), InvalidWitness> {
        // Unprovable statements are rejected here at the root, and only
        // here; nested branches commit tolerantly so an enclosing
        // composition can carry them as simulated branches.
        if self.prover_must_abort(witness).unwrap_u8() == 1 {
            return Err(InvalidWitness);
        }
        self.prover_commit_tolerant(witness, rng)
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> core::result::Result<Self::Response, InvalidWitness> {
        match (self.node(), state) {
            (InstanceNode::Simple(instance), ComposedProverState::Simple(state)) => {
                Self::prover_response_simple(instance, state, challenge)
            }
            (InstanceNode::And(instances), ComposedProverState::And(prover_state)) => {
                Self::prover_response_and(instances, prover_state, challenge)
            }
            (InstanceNode::Or(instances), ComposedProverState::Shares(prover_state)) => {
                Self::prover_response_or(instances, prover_state, challenge)
            }
            (
                InstanceNode::Threshold(threshold, instances),
                ComposedProverState::Shares(prover_state),
            ) => Self::prover_response_threshold(*threshold, instances, prover_state, challenge),
            (InstanceNode::Claim(_), ComposedProverState::Claim) => Ok(ComposedResponse::Claim),
            _ => Err(InvalidWitness),
        }
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), VerificationError> {
        match (self.node(), commitment, response) {
            (
                InstanceNode::Simple(p),
                ComposedCommitment::Simple(c),
                ComposedResponse::Simple(r),
            ) => p.verifier(c, challenge, r),
            (
                InstanceNode::And(ps),
                ComposedCommitment::Branches(commitments),
                ComposedResponse::And(responses),
            ) => {
                if ps.len() != commitments.len() || commitments.len() != responses.len() {
                    return Err(VerificationError);
                }
                ps.iter()
                    .zip_eq(commitments)
                    .zip_eq(responses)
                    .try_for_each(|((p, c), r)| p.verifier(c, challenge, r))
            }
            (
                InstanceNode::Or(ps) | InstanceNode::Threshold(_, ps),
                ComposedCommitment::Branches(commitments),
                ComposedResponse::Shares(shares, responses),
            ) => {
                if ps.len() != commitments.len() || ps.len() != responses.len() {
                    return Err(VerificationError);
                }
                let challenges = self.expand_shares(challenge, shares)?;
                ps.iter()
                    .zip_eq(commitments)
                    .zip_eq(&challenges)
                    .zip_eq(responses)
                    .try_for_each(|(((p, commitment), challenge), response)| {
                        p.verifier(commitment, challenge, response)
                    })
            }
            (
                InstanceNode::Claim(pairs),
                ComposedCommitment::Claim(commitment),
                ComposedResponse::Claim,
            ) => {
                // The claim's verification row:
                // `commitment + challenge * image == identity`.
                match bool::from((*commitment + Self::claim_image(pairs) * challenge).is_identity())
                {
                    true => Ok(()),
                    false => Err(VerificationError),
                }
            }
            _ => Err(VerificationError),
        }
    }

    /// The encoded composed instance.
    ///
    /// The composition structure is bound by the encoding itself: the variant
    /// label (`sigma-proofs composition` followed by `SIMPLE`, `AND`, `OR`,
    /// `THRESHOLD`, or `CLAIM`), the threshold and branch counts as 4-byte
    /// little-endian integers, and each sub-instance's label prefixed by its
    /// 4-byte length. A claim binds its pair count followed by each
    /// fixed-width `(coeff, elem)` pair, the element in its raw group encoding
    /// (identity admitted: the label only binds). The encoding is prefix-free,
    /// so structurally different compositions (and compositions of different
    /// sub-statements) absorb different bytes.
    fn encode_instance(&self) -> impl AsRef<[u8]> {
        fn extend_prefixed(bytes: &mut Vec<u8>, label: impl AsRef<[u8]>) {
            let label = label.as_ref();
            let len = u32::try_from(label.len()).expect("label length exceeds 2^32");
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(label);
        }

        fn len_u32(len: usize) -> [u8; 4] {
            u32::try_from(len)
                .expect("branch count exceeds 2^32")
                .to_le_bytes()
        }

        let mut bytes = Vec::new();
        match self.node() {
            InstanceNode::Simple(p) => {
                bytes.extend_from_slice(LABEL_SIMPLE);
                extend_prefixed(&mut bytes, p.encode_instance());
            }
            InstanceNode::And(ps) => {
                bytes.extend_from_slice(LABEL_AND);
                bytes.extend_from_slice(&len_u32(ps.len()));
                for p in ps {
                    extend_prefixed(&mut bytes, p.encode_instance());
                }
            }
            InstanceNode::Or(ps) => {
                bytes.extend_from_slice(LABEL_OR);
                bytes.extend_from_slice(&len_u32(ps.len()));
                for p in ps {
                    extend_prefixed(&mut bytes, p.encode_instance());
                }
            }
            InstanceNode::Threshold(threshold, ps) => {
                bytes.extend_from_slice(LABEL_THRESHOLD);
                bytes.extend_from_slice(&len_u32(*threshold));
                bytes.extend_from_slice(&len_u32(ps.len()));
                for p in ps {
                    extend_prefixed(&mut bytes, p.encode_instance());
                }
            }
            InstanceNode::Claim(pairs) => {
                bytes.extend_from_slice(LABEL_CLAIM);
                bytes.extend_from_slice(&len_u32(pairs.len()));
                let le = repr_is_le::<G::Scalar>();
                for (coeff, elem) in pairs {
                    serialize_scalar_le(coeff, le, &mut bytes);
                    bytes.extend_from_slice(elem.to_bytes().as_ref());
                }
            }
        }
        bytes
    }
}

impl<G> SigmaProtocolSimulator for ComposedInstance<G>
where
    G: PrimeGroup + ConstantTimeEq + ConditionallySelectable + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec + ConditionallySelectable,
{
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, VerificationError> {
        let commitment = match (self.node(), response) {
            (InstanceNode::Simple(p), ComposedResponse::Simple(r)) => {
                ComposedCommitment::Simple(p.simulate_commitment(challenge, r)?)
            }
            (InstanceNode::And(ps), ComposedResponse::And(rs)) => {
                if ps.len() != rs.len() {
                    return Err(VerificationError);
                }
                let commitments = ps
                    .iter()
                    .zip_eq(rs)
                    .map(|(p, r)| p.simulate_commitment(challenge, r))
                    .collect::<Result<Vec<_>, VerificationError>>()?;
                ComposedCommitment::Branches(commitments)
            }
            (
                InstanceNode::Or(ps) | InstanceNode::Threshold(_, ps),
                ComposedResponse::Shares(shares, rs),
            ) => {
                if rs.len() != ps.len() {
                    return Err(VerificationError);
                }
                let challenges = self.expand_shares(challenge, shares)?;
                let commitments = ps
                    .iter()
                    .zip_eq(&challenges)
                    .zip_eq(rs)
                    .map(|((p, ch), r)| p.simulate_commitment(ch, r))
                    .collect::<Result<Vec<_>, VerificationError>>()?;
                ComposedCommitment::Branches(commitments)
            }
            (InstanceNode::Claim(pairs), ComposedResponse::Claim) => {
                // Solves the claim's verification row for the commitment.
                ComposedCommitment::Claim(-(Self::claim_image(pairs) * challenge))
            }
            _ => return Err(VerificationError),
        };

        Ok(commitment)
    }

    fn simulate_response(
        &self,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> Self::Response {
        match self.node() {
            InstanceNode::Simple(p) => ComposedResponse::Simple(p.simulate_response(rng)),
            InstanceNode::And(ps) => {
                ComposedResponse::And(Self::simulate_branch_responses(ps, rng))
            }
            InstanceNode::Or(ps) => {
                let challenges: Vec<G::Scalar> = (0..ps.len().saturating_sub(1))
                    .map(|_| G::Scalar::sample(rng))
                    .collect();
                ComposedResponse::Shares(challenges, Self::simulate_branch_responses(ps, rng))
            }
            InstanceNode::Threshold(threshold, ps) => {
                if *threshold == 0 || *threshold > ps.len() {
                    return ComposedResponse::Shares(Vec::new(), Vec::new());
                }

                let degree = ps.len() - *threshold;
                let compressed_challenges: Vec<G::Scalar> =
                    (0..degree).map(|_| G::Scalar::sample(rng)).collect();
                ComposedResponse::Shares(
                    compressed_challenges,
                    Self::simulate_branch_responses(ps, rng),
                )
            }
            InstanceNode::Claim(_) => ComposedResponse::Claim,
        }
    }

    fn simulate_transcript(
        &self,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> Result<(Self::Commitment, Self::Challenge, Self::Response), VerificationError> {
        match self.node() {
            InstanceNode::Simple(p) => {
                let (c, ch, r) = p.simulate_transcript(rng)?;
                Ok((
                    ComposedCommitment::Simple(c),
                    ch,
                    ComposedResponse::Simple(r),
                ))
            }
            // Each composite arm draws its own randomness and then hands the
            // result to `simulate_commitment`, which solves every branch's
            // verification row for its commitment.
            InstanceNode::And(ps) => {
                let challenge = G::Scalar::sample(rng);
                let response = ComposedResponse::And(Self::simulate_branch_responses(ps, rng));
                Ok((
                    self.simulate_commitment(&challenge, &response)?,
                    challenge,
                    response,
                ))
            }
            InstanceNode::Or(ps) => {
                let share_count = ps.len().checked_sub(1).ok_or(VerificationError)?;
                let shares = Self::sample_shares(share_count, rng);
                let challenge = G::Scalar::sample(rng);
                let response =
                    ComposedResponse::Shares(shares, Self::simulate_branch_responses(ps, rng));
                Ok((
                    self.simulate_commitment(&challenge, &response)?,
                    challenge,
                    response,
                ))
            }
            InstanceNode::Threshold(threshold, ps) => {
                if *threshold == 0 || *threshold > ps.len() {
                    return Err(VerificationError);
                }
                let shares = Self::sample_shares(ps.len() - *threshold, rng);
                let responses = Self::simulate_branch_responses(ps, rng);
                let challenge = G::Scalar::sample(rng);
                let response = ComposedResponse::Shares(shares, responses);
                Ok((
                    self.simulate_commitment(&challenge, &response)?,
                    challenge,
                    response,
                ))
            }
            InstanceNode::Claim(_) => {
                let challenge = G::Scalar::sample(rng);
                let response = ComposedResponse::Claim;
                Ok((
                    self.simulate_commitment(&challenge, &response)?,
                    challenge,
                    response,
                ))
            }
        }
    }
}
