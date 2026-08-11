//! The validated instance of the sigma-protocols specification.
//!
//! This module is private; [`Instance`] is re-exported from
//! [`linear_relation`][super] and carries the documentation.

use alloc::format;
use alloc::vec::Vec;

use ff::Field;
use group::prime::PrimeGroup;
use itertools::Itertools;
use spongefish::{Encoding, NargDeserialize, NargReader};
use subtle::{Choice, ConstantTimeEq};

use crate::codec::{
    deserialize_scalar_le, repr_is_le, serialize_scalar_le, GroupCodec, ScalarCodec,
};
use crate::errors::InvalidInstance;
use crate::msm::MultiScalarMul;

/// One equation of the linear relation (Section "Representation").
///
/// The equation states `image = terms`, where both sides are linear
/// combinations of the instance's group elements:
///
/// - `image` (the left-hand side) is the list of `(element_index, coeff)`
///   pairs; the image element is `sum(coeff * elements[element_index])`.
/// - `terms` (the right-hand side) is the list of
///   `(scalar_index, element_index, coeff)` triples, each contributing
///   `coeff * witness[scalar_index] * elements[element_index]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Equation<G: PrimeGroup> {
    /// The image terms `(element_index, coeff)`.
    pub image: Vec<(u32, G::Scalar)>,
    /// The right-hand side terms `(scalar_index, element_index, coeff)`.
    pub terms: Vec<(u32, u32, G::Scalar)>,
}

impl<G: PrimeGroup> Equation<G> {
    /// Folds this equation's verification row, scaled by `randomness`, into a
    /// per-element weight accumulator: the coefficients that
    /// `randomness * (challenge * image - map(response))` puts on the
    /// instance's group elements.
    ///
    /// Both fused verifiers are this fold plus one MSM entry per commitment —
    /// [`verifier_with_randomness`][crate::traits::SigmaProtocol::verifier_with_randomness]
    /// over the powers of one squeezed scalar, and
    /// [`verify_batch`][crate::verify_batch] over an independent squeeze per
    /// equation — so the algebra they check is stated once, here.
    ///
    /// # Panics
    ///
    /// The indices come from a validated instance (checks 4 and 6), which
    /// bounds them by its own `num_elements()` and `num_scalars()`. Panics if
    /// `weights` is shorter than the former or `response` than the latter; the
    /// callers check the response length, which is the one that comes off the
    /// wire.
    #[allow(clippy::indexing_slicing)]
    pub(crate) fn accumulate_weights(
        &self,
        randomness: G::Scalar,
        challenge: &G::Scalar,
        response: &[G::Scalar],
        weights: &mut [G::Scalar],
    ) {
        let image_weight = randomness * challenge;
        for &(element_index, coeff) in &self.image {
            weights[element_index as usize] += image_weight * coeff;
        }
        for &(scalar_index, element_index, coeff) in &self.terms {
            weights[element_index as usize] -= randomness * coeff * response[scalar_index as usize];
        }
    }
}

/// The narrower of the two equivalent ways to evaluate one equation.
/// Chosen entirely from public instance data at construction.
#[derive(Clone, Debug)]
enum EvaluationPlan<G: PrimeGroup> {
    /// One precomputed effective base per scalar used by the equation.
    ByScalar(Vec<(u32, G)>),
    /// Combine witness coefficients at runtime, one entry per element used.
    ByElement,
}

const UNUSED_SCALAR_SLOT: u32 = u32::MAX;

/// The paired inputs to one effective-base MSM.
struct MsmTerms<G: PrimeGroup>(Vec<G::Scalar>, Vec<G>);

impl<G: PrimeGroup + MultiScalarMul> MsmTerms<G> {
    fn new() -> Self {
        Self(Vec::new(), Vec::new())
    }

    fn push(&mut self, coefficient: G::Scalar, base: G) {
        self.0.push(coefficient);
        self.1.push(base);
    }

    fn effective_base(&self) -> G {
        G::msm_vartime(&self.0, &self.1)
    }
}

fn clear_scalar_groups(scalar_slots: &mut [u32], grouped_scalars: &mut Vec<u32>) {
    for scalar_index in grouped_scalars.drain(..) {
        scalar_slots[scalar_index as usize] = UNUSED_SCALAR_SLOT;
    }
}

/// A validated instance for the linear-map Sigma Protocol.
///
/// An `Instance` is the compiled
/// [`LinearRelation`][super::LinearRelation] of
/// draft-irtf-cfrg-sigma-protocols, Section "Representation".
///
/// It contains a list of group elements (with the group generator fixed at index `0`)
/// and a list of equations whose image and right-hand-side terms carry explicit scalar
/// coefficients.
///
/// The only ways to obtain an `Instance` are
/// [`Instance::new`] (used by
/// [`LinearRelation::compile`][super::LinearRelation::compile]) and
/// [`Instance::deserialize`]; both run the specification's `ValidateInstance`
/// (checks 1-10), so every value of this type satisfies the same acceptance
/// criteria regardless of how it was built.
///
/// # No empty instance
///
/// Every `Instance` has at least one equation, to be spec-conforming and to prevent trivial
/// breaks of simulation extractability where multiple degenerate instances are valid for the
/// NARG string "".
#[derive(Clone)]
pub struct Instance<G: PrimeGroup> {
    /// The group elements of the statement.
    /// Note: `elements[0]` is the group generator.
    elements: Vec<G>,
    /// The equations of the statement.
    equations: Vec<Equation<G>>,
    /// The image of the linear morphism.
    image: Vec<G>,
    /// Number of witness scalars, derived and checked during validation.
    /// Protocol entry points ask for it repeatedly, so keep the O(1) result
    /// beside the other immutable instance caches.
    num_scalars: usize,
    /// Per equation, a compiled evaluator that uses the narrower of its
    /// distinct-scalar and distinct-element dimensions.
    ///
    /// The triples in [`Equation::terms`] are the canonical wire format and
    /// remain untouched. Evaluation can fold public coefficients into one
    /// effective base per scalar, but only keeps that form when it does not
    /// widen the MSM compared with grouping terms by element.
    evaluation_plans: Vec<EvaluationPlan<G>>,
    /// The encoded instance ([`Instance::serialize`]), computed once at
    /// construction time.
    label: Vec<u8>,
}

// Preserve the pre-cache `Debug` representation: execution plans and the
// scalar-count cache are derived data, not additional statement state.
impl<G: PrimeGroup> core::fmt::Debug for Instance<G> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Instance")
            .field("elements", &self.elements)
            .field("equations", &self.equations)
            .field("image", &self.image)
            .field("label", &self.label)
            .finish()
    }
}

impl<G> Instance<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    /// Build an instance from its parts, running the specification's
    /// `ValidateInstance` (checks 1-10).
    ///
    /// `elements[0]` must be the group generator.
    pub fn new(elements: Vec<G>, equations: Vec<Equation<G>>) -> Result<Self, InvalidInstance> {
        let mut instance = Self {
            elements,
            equations,
            image: Vec::new(),
            num_scalars: 0,
            evaluation_plans: Vec::new(),
            label: Vec::new(),
        };
        let (image, num_scalars, evaluation_plans) = instance.validate()?;
        instance.image = image;
        instance.num_scalars = num_scalars;
        instance.evaluation_plans = evaluation_plans;
        // Only after validation: `serialize` may not be called on an instance
        // whose elements have not been checked against the identity (check 8).
        //
        // Always serialized, never taken from the caller — including in
        // [`Instance::deserialize`], whose input is an encoding of this very
        // instance. Adopting those bytes would save one serialization and
        // make the label whatever arrived on the wire, which is the canonical
        // encoding only as long as every curve's decoder is canonical. That
        // is a property of each `GroupCodec` impl rather than of this type,
        // and getting it wrong would not fail loudly: it would bind the
        // transcript to a non-canonical encoding, so two encodings of one
        // statement would derive two different challenges.
        instance.label = instance.serialize();
        Ok(instance)
    }

    /// `ValidateInstance` of the specification: checks 1-10 of Section
    /// "Instance validation". Errors carry the number of the failed check.
    /// Returns the computed image, scalar count, and effective-base execution
    /// plan, all cached by the constructor.
    #[allow(clippy::type_complexity)]
    fn validate(&self) -> Result<(Vec<G>, usize, Vec<EvaluationPlan<G>>), InvalidInstance> {
        let num_elements = self.elements.len();

        // Check 1: at least one equation.
        if self.equations.is_empty() {
            return Err(InvalidInstance::check(1, "the instance has no equations"));
        }

        // Check 3: counts fit in u32 (indices are u32 by construction).
        if u32::try_from(self.equations.len()).is_err() || u32::try_from(num_elements).is_err() {
            return Err(InvalidInstance::check(3, "count exceeds 2^32"));
        }

        let mut element_used = alloc::vec![false; num_elements];
        let mut max_scalar: Option<u32> = None;
        let mut total_terms: usize = 0;
        for equation in &self.equations {
            // Check 2: non-empty image and terms lists.
            if equation.image.is_empty() || equation.terms.is_empty() {
                return Err(InvalidInstance::check(
                    2,
                    "every equation must have non-empty image and terms",
                ));
            }
            // Check 3 (counts per equation).
            if u32::try_from(equation.image.len()).is_err()
                || u32::try_from(equation.terms.len()).is_err()
            {
                return Err(InvalidInstance::check(3, "term count exceeds 2^32"));
            }
            // Check 4: every element index references a group element.
            for &(element_index, _) in &equation.image {
                let slot = element_used
                    .get_mut(element_index as usize)
                    .ok_or_else(|| {
                        InvalidInstance::check(
                            4,
                            format!("image element index {element_index} out of range"),
                        )
                    })?;
                *slot = true;
            }
            total_terms += equation.terms.len();
            for &(scalar_index, element_index, _) in &equation.terms {
                let slot = element_used
                    .get_mut(element_index as usize)
                    .ok_or_else(|| {
                        InvalidInstance::check(
                            4,
                            format!("term element index {element_index} out of range"),
                        )
                    })?;
                *slot = true;
                max_scalar = Some(max_scalar.map_or(scalar_index, |m| m.max(scalar_index)));
            }
        }

        // Check 5: every element other than the generator (index 0) appears in
        // at least one equation.
        if let Some(unused) = element_used.iter().skip(1).position(|used| !used) {
            return Err(InvalidInstance::check(
                5,
                format!("group element {} is not used by any equation", unused + 1),
            ));
        }

        // Check 6: every scalar index up to the maximum appears in the terms.
        // The early bound caps the allocation below on untrusted input.
        let num_scalars = max_scalar.map_or(0, |m| m as usize + 1);
        if num_scalars > total_terms {
            return Err(InvalidInstance::check(
                6,
                "scalar indices exceed the number of terms",
            ));
        }
        let mut scalar_used = alloc::vec![false; num_scalars];
        for equation in &self.equations {
            for &(scalar_index, _, _) in &equation.terms {
                scalar_used[scalar_index as usize] = true;
            }
        }
        if let Some(unused) = scalar_used.iter().position(|used| !used) {
            return Err(InvalidInstance::check(
                6,
                format!("scalar index {unused} does not appear in any equation"),
            ));
        }

        // Check 7: elements[0] is the group generator.
        if self.elements.first() != Some(&G::generator()) {
            return Err(InvalidInstance::check(
                7,
                "elements[0] must be the group generator",
            ));
        }

        // Check 8: no element is the identity.
        for (i, element) in self.elements.iter().enumerate() {
            if element.is_identity().into() {
                return Err(InvalidInstance::check(
                    8,
                    format!("group element {i} is the identity"),
                ));
            }
        }

        // Check 9: no image element is the identity.
        let image = self.compute_image();
        for (i, image_element) in image.iter().enumerate() {
            if image_element.is_identity().into() {
                return Err(InvalidInstance::check(
                    9,
                    format!("the image of equation {i} is the identity"),
                ));
            }
        }

        // Check 10: for every scalar there is at least one equation in which
        // its effective base (the sum of coeff * element over the terms
        // carrying that scalar) is not the identity. Compile the runtime plan
        // while checking this, retaining only effective bases the chosen plan
        // will actually use.
        let evaluation_plans = self.compile_evaluation_plans(num_scalars)?;

        Ok((image, num_scalars, evaluation_plans))
    }

    /// Compile the wire-format term triples into the bases used to evaluate
    /// the linear map. Grouping is driven entirely by public instance data.
    fn compile_evaluation_plans(
        &self,
        num_scalars: usize,
    ) -> Result<Vec<EvaluationPlan<G>>, InvalidInstance> {
        let mut scalar_slots = alloc::vec![UNUSED_SCALAR_SLOT; num_scalars];
        let mut grouped_scalars = Vec::new();
        let mut msm_terms = Vec::new();
        let mut element_seen = alloc::vec![false; self.elements.len()];
        let mut touched_elements = Vec::new();
        let mut plans = Vec::with_capacity(self.equations.len());
        let mut has_nontrivial_base = alloc::vec![false; num_scalars];

        for equation in &self.equations {
            for &(scalar_index, element_index, _) in &equation.terms {
                if !element_seen[element_index as usize] {
                    element_seen[element_index as usize] = true;
                    touched_elements.push(element_index);
                }
                if scalar_slots[scalar_index as usize] == UNUSED_SCALAR_SLOT {
                    scalar_slots[scalar_index as usize] = grouped_scalars.len() as u32;
                    grouped_scalars.push(scalar_index);
                }
            }

            // Equivalent scalar/element groupings let the runtime use the
            // narrower dimension; shared-element sums stay one-base MSMs.
            msm_terms.clear();
            let plan = if grouped_scalars.len() <= touched_elements.len() {
                msm_terms.resize_with(grouped_scalars.len(), MsmTerms::new);
                for &(scalar_index, element_index, coefficient) in &equation.terms {
                    let group = scalar_slots[scalar_index as usize] as usize;
                    msm_terms[group].push(coefficient, self.elements[element_index as usize]);
                }
                let row = grouped_scalars
                    .iter()
                    .enumerate()
                    .map(|(group, &scalar_index)| {
                        let base = msm_terms[group].effective_base();
                        if !bool::from(base.is_identity()) {
                            has_nontrivial_base[scalar_index as usize] = true;
                        }
                        (scalar_index, base)
                    })
                    .collect();
                EvaluationPlan::ByScalar(row)
            } else {
                // ByElement needs check-10 bases only for unresolved scalars,
                // avoiding both group storage and MSMs for proven ones.
                clear_scalar_groups(&mut scalar_slots, &mut grouped_scalars);
                for &(scalar_index, element_index, coefficient) in &equation.terms {
                    if has_nontrivial_base[scalar_index as usize] {
                        continue;
                    }
                    let group = match scalar_slots[scalar_index as usize] {
                        UNUSED_SCALAR_SLOT => {
                            let group = grouped_scalars.len();
                            scalar_slots[scalar_index as usize] = group as u32;
                            grouped_scalars.push(scalar_index);
                            msm_terms.push(MsmTerms::new());
                            group
                        }
                        group => group as usize,
                    };
                    msm_terms[group].push(coefficient, self.elements[element_index as usize]);
                }
                for (group, &scalar_index) in grouped_scalars.iter().enumerate() {
                    if !bool::from(msm_terms[group].effective_base().is_identity()) {
                        has_nontrivial_base[scalar_index as usize] = true;
                    }
                }
                EvaluationPlan::ByElement
            };
            clear_scalar_groups(&mut scalar_slots, &mut grouped_scalars);
            for element_index in touched_elements.drain(..) {
                element_seen[element_index as usize] = false;
            }
            plans.push(plan);
        }

        if let Some(scalar_index) = has_nontrivial_base.iter().position(|ok| !ok) {
            return Err(InvalidInstance::check(
                10,
                format!("scalar {scalar_index} has an identity effective base in every equation"),
            ));
        }

        Ok(plans)
    }

    /// Evaluate each equation's left-hand side (coefficients are public).
    fn compute_image(&self) -> Vec<G> {
        self.equations
            .iter()
            .map(|equation| {
                let (coeffs, bases): (Vec<_>, Vec<_>) = equation
                    .image
                    .iter()
                    .map(|&(e, coeff)| (coeff, self.elements[e as usize]))
                    .unzip();
                G::msm_vartime(&coeffs, &bases)
            })
            .collect()
    }
}

impl<G: PrimeGroup> Instance<G> {
    /// The group elements of the statement (`elements[0]` is the generator).
    pub fn elements(&self) -> &[G] {
        &self.elements
    }

    /// The equations of the statement.
    pub fn equations(&self) -> &[Equation<G>] {
        &self.equations
    }

    /// `image(instance)`: the evaluation of each equation's left-hand side,
    /// computed once at construction.
    pub fn image(&self) -> &[G] {
        &self.image
    }

    /// `num_elements(instance)`.
    pub fn num_elements(&self) -> usize {
        self.elements.len()
    }

    /// `num_equations(instance)`.
    pub fn num_equations(&self) -> usize {
        self.equations.len()
    }

    /// `num_scalars(instance)`: `1 + max(scalar_index)` over the terms,
    /// derived and checked once at construction (density is check 6).
    pub fn num_scalars(&self) -> usize {
        self.num_scalars
    }

    /// Appends the weights [`Equation::accumulate_weights`] has accumulated as
    /// MSM entries over this instance's group elements, dropping the zero ones
    /// (the coefficients are public, so the test is free to be variable-time).
    ///
    /// # Panics
    ///
    /// Panics unless `weights` has one entry per group element, which is what
    /// `accumulate_weights` requires of it too.
    pub(crate) fn push_weighted_elements(
        &self,
        weights: &[G::Scalar],
        scalars: &mut Vec<G::Scalar>,
        bases: &mut Vec<G>,
    ) {
        for (&weight, &element) in weights.iter().zip_eq(&self.elements) {
            if !bool::from(weight.is_zero()) {
                scalars.push(weight);
                bases.push(element);
            }
        }
    }
}

impl<G: PrimeGroup + MultiScalarMul> Instance<G> {
    /// `map(instance, scalars)`: evaluate the linear map at `scalars`, in
    /// constant time (the scalars may be secret: witnesses, prover nonces).
    ///
    /// # Panics
    ///
    /// Panics if fewer than [`Instance::num_scalars`] scalars are given.
    pub fn map(&self, scalars: &[G::Scalar]) -> Vec<G> {
        (0..self.num_equations())
            .map(|equation| {
                let (scalars, bases) = self.evaluation_pairs(equation, scalars);
                G::msm(&scalars, &bases)
            })
            .collect()
    }

    /// Materialize one row of the public execution plan with the supplied
    /// scalars. Its width depends on the instance, never on scalar values.
    pub(crate) fn evaluation_pairs(
        &self,
        equation_index: usize,
        scalars: &[G::Scalar],
    ) -> (Vec<G::Scalar>, Vec<G>) {
        match &self.evaluation_plans[equation_index] {
            EvaluationPlan::ByScalar(row) => row
                .iter()
                .map(|&(scalar_index, base)| (scalars[scalar_index as usize], base))
                .unzip(),
            EvaluationPlan::ByElement => {
                let equation = &self.equations[equation_index];
                let mut indices: Vec<u32> = Vec::with_capacity(equation.terms.len());
                let mut coefficients = Vec::with_capacity(equation.terms.len() + 1);
                let mut bases = Vec::with_capacity(equation.terms.len() + 1);
                for &(scalar_index, element_index, coefficient) in &equation.terms {
                    let value = coefficient * scalars[scalar_index as usize];
                    match indices.iter().position(|&index| index == element_index) {
                        Some(index) => coefficients[index] += value,
                        None => {
                            indices.push(element_index);
                            coefficients.push(value);
                            bases.push(self.elements[element_index as usize]);
                        }
                    }
                }
                (coefficients, bases)
            }
        }
    }
}

impl<G: PrimeGroup + ConstantTimeEq + MultiScalarMul> Instance<G> {
    /// Tests if the witness is valid, in constant time.
    ///
    /// # Panics
    ///
    /// Panics if fewer than [`Instance::num_scalars`] scalars are given.
    pub fn is_witness_valid(&self, witness: &[G::Scalar]) -> Choice {
        self.image()
            .iter()
            .zip_eq(self.map(witness))
            .fold(Choice::from(1), |acc, (lhs, rhs)| acc & lhs.ct_eq(&rhs))
    }
}

impl<G> Instance<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    /// `SerializeLinearRelation` of the specification.
    ///
    /// Encodes, in order: the equation count, then for each equation its image
    /// terms and right-hand-side terms (each list preceded by its count, with
    /// 4-byte little-endian counts and indices and ciphersuite-encoded scalar
    /// coefficients), followed by the serialization of `elements[1..]` (the
    /// generator at index `0` is never serialized). The encoding is
    /// unambiguous and prefix-free. The leading equation count is never zero
    /// ([no empty instance][Instance#no-empty-instance]).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let le = repr_is_le::<G::Scalar>();
        out.extend_from_slice(&(self.equations.len() as u32).to_le_bytes());
        for equation in &self.equations {
            out.extend_from_slice(&(equation.image.len() as u32).to_le_bytes());
            for (element_index, coeff) in &equation.image {
                out.extend_from_slice(&element_index.to_le_bytes());
                serialize_scalar_le(coeff, le, &mut out);
            }
            out.extend_from_slice(&(equation.terms.len() as u32).to_le_bytes());
            for (scalar_index, element_index, coeff) in &equation.terms {
                out.extend_from_slice(&scalar_index.to_le_bytes());
                out.extend_from_slice(&element_index.to_le_bytes());
                serialize_scalar_le(coeff, le, &mut out);
            }
        }
        G::serialize_elements_allowing_identity(&self.elements[1..], &mut out);
        out
    }

    /// The inverse of [`Instance::serialize`], followed by `ValidateInstance`.
    ///
    /// Fails on trailing bytes, non-canonical scalar or group encodings, any
    /// encoding of the identity element, and any instance that fails the
    /// specification's validation checks — the same acceptance criteria as
    /// construction via [`LinearRelation::compile`][super::LinearRelation::compile].
    pub fn deserialize(data: &[u8]) -> Result<Self, InvalidInstance> {
        let mut reader = NargReader::new(data);
        let le = repr_is_le::<G::Scalar>();

        let num_equations = read_u32(&mut reader, "equation count")?;
        let mut equations = Vec::new();
        let mut max_element_index = 0u32;
        for _ in 0..num_equations {
            let num_image_terms = read_u32(&mut reader, "image term count")?;
            let mut image = Vec::new();
            for _ in 0..num_image_terms {
                let element_index = read_u32(&mut reader, "image element index")?;
                let coeff = read_scalar::<G>(&mut reader, le)?;
                max_element_index = max_element_index.max(element_index);
                image.push((element_index, coeff));
            }
            let num_terms = read_u32(&mut reader, "term count")?;
            let mut terms = Vec::new();
            for _ in 0..num_terms {
                let scalar_index = read_u32(&mut reader, "scalar index")?;
                let element_index = read_u32(&mut reader, "term element index")?;
                let coeff = read_scalar::<G>(&mut reader, le)?;
                max_element_index = max_element_index.max(element_index);
                terms.push((scalar_index, element_index, coeff));
            }
            equations.push(Equation { image, terms });
        }

        // The generator (index 0) is implicit; elements 1..=max are serialized.
        let num_serialized = max_element_index as usize;
        let expected = num_serialized
            .checked_mul(G::element_len())
            .ok_or_else(|| InvalidInstance::new("group element section too large"))?;
        if reader.remaining_len() != expected {
            return Err(InvalidInstance::new(format!(
                "expected {expected} bytes of group elements, got {}",
                reader.remaining_len()
            )));
        }

        let mut elements = Vec::with_capacity(num_serialized + 1);
        elements.push(G::generator());
        for i in 1..=num_serialized {
            let element = G::deserialize_element(&mut reader)
                .map_err(|_| InvalidInstance::new(format!("invalid group element at index {i}")))?;
            elements.push(element);
        }
        debug_assert!(reader.is_empty());

        Self::new(elements, equations)
    }
}

impl<G> Encoding<[u8]> for Instance<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    /// The canonical encoded instance, cached at construction. It is
    /// length-prefixed and fixed-width throughout, hence prefix-free.
    fn encode(&self) -> impl AsRef<[u8]> {
        self.label.as_slice()
    }
}

impl<G> TryFrom<&super::LinearRelation<G>> for Instance<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    type Error = InvalidInstance;

    fn try_from(relation: &super::LinearRelation<G>) -> Result<Self, Self::Error> {
        relation.compile()
    }
}

impl<G> TryFrom<super::LinearRelation<G>> for Instance<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    type Error = InvalidInstance;

    fn try_from(relation: super::LinearRelation<G>) -> Result<Self, Self::Error> {
        relation.compile()
    }
}

fn read_u32(reader: &mut NargReader<'_>, field: &str) -> Result<u32, InvalidInstance> {
    u32::deserialize_from_narg(reader)
        .map_err(|_| InvalidInstance::new(format!("truncated {field}")))
}

fn read_scalar<G: PrimeGroup>(
    reader: &mut NargReader<'_>,
    le: bool,
) -> Result<G::Scalar, InvalidInstance>
where
    G::Scalar: ScalarCodec,
{
    deserialize_scalar_le(reader, le)
        .map_err(|_| InvalidInstance::new("invalid scalar coefficient"))
}

// Needs a concrete group with a `MultiScalarMul` impl, which only the curve
// features provide: `curve25519-dalek` is an unconditional dev-dependency, so
// without the gate this module compiles under `--no-default-features` and
// fails on the missing impl.
#[cfg(all(test, feature = "curve25519-dalek"))]
mod tests {
    use alloc::vec;
    use curve25519_dalek::scalar::Scalar as S;
    use curve25519_dalek::RistrettoPoint as G;
    use rand::thread_rng;

    use crate::LinearRelation;

    /// Effective-base compilation is driven by the instance alone: the number
    /// of pairs handed to the MSM — and so the work it does — may not depend
    /// on witness values. The canonical encoding still keeps every term.
    ///
    /// The witness here is chosen so that the two terms on the shared element
    /// cancel exactly, the one case where a value-driven implementation would
    /// be tempted to drop a pair.
    #[test]
    fn effective_bases_preserve_the_wire_relation() {
        let mut r = LinearRelation::<G>::new();
        let [x, y] = r.allocate_scalars();
        let h = r.allocate_element_with(G::random(&mut thread_rng()));
        let k = r.allocate_element_with(G::random(&mut thread_rng()));
        r.allocate_eq(x * h + y * h + x * k);
        let w = vec![S::random(&mut thread_rng()), S::random(&mut thread_rng())];
        let instance = r.compile_with_witness(&w).unwrap();
        let equation = &instance.equations()[0];
        assert_eq!(
            equation.terms.len(),
            3,
            "the encoding keeps all three terms"
        );

        assert_eq!(
            instance.evaluation_pairs(0, &w).0.len(),
            2,
            "the narrower plan has two entries"
        );

        // The cached plan agrees with direct evaluation for ordinary,
        // cancelling, and zero witnesses; its shape never depends on them.
        let cases = [w, vec![S::ONE, -S::ONE], vec![S::ZERO, S::ZERO]];
        for scalars in cases {
            let direct = equation
                .terms
                .iter()
                .map(|&(s, e, coefficient)| {
                    instance.elements()[e as usize] * (coefficient * scalars[s as usize])
                })
                .sum::<G>();
            assert_eq!(instance.map(&scalars), vec![direct]);
        }

        // Grouping by scalar must not regress the dual shape: several
        // witness scalars multiplying one shared element stay one MSM entry.
        let mut shared = LinearRelation::<G>::new();
        let [x, y] = shared.allocate_scalars();
        let h = shared.allocate_element_with(G::random(&mut thread_rng()));
        shared.allocate_eq(x * h + y * h);
        let witness = [S::from(3u64), S::from(5u64)];
        let shared = shared.compile_with_witness(&witness).unwrap();
        assert_eq!(
            shared.evaluation_pairs(0, &witness).0.len(),
            1,
            "one shared element stays one MSM entry"
        );
    }
}
