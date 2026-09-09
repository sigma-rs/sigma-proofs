//! The validated instance of the sigma-protocols specification.
//!
//! This module is private; [`Instance`] is re-exported from
//! [`linear_relation`][super] and carries the documentation.

use alloc::collections::{btree_map::Entry, BTreeMap};
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
///   pairs; the image element is `sum(coeff * element(element_index))`.
/// - `terms` (the right-hand side) is the list of
///   `(scalar_index, element_index, coeff)` triples, each contributing
///   `coeff * witness[scalar_index] * element(element_index)`.
///
/// Either list may be empty, in which case that side evaluates to the identity.
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
    /// The indices come from a validated instance: check 2 bounds element
    /// indices, and `num_scalars()` is defined from the largest scalar index.
    /// Panics if `weights` is shorter than the former or `response` than the
    /// latter; the callers check the response length, which is the one that
    /// comes off the wire.
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

/// A validated instance for the linear-map Sigma Protocol.
///
/// An `Instance` is the compiled
/// [`LinearRelation`][super::LinearRelation] of
/// draft-irtf-cfrg-sigma-protocols, Section "Representation".
///
/// It contains a list of group elements with indices starting at `2` and a
/// list of equations whose image and right-hand-side terms carry explicit
/// scalar coefficients. The identity and group generator have implicit
/// indices `0` and `1`.
///
/// The only ways to obtain an `Instance` are
/// [`Instance::new`] (used by
/// [`LinearRelation::compile`][super::LinearRelation::compile]) and
/// [`Instance::deserialize`]; both run the specification's `ValidateInstance`
/// (the checks of Section "Instance validation"), so every value of this type
/// satisfies the same acceptance criteria regardless of how it was built.
#[derive(Clone)]
pub struct Instance<G: PrimeGroup> {
    /// The logical group-element vector used internally for direct indexing.
    /// Its first two entries materialize the implicit identity and generator;
    /// [`Instance::elements`] exposes only the remaining statement elements.
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
            .field("elements", &self.elements())
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
    /// `ValidateInstance`.
    ///
    /// The supplied `elements` have logical element indices starting at `2`;
    /// the identity and group generator at indices `0` and `1` are implicit.
    pub fn new(elements: Vec<G>, equations: Vec<Equation<G>>) -> Result<Self, InvalidInstance> {
        let num_elements = elements
            .len()
            .checked_add(2)
            .ok_or_else(|| InvalidInstance::check(1, "count exceeds 2^32"))?;
        if u32::try_from(num_elements).is_err() {
            return Err(InvalidInstance::check(1, "count exceeds 2^32"));
        }
        let mut logical_elements = Vec::with_capacity(num_elements);
        logical_elements.push(G::identity());
        logical_elements.push(G::generator());
        logical_elements.extend(elements);
        let mut instance = Self {
            elements: logical_elements,
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

    /// `ValidateInstance` of the specification. Errors carry the number of
    /// the failed check.
    /// Returns the computed image, scalar count, and effective-base execution
    /// plan, all cached by the constructor.
    #[allow(clippy::type_complexity)]
    fn validate(&self) -> Result<(Vec<G>, usize, Vec<EvaluationPlan<G>>), InvalidInstance> {
        let num_elements = self.elements.len();

        // Check 1: counts fit in u32 (indices are u32 by construction).
        if u32::try_from(self.equations.len()).is_err() || u32::try_from(num_elements).is_err() {
            return Err(InvalidInstance::check(1, "count exceeds 2^32"));
        }

        let mut element_used = alloc::vec![false; num_elements];
        let mut max_scalar: Option<u32> = None;
        for equation in &self.equations {
            // Check 1 (counts per equation).
            if u32::try_from(equation.image.len()).is_err()
                || u32::try_from(equation.terms.len()).is_err()
            {
                return Err(InvalidInstance::check(1, "term count exceeds 2^32"));
            }
            // Check 2: every element index references a group element.
            for &(element_index, _) in &equation.image {
                let slot = element_used
                    .get_mut(element_index as usize)
                    .ok_or_else(|| {
                        InvalidInstance::check(
                            2,
                            format!("image element index {element_index} out of range"),
                        )
                    })?;
                *slot = true;
            }
            for &(scalar_index, element_index, _) in &equation.terms {
                let slot = element_used
                    .get_mut(element_index as usize)
                    .ok_or_else(|| {
                        InvalidInstance::check(
                            2,
                            format!("term element index {element_index} out of range"),
                        )
                    })?;
                *slot = true;
                max_scalar = Some(max_scalar.map_or(scalar_index, |m| m.max(scalar_index)));
            }
        }

        // Check 3: every element other than the identity and generator appears
        // in at least one equation.
        if let Some(unused) = element_used.iter().skip(2).position(|used| !used) {
            return Err(InvalidInstance::check(
                3,
                format!("group element {} is not used by any equation", unused + 2),
            ));
        }

        let num_scalars = match max_scalar {
            None => 0,
            Some(maximum) => usize::try_from(maximum)
                .ok()
                .and_then(|maximum| maximum.checked_add(1))
                .ok_or_else(|| {
                    InvalidInstance::check(1, "scalar count exceeds addressable size")
                })?,
        };

        let image = self.compute_image();
        let evaluation_plans = self.compile_evaluation_plans();

        Ok((image, num_scalars, evaluation_plans))
    }

    /// Compile the wire-format term triples into the bases used to evaluate
    /// the linear map. Grouping is driven entirely by public instance data.
    fn compile_evaluation_plans(&self) -> Vec<EvaluationPlan<G>> {
        let mut scalar_slots = BTreeMap::new();
        let mut grouped_scalars = Vec::new();
        let mut msm_terms = Vec::new();
        let mut element_seen = alloc::vec![false; self.elements.len()];
        let mut touched_elements = Vec::new();
        let mut plans = Vec::with_capacity(self.equations.len());

        for equation in &self.equations {
            for &(scalar_index, element_index, _) in &equation.terms {
                if !element_seen[element_index as usize] {
                    element_seen[element_index as usize] = true;
                    touched_elements.push(element_index);
                }
                if let Entry::Vacant(slot) = scalar_slots.entry(scalar_index) {
                    slot.insert(grouped_scalars.len());
                    grouped_scalars.push(scalar_index);
                }
            }

            // Equivalent scalar/element groupings let the runtime use the
            // narrower dimension; shared-element sums stay one-base MSMs.
            msm_terms.clear();
            let plan = if grouped_scalars.len() <= touched_elements.len() {
                msm_terms.resize_with(grouped_scalars.len(), MsmTerms::new);
                for &(scalar_index, element_index, coefficient) in &equation.terms {
                    if let Some(&group) = scalar_slots.get(&scalar_index) {
                        msm_terms[group].push(coefficient, self.elements[element_index as usize]);
                    }
                }
                let row = grouped_scalars
                    .iter()
                    .enumerate()
                    .map(|(group, &scalar_index)| (scalar_index, msm_terms[group].effective_base()))
                    .collect();
                EvaluationPlan::ByScalar(row)
            } else {
                EvaluationPlan::ByElement
            };
            scalar_slots.clear();
            grouped_scalars.clear();
            for element_index in touched_elements.drain(..) {
                element_seen[element_index as usize] = false;
            }
            plans.push(plan);
        }

        plans
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
    /// The group elements of the statement. Their logical element indices
    /// start at `2`; the identity and generator are implicit.
    pub fn elements(&self) -> &[G] {
        &self.elements[2..]
    }

    /// Returns the group element at a logical element index.
    pub fn element(&self, element_index: usize) -> Option<&G> {
        self.elements.get(element_index)
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

    /// `num_elements(instance)`, including the two implicit elements.
    /// This is `2 + self.elements().len()`.
    pub fn num_elements(&self) -> usize {
        self.elements.len()
    }

    /// `num_equations(instance)`.
    pub fn num_equations(&self) -> usize {
        self.equations.len()
    }

    /// `num_scalars(instance)`: `1 + max(scalar_index)` over the terms,
    /// derived and checked once at construction. Indices may have gaps, but
    /// there are no trailing scalar slots above the largest referenced index.
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
    /// coefficients), followed by the serialization of `elements` (the
    /// identity and generator at indices `0` and `1` are implicit).
    /// The encoding is unambiguous and prefix-free.
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
        G::serialize_elements_allowing_identity(self.elements(), &mut out);
        out
    }

    /// The inverse of [`Instance::serialize`], followed by `ValidateInstance`.
    ///
    /// Fails on trailing bytes, non-canonical scalar or group encodings, and
    /// any instance that fails the specification's validation checks — the
    /// same acceptance criteria as construction via
    /// [`LinearRelation::compile`][super::LinearRelation::compile].
    pub fn deserialize(data: &[u8]) -> Result<Self, InvalidInstance> {
        let mut reader = NargReader::new(data);
        let le = repr_is_le::<G::Scalar>();

        let num_equations = read_u32(&mut reader, "equation count")?;
        let mut equations = Vec::new();
        let mut max_element_index = 1u32;
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

        // The identity and generator (indices 0 and 1) are implicit;
        // elements 2..=max are serialized.
        let num_serialized = max_element_index as usize - 1;
        // `max_element_index` is read from `data`, so it cannot size the
        // allocation: the hint is capped and the `Vec` grows as elements
        // actually parse. The loop is bounded anyway, because every element
        // consumes `element_len()` bytes and a read past the end fails.
        let mut elements = Vec::with_capacity(usize::min(num_serialized, 64));
        for i in 2..=max_element_index as usize {
            let element = G::deserialize_element(&mut reader)
                .map_err(|_| InvalidInstance::new(format!("invalid group element at index {i}")))?;
            elements.push(element);
        }
        // Nothing follows the group-element section. A short section already
        // failed above, in the element that ran off the end; trailing bytes
        // have to be rejected here, or an instance would have more than one
        // encoding.
        if !reader.is_empty() {
            return Err(InvalidInstance::new(
                "trailing bytes after the group element section",
            ));
        }

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
                    *instance.element(e as usize).unwrap() * (coefficient * scalars[s as usize])
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
