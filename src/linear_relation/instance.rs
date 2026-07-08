//! The validated instance of the sigma-protocols specification.
//!
//! An [`Instance`] is the compiled `LinearRelation` of
//! draft-irtf-cfrg-sigma-protocols, Section "Representation": a list of group
//! elements (with the group generator fixed at index `0`) and a list of
//! equations whose image and right-hand-side terms carry explicit scalar
//! coefficients. **Every group element on which the statement depends is
//! individually indexed, serialized, and bound by the Fiat-Shamir transcript**
//! — nothing is folded, normalized, or replaced by precomputed combinations.
//!
//! The only ways to obtain an [`Instance`] are [`Instance::new`] (used by
//! [`LinearRelation::compile`][super::LinearRelation::compile]) and
//! [`Instance::deserialize`]; both run the specification's `ValidateInstance`
//! (checks 1-10), so every value of this type satisfies the same acceptance
//! criteria regardless of how it was built.

use alloc::format;
use alloc::vec::Vec;

use group::prime::PrimeGroup;
use itertools::Itertools;
use spongefish::{Encoding, NargDeserialize, NargSerialize};
use subtle::{Choice, ConstantTimeEq};

use crate::errors::InvalidInstance;
use crate::group::msm::MultiScalarMul;

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

/// A validated instance for the linear-map Sigma Protocol.
///
/// See the [module documentation][self]. Fields are private: an `Instance`
/// can only be built through constructors that run `ValidateInstance`.
#[derive(Clone, Debug)]
pub struct Instance<G: PrimeGroup> {
    /// The group elements of the statement. `elements[0]` is the group
    /// generator; it is validated (check 7) but never serialized.
    elements: Vec<G>,
    /// The equations of the statement.
    equations: Vec<Equation<G>>,
}

impl<G: PrimeGroup + MultiScalarMul> Instance<G> {
    /// Build an instance from its parts, running the specification's
    /// `ValidateInstance` (checks 1-10).
    ///
    /// `elements[0]` must be the group generator.
    pub fn new(elements: Vec<G>, equations: Vec<Equation<G>>) -> Result<Self, InvalidInstance> {
        let instance = Self {
            elements,
            equations,
        };
        instance.validate()?;
        Ok(instance)
    }

    /// `ValidateInstance` of the specification: checks 1-10 of Section
    /// "Instance validation". Errors carry the number of the failed check.
    fn validate(&self) -> Result<(), InvalidInstance> {
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
                let slot = element_used.get_mut(element_index as usize).ok_or_else(|| {
                    InvalidInstance::check(
                        4,
                        format!("image element index {element_index} out of range"),
                    )
                })?;
                *slot = true;
            }
            for &(scalar_index, element_index, _) in &equation.terms {
                let slot = element_used.get_mut(element_index as usize).ok_or_else(|| {
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
        let num_scalars = max_scalar.map_or(0, |m| m as usize + 1);
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
        for (i, image_element) in self.image().into_iter().enumerate() {
            if image_element.is_identity().into() {
                return Err(InvalidInstance::check(
                    9,
                    format!("the image of equation {i} is the identity"),
                ));
            }
        }

        // Check 10: for every scalar there is at least one equation in which
        // its effective base (the sum of coeff * element over the terms
        // carrying that scalar) is not the identity.
        for scalar_index in 0..num_scalars as u32 {
            let has_nontrivial_base = self.equations.iter().any(|equation| {
                let (scalars, bases): (Vec<_>, Vec<_>) = equation
                    .terms
                    .iter()
                    .filter(|&&(s, _, _)| s == scalar_index)
                    .map(|&(_, e, coeff)| (coeff, self.elements[e as usize]))
                    .unzip();
                !scalars.is_empty() && !bool::from(G::msm(&scalars, &bases).is_identity())
            });
            if !has_nontrivial_base {
                return Err(InvalidInstance::check(
                    10,
                    format!("scalar {scalar_index} has an identity effective base in every equation"),
                ));
            }
        }

        Ok(())
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

    /// `num_elements(instance)`.
    pub fn num_elements(&self) -> usize {
        self.elements.len()
    }

    /// `num_equations(instance)`.
    pub fn num_equations(&self) -> usize {
        self.equations.len()
    }

    /// `num_scalars(instance)`: derived from the terms, never stored
    /// (`1 + max(scalar_index)`; density is guaranteed by check 6).
    pub fn num_scalars(&self) -> usize {
        self.equations
            .iter()
            .flat_map(|equation| equation.terms.iter())
            .map(|&(scalar_index, _, _)| scalar_index as usize + 1)
            .max()
            .unwrap_or(0)
    }
}

impl<G: PrimeGroup + MultiScalarMul> Instance<G> {
    /// `map(instance, scalars)`: evaluate the linear map at `scalars`.
    ///
    /// # Panics
    ///
    /// Panics if fewer than [`Instance::num_scalars`] scalars are given.
    pub fn map(&self, scalars: &[G::Scalar]) -> Vec<G> {
        self.equations
            .iter()
            .map(|equation| {
                let (coeffs, bases): (Vec<_>, Vec<_>) = equation
                    .terms
                    .iter()
                    .map(|&(s, e, coeff)| {
                        (coeff * scalars[s as usize], self.elements[e as usize])
                    })
                    .unzip();
                G::msm(&coeffs, &bases)
            })
            .collect()
    }

    /// `image(instance)`: the evaluation of each equation's left-hand side.
    pub fn image(&self) -> Vec<G> {
        self.equations
            .iter()
            .map(|equation| {
                let (coeffs, bases): (Vec<_>, Vec<_>) = equation
                    .image
                    .iter()
                    .map(|&(e, coeff)| (coeff, self.elements[e as usize]))
                    .unzip();
                G::msm(&coeffs, &bases)
            })
            .collect()
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
            .into_iter()
            .zip_eq(self.map(witness))
            .fold(Choice::from(1), |acc, (lhs, rhs)| acc & lhs.ct_eq(&rhs))
    }
}

impl<G> Instance<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize,
{
    /// `SerializeLinearRelation` of the specification.
    ///
    /// Encodes, in order: the equation count, then for each equation its image
    /// terms and right-hand-side terms (each list preceded by its count, with
    /// 4-byte little-endian counts and indices and ciphersuite-encoded scalar
    /// coefficients), followed by the serialization of `elements[1..]` (the
    /// generator at index `0` is never serialized). The encoding is
    /// unambiguous and prefix-free.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.equations.len() as u32).to_le_bytes());
        for equation in &self.equations {
            out.extend_from_slice(&(equation.image.len() as u32).to_le_bytes());
            for (element_index, coeff) in &equation.image {
                out.extend_from_slice(&element_index.to_le_bytes());
                out.extend_from_slice(coeff.encode().as_ref());
            }
            out.extend_from_slice(&(equation.terms.len() as u32).to_le_bytes());
            for (scalar_index, element_index, coeff) in &equation.terms {
                out.extend_from_slice(&scalar_index.to_le_bytes());
                out.extend_from_slice(&element_index.to_le_bytes());
                out.extend_from_slice(coeff.encode().as_ref());
            }
        }
        for element in &self.elements[1..] {
            out.extend_from_slice(element.encode().as_ref());
        }
        out
    }

    /// The inverse of [`Instance::serialize`], followed by `ValidateInstance`.
    ///
    /// Fails on trailing bytes, non-canonical scalar or group encodings, any
    /// encoding of the identity element, and any instance that fails the
    /// specification's validation checks — the same acceptance criteria as
    /// construction via [`LinearRelation::compile`][super::LinearRelation::compile].
    pub fn deserialize(data: &[u8]) -> Result<Self, InvalidInstance> {
        let mut cursor = data;

        let num_equations = read_u32(&mut cursor, "equation count")?;
        let mut equations = Vec::new();
        let mut max_element_index = 0u32;
        for _ in 0..num_equations {
            let num_image_terms = read_u32(&mut cursor, "image term count")?;
            let mut image = Vec::new();
            for _ in 0..num_image_terms {
                let element_index = read_u32(&mut cursor, "image element index")?;
                let coeff = read_scalar::<G>(&mut cursor)?;
                max_element_index = max_element_index.max(element_index);
                image.push((element_index, coeff));
            }
            let num_terms = read_u32(&mut cursor, "term count")?;
            let mut terms = Vec::new();
            for _ in 0..num_terms {
                let scalar_index = read_u32(&mut cursor, "scalar index")?;
                let element_index = read_u32(&mut cursor, "term element index")?;
                let coeff = read_scalar::<G>(&mut cursor)?;
                max_element_index = max_element_index.max(element_index);
                terms.push((scalar_index, element_index, coeff));
            }
            equations.push(Equation { image, terms });
        }

        // The generator (index 0) is implicit; elements 1..=max are serialized.
        let num_serialized = max_element_index as usize;
        let element_size = <G as group::GroupEncoding>::Repr::default().as_ref().len();
        let expected = num_serialized
            .checked_mul(element_size)
            .ok_or_else(|| InvalidInstance::new("group element section too large"))?;
        if cursor.len() != expected {
            return Err(InvalidInstance::new(format!(
                "expected {expected} bytes of group elements, got {}",
                cursor.len()
            )));
        }

        let mut elements = Vec::with_capacity(num_serialized + 1);
        elements.push(G::generator());
        for i in 1..=num_serialized {
            let element = G::deserialize_from_narg(&mut cursor).map_err(|_| {
                InvalidInstance::new(format!("invalid group element at index {i}"))
            })?;
            // Group deserialization MUST reject any encoding of the identity.
            if element.is_identity().into() {
                return Err(InvalidInstance::check(
                    8,
                    format!("group element {i} is the identity"),
                ));
            }
            elements.push(element);
        }
        debug_assert!(cursor.is_empty());

        Self::new(elements, equations)
    }
}

impl<G: PrimeGroup + MultiScalarMul> TryFrom<&super::LinearRelation<G>> for Instance<G> {
    type Error = InvalidInstance;

    fn try_from(relation: &super::LinearRelation<G>) -> Result<Self, Self::Error> {
        relation.compile()
    }
}

impl<G: PrimeGroup + MultiScalarMul> TryFrom<super::LinearRelation<G>> for Instance<G> {
    type Error = InvalidInstance;

    fn try_from(relation: super::LinearRelation<G>) -> Result<Self, Self::Error> {
        relation.compile()
    }
}

fn read_u32(cursor: &mut &[u8], field: &str) -> Result<u32, InvalidInstance> {
    if cursor.len() < 4 {
        return Err(InvalidInstance::new(format!("truncated {field}")));
    }
    let (bytes, rest) = cursor.split_at(4);
    *cursor = rest;
    Ok(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
}

fn read_scalar<G: PrimeGroup>(cursor: &mut &[u8]) -> Result<G::Scalar, InvalidInstance>
where
    G::Scalar: NargDeserialize,
{
    G::Scalar::deserialize_from_narg(cursor)
        .map_err(|_| InvalidInstance::new("invalid scalar coefficient"))
}

