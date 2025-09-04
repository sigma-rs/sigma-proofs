#[cfg(not(feature = "std"))]
use ahash::RandomState;
use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::iter;
use core::marker::PhantomData;
#[cfg(not(feature = "std"))]
use hashbrown::HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

use ff::Field;
use group::prime::PrimeGroup;
use subtle::{Choice, ConstantTimeEq};

use super::{GroupMap, GroupVar, LinearCombination, LinearRelation, ScalarTerm, ScalarVar};
use crate::errors::{Error, InvalidInstance};
use crate::group::msm::VariableMultiScalarMul;

// XXX. this definition is uncomfortably similar to LinearRelation, exception made for the weights.
// It'd be nice to better compress potentially duplicated code.
/// A normalized form of the [`LinearRelation`], which is used for serialization into the transcript.
///
/// This struct represents a normalized form of a linear relation where each
/// constraint is of the form: image_i = Σ (scalar_j * group_element_k)
/// without weights or extra scalars.
#[derive(Clone, Debug, Default)]
pub struct CanonicalLinearRelation<G: PrimeGroup> {
    /// The image group elements (left-hand side of equations)
    pub image: Vec<G>,
    /// The constraints, where each constraint is a vector of (scalar_var, group_var) pairs
    /// representing the right-hand side of the equation
    pub linear_combinations: Vec<Vec<(ScalarVar<G>, GroupVar<G>)>>,
    /// The group elements map
    pub group_elements: GroupMap<G>,
    /// Number of scalar variables
    pub num_scalars: usize,
}

/// Private type alias used to simplify function signatures below.
///
/// The cache is essentially a mapping (GroupVar, Scalar) => GroupVar, which maps the original
/// weighted group vars to a new assignment, such that if a pair appears more than once, it will
/// map to the same group variable in the canonical linear relation.
#[cfg(feature = "std")]
type WeightedGroupCache<G> = HashMap<GroupVar<G>, Vec<(<G as group::Group>::Scalar, GroupVar<G>)>>;
#[cfg(not(feature = "std"))]
type WeightedGroupCache<G> =
    HashMap<GroupVar<G>, Vec<(<G as group::Group>::Scalar, GroupVar<G>)>, RandomState>;

impl<G: PrimeGroup> CanonicalLinearRelation<G> {
    /// Create a new empty canonical linear relation.
    ///
    /// This function is not meant to be publicly exposed. It is internally used to build a type-safe linear relation,
    /// so that all instances guaranteed to be "good" relations over which the prover will want to make a proof.
    fn new() -> Self {
        Self {
            image: Vec::new(),
            linear_combinations: Vec::new(),
            group_elements: GroupMap::default(),
            num_scalars: 0,
        }
    }

    /// Evaluate the canonical linear relation with the provided scalars
    ///
    /// This returns a list of image points produced by evaluating each linear combination in the
    /// relation. The order of the returned list matches the order of [`Self::linear_combinations`].
    ///
    /// # Panic
    ///
    /// Panics if the number of scalars given is less than the number of scalar variables in this
    /// linear relation.
    /// If the vector of scalars if longer than the number of terms in each linear combinations, the extra terms are ignored.
    pub fn evaluate(&self, scalars: &[G::Scalar]) -> Vec<G> {
        self.linear_combinations
            .iter()
            .map(|lc| {
                let scalars = lc
                    .iter()
                    .map(|(scalar_var, _)| scalars[scalar_var.index()])
                    .collect::<Vec<_>>();
                let bases = lc
                    .iter()
                    .map(|(_, group_var)| self.group_elements.get(*group_var).unwrap())
                    .collect::<Vec<_>>();
                G::msm(&scalars, &bases)
            })
            .collect()
    }

    /// Get or create a GroupVar for a weighted group element, with deduplication
    fn get_or_create_weighted_group_var(
        &mut self,
        group_var: GroupVar<G>,
        weight: &G::Scalar,
        original_group_elements: &GroupMap<G>,
        weighted_group_cache: &mut WeightedGroupCache<G>,
    ) -> Result<GroupVar<G>, InvalidInstance> {
        // Check if we already have this (weight, group_var) combination
        let entry = weighted_group_cache.entry(group_var).or_default();

        // Find if we already have this weight for this group_var
        if let Some((_, existing_var)) = entry.iter().find(|(w, _)| w == weight) {
            return Ok(*existing_var);
        }

        // Create new weighted group element
        let original_group_val = original_group_elements.get(group_var)?;
        let weighted_group = original_group_val * weight;

        // Add to our group elements with new index (length)
        let new_var = self.group_elements.push(weighted_group);

        // Cache the mapping for this group_var and weight
        entry.push((*weight, new_var));

        Ok(new_var)
    }

    /// Process a single constraint equation and add it to the canonical relation.
    fn process_constraint(
        &mut self,
        &image_var: &GroupVar<G>,
        equation: &LinearCombination<G>,
        original_relation: &LinearRelation<G>,
        weighted_group_cache: &mut WeightedGroupCache<G>,
    ) -> Result<(), InvalidInstance> {
        let mut rhs_terms = Vec::new();

        // Collect RHS terms that have scalar variables and apply weights
        for weighted_term in equation.terms() {
            if let ScalarTerm::Var(scalar_var) = weighted_term.term.scalar {
                let group_var = weighted_term.term.elem;
                let weight = &weighted_term.weight;

                if weight.is_zero().into() {
                    continue; // Skip zero weights
                }

                let canonical_group_var = self.get_or_create_weighted_group_var(
                    group_var,
                    weight,
                    &original_relation.linear_map.group_elements,
                    weighted_group_cache,
                )?;

                rhs_terms.push((scalar_var, canonical_group_var));
            }
        }

        // Compute the canonical image by subtracting constant terms from the original image
        let mut canonical_image = original_relation.linear_map.group_elements.get(image_var)?;
        for weighted_term in equation.terms() {
            if let ScalarTerm::Unit = weighted_term.term.scalar {
                let group_val = original_relation
                    .linear_map
                    .group_elements
                    .get(weighted_term.term.elem)?;
                canonical_image -= group_val * weighted_term.weight;
            }
        }

        // Only include constraints that are non-trivial (not zero constraints)
        // QUESTION: Should this actually be done? In the 0 = [] case, this seems to be no loss. In
        // the error case, this precludes including an always-false OR branch.
        if rhs_terms.is_empty() {
            if canonical_image.is_identity().into() {
                return Ok(());
            }
            return Err(InvalidInstance::new(
                "trivially false constraint: constraint has empty right-hand side and non-identity left-hand side",
            ));
        }

        self.image.push(canonical_image);
        self.linear_combinations.push(rhs_terms);

        Ok(())
    }

    /// Serialize the linear relation to bytes.
    ///
    /// The output format is:
    ///
    /// - `[Ne: u32]` number of equations
    /// - `Ne × equations`:
    ///   - `[lhs_index: u32]` output group element index
    ///   - `[Nt: u32]` number of terms
    ///   - `Nt × [scalar_index: u32, group_index: u32]` term entries
    /// - All group elements in serialized form.
    pub fn label(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Create an ordered list of unique group element representations. Elements are ordered
        // based on the order they appear in the canonical linear relation, as seen by the loop
        // below.
        // Order in this list is expected to be stable and lead to the same vector string.
        // However, relations built using TryFrom<LinearRelation> are NOT guaranteed to lead
        // to the same ordering of elements across versions of this library.
        // Changes to LinearRelation may have unpredictable effects on how this label is built.
        #[cfg(feature = "std")]
        let mut group_repr_mapping: HashMap<Box<[u8]>, u32> = HashMap::new();
        #[cfg(not(feature = "std"))]
        let mut group_repr_mapping: HashMap<Box<[u8]>, u32, RandomState> =
            HashMap::with_hasher(RandomState::new());
        let mut group_elements_ordered = Vec::new();

        // Helper function to get or create index for a group element representation
        let mut repr_index = |elem_repr: G::Repr| -> u32 {
            if let Some(&index) = group_repr_mapping.get(elem_repr.as_ref()) {
                return index;
            }

            let new_index = group_elements_ordered.len() as u32;
            group_elements_ordered.push(elem_repr);
            group_repr_mapping.insert(elem_repr.as_ref().into(), new_index);
            new_index
        };

        // Build constraint data in the same order as original, as a nested list of group and
        // scalar indices. Note that the group indices are into group_elements_ordered.
        let mut constraint_data = Vec::<(u32, Vec<(u32, u32)>)>::new();

        for (image_elem, constraint_terms) in iter::zip(&self.image, &self.linear_combinations) {
            // First, add the left-hand side (image) element
            let lhs_index = repr_index(image_elem.to_bytes());

            // Build the RHS terms
            let mut rhs_terms = Vec::new();
            for (scalar_var, group_var) in constraint_terms {
                let group_elem = self
                    .group_elements
                    .get(*group_var)
                    .expect("Group element not found");
                let group_index = repr_index(group_elem.to_bytes());
                rhs_terms.push((scalar_var.0 as u32, group_index));
            }

            constraint_data.push((lhs_index, rhs_terms));
        }

        // 1. Number of equations
        let ne = constraint_data.len();
        out.extend_from_slice(&(ne as u32).to_le_bytes());

        // 2. Encode each equation
        for (lhs_index, rhs_terms) in constraint_data {
            // a. Output point index (LHS)
            out.extend_from_slice(&lhs_index.to_le_bytes());

            // b. Number of terms in the RHS linear combination
            out.extend_from_slice(&(rhs_terms.len() as u32).to_le_bytes());

            // c. Each term: scalar index and point index
            for (scalar_index, group_index) in rhs_terms {
                out.extend_from_slice(&scalar_index.to_le_bytes());
                out.extend_from_slice(&group_index.to_le_bytes());
            }
        }

        // Dump the group elements in the order they were first encountered
        for elem_repr in group_elements_ordered {
            out.extend_from_slice(elem_repr.as_ref());
        }

        out
    }

    /// Parse a canonical linear relation from its label representation.
    ///
    /// Returns an [`InvalidInstance`] error if the label is malformed.
    ///
    /// # Examples
    ///
    /// ```
    /// use hex_literal::hex;
    /// use sigma_proofs::linear_relation::CanonicalLinearRelation;
    /// type G = bls12_381::G1Projective;
    ///
    /// let dlog_instance_label = hex!("01000000000000000100000000000000010000009823a3def60a6e07fb25feb35f211ee2cbc9c130c1959514f5df6b5021a2b21a4c973630ec2090c733c1fe791834ce1197f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
    /// let instance = CanonicalLinearRelation::<G>::from_label(&dlog_instance_label).unwrap();
    /// assert_eq!(&dlog_instance_label[..], &instance.label()[..]);
    /// ```
    pub fn from_label(data: &[u8]) -> Result<Self, Error> {
        use crate::errors::InvalidInstance;
        use crate::group::serialization::group_elt_serialized_len;

        let mut offset = 0;

        // Read number of equations (4 bytes, little endian)
        if data.len() < 4 {
            return Err(InvalidInstance::new("Invalid label: too short for equation count").into());
        }
        let num_equations = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        offset += 4;

        // Parse constraints and collect unique group element indices
        let mut constraint_data = Vec::new();
        let mut max_scalar_index = 0u32;
        let mut max_group_index = 0u32;

        for _ in 0..num_equations {
            // Read LHS index (4 bytes)
            if offset + 4 > data.len() {
                return Err(InvalidInstance::new("Invalid label: truncated LHS index").into());
            }
            let lhs_index = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            max_group_index = max_group_index.max(lhs_index);

            // Read number of RHS terms (4 bytes)
            if offset + 4 > data.len() {
                return Err(InvalidInstance::new("Invalid label: truncated RHS count").into());
            }
            let num_rhs_terms = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            // Read RHS terms
            let mut rhs_terms = Vec::new();
            for _ in 0..num_rhs_terms {
                // Read scalar index (4 bytes)
                if offset + 4 > data.len() {
                    return Err(
                        InvalidInstance::new("Invalid label: truncated scalar index").into(),
                    );
                }
                let scalar_index = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                offset += 4;
                max_scalar_index = max_scalar_index.max(scalar_index);

                // Read group index (4 bytes)
                if offset + 4 > data.len() {
                    return Err(InvalidInstance::new("Invalid label: truncated group index").into());
                }
                let group_index = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                offset += 4;
                max_group_index = max_group_index.max(group_index);

                rhs_terms.push((scalar_index, group_index));
            }

            constraint_data.push((lhs_index, rhs_terms));
        }

        // Calculate expected number of group elements
        let num_group_elements = (max_group_index + 1) as usize;
        let group_element_size = group_elt_serialized_len::<G>();
        let expected_remaining = num_group_elements * group_element_size;

        if data.len() - offset != expected_remaining {
            return Err(InvalidInstance::new(format!(
                "Invalid label: expected {} bytes for {} group elements, got {}",
                expected_remaining,
                num_group_elements,
                data.len() - offset
            ))
            .into());
        }

        // Parse group elements
        let mut group_elements_ordered = Vec::new();
        for i in 0..num_group_elements {
            let start = offset + i * group_element_size;
            let end = start + group_element_size;
            let elem_bytes = &data[start..end];

            let mut repr = G::Repr::default();
            repr.as_mut().copy_from_slice(elem_bytes);

            let elem = Option::<G>::from(G::from_bytes(&repr)).ok_or_else(|| {
                Error::from(InvalidInstance::new(format!(
                    "Invalid group element at index {i}"
                )))
            })?;

            group_elements_ordered.push(elem);
        }

        // Build the canonical relation
        let mut canonical = Self::new();
        canonical.num_scalars = (max_scalar_index + 1) as usize;

        // Add all group elements to the map
        let mut group_var_map = Vec::new();
        for elem in &group_elements_ordered {
            let var = canonical.group_elements.push(*elem);
            group_var_map.push(var);
        }

        // Build constraints
        for (lhs_index, rhs_terms) in constraint_data {
            // Add image element
            canonical
                .image
                .push(group_elements_ordered[lhs_index as usize]);

            // Build linear combination
            let mut linear_combination = Vec::new();
            for (scalar_index, group_index) in rhs_terms {
                let scalar_var = ScalarVar(scalar_index as usize, PhantomData);
                let group_var = group_var_map[group_index as usize];
                linear_combination.push((scalar_var, group_var));
            }
            canonical.linear_combinations.push(linear_combination);
        }

        Ok(canonical)
    }
}

impl<G: PrimeGroup> TryFrom<LinearRelation<G>> for CanonicalLinearRelation<G> {
    type Error = InvalidInstance;

    fn try_from(value: LinearRelation<G>) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<G: PrimeGroup> TryFrom<&LinearRelation<G>> for CanonicalLinearRelation<G> {
    type Error = InvalidInstance;

    fn try_from(relation: &LinearRelation<G>) -> Result<Self, Self::Error> {
        if relation.image.len() != relation.linear_map.linear_combinations.len() {
            return Err(InvalidInstance::new(
                "Number of equations must be equal to number of image elements.",
            ));
        }

        let mut canonical = CanonicalLinearRelation::new();
        canonical.num_scalars = relation.linear_map.num_scalars;

        // Cache for deduplicating weighted group elements
        #[cfg(feature = "std")]
        let mut weighted_group_cache = HashMap::new();
        #[cfg(not(feature = "std"))]
        let mut weighted_group_cache = HashMap::with_hasher(RandomState::new());

        // Process each constraint using the modular helper method
        for (lhs, rhs) in iter::zip(&relation.image, &relation.linear_map.linear_combinations) {
            // If any group element in the image is not assigned, return `InvalidInstance`.
            let lhs_value = relation.linear_map.group_elements.get(*lhs)?;

            // If any group element in the linear constraints is not assigned, return `InvalidInstance`.
            let rhs_elements = rhs
                .0
                .iter()
                .map(|weighted| relation.linear_map.group_elements.get(weighted.term.elem))
                .collect::<Result<Vec<G>, _>>()?;

            // Compute the constant terms on the right-hand side of the equation.
            let rhs_constants = rhs
                .0
                .iter()
                .map(|element| match element.term.scalar {
                    ScalarTerm::Unit => element.weight,
                    _ => G::Scalar::ZERO,
                })
                .collect::<Vec<_>>();
            let rhs_constant_term = G::msm(&rhs_constants, &rhs_elements);

            // We say that an equation is trivial if it contains no scalar variables.
            // To "contain no scalar variables" means that each term in the right-hand side is a unit or its weight is zero.
            let is_trivial = rhs.0.iter().all(|term| {
                matches!(term.term.scalar, ScalarTerm::Unit) || term.weight.is_zero_vartime()
            });

            // We say that an equation is homogenous if the constant term is zero.
            let is_homogenous = rhs_constant_term == lhs_value;

            // Skip processing trivial equations that are always true.
            // There's nothing to prove here.
            if is_trivial && is_homogenous {
                continue;
            }

            // Disallow non-trivial equations with trivial solutions.
            if !is_trivial && is_homogenous {
                return Err(InvalidInstance::new("Trivial kernel in this relation"));
            }

            canonical.process_constraint(lhs, rhs, relation, &mut weighted_group_cache)?;
        }

        Ok(canonical)
    }
}

impl<G: PrimeGroup + ConstantTimeEq> CanonicalLinearRelation<G> {
    /// Tests is the witness is valid.
    ///
    /// Returns a [`Choice`] indicating if the witness is valid for the instance constructed.
    ///
    /// # Panic
    ///
    /// Panics if the number of scalars given is less than the number of scalar variables.
    /// If the number of scalars is more than the number of scalar variables, the extra elements are ignored.
    pub fn is_witness_valid(&self, witness: &[G::Scalar]) -> Choice {
        let got = self.evaluate(witness);
        self.image
            .iter()
            .zip(got)
            .fold(Choice::from(1), |acc, (lhs, rhs)| acc & lhs.ct_eq(&rhs))
    }
}
