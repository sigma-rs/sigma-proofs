#[cfg(not(feature = "std"))]
use ahash::RandomState;
use alloc::format;
use alloc::vec::Vec;
use core::iter;
use core::marker::PhantomData;
#[cfg(not(feature = "std"))]
use hashbrown::{HashMap, HashSet};
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use ff::Field;
use group::prime::PrimeGroup;
use subtle::{Choice, ConstantTimeEq};

use super::{
    GroupMap, GroupVar, LinearCombination, LinearRelation, ScalarAssignments, ScalarTerm, ScalarVar,
};
use crate::errors::{Error, InvalidInstance};
use crate::group::msm::VariableMultiScalarMul;
use crate::linear_relation::Allocator;
use crate::serialization::serialize_elements;

// XXX. this definition is uncomfortably similar to LinearRelation, exception made for the weights.
// It'd be nice to better compress potentially duplicated code.
/// A normalized form of the [`LinearRelation`], which is used for serialization into the transcript.
///
/// This struct represents a normalized form of a linear relation where each
/// constraint is of the form: image_i = Σ (scalar_j * group_element_k)
/// without weights or extra scalars.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct CanonicalLinearRelation<G: PrimeGroup> {
    /// The image group elements (left-hand side of equations)
    pub image: Vec<GroupVar<G>>,
    /// The constraints, where each constraint is a vector of (scalar_var, group_var) pairs
    /// representing the right-hand side of the equation
    pub linear_combinations: Vec<Vec<(ScalarVar<G>, GroupVar<G>)>>,
    /// The group elements map
    pub group_elements: GroupMap<G>,
    /// Set of scalar variables used in this relation.
    pub scalar_vars: HashSet<ScalarVar<G>>,
}

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
            scalar_vars: HashSet::default(),
        }
    }

    // QUESTION: Why does this currently panic when a variable is unassigned? Should this return
    // Result instead?
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
    pub fn evaluate(&self, scalars: impl ScalarAssignments<G>) -> Vec<G> {
        self.linear_combinations
            .iter()
            .map(|lc| {
                let scalars = lc
                    .iter()
                    .map(|(scalar_var, _)| scalars.get(*scalar_var).unwrap())
                    .collect::<Vec<_>>();
                let bases = lc
                    .iter()
                    .map(|(_, group_var)| self.group_elements.get(*group_var).unwrap())
                    .collect::<Vec<_>>();
                G::msm(&scalars, &bases)
            })
            .collect()
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

        // Build constraint data in the same order as original, as a nested list of group and
        // scalar indices. Note that the group indices are into group_elements_ordered.
        let mut constraint_data = Vec::<(u32, Vec<(u32, u32)>)>::new();

        for (image_var, constraint_terms) in iter::zip(&self.image, &self.linear_combinations) {
            // Build the RHS terms
            let mut rhs_terms = Vec::new();
            for (scalar_var, group_var) in constraint_terms {
                rhs_terms.push((scalar_var.0 as u32, group_var.0 as u32));
            }

            constraint_data.push((image_var.0 as u32, rhs_terms));
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

        // Dump the group elements.
        let group_reprs = serialize_elements(
            self.group_elements
                .iter()
                .map(|(_, elem)| elem.expect("expected group variable to be assigned")),
        );
        out.extend_from_slice(&group_reprs);

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
        canonical.scalar_vars = (0..=max_scalar_index as usize)
            .map(|i| ScalarVar(i, PhantomData))
            .collect();

        // Add all group elements to the map
        let mut group_var_map = Vec::new();
        for elem in &group_elements_ordered {
            let var = canonical.group_elements.allocate_element_with(*elem);
            group_var_map.push(var);
        }

        // Build constraints
        for (lhs_index, rhs_terms) in constraint_data {
            // Add image element
            canonical.image.push(group_var_map[lhs_index as usize]);

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

    /// Access the group elements associated with the image (i.e. left-hand side), panicking if any
    /// of the image variables are unassigned in the group mkap.
    pub(crate) fn image_elements(&self) -> impl Iterator<Item = G> + use<'_, G> {
        self.image.iter().map(|var| {
            self.group_elements
                .get(*var)
                .expect("expected group variable to be assigned")
        })
    }
}

impl<G: PrimeGroup, A: Allocator<G = G>> TryFrom<LinearRelation<G, A>>
    for CanonicalLinearRelation<G>
{
    type Error = InvalidInstance;

    fn try_from(value: LinearRelation<G, A>) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<G: PrimeGroup, A: Allocator<G = G>> TryFrom<&LinearRelation<G, A>>
    for CanonicalLinearRelation<G>
{
    type Error = InvalidInstance;

    fn try_from(relation: &LinearRelation<G, A>) -> Result<Self, Self::Error> {
        if relation.image.len() != relation.linear_combinations.len() {
            return Err(InvalidInstance::new(
                "Number of equations must be equal to number of image elements.",
            ));
        }

        // Process each constraint using the canonical linear relation builder.
        let mut builder = CanonicalLinearRelationBuilder::default();
        for (lhs, rhs) in iter::zip(&relation.image, &relation.linear_combinations) {
            // If any group element in the image is not assigned, return `InvalidInstance`.
            let lhs_value = relation.heap.get_element(*lhs)?;

            // Compute the constant terms on the right-hand side of the equation.
            // If any group element in the linear constraints is not assigned, return `InvalidInstance`.
            let rhs_constant_terms = rhs
                .0
                .iter()
                .filter(|term| matches!(term.term.scalar, ScalarTerm::Unit))
                .map(|term| {
                    let elem = relation.heap.get_element(term.term.elem)?;
                    let scalar = term.weight;
                    Ok((elem, scalar))
                })
                .collect::<Result<(Vec<G>, Vec<G::Scalar>), Self::Error>>()?;

            let rhs_constant_term = G::msm(&rhs_constant_terms.1, &rhs_constant_terms.0);

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

            builder.process_constraint(lhs, rhs, relation)?;
        }

        Ok(builder.build())
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
    pub fn is_witness_valid(&self, witness: impl ScalarAssignments<G>) -> Choice {
        let got = self.evaluate(witness);
        self.image_elements()
            .zip(got)
            .fold(Choice::from(1), |acc, (lhs, rhs)| acc & lhs.ct_eq(&rhs))
    }
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

#[derive(Debug)]
struct CanonicalLinearRelationBuilder<G: PrimeGroup> {
    relation: CanonicalLinearRelation<G>,
    weighted_group_cache: WeightedGroupCache<G>,
}

impl<G: PrimeGroup> CanonicalLinearRelationBuilder<G> {
    /// Get or create a GroupVar for a weighted group element, with deduplication
    fn get_or_create_weighted_group_var<A: Allocator<G = G>>(
        &mut self,
        group_var: GroupVar<G>,
        weight: &G::Scalar,
        original_alloc: &A,
    ) -> Result<GroupVar<G>, InvalidInstance> {
        // Check if we already have this (weight, group_var) combination
        let entry = self.weighted_group_cache.entry(group_var).or_default();

        // Find if we already have this weight for this group_var
        if let Some((_, existing_var)) = entry.iter().find(|(w, _)| w == weight) {
            return Ok(*existing_var);
        }

        // Create new weighted group element
        // Use a special case for one, as this is the most common weight.
        let original_group_val = original_alloc.get_element(group_var)?;
        let weighted_group = match *weight == G::Scalar::ONE {
            true => original_group_val,
            false => original_group_val * weight,
        };

        // Add to our group elements with new index (length)
        let new_var = self
            .relation
            .group_elements
            .allocate_element_with(weighted_group);

        // Cache the mapping for this group_var and weight
        entry.push((*weight, new_var));

        Ok(new_var)
    }

    /// Process a single constraint equation and add it to the canonical relation.
    fn process_constraint<A: Allocator<G = G>>(
        &mut self,
        &image_var: &GroupVar<G>,
        equation: &LinearCombination<G>,
        allocator: &A,
    ) -> Result<(), InvalidInstance> {
        let mut rhs_terms = Vec::new();

        // Collect RHS terms that have scalar variables and apply weights
        for weighted_term in equation.terms() {
            if let ScalarTerm::Var(scalar_var) = weighted_term.term.scalar {
                let group_var = weighted_term.term.elem;
                let weight = &weighted_term.weight;

                if weight.is_zero_vartime() {
                    continue; // Skip zero weights
                }

                let canonical_group_var =
                    self.get_or_create_weighted_group_var(group_var, weight, allocator)?;

                rhs_terms.push((scalar_var, canonical_group_var));
                self.relation.scalar_vars.insert(scalar_var);
            }
        }

        // Compute the canonical image by subtracting constant terms from the original image
        let mut canonical_image = allocator.get_element(image_var)?;
        for weighted_term in equation.terms() {
            if let ScalarTerm::Unit = weighted_term.term.scalar {
                let group_val = allocator.get_element(weighted_term.term.elem)?;
                canonical_image -= group_val * weighted_term.weight;
            }
        }

        // Only include constraints that are non-trivial (not zero constraints).
        if rhs_terms.is_empty() {
            if canonical_image.is_identity().into() {
                return Ok(());
            }
            return Err(InvalidInstance::new(
                "trivially false constraint: constraint has empty right-hand side and non-identity left-hand side",
            ));
        }

        let canonical_image_group_var = self
            .relation
            .group_elements
            .allocate_element_with(canonical_image);
        self.relation.image.push(canonical_image_group_var);
        self.relation.linear_combinations.push(rhs_terms);

        Ok(())
    }

    fn build(self) -> CanonicalLinearRelation<G> {
        self.relation
    }
}

impl<G: PrimeGroup> Default for CanonicalLinearRelationBuilder<G> {
    fn default() -> Self {
        #[cfg(feature = "std")]
        let weighted_group_cache = HashMap::new();
        #[cfg(not(feature = "std"))]
        let weighted_group_cache = HashMap::with_hasher(RandomState::new());

        Self {
            relation: CanonicalLinearRelation::new(),
            weighted_group_cache,
        }
    }
}
