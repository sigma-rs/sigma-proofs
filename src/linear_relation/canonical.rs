
use std::collections::HashMap;
use std::iter;
use std::marker::PhantomData;

use ff::Field;
use group::prime::PrimeGroup;

use crate::errors::{Error, InvalidInstance};
use super::{ScalarVar, GroupVar, GroupMap, LinearRelation, LinearCombination, ScalarTerm};


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

impl<G: PrimeGroup> CanonicalLinearRelation<G> {
    /// Create a new empty canonical linear relation
    pub fn new() -> Self {
        Self {
            image: Vec::new(),
            linear_combinations: Vec::new(),
            group_elements: GroupMap::default(),
            num_scalars: 0,
        }
    }

    /// Get or create a GroupVar for a weighted group element, with deduplication
    fn get_or_create_weighted_group_var(
        &mut self,
        group_var: GroupVar<G>,
        weight: &G::Scalar,
        original_group_elements: &GroupMap<G>,
        weighted_group_cache: &mut HashMap<GroupVar<G>, Vec<(G::Scalar, GroupVar<G>)>>,
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

    /// Process a single constraint equation and add it to the canonical relation
    fn process_constraint(
        &mut self,
        &image_var: &GroupVar<G>,
        equation: &LinearCombination<G>,
        original_relation: &LinearRelation<G>,
        weighted_group_cache: &mut HashMap<GroupVar<G>, Vec<(G::Scalar, GroupVar<G>)>>,
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
        self.image.push(canonical_image);
        self.linear_combinations.push(rhs_terms);

        Ok(())
    }

    /// Serialize the linear relation to bytes.
    ///
    /// The output format is:
    /// - [Ne: u32] number of equations
    /// - Ne × equations:
    ///   - [lhs_index: u32] output group element index
    ///   - [Nt: u32] number of terms
    ///   - Nt × [scalar_index: u32, group_index: u32] term entries
    /// - Followed by all group elements in serialized form
    pub fn label(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Replicate the original LinearRelationReprBuilder ordering behavior
        let mut group_repr_mapping: HashMap<Box<[u8]>, u32> = HashMap::new();
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

        // Build constraint data in the same order as original
        let mut constraint_data = Vec::new();

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

    /// Parse a canonical linear relation from its label representation
    pub fn from_label(data: &[u8]) -> Result<Self, Error> {
        use crate::errors::InvalidInstance;
        use crate::serialization::group_elt_serialized_len;

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
                    "Invalid group element at index {}",
                    i
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

impl<G: PrimeGroup> TryFrom<&LinearRelation<G>> for CanonicalLinearRelation<G> {
    type Error = InvalidInstance;

    fn try_from(relation: &LinearRelation<G>) -> Result<Self, Self::Error> {
        if relation.image.len() != relation.linear_map.linear_combinations.len() {
            return Err(InvalidInstance::new(
                "Equations and image elements must match",
            ));
        }

        if !relation
            .image()
            .is_ok_and(|img| img.iter().all(|&x| x != G::identity()))
        {
            return Err(InvalidInstance::new("Image contains identity element"));
        }

        let mut canonical = CanonicalLinearRelation::new();
        canonical.num_scalars = relation.linear_map.num_scalars;

        // Cache for deduplicating weighted group elements
        let mut weighted_group_cache = HashMap::new();

        // Process each constraint using the modular helper method
        for (lhs, rhs) in
            iter::zip(&relation.image, &relation.linear_map.linear_combinations)
        {
            // If the linear combination is trivial, check it directly and skip processing.
            if rhs.0.iter().all(|weighted| matches!(weighted.term.scalar, ScalarTerm::Unit)) {
                let lhs_value = relation
                    .linear_map
                    .group_elements
                    .get(*lhs)
                    .map_err(|_| InvalidInstance::new("Unassigned group variable in image"))?;

                let rhs_value = rhs.0.iter().fold(G::identity(), |acc, weighted| {
                    acc + relation
                        .linear_map
                        .group_elements
                        .get(weighted.term.elem)
                        .unwrap_or_else(|_| panic!("Unassigned group variable in linear combination"))
                        * weighted.weight
                });
                if lhs_value != rhs_value {
                    return Err(InvalidInstance::new("Trivial linear combination does not match image"));
                } else {
                    continue; // Skip processing trivial constraints
                }
            }

            canonical.process_constraint(
                lhs,
                rhs,
                relation,
                &mut weighted_group_cache,
            )?;
        }

        Ok(canonical)
    }
}
