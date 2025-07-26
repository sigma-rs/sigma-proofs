//! # Linear Maps and Relations Handling.
//!
//! This module provides utilities for describing and manipulating **linear group linear maps**,
//! supporting sigma protocols over group-based statements (e.g., discrete logarithms, DLEQ proofs). See Maurer09.
//!
//! It includes:
//! - [`LinearCombination`]: a sparse representation of scalar multiplication relations.
//! - [`LinearMap`]: a collection of linear combinations acting on group elements.
//! - [`LinearRelation`]: a higher-level structure managing linear maps and their associated images.

use std::collections::HashMap;
use std::hash::Hash;
use std::iter;
use std::marker::PhantomData;

use ff::Field;
use group::prime::PrimeGroup;

use crate::codec::Shake128DuplexSponge;
use crate::errors::Error;
use crate::schnorr_protocol::SchnorrProof;
use crate::Nizk;

/// Implementations of conversion operations such as From and FromIterator for var and term types.
mod convert;
/// Implementations of core ops for the linear combination types.
mod ops;

/// A wrapper representing an index for a scalar variable.
///
/// Used to reference scalars in sparse linear combinations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ScalarVar<G>(usize, PhantomData<G>);

impl<G> ScalarVar<G> {
    pub fn index(&self) -> usize {
        self.0
    }
}

impl<G> Hash for ScalarVar<G> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

/// A wrapper representing an index for a group element (point).
///
/// Used to reference group elements in sparse linear combinations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GroupVar<G>(usize, PhantomData<G>);

impl<G> GroupVar<G> {
    pub fn index(&self) -> usize {
        self.0
    }
}

impl<G> Hash for GroupVar<G> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum ScalarTerm<G> {
    Var(ScalarVar<G>),
    Unit,
}

impl<G: PrimeGroup> ScalarTerm<G> {
    // NOTE: This function is private intentionally as it would be replaced if a ScalarMap struct
    // were to be added.
    fn value(self, scalars: &[G::Scalar]) -> G::Scalar {
        match self {
            Self::Var(var) => scalars[var.0],
            Self::Unit => G::Scalar::ONE,
        }
    }
}

/// A term in a linear combination, representing `scalar * elem`.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Term<G> {
    scalar: ScalarTerm<G>,
    elem: GroupVar<G>,
}

#[derive(Copy, Clone, Debug)]
pub struct Weighted<T, F> {
    pub term: T,
    pub weight: F,
}

#[derive(Clone, Debug)]
pub struct Sum<T>(Vec<T>);

impl<T> Sum<T> {
    /// Access the terms of the sum as slice reference.
    pub fn terms(&self) -> &[T] {
        &self.0
    }
}

/// Represents a sparse linear combination of scalars and group elements.
///
/// For example, it can represent an equation like:
/// `w_1 * (s_1 * P_1) + w_2 * (s_2 * P_2) + ... + w_n * (s_n * P_n)`
///
/// where:
/// - `(s_i * P_i)` are the terms, with `s_i` scalars (referenced by `scalar_vars`) and `P_i` group elements (referenced by `element_vars`).
/// - `w_i` are the constant weight scalars
///
/// The indices refer to external lists managed by the containing LinearMap.
pub type LinearCombination<G> = Sum<Weighted<Term<G>, <G as group::Group>::Scalar>>;

/// Ordered mapping of [GroupVar] to group elements assignments.
#[derive(Clone, Debug)]
pub struct GroupMap<G>(Vec<Option<G>>);

impl<G: PrimeGroup> GroupMap<G> {
    /// Assign a group element value to a point variable.
    ///
    /// # Parameters
    ///
    /// - `var`: The variable to assign.
    /// - `element`: The value to assign to the variable.
    ///
    /// # Panics
    ///
    /// Panics if the given assignment conflicts with the existing assignment.
    pub fn assign_element(&mut self, var: GroupVar<G>, element: G) {
        if self.0.len() <= var.0 {
            self.0.resize(var.0 + 1, None);
        } else if let Some(assignment) = self.0[var.0] {
            assert_eq!(
                assignment, element,
                "conflicting assignments for var {var:?}"
            )
        }
        self.0[var.0] = Some(element);
    }

    /// Assigns specific group elements to point variables (indices).
    ///
    /// # Parameters
    ///
    /// - `assignments`: A collection of `(GroupVar, GroupElement)` pairs that can be iterated over.
    ///
    /// # Panics
    ///
    /// Panics if the collection contains two conflicting assignments for the same variable.
    pub fn assign_elements(&mut self, assignments: impl IntoIterator<Item = (GroupVar<G>, G)>) {
        for (var, elem) in assignments.into_iter() {
            self.assign_element(var, elem);
        }
    }

    /// Get the element value assigned to the given point var.
    ///
    /// Returns [`Error::UnassignedGroupVar`] if a value is not assigned.
    pub fn get(&self, var: GroupVar<G>) -> Result<G, Error> {
        match self.0.get(var.0) {
            Some(Some(elem)) => Ok(*elem),
            Some(None) => Err(Error::UnassignedGroupVar {
                var_debug: format!("{var:?}"),
            }),
            None => Err(Error::UnassignedGroupVar {
                var_debug: format!("{var:?}"),
            }),
        }
    }

    /// Iterate over the assigned variable and group element pairs in this mapping.
    // NOTE: Not implemented as `IntoIterator` for now because doing so requires explicitly
    // defining an iterator type, See https://github.com/rust-lang/rust/issues/63063
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> impl Iterator<Item = (GroupVar<G>, Option<G>)> {
        self.0
            .into_iter()
            .enumerate()
            .map(|(i, x)| (GroupVar(i, PhantomData), x))
    }

    pub fn iter(&self) -> impl Iterator<Item = (GroupVar<G>, Option<&G>)> {
        self.0
            .iter()
            .enumerate()
            .map(|(i, opt)| (GroupVar(i, PhantomData), opt.as_ref()))
    }

    /// Add a new group element to the map and return its variable index
    pub fn push(&mut self, element: G) -> GroupVar<G> {
        let index = self.0.len();
        self.0.push(Some(element));
        GroupVar(index, PhantomData)
    }

    /// Get the number of elements in the map
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<G> Default for GroupMap<G> {
    fn default() -> Self {
        Self(Vec::default())
    }
}

impl<G: PrimeGroup> FromIterator<(GroupVar<G>, G)> for GroupMap<G> {
    fn from_iter<T: IntoIterator<Item = (GroupVar<G>, G)>>(iter: T) -> Self {
        iter.into_iter()
            .fold(Self::default(), |mut instance, (var, val)| {
                instance.assign_element(var, val);
                instance
            })
    }
}

/// A LinearMap represents a list of linear combinations over group elements.
///
/// It supports dynamic allocation of scalars and elements,
/// and evaluates by performing multi-scalar multiplications.
#[derive(Clone, Default, Debug)]
pub struct LinearMap<G: PrimeGroup> {
    /// The set of linear combination constraints (equations).
    pub linear_combinations: Vec<LinearCombination<G>>,
    /// The list of group elements referenced in the linear map.
    ///
    /// Uninitialized group elements are presented with `None`.
    pub group_elements: GroupMap<G>,
    /// The total number of scalar variables allocated.
    pub num_scalars: usize,
    /// The total number of group element variables allocated.
    pub num_elements: usize,
}

/// Perform a simple multi-scalar multiplication (MSM) over scalars and points.
///
/// Given slices of scalars and corresponding group elements (bases),
/// returns the sum of each base multiplied by its scalar coefficient.
///
/// # Parameters
/// - `scalars`: slice of scalar multipliers.
/// - `bases`: slice of group elements to be multiplied by the scalars.
///
/// # Returns
/// The group element result of the MSM.
pub fn msm_pr<G: PrimeGroup>(scalars: &[G::Scalar], bases: &[G]) -> G {
    let mut acc = G::identity();
    for (s, p) in scalars.iter().zip(bases.iter()) {
        acc += *p * s;
    }
    acc
}

impl<G: PrimeGroup> LinearMap<G> {
    /// Creates a new empty [`LinearMap`].
    ///
    /// # Returns
    ///
    /// A [`LinearMap`] instance with empty linear combinations and group elements,
    /// and zero allocated scalars and elements.
    pub fn new() -> Self {
        Self {
            linear_combinations: Vec::new(),
            group_elements: GroupMap::default(),
            num_scalars: 0,
            num_elements: 0,
        }
    }

    /// Returns the number of constraints (equations) in this linear map.
    pub fn num_constraints(&self) -> usize {
        self.linear_combinations.len()
    }

    /// Adds a new linear combination constraint to the linear map.
    ///
    /// # Parameters
    /// - `lc`: The [`LinearCombination`] to add.
    pub fn append(&mut self, lc: LinearCombination<G>) {
        self.linear_combinations.push(lc);
    }

    /// Evaluates all linear combinations in the linear map with the provided scalars.
    ///
    /// # Parameters
    /// - `scalars`: A slice of scalar values corresponding to the scalar variables.
    ///
    /// # Returns
    ///
    /// A vector of group elements, each being the result of evaluating one linear combination with the scalars.
    pub fn evaluate(&self, scalars: &[G::Scalar]) -> Result<Vec<G>, Error> {
        self.linear_combinations
            .iter()
            .map(|lc| {
                // TODO: The multiplication by the (public) weight is potentially wasteful in the
                // weight is most commonly 1, but multiplication is constant time.
                let weighted_coefficients =
                    lc.0.iter()
                        .map(|weighted| weighted.term.scalar.value(scalars) * weighted.weight)
                        .collect::<Vec<_>>();
                let elements =
                    lc.0.iter()
                        .map(|weighted| self.group_elements.get(weighted.term.elem))
                        .collect::<Result<Vec<_>, Error>>()?;
                Ok(msm_pr(&weighted_coefficients, &elements))
            })
            .collect()
    }
}

/// A wrapper struct coupling a [`LinearMap`] with the corresponding expected output (image) elements.
///
/// This structure represents the *preimage problem* for a group linear map: given a set of scalar inputs,
/// determine whether their image under the linear map matches a target set of group elements.
///
/// Internally, the constraint system is defined through:
/// - A list of group elements and linear equations (held in the [`LinearMap`] field),
/// - A list of [`GroupVar`] indices (`image`) that specify the expected output for each constraint.
#[derive(Clone, Default, Debug)]
pub struct LinearRelation<G: PrimeGroup> {
    /// The underlying linear map describing the structure of the statement.
    pub linear_map: LinearMap<G>,
    /// Indices pointing to elements representing the "target" images for each constraint.
    pub image: Vec<GroupVar<G>>,
}

/// A normalized form of the [LinearRelation], which is used for serialization into the transcript.
///
/// This struct represents a normalized form of a linear relation where each
/// constraint is of the form: image[i] = Σ (scalar_j * group_element_k)
/// without weights or extra scalars.
#[derive(Clone, Debug, Default)]
#[warn(clippy::type_complexity)]
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

type WeightedCache<A, B> = HashMap<B, Vec<(A, B)>>;

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
        weighted_group_cache: &mut WeightedCache<G::Scalar, GroupVar<G>>,
    ) -> Result<GroupVar<G>, Error> {
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
        image_var: GroupVar<G>,
        equation: &LinearCombination<G>,
        original_relation: &LinearRelation<G>,
        weighted_group_cache: &mut WeightedCache<G::Scalar, GroupVar<G>>,
    ) -> Result<(), Error> {
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

impl<G: PrimeGroup> TryFrom<&LinearRelation<G>> for CanonicalLinearRelation<G> {
    type Error = Error;

    fn try_from(relation: &LinearRelation<G>) -> Result<Self, Self::Error> {
        // Number of equations and image variables must match
        if relation.image.len() != relation.linear_map.linear_combinations.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        // If the image is the identity, then the relation must be trivial, or else the proof will be unsound
        if !relation
            .image()
            .is_ok_and(|img| img.iter().all(|&x| x != G::identity()))
        {
            return Err(Error::InvalidInstanceWitnessPair);
        }
        // Empty relations (without constraints) cannot be proven
        if relation.linear_map.linear_combinations.is_empty() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        // If any linear combination is empty, the relation is invalid
        if relation
            .linear_map
            .linear_combinations
            .iter()
            .any(|lc| lc.0.is_empty())
        {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        // If any linear combination has no witness variables, the relation is invalid
        if relation.linear_map.linear_combinations.iter().any(|lc| {
            lc.0.iter()
                .all(|weighted| matches!(weighted.term.scalar, ScalarTerm::Unit))
        }) {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let mut canonical = CanonicalLinearRelation::new();
        canonical.num_scalars = relation.linear_map.num_scalars;

        // Cache for deduplicating weighted group elements
        let mut weighted_group_cache = HashMap::new();

        // Process each constraint using the modular helper method
        for (image_var, equation) in
            iter::zip(&relation.image, &relation.linear_map.linear_combinations)
        {
            canonical.process_constraint(
                *image_var,
                equation,
                relation,
                &mut weighted_group_cache,
            )?;
        }

        Ok(canonical)
    }
}

impl<G: PrimeGroup> LinearRelation<G> {
    /// Create a new empty [`LinearRelation`].
    pub fn new() -> Self {
        Self {
            linear_map: LinearMap::new(),
            image: Vec::new(),
        }
    }

    /// Adds a new equation to the statement of the form:
    /// `lhs = Σ weight_i * (scalar_i * point_i)`.
    ///
    /// # Parameters
    /// - `lhs`: The image group element variable (left-hand side of the equation).
    /// - `rhs`: An instance of [`LinearCombination`] representing the linear combination on the right-hand side.
    pub fn append_equation(&mut self, lhs: GroupVar<G>, rhs: impl Into<LinearCombination<G>>) {
        self.linear_map.append(rhs.into());
        self.image.push(lhs);
    }

    /// Adds a new equation to the statement of the form:
    /// `lhs = Σ weight_i * (scalar_i * point_i)` without allocating `lhs`.
    ///
    /// # Parameters
    /// - `rhs`: An instance of [`LinearCombination`] representing the linear combination on the right-hand side.
    pub fn allocate_eq(&mut self, rhs: impl Into<LinearCombination<G>>) -> GroupVar<G> {
        let var = self.allocate_element();
        self.append_equation(var, rhs);
        var
    }

    /// Allocates a scalar variable for use in the linear map.
    pub fn allocate_scalar(&mut self) -> ScalarVar<G> {
        self.linear_map.num_scalars += 1;
        ScalarVar(self.linear_map.num_scalars - 1, PhantomData)
    }

    /// Allocates space for `N` new scalar variables.
    ///
    /// # Returns
    /// An array of [`ScalarVar`] representing the newly allocated scalar indices.
    ///
    /// # Example
    /// ```
    /// # use sigma_rs::LinearRelation;
    /// use curve25519_dalek::RistrettoPoint as G;
    ///
    /// let mut relation = LinearRelation::<G>::new();
    /// let [var_x, var_y] = relation.allocate_scalars();
    /// let vars = relation.allocate_scalars::<10>();
    /// ```
    pub fn allocate_scalars<const N: usize>(&mut self) -> [ScalarVar<G>; N] {
        let mut vars = [ScalarVar(usize::MAX, PhantomData); N];
        for var in vars.iter_mut() {
            *var = self.allocate_scalar();
        }
        vars
    }

    /// Allocates a point variable (group element) for use in the linear map.
    pub fn allocate_element(&mut self) -> GroupVar<G> {
        self.linear_map.num_elements += 1;
        GroupVar(self.linear_map.num_elements - 1, PhantomData)
    }

    /// Allocates `N` point variables (group elements) for use in the linear map.
    ///
    /// # Returns
    /// An array of [`GroupVar`] representing the newly allocated group element indices.
    ///
    /// # Example
    /// ```
    /// # use sigma_rs::LinearRelation;
    /// use curve25519_dalek::RistrettoPoint as G;
    ///
    /// let mut relation = LinearRelation::<G>::new();
    /// let [var_g, var_h] = relation.allocate_elements();
    /// let vars = relation.allocate_elements::<10>();
    /// ```
    pub fn allocate_elements<const N: usize>(&mut self) -> [GroupVar<G>; N] {
        let mut vars = [GroupVar(usize::MAX, PhantomData); N];
        for var in vars.iter_mut() {
            *var = self.allocate_element();
        }
        vars
    }

    /// Assign a group element value to a point variable.
    ///
    /// # Parameters
    ///
    /// - `var`: The variable to assign.
    /// - `element`: The value to assign to the variable.
    ///
    /// # Panics
    ///
    /// Panics if the given assignment conflicts with the existing assignment.
    pub fn set_element(&mut self, var: GroupVar<G>, element: G) {
        self.linear_map.group_elements.assign_element(var, element)
    }

    /// Assigns specific group elements to point variables (indices).
    ///
    /// # Parameters
    ///
    /// - `assignments`: A collection of `(GroupVar, GroupElement)` pairs that can be iterated over.
    ///
    /// # Panics
    ///
    /// Panics if the collection contains two conflicting assignments for the same variable.
    pub fn set_elements(&mut self, assignments: impl IntoIterator<Item = (GroupVar<G>, G)>) {
        self.linear_map.group_elements.assign_elements(assignments)
    }

    /// Evaluates all linear combinations in the linear map with the provided scalars, computing the
    /// left-hand side of this constraints (i.e. the image).
    ///
    /// After calling this function, all point variables will be assigned.
    ///
    /// # Parameters
    ///
    /// - `scalars`: A slice of scalar values corresponding to the scalar variables.
    ///
    /// # Returns
    ///
    /// Return `Ok` on success, and an error if unassigned elements prevent the image from being
    /// computed. Modifies the group elements assigned in the [LinearRelation].
    pub fn compute_image(&mut self, scalars: &[G::Scalar]) -> Result<(), Error> {
        if self.linear_map.num_constraints() != self.image.len() {
            // NOTE: This is a panic, rather than a returned error, because this can only happen if
            // this implementation has a bug.
            panic!("invalid LinearRelation: different number of constraints and image variables");
        }

        for (lc, lhs) in iter::zip(
            self.linear_map.linear_combinations.as_slice(),
            self.image.as_slice(),
        ) {
            // TODO: The multiplication by the (public) weight is potentially wasteful in the
            // weight is most commonly 1, but multiplication is constant time.
            let weighted_coefficients =
                lc.0.iter()
                    .map(|weighted| weighted.term.scalar.value(scalars) * weighted.weight)
                    .collect::<Vec<_>>();
            let elements =
                lc.0.iter()
                    .map(|weighted| self.linear_map.group_elements.get(weighted.term.elem))
                    .collect::<Result<Vec<_>, Error>>()?;
            self.linear_map
                .group_elements
                .assign_element(*lhs, msm_pr(&weighted_coefficients, &elements))
        }
        Ok(())
    }

    /// Returns the current group elements corresponding to the image variables.
    ///
    /// # Returns
    ///
    /// A vector of group elements (`Vec<G>`) representing the linear map's image.
    // TODO: Should this return GroupMap?
    pub fn image(&self) -> Result<Vec<G>, Error> {
        self.image
            .iter()
            .map(|&var| self.linear_map.group_elements.get(var))
            .collect()
    }

    /// Convert this LinearRelation into a non-interactive zero-knowledge protocol
    /// using the ShakeCodec and a specified context/domain separator.
    ///
    /// # Parameters
    /// - `context`: Domain separator bytes for the Fiat-Shamir transform
    ///
    /// # Returns
    /// A `Nizk` instance ready for proving and verification
    ///
    /// # Example
    /// ```
    /// # use sigma_rs::{LinearRelation, Nizk};
    /// # use curve25519_dalek::RistrettoPoint as G;
    /// # use curve25519_dalek::scalar::Scalar;
    /// # use rand::rngs::OsRng;
    /// # use group::Group;
    ///
    /// let mut relation = LinearRelation::<G>::new();
    /// let x_var = relation.allocate_scalar();
    /// let g_var = relation.allocate_element();
    /// let p_var = relation.allocate_eq(x_var * g_var);
    ///
    /// relation.set_element(g_var, G::generator());
    /// let x = Scalar::random(&mut OsRng);
    /// relation.compute_image(&[x]).unwrap();
    ///
    /// // Convert to NIZK with custom context
    /// let nizk = relation.into_nizk(b"my-protocol-v1");
    /// let proof = nizk.prove_batchable(&vec![x], &mut OsRng).unwrap();
    /// assert!(nizk.verify_batchable(&proof).is_ok());
    /// ```
    pub fn into_nizk(
        self,
        session_identifier: &[u8],
    ) -> Nizk<SchnorrProof<G>, Shake128DuplexSponge<G>> {
        let schnorr =
            SchnorrProof::try_from(self).expect("Failed to convert LinearRelation to SchnorrProof");
        Nizk::new(session_identifier, schnorr)
    }
}
