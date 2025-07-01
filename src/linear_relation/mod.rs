//! # Linear Maps and Relations Handling.
//!
//! This module provides utilities for describing and manipulating **linear group morphisms**,
//! supporting sigma protocols over group-based statements (e.g., discrete logarithms, DLEQ proofs). See Maurer09.
//!
//! It includes:
//! - [`LinearCombination`]: a sparse representation of scalar multiplication relations.
//! - [`LinearMap`]: a collection of linear combinations acting on group elements.
//! - [`LinearRelation`]: a higher-level structure managing morphisms and their associated images.

use std::collections::HashMap;
use std::hash::Hash;
use std::iter;
use std::marker::PhantomData;

use ff::Field;
use group::{Group, GroupEncoding};

use crate::codec::ShakeCodec;
use crate::errors::Error;
use crate::schnorr_protocol::SchnorrProof;
use crate::NISigmaProtocol;

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

impl<G: Group> ScalarTerm<G> {
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
pub type LinearCombination<G> = Sum<Weighted<Term<G>, <G as Group>::Scalar>>;

/// Ordered mapping of [GroupVar] to group elements assignments.
#[derive(Clone, Debug)]
pub struct GroupMap<G>(Vec<Option<G>>);

impl<G: Group> GroupMap<G> {
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
        self.0[var.0].ok_or(Error::UnassignedGroupVar {
            var_debug: format!("{var:?}"),
        })
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
}

impl<G> Default for GroupMap<G> {
    fn default() -> Self {
        Self(Vec::default())
    }
}

impl<G: Group> FromIterator<(GroupVar<G>, G)> for GroupMap<G> {
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
pub struct LinearMap<G: Group> {
    /// The set of linear combination constraints (equations).
    pub constraints: Vec<LinearCombination<G>>,
    // TODO: Update the usage of the word "morphism"
    /// The list of group elements referenced in the morphism.
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
pub fn msm_pr<G: Group>(scalars: &[G::Scalar], bases: &[G]) -> G {
    let mut acc = G::identity();
    for (s, p) in scalars.iter().zip(bases.iter()) {
        acc += *p * s;
    }
    acc
}

impl<G: Group> LinearMap<G> {
    /// Creates a new empty [`LinearMap`].
    ///
    /// # Returns
    ///
    /// A [`LinearMap`] instance with empty linear combinations and group elements,
    /// and zero allocated scalars and elements.
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            group_elements: GroupMap::default(),
            num_scalars: 0,
            num_elements: 0,
        }
    }

    /// Returns the number of constraints (equations) in this linear map.
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Adds a new linear combination constraint to the morphism.
    ///
    /// # Parameters
    /// - `lc`: The [`LinearCombination`] to add.
    pub fn append(&mut self, lc: LinearCombination<G>) {
        self.constraints.push(lc);
    }

    /// Evaluates all linear combinations in the morphism with the provided scalars.
    ///
    /// # Parameters
    /// - `scalars`: A slice of scalar values corresponding to the scalar variables.
    ///
    /// # Returns
    ///
    /// A vector of group elements, each being the result of evaluating one linear combination with the scalars.
    pub fn evaluate(&self, scalars: &[<G as Group>::Scalar]) -> Result<Vec<G>, Error> {
        self.constraints
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
/// This structure represents the *preimage problem* for a group morphism: given a set of scalar inputs,
/// determine whether their image under the morphism matches a target set of group elements.
///
/// Internally, the constraint system is defined through:
/// - A list of group elements and linear equations (held in the [`LinearMap`] field),
/// - A list of [`GroupVar`] indices (`image`) that specify the expected output for each constraint.
#[derive(Clone, Default, Debug)]
pub struct LinearRelation<G>
where
    G: Group + GroupEncoding,
{
    /// The underlying linear map describing the structure of the statement.
    pub linear_map: LinearMap<G>,
    /// Indices pointing to elements representing the "target" images for each constraint.
    pub image: Vec<GroupVar<G>>,
}

/// A normalized form of the [LinearRelation], which is used for serialization into the transcript.
// NOTE: This is not intended to be exposed beyond this module.
#[derive(Clone)]
struct LinearRelationRepr<G: GroupEncoding> {
    constraints: Vec<(u32, Vec<(u32, u32)>)>,
    group_elements: Vec<G::Repr>,
}

impl<G: GroupEncoding> Default for LinearRelationRepr<G> {
    fn default() -> Self {
        Self {
            constraints: Default::default(),
            group_elements: Default::default(),
        }
    }
}

// A utility struct used to build the LinearRelationRepr.
#[derive(Clone)]
struct LinearRelationReprBuilder<G: Group + GroupEncoding> {
    repr: LinearRelationRepr<G>,
    /// Mapping from the serialized group representation to its index in the repr.
    /// Acts as a reverse index into the group_elements.
    group_repr_mapping: HashMap<Box<[u8]>, u32>,
    /// A mapping from GroupVar index and weight to repr index, to avoid recomputing the scalar mul
    /// of the group element multiple times.
    weighted_group_cache: HashMap<GroupVar<G>, Vec<(G::Scalar, u32)>>,
}

impl<G: Group + GroupEncoding> Default for LinearRelationReprBuilder<G> {
    fn default() -> Self {
        Self {
            repr: Default::default(),
            group_repr_mapping: Default::default(),
            weighted_group_cache: Default::default(),
        }
    }
}

impl<G: Group + GroupEncoding> LinearRelationReprBuilder<G> {
    fn repr_index(&mut self, elem: &G::Repr) -> u32 {
        if let Some(index) = self.group_repr_mapping.get(elem.as_ref()) {
            return *index;
        }

        let new_index = self.repr.group_elements.len() as u32;
        self.repr.group_elements.push(*elem);
        self.group_repr_mapping
            .insert(elem.as_ref().into(), new_index);
        new_index
    }

    fn weighted_group_var_index(&mut self, var: GroupVar<G>, weight: &G::Scalar, elem: &G) -> u32 {
        let entry = self.weighted_group_cache.entry(var).or_default();

        // If the (weight, group_var) pair is already in the cache, use it.
        if let Some(index) = entry
            .iter()
            .find_map(|(entry_weight, index)| (weight == entry_weight).then_some(index))
        {
            return *index;
        }

        // Compute the scalar mul of the element and the weight, then the representation.
        let weighted_elem_repr = (*elem * weight).to_bytes();
        // Lookup or assign the index to the representation.
        let index = self.repr_index(&weighted_elem_repr);

        // Add the index to the cache.
        // NOTE: entry is dropped earlier to satisfy borrow-check rules.
        self.weighted_group_cache
            .get_mut(&var)
            .unwrap()
            .push((*weight, index));

        index
    }

    fn finalize(self) -> LinearRelationRepr<G> {
        self.repr
    }
}

impl<G> LinearRelation<G>
where
    G: Group + GroupEncoding,
{
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

    /// Allocates a scalar variable for use in the morphism.
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
    /// let mut morphism = LinearRelation::<G>::new();
    /// let [var_x, var_y] = morphism.allocate_scalars();
    /// let vars = morphism.allocate_scalars::<10>();
    /// ```
    pub fn allocate_scalars<const N: usize>(&mut self) -> [ScalarVar<G>; N] {
        let mut vars = [ScalarVar(usize::MAX, PhantomData); N];
        for var in vars.iter_mut() {
            *var = self.allocate_scalar();
        }
        vars
    }

    /// Allocates a point variable (group element) for use in the morphism.
    pub fn allocate_element(&mut self) -> GroupVar<G> {
        self.linear_map.num_elements += 1;
        GroupVar(self.linear_map.num_elements - 1, PhantomData)
    }

    /// Allocates `N` point variables (group elements) for use in the morphism.
    ///
    /// # Returns
    /// An array of [`GroupVar`] representing the newly allocated group element indices.
    ///
    /// # Example
    /// ```
    /// # use sigma_rs::LinearRelation;
    /// use curve25519_dalek::RistrettoPoint as G;
    ///
    /// let mut morphism = LinearRelation::<G>::new();
    /// let [var_g, var_h] = morphism.allocate_elements();
    /// let vars = morphism.allocate_elements::<10>();
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

    /// Evaluates all linear combinations in the morphism with the provided scalars, computing the
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
    pub fn compute_image(&mut self, scalars: &[<G as Group>::Scalar]) -> Result<(), Error> {
        if self.linear_map.num_constraints() != self.image.len() {
            // NOTE: This is a panic, rather than a returned error, because this can only happen if
            // this implementation has a bug.
            panic!("invalid LinearRelation: different number of constraints and image variables");
        }

        for (lc, lhs) in iter::zip(
            self.linear_map.constraints.as_slice(),
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
    /// A vector of group elements (`Vec<G>`) representing the morphism's image.
    // TODO: Should this return GroupMap?
    pub fn image(&self) -> Result<Vec<G>, Error> {
        self.image
            .iter()
            .map(|&var| self.linear_map.group_elements.get(var))
            .collect()
    }

    /// Returns a binary label describing the morphism.
    ///
    /// The format is:
    /// - [Ne: u32] number of equations
    /// - For each equation:
    ///   - [output_point_index: u32]
    ///   - [Nt: u32] number of terms
    ///   - Nt × [scalar_index: u32, point_index: u32] term entries
    pub fn label(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // XXX. We should return an error if the group elements are not assigned, instead of panicking.
        let repr = self.standard_repr().unwrap();

        // 1. Number of equations
        let ne = repr.constraints.len();
        out.extend_from_slice(&(ne as u32).to_le_bytes());

        // 2. Encode each equation
        for (output_index, constraint) in repr.constraints {
            // a. Output point index (LHS)
            out.extend_from_slice(&output_index.to_le_bytes());

            // b. Number of terms in the RHS linear combination
            out.extend_from_slice(&(constraint.len() as u32).to_le_bytes());

            // c. Each term: scalar index and point index
            for (scalar_index, group_index) in constraint {
                out.extend_from_slice(&scalar_index.to_le_bytes());
                out.extend_from_slice(&group_index.to_le_bytes());
            }
        }

        // Dump the group elements.
        // TODO batch serialization of group elements should not require allocation of a new vector in this case and should be part of a Group trait.
        for elem in repr.group_elements {
            out.extend_from_slice(elem.as_ref());
        }

        out
    }

    /// Construct an equivalent linear relation in the standardized form, without weights and with
    /// a single group var on the left-hand side.
    fn standard_repr(&self) -> Result<LinearRelationRepr<G>, Error> {
        assert_eq!(
            self.image.len(),
            self.linear_map.constraints.len(),
            "Number of equations and image variables must match"
        );

        let mut repr_builder = LinearRelationReprBuilder::default();

        // Iterate through the constraints, applying to remapping to weighed group variables and
        // casting scalar vars to u32.
        for (image_var, equation) in iter::zip(&self.image, &self.linear_map.constraints) {
            // Construct the right-hand side, omitting any terms that no not include a scalar, as
            // they will be moved to the left-hand side.
            let rhs: Vec<(u32, u32)> = equation
                .terms()
                .iter()
                .filter_map(|weighted_term| match weighted_term.term.scalar {
                    ScalarTerm::Var(var) => {
                        Some((var, weighted_term.term.elem, weighted_term.weight))
                    }
                    ScalarTerm::Unit => None,
                })
                .map(|(scalar_var, group_var, weight)| {
                    let group_val = self.linear_map.group_elements.get(group_var)?;
                    let group_index =
                        repr_builder.weighted_group_var_index(group_var, &weight, &group_val);
                    Ok((scalar_var.0 as u32, group_index))
                })
                .collect::<Result<_, _>>()?;

            // Construct the left-hand side, subtracting all the terms on the right that don't have
            // a variable scalar term.
            let image_val = self.linear_map.group_elements.get(*image_var)?;
            let lhs_val = equation
                .terms()
                .iter()
                .filter_map(|weighted_term| match weighted_term.term.scalar {
                    ScalarTerm::Unit => Some((weighted_term.term.elem, weighted_term.weight)),
                    ScalarTerm::Var(_) => None,
                })
                .try_fold(image_val, |sum, (group_var, weight)| {
                    let group_val = self.linear_map.group_elements.get(group_var)?;
                    Ok(sum - group_val * weight)
                })?;
            let lhs_index = repr_builder.repr_index(&lhs_val.to_bytes());

            repr_builder.repr.constraints.push((lhs_index, rhs));
        }

        Ok(repr_builder.finalize())
    }

    /// Convert this LinearRelation into a non-interactive zero-knowledge protocol
    /// using the ShakeCodec and a specified context/domain separator.
    ///
    /// # Parameters
    /// - `context`: Domain separator bytes for the Fiat-Shamir transform
    ///
    /// # Returns
    /// A `NISigmaProtocol` instance ready for proving and verification
    ///
    /// # Example
    /// ```
    /// # use sigma_rs::{LinearRelation, NISigmaProtocol};
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
    ) -> NISigmaProtocol<SchnorrProof<G>, ShakeCodec<G>>
    where
        G: group::GroupEncoding,
    {
        let schnorr = SchnorrProof::from(self);
        NISigmaProtocol::new(session_identifier, schnorr)
    }
}
