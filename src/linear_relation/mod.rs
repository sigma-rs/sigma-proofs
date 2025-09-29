//! # Linear Maps and Relations Handling.
//!
//! This module provides utilities for describing and manipulating **linear group linear maps**,
//! supporting sigma protocols over group-based statements (e.g., discrete logarithms, DLEQ proofs). See Maurer09.
//!
//! It includes:
//! - [`LinearCombination`]: a sparse representation of scalar multiplication relations.
//! - [`LinearMap`]: a collection of linear combinations acting on group elements.
//! - [`LinearRelation`]: a higher-level structure managing linear maps and their associated images.

use alloc::format;
use alloc::vec::Vec;
use core::iter;
use core::marker::PhantomData;

use ff::Field;
use group::prime::PrimeGroup;

use crate::codec::Shake128DuplexSponge;
use crate::errors::{Error, InvalidInstance};
use crate::group::msm::VariableMultiScalarMul;
use crate::Nizk;

/// Implementations of conversion operations such as From and FromIterator for var and term types.
mod convert;
/// Implementations of core ops for the linear combination types.
mod ops;

/// Implementation of canonical linear relation.
mod canonical;
pub use canonical::CanonicalLinearRelation;

/// A wrapper representing an index for a scalar variable.
///
/// Used to reference scalars in sparse linear combinations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ScalarVar<G>(pub(crate) usize, PhantomData<G>);

impl<G> ScalarVar<G> {
    pub fn index(&self) -> usize {
        self.0
    }
}

impl<G> core::hash::Hash for ScalarVar<G> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
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

impl<G> core::hash::Hash for GroupVar<G> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
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

impl<T> core::iter::Sum<T> for Sum<T> {
    /// Add a bunch of `T` to yield a `Sum<T>`
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        Self(iter.collect())
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

impl<G: PrimeGroup> LinearMap<G> {
    fn map(&self, scalars: &[G::Scalar]) -> Result<Vec<G>, InvalidInstance> {
        self.linear_combinations
            .iter()
            .map(|lc| {
                let weighted_coefficients =
                    lc.0.iter()
                        .map(|weighted| weighted.term.scalar.value(scalars) * weighted.weight)
                        .collect::<Vec<_>>();
                let elements =
                    lc.0.iter()
                        .map(|weighted| self.group_elements.get(weighted.term.elem))
                        .collect::<Result<Vec<_>, InvalidInstance>>();
                match elements {
                    Ok(elements) => Ok(G::msm(&weighted_coefficients, &elements)),
                    Err(error) => Err(error),
                }
            })
            .collect::<Result<Vec<_>, InvalidInstance>>()
    }
}

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
    /// Returns [`InvalidInstance`] if a value is not assigned.
    pub fn get(&self, var: GroupVar<G>) -> Result<G, InvalidInstance> {
        match self.0.get(var.0) {
            Some(Some(elem)) => Ok(*elem),
            Some(None) | None => Err(InvalidInstance::new(format!(
                "unassigned group variable {}",
                var.0
            ))),
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
                        .collect::<Result<Vec<_>, _>>()?;
                Ok(G::msm(&weighted_coefficients, &elements))
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
    /// # use sigma_proofs::LinearRelation;
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

    /// Allocates a vector of new scalar variables.
    ///
    /// # Returns
    /// A vector of [`ScalarVar`] representing the newly allocated scalar indices.
    ///    /// # Example
    /// ```
    /// # use sigma_proofs::LinearRelation;
    /// use curve25519_dalek::RistrettoPoint as G;
    ///
    /// let mut relation = LinearRelation::<G>::new();
    /// let [var_x, var_y] = relation.allocate_scalars();
    /// let vars = relation.allocate_scalars_vec(10);
    /// ```
    pub fn allocate_scalars_vec(&mut self, n: usize) -> Vec<ScalarVar<G>> {
        (0..n).map(|_| self.allocate_scalar()).collect()
    }

    /// Allocates a point variable (group element) for use in the linear map.
    pub fn allocate_element(&mut self) -> GroupVar<G> {
        self.linear_map.num_elements += 1;
        GroupVar(self.linear_map.num_elements - 1, PhantomData)
    }

    /// Allocates a point variable (group element) and sets it immediately to the given value
    pub fn allocate_element_with(&mut self, element: G) -> GroupVar<G> {
        let var = self.allocate_element();
        self.set_element(var, element);
        var
    }

    /// Allocates `N` point variables (group elements) for use in the linear map.
    ///
    /// # Returns
    /// An array of [`GroupVar`] representing the newly allocated group element indices.
    ///
    /// # Example
    /// ```
    /// # use sigma_proofs::LinearRelation;
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

    /// Allocates a vector of new point variables (group elements).
    ///
    /// # Returns
    /// A vector of [`GroupVar`] representing the newly allocated group element indices.
    ///
    /// # Example
    /// ```
    /// # use sigma_proofs::LinearRelation;
    /// use curve25519_dalek::RistrettoPoint as G;
    /// let mut relation = LinearRelation::<G>::new();
    /// let [var_g, var_h
    /// ] = relation.allocate_elements();
    /// let vars = relation.allocate_elements_vec(10);
    /// ```
    pub fn allocate_elements_vec(&mut self, n: usize) -> Vec<GroupVar<G>> {
        (0..n).map(|_| self.allocate_element()).collect()
    }

    /// Allocates a point variable (group element) and sets it immediately to the given value.
    pub fn allocate_elements_with(&mut self, elements: &[G]) -> Vec<GroupVar<G>> {
        elements
            .iter()
            .map(|element| self.allocate_element_with(*element))
            .collect()
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

        let mapped_scalars = self.linear_map.map(scalars)?;

        for (mapped_scalar, lhs) in iter::zip(mapped_scalars, &self.image) {
            self.linear_map
                .group_elements
                .assign_element(*lhs, mapped_scalar)
        }
        Ok(())
    }

    /// Returns the current group elements corresponding to the image variables.
    ///
    /// # Returns
    ///
    /// A vector of group elements (`Vec<G>`) representing the linear map's image.
    // TODO: Should this return GroupMap?
    pub fn image(&self) -> Result<Vec<G>, InvalidInstance> {
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
    /// # use sigma_proofs::{LinearRelation, Nizk};
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
    /// let nizk = relation.into_nizk(b"my-protocol-v1").unwrap();
    /// let proof = nizk.prove_batchable(&vec![x], &mut OsRng).unwrap();
    /// assert!(nizk.verify_batchable(&proof).is_ok());
    /// ```
    pub fn into_nizk(
        self,
        session_identifier: &[u8],
    ) -> Result<Nizk<CanonicalLinearRelation<G>, Shake128DuplexSponge<G>>, InvalidInstance> {
        Ok(Nizk::new(session_identifier, self.try_into()?))
    }

    /// Construct a [CanonicalLinearRelation] from this generalized linear relation.
    ///
    /// The construction may fail if the linear relation is malformed, unsatisfiable, or trivial.
    pub fn canonical(&self) -> Result<CanonicalLinearRelation<G>, InvalidInstance> {
        self.try_into()
    }

    #[warn(unstable_features)]
    pub fn squashed(&self) -> Result<LinearRelation<G>, InvalidInstance> {
        // xxx. get a challenge from the original data.
        let batch_challenge = G::Scalar::from(424242);

        let batch_challenges = powers(batch_challenge, self.image.len());

        // squash the image
        let mut squashed_image_bases = self.image()?;
        let mut squashed_image_scalars = batch_challenges.clone();

        // squash the linear combination
        let mut squashed_lc_bases = vec![G::identity(); self.linear_map.num_scalars];
        let mut squashed_lc_scalars = vec![G::Scalar::ZERO; self.linear_map.num_scalars];

        for (i, linear_combination) in self.linear_map.linear_combinations.iter().enumerate() {
            for weighted_term in linear_combination.terms() {
                let term_base = self
                    .linear_map
                    .group_elements
                    .get(weighted_term.term.elem)?;

                match weighted_term.term.scalar {
                    ScalarTerm::Unit => {
                        squashed_image_scalars.push(batch_challenges[i] * weighted_term.weight);
                        squashed_image_bases.push(term_base);
                    }
                    ScalarTerm::Var(var) => {
                        let scalar_index = var.index();
                        squashed_lc_scalars[scalar_index] +=
                            batch_challenges[i] * weighted_term.weight;
                        squashed_lc_bases[scalar_index] = term_base;
                    }
                }
            }
        }

        let squashed_image = G::msm(&squashed_image_scalars, &squashed_image_bases);
        let squashed_lc = squashed_lc_bases
            .into_iter()
            .zip(squashed_lc_scalars)
            .map(|(base, scalar)| base * scalar)
            .collect::<Vec<_>>();

        let mut squashed_lr = LinearRelation::new();
        let scalar_vars = squashed_lr.allocate_scalars_vec(squashed_lc.len());
        let group_vars = squashed_lr.allocate_elements_with(&squashed_lc);

        let image_var = squashed_lr.allocate_eq(
            group_vars
                .into_iter()
                .zip(scalar_vars)
                .map(|(base, scalar_var)| scalar_var * base)
                .sum::<Sum<_>>(),
        );
        squashed_lr.set_element(image_var, squashed_image);

        Ok(squashed_lr)
    }
}

pub(crate) fn powers<F: Field>(element: F, len: usize) -> Vec<F> {
    let mut powers = vec![F::ONE; len];
    for i in 1..len {
        powers[i] = element * powers[i - 1];
    }
    powers
}

#[test]
pub fn test_bbs_blind_commitment() {
    type G = curve25519_dalek::ristretto::RistrettoPoint;
    type Scalar = curve25519_dalek::scalar::Scalar;
    let rng = &mut rand::rngs::OsRng;

    let [Q_2, J_1, J_2, J_3] = [
        G::random(&mut *rng),
        G::random(&mut *rng),
        G::random(&mut *rng),
        G::random(&mut *rng),
    ];
    let [msg_1, msg_2, msg_3] = [
        Scalar::random(&mut *rng),
        Scalar::random(&mut *rng),
        Scalar::random(&mut *rng),
    ];
    let secret_prover_blind = Scalar::random(&mut *rng);
    let mut relation = LinearRelation::new();

    // these are computed before the proof in the specification
    let C = Q_2 * secret_prover_blind + J_1 * msg_1 + J_2 * msg_2 + J_3 * msg_3;

    // This is the part that needs to be changed in the specification of blind bbs.
    let [var_secret_prover_blind, var_msg_1, var_msg_2, var_msg_3] = relation.allocate_scalars();

    // Match Sage's allocation order: allocate all elements in the same order
    let [var_Q_2, var_J_1, var_J_2, var_J_3] = relation.allocate_elements();
    let var_C = relation.allocate_element(); // Allocate var_C separately, giving it index 4

    // Now append the equation separately (like Sage's append_equation)
    relation.append_equation(
        var_C,
        var_secret_prover_blind * var_Q_2
            + var_msg_1 * var_J_1
            + var_msg_2 * var_J_2
            + var_msg_3 * var_J_3,
    );

    relation.set_elements([
        (var_Q_2, Q_2),
        (var_J_1, J_1),
        (var_J_2, J_2),
        (var_J_3, J_3),
        (var_C, C),
    ]);

    let witness = vec![secret_prover_blind, msg_1, msg_2, msg_3];

    assert!(vec![C] == relation.linear_map.evaluate(&witness).unwrap());

    let nizk = relation.squashed().unwrap().into_nizk(b"").unwrap();
    let proof = nizk.prove_batchable(&witness, &mut *rng).unwrap();
    assert!(nizk.verify_batchable(&proof).is_ok());
}
