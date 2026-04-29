//! # Linear Maps and Relations Handling.
//!
//! This module provides utilities for describing and manipulating **linear group linear maps**,
//! supporting sigma protocols over group-based statements (e.g., discrete logarithms, DLEQ proofs). See Maurer09.
//!
//! It includes:
//! - [`LinearCombination`]: a sparse representation of scalar multiplication relations.
//! - [`LinearMap`]: a collection of linear combinations acting on group elements.
//! - [`LinearRelation`]: a higher-level structure managing linear maps and their associated images.
/// Implementations of conversion operations such as From and FromIterator for var and term types.
mod convert;
/// Implementations of core ops for the linear combination types.
mod ops;

/// Implementation of canonical linear relation.
mod canonical;
pub use canonical::CanonicalLinearRelation;

/// Collections for group elements and scalars, used in the linear maps.
pub(crate) mod collections;
pub use collections::{GroupMap, ScalarAssignments, ScalarMap};

mod allocator;
pub use allocator::{Allocator, Heap};

use alloc::vec::Vec;
use collections::{UnassignedGroupVarError, UnassignedScalarVarError};
use core::marker::PhantomData;

use ff::Field;
use group::prime::PrimeGroup;

use crate::errors::{Error, InvalidInstance};
use crate::group::msm::MultiScalarMul;

// NOTE: This type is intended to opaque.
/// A reference for a scalar variable in a relation.
#[derive(Debug)]
pub struct ScalarVar<G> {
    index: u32,
    tag: u32,
    phantom_g: PhantomData<G>,
}

// Implement core traits for ScalarVar.
// NOTE: Derive cannot be used because it requires all generic paramter types to implement the
// derived trait. Instead, we provide a manual implementation over all G without bounds.
// TODO: Include some metadata to determine if two variables come from the same allocator and use
// it below.
impl<G> Copy for ScalarVar<G> {}
impl<G> Clone for ScalarVar<G> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<G> core::hash::Hash for ScalarVar<G> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.tag.hash(state);
        self.index.hash(state);
    }
}

/// Compare two variables, returning `true` if there are the same variable (i.e. the symbolically
/// reference the same scalar).
///
/// Variables from two distinct allocators are unequal by definition.
impl<G> PartialEq for ScalarVar<G> {
    fn eq(&self, other: &Self) -> bool {
        self.tag == other.tag && self.index == other.index
    }
}

/// Compare two variables, returning `true` if there are the same variable (i.e. the symbolically
/// reference the same scalar).
///
/// Variables from two distinct allocators are unequal by definition.
impl<G> Eq for ScalarVar<G> {}

/// Partial ordering for [`ScalarVar`].
///
/// Variables created by an allocator are ordered by their allocation, such that variables created
/// earlier as "less" than variables created later. Variables created by two distinct allocators
/// have no defined ordering.
impl<G> PartialOrd for ScalarVar<G> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Total ordering for [`ScalarVar`].
///
/// Variables created by an allocator are ordered by the allocation, such that variables created
/// earlier as "less" than variables created later. Variables created by two distinct allocators
/// have no defined ordering.
impl<G> Ord for ScalarVar<G> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.tag, self.index).cmp(&(other.tag, other.index))
    }
}

/// A wrapper representing a reference for a group element (i.e. elliptic curve point).
///
/// Used to reference group elements in sparse linear combinations.
// TODO: If GroupVar has an ordering, then the CanonicalLinearRelation encoding could be made
// invariant to order of the constraints and perhaps the building could be made more efficient.
#[derive(Debug, PartialEq, Eq)]
pub struct GroupVar<G>(usize, PhantomData<G>);

impl<G> GroupVar<G> {
    pub fn index(&self) -> usize {
        self.0
    }
}

// Implement copy and clone for all G
impl<G> Copy for GroupVar<G> {}
impl<G> Clone for GroupVar<G> {
    fn clone(&self) -> Self {
        *self
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
    // TODO: Move this function onto ScalarMap instead? Maybe ScalarMap should have an associated
    // valuation function.
    fn value(
        self,
        scalars: &impl ScalarAssignments<G>,
    ) -> Result<G::Scalar, UnassignedScalarVarError> {
        Ok(match self {
            Self::Var(var) => scalars.get(var)?,
            Self::Unit => G::Scalar::ONE,
        })
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
pub type LinearCombination<G> = Sum<Weighted<Term<G>, <G as group::Group>::Scalar>>;

/// This structure represents the *preimage problem* for a group linear map: given a set of scalar inputs,
/// determine whether their image under the linear map matches a target set of group elements.
///
/// Internally, the constraint system is defined through:
/// - A list of group elements and linear equations.
/// - A list of [`GroupVar`] references (`image`) that specify the expected output for each constraint.
#[non_exhaustive]
#[derive(Clone, Default, Debug)]
pub struct LinearRelation<G: PrimeGroup, A = Heap<G>> {
    /// The set of linear combination constraints (equations).
    pub linear_combinations: Vec<LinearCombination<G>>,
    // TODO(victor): Should the allocator be pub? We provide a pass-through impl Allocator for LinearRelation
    pub allocator: A,
    /// References pointing to elements representing the "target" images for each constraint.
    pub image: Vec<GroupVar<G>>,
}

impl<G: PrimeGroup> LinearRelation<G> {
    /// Create a new empty [`LinearRelation`].
    pub fn new() -> Self {
        Self {
            linear_combinations: Vec::new(),
            allocator: Default::default(),
            image: Vec::new(),
        }
    }
}

impl<G: PrimeGroup, A: Allocator<G = G>> LinearRelation<G, A> {
    /// Create a new empty [`LinearRelation`] using the given [`Allocator`].
    pub fn new_in(allocator: A) -> Self {
        Self {
            linear_combinations: Vec::new(),
            allocator,
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
        self.linear_combinations.push(rhs.into());
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

    /// Allocates a group element variable (i.e. elliptic curve point) and sets it immediately to the given value
    pub fn allocate_element_with(&mut self, element: G) -> GroupVar<G> {
        let var = self.allocate_element();
        self.assign_element(var, element);
        var
    }

    /// Allocates a point variable (group element) and sets it immediately to the given value.
    pub fn allocate_elements_with(&mut self, elements: &[G]) -> Vec<GroupVar<G>> {
        elements
            .iter()
            .map(|element| self.allocate_element_with(*element))
            .collect()
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
    pub fn compute_image(&mut self, scalars: impl ScalarAssignments<G>) -> Result<(), Error>
    where
        G: MultiScalarMul,
    {
        if self.linear_combinations.len() != self.image.len() {
            // NOTE: This is a panic, rather than a returned error, because this can only happen if
            // this implementation has a bug.
            panic!("invalid LinearRelation: different number of constraints and image variables");
        }

        let mapped_scalars: Vec<(GroupVar<G>, G)> =
            itertools::zip_eq(self.image.iter().copied(), self.evaluate(scalars)?).collect();

        self.allocator.assign_elements(mapped_scalars);
        Ok(())
    }

    /// Returns the current group elements corresponding to the image variables.
    ///
    /// # Returns
    ///
    /// A vector of group elements (`Vec<G>`) representing the linear map's image.
    // TODO: Should this return GroupMap?
    pub fn image(&self) -> Result<Vec<G>, UnassignedGroupVarError> {
        self.image
            .iter()
            .map(|&var| self.allocator.get_element(var))
            .collect()
    }

    /// Evaluates all linear combinations in the linear relation with the provided scalars.
    ///
    /// # Parameters
    /// - `scalars`: A slice of scalar values corresponding to the scalar variables.
    ///
    /// # Returns
    ///
    /// A vector of group elements, each being the result of evaluating one linear combination with the scalars.
    pub fn evaluate(&self, scalars: impl ScalarAssignments<G>) -> Result<Vec<G>, Error>
    where
        G: MultiScalarMul,
    {
        self.linear_combinations
            .iter()
            .map(|lc| {
                // TODO: The multiplication by the (public) weight is potentially wasteful in the
                // weight is most commonly 1, but multiplication is constant time.
                let weighted_coefficients =
                    lc.0.iter()
                        .map(|weighted| {
                            weighted
                                .term
                                .scalar
                                .value(&scalars)
                                .map(|scalar| scalar * weighted.weight)
                        })
                        .collect::<Result<Vec<_>, UnassignedScalarVarError>>()?;
                let elements =
                    lc.0.iter()
                        .map(|weighted| self.allocator.get_element(weighted.term.elem))
                        .collect::<Result<Vec<_>, _>>()?;
                Ok(G::msm(&weighted_coefficients, &elements))
            })
            .collect()
    }

    /// Construct a [CanonicalLinearRelation] from this generalized linear relation.
    ///
    /// The construction may fail if the linear relation is malformed, unsatisfiable, or trivial.
    pub fn canonical(&self) -> Result<CanonicalLinearRelation<G>, InvalidInstance>
    where
        G: MultiScalarMul,
    {
        self.try_into()
    }
}

impl<G: PrimeGroup, A: Allocator<G = G>> Allocator for LinearRelation<G, A> {
    type G = G;

    /// Allocates a scalar variable for use in the linear map.
    fn allocate_scalar(&mut self) -> ScalarVar<G> {
        self.allocator.allocate_scalar()
    }

    /// Allocates a group element variable (i.e. elliptic curve point) for use in the linear map.
    fn allocate_element(&mut self) -> GroupVar<G> {
        self.allocator.allocate_element()
    }

    fn assign_element(&mut self, var: GroupVar<Self::G>, element: Self::G) {
        self.allocator.assign_element(var, element)
    }

    fn get_element(&self, var: GroupVar<Self::G>) -> Result<Self::G, UnassignedGroupVarError> {
        self.allocator.get_element(var)
    }
}
