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
pub use allocator::Allocator;

use alloc::vec::Vec;
use collections::{UnassignedGroupVarError, UnassignedScalarVarError};
use core::iter;
use core::marker::PhantomData;

use ff::Field;
use group::prime::PrimeGroup;

use crate::codec::Shake128DuplexSponge;
use crate::errors::{Error, InvalidInstance};
use crate::group::msm::VariableMultiScalarMul;
use crate::linear_relation::allocator::Heap;
use crate::Nizk;

/// A wrapper representing an reference for a scalar variable.
///
/// Used to reference scalars in sparse linear combinations.
#[derive(Debug, PartialEq, Eq)]
pub struct ScalarVar<G>(usize, PhantomData<G>);

impl<G> ScalarVar<G> {
    // QUESTION: Should I mark this method as deprecated? It currently leaks the internal
    // representation of the variable and may not be stable. It's not clear what valid use cases
    // there are for this index.
    pub fn index(&self) -> usize {
        self.0
    }
}

// Implement copy and clone for all G
impl<G> Copy for ScalarVar<G> {}
impl<G> Clone for ScalarVar<G> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<G> core::hash::Hash for ScalarVar<G> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

/// A wrapper representing a reference for a group element (i.e. elliptic curve point).
///
/// Used to reference group elements in sparse linear combinations.
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
    pub heap: A,
    /// References pointing to elements representing the "target" images for each constraint.
    pub image: Vec<GroupVar<G>>,
}

impl<G: PrimeGroup> LinearRelation<G> {
    /// Create a new empty [`LinearRelation`].
    pub fn new() -> Self {
        Self {
            linear_combinations: Vec::new(),
            heap: Default::default(),
            image: Vec::new(),
        }
    }
}

impl<G: PrimeGroup, A: Allocator<G = G>> LinearRelation<G, A> {
    /// Create a new empty [`LinearRelation`] using the given [`Allocator`].
    pub fn new_in(allocator: A) -> Self {
        Self {
            linear_combinations: Vec::new(),
            heap: allocator,
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
    pub fn compute_image(&mut self, scalars: impl ScalarAssignments<G>) -> Result<(), Error> {
        if self.linear_combinations.len() != self.image.len() {
            // NOTE: This is a panic, rather than a returned error, because this can only happen if
            // this implementation has a bug.
            panic!("invalid LinearRelation: different number of constraints and image variables");
        }

        let mapped_scalars: Vec<(GroupVar<G>, G)> =
            iter::zip(self.image.iter().copied(), self.evaluate(scalars)?).collect();

        self.heap.assign_elements(mapped_scalars);
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
            .map(|&var| self.heap.get_element(var))
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
    pub fn evaluate(&self, scalars: impl ScalarAssignments<G>) -> Result<Vec<G>, Error> {
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
                        .map(|weighted| self.heap.get_element(weighted.term.elem))
                        .collect::<Result<Vec<_>, _>>()?;
                Ok(G::msm(&weighted_coefficients, &elements))
            })
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
    /// relation.compute_image([(x_var, x)]).unwrap();
    ///
    /// // Convert to NIZK with custom context
    /// let nizk = relation.into_nizk(b"my-protocol-v1").unwrap();
    /// let proof = nizk.prove_batchable([(x_var, x)], &mut OsRng).unwrap();
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
}

impl<G: PrimeGroup, A: Allocator<G = G>> Allocator for LinearRelation<G, A> {
    type G = G;

    /// Allocates a scalar variable for use in the linear map.
    fn allocate_scalar(&mut self) -> ScalarVar<G> {
        self.heap.allocate_scalar()
    }

    /// Allocates a group element variable (i.e. elliptic curve point) for use in the linear map.
    fn allocate_element(&mut self) -> GroupVar<G> {
        self.heap.allocate_element()
    }

    fn assign_element(&mut self, var: GroupVar<Self::G>, element: Self::G) {
        self.heap.assign_element(var, element)
    }

    fn get_element(&self, var: GroupVar<Self::G>) -> Result<Self::G, UnassignedGroupVarError> {
        self.heap.get_element(var)
    }
}
