//! # Group Morphism and Preimage Handling
//!
//! This module provides utilities for describing and manipulating **linear group morphisms**,
//! supporting sigma protocols over group-based statements (e.g., discrete logarithms, DLEQ proofs). See Maurer09.
//!
//! It includes:
//! - [`LinearCombination`]: a sparse representation of scalar multiplication relations
//! - [`Morphism`]: a collection of linear combinations acting on group elements
//! - [`GroupMorphismPreimage`]: a higher-level structure managing morphisms and their associated images

use std::iter;
use std::marker::PhantomData;

use crate::errors::Error;
use ff::Field;
use group::{Group, GroupEncoding};

/// Implementations of core ops for the linear combination types.
mod ops;

/// A wrapper representing an index for a scalar variable.
///
/// Used to reference scalars in sparse linear combinations.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ScalarVar(usize);

impl ScalarVar {
    pub fn index(&self) -> usize {
        self.0
    }
}

/// A wrapper representing an index for a group element (point).
///
/// Used to reference group elements in sparse linear combinations.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct PointVar<G>(usize, PhantomData<G>);

impl<G> PointVar<G> {
    pub fn index(&self) -> usize {
        self.0
    }
}

/// A term in a linear combination, representing `scalar * elem * weight`.
#[derive(Copy, Clone, Debug)]
pub struct Term<G: Group> {
    scalar: ScalarVar,
    elem: PointVar<G>,
    /// A public constanat weight applied to the point as part of the morphism.
    weight: G::Scalar,
}

impl<G: Group> From<(ScalarVar, PointVar<G>)> for Term<G> {
    fn from((scalar, elem): (ScalarVar, PointVar<G>)) -> Self {
        Self {
            scalar,
            elem,
            weight: G::Scalar::ONE,
        }
    }
}

/// Represents a sparse linear combination of scalars and group elements.
///
/// For example, it can represent an equation like:
/// `s_1 * P_1 + s_2 * P_2 + ... + s_n * P_n`
///
/// where `s_i` are scalars (referenced by `scalar_vars`) and `P_i` are group elements (referenced by `element_vars`).
///
/// The indices refer to external lists managed by the containing Morphism.
pub struct LinearCombination<G: Group>(Vec<Term<G>>);

impl<G: Group, T: Into<Term<G>>> From<T> for LinearCombination<G> {
    fn from(term: T) -> Self {
        Self(vec![term.into()])
    }
}

impl<G: Group, T: Into<Term<G>>> From<Vec<T>> for LinearCombination<G> {
    fn from(terms: Vec<T>) -> Self {
        Self(terms.into_iter().map(|x| x.into()).collect())
    }
}

impl<G: Group, T: Into<Term<G>>, const N: usize> From<[T; N]> for LinearCombination<G> {
    fn from(terms: [T; N]) -> Self {
        Self(terms.into_iter().map(|x| x.into()).collect())
    }
}

impl<G: Group, T: Into<Term<G>>> FromIterator<T> for LinearCombination<G> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(iter.into_iter().map(|x| x.into()).collect())
    }
}

/// Instance of a relation (i.e. morphism) containing assignments of [PointVar] to group elements.
// QUESTION: Name was chosen with relation to the name "relation". Should it be named something
// else if we want to call the structure its related to "morphism"?
#[derive(Clone, Debug)]
pub struct Instance<G>(Vec<Option<G>>);

impl<G: Group> Instance<G> {
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
    pub fn assign_element(&mut self, var: PointVar<G>, element: G) {
        if self.0.len() <= var.0 {
            self.0.resize(var.0 + 1, None);
        } else if let Some(assignment) = self.0[var.0] {
            // QUESTION: Should we panic here? It seems like a good sanity check in that if you
            // assign the same point twice, its probably a mistake. But maybe there are legitimate
            // reasons to do this.
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
    /// - `assignments`: A collection of `(PointVar, GroupElement)` pairs that can be iterated over.
    ///
    /// # Panics
    ///
    /// Panics if the collection contains two conflicting assignments for the same variable.
    pub fn assign_elements(&mut self, assignments: impl IntoIterator<Item = (PointVar<G>, G)>) {
        for (var, elem) in assignments.into_iter() {
            self.assign_element(var, elem);
        }
    }

    /// Get the element value assigned to the given point var.
    ///
    /// Returns [Error::UninitializedPointVar] if a value is not assigned.
    pub fn get(&self, var: PointVar<G>) -> Result<G, Error> {
        self.0[var.0].ok_or(Error::UnassignedPointVar {
            var: PointVar(var.0, PhantomData),
        })
    }

    /// Iterate over the assigned variables in this instance.
    // NOTE: Not implemented as `IntoIterator` for now because doing so requires explicitly
    // defining an iterator type, See https://github.com/rust-lang/rust/issues/63063
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> impl Iterator<Item = (PointVar<G>, G)> {
        self.0
            .into_iter()
            .enumerate()
            .filter_map(|(i, x)| x.map(|x| (PointVar(i, PhantomData), x)))
    }
}

impl<G> Default for Instance<G> {
    fn default() -> Self {
        Self(Vec::default())
    }
}

/// A Morphism represents a list of linear combinations over group elements.
///
/// It supports dynamic allocation of scalars and elements,
/// and evaluates by performing multi-scalar multiplications.
#[derive(Default)]
pub struct Morphism<G: Group> {
    /// The set of linear combination constraints (equations).
    pub constraints: Vec<LinearCombination<G>>,
    /// The list of group elements referenced in the morphism.
    ///
    /// Uninitialized group elements are presented with `None`.
    pub instance: Instance<G>,
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
/// - `scalars`: slice of scalar multipliers
/// - `bases`: slice of group elements to be multiplied by the scalars
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

impl<G: Group> Morphism<G> {
    /// Creates a new empty [`Morphism`].
    ///
    /// # Returns
    ///
    /// A [`Morphism`] instance with empty linear combinations and group elements,
    /// and zero allocated scalars and elements.
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            instance: Instance::default(),
            num_scalars: 0,
            num_elements: 0,
        }
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
                let coefficients =
                    lc.0.iter()
                        .map(|term| scalars[term.scalar.0] * term.weight)
                        .collect::<Vec<_>>();
                let elements =
                    lc.0.iter()
                        .map(|term| self.instance.get(term.elem))
                        .collect::<Result<Vec<_>, Error>>()?;
                Ok(msm_pr(&coefficients, &elements))
            })
            .collect()
    }
}

/// A wrapper struct coupling a [`Morphism`] with the corresponding expected output (image) elements.
///
/// This structure represents the *preimage problem* for a group morphism: given a set of scalar inputs,
/// determine whether their image under the morphism matches a target set of group elements.
///
/// Internally, the constraint system is defined through:
/// - A list of group elements and linear equations (held in the [`Morphism`] field),
/// - A list of [`PointVar`] indices (`image`) that specify the expected output for each constraint.
#[derive(Default)]
pub struct GroupMorphismPreimage<G>
where
    G: Group + GroupEncoding,
{
    /// The underlying morphism describing the structure of the statement.
    pub morphism: Morphism<G>,
    /// Indices pointing to elements representing the "target" images for each constraint.
    pub image: Vec<PointVar<G>>,
}

impl<G> GroupMorphismPreimage<G>
where
    G: Group + GroupEncoding,
{
    /// Create a new empty GroupMorphismPreimage.
    pub fn new() -> Self {
        Self {
            morphism: Morphism::new(),
            image: Vec::new(),
        }
    }

    /// Computes the total number of bytes required to serialize all current commitments.
    pub fn commit_bytes_len(&self) -> usize {
        let repr_len = <G::Repr as Default>::default().as_ref().len(); // size of encoded point
        self.morphism.constraints.len() * repr_len // total size of a commit
    }

    /// Adds a new equation to the statement of the form:
    /// `lhs = Σ (scalar_i * point_i)`
    ///
    /// # Parameters
    /// - `lhs`: The image group element variable (left-hand side of the equation).
    /// - `rhs`: A slice of `(ScalarVar, PointVar)` pairs representing the linear combination on the right-hand side.
    pub fn constrain(&mut self, lhs: PointVar<G>, rhs: impl Into<LinearCombination<G>>) {
        self.morphism.append(rhs.into());
        self.image.push(lhs);
    }

    /// Adds a new equation to the statement of the form:
    /// `lhs = Σ (scalar_i * point_i)`
    ///
    /// # Parameters
    /// - `lhs`: The image group element variable (left-hand side of the equation).
    /// - `rhs`: A slice of `(ScalarVar, PointVar)` pairs representing the linear combination on the right-hand side.
    pub fn allocate_eq(&mut self, rhs: impl Into<LinearCombination<G>>) -> PointVar<G> {
        let var = self.allocate_element();
        self.constrain(var, rhs);
        var
    }

    /// Allocates a scalar variable for use in the morphism.
    pub fn allocate_scalar(&mut self) -> ScalarVar {
        self.morphism.num_scalars += 1;
        ScalarVar(self.morphism.num_scalars - 1)
    }

    /// Allocates space for `N` new scalar variables.
    ///
    /// # Returns
    /// An array of [`ScalarVar`] representing the newly allocated scalar indices.
    ///
    /// # Example
    /// ```
    /// # use sigma_rs::group_morphism::GroupMorphismPreimage;
    /// use curve25519_dalek::RistrettoPoint as G;
    ///
    /// let mut morphism = GroupMorphismPreimage::<G>::new();
    /// let [var_x, var_y] = morphism.allocate_scalars();
    /// let vars = morphism.allocate_scalars::<10>();
    /// ```
    pub fn allocate_scalars<const N: usize>(&mut self) -> [ScalarVar; N] {
        let mut vars = [ScalarVar(usize::MAX); N];
        for var in vars.iter_mut() {
            *var = self.allocate_scalar();
        }
        vars
    }

    /// Allocates a point variable (group element) for use in the morphism.
    pub fn allocate_element(&mut self) -> PointVar<G> {
        self.morphism.num_elements += 1;
        PointVar(self.morphism.num_elements - 1, PhantomData)
    }

    /// Allocates `N` point variables (group elements) for use in the morphism.
    ///
    /// # Returns
    /// An array of [`PointVar`] representing the newly allocated group element indices.
    ///
    /// # Example
    /// ```
    /// # use sigma_rs::group_morphism::GroupMorphismPreimage;
    /// use curve25519_dalek::RistrettoPoint as G;
    ///
    /// let mut morphism = GroupMorphismPreimage::<G>::new();
    /// let [var_g, var_h] = morphism.allocate_elements();
    /// let vars = morphism.allocate_elements::<10>();
    /// ```
    pub fn allocate_elements<const N: usize>(&mut self) -> [PointVar<G>; N] {
        let mut vars = [PointVar(usize::MAX, PhantomData); N];
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
    pub fn assign_element(&mut self, var: PointVar<G>, element: G) {
        self.morphism.instance.assign_element(var, element)
    }

    /// Assigns specific group elements to point variables (indices).
    ///
    /// # Parameters
    ///
    /// - `assignments`: A collection of `(PointVar, GroupElement)` pairs that can be iterated over.
    ///
    /// # Panics
    ///
    /// Panics if the collection contains two conflicting assignments for the same variable.
    pub fn assign_elements(&mut self, assignments: impl IntoIterator<Item = (PointVar<G>, G)>) {
        self.morphism.instance.assign_elements(assignments)
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
    /// computed. Modifies the instance in the [GroupMorphismPreimage].
    pub fn compute_image(&mut self, scalars: &[<G as Group>::Scalar]) -> Result<(), Error> {
        if self.morphism.constraints.len() != self.image.len() {
            panic!(
                "invalid GroupMorphismPreimage: different number of constraints and image variables"
            );
        }

        for (lc, lhs) in iter::zip(self.morphism.constraints.as_slice(), self.image.as_slice()) {
            let coefficients =
                lc.0.iter()
                    .map(|term| scalars[term.scalar.0] * term.weight)
                    .collect::<Vec<_>>();
            let elements =
                lc.0.iter()
                    .map(|term| self.morphism.instance.get(term.elem))
                    .collect::<Result<Vec<_>, Error>>()?;
            self.morphism
                .instance
                .assign_element(*lhs, msm_pr(&coefficients, &elements))
        }
        Ok(())
    }

    /// Returns the current group elements corresponding to the image variables.
    ///
    /// # Returns
    ///
    /// A vector of group elements (`Vec<G>`) representing the morphism's image.
    // TODO: Should this return Instance?
    pub fn image(&self) -> Result<Vec<G>, Error> {
        self.image
            .iter()
            .map(|&var| self.morphism.instance.get(var))
            .collect()
    }
}
