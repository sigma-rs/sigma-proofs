//! # Linear Maps and Relations Handling.
//!
//! This module provides utilities for describing and manipulating **linear group morphisms**,
//! supporting sigma protocols over group-based statements (e.g., discrete logarithms, DLEQ proofs). See Maurer09.
//!
//! It includes:
//! - [`LinearCombination`]: a sparse representation of scalar multiplication relations.
//! - [`LinearMap`]: a collection of linear combinations acting on group elements.
//! - [`LinearRelation`]: a higher-level structure managing morphisms and their associated images.

use std::collections::BTreeMap;
use std::iter;

use ff::Field;
use group::{Group, GroupEncoding};

use crate::errors::Error;

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
pub struct GroupVar(usize);

impl GroupVar {
    pub fn index(&self) -> usize {
        self.0
    }
}

/// A term in a linear combination, representing `scalar * elem`.
#[derive(Copy, Clone, Debug)]
pub struct Term {
    scalar: ScalarVar,
    elem: GroupVar,
}

// QUESTION: Why have accessor functions? Its not generally ideomatic in Rust, which prefers public
// fields. One reason for this is that, unlike C++ of Java, Rust has strong notions of immutability
// in that a normal reference to an object cannot be used to mutate its fields.

impl From<(ScalarVar, GroupVar)> for Term {
    fn from((scalar, elem): (ScalarVar, GroupVar)) -> Self {
        Self { scalar, elem }
    }
}

impl<F: Field> From<(ScalarVar, GroupVar)> for Weighted<Term, F> {
    fn from(pair: (ScalarVar, GroupVar)) -> Self {
        Term::from(pair).into()
    }
}

// TODO: Should this be generic over the field instead of the group?
#[derive(Copy, Clone, Debug)]
pub struct Weighted<T, F> {
    pub term: T,
    pub weight: F,
}

impl<T, F: Field> From<T> for Weighted<T, F> {
    fn from(term: T) -> Self {
        Self {
            term,
            weight: F::ONE,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Sum<T>(Vec<T>);

impl<T> Sum<T> {
    /// Access the terms of the sum as slice reference.
    pub fn terms(&self) -> &[T] {
        &self.0
    }
}

// NOTE: This is implemented directly for each of the key types to avoid collision with the blanket
// Into impl provided by the standard library.
macro_rules! impl_from_for_sum {
    ($($type:ty),+) => {
        $(
        impl<T: Into<$type>> From<T> for Sum<$type> {
            fn from(value: T) -> Self {
                Sum(vec![value.into()])
            }
        }

        impl<T: Into<$type>> From<Vec<T>> for Sum<$type> {
            fn from(terms: Vec<T>) -> Self {
                Self::from_iter(terms)
            }
        }

        impl<T: Into<$type>, const N: usize> From<[T; N]> for Sum<$type> {
            fn from(terms: [T; N]) -> Self {
                Self::from_iter(terms)
            }
        }

        impl<T: Into<$type>> FromIterator<T> for Sum<$type> {
            fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
                Self(iter.into_iter().map(|x| x.into()).collect())
            }
        }

        impl<F, T: Into<Weighted<$type, F>>> From<T> for Sum<Weighted<$type, F>> {
            fn from(value: T) -> Self {
                Sum(vec![value.into()])
            }
        }

        impl<F, T: Into<Weighted<$type, F>>> From<Vec<T>> for Sum<Weighted<$type, F>> {
            fn from(terms: Vec<T>) -> Self {
                Self::from_iter(terms)
            }
        }

        impl<F, T: Into<Weighted<$type, F>>, const N: usize> From<[T; N]> for Sum<Weighted<$type, F>> {
            fn from(terms: [T; N]) -> Self {
                Self::from_iter(terms)
            }
        }

        impl<F, T: Into<Weighted<$type, F>>> FromIterator<T> for Sum<Weighted<$type, F>> {
            fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
                Self(iter.into_iter().map(|x| x.into()).collect())
            }
        }
        )+
    };
}

impl_from_for_sum!(ScalarVar, GroupVar, Term);

impl<T, F: Field> From<Sum<T>> for Sum<Weighted<T, F>> {
    fn from(sum: Sum<T>) -> Self {
        Self(sum.0.into_iter().map(|x| x.into()).collect())
    }
}

/// Represents a sparse linear combination of scalars and group elements.
///
/// For example, it can represent an equation like:
/// `s_1 * P_1 + s_2 * P_2 + ... + s_n * P_n`
///
/// where `s_i` are scalars (referenced by `scalar_vars`) and `P_i` are group elements (referenced by `element_vars`).
///
/// The indices refer to external lists managed by the containing LinearMap.
pub type LinearCombination<G> = Sum<Weighted<Term, <G as Group>::Scalar>>;

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
    pub fn assign_element(&mut self, var: GroupVar, element: G) {
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
    pub fn assign_elements(&mut self, assignments: impl IntoIterator<Item = (GroupVar, G)>) {
        for (var, elem) in assignments.into_iter() {
            self.assign_element(var, elem);
        }
    }

    /// Get the element value assigned to the given point var.
    ///
    /// Returns [`Error::UnassignedGroupVar`] if a value is not assigned.
    pub fn get(&self, var: GroupVar) -> Result<G, Error> {
        self.0[var.0].ok_or(Error::UnassignedGroupVar { var })
    }

    /// Iterate over the assigned variable and group element pairs in this mapping.
    // NOTE: Not implemented as `IntoIterator` for now because doing so requires explicitly
    // defining an iterator type, See https://github.com/rust-lang/rust/issues/63063
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> impl Iterator<Item = (GroupVar, G)> {
        self.0
            .into_iter()
            .enumerate()
            .filter_map(|(i, x)| x.map(|x| (GroupVar(i), x)))
    }

    pub fn iter(&self) -> impl Iterator<Item = (GroupVar, &G)> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, opt)| opt.as_ref().map(|g| (GroupVar(i), g)))
    }
}

impl<G> Default for GroupMap<G> {
    fn default() -> Self {
        Self(Vec::default())
    }
}

impl<G: Group> FromIterator<(GroupVar, G)> for GroupMap<G> {
    fn from_iter<T: IntoIterator<Item = (GroupVar, G)>>(iter: T) -> Self {
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
                        .map(|weighted| scalars[weighted.term.scalar.0] * weighted.weight)
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
    pub image: Vec<GroupVar>,
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

    /// Computes the total number of bytes required to serialize all current commitments.
    pub fn commit_bytes_len(&self) -> usize {
        let repr_len = <G::Repr as Default>::default().as_ref().len(); // size of encoded point
        self.linear_map.num_constraints() * repr_len // total size of a commit
    }

    /// Adds a new equation to the statement of the form:
    /// `lhs = Σ (scalar_i * point_i)`.
    ///
    /// # Parameters
    /// - `lhs`: The image group element variable (left-hand side of the equation).
    /// - `rhs`: A slice of `(ScalarVar, GroupVar)` pairs representing the linear combination on the right-hand side.
    pub fn append_equation(&mut self, lhs: GroupVar, rhs: impl Into<LinearCombination<G>>) {
        self.linear_map.append(rhs.into());
        self.image.push(lhs);
    }

    /// Adds a new equation to the statement of the form:
    /// `lhs = Σ (scalar_i * point_i)`.
    ///
    /// # Parameters
    /// - `lhs`: The image group element variable (left-hand side of the equation).
    /// - `rhs`: A slice of `(ScalarVar, GroupVar)` pairs representing the linear combination on the right-hand side.
    pub fn allocate_eq(&mut self, rhs: impl Into<LinearCombination<G>>) -> GroupVar {
        let var = self.allocate_element();
        self.append_equation(var, rhs);
        var
    }

    /// Allocates a scalar variable for use in the morphism.
    pub fn allocate_scalar(&mut self) -> ScalarVar {
        self.linear_map.num_scalars += 1;
        ScalarVar(self.linear_map.num_scalars - 1)
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
    pub fn allocate_scalars<const N: usize>(&mut self) -> [ScalarVar; N] {
        let mut vars = [ScalarVar(usize::MAX); N];
        for var in vars.iter_mut() {
            *var = self.allocate_scalar();
        }
        vars
    }

    /// Allocates a point variable (group element) for use in the morphism.
    pub fn allocate_element(&mut self) -> GroupVar {
        self.linear_map.num_elements += 1;
        GroupVar(self.linear_map.num_elements - 1)
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
    pub fn allocate_elements<const N: usize>(&mut self) -> [GroupVar; N] {
        let mut vars = [GroupVar(usize::MAX); N];
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
    pub fn set_element(&mut self, var: GroupVar, element: G) {
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
    pub fn set_elements(&mut self, assignments: impl IntoIterator<Item = (GroupVar, G)>) {
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
                    .map(|weighted| scalars[weighted.term.scalar.0] * weighted.weight)
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

    /// Returns a binary label describing the morphism structure, inspired by the Signal POKSHO format,
    /// but adapted to u32 to support large statements.
    ///
    /// The format is:
    /// - [Ne: u32] number of equations
    /// - For each equation:
    ///   - [output_point_index: u32]
    ///   - [Nt: u32] number of terms
    ///   - Nt × [scalar_index: u32, point_index: u32] term entries
    pub fn label(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let repr = self.standard_repr();

        // 1. Number of equations
        let ne = repr.len();
        out.extend_from_slice(&(ne as u32).to_le_bytes());

        // 2. Encode each equation
        for (output_index, constraint) in repr {
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

        out
    }

    /// Construct an equivalent linear relation in the standardized form, without weights and with
    /// a single group var on the left-hand side.
    // NOTE: This function has a complimentary function that generates the Group elements for the
    // remapped variables by multiplying their values by the assigned weights. This function can be
    // called before the group elements are known, and when they are known the actual values can be
    // assigned to the remapped indices.
    fn standard_repr(&self) -> Vec<(u32, Vec<(u32, u32)>)> {
        assert_eq!(
            self.image.len(),
            self.linear_map.constraints.len(),
            "Number of equations and image variables must match"
        );

        // Create an allocator function to remap each (group_var, weight) pair to a new index.
        // NOTE: Logically, this is a map of (usize, G::Scalar) => u32. However, Field does not
        // implement Hash or Ord.
        let mut remapping = BTreeMap::<usize, Vec<(G::Scalar, u32)>>::new();
        let mut group_var_remap_index = 0u32;
        let mut remap_var = |var: GroupVar, weight: G::Scalar| -> u32 {
            let entry = remapping.entry(var.0).or_default();

            // If the (weight, group_var) pair has already been assigned an index, use it.
            if let Some(remapped_var) = entry.iter().find_map(|(entry_weight, remapped_var)| {
                (weight == *entry_weight).then_some(remapped_var)
            }) {
                return *remapped_var;
            }

            // The (weight, group_var) pair has not been assigned an index, assign one now.
            let remapped_var = group_var_remap_index;
            entry.push((weight, remapped_var));
            group_var_remap_index += 1;

            remapped_var
        };

        // Iterate through the constraints, applying to remapping to weighed group variables and
        // casting scalar vars to u32.
        let mut repr = Vec::new();
        for (image_var, equation) in iter::zip(&self.image, &self.linear_map.constraints) {
            let eq_repr: Vec<(u32, u32)> = equation
                .terms()
                .iter()
                .map(|weighted_term| {
                    (
                        weighted_term.term.scalar.0 as u32,
                        remap_var(weighted_term.term.elem, weighted_term.weight),
                    )
                })
                .collect();
            repr.push((remap_var(*image_var, G::Scalar::ONE), eq_repr));
        }

        repr
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
        context: &[u8],
    ) -> crate::fiat_shamir::NISigmaProtocol<
        crate::schnorr_protocol::SchnorrProof<G>,
        crate::codec::ShakeCodec<G>,
    >
    where
        G: group::GroupEncoding,
    {
        let schnorr = crate::schnorr_protocol::SchnorrProof::from(self);
        crate::fiat_shamir::NISigmaProtocol::new(context, schnorr)
    }
}
