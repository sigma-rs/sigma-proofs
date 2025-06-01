//! # Group Morphism and Preimage Handling
//!
//! This module provides utilities for describing and manipulating **linear group morphisms**,
//! supporting sigma protocols over group-based statements (e.g., discrete logarithms, DLEQ proofs). See Maurer09.
//!
//! It includes:
//! - [`LinearCombination`]: a sparse representation of scalar multiplication relations
//! - [`Morphism`]: a collection of linear combinations acting on group elements
//! - [`GroupMorphismPreimage`]: a higher-level structure managing morphisms and their associated images

use group::{Group, GroupEncoding};

/// A wrapper representing an index for a scalar variable.
///
/// Used to reference scalars in sparse linear combinations.
#[derive(Copy, Clone)]
pub struct ScalarVar(usize);

impl ScalarVar {
    pub fn index(&self) -> usize {
        self.0
    }
}
/// A wrapper representing an index for a group element (point).
///
/// Used to reference group elements in sparse linear combinations.
#[derive(Copy, Clone)]
pub struct PointVar(usize);

impl PointVar {
    pub fn index(&self) -> usize {
        self.0
    }
}

/// Represents a sparse linear combination of scalars and group elements.
///
/// For example, it can represent an equation like:
/// `s_1 * P_1 + s_2 * P_2 + ... + s_n * P_n`
///
/// where `s_i` are scalars (referenced by `scalar_indices`) and `P_i` are group elements (referenced by `element_indices`).
///
/// The indices refer to external lists managed by the containing Morphism.
pub struct LinearCombination {
    pub scalar_indices: Vec<ScalarVar>,
    pub element_indices: Vec<PointVar>,
}

/// A Morphism represents a list of linear combinations over group elements.
///
/// It supports dynamic allocation of scalars and elements,
/// and evaluates by performing multi-scalar multiplications.
#[derive(Default)]
pub struct Morphism<G: Group> {
    /// The set of linear combination constraints (equations).
    pub linear_combination: Vec<LinearCombination>,
    /// The list of group elements referenced in the morphism.
    pub group_elements: Vec<G>,
    /// The total number of scalar variables allocated.
    pub num_scalars: usize,
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
    /// A [`Morphism`] instance with empty linear combinations and group elements,
    /// and zero allocated scalars and elements.
    pub fn new() -> Self {
        Self {
            linear_combination: Vec::new(),
            group_elements: Vec::new(),
            num_scalars: 0,
        }
    }

    /// Adds a new linear combination constraint to the morphism.
    ///
    /// # Parameters
    /// - `lc`: The [`LinearCombination`] to add.
    pub fn append(&mut self, lc: LinearCombination) {
        self.linear_combination.push(lc);
    }

    /// Returns the number of linear combination constraints.
    pub fn num_statements(&self) -> usize {
        self.linear_combination.len()
    }

    /// Evaluates all linear combinations in the morphism with the provided scalars.
    ///
    /// # Parameters
    /// - `scalars`: A slice of scalar values corresponding to the scalar variables.
    ///
    /// # Returns
    /// A vector of group elements, each being the result of evaluating one linear combination with the scalars.
    pub fn evaluate(&self, scalars: &[<G as Group>::Scalar]) -> Vec<G> {
        self.linear_combination
            .iter()
            .map(|lc| {
                let coefficients: Vec<_> =
                    lc.scalar_indices.iter().map(|&i| scalars[i.0]).collect();
                // QUESTION: This accesses the group_elements, but it does not attempt to tell
                // whether they have been set. If I allocate a point var, and use it in the
                // equations here, will the variables always be set. I think not, as a result, the
                // solution here may not be valid.
                let elements: Vec<_> = lc
                    .element_indices
                    .iter()
                    .map(|&i| self.group_elements[i.0])
                    .collect();
                msm_pr(&coefficients, &elements)
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
    pub image: Vec<PointVar>,
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
        self.morphism.num_statements() * repr_len // total size of a commit
    }

    /// Adds a new equation to the statement of the form:
    /// `lhs = Σ (scalar_i * point_i)`
    ///
    /// # Parameters
    /// - `lhs`: The variable representing the left-hand group element
    /// - `rhs`: A list of (scalar variable, point variable) tuples for the linear combination
    pub fn append_equation(&mut self, lhs: PointVar, rhs: &[(ScalarVar, PointVar)]) {
        let lc = LinearCombination {
            scalar_indices: rhs.iter().map(|&(s, _)| s).collect(),
            element_indices: rhs.iter().map(|&(_, e)| e).collect(),
        };
        self.morphism.append(lc);
        self.image.push(lhs);
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
    pub fn allocate_element(&mut self) -> PointVar {
        self.morphism.group_elements.push(G::identity());
        PointVar(self.morphism.group_elements.len() - 1)
    }

    /// Allocates space for `N` new group elements, initialized to the identity element.
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
    pub fn allocate_elements<const N: usize>(&mut self) -> [PointVar; N] {
        let mut vars = [PointVar(usize::MAX); N];
        for var in vars.iter_mut() {
            *var = self.allocate_element();
        }
        vars
    }

    /// Assign a group element value to a point variable.
    ///
    /// # Parameters
    /// - `var`: The variable to assign.
    /// - `element`: The value to assign to the variable.
    pub fn assign_element(&mut self, var: PointVar, element: G) {
        self.morphism.group_elements[var.0] = element;
    }

    /// Assigns specific group elements to point variables (indices).
    ///
    /// # Parameters
    /// - `elements`: A list of `(PointVar, GroupElement)` pairs
    pub fn assign_elements(&mut self, elements: &[(PointVar, G)]) {
        for (var, element) in elements {
            self.assign_element(*var, *element)
        }
    }

    /// Returns the current group elements corresponding to the image variables.
    ///
    /// # Returns
    /// A vector of group elements (`Vec<G>`) representing the morphism's image.
    pub fn image(&self) -> Vec<G> {
        let mut result = Vec::new();
        for i in &self.image {
            result.push(self.morphism.group_elements[i.0]);
        }
        result
    }
}
