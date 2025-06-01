//! # Group Morphism and Preimage Handling
//!
//! This module provides utilities for describing and manipulating **linear group morphisms**,
//! supporting sigma protocols over group-based statements (e.g., discrete logarithms, DLEQ proofs). See Maurer09.
//!
//! It includes:
//! - `LinearCombination`: a sparse representation of scalar multiplication relations
//! - `Morphism`: a collection of linear combinations acting on group elements
//! - `GroupMorphismPreimage`: a higher-level structure managing morphisms and their associated images

use group::{Group, GroupEncoding};

#[derive(Copy, Clone)]
pub struct ScalarVar(usize);

impl ScalarVar {
    pub fn index(&self) -> usize {
        self.0
    }
}

#[derive(Copy, Clone)]
pub struct PointVar(usize);

impl PointVar {
    pub fn index(&self) -> usize {
        self.0
    }
}

/// A sparse linear combination of scalars and group elements.
///
/// Stores indices into external lists of scalars and group elements.
/// Used to define individual constraints inside a Morphism.
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
    pub linear_combination: Vec<LinearCombination>,
    pub group_elements: Vec<G>,
    pub num_scalars: usize,
}

/// Perform a simple multi-scalar multiplication (MSM) over scalars and points.
pub fn msm_pr<G: Group>(scalars: &[G::Scalar], bases: &[G]) -> G {
    let mut acc = G::identity();
    for (s, p) in scalars.iter().zip(bases.iter()) {
        acc += *p * s;
    }
    acc
}

impl<G: Group> Morphism<G> {
    /// Creates a new empty Morphism.
    pub fn new() -> Self {
        Self {
            linear_combination: Vec::new(),
            group_elements: Vec::new(),
            num_scalars: 0,
        }
    }

    /// Adds a new linear combination constraint.
    pub fn append(&mut self, lc: LinearCombination) {
        self.linear_combination.push(lc);
    }

    /// Returns the number of constraint statements.
    pub fn num_statements(&self) -> usize {
        self.linear_combination.len()
    }

    /// Evaluate the Morphism given a set of scalar values.
    ///
    /// Computes all linear combinations using the provided scalars and returns their group outputs.
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

/// A wrapper struct coupling a Morphism and the corresponding expected image elements.
///
/// Provides a higher-level API to build proof instances from sparse constraints. The equations are manipulated solely through 2 lists:
/// - the index of a set of Group elements (maintained in Morphism)
/// - the index of a set of scalars (provided as input for the execution)
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

    /// Computes the number of bytes needed when serializing all the current commitments.
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

    /// Allocates `n` scalar variables for use in the morphism.
    ///
    /// Returns a vector of `ScalarVar` indices.
    // TODO: When no_std suport is desired, the `Vec` return type here can be changed to
    // `T: FromIterator<ScalarVar>`, which allows the caller to decide whether the result should be
    // collected into a `Vec`, `[_; N]`, `Array`, etc.
    pub fn allocate_scalars(&mut self, n: usize) -> Vec<ScalarVar> {
        (0..n).map(|_| self.allocate_scalar()).collect()
    }

    /// Allocates a point variable (group element) for use in the morphism.
    pub fn allocate_element(&mut self) -> PointVar {
        self.morphism.group_elements.push(G::identity());
        PointVar(self.morphism.group_elements.len() - 1)
    }

    /// Allocates `n` point variables (group elements) for use in the morphism.
    ///
    /// Returns a vector of `PointVar` indices.
    pub fn allocate_elements(&mut self, n: usize) -> Vec<PointVar> {
        (0..n).map(|_| self.allocate_element()).collect()
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

    /// Return the group elements corresponding to the image indices.
    pub fn image(&self) -> Vec<G> {
        let mut result = Vec::new();
        for i in &self.image {
            result.push(self.morphism.group_elements[i.0]);
        }
        result
    }
}
