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
use std::iter;

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
pub struct Morphism<G: Group> {
    pub linear_combination: Vec<LinearCombination>,
    pub group_elements: Vec<G>,
    pub num_scalars: usize,
    pub num_elements: usize,
}

/// Perform a simple multi-scalar multiplication (MSM) over scalars and points.
pub fn msm_pr<G: Group>(scalars: &[G::Scalar], bases: &[G]) -> G {
    let mut acc = G::identity();
    for (s, p) in scalars.iter().zip(bases.into_iter()) {
        acc += *p * s;
    }
    acc
}

impl<G: Group> Default for Morphism<G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: Group> Morphism<G> {
    /// Creates a new empty Morphism.
    pub fn new() -> Self {
        Self {
            linear_combination: Vec::new(),
            group_elements: Vec::new(),
            num_scalars: 0,
            num_elements: 0,
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
pub struct GroupMorphismPreimage<G>
where
    G: Group + GroupEncoding,
{
    /// The underlying morphism describing the structure of the statement.
    pub morphism: Morphism<G>,
    /// Indices pointing to elements representing the "target" images for each constraint.
    pub image: Vec<PointVar>,
}

impl<G> Default for GroupMorphismPreimage<G>
where
    G: Group + GroupEncoding,
{
    fn default() -> Self {
        Self::new()
    }
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

    /// Append a new equation relating scalars to group elements.
    ///
    /// `lhs` is the image, and `rhs` is a list of (scalar, element) pairs.
    pub fn append_equation(&mut self, lhs: PointVar, rhs: &[(ScalarVar, PointVar)]) {
        let lc = LinearCombination {
            scalar_indices: rhs.iter().map(|&(s, _)| s).collect(),
            element_indices: rhs.iter().map(|&(_, e)| e).collect(),
        };
        self.morphism.append(lc);
        self.image.push(lhs);
    }

    /// Allocate space for `n` new scalars and return their ScalarVar.
    pub fn allocate_scalars(&mut self, n: usize) -> Vec<ScalarVar> {
        let start = self.morphism.num_scalars;
        self.morphism.num_scalars += n;
        (start..start + n).map(ScalarVar).collect()
    }

    /// Allocate space for `n` new group elements and return their PointVar.
    ///
    /// The allocated elements are initially set to the identity.
    pub fn allocate_elements(&mut self, n: usize) -> Vec<PointVar> {
        let start = self.morphism.num_elements;
        let indices: Vec<usize> = (start..start + n).collect();

        self.morphism
            .group_elements
            .extend(iter::repeat(G::identity()).take(n));
        let mut points = Vec::new();
        for i in indices.iter() {
            points.push(PointVar(*i));
        }
        self.morphism.num_elements += n;
        points
    }

    /// Set the value of group elements at a given index, inside the list of allocated group elements.
    pub fn set_elements(&mut self, elements: &[(PointVar, G)]) {
        for &(i, ref elt) in elements {
            self.morphism.group_elements[i.0] = *elt;
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
