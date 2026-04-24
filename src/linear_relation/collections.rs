//! # Collections for Group and Scalar Vars
//!
//! This module provides collections of group elements and scalars, [GroupMap] and [ScalarMap].
//! These collections act as a mapping of opaque variable references to values.

use alloc::collections::BTreeMap;
use core::marker::PhantomData;
use group::Group;
use std::collections::btree_map;

use super::{GroupVar, ScalarVar};

// TODO: Also refactor GroupMap to match ScalarMap?
/// Ordered mapping of [GroupVar] to group elements assignments.
#[derive(Clone, Debug)]
pub struct GroupMap<G>(Vec<Option<G>>);

impl<G: Group> GroupMap<G> {
    pub fn allocate_element(&mut self) -> GroupVar<G> {
        self.0.push(None);
        GroupVar(self.0.len() - 1, PhantomData)
    }

    /// Add a new group element to the map and return its variable reference
    pub fn allocate_element_with(&mut self, element: G) -> GroupVar<G> {
        self.0.push(Some(element));
        GroupVar(self.0.len() - 1, PhantomData)
    }

    /// Assign a group element value to a variable.
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

    /// Assigns specific group elements to variables.
    ///
    /// # Parameters
    ///
    /// - `assignments`: A collection of `(GroupVar, G)` pairs that can be iterated over.
    ///
    /// # Panics
    ///
    /// Panics if the collection contains two conflicting assignments for the same variable.
    pub fn assign_elements(&mut self, assignments: impl IntoIterator<Item = (GroupVar<G>, G)>) {
        for (var, elem) in assignments.into_iter() {
            self.assign_element(var, elem);
        }
    }

    /// Get the element value assigned to the given variable.
    ///
    /// Returns [`InvalidInstance`] if a value is not assigned.
    pub fn get(&self, var: GroupVar<G>) -> Result<G, UnassignedGroupVarError> {
        match self.0.get(var.0) {
            Some(Some(elem)) => Ok(*elem),
            Some(None) | None => Err(UnassignedGroupVarError(var.to_elided())),
        }
    }

    /// Iterate over the assigned variable and group element pairs in this map.
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

    pub fn vars(&self) -> impl Iterator<Item = GroupVar<G>> {
        (0..self.len()).map(|i| GroupVar(i, PhantomData))
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

impl<G: Group> FromIterator<(GroupVar<G>, G)> for GroupMap<G> {
    fn from_iter<T: IntoIterator<Item = (GroupVar<G>, G)>>(iter: T) -> Self {
        iter.into_iter()
            .fold(Self::default(), |mut instance, (var, val)| {
                instance.assign_element(var, val);
                instance
            })
    }
}

/// Ordered mapping of [ScalarVar] to scalar assignments.
#[derive(Clone, Debug)]
pub struct ScalarMap<G: Group>(BTreeMap<ScalarVar<G>, G::Scalar>);

impl<G: Group> ScalarMap<G> {
    /// Assign a scalar value to a variable.
    ///
    /// # Parameters
    ///
    /// - `var`: The variable to assign.
    /// - `scalar`: The value to assign to the variable.
    ///
    /// # Panics
    ///
    /// Panics if the given assignment conflicts with the existing assignment.
    pub fn assign_scalar(&mut self, var: ScalarVar<G>, scalar: G::Scalar) {
        match self.0.entry(var) {
            btree_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(scalar);
            }
            btree_map::Entry::Occupied(occupied_entry) => assert_eq!(
                *occupied_entry.get(),
                scalar,
                "conflicting assignments for var {var:?}"
            ),
        };
    }

    /// Assigns specific scalars to variables.
    ///
    /// # Parameters
    ///
    /// - `assignments`: A collection of `(ScalarVar, G::Scalar)` pairs that can be iterated over.
    ///
    /// # Panics
    ///
    /// Panics if the collection contains two conflicting assignments for the same variable.
    pub fn assign_scalars(
        &mut self,
        assignments: impl IntoIterator<Item = (ScalarVar<G>, G::Scalar)>,
    ) {
        for (var, elem) in assignments.into_iter() {
            self.assign_scalar(var, elem);
        }
    }

    /// Get the scalar value assigned to the given variable.
    ///
    /// Returns [`UnassignedScalarVarError`] if a value is not assigned.
    pub fn get(&self, var: ScalarVar<G>) -> Result<G::Scalar, UnassignedScalarVarError> {
        self.0
            .get(&var)
            .copied()
            .ok_or(UnassignedScalarVarError(var.to_elided()))
    }

    /// Iterate over the assigned variable and scalar pairs in this map.
    pub fn iter(&self) -> impl Iterator<Item = (ScalarVar<G>, G::Scalar)> + use<'_, G> {
        self.0.iter().map(|(var, val)| (*var, *val))
    }

    /// Iterate over the scalar variable references in this scalar map.
    pub fn vars(&self) -> impl Iterator<Item = ScalarVar<G>> + use<'_, G> {
        self.0.keys().copied()
    }

    /// Get the number of scalars in the map
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<G: Group> Default for ScalarMap<G> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<G: Group> From<Vec<(ScalarVar<G>, G::Scalar)>> for ScalarMap<G> {
    fn from(value: Vec<(ScalarVar<G>, G::Scalar)>) -> Self {
        Self::from_iter(value)
    }
}

impl<G: Group, const N: usize> From<[(ScalarVar<G>, G::Scalar); N]> for ScalarMap<G> {
    fn from(value: [(ScalarVar<G>, G::Scalar); N]) -> Self {
        Self::from_iter(value)
    }
}

impl<G: Group> FromIterator<(ScalarVar<G>, G::Scalar)> for ScalarMap<G> {
    fn from_iter<T: IntoIterator<Item = (ScalarVar<G>, G::Scalar)>>(iter: T) -> Self {
        iter.into_iter()
            .fold(Self::default(), |mut instance, (var, val)| {
                instance.assign_scalar(var, val);
                instance
            })
    }
}

// TODO(victor/scalarvars): Potentially fold this into the definitions in allocator.
// A trait providing a mapping from [ScalarVar] for scalar values of type `G::Scalar`.
// TODO: The generic should at least by an associated type instead. A single struct will not
// implement multiple parameterizations of ScalarAssignments.
pub trait ScalarAssignments<G: Group> {
    fn get(&self, var: ScalarVar<G>) -> Result<G::Scalar, UnassignedScalarVarError>;
}

impl<G: Group> ScalarAssignments<G> for ScalarMap<G> {
    fn get(&self, var: ScalarVar<G>) -> Result<G::Scalar, UnassignedScalarVarError> {
        self.get(var)
    }
}

impl<G: Group> ScalarAssignments<G> for &ScalarMap<G> {
    fn get(&self, var: ScalarVar<G>) -> Result<G::Scalar, UnassignedScalarVarError> {
        (*self).get(var)
    }
}

impl<G: Group> ScalarAssignments<G> for [(ScalarVar<G>, G::Scalar)] {
    /// Access the assignment of a [ScalarVar] from an array-like struct (e.g. `[_; N]` or `Vec`).
    ///
    /// The variable is fetched via a linear search. For small arrays, this is optimal and avoids
    /// allocation into a [ScalarMap]. For statements with a large number of scalars, this will not
    /// be as effcicient as allocating a [ScalarMap].
    fn get(&self, var: ScalarVar<G>) -> Result<<G as Group>::Scalar, UnassignedScalarVarError> {
        self.iter()
            .copied()
            .find_map(|(var_i, scalar)| (var == var_i).then_some(scalar))
            .ok_or(UnassignedScalarVarError(var.to_elided()))
    }
}

impl<G: Group, const N: usize> ScalarAssignments<G> for [(ScalarVar<G>, G::Scalar); N] {
    fn get(&self, var: ScalarVar<G>) -> Result<<G as Group>::Scalar, UnassignedScalarVarError> {
        ScalarAssignments::get(self.as_slice(), var)
    }
}

impl<G: Group> ScalarAssignments<G> for Vec<(ScalarVar<G>, G::Scalar)> {
    fn get(&self, var: ScalarVar<G>) -> Result<<G as Group>::Scalar, UnassignedScalarVarError> {
        ScalarAssignments::get(self.as_slice(), var)
    }
}

/// An uninhabited type used to elide the type parameter on [UnassignedScalarVarError] and
/// [UnassignedGroupVarError].
#[derive(Copy, Clone, Debug)]
enum Elided {}

impl<G> GroupVar<G> {
    fn to_elided(self) -> GroupVar<Elided> {
        GroupVar(self.0, PhantomData)
    }
}

impl<G> ScalarVar<G> {
    fn to_elided(self) -> ScalarVar<Elided> {
        ScalarVar(self.0, PhantomData)
    }
}

/// Error for an attempted access to an unassigned [GroupVar].
#[derive(Clone, Debug, thiserror::Error)]
#[error("Unassigned group variable: {0:?}")]
pub struct UnassignedGroupVarError(GroupVar<Elided>);

/// Error for an attempted access to an unassigned [ScalarVar].
#[derive(Clone, Debug, thiserror::Error)]
#[error("Unassigned scalar variable: {0:?}")]
pub struct UnassignedScalarVarError(ScalarVar<Elided>);
