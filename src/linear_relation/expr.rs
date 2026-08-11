//! The scalar/element variable, term, and sum types of linear combination expressions.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ff::Field;
use group::prime::PrimeGroup;

/// An index referencing a scalar variable in a sparse linear combination.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ScalarVar<G>(pub(super) usize, pub(super) PhantomData<G>);

impl<G> core::hash::Hash for ScalarVar<G> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

/// An index referencing a group element (point) in a sparse linear combination.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GroupVar<G>(pub(super) usize, pub(super) PhantomData<G>);

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
    pub(super) fn value(self, scalars: &[G::Scalar]) -> G::Scalar {
        match self {
            Self::Var(var) => scalars[var.0],
            Self::Unit => G::Scalar::ONE,
        }
    }
}

/// A term in a linear combination, representing `scalar * elem`.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Term<G> {
    pub(super) scalar: ScalarTerm<G>,
    pub(super) elem: GroupVar<G>,
}

#[derive(Copy, Clone, Debug)]
pub struct Weighted<T, F> {
    pub term: T,
    pub weight: F,
}

#[derive(Clone, Debug)]
pub struct Sum<T>(pub(super) Vec<T>);

impl<T> Sum<T> {
    /// The terms of the sum, as a slice.
    pub fn terms(&self) -> &[T] {
        &self.0
    }
}

impl<T> core::iter::Sum<T> for Sum<T> {
    /// Sums an iterator of `T` into a `Sum<T>`.
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        Self(iter.collect())
    }
}
