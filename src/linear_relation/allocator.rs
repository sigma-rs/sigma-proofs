use core::{array, iter::zip, marker::PhantomData};

use group::{prime::PrimeGroup, Group};

use crate::{
    errors::UnassignedGroupVarError,
    linear_relation::{GroupMap, GroupVar, ScalarMap, ScalarVar},
    LinearRelation,
};

pub trait Allocator {
    type G;

    /// Allocates a scalar variable for use in the linear map.
    fn allocate_scalar(&mut self) -> ScalarVar<Self::G>;

    /// Allocates `N` new scalar variables, with `N` known at compile-time.
    ///
    /// # Returns
    /// An array of [`ScalarVar`] representing the newly allocated scalar references.
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
    fn allocate_scalars<const N: usize>(&mut self) -> [ScalarVar<Self::G>; N] {
        array::from_fn(|_| self.allocate_scalar())
    }

    /// Allocates `n` new scalar variables, with `n` decided at runtime.
    ///
    /// # Returns
    /// A `Vec` of [`ScalarVar`] representing the newly allocated scalar references.
    ///
    /// # Example
    /// ```
    /// # use sigma_proofs::LinearRelation;
    /// use curve25519_dalek::RistrettoPoint as G;
    ///
    /// let mut relation = LinearRelation::<G>::new();
    /// let vars = relation.allocate_scalars_vec(2);
    /// assert_eq!(vars.len(), 2);
    /// ```
    fn allocate_scalars_vec(&mut self, n: usize) -> Vec<ScalarVar<Self::G>> {
        (0..n).map(|_| self.allocate_scalar()).collect()
    }

    /// Allocates a group element variable (i.e. elliptic curve point) for use in the linear map.
    fn allocate_element(&mut self) -> GroupVar<Self::G>;

    /// Allocates `N` group element variables, with `N` known at compile-time.
    ///
    /// # Returns
    /// An array of [`GroupVar`] representing the newly allocated group element references.
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
    fn allocate_elements<const N: usize>(&mut self) -> [GroupVar<Self::G>; N] {
        array::from_fn(|_| self.allocate_element())
    }

    /// Allocates `N` group element variables, with `N` decided at runtime.
    ///
    /// # Returns
    /// A `Vec` of [`GroupVar`] representing the newly allocated group element references.
    ///
    /// # Example
    /// ```
    /// # use sigma_proofs::LinearRelation;
    /// use curve25519_dalek::RistrettoPoint as G;
    ///
    /// let mut relation = LinearRelation::<G>::new();
    /// let vars = relation.allocate_elements_vec(2);
    /// assert_eq!(vars.len(), 2);
    /// ```
    fn allocate_elements_vec(&mut self, n: usize) -> Vec<GroupVar<Self::G>> {
        (0..n).map(|_| self.allocate_element()).collect()
    }

    fn allocate<T: Allocate<G = Self::G>>(&mut self) -> T {
        T::allocate(self)
    }

    // TODO(victor/scalarvars): Should this be part of this trait, or should it be split off into
    // its own trait?
    fn assign_element(&mut self, var: GroupVar<Self::G>, element: Self::G);

    fn assign_elements(
        &mut self,
        assignments: impl IntoIterator<Item = (GroupVar<Self::G>, Self::G)>,
    ) {
        for (var, elem) in assignments.into_iter() {
            self.assign_element(var, elem);
        }
    }

    fn get_element(&self, var: GroupVar<Self::G>) -> Result<Self::G, UnassignedGroupVarError>;
}

pub trait Allocate {
    type G;

    fn allocate<A: Allocator<G = Self::G> + ?Sized>(alloc: &mut A) -> Self;
}

impl<G> Allocate for ScalarVar<G> {
    type G = G;

    fn allocate<A: Allocator<G = G> + ?Sized>(alloc: &mut A) -> Self {
        alloc.allocate_scalar()
    }
}

impl<G> Allocate for GroupVar<G> {
    type G = G;

    fn allocate<A: Allocator<G = G> + ?Sized>(alloc: &mut A) -> Self {
        alloc.allocate_element()
    }
}

impl<T: Allocate, const N: usize> Allocate for [T; N] {
    type G = T::G;

    fn allocate<A: Allocator<G = Self::G> + ?Sized>(alloc: &mut A) -> Self {
        array::from_fn(|_| alloc.allocate())
    }
}

impl<T1, T2> Allocate for (T1, T2)
where
    T1: Allocate,
    T2: Allocate<G = T1::G>,
{
    type G = T1::G;

    fn allocate<A: Allocator<G = Self::G> + ?Sized>(alloc: &mut A) -> Self {
        (T1::allocate(alloc), T2::allocate(alloc))
    }
}

// TODO(victor/scalarvars) Rename this from Heap. Its not really a heap.
#[derive(Clone, Debug)]
pub struct Heap<G> {
    pub elements: GroupMap<G>,
    // TODO(victor/scalarvars): Should this be a ScalarMap? I hesitate to do so because I don't
    // really want to store witness values on a struct like this. One particular reason for this is
    // that this is a member of LinearRelation, which seems ok, but we do not want to carry the
    // witness assignments in that struct as we convert it to a CanonicalRelation or Nizk.
    pub num_scalars: usize,
}

impl<G> Default for Heap<G> {
    fn default() -> Self {
        Self {
            elements: Default::default(),
            num_scalars: 0,
        }
    }
}

impl<G: Group> Allocator for Heap<G> {
    type G = G;

    fn allocate_scalar(&mut self) -> ScalarVar<Self::G> {
        self.num_scalars += 1;
        ScalarVar(self.num_scalars - 1, PhantomData)
    }

    fn allocate_element(&mut self) -> GroupVar<Self::G> {
        self.elements.allocate_element()
    }

    fn assign_element(&mut self, var: GroupVar<Self::G>, element: Self::G) {
        self.elements.assign_element(var, element)
    }

    fn get_element(&self, var: GroupVar<Self::G>) -> Result<Self::G, UnassignedGroupVarError> {
        self.elements.get(var)
    }
}

pub trait ScalarAssignment {
    type G: Group;
    type Assignment;

    fn assign(&self, map: &mut ScalarMap<Self::G>, value: Self::Assignment);

    fn assignments(&self, value: Self::Assignment) -> ScalarMap<Self::G> {
        let mut map = ScalarMap::default();
        map.assign(self, value);
        map
    }
}

impl<G: Group> ScalarAssignment for ScalarVar<G> {
    type G = G;
    type Assignment = G::Scalar;

    fn assign(&self, map: &mut ScalarMap<Self::G>, value: Self::Assignment) {
        map.assign_scalar(*self, value)
    }
}

impl<T: ScalarAssignment, const N: usize> ScalarAssignment for [T; N] {
    type G = T::G;
    type Assignment = [T::Assignment; N];

    fn assign(&self, map: &mut ScalarMap<Self::G>, value: Self::Assignment) {
        for (var, value) in zip(self, value) {
            var.assign(map, value);
        }
    }
}

impl<T1, T2> ScalarAssignment for (T1, T2)
where
    T1: ScalarAssignment,
    T2: ScalarAssignment<G = T1::G>,
{
    type G = T1::G;
    type Assignment = (T1::Assignment, T2::Assignment);

    fn assign(&self, map: &mut ScalarMap<Self::G>, value: Self::Assignment) {
        self.0.assign(map, value.0);
        self.1.assign(map, value.1);
    }
}

impl<G: Group> ScalarMap<G> {
    pub fn assign<A: ScalarAssignment<G = G> + ?Sized>(&mut self, var: &A, value: A::Assignment) {
        var.assign(self, value)
    }
}

#[non_exhaustive]
pub struct StructuredRelation<G: PrimeGroup, Vars> {
    pub vars: Vars,
    pub relation: LinearRelation<G>,
}

impl<G: PrimeGroup, Vars: Allocate<G = G>> StructuredRelation<G, Vars> {
    fn new() -> Self {
        let mut relation = LinearRelation::new();
        Self {
            vars: relation.allocate(),
            relation,
        }
    }
}
