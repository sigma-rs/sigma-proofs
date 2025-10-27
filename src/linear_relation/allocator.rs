use core::{array, marker::PhantomData};

use crate::linear_relation::{GroupVar, ScalarVar};

pub trait Allocator<G> {
    /// Allocates a scalar variable for use in the linear map.
    fn allocate_scalar(&mut self) -> ScalarVar<G>;

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
    fn allocate_scalars<const N: usize>(&mut self) -> [ScalarVar<G>; N] {
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
    fn allocate_scalars_vec(&mut self, n: usize) -> Vec<ScalarVar<G>> {
        (0..n).map(|_| self.allocate_scalar()).collect()
    }

    /// Allocates a group element variable (i.e. elliptic curve point) for use in the linear map.
    fn allocate_element(&mut self) -> GroupVar<G>;

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
    fn allocate_elements<const N: usize>(&mut self) -> [GroupVar<G>; N] {
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
    fn allocate_elements_vec(&mut self, n: usize) -> Vec<GroupVar<G>> {
        (0..n).map(|_| self.allocate_element()).collect()
    }

    fn allocate<T: Allocate<G>>(&mut self) -> T {
        T::allocate(self)
    }
}

pub trait Allocate<G> {
    fn allocate<A: Allocator<G> + ?Sized>(alloc: &mut A) -> Self;
}

impl<G> Allocate<G> for ScalarVar<G> {
    fn allocate<A: Allocator<G> + ?Sized>(alloc: &mut A) -> Self {
        alloc.allocate_scalar()
    }
}

impl<G> Allocate<G> for GroupVar<G> {
    fn allocate<A: Allocator<G> + ?Sized>(alloc: &mut A) -> Self {
        alloc.allocate_element()
    }
}

impl<G, T: Allocate<G>, const N: usize> Allocate<G> for [T; N] {
    fn allocate<A: Allocator<G> + ?Sized>(alloc: &mut A) -> Self {
        array::from_fn(|_| alloc.allocate())
    }
}

impl<G, T1: Allocate<G>, T2: Allocate<G>> Allocate<G> for (T1, T2) {
    fn allocate<A: Allocator<G> + ?Sized>(alloc: &mut A) -> Self {
        (
            <T1 as Allocate<G>>::allocate(alloc),
            <T2 as Allocate<G>>::allocate(alloc),
        )
    }
}
