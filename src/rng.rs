//! The pseudo-random generator used for sampling scalars.

use alloc::vec::Vec;
use core::{array::from_fn, iter::repeat_with};

use group::{ff::Field, Group};
use rand_core::{CryptoRng, RngCore};

use crate::traits::ScalarRng;

impl<R: RngCore + CryptoRng> ScalarRng for R {
    fn random_scalars<G: Group, const N: usize>(&mut self) -> [G::Scalar; N] {
        from_fn(|_| G::Scalar::random(&mut *self))
    }

    fn random_scalars_vec<G: Group>(&mut self, n: usize) -> Vec<G::Scalar> {
        let mut v = Vec::with_capacity(n);
        v.extend(repeat_with(|| G::Scalar::random(&mut *self)).take(n));
        v
    }
}
