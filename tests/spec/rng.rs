use core::{array::from_fn, iter::repeat_with};

use group::{ff::PrimeField, Group};

use sigma_proofs::traits::ScalarRng;

pub struct MockScalarRng<I: Iterator<Item = Vec<u8>>>(pub I);

impl<I: Iterator<Item = Vec<u8>>> MockScalarRng<I> {
    fn next<G: Group>(&mut self) -> G::Scalar {
        let scalar = self.0.next().expect("missing scalar bytes");
        let mut repr = <G::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&scalar);
        G::Scalar::from_repr(repr).expect("invalid scalar bytes")
    }
}

impl<I: Iterator<Item = Vec<u8>>> ScalarRng for MockScalarRng<I> {
    fn random_scalars<G: Group, const N: usize>(&mut self) -> [G::Scalar; N] {
        from_fn(|_| self.next::<G>())
    }

    fn random_scalars_vec<G: Group>(&mut self, n: usize) -> Vec<G::Scalar> {
        let mut v = Vec::with_capacity(n);
        v.extend(repeat_with(|| self.next::<G>()).take(n));
        v
    }
}
