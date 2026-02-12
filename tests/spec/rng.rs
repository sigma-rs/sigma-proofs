use core::{array::from_fn, iter::repeat_with};

use group::{ff::PrimeField, Group};
use rand_core::{Error, RngCore, SeedableRng};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

use sigma_proofs::traits::Prng;

pub struct Shake128PRNG(<Shake128 as ExtendableOutput>::Reader);

impl SeedableRng for Shake128PRNG {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        let mut shake = Shake128::default();
        shake.update(&seed);
        Self(shake.finalize_xof())
    }
}

impl RngCore for Shake128PRNG {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.read(dst)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

pub struct TracingPRNG<R: Prng> {
    inner: R,
    store: Vec<Vec<u8>>,
}

impl<R: Prng> TracingPRNG<R> {
    pub fn new(rng: R) -> Self {
        Self {
            inner: rng,
            store: vec![],
        }
    }

    pub fn collect(self) -> Vec<Vec<u8>> {
        self.store
    }
}

impl<R: Prng> Prng for TracingPRNG<R> {
    fn random_scalars<G: Group, const N: usize>(&mut self) -> [G::Scalar; N] {
        let scalars = self.inner.random_scalars::<G, N>();
        self.store
            .extend(scalars.iter().map(|s| s.to_repr().as_ref().to_vec()));
        scalars
    }

    fn random_scalars_vec<G: Group>(&mut self, n: usize) -> Vec<G::Scalar> {
        let scalars = self.inner.random_scalars_vec::<G>(n);
        self.store
            .extend(scalars.iter().map(|s| s.to_repr().as_ref().to_vec()));
        scalars
    }
}

pub struct MockPRNG<I: Iterator<Item = Vec<u8>>>(pub I);

impl<I: Iterator<Item = Vec<u8>>> MockPRNG<I> {
    fn next<G: Group>(&mut self) -> G::Scalar {
        let scalar = self.0.next().unwrap();
        let mut repr = <G::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&scalar);
        G::Scalar::from_repr(repr).unwrap()
    }
}

impl<I: Iterator<Item = Vec<u8>>> Prng for MockPRNG<I> {
    fn random_scalars<G: Group, const N: usize>(&mut self) -> [G::Scalar; N] {
        from_fn(|_| self.next::<G>())
    }

    fn random_scalars_vec<G: Group>(&mut self, n: usize) -> Vec<G::Scalar> {
        let mut v = Vec::with_capacity(n);
        v.extend(repeat_with(|| self.next::<G>()).take(n));
        v
    }
}

#[test]
fn test_rng() {
    type G = bls12_381::G1Projective;
    let seed = *b"0x0102030405060708090a0b0c0d0e0f";
    let seedable = Shake128PRNG::from_seed(seed);

    let mut trace = TracingPRNG::new(seedable);
    let want = trace.random_scalars_vec::<G>(3);
    let scalars = trace.collect();

    let mut mock = MockPRNG(scalars.into_iter());
    let got = mock.random_scalars_vec::<G>(3);

    assert_eq!(got, want);
}
