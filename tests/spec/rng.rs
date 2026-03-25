use core::{array::from_fn, iter::repeat_with};

use group::{ff::PrimeField, prime::PrimeGroup, Group};
use spongefish::Decoding;

use sigma_proofs::{traits::ScalarRng, DuplexSpongeInterface, ShakeDuplexSponge};

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

pub fn proof_generation_rng<G>(count: usize) -> MockScalarRng<std::vec::IntoIter<Vec<u8>>>
where
    G: PrimeGroup,
    G::Scalar: Decoding<[u8]>,
{
    MockScalarRng(test_drng_scalars::<G>(b"proof_generation_seed", count).into_iter())
}

fn test_drng_scalars<G>(seed_label: &[u8], count: usize) -> Vec<Vec<u8>>
where
    G: PrimeGroup,
    G::Scalar: Decoding<[u8]>,
{
    let mut drng = TestDrng::from_seed(seed_label);
    (0..count)
        .map(|_| drng.random_scalar_bytes::<G>())
        .collect()
}

struct TestDrng {
    state: ShakeDuplexSponge,
    squeeze_offset: usize,
}

impl TestDrng {
    fn from_seed(seed_label: &[u8]) -> Self {
        let mut state =
            ShakeDuplexSponge::new(padded_identifier(b"sigma-proofs/TestDRNG/SHAKE128"));
        state.absorb(&fixed_seed(seed_label));
        Self {
            state,
            squeeze_offset: 0,
        }
    }

    fn random_scalar_bytes<G>(&mut self) -> Vec<u8>
    where
        G: PrimeGroup,
        G::Scalar: Decoding<[u8]>,
    {
        let mut repr = <G::Scalar as Decoding<[u8]>>::Repr::default();
        let uniform_bytes = self.squeeze(repr.as_mut().len());
        repr.as_mut().copy_from_slice(&uniform_bytes);
        let scalar = G::Scalar::decode(repr);
        scalar.to_repr().as_ref().to_vec()
    }

    fn squeeze(&mut self, length: usize) -> Vec<u8> {
        let end = self.squeeze_offset + length;
        let full = self.state.squeeze(end);
        let out = full[self.squeeze_offset..end].to_vec();
        self.squeeze_offset = end;
        out
    }
}

fn fixed_seed(label: &[u8]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..label.len()].copy_from_slice(label);
    seed
}

fn padded_identifier(identifier: &[u8]) -> [u8; 64] {
    let mut padded = [0u8; 64];
    padded[..identifier.len()].copy_from_slice(identifier);
    padded
}
