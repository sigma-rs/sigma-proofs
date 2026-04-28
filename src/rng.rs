//! The pseudo-random generator used for sampling scalars.

use alloc::vec::Vec;
use core::{array::from_fn, iter::repeat_with};

use group::Group;
use rand_core::CryptoRngCore;
use spongefish::Decoding;

use crate::traits::ScalarRng;

/// Blanket implementation for all types that implement [`group::Group`] and
/// its Scalar field implements [`spongefish::Decoding<u8>`].
impl<G> ScalarRng for G
where
    G: Group,
    G::Scalar: Decoding<[u8]>,
{
    fn random_scalars<const N: usize>(rng: &mut impl CryptoRngCore) -> [G::Scalar; N] {
        from_fn(|_| sample_by_decoding(rng))
    }

    fn random_scalars_vec(rng: &mut impl CryptoRngCore, n: usize) -> Vec<G::Scalar> {
        let mut v = Vec::with_capacity(n);
        v.extend(repeat_with(|| sample_by_decoding::<G::Scalar>(rng)).take(n));
        v
    }
}

/// Returns a type by decoding a byte string sampled from a
/// cryptographically-secure random source of bytes.
fn sample_by_decoding<D: Decoding<[u8]>>(rng: &mut impl CryptoRngCore) -> D {
    let mut repr = D::Repr::default();
    rng.fill_bytes(repr.as_mut());
    D::decode(repr)
}
