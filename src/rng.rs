//! The random number generator used for sampling scalars.
//!
//! Per the specification (Section "Randomized algorithms"), sampling a random
//! scalar takes two steps: obtaining high-quality entropy via a CSPRNG (the
//! operating system's entropy source by default), and reducing the resulting
//! bytes to a scalar via the wide reduction of the Fiat-Shamir draft's
//! `DecodeField` -- the same distribution-preserving path used for challenges.
//!
//! The concrete generator is [`spongefish::PrivateRng`], re-exported here as
//! [`ProofRng`]: a SHAKE128 duplex sponge whose seed occupies its own permuted
//! compartment. Build one with [`ProofRng::from_os_entropy`] (default) or
//! [`ProofRng::from_seed`] (deterministic; test vectors only), and mix in
//! external entropy with `mix_entropy`.

use alloc::vec::Vec;
use core::{array::from_fn, iter::repeat_with};

use group::Group;
use spongefish::Decoding;

use crate::traits::ScalarRng;

/// The prover's random number generator (see the [module docs][self]).
pub use spongefish::PrivateRng as ProofRng;

impl ScalarRng for ProofRng {
    fn random_scalars<G: Group, const N: usize>(&mut self) -> [G::Scalar; N]
    where
        G::Scalar: Decoding<[u8]>,
    {
        from_fn(|_| self.sample::<G::Scalar>())
    }

    fn random_scalars_vec<G: Group>(&mut self, n: usize) -> Vec<G::Scalar>
    where
        G::Scalar: Decoding<[u8]>,
    {
        let mut v = Vec::with_capacity(n);
        v.extend(repeat_with(|| self.sample::<G::Scalar>()).take(n));
        v
    }
}
