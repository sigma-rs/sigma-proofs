//! The seeded test DRNG of the specification (Section "Test Vectors").
//!
//! `random_scalar()` is `DecodeField(Squeeze(Ns + 16), p, 1)` on a SHAKE128
//! duplex sponge initialized with the 32-byte session identifier
//! `__sigma-proofs/TestDRNG/SHAKE128` that absorbed the vector's tag once.

use core::array::from_fn;

use group::Group;
use spongefish::instantiations::dsfs::Shake128;
use spongefish::Decoding;

use sigma_proofs::traits::ScalarRng;

/// The session identifier of the test DRNG (exactly 32 bytes).
const TESTDRNG_SID: &[u8; 32] = b"__sigma-proofs/TestDRNG/SHAKE128";

pub struct TestDrng(Shake128);

impl TestDrng {
    pub fn new(tag: &[u8]) -> Self {
        let mut sponge = Shake128::new(TESTDRNG_SID);
        sponge.absorb(tag);
        Self(sponge)
    }

    /// Advance the stream by `n` scalar draws, as consumed by the vector
    /// generator's relation builder (instance and witness scalars) before
    /// the prover draws its nonces.
    pub fn skip_scalars<G: Group>(&mut self, n: usize)
    where
        G::Scalar: Decoding<[u8]>,
    {
        for _ in 0..n {
            let _ = self.random_scalar::<G>();
        }
    }

    fn random_scalar<G: Group>(&mut self) -> G::Scalar
    where
        G::Scalar: Decoding<[u8]>,
    {
        // Squeeze the scalar's decoding buffer (Ns + 16 bytes for the
        // ciphersuites of the specification) and wide-reduce.
        let mut repr = <G::Scalar as Decoding<[u8]>>::Repr::default();
        self.0.squeeze(repr.as_mut());
        <G::Scalar as Decoding<[u8]>>::decode(repr)
    }
}

impl ScalarRng for TestDrng {
    fn random_scalars<G: Group, const N: usize>(&mut self) -> [G::Scalar; N]
    where
        G::Scalar: Decoding<[u8]>,
    {
        from_fn(|_| self.random_scalar::<G>())
    }

    fn random_scalars_vec<G: Group>(&mut self, n: usize) -> Vec<G::Scalar>
    where
        G::Scalar: Decoding<[u8]>,
    {
        (0..n).map(|_| self.random_scalar::<G>()).collect()
    }
}
