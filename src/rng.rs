//! The pseudo-random generator used for sampling scalars.

use group::{ff::Field, Group};
use rand_core::{CryptoRng, RngCore};

use crate::traits::ScalarRng;

impl<R: RngCore + CryptoRng> ScalarRng for R {
    fn random_scalar<G: Group>(&mut self) -> G::Scalar {
        G::Scalar::random(self)
    }
}
