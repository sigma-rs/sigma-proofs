//! The seeded PRNG of the specification's "Test Vectors" appendix.
//!
//! A [`PrivateRng`] over SHAKE128 seeded with `DeriveSessionID` of the
//! stream's tag: scalar draws are `DecodeField(Squeeze(Ns + 16), p, 1)` on a
//! continuous output stream. Test-only: applications MUST NOT use a
//! deterministic RNG.

use spongefish::{derive_session_id, instantiations::Shake128, PrivateRng};

pub type TestDrng = PrivateRng<Shake128>;

pub fn from_tag(tag: &[u8]) -> TestDrng {
    PrivateRng::from_seed(*derive_session_id::<Shake128>(tag).as_bytes())
}

/// The instance/witness stream, `TestDRNG-SIGMA-PROOFS-{suite}-{relation}`.
pub fn instance_stream(suite: &str, relation: &str) -> TestDrng {
    from_tag(format!("TestDRNG-SIGMA-PROOFS-{suite}-{relation}").as_bytes())
}

/// A flavor's nonce stream,
/// `TestDRNG-SIGMA-PROOFS-{DSFS|CMPT}-{suite}-{relation}`.
pub fn nonce_stream(marker: &str, suite: &str, relation: &str) -> TestDrng {
    from_tag(format!("TestDRNG-SIGMA-PROOFS-{marker}-{suite}-{relation}").as_bytes())
}
