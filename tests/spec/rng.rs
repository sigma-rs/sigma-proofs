use rand_core::{
    impls::{next_u32_via_fill, next_u64_via_fill},
    CryptoRng, Error, RngCore,
};

use spongefish::{instantiations::Shake128, DuplexSpongeInterface as _};

/// TestDrng from draft-sigma specification [1].
///
/// [1] https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-sigma-protocols-02#appendix-A.1
pub struct TestDrng(Shake128);

impl TestDrng {
    pub fn from_seed(seed_label: &[u8]) -> Self {
        const DOMAIN: &[u8] = b"sigma-proofs/TestDRNG/SHAKE128";
        let mut initial_block = [0u8; 168];
        initial_block[..DOMAIN.len()].copy_from_slice(DOMAIN);

        let mut sponge = Shake128::default();
        sponge.absorb(&initial_block);
        sponge.absorb(&fixed_seed(seed_label));
        Self(sponge)
    }
}

fn fixed_seed(label: &[u8]) -> [u8; 32] {
    if label.len() > 32 {
        panic!("seed label length must be less or equal to 32 bytes")
    }

    let mut seed = [0u8; 32];
    seed[..label.len()].copy_from_slice(label);
    seed
}

impl CryptoRng for TestDrng {}

impl RngCore for TestDrng {
    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.squeeze(dst);
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}
