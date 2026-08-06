use rand_core::{utils::next_word_via_fill, Infallible, TryCryptoRng, TryRng};

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

impl TryCryptoRng for TestDrng {}

impl TryRng for TestDrng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0.squeeze(dst);
        Ok(())
    }
}
