use rand_core::{
    impls::{next_u32_via_fill, next_u64_via_fill},
    CryptoRng, Error, RngCore,
};
use sha3::digest::{ExtendableOutput, Update, XofReader};

pub struct TestDrng {
    state: sha3::Shake128,
    squeeze_offset: usize,
}

impl TestDrng {
    pub fn from_seed(seed_label: &[u8]) -> Self {
        let mut initial_block = [0u8; 168];
        let domain = b"sigma-proofs/TestDRNG/SHAKE128";
        initial_block[..domain.len()].copy_from_slice(domain);

        let mut state = sha3::Shake128::default();
        state.update(&initial_block);
        state.update(&fixed_seed(seed_label));
        Self {
            state,
            squeeze_offset: 0,
        }
    }

    fn squeeze_into(&mut self, buf: &mut [u8]) {
        let end = self.squeeze_offset + buf.len();
        let mut full = vec![0u8; end];
        self.state.clone().finalize_xof().read(&mut full);
        buf.copy_from_slice(&full[self.squeeze_offset..end]);
        self.squeeze_offset = end;
    }
}

fn fixed_seed(label: &[u8]) -> [u8; 32] {
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
        self.squeeze_into(dst)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}
