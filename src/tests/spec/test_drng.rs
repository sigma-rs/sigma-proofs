use rand::{CryptoRng, Error, RngCore};
use sha2::{Digest, Sha256};

pub struct TestDRNG {
    seed: [u8; 32],
}

impl TestDRNG {
    pub fn new(seed: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        let result = hasher.finalize();
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&result);
        Self { seed: seed_bytes }
    }
}

impl RngCore for TestDRNG {
    fn next_u32(&mut self) -> u32 {
        let val = u32::from_be_bytes([self.seed[0], self.seed[1], self.seed[2], self.seed[3]]);
        let mut hasher = Sha256::new();
        hasher.update(val.to_be_bytes());
        let result = hasher.finalize();
        self.seed.copy_from_slice(&result);
        val
    }

    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | (self.next_u32() as u64)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let rand = self.next_u32().to_be_bytes();
            for b in rand.iter() {
                if i < dest.len() {
                    dest[i] = *b;
                    i += 1;
                } else {
                    break;
                }
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestDRNG {}
