use sha2::{Sha256, Digest};
use rand::{CryptoRng, Error, RngCore};
use num_bigint::BigUint;
use num_traits::One;

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

    pub fn _randint(&mut self, l: u64, h: u64) -> u64 {
        assert!(l <= h);
        let range = h - l + 1;
        let bits = 64 - range.leading_zeros();
        let bytes_needed = ((bits + 7) / 8) as usize;

        loop {
            let mut buf = vec![0u8; bytes_needed];
            self.fill_bytes(&mut buf);
            let mut val = 0u64;
            for b in buf {
                val = (val << 8) | b as u64;
            }
            if val < (1u64 << bits) {
                return l + (val % range);
            }
        }
    }

    pub fn _randint_big(&mut self, l: &BigUint, h: &BigUint) -> BigUint {
        assert!(l <= h);
        let range = h - l + BigUint::one();
        let bits = range.bits();
        let bytes_needed = ((bits + 7) / 8) as usize;

        loop {
            let mut buf = vec![0u8; bytes_needed];
            self.fill_bytes(&mut buf);
            let val = BigUint::from_bytes_be(&buf);
            if val.bits() <= bits {
                return l + (val % &range);
            }
        }
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

impl CryptoRng for TestDRNG { }