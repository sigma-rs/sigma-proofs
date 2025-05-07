use sigma_rs::tests::spec::random::{SInput, SRandom};
use sigma_rs::toolbox::sigma::transcript::keccak_transcript::Modulable;
use group::Group;
use ff::PrimeField;
use bls12_381::{G1Projective, Scalar};
use rand::{Rng, CryptoRng};
use subtle::CtOption;
use num_bigint::BigUint;
use hex::FromHex;
use num_traits::One;

impl SInput for G1Projective {
    fn scalar_from_hex_be(
            hex_str: &str
        ) -> Option<Self::Scalar> {
        let be_bytes = Vec::from_hex(hex_str).ok()?;
        if be_bytes.len() != 32 {
            return None;
        }

        let mut le_bytes = [0u8; 32];
        for (i, b) in be_bytes.iter().enumerate() {
            le_bytes[31 - i] = *b;
        }

        let ctopt: CtOption<Self::Scalar> = <Self as Group>::Scalar::from_repr(le_bytes);
        if bool::from(ctopt.is_some()) {
            Some(ctopt.unwrap())
        } else {
            None
        }
    }
}

impl SRandom for G1Projective {
    fn randint_big(
        l: &BigUint,
        h: &BigUint,
        rng: &mut (impl Rng + CryptoRng)
    ) -> BigUint {
        assert!(l <= h);
        let range = h - l + BigUint::one();
        let bits = range.bits();
        let bytes_needed = ((bits + 7) / 8) as usize;

        loop {
            let mut buf = vec![0u8; bytes_needed];
            rng.fill_bytes(&mut buf);
            let val = BigUint::from_bytes_be(&buf);
            if val.bits() <= bits {
                return l + (val % &range);
            }
        }
    }

    fn srandom(
        rng: &mut (impl Rng + CryptoRng)
    ) -> Self::Scalar {
        let low = BigUint::parse_bytes(b"1", 10).unwrap();
        let high = BigUint::parse_bytes(b"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000", 16).unwrap();
        let rand = Self::randint_big(&low, &high, rng);
        let mut hex_string = rand.to_str_radix(16);
        if hex_string.len() < 64 {
            hex_string = format!("{:0>64}", hex_string); // pad à gauche avec des zéros
        }
        G1Projective::scalar_from_hex_be(&hex_string).unwrap()
    }
}

impl Modulable for Scalar {
    fn cardinal() -> BigUint {
        BigUint::parse_bytes(b"111001111101101101001110101001100101001100111010111110101001000001100110011100111011000000010000000100110100001110110000000010101010011101111011010010000000010111111111111111001011011111111101111111111111111111111111111111100000000000000000000000000000001", 2).unwrap()
    }
}