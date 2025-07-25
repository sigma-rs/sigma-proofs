use bls12_381::G1Projective;
use ff::PrimeField;
use group::Group;
use hex::FromHex;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use subtle::CtOption;

use crate::tests::spec::random::{SInput, SRandom};

impl SInput for G1Projective {
    fn scalar_from_hex_be(hex_str: &str) -> Option<Self::Scalar> {
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
    fn randint_big(l: &BigUint, h: &BigUint, rng: &mut (impl Rng + CryptoRng)) -> BigUint {
        assert!(l <= h);
        let range = h - l;
        let bits = range.bits();
        #[allow(clippy::manual_div_ceil)]
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

    fn random_scalar_elt(rng: &mut (impl Rng + CryptoRng)) -> Self::Scalar {
        let low = BigUint::parse_bytes(b"1", 10).unwrap();
        let high = BigUint::parse_bytes(
            b"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
            16,
        )
        .unwrap();
        let rand = Self::randint_big(&low, &high, rng);
        let mut hex_string = rand.to_str_radix(16);
        if hex_string.len() < 64 {
            hex_string = format!("{hex_string:0>64}");
        }
        G1Projective::scalar_from_hex_be(&hex_string).unwrap()
    }

}
