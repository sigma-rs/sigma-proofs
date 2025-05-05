use crate::toolbox::sigma::sage_test::{TestDRNG, SInput, SRandom};
use group::Group;
use ff::PrimeField;
use bls12_381::G1Projective;
use subtle::CtOption;
use num_bigint::BigUint;
use hex::FromHex;

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

impl SRandom<TestDRNG> for G1Projective {
    fn srandom(
        rng: &mut TestDRNG
    ) -> Self::Scalar {
        let low = BigUint::parse_bytes(b"1", 10).unwrap();
        let high = BigUint::parse_bytes(b"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000", 16).unwrap();
        let rand = rng.randint_big(&low, &high);
        let mut hex_string = rand.to_str_radix(16);
        if hex_string.len() < 64 {
            hex_string = format!("{:0>64}", hex_string); // pad à gauche avec des zéros
        }
        G1Projective::scalar_from_hex_be(&hex_string).unwrap()
    }
}