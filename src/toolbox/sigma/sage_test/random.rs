use group::{Group, GroupEncoding};
use rand::{Rng, CryptoRng};
use num_bigint::BigUint;

pub trait SInput: Group + GroupEncoding {
    fn scalar_from_hex_be(
        hex_str: &str
    ) -> Option<Self::Scalar>;
}

pub trait SRandom<DRNG: Rng + CryptoRng>: Group {
    fn randint_big(
        rng: &mut DRNG, l: &BigUint, h: &BigUint
    ) -> BigUint;

    fn srandom(
        rng: &mut DRNG
    ) -> Self::Scalar;
}