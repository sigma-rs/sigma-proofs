use group::{Group, GroupEncoding};
use rand::{Rng, CryptoRng};

pub trait SInput: Group + GroupEncoding {
    fn scalar_from_hex_be(
        hex_str: &str
    ) -> Option<Self::Scalar>;
}

pub trait SRandom<DRNG: Rng + CryptoRng>: Group {
    fn srandom(
        rng: &mut DRNG
    ) -> Self::Scalar;
}