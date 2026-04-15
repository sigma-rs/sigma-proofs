use curve25519_dalek::RistrettoPoint;

use crate::FromUniformBytes;

impl FromUniformBytes for RistrettoPoint {
    type Bytes = [u8; 64];

    fn from_uniform_bytes(bytes: &Self::Bytes) -> Self {
        Self::from_uniform_bytes(bytes)
    }
}

crate::impl_from_hash!(RistrettoPoint);
