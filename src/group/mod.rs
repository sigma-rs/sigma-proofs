use bytemuck::Zeroable;
use digest::{Digest, ExtendableOutput, Output, XofReader};

/// Implementation of multi-scalar multiplication (MSM) over scalars and points.
pub mod msm;

pub trait FromUniformBytes: Sized {
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Zeroable;

    fn from_uniform_bytes(bytes: &Self::Bytes) -> Self;
}

pub trait FromHash: FromUniformBytes {
    // TODO: Provide an example of using this with XofFixedWrapper
    fn from_digest<D>(digest: D) -> Self
    where
        D: Digest,
        // NOTE: This bound is mildly odd in that Output<D> is a fully constrained type.
        Output<D>: AsRef<Self::Bytes>,
    {
        Self::from_uniform_bytes(digest.finalize().as_ref())
    }

    fn from_hash<D>(input: impl AsRef<[u8]>) -> Self
    where
        D: Digest,
        Output<D>: AsRef<Self::Bytes>,
    {
        Self::from_digest(D::new().chain_update(input))
    }
}

pub trait FromXof: FromUniformBytes {
    fn from_xof<X: XofReader>(xof: &mut X) -> Self {
        let mut bytes = Self::Bytes::zeroed();
        xof.read(bytes.as_mut());
        Self::from_uniform_bytes(&bytes)
    }

    // TODO: This method is slightly redundant with from_hash in the current implementation.
    fn from_hash_xof<D>(input: impl AsRef<[u8]>) -> Self
    where
        D: ExtendableOutput + Default,
    {
        let mut bytes = Self::Bytes::zeroed();
        D::digest_xof(input, bytes.as_mut());
        Self::from_uniform_bytes(&bytes)
    }
}

#[cfg(feature = "curve25519-dalek")]
mod curve25519 {
    use curve25519_dalek::RistrettoPoint;

    use super::{FromHash, FromUniformBytes, FromXof};

    impl FromUniformBytes for RistrettoPoint {
        type Bytes = [u8; 64];

        fn from_uniform_bytes(bytes: &Self::Bytes) -> Self {
            Self::from_uniform_bytes(bytes)
        }
    }

    impl FromHash for RistrettoPoint {}
    impl FromXof for RistrettoPoint {}
}

#[cfg(feature = "k256")]
mod k256 {
    use elliptic_curve::hash2curve::{FromOkm, MapToCurve};
    use k256::{FieldElement, ProjectivePoint};

    use super::{FromHash, FromUniformBytes, FromXof};

    impl FromUniformBytes for ProjectivePoint {
        type Bytes = [u8; 96];

        fn from_uniform_bytes(bytes: &Self::Bytes) -> Self {
            fn to_curve_nonuniform(bytes: &[u8; 48]) -> ProjectivePoint {
                FieldElement::from_okm(bytes.into()).map_to_curve()
            }
            let [b0, b1] = bytemuck::cast_ref(bytes);
            to_curve_nonuniform(b0) + to_curve_nonuniform(b1)
        }
    }

    impl FromHash for ProjectivePoint {}
    impl FromXof for ProjectivePoint {}
}

#[cfg(feature = "p256")]
mod p256 {
    use elliptic_curve::hash2curve::{FromOkm, MapToCurve};
    use p256::{FieldElement, ProjectivePoint};

    use super::{FromHash, FromUniformBytes, FromXof};

    impl FromUniformBytes for ProjectivePoint {
        type Bytes = [u8; 96];

        fn from_uniform_bytes(bytes: &Self::Bytes) -> Self {
            fn to_curve_nonuniform(bytes: &[u8; 48]) -> ProjectivePoint {
                FieldElement::from_okm(bytes.into()).map_to_curve()
            }
            let [b0, b1] = bytemuck::cast_ref(bytes);
            to_curve_nonuniform(b0) + to_curve_nonuniform(b1)
        }
    }

    impl FromHash for ProjectivePoint {}
    impl FromXof for ProjectivePoint {}
}

#[cfg(test)]
mod tests {

    #[allow(unused)]
    use digest::consts::{U64, U96};

    use crate::group::{FromHash, FromXof};

    #[test]
    fn usage_sha2() {
        use curve25519_dalek::RistrettoPoint;
        use sha2::{Digest as _, Sha512};

        // NOTE: RistrettoPoint has directly implemented methods called from_hash and from_digest.
        let _: RistrettoPoint = FromHash::from_hash::<Sha512>(b"hello");
        let _: RistrettoPoint = FromHash::from_digest(Sha512::new().chain_update(b"hello"));
    }

    #[test]
    fn usage_sha3() {
        use curve25519_dalek::RistrettoPoint;
        use digest::{Digest as _, ExtendableOutput as _, Update as _, XofFixedWrapper};
        use sha3::Shake128;

        let _ = RistrettoPoint::from_hash_xof::<Shake128>(b"hello");
        let _ = RistrettoPoint::from_xof(&mut Shake128::default().chain(b"hello").finalize_xof());

        // NOTE: RistrettoPoint has directly implemented methods called from_hash and from_digest.
        let _: RistrettoPoint = FromHash::from_hash::<XofFixedWrapper<Shake128, U64>>(b"hello");
        let _: RistrettoPoint =
            FromHash::from_digest(XofFixedWrapper::<Shake128, U64>::new().chain_update(b"hello"));

        let _ = p256::ProjectivePoint::from_hash::<XofFixedWrapper<Shake128, U96>>(b"hello");
        let _ = p256::ProjectivePoint::from_digest(
            XofFixedWrapper::<Shake128, U96>::new().chain_update(b"hello"),
        );
    }
}
