use bytemuck::Zeroable;
use digest::{
    array::{Array, AssocArraySize},
    common::BlockSizeUser,
    Digest,
};

/// Implementation of multi-scalar multiplication (MSM) over scalars and points.
pub mod msm;

// TODO: Move these out into their own crate.
/// Implementation of hashing utilities from RFC9380.
pub mod hash;

pub trait FromUniformBytes: Sized {
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Zeroable;

    fn from_uniform_bytes(bytes: &Self::Bytes) -> Self;
}

pub trait FromDigest<D>: FromUniformBytes
where
    D: Digest + BlockSizeUser,
    Self::Bytes: AssocArraySize + From<Array<u8, <Self::Bytes as AssocArraySize>::Size>>,
{
    // TODO: Provide an example of using this with XofFixedWrapper
    // TODO: Add the domain_separator to this interface.
    fn from_digest(digest: D) -> Self {
        let uniform_bytes = hash::expand_message_digest_xmd(b"".as_slice(), digest).into();
        Self::from_uniform_bytes(&uniform_bytes)
    }

    fn from_hash(input: impl AsRef<[u8]>) -> Self {
        Self::from_digest(
            D::new()
                .chain_update(hash::zero_pad::<D>())
                .chain_update(input),
        )
    }
}

pub trait DigestInto<T>: Sized + Digest + BlockSizeUser
where
    T: FromDigest<Self>,
    T::Bytes: AssocArraySize + From<Array<u8, <T::Bytes as AssocArraySize>::Size>>,
{
    fn digest_into(self) -> T {
        T::from_digest(self)
    }

    fn hash_into(input: impl AsRef<[u8]>) -> T {
        T::from_hash(input)
    }
}

impl<D, T> DigestInto<T> for D
where
    D: Sized + Digest + BlockSizeUser,
    T: FromDigest<Self>,
    T::Bytes: AssocArraySize + From<Array<u8, <T::Bytes as AssocArraySize>::Size>>,
{
}

#[cfg(feature = "curve25519-dalek")]
mod curve25519 {
    use curve25519_dalek::RistrettoPoint;
    use digest::{
        array::{Array, AssocArraySize},
        common::BlockSizeUser,
        Digest,
    };

    use super::{FromDigest, FromUniformBytes};

    impl FromUniformBytes for RistrettoPoint {
        type Bytes = [u8; 64];

        fn from_uniform_bytes(bytes: &Self::Bytes) -> Self {
            Self::from_uniform_bytes(bytes)
        }
    }

    impl<D> FromDigest<D> for RistrettoPoint
    where
        D: Digest + BlockSizeUser,
        Self::Bytes: AssocArraySize + From<Array<u8, <Self::Bytes as AssocArraySize>::Size>>,
    {
    }
}

#[cfg(feature = "k256")]
mod k256 {
    use digest::{
        array::{Array, AssocArraySize},
        common::BlockSizeUser,
        Digest,
    };
    use elliptic_curve::hash2curve::{FromOkm, MapToCurve};
    use k256::{FieldElement, ProjectivePoint};

    use super::{FromDigest, FromUniformBytes};

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

    impl<D> FromDigest<D> for ProjectivePoint
    where
        D: Digest + BlockSizeUser,
        Self::Bytes: AssocArraySize + From<Array<u8, <Self::Bytes as AssocArraySize>::Size>>,
    {
    }
}

#[cfg(feature = "p256")]
mod p256 {
    use digest::{
        array::{Array, AssocArraySize},
        common::BlockSizeUser,
        Digest,
    };
    use elliptic_curve::hash2curve::{FromOkm, MapToCurve};
    use p256::{FieldElement, ProjectivePoint};

    use super::{FromDigest, FromUniformBytes};

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

    impl<D> FromDigest<D> for ProjectivePoint
    where
        D: Digest + BlockSizeUser,
        Self::Bytes: AssocArraySize + From<Array<u8, <Self::Bytes as AssocArraySize>::Size>>,
    {
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused)] // TODO: Remove this

    use digest::consts::{U64, U96};

    use crate::group::{DigestInto, FromDigest};

    // TODO: Move these usage examples into docs.
    #[test]
    fn usage_sha2() {
        use curve25519_dalek::RistrettoPoint;
        #[allow(unused)]
        use sha2::{Digest as _, Sha256, Sha512};

        // NOTE: RistrettoPoint has directly implemented methods called from_hash and from_digest.
        let _: RistrettoPoint = FromDigest::<Sha512>::from_hash(b"hello");
        let _: RistrettoPoint = FromDigest::from_digest(Sha512::new().chain_update(b"hello"));
    }

    #[test]
    fn usage_sha3() {
        use curve25519_dalek::RistrettoPoint;
        use digest::{Digest as _, ExtendableOutput as _, Update as _, XofFixedWrapper};
        use sha3::Shake128;

        /*
        let _ = RistrettoPoint::from_hash_xof::<Shake128>(b"hello");
        let _ = RistrettoPoint::from_xof(&mut Shake128::default().chain(b"hello").finalize_xof());
        */

        // NOTE: RistrettoPoint has directly implemented methods called from_hash and from_digest.
        let _: RistrettoPoint = FromDigest::<XofFixedWrapper<Shake128, U64>>::from_hash(b"hello");
        let _: RistrettoPoint =
            FromDigest::from_digest(XofFixedWrapper::<Shake128, U64>::new().chain_update(b"hello"));

        let _: p256::ProjectivePoint = XofFixedWrapper::<Shake128, U96>::hash_into(b"hello");
        let _ = p256::ProjectivePoint::from_digest(
            XofFixedWrapper::<Shake128, U96>::new().chain_update(b"hello"),
        );
    }
}
