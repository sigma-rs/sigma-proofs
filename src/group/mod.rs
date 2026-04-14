use bytemuck::Zeroable;
/// Implementation of multi-scalar multiplication (MSM) over scalars and points.
pub mod msm;

// TODO: Move these out into their own crate.
/// Implementation of hashing utilities from RFC9380.
pub mod hash;

pub trait FromUniformBytes: Sized {
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Zeroable;

    fn from_uniform_bytes(bytes: &Self::Bytes) -> Self;
}

// TODO: Provide an example of using this with XofFixedWrapper
// TODO: Add the domain_separator to this interface.
pub trait FromDigest<D>: FromUniformBytes {
    fn from_digest(digest: D) -> Self;

    fn from_hash(input: impl AsRef<[u8]>) -> Self;
}

pub trait DigestInto<T>: Sized
where
    T: FromDigest<Self>,
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
    D: Sized,
    T: FromDigest<D>,
{
}

/// Generates a default [`FromDigest`] impl for a group element type that implements
/// [`FromUniformBytes`], using [`expand_message_digest_xmd`][hash::expand_message_digest_xmd].
///
/// Provides a blanket implementation for all digest types `D: Digest + BlockSizeUser`, and assumes
/// that `<Self as UniformBytes>::Bytes` is a byte array (i.e. is some `[u8; _]`).
macro_rules! impl_from_digest {
    ($type:ty) => {
        impl<D> $crate::group::FromDigest<D> for $type
        where
            D: ::digest::Digest + ::digest::common::BlockSizeUser,
        {
            fn from_digest(digest: D) -> Self {
                let uniform_bytes =
                    $crate::group::hash::expand_message_digest_xmd(b"".as_slice(), digest);
                <Self as $crate::group::FromUniformBytes>::from_uniform_bytes(&uniform_bytes)
            }

            fn from_hash(input: impl AsRef<[u8]>) -> Self {
                <Self as $crate::group::FromDigest<D>>::from_digest(
                    <D as ::digest::Digest>::new()
                        .chain_update($crate::group::hash::zero_pad::<D>())
                        .chain_update(input),
                )
            }
        }
    };
}

#[cfg(feature = "curve25519-dalek")]
mod curve25519 {
    use curve25519_dalek::RistrettoPoint;

    use super::FromUniformBytes;

    impl FromUniformBytes for RistrettoPoint {
        type Bytes = [u8; 64];

        fn from_uniform_bytes(bytes: &Self::Bytes) -> Self {
            Self::from_uniform_bytes(bytes)
        }
    }

    impl_from_digest!(RistrettoPoint);
}

#[cfg(feature = "k256")]
mod k256 {
    use elliptic_curve::hash2curve::{FromOkm, MapToCurve};
    use k256::{FieldElement, ProjectivePoint};

    use super::FromUniformBytes;

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

    impl_from_digest!(ProjectivePoint);
}

#[cfg(feature = "p256")]
mod p256 {
    use elliptic_curve::hash2curve::{FromOkm, MapToCurve};
    use p256::{FieldElement, ProjectivePoint};

    use super::FromUniformBytes;

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

    impl_from_digest!(ProjectivePoint);
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
