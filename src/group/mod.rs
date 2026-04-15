use bytemuck::Zeroable;

use crate::group::hash::ExpandMessage;
/// Implementation of multi-scalar multiplication (MSM) over scalars and points.
pub mod msm;

// TODO: Move these out into their own crate.
/// Implementation of hashing utilities from RFC9380.
pub mod hash;

/// Map a fixed number of uniform bytes into the target group, ensuring a uniform distribution.
///
/// Group elements generated from pseudo-random bytes using this method will have no known discrete
/// log with respect to other members of the group.
pub trait FromUniformBytes: Sized {
    /// Byte array type used as the input to [FromUniformBytes::from_uniform_bytes]. In most cases,
    /// this should be `[u8; N]` where `N` is the number of bytes for a uniform map to the group.
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Zeroable;

    /// Map a fixed number of uniform bytes into the target group, ensuring a uniform distribution.
    fn from_uniform_bytes(bytes: &Self::Bytes) -> Self;
}

/// # Examples
///
/// Hashing with SHA-256 (via [`ExpandMsgXmd`](hash::ExpandMsgXmd)):
///
/// ```
/// use curve25519_dalek::RistrettoPoint;
/// use sha2::Sha256;
/// use sigma_proofs::group::{FromHash, hash::ExpandMsgXmd};
///
/// let _: RistrettoPoint = FromHash::<ExpandMsgXmd<Sha256>>::from_hash(b"FromHash::doctest", b"msg");
/// ```
///
/// Hashing with SHAKE128:
///
/// ```
/// use sha3::Shake128;
/// use sigma_proofs::group::FromHash;
///
/// let _: p256::ProjectivePoint = FromHash::<Shake128>::from_hash(b"FromHash::doctest", b"msg");
/// ```
///
/// Using incremental hashing:
///
/// ```
/// use digest::Update as _;
/// use sha3::Shake128;
/// use sigma_proofs::group::FromHash;
///
/// let mut hasher = Shake128::default();
/// hasher.update(b"part of my message");
/// hasher.update(b"the other part of my message");
/// let _: p256::ProjectivePoint = FromHash::<Shake128>::from_hasher(b"FromHash::doctest", hasher);
/// ```
pub trait FromHash<H: ExpandMessage>: FromUniformBytes {
    fn from_hasher(domain: &[u8], hasher: H) -> Self;

    fn from_hash(domain: &[u8], input: &[u8]) -> Self;
}

/// # Examples
///
/// ```
/// use digest::Update as _;
/// use sha3::Shake128;
/// use sigma_proofs::group::HashInto;
///
/// // Hash bytes directly.
/// let _: curve25519_dalek::RistrettoPoint = Shake128::hash_into(b"domain", b"msg");
///
/// // Or drive the XOF manually and hand off the state.
/// let _: curve25519_dalek::RistrettoPoint =
///     Shake128::default().chain(b"msg").hasher_into(b"domain");
/// ```
pub trait HashInto<T>: Sized + ExpandMessage
where
    T: FromHash<Self>,
{
    fn hasher_into(self, domain: &[u8]) -> T {
        T::from_hasher(domain, self)
    }

    fn hash_into(domain: &[u8], input: &[u8]) -> T {
        T::from_hash(domain, input)
    }
}

impl<H, T> HashInto<T> for H
where
    H: Sized + ExpandMessage,
    T: FromHash<H>,
{
}

/// Generates a default [`FromHash`] impl for a type that implements [`FromUniformBytes`].
///
/// The generated impl is blanket over [ExpandMessage].
/// Assumes `<Self as FromUniformBytes>::Bytes` is a byte array (some `[u8; _]`).
macro_rules! impl_from_digest {
    ($type:ty) => {
        impl<H> $crate::group::FromHash<H> for $type
        where
            H: $crate::group::ExpandMessage,
        {
            fn from_hasher(domain: &[u8], hasher: H) -> Self {
                let uniform_bytes =
                    <H as $crate::group::ExpandMessage>::expand_message_digest(hasher, domain);
                <Self as $crate::group::FromUniformBytes>::from_uniform_bytes(&uniform_bytes)
            }

            fn from_hash(domain: &[u8], input: &[u8]) -> Self {
                let uniform_bytes =
                    <H as $crate::group::ExpandMessage>::expand_message(domain, input);
                <Self as $crate::group::FromUniformBytes>::from_uniform_bytes(&uniform_bytes)
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
