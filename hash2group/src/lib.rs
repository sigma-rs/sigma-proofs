//! Hash-to-group traits with optional implementations of RFC 9380 expand_message
//! and select elliptic curves.
//!
//! By default this crate provides only the traits ([`ExpandMessage`],
//! [`FromUniformBytes`], [`FromHash`], [`HashInto`]) and the [`impl_from_hash!`]
//! macro. Implementations are pulled in through optional features:
//!
//! - `rfc9380` — [`ExpandMessage`] implementations for fixed-output digests and
//!   extendable-output functions from the [`digest`] crate.
//! - `curve25519-dalek` — [`FromUniformBytes`] / [`FromHash`] for
//!   `curve25519_dalek::RistrettoPoint`.
//! - `k256` — [`FromUniformBytes`] / [`FromHash`] for `k256::ProjectivePoint`.
//! - `p256` — [`FromUniformBytes`] / [`FromHash`] for `p256::ProjectivePoint`.

#![no_std]

use bytemuck::Zeroable;

#[cfg(feature = "rfc9380")]
pub mod rfc9380;

#[cfg(feature = "curve25519-dalek")]
mod curve25519;

#[cfg(feature = "k256")]
mod k256;

#[cfg(feature = "p256")]
mod p256;

/// Maps a message and domain separation tag to a pseudorandom byte array.
///
/// Output is independent for each combination of domain separator, message, and length.
///
/// Implementations of this trait are RFC 9380 `expand_message` variants and must satisfy
/// the properties in [RFC 9380 Section 5.3.4][rfc9380-5.3.4].
///
/// [rfc9380-5.3.4]: https://www.rfc-editor.org/rfc/rfc9380#section-5.3.4
pub trait ExpandMessage: Sized {
    /// Expand `message` into a pseudorandom `[u8; N]` under `domain_separator`.
    fn expand_message<const N: usize>(domain_separator: &[u8], message: &[u8]) -> [u8; N];

    /// Expand the message already absorbed into `self` into a pseudorandom `[u8; N]`.
    fn expand_message_digest<const N: usize>(self, domain_separator: &[u8]) -> [u8; N];
}

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

/// Hash a byte string into a group element under a domain separation tag.
///
/// An implementation defines, for one group, a family of hash functions parameterized by the
/// [`ExpandMessage`] variant `H`. Each `(H, domain)` pair is a distinct hash function whose
/// output is indistinguishable from a random oracle returning elements of the group.
///
/// # Implementer requirements
///
/// Implementations must be indistinguishable from a random oracle mapping the domain and message
/// into the group. This implies:
///
/// - **Uniform distribution.** Outputs are statistically close to uniform over the group.
/// - **Unknown discrete log.** Outputs have no known discrete log with other group elements.
/// - **Domain separation.** Distinct `domain` values yield statistically independent outputs.
/// - **Determinism.** The `(domain, input)` pair fully determines the output.
///
/// The [`impl_from_hash`] macro may be used to implement this trait.
///
/// # Example
///
/// ```
/// # #[cfg(all(feature = "rfc9380", feature = "curve25519-dalek"))] {
/// use curve25519_dalek::RistrettoPoint;
/// use sha3::Shake128;
/// use hash2group::FromHash;
///
/// let a: RistrettoPoint = FromHash::<Shake128>::from_hash(b"FromHash::docs", b"msg");
/// # }
/// ```
pub trait FromHash<H: ExpandMessage>: FromUniformBytes {
    /// Hash a hasher state with `input` already absorbed into a group element under `domain`.
    ///
    /// Use this when the message is built incrementally or is not available as a single contiguous
    /// slice. Calling [`from_hasher`](FromHash::from_hasher) with an `H` that has absorbed the
    /// concatenated `input` returns the same point as [`from_hash(domain, input)`](FromHash::from_hash).
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rfc9380", feature = "p256"))] {
    /// use digest::Update as _;
    /// use sha3::Shake128;
    /// use hash2group::FromHash;
    ///
    /// let mut hasher = Shake128::default();
    /// hasher.update(b"part of my message");
    /// hasher.update(b"the other part of my message");
    /// let _: p256::ProjectivePoint =
    ///     FromHash::<Shake128>::from_hasher(b"FromHash::from_hasher::docs", hasher);
    /// # }
    /// ```
    fn from_hasher(domain: &[u8], hasher: H) -> Self;

    /// Hash `input` into a group element under `domain`.
    ///
    /// # Examples
    ///
    /// Hashing with SHA-256 via [`ExpandMsgXmd`](crate::rfc9380::ExpandMsgXmd):
    ///
    /// ```
    /// # #[cfg(all(feature = "rfc9380", feature = "curve25519-dalek"))] {
    /// use curve25519_dalek::RistrettoPoint;
    /// use sha2::Sha256;
    /// use hash2group::{FromHash, rfc9380::ExpandMsgXmd};
    ///
    /// let _: RistrettoPoint =
    ///     FromHash::<ExpandMsgXmd<Sha256>>::from_hash(b"FromHash::from_hash::docs::sha256", b"msg");
    /// # }
    /// ```
    ///
    /// Hashing with SHAKE128 (uses the `expand_message_xof` algorithm):
    ///
    /// ```
    /// # #[cfg(all(feature = "rfc9380", feature = "p256"))] {
    /// use sha3::Shake128;
    /// use hash2group::FromHash;
    ///
    /// let _: p256::ProjectivePoint =
    ///     FromHash::<Shake128>::from_hash(b"FromHash::from_hash::docs::shake128", b"msg");
    /// # }
    /// ```
    fn from_hash(domain: &[u8], input: &[u8]) -> Self;
}

/// Hash a byte string into a group element under a domain separation tag.
///
/// Complimenting [`FromHash`], this method is implemented on the hasher rather than the group.
/// See [`FromHash`] for more information and implementation properties.
///
/// # Example
///
/// ```
/// # #[cfg(all(feature = "rfc9380", feature = "curve25519-dalek"))] {
/// use curve25519_dalek::RistrettoPoint;
/// use sha3::Shake128;
/// use hash2group::HashInto;
///
/// let a: RistrettoPoint = Shake128::hash_into(b"HashInto::docs", b"msg");
/// # }
/// ```
pub trait HashInto<T>: Sized + ExpandMessage
where
    T: FromHash<Self>,
{
    /// Finalize the hasher state into the group under `domain`.
    ///
    /// See [`FromHash::from_hasher`].
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rfc9380", feature = "curve25519-dalek"))] {
    /// use curve25519_dalek::RistrettoPoint;
    /// use digest::Update as _;
    /// use sha3::Shake128;
    /// use hash2group::HashInto;
    ///
    /// let a: RistrettoPoint = Shake128::default()
    ///     .chain(b"msg")
    ///     .hasher_into(b"HashInto::hasher_into::docs");
    /// # }
    /// ```
    // TODO: hasher_into is not my favorite name for a method ever
    fn hasher_into(self, domain: &[u8]) -> T {
        T::from_hasher(domain, self)
    }

    /// Hash `input` into `T` under `domain`.
    ///
    /// See [`FromHash::from_hash`].
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(all(feature = "rfc9380", feature = "curve25519-dalek"))] {
    /// use curve25519_dalek::RistrettoPoint;
    /// use sha3::Shake128;
    /// use hash2group::HashInto;
    ///
    /// let _: RistrettoPoint = Shake128::hash_into(b"HashInto::hash_into::docs", b"msg");
    /// # }
    /// ```
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
/// The generated impl is blanket over [`ExpandMessage`].
/// Assumes `<Self as FromUniformBytes>::Bytes` is a byte array (some `[u8; _]`).
#[macro_export]
macro_rules! impl_from_hash {
    ($type:ty) => {
        impl<H> $crate::FromHash<H> for $type
        where
            H: $crate::ExpandMessage,
        {
            fn from_hasher(domain: &[u8], hasher: H) -> Self {
                let uniform_bytes =
                    <H as $crate::ExpandMessage>::expand_message_digest(hasher, domain);
                <Self as $crate::FromUniformBytes>::from_uniform_bytes(&uniform_bytes)
            }

            fn from_hash(domain: &[u8], input: &[u8]) -> Self {
                let uniform_bytes = <H as $crate::ExpandMessage>::expand_message(domain, input);
                <Self as $crate::FromUniformBytes>::from_uniform_bytes(&uniform_bytes)
            }
        }
    };
}
