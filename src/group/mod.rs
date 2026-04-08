use bytemuck::Zeroable;
use digest::{
    array::{Array, ArraySize},
    common::BlockSizeUser,
    typenum::Unsigned,
    Digest, ExtendableOutput, Output, XofReader,
};

/// Implementation of multi-scalar multiplication (MSM) over scalars and points.
pub mod msm;

pub trait FromUniformBytes: Sized {
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Zeroable;

    fn from_uniform_bytes(bytes: &Self::Bytes) -> Self;
}

/// Generates a uniformly random byte array of length `N` from a domain separator and message.
///
/// This is an implementation of expand_message_xmd from RFC9380.
///
/// <!-- TODO: Add panic conditions -->
fn expand_message_xmd<D: Digest + BlockSizeUser, N: ArraySize>(
    domain_separator: &[u8],
    message: &[u8],
) -> Array<u8, N> {
    // Compress the message and domain separator into the digest state.
    let message_digest = D::new()
        // Prefix with a block of zeroes and the block length, as discussed in RFC9380 Section 10.6
        .chain_update(Array::<u8, D::BlockSize>::default())
        // Add in the message.
        // NOTE: The length is not included here.
        .chain_update(message);

    expand_message_digest_xmd(domain_separator, message_digest)
}

/// Generates a uniformly random byte array of length `N` from a domain separator and digest.
///
/// When the message is padded with a block of zeroes, this is an implementation of
/// expand_message_xmd from RFC9380.
///
/// <!-- TODO: Add panic conditions -->
fn expand_message_digest_xmd<D: Digest, N: ArraySize>(
    domain_separator: &[u8],
    message_digest: D,
) -> Array<u8, N> {
    // Check the invariants required by expand_message_xmd to ensure counters will not overflow.
    assert!(
        domain_separator.len() <= u8::MAX as usize,
        "expand_message_xmd requires the domain separator to be at most 255 bytes"
    );
    // NOTE: These two asserts depend only on constants.
    assert!(
        N::USIZE <= u16::MAX as usize,
        "expand_message_xmd requires the output length to be at most 65535 bytes"
    );
    assert!(
        N::USIZE / <D::OutputSize as Unsigned>::USIZE <= u8::MAX as usize,
        "expand_message_xmd requires the output length to be at most 255 times the digest length"
    );

    let digest_0 = message_digest
        // Add the requested output length.
        .chain_update(N::U16.to_be_bytes())
        // Add a zero index to mark this as the 0-index digest.
        .chain_update([0u8])
        // Add the domain separator and length.
        .chain_update(domain_separator)
        .chain_update(u8::try_from(domain_separator.len()).unwrap().to_be_bytes())
        .finalize();

    // Expand the message to fill the output array.
    let mut output = Array::<u8, N>::default();
    let mut output_chunks = output
        .chunks_mut(<D::OutputSize as Unsigned>::USIZE)
        .enumerate();

    // Write the message digest to the first chunk.
    output_chunks.next().map(|(_, chunk_0)| {
        chunk_0.copy_from_slice(&digest_0[..chunk_0.len()]);
    });

    // Using a counter and chaining to previous chunks, fill the rest of the buffer.
    let mut prev_digest: Option<Output<D>> = None;
    for (i, output_chunk_i) in output_chunks {
        // XOR the message digest with the previous digest, except on the first iteration.
        // NOTE: RFC9380 includes this to bolster defense against nonideal hash behavior.
        let mut mixed_digest = digest_0.clone();
        if let Some(prev_digest) = prev_digest {
            // NOTE: This assert can be checked at compile time.
            // TODO: Is there any way to turn this into a compile-time assert, given that the size
            // of the arrays is determined by a generic parameter.
            assert_eq!(mixed_digest.len(), prev_digest.len());
            for (a, b) in core::iter::zip(mixed_digest.iter_mut(), prev_digest.iter()) {
                *a ^= b;
            }
        }

        let chunk_i = D::new()
            // Add the fixed-length message digest.
            .chain_update(&mixed_digest)
            // Add the index, starting from one.
            .chain_update(u8::try_from(i).unwrap().to_be_bytes())
            // Ass the domain separator and length.
            .chain_update(domain_separator)
            .chain_update(u8::try_from(domain_separator.len()).unwrap().to_be_bytes())
            .finalize();

        // Copy the digest into the output chunk.
        // NOTE: This will copy the entire digest except on the last iteration.
        output_chunk_i.copy_from_slice(&chunk_i[..output_chunk_i.len()]);

        prev_digest = Some(chunk_i);
    }

    output
}

pub trait FromDigest<D: Digest + BlockSizeUser>: FromUniformBytes {
    // TODO: Provide an example of using this with XofFixedWrapper
    fn from_digest(digest: D) -> Self {
        Self::from_uniform_bytes(digest.finalize().as_ref())
    }

    fn from_hash(input: impl AsRef<[u8]>) -> Self {
        Self::from_digest(D::new().chain_update(input))
    }
}

pub trait FromXof: FromUniformBytes {
    fn from_xof<X: XofReader>(xof: &mut X) -> Self {
        let mut bytes = Self::Bytes::zeroed();
        xof.read(bytes.as_mut());
        Self::from_uniform_bytes(&bytes)
    }

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

    use super::{FromDigest, FromUniformBytes, FromXof};

    impl FromUniformBytes for RistrettoPoint {
        type Bytes = [u8; 64];

        fn from_uniform_bytes(bytes: &Self::Bytes) -> Self {
            Self::from_uniform_bytes(bytes)
        }
    }

    impl FromDigest for RistrettoPoint {}
    impl FromXof for RistrettoPoint {}
}

#[cfg(feature = "k256")]
mod k256 {
    use elliptic_curve::hash2curve::{FromOkm, MapToCurve};
    use k256::{FieldElement, ProjectivePoint};

    use super::{FromDigest, FromUniformBytes, FromXof};

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

    impl FromDigest for ProjectivePoint {}
    impl FromXof for ProjectivePoint {}
}

#[cfg(feature = "p256")]
mod p256 {
    use elliptic_curve::hash2curve::{FromOkm, MapToCurve};
    use p256::{FieldElement, ProjectivePoint};

    use super::{FromDigest, FromUniformBytes, FromXof};

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

    impl FromDigest for ProjectivePoint {}
    impl FromXof for ProjectivePoint {}
}

#[cfg(test)]
mod tests {

    #[allow(unused)]
    use digest::consts::{U64, U96};

    use crate::group::{FromDigest, FromXof};

    #[test]
    fn usage_sha2() {
        use curve25519_dalek::RistrettoPoint;
        #[allow(unused)]
        use sha2::{Digest as _, Sha256, Sha512};

        // NOTE: RistrettoPoint has directly implemented methods called from_hash and from_digest.
        let _: RistrettoPoint = FromDigest::from_hash::<Sha512>(b"hello");
        let _: RistrettoPoint = FromDigest::from_digest(Sha512::new().chain_update(b"hello"));
    }

    #[test]
    fn usage_sha3() {
        use curve25519_dalek::RistrettoPoint;
        use digest::{Digest as _, ExtendableOutput as _, Update as _, XofFixedWrapper};
        use sha3::Shake128;

        let _ = RistrettoPoint::from_hash_xof::<Shake128>(b"hello");
        let _ = RistrettoPoint::from_xof(&mut Shake128::default().chain(b"hello").finalize_xof());

        // NOTE: RistrettoPoint has directly implemented methods called from_hash and from_digest.
        let _: RistrettoPoint = FromDigest::from_hash::<XofFixedWrapper<Shake128, U64>>(b"hello");
        let _: RistrettoPoint =
            FromDigest::from_digest(XofFixedWrapper::<Shake128, U64>::new().chain_update(b"hello"));

        let _ = p256::ProjectivePoint::from_hash::<XofFixedWrapper<Shake128, U96>>(b"hello");
        let _ = p256::ProjectivePoint::from_digest(
            XofFixedWrapper::<Shake128, U96>::new().chain_update(b"hello"),
        );
    }
}
