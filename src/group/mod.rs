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

// NOTE: This implementation is similar to expand_message_xmd, with modifications to make it
// infallible for any sized domain separator and output length.
/// Generates a uniformly random byte array of length `N` from a domain separator and message.
///
/// This function satisfies the requirements of RFC9380 section 5.3.4, but does not implement any
/// standardized routine. It should not be used where standards compliance is required.
fn expand_message<D: Digest + BlockSizeUser, N: ArraySize>(
    domain_separator: &[u8],
    message: &[u8],
) -> Array<u8, N> {
    // Encode usize lengths as big-endian u64 values.
    // This is infallible under the assumption that a slice cannot exceed u64::MAX in length.
    fn encode_len(buffer: &[u8]) -> [u8; 8] {
        u64::try_from(buffer.len()).unwrap().to_be_bytes()
    }

    // Compress the message and domain separator into a single output digest.
    let message_digest = D::new()
        // Prefix with a block of zeroes and the block length, as discussed in RFC9380 Section 10.6
        .chain_update(Array::<u8, D::BlockSize>::default())
        // Add in the message.
        // NOTE: The length is not included here.
        .chain_update(message)
        // Add the requested output length.
        .chain_update(N::U64.to_be_bytes())
        // Add a zero index to mark this as the 0-index digest.
        .chain_update(0u64.to_be_bytes())
        // Add the domain separator and length.
        .chain_update(domain_separator)
        .chain_update(encode_len(domain_separator))
        .finalize();

    // Expand the message to fill the output array.
    let mut output = Array::<u8, N>::default();
    for (i, output_chunk) in output
        .chunks_mut(<D::OutputSize as Unsigned>::USIZE)
        .enumerate()
    {
        let chunk_digest = D::new()
            // Add the fixed-length message digest.
            // NOTE: The message digest (b0) is not XORd with the previous chunk. This is included
            // in expand_message_xmd to mitigate potential nonideal behavior of D.
            .chain_update(&message_digest)
            // Add the index, starting from one.
            .chain_update((i as u64 + 1).to_be_bytes())
            // Ass the domain separator and length.
            .chain_update(domain_separator)
            .chain_update(encode_len(domain_separator))
            .finalize();

        // Copy the digest into the output chunk.
        // NOTE: This will copy the entire digest except on the last iteration.
        output_chunk.copy_from_slice(&chunk_digest[..output_chunk.len()]);
    }

    output
}

pub trait FromDigest<D: Digest>: FromUniformBytes {
    // TODO: Provide an example of using this with XofFixedWrapper
    fn from_digest(digest: D) -> Self
    where
        Output<D>: AsRef<Self::Bytes>,
    {
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
