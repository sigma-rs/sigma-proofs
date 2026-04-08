use bytemuck::Zeroable;
use digest::{
    array::{Array, ArraySize, AssocArraySize},
    common::BlockSizeUser,
    typenum::Unsigned,
    Digest, ExtendableOutput, Output, XofReader,
};

// TODO: Once the code is looking good, move these from digest functions into their own module.

/// Implementation of multi-scalar multiplication (MSM) over scalars and points.
pub mod msm;

pub trait FromUniformBytes: Sized {
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Zeroable;

    fn from_uniform_bytes(bytes: &Self::Bytes) -> Self;
}

/// Create a block of zeroes to use as padding as per RFC9380.
///
/// ```rust
/// use sha2::Sha256;
/// use sigma_proofs::group::zero_pad;
///
/// let zeroes = zero_pad::<Sha256>();
/// assert!(zeroes.iter().all(|b| *b == 0));
/// ```
pub fn zero_pad<D: BlockSizeUser>() -> Array<u8, D::BlockSize> {
    Array::default()
}

/// Generates a uniformly random byte array of length `N` from a domain separator and message.
///
/// This is an implementation of expand_message_xmd from RFC9380.
///
/// <!-- TODO: Add panic conditions -->
pub fn expand_message_xmd<D: Digest + BlockSizeUser, N: ArraySize>(
    domain_separator: &[u8],
    message: &[u8],
) -> Array<u8, N> {
    // Compress the message and domain separator into the digest state.
    let message_digest = D::new()
        // Prefix with a block of zeroes and the block length, as discussed in RFC9380 Section 10.6
        .chain_update(zero_pad::<D>())
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
pub fn expand_message_digest_xmd<D: Digest, N: ArraySize>(
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
        N::USIZE.div_ceil(<D::OutputSize as Unsigned>::USIZE) <= u8::MAX as usize,
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

    // Expand the message to fill the output array with b_1 || ... || b_ell.
    let mut output = Array::<u8, N>::default();
    let output_chunks = output.chunks_mut(<D::OutputSize as Unsigned>::USIZE);

    // Using a counter and chaining to previous digests, fill the output buffer.
    let mut prev_digest: Option<Output<D>> = None;
    for (i, output_chunk_i) in output_chunks.enumerate() {
        // XOR the message digest with the previous digest, except on the first iteration.
        // NOTE: RFC9380 includes this to bolster defense against nonideal hash behavior.
        let mut mixed_digest = digest_0.clone();
        if let Some(prev_digest) = &prev_digest {
            // NOTE: This assert can be checked at compile time.
            // TODO: Is there any way to turn this into a compile-time assert, given that the size
            // of the arrays is determined by a generic parameter.
            assert_eq!(mixed_digest.len(), prev_digest.len());
            for (a, b) in core::iter::zip(mixed_digest.iter_mut(), prev_digest.iter()) {
                *a ^= b;
            }
        }

        let b_i = D::new()
            // Add the fixed-length message digest.
            .chain_update(&mixed_digest)
            // Add the index, starting from one.
            .chain_update(u8::try_from(i + 1).unwrap().to_be_bytes())
            // Add the domain separator and length.
            .chain_update(domain_separator)
            .chain_update(u8::try_from(domain_separator.len()).unwrap().to_be_bytes())
            .finalize();

        // Copy the digest into the output chunk.
        // NOTE: This will copy the entire digest except on the last iteration.
        output_chunk_i.copy_from_slice(&b_i[..output_chunk_i.len()]);

        prev_digest = Some(b_i);
    }

    output
}

pub trait FromDigest<D>: FromUniformBytes
where
    D: Digest + BlockSizeUser,
    Self::Bytes: AssocArraySize + From<Array<u8, <Self::Bytes as AssocArraySize>::Size>>,
{
    // TODO: Provide an example of using this with XofFixedWrapper
    fn from_digest(digest: D) -> Self {
        let uniform_bytes = expand_message_digest_xmd(b"".as_slice(), digest).into();
        Self::from_uniform_bytes(&uniform_bytes)
    }

    fn from_hash(input: impl AsRef<[u8]>) -> Self {
        Self::from_digest(D::new().chain_update(zero_pad::<D>()).chain_update(input))
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
    use digest::{
        array::{Array, AssocArraySize},
        common::BlockSizeUser,
        Digest,
    };

    use super::{FromDigest, FromUniformBytes, FromXof};

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
    impl FromXof for RistrettoPoint {}
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

    impl<D> FromDigest<D> for ProjectivePoint
    where
        D: Digest + BlockSizeUser,
        Self::Bytes: AssocArraySize + From<Array<u8, <Self::Bytes as AssocArraySize>::Size>>,
    {
    }
    impl FromXof for ProjectivePoint {}
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

    impl<D> FromDigest<D> for ProjectivePoint
    where
        D: Digest + BlockSizeUser,
        Self::Bytes: AssocArraySize + From<Array<u8, <Self::Bytes as AssocArraySize>::Size>>,
    {
    }
    impl FromXof for ProjectivePoint {}
}

#[cfg(test)]
mod tests {

    #[allow(unused)]
    use digest::consts::{U64, U96};

    use crate::group::{FromDigest, FromXof};

    mod expand_message_xmd_sha256 {
        use digest::consts::{U32, U128};
        use hex_literal::hex;
        use sha2::Sha256;

        use crate::group::expand_message_xmd;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";

        // RFC9380 Appendix K.1 test vectors for expand_message_xmd(SHA-256)

        #[test]
        fn empty_msg_32b() {
            let result = expand_message_xmd::<Sha256, U32>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
            );
        }

        #[test]
        fn abc_32b() {
            let result = expand_message_xmd::<Sha256, U32>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615")
            );
        }

        #[test]
        fn abcdef0123456789_32b() {
            let result = expand_message_xmd::<Sha256, U32>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!("eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1")
            );
        }

        #[test]
        fn q128_32b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xmd::<Sha256, U32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9")
            );
        }

        #[test]
        fn empty_msg_128b() {
            let result = expand_message_xmd::<Sha256, U128>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbe"
                    "e0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18"
                    "eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dc"
                    "c541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"
                ),
            );
        }

        #[test]
        fn abc_128b() {
            let result = expand_message_xmd::<Sha256, U128>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a"
                    "647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635"
                    "bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00"
                    "058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"
                ),
            );
        }

        #[test]
        fn abcdef0123456789_128b() {
            let result = expand_message_xmd::<Sha256, U128>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9"
                    "ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4b"
                    "c95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be1"
                    "4cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df"
                ),
            );
        }
    }

    // RFC9380 Appendix K.1 continued: remaining test vectors
    mod expand_message_xmd_sha256_continued {
        use digest::consts::{U32, U128};
        use hex_literal::hex;
        use sha2::Sha256;

        use crate::group::expand_message_xmd;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";

        #[test]
        fn a512_32b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xmd::<Sha256, U32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c")
            );
        }

        #[test]
        fn q128_128b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xmd::<Sha256, U128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bb"
                    "d88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0"
                    "e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b"
                    "29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a"
                ),
            );
        }

        #[test]
        fn a512_128b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xmd::<Sha256, U128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d0"
                    "6d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608"
                    "ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4"
                    "a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487"
                ),
            );
        }
    }

    // RFC9380 Appendix K.3: expand_message_xmd(SHA-512)
    mod expand_message_xmd_sha512 {
        use digest::consts::{U32, U128};
        use hex_literal::hex;
        use sha2::Sha512;

        use crate::group::expand_message_xmd;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA512-256";

        #[test]
        fn empty_msg_32b() {
            let result = expand_message_xmd::<Sha512, U32>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!("6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba")
            );
        }

        #[test]
        fn abc_32b() {
            let result = expand_message_xmd::<Sha512, U32>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!("0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc")
            );
        }

        #[test]
        fn abcdef0123456789_32b() {
            let result = expand_message_xmd::<Sha512, U32>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!("087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58")
            );
        }

        #[test]
        fn q128_32b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xmd::<Sha512, U32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3")
            );
        }

        #[test]
        fn a512_32b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xmd::<Sha512, U32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4")
            );
        }

        #[test]
        fn empty_msg_128b() {
            let result = expand_message_xmd::<Sha512, U128>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921"
                    "b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e"
                    "0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7e"
                    "b00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961"
                ),
            );
        }

        #[test]
        fn abc_128b() {
            let result = expand_message_xmd::<Sha512, U128>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11"
                    "bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb134"
                    "7ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b48843"
                    "1851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1"
                ),
            );
        }

        #[test]
        fn abcdef0123456789_128b() {
            let result = expand_message_xmd::<Sha512, U128>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "3f721f208e6199fe903545abc26c837ce59ac6fa45733f1baaf0222f8b7acb04"
                    "24814fcb5eecf6c1d38f06e9d0a6ccfbf85ae612ab8735dfdf9ce84c372a77c8"
                    "f9e1c1e952c3a61b7567dd0693016af51d2745822663d0c2367e3f4f0bed827f"
                    "eecc2aaf98c949b5ed0d35c3f1023d64ad1407924288d366ea159f46287e61ac"
                ),
            );
        }

        #[test]
        fn q128_128b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xmd::<Sha512, U128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd12fb603eaee70db7"
                    "317bf807c406e26373922b7b8920fa29142703dd52bdf280084fb7ef69da78af"
                    "df80b3586395b433dc66cde048a258e476a561e9deba7060af40adf30c64249c"
                    "a7ddea79806ee5beb9a1422949471d267b21bc88e688e4014087a0b592b695ed"
                ),
            );
        }

        #[test]
        fn a512_128b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xmd::<Sha512, U128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "05b0bfef265dcee87654372777b7c44177e2ae4c13a27f103340d9cd11c86cb2"
                    "426ffcad5bd964080c2aee97f03be1ca18e30a1f14e27bc11ebbd650f305269c"
                    "c9fb1db08bf90bfc79b42a952b46daf810359e7bc36452684784a64952c343c5"
                    "2e5124cd1f71d474d5197fefc571a92929c9084ffe1112cf5eea5192ebff330b"
                ),
            );
        }
    }

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

        let _ = RistrettoPoint::from_hash_xof::<Shake128>(b"hello");
        let _ = RistrettoPoint::from_xof(&mut Shake128::default().chain(b"hello").finalize_xof());

        // NOTE: RistrettoPoint has directly implemented methods called from_hash and from_digest.
        let _: RistrettoPoint = FromDigest::<XofFixedWrapper<Shake128, U64>>::from_hash(b"hello");
        let _: RistrettoPoint =
            FromDigest::from_digest(XofFixedWrapper::<Shake128, U64>::new().chain_update(b"hello"));

        // TODO: This syntax suffers from an awkwardness with having the generic param on the
        // trait. Figure out the best way to address this.
        //let _ = p256::ProjectivePoint::from_hash(b"hello");
        let _ = p256::ProjectivePoint::from_digest(
            XofFixedWrapper::<Shake128, U96>::new().chain_update(b"hello"),
        );
    }
}
