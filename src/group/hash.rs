use core::marker::PhantomData;

use digest::{
    array::Array, common::BlockSizeUser, typenum::Unsigned, CollisionResistance, Digest,
    ExtendableOutput, Output, Update, XofReader,
};

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

/// Adapter that routes a fixed-output digest to [`ExpandMessage`] via `expand_message_xmd`.
///
/// The inner digest always has the RFC 9380 zero-block prefix absorbed: construct via
/// [`Default`] or [`extract`](Self::extract), then feed additional input through
/// [`digest::Update`].
#[derive(Clone)]
pub struct ExpandMsgXmd<D: Digest + BlockSizeUser> {
    inner: D,
}

impl<D: Digest + BlockSizeUser> Default for ExpandMsgXmd<D> {
    fn default() -> Self {
        Self {
            inner: D::new().chain_update(zero_pad::<D>()),
        }
    }
}

impl<D: Digest + BlockSizeUser> ExpandMsgXmd<D> {
    /// Start an [`ExpandMsgXmd`] with `input` absorbed after the zero-block prefix.
    pub fn extract(input: &[u8]) -> Self {
        let mut this = Self::default();
        Update::update(&mut this, input);
        this
    }
}

impl<D: Digest + BlockSizeUser> Update for ExpandMsgXmd<D> {
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }
}

impl<D: Digest + BlockSizeUser> ExpandMessage for ExpandMsgXmd<D> {
    fn expand_message<const N: usize>(domain_separator: &[u8], message: &[u8]) -> [u8; N] {
        Self::extract(message).expand_message_digest(domain_separator)
    }

    fn expand_message_digest<const N: usize>(self, domain_separator: &[u8]) -> [u8; N] {
        crate::group::hash::expand_message_digest_xmd::<D, N>(domain_separator, self.inner)
    }
}

impl<X> ExpandMessage for X
where
    X: ExtendableOutput + Default + CollisionResistance,
{
    fn expand_message<const N: usize>(domain_separator: &[u8], message: &[u8]) -> [u8; N] {
        crate::group::hash::expand_message_xof::<X, N>(domain_separator, message)
    }

    fn expand_message_digest<const N: usize>(self, domain_separator: &[u8]) -> [u8; N] {
        crate::group::hash::expand_message_digest_xof::<X, N>(domain_separator, self)
    }
}

/// Returns a block of zeroes for use as padding per RFC 9380 Section 5.3.1.
fn zero_pad<D: BlockSizeUser>() -> Array<u8, D::BlockSize> {
    Array::default()
}

/// `CheckExpandMsgXmdParams` implements compile-time checks to ensure the given generic parameters
/// will result in an infallible call to [expand_message_xmd].
struct CheckExpandMsgXmdParams<D: Digest, const N: usize>(PhantomData<D>);

impl<const N: usize, D: Digest> CheckExpandMsgXmdParams<D, N> {
    /// Access to this associated constant will cause a compilation error if the given generic
    /// parameters are invalid. This enables compile time assertion over the generic parameters.
    const VALID: () = {
        assert!(
            N <= u16::MAX as usize,
            "expand_message_xmd requires the output length to be at most 65535 bytes"
        );
        assert!(
            N.div_ceil(<D::OutputSize as Unsigned>::USIZE) <= u8::MAX as usize,
            "expand_message_xmd requires the output length to be at most 255 times the digest length"
        );
        // NOTE: This ensures that domain separators of all lengths can be used, applying
        // compression as needed.
        assert!(
            <D::OutputSize as Unsigned>::USIZE < u8::MAX as usize,
            "expand_message_xm requires the digest output size to be at most 255 bytes",
        )
    };
}

/// Expands `message` into a pseudorandom `[u8; N]` under `domain_separator`.
///
/// This is `expand_message_xmd` from [RFC 9380 Section 5.3.1][rfc9380-5.3.1].
///
/// The generic parameters must satisfy the following bounds, rejected at compile time:
/// - `N <= u16::MAX`,
/// - `ceil(N / D::OutputSize) <= 255`,
/// - `D::OutputSize < 255`.
///
/// [rfc9380-5.3.1]: https://www.rfc-editor.org/rfc/rfc9380#section-5.3.1
pub fn expand_message_xmd<D: Digest + BlockSizeUser, const N: usize>(
    domain_separator: &[u8],
    message: &[u8],
) -> [u8; N] {
    ExpandMsgXmd::<D>::extract(message).expand_message_digest(domain_separator)
}

/// Expands a digest state (with message already absorbed) into a pseudorandom `[u8; N]`
/// under `domain_separator`.
///
/// When the caller prefixed the message with a block of zeroes, this is `expand_message_xmd`
/// from [RFC 9380 Section 5.3.1][rfc9380-5.3.1].
///
/// Generic parameter bounds are the same as [`expand_message_xmd`] and are rejected at
/// compile time.
///
/// [rfc9380-5.3.1]: https://www.rfc-editor.org/rfc/rfc9380#section-5.3.1
pub fn expand_message_digest_xmd<D: Digest, const N: usize>(
    domain_separator: &[u8],
    message_digest: D,
) -> [u8; N] {
    // Ensure the generic parameters are valid. This is a compile time check.
    #[allow(path_statements)]
    CheckExpandMsgXmdParams::<D, N>::VALID;

    // If the domain_separator is longer than 255 bytes, compress it per RFC9380 Section 5.3.3.
    let compressed_dst;
    let dst = if domain_separator.len() <= u8::MAX as usize {
        domain_separator
    } else {
        compressed_dst = D::new()
            .chain_update(b"H2C-OVERSIZE-DST-")
            .chain_update(domain_separator)
            .finalize();
        &compressed_dst
    };

    let digest_0 = message_digest
        // Add the requested output length.
        .chain_update(u16::try_from(N).unwrap().to_be_bytes())
        // Add a zero index to mark this as the 0-index digest.
        .chain_update([0u8])
        // Add the domain separator and length.
        .chain_update(dst)
        .chain_update(u8::try_from(dst.len()).unwrap().to_be_bytes())
        .finalize();

    // Expand the message to fill the output array with b_1 || ... || b_ell.
    let mut output = [0u8; N];
    let output_chunks = output.chunks_mut(<D::OutputSize as Unsigned>::USIZE);

    // Using a counter and chaining to previous digests, fill the output buffer.
    let mut prev_digest: Option<Output<D>> = None;
    for (i, output_chunk_i) in output_chunks.enumerate() {
        // XOR the message digest with the previous digest, except on the first iteration.
        // NOTE: RFC9380 includes this to bolster defense against nonideal hash behavior.
        let mut mixed_digest = digest_0.clone();
        if let Some(prev_digest) = &prev_digest {
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
            .chain_update(dst)
            .chain_update(u8::try_from(dst.len()).unwrap().to_be_bytes())
            .finalize();

        // Copy the digest into the output chunk.
        // NOTE: This will copy the entire digest except on the last iteration.
        output_chunk_i.copy_from_slice(&b_i[..output_chunk_i.len()]);

        prev_digest = Some(b_i);
    }

    output
}

/// `CheckExpandMsgXofParams` implements compile-time checks to ensure the given generic parameters
/// will result in an infallible call to [expand_message_xof].
struct CheckExpandMsgXofParams<X: CollisionResistance, const N: usize>(PhantomData<X>);

impl<X: CollisionResistance, const N: usize> CheckExpandMsgXofParams<X, N> {
    /// Access to this associated constant will cause a compilation error if the given generic
    /// parameters are invalid. This enables compile time assertion over the generic parameters.
    const VALID: () = {
        assert!(
            N <= u16::MAX as usize,
            "expand_message_xof requires the output length to be at most 65535 bytes"
        );
        // NOTE: This ensures that the compressed DST length (max(2k/8, 32), per RFC9380
        // Section 5.3.3) fits into the one-byte I2OSP length field in DST_prime.
        let cr_bytes = <X::CollisionResistance as Unsigned>::USIZE;
        let compressed_dst_len = if 2 * cr_bytes > 32 { 2 * cr_bytes } else { 32 };
        assert!(
            compressed_dst_len < u8::MAX as usize,
            "expand_message_xof requires the compressed DST length (max(2k/8, 32) bytes) to be at most 255 bytes",
        );
    };
}

/// Expands `message` into a pseudorandom `[u8; N]` under `domain_separator`.
///
/// This is `expand_message_xof` from [RFC 9380 Section 5.3.2][rfc9380-5.3.2].
///
/// The generic parameters must satisfy the following bounds, rejected at compile time:
/// - `N <= u16::MAX`,
/// - `max(2 * X::CollisionResistance, 32) < 255`.
///
/// [rfc9380-5.3.2]: https://www.rfc-editor.org/rfc/rfc9380#section-5.3.2
pub fn expand_message_xof<X, const N: usize>(domain_separator: &[u8], message: &[u8]) -> [u8; N]
where
    X: ExtendableOutput + Default + CollisionResistance,
{
    let mut xof = X::default();
    xof.update(message);
    expand_message_digest_xof::<X, N>(domain_separator, xof)
}

/// Expands an XOF state (with message already absorbed) into a pseudorandom `[u8; N]`
/// under `domain_separator`.
///
/// This is `expand_message_xof` from [RFC 9380 Section 5.3.2][rfc9380-5.3.2].
///
/// Generic parameter bounds are the same as [`expand_message_xof`] and are rejected at
/// compile time.
///
/// [rfc9380-5.3.2]: https://www.rfc-editor.org/rfc/rfc9380#section-5.3.2
pub fn expand_message_digest_xof<X, const N: usize>(domain_separator: &[u8], mut xof: X) -> [u8; N]
where
    X: ExtendableOutput + Default + CollisionResistance,
{
    #[allow(path_statements)]
    CheckExpandMsgXofParams::<X, N>::VALID;

    // If the domain separator is longer than 255 bytes, compress it per RFC9380 Section 5.3.3.
    // The compressed length is max(2k/8, 32) bytes, where k is the XOF's collision resistance
    // in bits.
    let mut compressed_dst;
    let dst = if domain_separator.len() <= u8::MAX as usize {
        domain_separator
    } else {
        let mut hasher = X::default();
        hasher.update(b"H2C-OVERSIZE-DST-");
        hasher.update(domain_separator);

        // Compute the collision resistance value k to determine the compressed length.
        let cr_bytes = <X::CollisionResistance as Unsigned>::USIZE;
        let compressed_dst_len = 2 * cr_bytes;

        // NOTE: Use the max length such that this works for any collision resistance.
        compressed_dst = [0u8; 255];
        let compressed_dst_ref = &mut compressed_dst[..compressed_dst_len];
        hasher.finalize_xof_into(compressed_dst_ref);
        compressed_dst_ref
    };

    // Finish the msg_prime construction by absorbing I2OSP(N, 2) || DST || I2OSP(len(DST), 1).
    xof.update(&u16::try_from(N).unwrap().to_be_bytes());
    xof.update(dst);
    xof.update(&[u8::try_from(dst.len()).unwrap()]);

    let mut output = [0u8; N];
    xof.finalize_xof().read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use crate::group::hash::zero_pad;

    #[test]
    fn zero_pad_is_all_zero() {
        let zeroes = zero_pad::<Sha256>();
        assert!(zeroes.iter().all(|b| *b == 0));
    }

    mod expand_message_xmd_sha256 {
        use hex_literal::hex;
        use sha2::Sha256;

        use crate::group::hash::expand_message_xmd;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";

        // RFC9380 Appendix K.1 test vectors for expand_message_xmd(SHA-256)

        #[test]
        fn empty_msg_32b() {
            let result = expand_message_xmd::<Sha256, 32>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
            );
        }

        #[test]
        fn abc_32b() {
            let result = expand_message_xmd::<Sha256, 32>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615")
            );
        }

        #[test]
        fn abcdef0123456789_32b() {
            let result = expand_message_xmd::<Sha256, 32>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!("eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1")
            );
        }

        #[test]
        fn q128_32b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xmd::<Sha256, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9")
            );
        }

        #[test]
        fn empty_msg_128b() {
            let result = expand_message_xmd::<Sha256, 128>(DST, b"");
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
            let result = expand_message_xmd::<Sha256, 128>(DST, b"abc");
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
            let result = expand_message_xmd::<Sha256, 128>(DST, b"abcdef0123456789");
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

    // RFC9380 Appendix K.2: expand_message_xmd(SHA-256) with long DST (>255 bytes)
    mod expand_message_xmd_sha256_long_dst {
        use hex_literal::hex;
        use sha2::Sha256;

        use crate::group::hash::expand_message_xmd;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

        #[test]
        fn empty_msg_32b() {
            let result = expand_message_xmd::<Sha256, 32>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!("e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3")
            );
        }

        #[test]
        fn abc_32b() {
            let result = expand_message_xmd::<Sha256, 32>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!("52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12")
            );
        }

        #[test]
        fn abcdef0123456789_32b() {
            let result = expand_message_xmd::<Sha256, 32>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!("35387dcf22618f3728e6c686490f8b431f76550b0b2c61cbc1ce7001536f4521")
            );
        }

        #[test]
        fn q128_32b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xmd::<Sha256, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("01b637612bb18e840028be900a833a74414140dde0c4754c198532c3a0ba42bc")
            );
        }

        #[test]
        fn a512_32b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xmd::<Sha256, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("20cce7033cabc5460743180be6fa8aac5a103f56d481cf369a8accc0c374431b")
            );
        }

        #[test]
        fn empty_msg_128b() {
            let result = expand_message_xmd::<Sha256, 128>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "14604d85432c68b757e485c8894db3117992fc57e0e136f71ad987f789a0abc2"
                    "87c47876978e2388a02af86b1e8d1342e5ce4f7aaa07a87321e691f6fba7e007"
                    "2eecc1218aebb89fb14a0662322d5edbd873f0eb35260145cd4e64f748c5dfe6"
                    "0567e126604bcab1a3ee2dc0778102ae8a5cfd1429ebc0fa6bf1a53c36f55dfc"
                ),
            );
        }

        #[test]
        fn abc_128b() {
            let result = expand_message_xmd::<Sha256, 128>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d0471d55b66684914"
                    "aef87dbb3626eaabf5ded8cd0686567e503853e5c84c259ba0efc37f71c839da"
                    "2129fe81afdaec7fbdc0ccd4c794727a17c0d20ff0ea55e1389d6982d1241cb8"
                    "d165762dbc39fb0cee4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267"
                ),
            );
        }

        #[test]
        fn abcdef0123456789_128b() {
            let result = expand_message_xmd::<Sha256, 128>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "d2ecef3635d2397f34a9f86438d772db19ffe9924e28a1caf6f1c8f15603d402"
                    "8f40891044e5c7e39ebb9b31339979ff33a4249206f67d4a1e7c765410bcd249"
                    "ad78d407e303675918f20f26ce6d7027ed3774512ef5b00d816e51bfcc96c353"
                    "9601fa48ef1c07e494bdc37054ba96ecb9dbd666417e3de289d4f424f502a982"
                ),
            );
        }

        #[test]
        fn q128_128b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xmd::<Sha256, 128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "ed6e8c036df90111410431431a232d41a32c86e296c05d426e5f44e75b9a50d3"
                    "35b2412bc6c91e0a6dc131de09c43110d9180d0a70f0d6289cb4e43b05f7ee5e"
                    "9b3f42a1fad0f31bac6a625b3b5c50e3a83316783b649e5ecc9d3b1d9471cb50"
                    "24b7ccf40d41d1751a04ca0356548bc6e703fca02ab521b505e8e45600508d32"
                ),
            );
        }

        #[test]
        fn a512_128b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xmd::<Sha256, 128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "78b53f2413f3c688f07732c10e5ced29a17c6a16f717179ffbe38d92d6c9ec29"
                    "6502eb9889af83a1928cd162e845b0d3c5424e83280fed3d10cffb2f8431f14e"
                    "7a23f4c68819d40617589e4c41169d0b56e0e3535be1fd71fbb08bb70c5b5ffe"
                    "d953d6c14bf7618b35fc1f4c4b30538236b4b08c9fbf90462447a8ada60be495"
                ),
            );
        }
    }

    // RFC9380 Appendix K.1 continued: remaining test vectors
    mod expand_message_xmd_sha256_continued {
        use hex_literal::hex;
        use sha2::Sha256;

        use crate::group::hash::expand_message_xmd;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";

        #[test]
        fn a512_32b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xmd::<Sha256, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c")
            );
        }

        #[test]
        fn q128_128b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xmd::<Sha256, 128>(DST, msg);
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
            let result = expand_message_xmd::<Sha256, 128>(DST, msg);
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
        use hex_literal::hex;
        use sha2::Sha512;

        use crate::group::hash::expand_message_xmd;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA512-256";

        #[test]
        fn empty_msg_32b() {
            let result = expand_message_xmd::<Sha512, 32>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!("6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba")
            );
        }

        #[test]
        fn abc_32b() {
            let result = expand_message_xmd::<Sha512, 32>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!("0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc")
            );
        }

        #[test]
        fn abcdef0123456789_32b() {
            let result = expand_message_xmd::<Sha512, 32>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!("087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58")
            );
        }

        #[test]
        fn q128_32b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xmd::<Sha512, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3")
            );
        }

        #[test]
        fn a512_32b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xmd::<Sha512, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4")
            );
        }

        #[test]
        fn empty_msg_128b() {
            let result = expand_message_xmd::<Sha512, 128>(DST, b"");
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
            let result = expand_message_xmd::<Sha512, 128>(DST, b"abc");
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
            let result = expand_message_xmd::<Sha512, 128>(DST, b"abcdef0123456789");
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
            let result = expand_message_xmd::<Sha512, 128>(DST, msg);
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
            let result = expand_message_xmd::<Sha512, 128>(DST, msg);
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

    // RFC9380 Appendix K.4 test vectors for expand_message_xof(SHAKE128)
    mod expand_message_xof_shake128 {
        use hex_literal::hex;
        use sha3::Shake128;

        use crate::group::hash::expand_message_xof;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHAKE128";

        #[test]
        fn empty_msg_32b() {
            let result = expand_message_xof::<Shake128, 32>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!("86518c9cd86581486e9485aa74ab35ba150d1c75c88e26b7043e44e2acd735a2")
            );
        }

        #[test]
        fn abc_32b() {
            let result = expand_message_xof::<Shake128, 32>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!("8696af52a4d862417c0763556073f47bc9b9ba43c99b505305cb1ec04a9ab468")
            );
        }

        #[test]
        fn abcdef0123456789_32b() {
            let result = expand_message_xof::<Shake128, 32>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!("912c58deac4821c3509dbefa094df54b34b8f5d01a191d1d3108a2c89077acca")
            );
        }

        #[test]
        fn q128_32b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xof::<Shake128, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("1adbcc448aef2a0cebc71dac9f756b22e51839d348e031e63b33ebb50faeaf3f")
            );
        }

        #[test]
        fn a512_32b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xof::<Shake128, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("df3447cc5f3e9a77da10f819218ddf31342c310778e0e4ef72bbaecee786a4fe")
            );
        }

        #[test]
        fn empty_msg_128b() {
            let result = expand_message_xof::<Shake128, 128>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "7314ff1a155a2fb99a0171dc71b89ab6e3b2b7d59e38e64419b8b6294d03ffee"
                    "42491f11370261f436220ef787f8f76f5b26bdcd850071920ce023f3ac468477"
                    "44f4612b8714db8f5db83205b2e625d95afd7d7b4d3094d3bdde815f52850bb4"
                    "1ead9822e08f22cf41d615a303b0d9dde73263c049a7b9898208003a739a2e57"
                ),
            );
        }

        #[test]
        fn abc_128b() {
            let result = expand_message_xof::<Shake128, 128>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "c952f0c8e529ca8824acc6a4cab0e782fc3648c563ddb00da7399f2ae35654f4"
                    "860ec671db2356ba7baa55a34a9d7f79197b60ddae6e64768a37d699a7832349"
                    "6db3878c8d64d909d0f8a7de4927dcab0d3dbbc26cb20a49eceb0530b431cdf4"
                    "7bc8c0fa3e0d88f53b318b6739fbed7d7634974f1b5c386d6230c76260d5337a"
                ),
            );
        }

        #[test]
        fn abcdef0123456789_128b() {
            let result = expand_message_xof::<Shake128, 128>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "19b65ee7afec6ac06a144f2d6134f08eeec185f1a890fe34e68f0e377b7d0312"
                    "883c048d9b8a1d6ecc3b541cb4987c26f45e0c82691ea299b5e6889bbfe58915"
                    "3016d8131717ba26f07c3c14ffbef1f3eff9752e5b6183f43871a78219a75e70"
                    "00fbac6a7072e2b83c790a3a5aecd9d14be79f9fd4fb180960a3772e08680495"
                ),
            );
        }

        #[test]
        fn q128_128b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xof::<Shake128, 128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "ca1b56861482b16eae0f4a26212112362fcc2d76dcc80c93c4182ed66c5113fe"
                    "41733ed68be2942a3487394317f3379856f4822a611735e50528a60e7ade8ec8"
                    "c71670fec6661e2c59a09ed36386513221688b35dc47e3c3111ee8c67ff49579"
                    "089d661caa29db1ef10eb6eace575bf3dc9806e7c4016bd50f3c0e2a6481ee6d"
                ),
            );
        }

        #[test]
        fn a512_128b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xof::<Shake128, 128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "9d763a5ce58f65c91531b4100c7266d479a5d9777ba761693d052acd37d149e7"
                    "ac91c796a10b919cd74a591a1e38719fb91b7203e2af31eac3bff7ead2c195af"
                    "7d88b8bc0a8adf3d1e90ab9bed6ddc2b7f655dd86c730bdeaea884e737410971"
                    "42c92f0e3fc1811b699ba593c7fbd81da288a29d423df831652e3a01a9374999"
                ),
            );
        }
    }

    // RFC9380 Appendix K.5 test vectors for expand_message_xof(SHAKE128) with long DST
    mod expand_message_xof_shake128_long_dst {
        use hex_literal::hex;
        use sha3::Shake128;

        use crate::group::hash::expand_message_xof;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHAKE128-long-DST-111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

        #[test]
        fn empty_msg_32b() {
            let result = expand_message_xof::<Shake128, 32>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!("827c6216330a122352312bccc0c8d6e7a146c5257a776dbd9ad9d75cd880fc53")
            );
        }

        #[test]
        fn abc_32b() {
            let result = expand_message_xof::<Shake128, 32>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!("690c8d82c7213b4282c6cb41c00e31ea1d3e2005f93ad19bbf6da40f15790c5c")
            );
        }

        #[test]
        fn abcdef0123456789_32b() {
            let result = expand_message_xof::<Shake128, 32>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!("979e3a15064afbbcf99f62cc09fa9c85028afcf3f825eb0711894dcfc2f57057")
            );
        }

        #[test]
        fn q128_32b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xof::<Shake128, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("c5a9220962d9edc212c063f4f65b609755a1ed96e62f9db5d1fd6adb5a8dc52b")
            );
        }

        #[test]
        fn a512_32b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xof::<Shake128, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("f7b96a5901af5d78ce1d071d9c383cac66a1dfadb508300ec6aeaea0d62d5d62")
            );
        }

        #[test]
        fn empty_msg_128b() {
            let result = expand_message_xof::<Shake128, 128>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "3890dbab00a2830be398524b71c2713bbef5f4884ac2e6f070b092effdb19208"
                    "c7df943dc5dcbaee3094a78c267ef276632ee2c8ea0c05363c94b6348500fae4"
                    "208345dd3475fe0c834c2beac7fa7bc181692fb728c0a53d809fc8111495222c"
                    "e0f38468b11becb15b32060218e285c57a60162c2c8bb5b6bded13973cd41819"
                ),
            );
        }

        #[test]
        fn abc_128b() {
            let result = expand_message_xof::<Shake128, 128>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "41b7ffa7a301b5c1441495ebb9774e2a53dbbf4e54b9a1af6a20fd41eafd69ef"
                    "7b9418599c5545b1ee422f363642b01d4a53449313f68da3e49dddb9cd25b974"
                    "65170537d45dcbdf92391b5bdff344db4bd06311a05bca7dcd360b6caec849c2"
                    "99133e5c9194f4e15e3e23cfaab4003fab776f6ac0bfae9144c6e2e1c62e7d57"
                ),
            );
        }

        #[test]
        fn abcdef0123456789_128b() {
            let result = expand_message_xof::<Shake128, 128>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "55317e4a21318472cd2290c3082957e1242241d9e0d04f47026f034016431314"
                    "01071f01aa03038b2783e795bdfa8a3541c194ad5de7cb9c225133e24af6c86e"
                    "748deb52e560569bd54ef4dac03465111a3a44b0ea490fb36777ff8ea9f1a8a3"
                    "e8e0de3cf0880b4b2f8dd37d3a85a8b82375aee4fa0e909f9763319b55778e71"
                ),
            );
        }

        #[test]
        fn q128_128b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xof::<Shake128, 128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "19fdd2639f082e31c77717ac9bb032a22ff0958382b2dbb39020cdc78f0da433"
                    "05414806abf9a561cb2d0067eb2f7bc544482f75623438ed4b4e39dd9e6e2909"
                    "dd858bd8f1d57cd0fce2d3150d90aa67b4498bdf2df98c0100dd1a173436ba5d"
                    "0df6be1defb0b2ce55ccd2f4fc05eb7cb2c019c35d5398b85adc676da4238bc7"
                ),
            );
        }

        #[test]
        fn a512_128b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xof::<Shake128, 128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "945373f0b3431a103333ba6a0a34f1efab2702efde41754c4cb1d5216d5b0a92"
                    "a67458d968562bde7fa6310a83f53dda1383680a276a283438d58ceebfa7ab7b"
                    "a72499d4a3eddc860595f63c93b1c5e823ea41fc490d938398a26db28f618576"
                    "98553e93f0574eb8c5017bfed6249491f9976aaa8d23d9485339cc85ca329308"
                ),
            );
        }
    }

    // RFC9380 Appendix K.6 test vectors for expand_message_xof(SHAKE256)
    mod expand_message_xof_shake256 {
        use hex_literal::hex;
        use sha3::Shake256;

        use crate::group::hash::expand_message_xof;

        const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHAKE256";

        #[test]
        fn empty_msg_32b() {
            let result = expand_message_xof::<Shake256, 32>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!("2ffc05c48ed32b95d72e807f6eab9f7530dd1c2f013914c8fed38c5ccc15ad76")
            );
        }

        #[test]
        fn abc_32b() {
            let result = expand_message_xof::<Shake256, 32>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!("b39e493867e2767216792abce1f2676c197c0692aed061560ead251821808e07")
            );
        }

        #[test]
        fn abcdef0123456789_32b() {
            let result = expand_message_xof::<Shake256, 32>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!("245389cf44a13f0e70af8665fe5337ec2dcd138890bb7901c4ad9cfceb054b65")
            );
        }

        #[test]
        fn q128_32b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xof::<Shake256, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("719b3911821e6428a5ed9b8e600f2866bcf23c8f0515e52d6c6c019a03f16f0e")
            );
        }

        #[test]
        fn a512_32b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xof::<Shake256, 32>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!("9181ead5220b1963f1b5951f35547a5ea86a820562287d6ca4723633d17ccbbc")
            );
        }

        #[test]
        fn empty_msg_128b() {
            let result = expand_message_xof::<Shake256, 128>(DST, b"");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "7a1361d2d7d82d79e035b8880c5a3c86c5afa719478c007d96e6c88737a3f631"
                    "dd74a2c88df79a4cb5e5d9f7504957c70d669ec6bfedc31e01e2bacc4ff3fdf9"
                    "b6a00b17cc18d9d72ace7d6b81c2e481b4f73f34f9a7505dccbe8f5485f3d20c"
                    "5409b0310093d5d6492dea4e18aa6979c23c8ea5de01582e9689612afbb353df"
                ),
            );
        }

        #[test]
        fn abc_128b() {
            let result = expand_message_xof::<Shake256, 128>(DST, b"abc");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "a54303e6b172909783353ab05ef08dd435a558c3197db0c132134649708e0b9b"
                    "4e34fb99b92a9e9e28fc1f1d8860d85897a8e021e6382f3eea10577f968ff6df"
                    "6c45fe624ce65ca25932f679a42a404bc3681efe03fcd45ef73bb3a8f79ba784"
                    "f80f55ea8a3c367408f30381299617f50c8cf8fbb21d0f1e1d70b0131a7b6fbe"
                ),
            );
        }

        #[test]
        fn abcdef0123456789_128b() {
            let result = expand_message_xof::<Shake256, 128>(DST, b"abcdef0123456789");
            assert_eq!(
                result.as_slice(),
                hex!(
                    "e42e4d9538a189316e3154b821c1bafb390f78b2f010ea404e6ac063deb8c085"
                    "2fcd412e098e231e43427bd2be1330bb47b4039ad57b30ae1fc94e34993b162f"
                    "f4d695e42d59d9777ea18d3848d9d336c25d2acb93adcad009bcfb9cde12286d"
                    "f267ada283063de0bb1505565b2eb6c90e31c48798ecdc71a71756a9110ff373"
                ),
            );
        }

        #[test]
        fn q128_128b() {
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let result = expand_message_xof::<Shake256, 128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "4ac054dda0a38a65d0ecf7afd3c2812300027c8789655e47aecf1ecc1a2426b1"
                    "7444c7482c99e5907afd9c25b991990490bb9c686f43e79b4471a23a703d4b02"
                    "f23c669737a886a7ec28bddb92c3a98de63ebf878aa363a501a60055c048bea1"
                    "1840c4717beae7eee28c3cfa42857b3d130188571943a7bd747de831bd6444e0"
                ),
            );
        }

        #[test]
        fn a512_128b() {
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let result = expand_message_xof::<Shake256, 128>(DST, msg);
            assert_eq!(
                result.as_slice(),
                hex!(
                    "09afc76d51c2cccbc129c2315df66c2be7295a231203b8ab2dd7f95c2772c68e"
                    "500bc72e20c602abc9964663b7a03a389be128c56971ce81001a0b875e7fd178"
                    "22db9d69792ddf6a23a151bf470079c518279aef3e75611f8f828994a9988f4a"
                    "8a256ddb8bae161e658d5a2a09bcfe839c6396dc06ee5c8ff3c22d3b1f9deb7e"
                ),
            );
        }
    }
}
