use digest::{array::Array, common::BlockSizeUser, typenum::Unsigned, Digest, Output};

// TODO: Try to remove hybrid_array::Array from this function signature?
/// Create a block of zeroes to use as padding as per RFC9380.
///
/// ```rust
/// use sha2::Sha256;
/// use sigma_proofs::group::hash::zero_pad;
///
/// let zeroes = zero_pad::<Sha256>();
/// assert!(zeroes.iter().all(|b| *b == 0));
/// ```
pub fn zero_pad<D: BlockSizeUser>() -> Array<u8, D::BlockSize> {
    Array::default()
}

// TODO: Refactor this to provide a version of this function that takes in an "out" &mut [u8], and
// uses the length of the slice as the output length.

/// Generates a uniformly random byte array of length `N` from a domain separator and message.
///
/// This is an implementation of expand_message_xmd from RFC9380.
///
/// <!-- TODO: Add panic conditions -->
pub fn expand_message_xmd<D: Digest + BlockSizeUser, const N: usize>(
    domain_separator: &[u8],
    message: &[u8],
) -> [u8; N] {
    // Compress the message and domain separator into the digest state.
    let message_digest = D::new()
        // Prefix with a block of zeroes and the block length, as discussed in RFC9380 Section 10.6
        .chain_update(zero_pad::<D>())
        // Add in the message.
        // NOTE: The length is not included here.
        .chain_update(message);

    expand_message_digest_xmd::<D, N>(domain_separator, message_digest)
}

pub fn expand_message_xmd_into<D: Digest + BlockSizeUser>(
    domain_separator: &[u8],
    message: &[u8],
    out: &mut [u8],
) {
    // Compress the message and domain separator into the digest state.
    let message_digest = D::new()
        // Prefix with a block of zeroes and the block length, as discussed in RFC9380 Section 10.6
        .chain_update(zero_pad::<D>())
        // Add in the message.
        // NOTE: The length is not included here.
        .chain_update(message);

    expand_message_digest_xmd_into(domain_separator, message_digest, out)
}

/// Generates a uniformly random byte array of length `N` from a domain separator and digest.
///
/// When the message is padded with a block of zeroes, this is an implementation of
/// expand_message_xmd from RFC9380.
///
/// <!-- TODO: Add panic conditions -->
pub fn expand_message_digest_xmd<D: Digest, const N: usize>(
    domain_separator: &[u8],
    message_digest: D,
) -> [u8; N] {
    let mut out = [0u8; N];
    expand_message_digest_xmd_into(domain_separator, message_digest, &mut out);
    out
}

pub fn expand_message_digest_xmd_into<D: Digest>(
    domain_separator: &[u8],
    message_digest: D,
    out: &mut [u8],
) {
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

    // Check the invariants required by expand_message_xmd to ensure counters will not overflow.
    // NOTE: dst length check under the unlikely condition that the digest output is > 255 bytes.
    // TODO: Update the assert message.
    assert!(
        dst.len() <= u8::MAX as usize,
        "expand_message_xmd requires the domain separator to be at most 255 bytes"
    );
    // NOTE: These two asserts depend only on constants.
    assert!(
        out.len() <= u16::MAX as usize,
        "expand_message_xmd requires the output length to be at most 65535 bytes"
    );
    assert!(
        out.len().div_ceil(<D::OutputSize as Unsigned>::USIZE) <= u8::MAX as usize,
        "expand_message_xmd requires the output length to be at most 255 times the digest length"
    );

    let digest_0 = message_digest
        // Add the requested output length.
        .chain_update((out.len() as u16).to_be_bytes())
        // Add a zero index to mark this as the 0-index digest.
        .chain_update([0u8])
        // Add the domain separator and length.
        .chain_update(dst)
        .chain_update(u8::try_from(dst.len()).unwrap().to_be_bytes())
        .finalize();

    // Expand the message to fill the output array with b_1 || ... || b_ell.
    let output_chunks = out.chunks_mut(<D::OutputSize as Unsigned>::USIZE);

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
            .chain_update(dst)
            .chain_update(u8::try_from(dst.len()).unwrap().to_be_bytes())
            .finalize();

        // Copy the digest into the output chunk.
        // NOTE: This will copy the entire digest except on the last iteration.
        output_chunk_i.copy_from_slice(&b_i[..output_chunk_i.len()]);

        prev_digest = Some(b_i);
    }
}

#[cfg(test)]
mod tests {
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
}
