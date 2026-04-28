//! [`ExpandMessage`] implementations from RFC 9380 over the [`digest`] crate.
//!
//! Provides [`expand_message_xmd`] for fixed-output digests and [`expand_message_xof`]
//! for extendable-output functions, plus the [`ExpandMsgXmd`] adapter that lets a
//! fixed-output digest implement [`ExpandMessage`].

use core::marker::PhantomData;

use digest::{
    array::Array, common::BlockSizeUser, typenum::Unsigned, CollisionResistance, Digest,
    ExtendableOutput, Output, Update, XofReader,
};

use crate::ExpandMessage;

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
        expand_message_digest_xmd::<D, N>(domain_separator, self.inner)
    }
}

impl<X> ExpandMessage for X
where
    X: ExtendableOutput + Default + CollisionResistance,
{
    fn expand_message<const N: usize>(domain_separator: &[u8], message: &[u8]) -> [u8; N] {
        expand_message_xof::<X, N>(domain_separator, message)
    }

    fn expand_message_digest<const N: usize>(self, domain_separator: &[u8]) -> [u8; N] {
        expand_message_digest_xof::<X, N>(domain_separator, self)
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

