//! Codecs for Sigma Protocols.
//!
//! These are the `Group.serialize`/`Group.deserialize` and
//! `Scalar.serialize`/`Scalar.deserialize` functions of
//! draft-irtf-cfrg-sigma-protocols, plus the `DecodeField` uniform decoding of
//! draft-irtf-cfrg-fiat-shamir used for challenges and nonce sampling.
//!
//! Internally, codecs rely on [`GroupEncoding`][group::GroupEncoding], including its
//! fixed-length identity encoding, and scalars are encoded big-endian `I2OSP` regardless
//! of the field's native representation. The specification's ciphersuites are
//! `sigma-proofs_Shake128_P256` and `sigma-proofs_Shake128_BLS12381`; other
//! prime-order groups use the same generic codecs under their own
//! ciphersuite identifiers.

// Everything here can run on bytes chosen by an attacker.
// Indexing and slicing are denied outright so that no out-of-range access can be introduced
// without saying why (panic policy: `docs/threat-model.md` §2.1).
#![deny(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use alloc::vec::Vec;

use ff::PrimeField;
use group::prime::PrimeGroup;
use spongefish::{NargReader, VerificationError, VerificationResult};

/// Canonical byte codec for group elements.
///
/// Serialization includes the identity. Deserialization rejects invalid or
/// non-canonical encodings.
pub trait GroupCodec: PrimeGroup {
    /// `Ne`: the byte length of one serialized element.
    fn element_len() -> usize {
        <Self as group::GroupEncoding>::Repr::default()
            .as_ref()
            .len()
    }

    /// Appends the canonical encoding of `self` to `out`.
    fn serialize_element(&self, out: &mut Vec<u8>) -> VerificationResult<()> {
        self.serialize_element_allowing_identity(out);
        Ok(())
    }

    /// Reads one element from the front of `reader`.
    fn deserialize_element(reader: &mut NargReader<'_>) -> VerificationResult<Self> {
        Self::deserialize_element_allowing_identity(reader)
    }

    /// Infallible primitive used by the batched serialization path.
    fn serialize_element_allowing_identity(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.to_bytes().as_ref());
    }

    /// Primitive used by curves that need a ciphersuite-specific decoder.
    fn deserialize_element_allowing_identity(
        reader: &mut NargReader<'_>,
    ) -> VerificationResult<Self> {
        let mut repr = <Self as group::GroupEncoding>::Repr::default();
        let len = repr.as_ref().len();
        repr.as_mut().copy_from_slice(reader.take(len)?);
        Option::<Self>::from(Self::from_bytes(&repr)).ok_or(VerificationError)
    }

    /// Appends the canonical encodings of `elements`, in order.
    ///
    /// Equivalent to [`serialize_element`][GroupCodec::serialize_element] in a
    /// loop, and required to produce identical bytes.
    fn serialize_elements(elements: &[Self], out: &mut Vec<u8>) -> VerificationResult<()> {
        Self::serialize_elements_allowing_identity(elements, out);
        Ok(())
    }

    /// Infallible primitive used by curves with a batched encoding path.
    ///
    /// This is the method a curve overrides, and the one both encoding paths
    /// run through. Curves whose encoding is a projective-to-affine conversion
    /// override it to amortize the field inversion across the whole slice.
    /// That is the only reason it exists: on BLS12-381 G1 one compression is
    /// an inversion (17.1 µs) and the batched form costs one inversion for the
    /// slice, which is an order of magnitude on the instance label. Curves
    /// whose encoding is already cheap keep the default loop.
    fn serialize_elements_allowing_identity(elements: &[Self], out: &mut Vec<u8>) {
        for element in elements {
            element.serialize_element_allowing_identity(out);
        }
    }
}

// Per-curve implementations. `GroupCodec` has no blanket implementation due to different encodings per elliptic curve.

#[cfg(feature = "curve25519-dalek")]
mod curve25519 {
    use super::GroupCodec;
    use curve25519_dalek::RistrettoPoint;

    // Ristretto compression has no batch form: `RistrettoPoint` does not
    // implement `group::Curve`, and curve25519-dalek exposes only
    // `double_and_compress_batch`, which compresses `2P`. It keeps the
    // default loop, which is what it was doing before.
    impl GroupCodec for RistrettoPoint {}
}

#[cfg(feature = "bls12_381")]
mod bls12_381_impl {
    use alloc::vec;
    use alloc::vec::Vec;

    use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};

    use super::GroupCodec;

    /// `to_bytes` on a projective point normalizes it first, which is a field
    /// inversion per point. `batch_normalize` is Montgomery's trick: one
    /// inversion for the whole slice. The encoding is unchanged — these are
    /// the same affine points, encoded by the same function.
    macro_rules! batched {
        ($proj:ty, $affine:ty) => {
            impl GroupCodec for $proj {
                fn serialize_elements_allowing_identity(elements: &[Self], out: &mut Vec<u8>) {
                    let mut affine = vec![<$affine>::identity(); elements.len()];
                    Self::batch_normalize(elements, &mut affine);
                    for point in &affine {
                        out.extend_from_slice(point.to_compressed().as_ref());
                    }
                }
            }
        };
    }

    batched!(G1Projective, G1Affine);
    batched!(G2Projective, G2Affine);
}

// The SEC1 curves. Two notes, one per overridden method.
//
// `serialize_elements_allowing_identity` is worth overriding for one of the
// two, and the two curves differ because their crates do. `serialize_elements`
// is not overridden by anyone: it delegates, so a curve gets its
// batch form on both paths from the one override below.
//
// k256 implements `group::Curve` with a
// real batched normalization (one inversion for the slice), so it takes the
// same override BLS12-381 does: 58.3/132.7/211.8 µs one-by-one against
// 4.7/7.6/9.0 µs batched at 8/32/64 points, i.e. 12x to 23x.
//
// P-256 does not. `primeorder` leaves `group::Curve::batch_normalize` at the
// trait's one-by-one default (its batched form is behind `BatchNormalize`,
// which P-256's field element cannot satisfy: it implements no `Invert`), so
// the override would buy nothing there and P-256 keeps the default loop.
// Measured at 8/32/64 points: 32.8/131.9/256.7 µs against 32.7/127.4/257.8,
// i.e. noise. Re-measure before assuming this is still true of a later
// `primeorder`.
//
// Deserialization, though, is not canonical without help. SEC1 defines a
// third one-byte tag beside the `02`/`03` of a compressed point: `05`, the
// "compact" representation, whose encoding is the same 33 bytes. `sec1`
// accepts it and `from_encoded_point` recovers the point through `decompact`,
// so `05 || x` and `03 || x` decode to the *same element* and re-encode to
// `03 || x`. About half of all points admit such a rewrite. That breaks the
// invariant this trait's documentation states and the specification requires
// — one element, one encoding — and it is load-bearing here, because the
// encoded instance is absorbed as the transcript's domain separator: two
// encodings of one statement would derive two different challenges.
//
// Rejecting the tag costs nothing (3.577 µs against 3.589 µs per element on
// P-256, i.e. noise) and rejects no honest encoding, since an encoder emits
// only `02`/`03`. Re-encoding and comparing would also work and would need no
// per-curve knowledge, but it doubles deserialization (7.226 µs).
// The tag check is the same for both curves, so it is written once here and
// expanded into each impl. It cannot be shared as a blanket implementation for
// the reason `GroupCodec` has no blanket implementation at all.
#[cfg(any(feature = "k256", feature = "p256"))]
macro_rules! sec1_deserialize {
    () => {
        fn deserialize_element_allowing_identity(
            reader: &mut NargReader<'_>,
        ) -> VerificationResult<Self> {
            let mut repr = <Self as group::GroupEncoding>::Repr::default();
            let bytes = reader.take(Self::element_len())?;
            // `00` is the identity, which this method admits by contract;
            // `02` and `03` are the compressed-point tags. Everything
            // else, `05` included, is not an encoding this crate emits.
            // Matched through `first()` so that a zero-length element
            // encoding rejects rather than panicking: this runs on
            // attacker-supplied bytes.
            match bytes.first() {
                Some(0x00 | 0x02 | 0x03) => {}
                _ => return Err(VerificationError),
            }
            AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(bytes);
            Option::<Self>::from(<Self as group::GroupEncoding>::from_bytes(&repr))
                .ok_or(VerificationError)
        }
    };
}

#[cfg(feature = "k256")]
impl GroupCodec for k256::ProjectivePoint {
    sec1_deserialize!();

    fn serialize_elements_allowing_identity(elements: &[Self], out: &mut Vec<u8>) {
        use alloc::vec;
        use group::{Curve, GroupEncoding};

        // `k256`'s `batch_normalize` unwraps a batch inversion, and the
        // inversion has no solution for an empty slice, so it panics there.
        // The empty case is reachable: an instance with no statement elements
        // serializes an empty `elements` list.
        if elements.is_empty() {
            return;
        }
        let mut affine = vec![k256::AffinePoint::IDENTITY; elements.len()];
        Self::batch_normalize(elements, &mut affine);
        for point in &affine {
            // `AffinePoint`'s encoding is the one `ProjectivePoint::to_bytes`
            // produces: the latter is defined as `self.to_affine().to_bytes()`.
            out.extend_from_slice(point.to_bytes().as_ref());
        }
    }
}

#[cfg(feature = "p256")]
impl GroupCodec for p256::ProjectivePoint {
    sec1_deserialize!();
}

/// Byte codec and uniform decoding for scalars.
///
/// The wire encoding is big-endian `I2OSP` (see the [module docs][self]);
/// deserialization rejects values outside the canonical range `[0, p)`.
///
/// # Zeroize
///
/// The [`Zeroize`][zeroize::Zeroize] bound is what lets the prover wipe the
/// witness and its nonces when the prover state is dropped. It is
/// unconditional rather than behind a feature: a feature that *narrows* a
/// blanket implementation is not additive, so one crate turning it on would
/// break a sibling in the same dependency graph whose scalar does not
/// implement it. A group whose scalar lacks `Zeroize` can still be used
/// through a newtype.
pub trait ScalarCodec: PrimeField + zeroize::Zeroize {
    /// `Ns`: the byte length of one serialized scalar.
    fn scalar_len() -> usize {
        Self::Repr::default().as_ref().len()
    }

    /// `Ns + 16`: the number of uniform bytes one scalar is decoded from,
    /// whether squeezed from the transcript as a challenge or drawn from the
    /// prover's randomness. The 16-byte margin is what makes the wide
    /// reduction in [`from_uniform_bytes`][ScalarCodec::from_uniform_bytes]
    /// statistically uniform over `[0, p)`; prover and verifier must squeeze
    /// this same width, so state it here and nowhere else.
    fn challenge_len() -> usize {
        Self::scalar_len() + 16
    }

    /// Appends the big-endian encoding of `self` to `out`.
    fn serialize_scalar(&self, out: &mut Vec<u8>);

    /// Reads one canonical scalar from the front of `reader`.
    fn deserialize_scalar(reader: &mut NargReader<'_>) -> VerificationResult<Self>;

    /// `DecodeField(buf, p, 1)`: little-endian wide reduction of
    /// [`challenge_len()`][ScalarCodec::challenge_len] uniform bytes.
    fn from_uniform_bytes(bytes: &[u8]) -> Self {
        wide_reduce(bytes)
    }

    /// Samples a uniformly random scalar from `rng` by wide reduction of
    /// [`challenge_len()`][ScalarCodec::challenge_len] bytes — the same
    /// distribution-preserving path used for challenges.
    ///
    /// This is where the prover's nonces come from, so the uniform bytes are
    /// as sensitive as the nonce they reduce to: a nonce recovered from memory,
    /// together with the published response and challenge, yields the witness
    /// scalar. [`Zeroizing`][zeroize::Zeroizing] wipes the buffer when this
    /// returns; without it the preimage of every nonce would be left on the
    /// stack, which would leave the wiping of the nonces themselves covering
    /// only half of the exposure.
    // `n` is `challenge_len()`, a constant of the field type and never a value
    // read off the wire, so the two slices are in range for every field this
    // crate can be instantiated with. The assertion states that as a checked
    // precondition rather than a comment; if a field ever declares a challenge
    // wider than the buffer, sampling aborts instead of truncating entropy.
    #[allow(clippy::indexing_slicing)]
    fn sample(rng: &mut spongefish::PrivateRng<impl spongefish::DuplexSpongeInit<U = u8>>) -> Self {
        let mut buf = zeroize::Zeroizing::new([0u8; 64]);
        let n = Self::challenge_len();
        assert!(n <= buf.len());
        rng.fill_bytes(&mut buf[..n]);
        Self::from_uniform_bytes(&buf[..n])
    }
}

impl<F: PrimeField + zeroize::Zeroize> ScalarCodec for F {
    fn serialize_scalar(&self, out: &mut Vec<u8>) {
        serialize_scalar_le(self, repr_is_le::<F>(), out);
    }

    fn deserialize_scalar(reader: &mut NargReader<'_>) -> VerificationResult<Self> {
        deserialize_scalar_le(reader, repr_is_le::<F>())
    }
}

/// [`ScalarCodec::serialize_scalar`] with the endianness already probed.
///
/// [`repr_is_le`] is itself a `to_repr` call, and only folds to a constant
/// where the field's implementation is inlinable — on BLS12-381 it is not.
/// Every loop over scalars therefore probes once and calls this, rather than
/// paying the probe per scalar.
pub(crate) fn serialize_scalar_le<F: PrimeField>(scalar: &F, le: bool, out: &mut Vec<u8>) {
    let mut repr = scalar.to_repr();
    if le {
        repr.as_mut().reverse();
    }
    out.extend_from_slice(repr.as_ref());
}

/// [`ScalarCodec::deserialize_scalar`] with the endianness already probed. See
/// [`serialize_scalar_le`].
pub(crate) fn deserialize_scalar_le<F: PrimeField>(
    reader: &mut NargReader<'_>,
    le: bool,
) -> VerificationResult<F> {
    let mut repr = F::Repr::default();
    let len = repr.as_ref().len();
    repr.as_mut().copy_from_slice(reader.take(len)?);
    if le {
        repr.as_mut().reverse();
    }
    Option::<F>::from(F::from_repr(repr)).ok_or(VerificationError)
}

/// Concatenates the encodings of `elements`.
///
/// This is the prover's commitment and the batchable NARG's element run, so it
/// goes through [`GroupCodec::serialize_elements_allowing_identity`] and gets
/// whatever batch form the curve has. Encodability is settled before the
/// bytes are produced, by
/// [`NargCodec::is_valid_commitment`][crate::fiat_shamir::NargCodec::is_valid_commitment].
pub(crate) fn serialize_elements_allowing_identity<G: GroupCodec>(elements: &[G]) -> Vec<u8> {
    let mut out = Vec::new();
    G::serialize_elements_allowing_identity(elements, &mut out);
    out
}

/// Concatenates the encodings of `scalars`.
pub(crate) fn serialize_scalars<F: ScalarCodec>(scalars: &[F]) -> Vec<u8> {
    let mut out = Vec::new();
    serialize_scalars_into(scalars, &mut out);
    out
}

/// [`serialize_scalars`], appending to an existing buffer.
pub(crate) fn serialize_scalars_into<F: ScalarCodec>(scalars: &[F], out: &mut Vec<u8>) {
    let le = repr_is_le::<F>();
    for scalar in scalars {
        serialize_scalar_le(scalar, le, out);
    }
}

/// Reads `n` elements from the front of `reader`.
///
/// `n` comes from the instance, never from the byte string being read.
pub(crate) fn deserialize_elements<G: GroupCodec>(
    reader: &mut NargReader<'_>,
    n: usize,
) -> VerificationResult<Vec<G>> {
    (0..n).map(|_| G::deserialize_element(reader)).collect()
}

/// Reads `n` scalars from the front of `reader`.
///
/// `n` comes from the instance, never from the byte string being read.
pub(crate) fn deserialize_scalars<F: ScalarCodec>(
    reader: &mut NargReader<'_>,
    n: usize,
) -> VerificationResult<Vec<F>> {
    let expected = n.checked_mul(F::scalar_len()).ok_or(VerificationError)?;
    if reader.remaining_len() < expected {
        return Err(VerificationError);
    }
    let le = repr_is_le::<F>();
    (0..n).map(|_| deserialize_scalar_le(reader, le)).collect()
}

/// Whether the field's canonical representation is little-endian, probed by
/// encoding `1`.
///
/// Assumes the representation is a plain little- or big-endian fixed-width
/// integer encoding, which holds for every `PrimeField` implementation in the
/// `group` ecosystem.
pub(crate) fn repr_is_le<F: PrimeField>() -> bool {
    let repr = F::ONE.to_repr();
    let bytes = repr.as_ref();
    // `first`/`last` rather than indexing: an empty representation would
    // otherwise underflow `len() - 1` before the assertion could report it.
    // Both operands come from the field type, never from a proof.
    let le = bytes.first() == Some(&1);
    assert!(
        le != (bytes.last() == Some(&1)),
        "scalar representation is neither little- nor big-endian"
    );
    le
}

/// `LE2IP(bytes) mod p`, straight-line over 8-byte limbs.
fn wide_reduce<F: PrimeField>(bytes: &[u8]) -> F {
    // A property of the field type (challenge widths are `Ns + 16`), never of
    // a proof, so this cannot be tripped by an attacker.
    assert_eq!(bytes.len() % 8, 0);
    let shift = F::from(u64::MAX) + F::ONE;
    let mut acc = F::ZERO;
    for chunk in bytes.rchunks(8) {
        // Folded rather than converted to `[u8; 8]`: the fold is total for a
        // chunk of any length, so the limb assembly has no failure case to
        // unwrap and no panic to reason about.
        let limb = chunk
            .iter()
            .rev()
            .fold(0u64, |w, &b| (w << 8) | u64::from(b));
        acc = acc * shift + F::from(limb);
    }
    acc
}

// Without a curve feature there is no `GroupCodec` implementor to test.
#[cfg(all(
    test,
    any(
        feature = "bls12_381",
        feature = "curve25519-dalek",
        feature = "k256",
        feature = "p256"
    )
))]
mod tests {
    use super::GroupCodec;
    use alloc::{vec, vec::Vec};
    use spongefish::NargReader;

    /// [`GroupCodec::serialize_elements`] is documented to produce exactly what
    /// [`GroupCodec::serialize_element`] in a loop produces, and the curves
    /// that batch their projective-to-affine conversion override it. The
    /// equality is load-bearing: these bytes are the encoded instance, which is
    /// absorbed as the transcript's domain separator, so a curve whose batched
    /// form disagreed with its element-wise form would derive a different
    /// challenge for the same statement.
    fn batched_matches_loop<G: GroupCodec>() {
        let points: Vec<G> = (1..=5u64)
            .map(|i| G::generator() * G::Scalar::from(i))
            .collect();

        for n in 0..=points.len() {
            let (slice, _) = points.split_at(n);

            let mut batched = Vec::new();
            assert!(
                G::serialize_elements(slice, &mut batched).is_ok(),
                "n = {n}"
            );

            let mut looped = Vec::new();
            for point in slice {
                assert!(point.serialize_element(&mut looped).is_ok(), "n = {n}");
            }

            assert_eq!(batched, looped, "n = {n}");
            assert_eq!(batched.len(), n * G::element_len(), "n = {n}");
        }
    }

    /// Identity encodings use the same public element-wise and batched paths
    /// as every other point, and decode back to the identity.
    fn identity_roundtrips<G: GroupCodec>() {
        let point = G::generator() * G::Scalar::from(7u64);
        for slice in [
            vec![G::identity()],
            vec![G::identity(), point],
            vec![point, G::identity()],
            vec![point, G::identity(), point],
        ] {
            let mut encoded = Vec::new();
            assert!(G::serialize_elements(&slice, &mut encoded).is_ok());

            let mut reader = NargReader::new(&encoded);
            let decoded = (0..slice.len())
                .map(|_| G::deserialize_element(&mut reader))
                .collect::<Result<Vec<_>, _>>();
            assert_eq!(decoded.ok().as_deref(), Some(slice.as_slice()));
            assert!(reader.is_empty());
        }
    }

    /// The identity-admitting form is the one the curves override, so its
    /// batched projective-to-affine conversion is the one that now meets
    /// identity points — on the claim rows of a composed commitment, where the
    /// identity is legal, and on any slice reaching it before
    /// [`NargCodec::is_valid_commitment`][crate::fiat_shamir::NargCodec::is_valid_commitment]
    /// has ruled. A `batch_normalize` that mishandled a zero `z` would encode
    /// those rows differently from the element-wise form, and silently.
    fn batched_matches_loop_with_identity<G: GroupCodec>() {
        let point = G::generator() * G::Scalar::from(7u64);
        for slice in [
            vec![G::identity()],
            vec![G::identity(), point],
            vec![point, G::identity()],
            vec![point, G::identity(), point],
            vec![G::identity(), G::identity()],
        ] {
            let mut batched = Vec::new();
            G::serialize_elements_allowing_identity(&slice, &mut batched);

            let mut looped = Vec::new();
            for point in &slice {
                point.serialize_element_allowing_identity(&mut looped);
            }

            assert_eq!(batched, looped);
            assert_eq!(batched.len(), slice.len() * G::element_len());
        }
    }

    macro_rules! codec_tests {
        ($name:ident, $group:ty) => {
            #[test]
            fn $name() {
                batched_matches_loop::<$group>();
                batched_matches_loop_with_identity::<$group>();
                identity_roundtrips::<$group>();
            }
        };
    }

    #[cfg(feature = "curve25519-dalek")]
    codec_tests!(ristretto, curve25519_dalek::RistrettoPoint);
    #[cfg(feature = "k256")]
    codec_tests!(k256, ::k256::ProjectivePoint);
    #[cfg(feature = "p256")]
    codec_tests!(p256, ::p256::ProjectivePoint);
    #[cfg(feature = "bls12_381")]
    codec_tests!(bls12_381_g1, ::bls12_381::G1Projective);
    #[cfg(feature = "bls12_381")]
    codec_tests!(bls12_381_g2, ::bls12_381::G2Projective);
}
