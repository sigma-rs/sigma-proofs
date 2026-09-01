use alloc::vec::Vec;

use group::Group;
use itertools::Itertools;
use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::codec::repr_is_le;

/// Trait for performing Multi-Scalar Multiplication (MSM).
///
/// MSM computes the sum:
///
/// ```text
/// result = Σ (scalar[i] * point[i])
/// ```
///
/// Both methods have generic defaults that work for any [`Group`], so a group
/// opts in with an empty impl:
///
/// ```text
/// impl MultiScalarMul for MyGroup {}
/// ```
///
/// The curves behind this crate's curve features already have one; those with
/// a tuned MSM of their own (Ristretto, k256) override the defaults with it.
pub trait MultiScalarMul: Group + ConditionallySelectable {
    /// Computes the MSM with runtime independent of the scalars (Straus'
    /// interleaved windowed method with signed radix-16 digits and a
    /// constant-time table lookup).
    ///
    /// Used wherever a scalar may be secret, such as the prover's commitment.
    ///
    /// # Safety
    ///
    /// An implementor overriding this **must** keep secrecy of scalars.
    /// See [`straus_ct`] for the argument the generic body makes, and
    /// [`MultiScalarMul::msm_vartime`] for where value-dependent shortcuts are
    /// allowed instead.
    ///
    /// # Panics
    ///
    /// Panics if `scalars.len() != bases.len()`.
    fn msm(scalars: &[Self::Scalar], bases: &[Self]) -> Self {
        straus_ct(scalars, bases)
    }

    /// Computes the MSM in variable time (Straus' interleaved windowed
    /// method). Only for public scalars: verification equations, image
    /// evaluation, and simulated transcripts.
    ///
    /// # Panics
    ///
    /// Panics if `scalars.len() != bases.len()`.
    fn msm_vartime(scalars: &[Self::Scalar], bases: &[Self]) -> Self {
        straus_vartime(scalars, bases)
    }
}

/// Straus' interleaved windowed method over 4-bit windows, the generic
/// default for [`MultiScalarMul::msm_vartime`]. Exposed so that a group whose
/// own MSM is tuned for full-width scalars can still fall back to it; see the
/// Ristretto impl below.
///
/// # Panics
///
/// Panics if `scalars.len() != bases.len()`.
pub fn straus_vartime<G: Group>(scalars: &[G::Scalar], bases: &[G]) -> G {
    use ff::PrimeField;

    assert_eq!(scalars.len(), bases.len());
    if scalars.is_empty() {
        return G::identity();
    }
    // A lone term with coefficient one is its own base. Image and effective-
    // base computation hit this on nearly every call, and even the
    // truncated multiples table below costs far more than the answer.
    if scalars.len() == 1 && scalars[0] == <G::Scalar as ff::Field>::ONE {
        return bases[0];
    }

    let le = repr_is_le::<G::Scalar>();
    let scalar_bytes: Vec<_> = scalars
        .iter()
        .map(|scalar| {
            let mut repr = scalar.to_repr();
            if le {
                repr.as_mut().reverse();
            }
            repr
        })
        .collect();

    // Start at the most significant byte that any scalar actually uses, and
    // build each table only as far as the largest window digit that occurs.
    // Instance coefficients are usually the literal 1, and paying 15 point
    // additions and 64 doublings for `base * 1` is what made `compile` slow.
    let len = scalar_bytes[0].as_ref().len();
    let start = (0..len)
        .find(|&i| scalar_bytes.iter().any(|b| b.as_ref()[i] != 0))
        .unwrap_or(len);

    let tables: Vec<Vec<G>> = bases
        .iter()
        .zip_eq(&scalar_bytes)
        .map(|(base, bytes)| {
            let top = bytes.as_ref()[start..]
                .iter()
                .map(|b| (b & 0x0f).max(b >> 4))
                .max()
                .unwrap_or(0);
            // table[j] = (j + 1) * base
            let mut table = Vec::with_capacity(top as usize);
            let mut acc = *base;
            for _ in 0..top {
                table.push(acc);
                acc += base;
            }
            table
        })
        .collect();

    let mut acc = G::identity();
    for i in start..len {
        for shift in [4u8, 0u8] {
            for _ in 0..4 {
                acc = acc.double();
            }
            for (table, bytes) in tables.iter().zip_eq(&scalar_bytes) {
                let window = (bytes.as_ref()[i] >> shift) & 0x0f;
                if window != 0 {
                    acc += table[window as usize - 1];
                }
            }
        }
    }
    acc
}

/// Append the signed radix-16 digits of a little-endian scalar encoding to a
/// shared buffer. Each digit is in `[-8, 8]`, with one more digit than there
/// are nibbles to hold the final carry.
fn extend_signed_radix16(le_bytes: &[u8], digits: &mut Vec<i8>) {
    let start = digits.len();
    for byte in le_bytes {
        digits.push((byte & 0x0f) as i8);
        digits.push((byte >> 4) as i8);
    }
    digits.push(0);

    let mut carry = 0i8;
    for digit in &mut digits[start..] {
        let value = *digit + carry;
        carry = (value + 8) >> 4;
        *digit = value - (carry << 4);
    }
}

/// Straus' interleaved windowed method with signed radix-16 digits, the
/// generic default for [`MultiScalarMul::msm`].
///
/// Signed digits halve the table: only `1..=8` times each base is stored, and
/// a negative digit selects the negation.
///
/// # Constant time
///
/// A big part of the proving cost for a sigma protocol is by `prover_commit`.
/// It invokes an MSM on random nonces, which must be kept secret.
///
/// The scalar length and the generators are assumed to be public.
/// Implementations might choose different algorithms depending on the scalars length.
///
/// The group's own algebra (`double`, `add`, and `neg`, and `PrimeField::to_repr`) are assumed constant time.
///
/// # Panics
///
/// Panics if `scalars.len() != bases.len()`.
pub fn straus_ct<G: Group + ConditionallySelectable>(scalars: &[G::Scalar], bases: &[G]) -> G {
    use ff::PrimeField;

    assert_eq!(scalars.len(), bases.len());
    if scalars.is_empty() {
        return G::identity();
    }

    let le = repr_is_le::<G::Scalar>();
    let width = 2 * scalars[0].to_repr().as_ref().len() + 1;
    // One flat allocation instead of one `Vec` allocation per scalar. Scalar
    // encodings all have the field's fixed width, so rows remain addressable
    // as exact chunks without storing offsets.
    let mut digits = Vec::with_capacity(scalars.len() * width);
    for scalar in scalars {
        let mut repr = scalar.to_repr();
        if !le {
            repr.as_mut().reverse();
        }
        extend_signed_radix16(repr.as_ref(), &mut digits);
    }
    debug_assert_eq!(digits.len(), scalars.len() * width);

    // table[j] = (j + 1) * base
    let tables: Vec<[G; 8]> = bases
        .iter()
        .map(|base| {
            let mut table = [*base; 8];
            for j in 1..8 {
                table[j] = table[j - 1] + base;
            }
            table
        })
        .collect();

    let mut acc = G::identity();
    for i in (0..width).rev() {
        if i != width - 1 {
            for _ in 0..4 {
                acc = acc.double();
            }
        }
        for (table, scalar_digits) in tables.iter().zip_eq(digits.chunks_exact(width)) {
            let digit = scalar_digits[i];
            let sign = ((digit >> 7) as u8) & 1;
            let magnitude = ((digit ^ (digit >> 7)) - (digit >> 7)) as u8;

            let mut selected = G::identity();
            for (j, entry) in table.iter().enumerate() {
                selected.conditional_assign(entry, (j as u8 + 1).ct_eq(&magnitude));
            }
            acc += G::conditional_select(&selected, &-selected, sign.into());
        }
    }
    acc
}

/// A public scalar that fits in this many bytes is faster through the generic
/// body, which walks only the bytes in use, than through dalek's, which always
/// walks all 32. The crossover is flat in the number of scalars but does move
/// with the host: `benches/msm.rs`'s `width` sweep puts it between 12 and 16
/// bytes on aarch64 (at 12 the generic body wins by 8-18% across runs; at 16
/// the two trade places), against the 20 bytes measured when this was first
/// tuned. 12 is the widest value both measurements agree on.
///
/// Re-run that sweep rather than adjusting this from first principles.
#[cfg(feature = "curve25519-dalek")]
const NARROW_BYTES: usize = 12;

/// Whether every scalar is narrow enough for the generic variable-time body
/// to win. **Variable-time paths only** — this branches on scalar magnitude,
/// so calling it on a secret scalar would leak that scalar's size. The
/// constant-time `msm` below must, and does, dispatch on `scalars.len()`
/// alone, which is public.
#[cfg(feature = "curve25519-dalek")]
fn all_narrow(scalars: &[curve25519_dalek::Scalar]) -> bool {
    scalars
        .iter()
        .all(|x| x.as_bytes()[NARROW_BYTES..] == [0u8; 32 - NARROW_BYTES])
}

/// Ristretto and Edwards have a tuned MSM of their own: constant-time Straus,
/// and Straus/Pippenger with signed windows in variable time.
///
/// Both are dispatched, and on different axes:
///
/// - `msm` sends `n == 1` to a plain scalar multiplication (16.7 µs against
///   dalek's 17.3) and everything wider to dalek, which wins from `n == 2`
///   on. The axis is the slice length, which is public.
/// - `msm_vartime` sends *narrow* scalars to the generic body, which stops at
///   the most significant byte in use. `Instance::validate` evaluates
///   single-term images with coefficient one about 32 times per `compile`,
///   and dalek pays a full 256-bit ladder for each: 11.3 µs against the
///   generic body's 0.72 µs. Dispatching to dalek unconditionally makes
///   `compile(cmz_show_10)` 363 µs instead of 31 µs.
///
/// The two impls are identical apart from the point type, so they are written
/// once here rather than duplicated and left to drift.
#[cfg(feature = "curve25519-dalek")]
macro_rules! dalek_msm {
    ($point:ty) => {
        impl MultiScalarMul for $point {
            fn msm(scalars: &[Self::Scalar], bases: &[Self]) -> Self {
                use curve25519_dalek::traits::MultiscalarMul;

                assert_eq!(scalars.len(), bases.len());
                match scalars {
                    // Straus is a loss against a plain multiplication here.
                    [] => Self::identity(),
                    [x] => bases[0] * x,
                    _ => Self::multiscalar_mul(scalars, bases),
                }
            }

            fn msm_vartime(scalars: &[Self::Scalar], bases: &[Self]) -> Self {
                use curve25519_dalek::traits::VartimeMultiscalarMul;

                assert_eq!(scalars.len(), bases.len());
                if all_narrow(scalars) {
                    return straus_vartime(scalars, bases);
                }
                Self::vartime_multiscalar_mul(scalars, bases)
            }
        }
    };
}

#[cfg(feature = "curve25519-dalek")]
dalek_msm!(curve25519_dalek::RistrettoPoint);

#[cfg(feature = "curve25519-dalek")]
dalek_msm!(curve25519_dalek::EdwardsPoint);

#[cfg(feature = "k256")]
impl MultiScalarMul for k256::ProjectivePoint {
    fn msm(scalars: &[Self::Scalar], bases: &[Self]) -> Self {
        use k256::elliptic_curve::ops::LinearCombinationExt;

        assert_eq!(scalars.len(), bases.len());
        LinearCombinationExt::lincomb_ext(
            core::iter::zip(bases.iter().copied(), scalars.iter().copied())
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }
}

// NOTE: As of 0.13.2 the p256 crate does not implement LinearCombinationExt on
// ProjectivePoint, so p256 takes the generic Straus.
#[cfg(feature = "p256")]
impl MultiScalarMul for p256::ProjectivePoint {}

#[cfg(feature = "bls12_381")]
impl MultiScalarMul for bls12_381::G1Projective {}

#[cfg(feature = "bls12_381")]
impl MultiScalarMul for bls12_381::G2Projective {}

#[cfg(test)]
mod tests {
    use super::{extend_signed_radix16, straus_ct, straus_vartime, MultiScalarMul};
    use alloc::{vec, vec::Vec};
    use ff::Field;
    use group::Group;

    fn naive<G: Group>(scalars: &[G::Scalar], bases: &[G]) -> G {
        core::iter::zip(bases, scalars).map(|(g, x)| *g * *x).sum()
    }

    #[test]
    fn flat_radix_rows_do_not_share_carries() {
        let mut digits = Vec::new();
        extend_signed_radix16(&[0xff], &mut digits);
        extend_signed_radix16(&[0x88], &mut digits);
        assert_eq!(digits, [-1, 0, 1, -8, -7, 1]);
    }

    /// Inputs chosen to hit every fast path: the empty case, zero, the
    /// coefficient `ONE` that `Instance::validate` passes, the digit
    /// boundaries the radix-16 recoding carries across, and random scalars.
    fn cases<G: Group>() -> Vec<Vec<G::Scalar>> {
        let mut rng = rand::thread_rng();
        let one = G::Scalar::ONE;
        vec![
            vec![],
            vec![G::Scalar::ZERO],
            vec![one],
            vec![-one],
            vec![G::Scalar::ZERO, G::Scalar::ZERO],
            vec![one, one],
            vec![one, G::Scalar::from(15)],
            vec![one, G::Scalar::from(16)],
            vec![G::Scalar::from(255), G::Scalar::from(256)],
            vec![one, -one, G::Scalar::random(&mut rng)],
            (0..5).map(|_| G::Scalar::random(&mut rng)).collect(),
            (0..17).map(|_| G::Scalar::random(&mut rng)).collect(),
        ]
    }

    /// Both entry points, the group's own and the generic bodies, must all
    /// agree with `sum(g * x)`.
    fn agree<G: MultiScalarMul>() {
        for scalars in cases::<G>() {
            let bases: Vec<G> = (0..scalars.len() as u64)
                .map(|i| G::generator() * G::Scalar::from(i + 7))
                .collect();
            let expected = naive(&scalars, &bases);
            let n = scalars.len();
            assert_eq!(G::msm(&scalars, &bases), expected, "msm, n = {n}");
            assert_eq!(
                G::msm_vartime(&scalars, &bases),
                expected,
                "msm_vartime, n = {n}"
            );
            assert_eq!(straus_ct(&scalars, &bases), expected, "straus_ct, n = {n}");
            assert_eq!(
                straus_vartime(&scalars, &bases),
                expected,
                "straus_vartime, n = {n}"
            );
        }
    }

    #[cfg(feature = "curve25519-dalek")]
    #[test]
    fn agree_ristretto() {
        agree::<curve25519_dalek::RistrettoPoint>();
    }

    #[cfg(feature = "curve25519-dalek")]
    #[test]
    fn agree_edwards() {
        agree::<curve25519_dalek::EdwardsPoint>();
    }

    // A big-endian scalar repr, so the byte-order handling is covered too.
    #[cfg(feature = "p256")]
    #[test]
    fn agree_p256() {
        agree::<p256::ProjectivePoint>();
    }

    #[cfg(feature = "k256")]
    #[test]
    fn agree_k256() {
        agree::<k256::ProjectivePoint>();
    }

    #[cfg(feature = "bls12_381")]
    #[test]
    fn agree_bls12_381() {
        agree::<bls12_381::G1Projective>();
    }
}
