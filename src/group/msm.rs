use alloc::vec;
use alloc::vec::Vec;
use ff::PrimeField;
use group::prime::PrimeGroup;

/// The result of this function is only approximately `ln(a)`. This is inherited from Zexe and libsnark.
#[inline]
const fn ln_without_floats(a: usize) -> usize {
    if a == 0 {
        1
    } else {
        // log2(a) * ln(2), ensure minimum value of 1
        let result = (usize::BITS - (a - 1).leading_zeros()) as usize * 69 / 100;
        if result == 0 {
            1
        } else {
            result
        }
    }
}

/// Trait for performing Multi-Scalar Multiplication (MSM).
///
/// MSM computes the sum:
/// ```text
/// result = Σ (scalar[i] * point[i])
/// ```
/// Implementations can override this with optimized algorithms for specific groups,
/// while a default naive implementation is provided for all [`PrimeGroup`] types.
pub trait VariableMultiScalarMul: Sized {
    /// The scalar field type associated with the group.
    type Scalar;
    /// The group element (point) type.
    type Point: PrimeGroup;

    /// Computes the multi-scalar multiplication (MSM) over the provided scalars and points.
    ///
    /// # Parameters
    /// - `scalars`: Slice of scalar multipliers.
    /// - `bases`: Slice of group elements to be multiplied by the scalars.
    ///
    /// # Returns
    /// The resulting group element from the MSM computation.
    ///
    /// # Panics
    /// Panics if `scalars.len() != bases.len()`.
    fn msm(scalars: &[Self::Scalar], bases: &[Self::Point]) -> Self {
        assert_eq!(scalars.len(), bases.len());
        Self::msm_unchecked(scalars, bases)
    }

    fn msm_unchecked(scalars: &[Self::Scalar], bases: &[Self::Point]) -> Self;
}

impl<G: PrimeGroup> VariableMultiScalarMul for G {
    type Scalar = G::Scalar;
    type Point = G;

    /// Default naive MSM implementation for any [`PrimeGroup`].
    ///
    /// This method performs a straightforward sum of scalar multiplications:
    /// ```text
    /// Σ (scalar[i] * point[i])
    /// ```
    /// Complexity: **O(n)** group multiplications and additions.
    ///
    /// # Panics
    /// Panics if `scalars.len() != bases.len()`.
    fn msm_unchecked(scalars: &[Self::Scalar], bases: &[Self::Point]) -> Self {
        assert_eq!(scalars.len(), bases.len());

        // NOTE: Based on the msm benchmark in this repo, msm_pippenger provides improvements over
        // msm_naive past a small constant size, but is significantly slower for very small MSMs.
        match scalars.len() {
            0 => Self::identity(),
            1..16 => msm_naive(bases, scalars),
            16.. => msm_pippenger(bases, scalars),
        }
    }
}

/// A naive MSM implementation.
fn msm_naive<G: PrimeGroup>(bases: &[G], scalars: &[G::Scalar]) -> G {
    core::iter::zip(bases, scalars).map(|(g, x)| *g * x).sum()
}

/// An MSM implementation that employ's Pippenger's algorithm and works for all groups that
/// implement `PrimeGroup`.
fn msm_pippenger<G: PrimeGroup>(bases: &[G], scalars: &[G::Scalar]) -> G {
    let c = ln_without_floats(scalars.len());
    let num_bits = <G::Scalar as PrimeField>::NUM_BITS as usize;
    // split `num_bits` into steps of `c`, but skip window 0.
    let windows = (0..num_bits).step_by(c);
    let buckets_num = 1 << c;

    let mut window_buckets = Vec::with_capacity(windows.len());
    for window in windows {
        window_buckets.push((window, vec![G::identity(); buckets_num]));
    }

    for (scalar, base) in scalars.iter().zip(bases) {
        for (w, bucket) in window_buckets.iter_mut() {
            let scalar_repr = scalar.to_repr();
            let scalar_bytes = scalar_repr.as_ref();

            // Extract the relevant bits for this window
            let window_start = *w;
            let window_end = (window_start + c).min(scalar_bytes.len() * 8);

            if window_start >= scalar_bytes.len() * 8 {
                continue; // Window is beyond the scalar size
            }

            let mut scalar_bits = 0u64;

            // Extract bits from the byte representation
            for bit_idx in window_start..window_end {
                let byte_idx = bit_idx / 8;
                let bit_in_byte = bit_idx % 8;

                if byte_idx < scalar_bytes.len() {
                    let bit = (scalar_bytes[byte_idx] >> bit_in_byte) & 1;
                    scalar_bits |= (bit as u64) << (bit_idx - window_start);
                }
            }

            // If the scalar is non-zero, we update the corresponding bucket.
            // (Recall that `buckets` doesn't have a zero bucket.)
            if scalar_bits != 0 {
                bucket[(scalar_bits - 1) as usize].add_assign(base);
            }
        }
    }

    let mut window_sums = window_buckets.iter().rev().map(|(_w, bucket)| {
        // `running_sum` = sum_{j in i..num_buckets} bucket[j],
        // where we iterate backward from i = num_buckets to 0.
        let mut bucket_sum = G::identity();
        let mut bucket_running_sum = G::identity();
        bucket.iter().rev().for_each(|b| {
            bucket_running_sum += b;
            bucket_sum += &bucket_running_sum;
        });
        bucket_sum
    });

    // We're traversing windows from high to low.
    let first = window_sums.next().unwrap();
    window_sums.fold(first, |mut total, sum_i| {
        for _ in 0..c {
            total = total.double();
        }
        total + sum_i
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use group::Group;

    #[test]
    fn test_msm() {
        use bls12_381::{G1Projective, Scalar};
        use rand::thread_rng;

        let mut rng = thread_rng();
        const N: usize = 1024;

        // Generate random scalars and bases
        let scalars: Vec<Scalar> = (0..N).map(|_| Scalar::random(&mut rng)).collect();
        let bases: Vec<G1Projective> = (0..N).map(|_| G1Projective::random(&mut rng)).collect();

        // Compute MSM using our optimized implementation
        let msm_result = G1Projective::msm(&scalars, &bases);

        // Compute reference result using naive scalar multiplication and sum
        let naive_result = scalars
            .iter()
            .zip(bases.iter())
            .map(|(scalar, base)| base * scalar)
            .fold(G1Projective::identity(), |acc, x| acc + x);

        assert_eq!(
            msm_result, naive_result,
            "MSM result should equal naive computation"
        );
    }
}
