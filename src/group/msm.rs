use core::{iter::Sum, ops::Mul};

/// Trait for performing Multi-Scalar Multiplication (MSM).
///
/// Runtime is guaranteed to be constant with respect to the scalars. No constant time guarantees
/// are provided with respect to the bases.
///
/// MSM computes the sum:
///
/// ```text
/// result = Σ (scalar[i] * point[i])
/// ```
///
/// Implementations can override this with optimized algorithms for specific groups,
/// while a default naive implementation is provided for all [`PrimeGroup`] types.
pub trait MultiScalarMul<Scalar: Clone>: Clone + Mul<Scalar, Output = Self> + Sum {
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
    ///
    /// Panics if `scalars.len() != bases.len()`.
    fn msm(scalars: &[Scalar], bases: &[Self]) -> Self {
        assert_eq!(scalars.len(), bases.len());
        core::iter::zip(bases, scalars)
            .map(|(g, x)| g.clone() * x.clone())
            .sum()
    }
}

#[cfg(feature = "curve25519-dalek")]
mod curve25519 {
    use super::MultiScalarMul;
    use curve25519_dalek::{traits::MultiscalarMul as _, RistrettoPoint, Scalar};

    impl MultiScalarMul<Scalar> for RistrettoPoint {
        fn msm(scalars: &[Scalar], bases: &[Self]) -> Self {
            RistrettoPoint::multiscalar_mul(scalars, bases)
        }
    }
}
