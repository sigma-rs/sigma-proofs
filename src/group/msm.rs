use group::Group;

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
/// while a default naive implementation is provided for all [`Group`] implementations.
pub trait MultiScalarMul: Group {
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
    fn msm(scalars: &[Self::Scalar], bases: &[Self]) -> Self {
        assert_eq!(scalars.len(), bases.len());
        core::iter::zip(bases, scalars).map(|(g, x)| *g * *x).sum()
    }
}

#[cfg(feature = "curve25519-dalek")]
mod curve25519 {
    use super::MultiScalarMul;
    use curve25519_dalek::{traits::MultiscalarMul as _, RistrettoPoint, Scalar};
    use group::Group;

    impl MultiScalarMul for RistrettoPoint {
        fn msm(scalars: &[Scalar], bases: &[Self]) -> Self {
            assert_eq!(scalars.len(), bases.len());
            match scalars.len() {
                // curve25519_dalek always computes powers the the identity point, even when the
                // input length is zero. Special case 0 to avoid this work. Expect for 0, the
                // curve25519_dalek MSM is at least as fast as the naive MSM.
                0 => RistrettoPoint::identity(),
                1.. => RistrettoPoint::multiscalar_mul(scalars, bases),
            }
        }
    }
}

#[cfg(feature = "bls12_381")]
mod bls12_381 {
    use super::MultiScalarMul;
    use bls12_381::{G1Projective, G2Projective};

    impl MultiScalarMul for G1Projective {}
    impl MultiScalarMul for G2Projective {}
}

#[cfg(feature = "k256")]
mod k256 {
    use super::MultiScalarMul;
    use k256::{elliptic_curve::ops::LinearCombinationExt, ProjectivePoint, Scalar};

    impl MultiScalarMul for ProjectivePoint {
        fn msm(scalars: &[Scalar], bases: &[Self]) -> Self {
            assert_eq!(scalars.len(), bases.len());
            LinearCombinationExt::lincomb_ext(
                core::iter::zip(bases.iter().copied(), scalars.iter().copied())
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
        }
    }
}

#[cfg(feature = "p256")]
mod p256 {
    use super::MultiScalarMul;
    use p256::ProjectivePoint;

    // NOTE: As of 0.13.2 the p256 crate does not implement LinearCombinationExt on ProjectivePoint
    impl MultiScalarMul for ProjectivePoint {}
}
