use group::prime::PrimeGroup;

/// Trait for performing Multi-Scalar Multiplication (MSM).
///
/// MSM computes the sum:
/// ```text
/// result = Σ (scalar[i] * point[i])
/// ```
/// Implementations can override this with optimized algorithms for specific groups,
/// while a default naive implementation is provided for all [`PrimeGroup`] types.
pub trait VariableMultiScalarMul {
    /// The scalar field type associated with the group.
    type Scalar;
    /// The group element (point) type.
    type Point;

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
    fn msm(scalars: &[Self::Scalar], bases: &[Self::Point]) -> Self;
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
    fn msm(scalars: &[Self::Scalar], bases: &[Self::Point]) -> Self {
        assert_eq!(
            scalars.len(),
            bases.len(),
            "scalars and bases must have the same length"
        );

        let mut acc = Self::identity();
        for (s, p) in scalars.iter().zip(bases.iter()) {
            acc += *p * s;
        }
        acc
    }
}
