use group::prime::PrimeGroup;

pub trait VariableMultiScalarMul {
    type Scalar;
    type Point;

    fn msm(scalars: &[Self::Scalar], bases: &[Self::Point]) -> Self;
}

impl<G: PrimeGroup> VariableMultiScalarMul for G {
    type Scalar = G::Scalar;
    type Point = G;

    /// Perform a simple multi-scalar multiplication (MSM) over scalars and points.
    ///
    /// Given slices of scalars and corresponding group elements (bases),
    /// returns the sum of each base multiplied by its scalar coefficient.
    ///
    /// # Parameters
    /// - `scalars`: slice of scalar multipliers.
    /// - `bases`: slice of group elements to be multiplied by the scalars.
    ///
    /// # Returns
    /// The group element result of the MSM.
    fn msm(scalars: &[Self::Scalar], bases: &[Self::Point]) -> Self {
        let mut acc = Self::identity();
        for (s, p) in scalars.iter().zip(bases.iter()) {
            acc += *p * s;
        }
        acc
    }
}
