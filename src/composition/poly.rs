//! Lagrange interpolation and threshold challenge expansion.

use alloc::{vec, vec::Vec};
use ff::{Field, PrimeField};
use itertools::Itertools;

use super::ct::Evaluation;
use crate::errors::VerificationError;

pub(super) fn threshold_x<F: PrimeField>(index: usize) -> F {
    F::from((index + 1) as u64)
}

/// Multiply a polynomial by `x + constant`.
///
/// # Panics
///
/// Never: `out` is allocated one longer than `coeffs`, so both `i` and
/// `i + 1` are in range for every index the loop produces. Zipping would say
/// that without indexing, but the two sequences differ in length by one on
/// purpose, and a length mismatch is what `zip_eq` is here to reject.
#[allow(clippy::indexing_slicing)]
pub(super) fn poly_mul_linear<F: Field>(coeffs: &[F], constant: F) -> Vec<F> {
    let mut out = vec![F::ZERO; coeffs.len() + 1];
    for (i, coeff) in coeffs.iter().enumerate() {
        out[i] += *coeff * constant;
        out[i + 1] += *coeff;
    }
    out
}

/// Perform lagrange interpolation of `points`
pub(super) fn interpolate_polynomial<F: Field>(
    points: &[Evaluation<F>],
) -> Result<Vec<F>, VerificationError> {
    if points.is_empty() {
        return Err(VerificationError);
    }

    let mut coeffs = vec![F::ZERO; points.len()];

    for (i, point_i) in points.iter().enumerate() {
        let mut basis = vec![F::ONE];
        let mut denom = F::ONE;

        for (j, point_j) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            denom *= point_i.x - point_j.x;
            basis = poly_mul_linear::<F>(&basis, -point_j.x);
        }

        let denom_inv = denom.invert();
        if denom_inv.is_none().into() {
            return Err(VerificationError);
        }
        let scale = point_i.y * denom_inv.unwrap_or(F::ZERO);
        for (coeff, basis_coeff) in coeffs.iter_mut().zip_eq(basis.iter()) {
            *coeff += *basis_coeff * scale;
        }
    }

    Ok(coeffs)
}

/// Evaluate a polynomial with Horner's method.
pub(super) fn evaluate_polynomial<F: Field>(coeffs: &[F], x: F) -> F {
    coeffs
        .iter()
        .rev()
        .fold(F::ZERO, |acc, coeff| acc * x + coeff)
}

pub(super) fn expand_threshold_challenges<F: PrimeField>(
    threshold: usize,
    total: usize,
    challenge: F,
    compressed_challenges: &[F],
) -> Result<Vec<F>, VerificationError> {
    if threshold > total {
        return Err(VerificationError);
    }

    let degree = total - threshold;
    if compressed_challenges.len() != degree {
        return Err(VerificationError);
    }

    let mut points = Vec::with_capacity(degree + 1);
    points.push(Evaluation {
        x: F::ZERO,
        y: challenge,
    });
    for (index, share) in compressed_challenges.iter().enumerate() {
        points.push(Evaluation {
            x: threshold_x::<F>(index),
            y: *share,
        });
    }

    let coeffs = interpolate_polynomial::<F>(&points)?;
    let mut challenges = Vec::with_capacity(total);
    for index in 0..total {
        challenges.push(evaluate_polynomial::<F>(&coeffs, threshold_x::<F>(index)));
    }

    Ok(challenges)
}

#[cfg(test)]
mod tests {
    use super::{evaluate_polynomial, expand_threshold_challenges, threshold_x};
    use alloc::vec::Vec;
    use bls12_381::Scalar;

    /// The prover may expand the polynomial it already interpolated instead
    /// of re-interpolating the compressed wire representation.  Pin that
    /// equivalence across constant and non-constant threshold polynomials,
    /// down to the zero threshold whose polynomial is free at every branch.
    #[test]
    fn direct_expansion_matches_wire_reconstruction() {
        for total in 0..=12 {
            for threshold in 0..=total {
                let degree = total - threshold;
                let coeffs = (0..=degree)
                    .map(|i| Scalar::from((i as u64 + 1).pow(3)))
                    .collect::<Vec<_>>();
                let direct = (0..total)
                    .map(|i| evaluate_polynomial(&coeffs, threshold_x(i)))
                    .collect::<Vec<_>>();
                let compressed = direct.iter().take(degree).copied().collect::<Vec<_>>();

                let reconstructed =
                    expand_threshold_challenges(threshold, total, coeffs[0], &compressed).unwrap();

                assert_eq!(direct, reconstructed, "{threshold}-of-{total}");
            }
        }
    }
}
