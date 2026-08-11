use std::hint::black_box;

use divan::Bencher;
use ff::Field;
use group::Group;
use rand::{thread_rng, Rng};
use sigma_proofs::msm::straus_vartime;
use sigma_proofs::MultiScalarMul;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

const MSM_SIZES: &[usize] = &[0, 1, 2, 4, 8, 16, 32, 64, 128];

fn main() {
    divan::main();
}

fn instance<G: Group>(n: usize) -> (Vec<G::Scalar>, Vec<G>) {
    (
        (0..n)
            .map(|_| <G::Scalar as Field>::random(&mut thread_rng()))
            .collect(),
        (0..n).map(|_| G::random(&mut thread_rng())).collect(),
    )
}

fn bench_msm<G: Group + MultiScalarMul>(bencher: Bencher, n: usize) {
    let (scalars, bases) = instance(n);
    bencher
        .counter(n)
        .bench(|| G::msm(black_box(&scalars), black_box(&bases)));
}

fn bench_msm_vartime<G: Group + MultiScalarMul>(bencher: Bencher, n: usize) {
    let (scalars, bases) = instance(n);
    bencher
        .counter(n)
        .bench(|| G::msm_vartime(black_box(&scalars), black_box(&bases)));
}

/// [`MultiScalarMul::msm_vartime`] on the coefficients an instance actually
/// carries. `Instance::validate` and `compute_image` evaluate single-term rows
/// whose coefficient is the literal one, which is the shape the variable-time
/// fast paths exist for; a curve that dispatches to a full-width ladder here
/// pays a whole scalar multiplication to compute `base * 1`.
fn bench_msm_vartime_coefficient_one<G: Group + MultiScalarMul>(bencher: Bencher, n: usize) {
    let scalars = vec![<G::Scalar as Field>::ONE; n];
    let bases: Vec<G> = (0..n).map(|_| G::random(&mut thread_rng())).collect();
    bencher
        .counter(n)
        .bench(|| G::msm_vartime(black_box(&scalars), black_box(&bases)));
}

#[allow(dead_code)]
fn msm_naive<G: Group>(scalars: &[G::Scalar], bases: &[G]) -> G {
    assert_eq!(scalars.len(), bases.len());
    std::iter::zip(scalars, bases).map(|(x, g)| *g * x).sum()
}

// Included as a baseline. As needed, add a benchmark using this function to provide a comparison.
#[allow(dead_code)]
fn bench_msm_naive<G: Group>(bencher: Bencher, n: usize) {
    let (scalars, bases) = instance(n);
    bencher
        .counter(n)
        .bench(|| msm_naive::<G>(black_box(&scalars), black_box(&bases)));
}

macro_rules! curve_benches {
    ($name:ident, $group:ty) => {
        mod $name {
            use super::*;

            #[divan::bench(args = MSM_SIZES)]
            fn msm(bencher: Bencher, n: usize) {
                bench_msm::<$group>(bencher, n);
            }

            #[divan::bench(args = MSM_SIZES)]
            fn msm_vartime(bencher: Bencher, n: usize) {
                bench_msm_vartime::<$group>(bencher, n);
            }

            #[divan::bench(args = MSM_SIZES)]
            fn msm_vartime_coefficient_one(bencher: Bencher, n: usize) {
                bench_msm_vartime_coefficient_one::<$group>(bencher, n);
            }
        }
    };
}

// Leading `::` on every path: each invocation opens a module named after the
// curve, which would otherwise shadow the crate of the same name.
curve_benches!(curve25519, ::curve25519_dalek::RistrettoPoint);
curve_benches!(k256, ::k256::ProjectivePoint);
curve_benches!(p256, ::p256::ProjectivePoint);
curve_benches!(bls12_381_g1, ::bls12_381::G1Projective);
curve_benches!(bls12_381_g2, ::bls12_381::G2Projective);

/// Where the generic variable-time body stops beating a curve's own.
///
/// The generic body walks only the bytes a scalar actually uses, so its cost
/// grows with the width in use; curve25519-dalek's walks all 32 regardless.
/// `MultiScalarMul::msm_vartime` for Ristretto dispatches on exactly that, and
/// `msm::NARROW_BYTES` is the threshold it uses -- these two benchmarks are
/// where that constant comes from, so re-read them before changing it. Run
/// them and compare the two arms at each width: the crossover is the width at
/// which `dalek` overtakes `generic`.
///
/// Ristretto is the only curve with a variable-time override, so it is the only
/// one swept here; for every other curve both arms would run the same code.
mod width {
    use super::*;
    use curve25519_dalek::{RistrettoPoint, Scalar};

    /// Scalar widths in bytes, spanning the documented crossover.
    const WIDTHS: &[usize] = &[1, 4, 8, 12, 16, 20, 24, 32];

    /// `n` is fixed: the crossover is flat in the number of scalars, and this
    /// sweep is about the width.
    const TERMS: usize = 4;

    fn instance_of_width(bytes: usize) -> (Vec<Scalar>, Vec<RistrettoPoint>) {
        let scalars = (0..TERMS)
            .map(|_| {
                // Dalek's canonical scalar encoding is little-endian, so
                // zeroing the high bytes is what bounds the value's width.
                let mut repr = [0u8; 32];
                thread_rng().fill(&mut repr[..bytes.min(32)]);
                Scalar::from_bytes_mod_order(repr)
            })
            .collect();
        let bases = (0..TERMS)
            .map(|_| RistrettoPoint::random(&mut thread_rng()))
            .collect();
        (scalars, bases)
    }

    #[divan::bench(args = WIDTHS)]
    fn generic(bencher: Bencher, bytes: usize) {
        let (scalars, bases) = instance_of_width(bytes);
        bencher.bench(|| straus_vartime(black_box(&scalars), black_box(&bases)));
    }

    #[divan::bench(args = WIDTHS)]
    fn dalek(bencher: Bencher, bytes: usize) {
        use curve25519_dalek::traits::VartimeMultiscalarMul;

        let (scalars, bases) = instance_of_width(bytes);
        bencher.bench(|| {
            RistrettoPoint::vartime_multiscalar_mul(black_box(&scalars), black_box(&bases))
        });
    }
}
