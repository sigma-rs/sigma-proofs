use std::hint::black_box;

use divan::Bencher;
use ff::Field;
use group::Group;
use rand::thread_rng;
use sigma_proofs::MultiScalarMul;

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

fn bench_msm<G: Group + MultiScalarMul<G::Scalar>>(bencher: Bencher, n: usize) {
    let (scalars, bases) = instance(n);
    bencher
        .counter(n)
        .bench(|| G::msm(black_box(&scalars), black_box(&bases)));
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

#[divan::bench(args = MSM_SIZES)]
fn curve25519(bencher: Bencher, n: usize) {
    bench_msm::<curve25519_dalek::RistrettoPoint>(bencher, n);
}

#[divan::bench(args = MSM_SIZES)]
fn k256(bencher: Bencher, n: usize) {
    bench_msm::<k256::ProjectivePoint>(bencher, n);
}

#[divan::bench(args = MSM_SIZES)]
fn p256(bencher: Bencher, n: usize) {
    bench_msm::<p256::ProjectivePoint>(bencher, n);
}

#[divan::bench(args = MSM_SIZES)]
fn bls12_381_g1(bencher: Bencher, n: usize) {
    bench_msm::<bls12_381::G1Projective>(bencher, n);
}

#[divan::bench(args = MSM_SIZES)]
fn bls12_381_g2(bencher: Bencher, n: usize) {
    bench_msm::<bls12_381::G2Projective>(bencher, n);
}
