use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ff::Field;
use group::Group;
use rand::thread_rng;
use sigma_proofs::VariableMultiScalarMul;

fn bench_msm_curve25519_dalek(c: &mut Criterion) {
    use curve25519_dalek::{RistrettoPoint, Scalar};

    let mut group = c.benchmark_group("MSM curve25519-dalek RistrettoPoint");
    let mut rng = thread_rng();

    for size in [1, 2, 4, 8, 16, 64, 256, 1024].iter() {
        let scalars: Vec<Scalar> = (0..*size).map(|_| Scalar::random(&mut rng)).collect();
        let bases: Vec<RistrettoPoint> = (0..*size)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect();

        group.bench_with_input(BenchmarkId::new("size", size), size, |b, _| {
            b.iter(|| RistrettoPoint::msm(black_box(&scalars), black_box(&bases)))
        });
    }
    group.finish();
}

fn bench_msm_k256(c: &mut Criterion) {
    use k256::{ProjectivePoint, Scalar};

    let mut group = c.benchmark_group("MSM k256 ProjectivePoint");
    let mut rng = thread_rng();

    for size in [1, 2, 4, 8, 16, 64, 256, 1024].iter() {
        let scalars: Vec<Scalar> = (0..*size).map(|_| Scalar::random(&mut rng)).collect();
        let bases: Vec<ProjectivePoint> = (0..*size)
            .map(|_| ProjectivePoint::random(&mut rng))
            .collect();

        group.bench_with_input(BenchmarkId::new("size", size), size, |b, _| {
            b.iter(|| ProjectivePoint::msm(black_box(&scalars), black_box(&bases)))
        });
    }
    group.finish();
}

fn bench_msm_p256(c: &mut Criterion) {
    use p256::{ProjectivePoint, Scalar};

    let mut group = c.benchmark_group("MSM p256 ProjectivePoint");
    let mut rng = thread_rng();

    for size in [1, 2, 4, 8, 16, 64, 256, 1024].iter() {
        let scalars: Vec<Scalar> = (0..*size).map(|_| Scalar::random(&mut rng)).collect();
        let bases: Vec<ProjectivePoint> = (0..*size)
            .map(|_| ProjectivePoint::random(&mut rng))
            .collect();

        group.bench_with_input(BenchmarkId::new("size", size), size, |b, _| {
            b.iter(|| ProjectivePoint::msm(black_box(&scalars), black_box(&bases)))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_msm_curve25519_dalek,
    bench_msm_k256,
    bench_msm_p256
);
criterion_main!(benches);
