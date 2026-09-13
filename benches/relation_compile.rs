//! Focused benchmarks for [`LinearRelation::compile`].
//!
//! Relation construction, hash-to-group, and image computation are setup;
//! each measured iteration calls only `compile` on an assigned relation.

use std::hint::black_box;

use curve25519_dalek::{RistrettoPoint as G, Scalar};
use divan::Bencher;
use group::Group;
use hash2group::{rfc9380::ExpandMsgXmd, FromHash};
use itertools::Itertools;
use sha2::Sha256;
use sigma_proofs::linear_relation::{LinearCombination, LinearRelation};

const WIDE_TERMS: usize = 1_024;
const MANY_EQUATIONS: usize = 256;
const CONSTANT_EQUATIONS: usize = 128;
const CONSTANT_TERMS: usize = 8;
const POINT_DOMAIN: &[u8] = b"sigma-proofs relation compile benchmark points";

type PointHash = ExpandMsgXmd<Sha256>;

fn main() {
    divan::main();
}

fn hashed_point(index: u64) -> G {
    <G as FromHash<PointHash>>::from_hash(POINT_DOMAIN, &index.to_le_bytes())
}

/// A small, typical two-witness commitment relation.
fn pedersen_commitment() -> LinearRelation<G> {
    let mut relation = LinearRelation::<G>::new();
    let [message, blind] = relation.allocate_scalars();
    let generator = relation.generator();
    let h = relation.allocate_element_with(hashed_point(7));
    relation.allocate_eq(message * generator + blind * h);
    relation
        .compute_image(&[Scalar::from(11u64), Scalar::from(13u64)])
        .unwrap();
    relation
}

/// One very wide equation exercises term conversion and element collection.
fn wide_equation() -> LinearRelation<G> {
    let mut relation = LinearRelation::<G>::new();
    let scalars = relation.allocate_scalars_vec(WIDE_TERMS);
    let elements = (0..WIDE_TERMS)
        .map(|i| relation.allocate_element_with(hashed_point((i + 2) as u64)))
        .collect::<Vec<_>>();
    let rhs: LinearCombination<G> = scalars
        .into_iter()
        .zip_eq(elements)
        .map(|(scalar, element)| scalar * element)
        .collect();
    relation.allocate_eq(rhs);

    let witness = (0..WIDE_TERMS)
        .map(|i| Scalar::from((i % 31 + 1) as u64))
        .collect::<Vec<_>>();
    relation.compute_image(&witness).unwrap();
    relation
}

/// Many narrow equations exercise per-equation image and term construction.
fn many_equations() -> LinearRelation<G> {
    let mut relation = LinearRelation::<G>::new();
    let generator = relation.generator();
    let scalars = relation.allocate_scalars_vec(MANY_EQUATIONS);
    for &scalar in &scalars {
        relation.allocate_eq(scalar * generator);
    }

    let witness = (0..MANY_EQUATIONS)
        .map(|i| Scalar::from((i + 1) as u64))
        .collect::<Vec<_>>();
    relation.compute_image(&witness).unwrap();
    relation
}

/// Constant equations are publicly checked and stripped by `compile`; this is
/// the normalization-heavy path. A final witness equation keeps the compiled
/// instance non-empty.
fn normalization_heavy() -> LinearRelation<G> {
    let mut relation = LinearRelation::<G>::new();
    let element_values = (0..CONSTANT_TERMS)
        .map(|i| hashed_point((i + 2) as u64))
        .collect::<Vec<_>>();
    let elements = element_values
        .iter()
        .copied()
        .map(|element| relation.allocate_element_with(element))
        .collect::<Vec<_>>();

    for equation in 0..CONSTANT_EQUATIONS {
        let mut lhs = G::identity();
        let rhs: LinearCombination<G> = elements
            .iter()
            .enumerate()
            .map(|(term, &element)| {
                let coefficient = Scalar::from(((equation + term) % 31 + 1) as u64);
                lhs += element_values[term] * coefficient;
                element * coefficient
            })
            .collect();
        relation.allocate_eq_with(lhs, rhs);
    }

    let witness = Scalar::from(11u64);
    let scalar = relation.allocate_scalar();
    let generator = relation.generator();
    relation.allocate_eq_with(G::generator() * witness, scalar * generator);
    relation
}

fn bench_compile(bencher: Bencher, make_relation: fn() -> LinearRelation<G>) {
    let relation = make_relation();
    bencher.bench(|| {
        let instance = black_box(&relation).compile().unwrap();
        black_box(instance)
    });
}

macro_rules! compile_benchmark {
    ($module:ident, $fixture:ident) => {
        mod $module {
            use super::*;

            #[divan::bench]
            fn compile(bencher: Bencher) {
                bench_compile(bencher, $fixture);
            }
        }
    };
}

compile_benchmark!(pedersen_commitment, pedersen_commitment);
compile_benchmark!(wide_equation, wide_equation);
compile_benchmark!(many_equations, many_equations);
compile_benchmark!(normalization_heavy, normalization_heavy);
