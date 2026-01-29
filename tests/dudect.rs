#[allow(unused)]
mod relations;

use std::{
    cmp,
    fmt::Display,
    hint::black_box,
    time::{Duration, Instant},
};

use anyhow::Context;
use curve25519_dalek::{RistrettoPoint as G, Scalar};
use ff::Field;
use group::Group;

use rand::seq::SliceRandom;
use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
use relations::TestRng;
use sigma_proofs::{
    LinearRelation, Nizk,
    codec::Shake128DuplexSponge,
    composition::{ComposedRelation, ComposedWitness},
    linear_relation::{CanonicalLinearRelation, Sum},
    traits::{SigmaProtocol, SigmaProtocolSimulator},
};

/// Maximum value for the max_t value. If the T value is higher, the test will fail.
const T_VALUE_THRESHOLD: f64 = 20.0;
/// Number of samples to take when comparing two distributions.
const SAMPLES: usize = 10000;

mod relation_ct_tests {
    use super::*;

    macro_rules! relation_ct_test {
        ($name:ident) => {
            #[test]
            fn $name() {
                set_core_affinity().ok();
                let stats = compare::<CanonicalLinearRelation<G>>(
                    relations::$name.distribution(&mut rand::thread_rng()),
                    relations::$name.distribution(&mut FixedRng),
                );
                println!("test {}: {stats}", stringify!($name));
                assert!(stats.max_t.abs() < T_VALUE_THRESHOLD);
            }
        };
    }

    relation_ct_test!(discrete_logarithm);
    relation_ct_test!(shifted_dlog);
    relation_ct_test!(dleq);
    relation_ct_test!(shifted_dleq);
    relation_ct_test!(pedersen_commitment);
    relation_ct_test!(twisted_pedersen_commitment);
    relation_ct_test!(pedersen_commitment_equality);
    relation_ct_test!(bbs_blind_commitment);
    relation_ct_test!(test_range);
    relation_ct_test!(weird_linear_combination);
    relation_ct_test!(simple_subtractions);
    relation_ct_test!(subtractions_with_shift);
    relation_ct_test!(cmz_wallet_spend_relation);
    relation_ct_test!(nested_affine_relation);
    relation_ct_test!(elgamal_subtraction);
}

#[test]
#[ignore = "used to establish a baseline noise on a given system"]
fn baseline() {
    set_core_affinity().ok();
    let stats = compare::<CanonicalLinearRelation<G>>(
        relations::pedersen_commitment.distribution(&mut rand::thread_rng()),
        relations::pedersen_commitment.distribution(&mut rand::thread_rng()),
    );
    println!("baseline: {stats}");
    assert!(stats.max_t.abs() < T_VALUE_THRESHOLD);
}

fn wide_relation<const WIDTH: usize>(
    rng: &mut (impl TestRng<G> + ?Sized),
) -> (CanonicalLinearRelation<G>, Vec<Scalar>) {
    let mut rel = LinearRelation::<G>::new();
    let constraint: Sum<_> = (0..WIDTH)
        .map(|_| rel.allocate_scalar() * rel.allocate_element_with(rng.random_elem()))
        .sum();
    let _ = rel.allocate_eq(constraint);

    let wit: Vec<_> = (0..WIDTH).map(|_| rng.random_scalar()).collect();
    rel.compute_image(&wit).unwrap();
    (rel.try_into().unwrap(), wit)
}

#[test]
fn test_composition_left_right() {
    set_core_affinity().ok();
    let stats = compare(
        or(falsify(relations::pedersen_commitment), wide_relation::<16>)
            .distribution(&mut rand::thread_rng()),
        or(falsify(relations::pedersen_commitment), wide_relation::<16>)
            .distribution(&mut FixedRng),
    );
    println!("test_composition: {stats}");
    assert!(stats.max_t.abs() < T_VALUE_THRESHOLD);
}

fn compare<P: SigmaProtocol>(
    mut left: impl InstanceDist<Protocol = P>,
    mut right: impl InstanceDist<Protocol = P>,
) -> CtSummary {
    let (left_times, right_times): (Vec<u64>, Vec<u64>) = (0..SAMPLES)
        .map(|_| {
            (
                time_prove(left()).as_nanos() as u64,
                time_prove(right()).as_nanos() as u64,
            )
        })
        .collect();

    ct_stats(&left_times, &right_times)
}

/// Time the call to [Nizk::prove_compact] with the given relation and witness.
#[inline(never)]
fn time_prove<P>((rel, wit): (P, P::Witness)) -> Duration
where
    P: SigmaProtocol<Challenge = Scalar> + SigmaProtocolSimulator,
{
    // NOTE: Creating a new RNG here was found to be important, compared to using `rand::thread_rng`
    // directly, when the instance generation uses `rand::thread_rng`. Otherwise caching behavior
    // leads to false positive timing variance.
    let mut rng = ChaCha12Rng::from_rng(rand::thread_rng()).unwrap();
    let nizk = Nizk::<_, Shake128DuplexSponge<G>>::new(b"sigma-proofs-dudect-test", rel);

    let start = Instant::now();
    let _ = black_box(nizk.prove_compact(&wit, &mut rng));
    start.elapsed()
}

/// A [TestRng] implementation that returns random values for group elements, but always returns a
/// fixed value for scalars. Used with [relations], this generates statements with fixed-value
/// witnesses.
struct FixedRng;

impl<G: Group> TestRng<G> for FixedRng {
    fn random_elem(&mut self) -> G {
        G::random(&mut rand::thread_rng())
    }

    fn random_scalar(&mut self) -> <G as Group>::Scalar {
        G::Scalar::ONE
    }
}

/// Set the current thread's core affinity to a random core.
///
/// This discourages the OS from switching witch thread the test is running on in the middle of the
/// test, providing some decrease in the amount of noise.
fn set_core_affinity() -> anyhow::Result<()> {
    let core_ids = core_affinity2::get_core_ids().context("Failed to get core IDs")?;

    let Some(core_id) = core_ids.choose(&mut rand::thread_rng()) else {
        anyhow::bail!("No core IDs available");
    };
    core_id
        .set_affinity_forced()
        .context("Failed to set affinity for core {core_id:?}")
}

trait FalsifyWitness {
    fn falsify(self) -> Self;
}

impl FalsifyWitness for Vec<Scalar> {
    fn falsify(self) -> Self {
        // Assumes that the zero-witness is false for all relations.
        // This is not strictly true, since you can have trivial relation for which the zero
        // witness if valid.
        (0..self.len()).map(|_| Scalar::ZERO).collect()
    }
}

impl FalsifyWitness for ComposedWitness<G> {
    fn falsify(self) -> Self {
        match self {
            ComposedWitness::Simple(wit) => ComposedWitness::Simple(wit.falsify()),
            ComposedWitness::And(items) => ComposedWitness::And(items.falsify()),
            ComposedWitness::Or(items) => ComposedWitness::Or(items.falsify()),
            ComposedWitness::Threshold(items) => ComposedWitness::Threshold(items.falsify()),
        }
    }
}

impl FalsifyWitness for Vec<ComposedWitness<G>> {
    fn falsify(self) -> Self {
        self.into_iter().map(|x| x.falsify()).collect()
    }
}

/// Transform an [InstanceFn] by falsifying the generated witness data. This can be used in an or
/// composition to create false branches.
fn falsify<R: ?Sized, F: InstanceFn<R>>(f: F) -> impl InstanceFn<R, Protocol = F::Protocol>
where
    <F::Protocol as SigmaProtocol>::Witness: FalsifyWitness,
{
    move |rng| {
        let (rel, wit) = f(rng);
        (rel, wit.falsify())
    }
}

fn or<R: ?Sized, FL, FR>(left: FL, right: FR) -> impl InstanceFn<R, Protocol = ComposedRelation<G>>
where
    FL: InstanceFn<R>,
    FR: InstanceFn<R>,
    FL::Protocol: Into<ComposedRelation<G>>,
    FR::Protocol: Into<ComposedRelation<G>>,
    <FL::Protocol as SigmaProtocol>::Witness: Into<ComposedWitness<G>>,
    <FR::Protocol as SigmaProtocol>::Witness: Into<ComposedWitness<G>>,
{
    move |rng| {
        let (left_rel, left_wit) = left(rng);
        let (right_rel, right_wit) = right(rng);
        (
            ComposedRelation::or([left_rel.into(), right_rel.into()]),
            ComposedWitness::or([left_wit.into(), right_wit.into()]),
        )
    }
}

trait InstanceFn<R: ?Sized>:
    Fn(&mut R) -> (Self::Protocol, <Self::Protocol as SigmaProtocol>::Witness)
{
    type Protocol: SigmaProtocol<Challenge = Scalar> + SigmaProtocolSimulator;

    fn distribution(self, rng: &mut R) -> impl InstanceDist<Protocol = Self::Protocol>
    where
        Self: Sized,
    {
        move || (self)(rng)
    }
}

trait InstanceDist: FnMut() -> (Self::Protocol, <Self::Protocol as SigmaProtocol>::Witness) {
    type Protocol: SigmaProtocol<Challenge = Scalar> + SigmaProtocolSimulator;
}

impl<R: ?Sized, F, P> InstanceFn<R> for F
where
    P: SigmaProtocol<Challenge = Scalar> + SigmaProtocolSimulator,
    F: Fn(&mut R) -> (P, P::Witness),
{
    type Protocol = P;
}

impl<F, P> InstanceDist for F
where
    P: SigmaProtocol<Challenge = Scalar> + SigmaProtocolSimulator,
    F: FnMut() -> (P, P::Witness),
{
    type Protocol = P;
}

// The following code is copied from the dudect_bencher, then modified here.
//
// Copyright 2012 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct CtSummary {
    pub max_t: f64,
    pub max_tau: f64,
    pub sample_size: usize,
}

impl Display for CtSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let &CtSummary {
            max_t,
            max_tau,
            sample_size,
        } = self;
        write!(
            f,
            "n == {:+0.3}M, max t = {:+0.5}, max tau = {:+0.5}, (5/tau)^2 = {}",
            (sample_size as f64) / 1_000_000f64,
            max_t,
            max_tau,
            (5f64 / max_tau).powi(2) as usize
        )
    }
}

#[derive(Copy, Clone, Debug, Default)]
struct CtTest {
    means: (f64, f64),
    sq_diffs: (f64, f64),
    sizes: (usize, usize),
}

// NaNs are smaller than everything
fn local_cmp(x: f64, y: f64) -> cmp::Ordering {
    use std::cmp::Ordering::{Equal, Greater, Less};
    if y.is_nan() {
        Greater
    } else if x.is_nan() || x < y {
        Less
    } else if x == y {
        Equal
    } else {
        Greater
    }
}

/// Helper function: extract a value representing the `pct` percentile of a sorted sample-set,
/// using linear interpolation. If samples are not sorted, return nonsensical value.
fn percentile_of_sorted(sorted_samples: &[f64], pct: f64) -> f64 {
    assert!(!sorted_samples.is_empty());
    if sorted_samples.len() == 1 {
        return sorted_samples[0];
    }
    let zero = 0f64;
    assert!(zero <= pct);
    let hundred = 100f64;
    assert!(pct <= hundred);
    let length = (sorted_samples.len() - 1) as f64;
    let rank = (pct / hundred) * length;
    let lrank = rank.floor();
    let d = rank - lrank;
    let n = lrank as usize;
    let lo = sorted_samples[n];
    let hi = sorted_samples[n + 1];
    lo + (hi - lo) * d
}

/// Return the percentiles at f(1), f(2), ..., f(100) of the runtime distribution, where
/// `f(k) = 1 - 0.5^(10k / 100)`
pub fn prepare_percentiles(durations: &[u64]) -> Vec<f64> {
    let sorted: Vec<f64> = {
        let mut v = durations.to_vec();
        v.sort();
        v.into_iter().map(|d| d as f64).collect()
    };

    // Collect all the percentile values
    (0..100)
        .map(|i| {
            let pct = {
                let exp = f64::from(10 * (i + 1)) / 100f64;
                1f64 - 0.5f64.powf(exp)
            };
            percentile_of_sorted(&sorted, 100f64 * pct)
        })
        .collect()
}

pub fn ct_stats(left_samples: &[u64], right_samples: &[u64]) -> CtSummary {
    // Only construct the context (that is, percentiles and test structs) on the first run
    let (mut tests, percentiles) = {
        let all_samples = {
            let mut v = left_samples.to_vec();
            v.extend_from_slice(right_samples);
            v
        };
        let pcts = prepare_percentiles(&all_samples);
        let tests = vec![CtTest::default(); 101];

        (tests, pcts)
    };

    let left_samples: Vec<f64> = left_samples.iter().map(|&n| n as f64).collect();
    let right_samples: Vec<f64> = right_samples.iter().map(|&n| n as f64).collect();

    for &left_sample in left_samples.iter() {
        update_test_left(&mut tests[0], left_sample);
    }
    for &right_sample in right_samples.iter() {
        update_test_right(&mut tests[0], right_sample);
    }

    for (test, &pct) in tests.iter_mut().skip(1).zip(percentiles.iter()) {
        let left_cropped = left_samples.iter().filter(|&&x| x < pct);
        let right_cropped = right_samples.iter().filter(|&&x| x < pct);

        for &left_sample in left_cropped {
            update_test_left(test, left_sample);
        }
        for &right_sample in right_cropped {
            update_test_right(test, right_sample);
        }
    }

    let (max_t, max_tau, sample_size) = {
        // Get the test with the maximum t
        let max_test = tests
            .iter()
            .max_by(|&x, &y| local_cmp(compute_t(x).abs(), compute_t(y).abs()))
            .unwrap();
        let sample_size = max_test.sizes.0 + max_test.sizes.1;
        let max_t = compute_t(max_test);
        let max_tau = max_t / (sample_size as f64).sqrt();

        (max_t, max_tau, sample_size)
    };

    CtSummary {
        max_t,
        max_tau,
        sample_size,
    }
}

fn compute_t(test: &CtTest) -> f64 {
    let &CtTest {
        means,
        sq_diffs,
        sizes,
    } = test;
    let num = means.0 - means.1;
    let n0 = sizes.0 as f64;
    let n1 = sizes.1 as f64;
    let var0 = sq_diffs.0 / (n0 - 1f64);
    let var1 = sq_diffs.1 / (n1 - 1f64);
    let den = (var0 / n0 + var1 / n1).sqrt();

    num / den
}

fn update_test_left(test: &mut CtTest, datum: f64) {
    test.sizes.0 += 1;
    let diff = datum - test.means.0;
    test.means.0 += diff / (test.sizes.0 as f64);
    test.sq_diffs.0 += diff * (datum - test.means.0);
}

fn update_test_right(test: &mut CtTest, datum: f64) {
    test.sizes.1 += 1;
    let diff = datum - test.means.1;
    test.means.1 += diff / (test.sizes.1 as f64);
    test.sq_diffs.1 += diff * (datum - test.means.1);
}
