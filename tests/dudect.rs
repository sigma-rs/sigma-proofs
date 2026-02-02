//! Statistical testing for constant-timedness of proving with respect to secret witness data,
//! based on [dudect](https://github.com/oreparaz/dudect)
//!
//! To run this test and print the observed statistics, you can use the following command:
//!
//! ```sh
//! DUDECT_SAMPLES=10000 cargo test --test dudect -- --nocapture --test-threads=1
//! ```
//!
//! This will run all of the tests with 10k samples each. You can specify more or fewer samples as
//! desired. `--nocapture` ensures the computed statistics are printed to the terminal.
//! `--test-threads=1` avoids warnings about tests taking too long. The tests in this module always
//! run in serial to reduce noise.
//!
//! By default, when DUDECT_SAMPLES is not set, the tests here use a small number of samples. This
//! serves as a "smoke-test" in that it ensures the test harness still runs, and would catch
//! egregious violations of constant-timedness. It is, however, insufficient to detect smaller
//! differences.

mod relations;

use core::{array::from_fn, iter::repeat_with};
use std::{
    hint::black_box,
    sync::LazyLock,
    time::{Duration, Instant},
};

use curve25519_dalek::{RistrettoPoint as G, Scalar};
use group::{ff::Field, Group};

use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};
use serial_test::serial;
use sigma_proofs::{
    composition::{ComposedRelation, ComposedWitness},
    linear_relation::{CanonicalLinearRelation, Sum},
    traits::{Prng, SigmaProtocol, SigmaProtocolSimulator},
    LinearRelation, Nizk,
};

use crate::stats::{ct_stats, CtSummary};

/// Maximum value for the max_t value. If the T value is higher, the test will fail.
const T_VALUE_THRESHOLD: f64 = 20.0;
/// Number of samples to take when comparing two distributions.
static SAMPLES: LazyLock<usize> = LazyLock::new(|| match std::env::var("DUDECT_SAMPLES") {
    Ok(string) => string
        .parse::<usize>()
        .expect("DUDECT_SAMPLES env var is not a valid count"),
    Err(std::env::VarError::NotPresent) => 100,
    Err(std::env::VarError::NotUnicode(_)) => panic!("DUDECT_SAMPLES env var is not unicode"),
});

mod relation_ct_tests {
    use super::*;

    macro_rules! relation_ct_test {
        ($name:ident) => {
            #[test]
            #[serial]
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

/// Test to establish a baseline noise on a given system, other tests are likely to fail with false
/// positives as well.
#[test]
#[serial]
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
    rng: &mut impl Prng,
) -> (CanonicalLinearRelation<G>, Vec<Scalar>) {
    let mut rel = LinearRelation::<G>::new();
    let constraint: Sum<_> = (0..WIDTH)
        .map(|_| rel.allocate_scalar() * rel.allocate_element_with(relations::random_elem(rng)))
        .sum();
    let _ = rel.allocate_eq(constraint);

    let wit = rng.random_scalars::<G, WIDTH>();
    rel.compute_image(&wit).unwrap();
    (rel.try_into().unwrap(), wit.to_vec())
}

/// Create two OR composition instances, one with the left branch false and one with the right
/// branch false, along with the used of [FixedRng] to check for basic constant-timedness.
#[test]
#[serial]
fn test_ct_or_composition() {
    set_core_affinity().ok();
    let stats = compare(
        or(relations::pedersen_commitment, falsify(wide_relation::<16>))
            .distribution(&mut rand::thread_rng()),
        or(falsify(relations::pedersen_commitment), wide_relation::<16>)
            .distribution(&mut FixedRng),
    );
    println!("test_composition: {stats}");
    assert!(stats.max_t.abs() < T_VALUE_THRESHOLD);
}

fn compare<P: SigmaProtocol<Challenge = Scalar> + SigmaProtocolSimulator>(
    mut left: impl InstanceDist<Protocol = P>,
    mut right: impl InstanceDist<Protocol = P>,
) -> CtSummary {
    let (left_times, right_times): (Vec<u64>, Vec<u64>) = (0..*SAMPLES)
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
    let nizk = Nizk::new(b"sigma-proofs-dudect-test", rel);

    let start = Instant::now();
    let _ = black_box(nizk.prove_compact(&wit, &mut rng));
    start.elapsed()
}

/// A [TestRng] implementation that returns random values for group elements, but always returns a
/// fixed value for scalars. Used with [relations], this generates statements with fixed-value
/// witnesses.
struct FixedRng;

impl Prng for FixedRng {
    fn random_scalars<G: Group, const N: usize>(&mut self) -> [G::Scalar; N] {
        from_fn(|_| <G::Scalar as Field>::ONE)
    }

    fn random_scalars_vec<G: Group>(&mut self, n: usize) -> Vec<G::Scalar> {
        repeat_with(|| <G::Scalar as Field>::ONE).take(n).collect()
    }
}

/// Set the current thread's core affinity to a random core.
///
/// This discourages the OS from switching witch thread the test is running on in the middle of the
/// test, providing some decrease in the amount of noise.
#[cfg(not(target_arch = "wasm32"))]
fn set_core_affinity() -> anyhow::Result<()> {
    use anyhow::Context;
    use rand::seq::SliceRandom;

    let core_ids = core_affinity2::get_core_ids().context("Failed to get core IDs")?;

    let Some(core_id) = core_ids.choose(&mut rand::thread_rng()) else {
        anyhow::bail!("No core IDs available");
    };
    core_id
        .set_affinity_forced()
        .context("Failed to set affinity for core {core_id:?}")
}

#[cfg(target_arch = "wasm32")]
fn set_core_affinity() -> anyhow::Result<()> {
    anyhow::bail!("set_core_affinity not supported in WASM")
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

mod stats {
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

    use std::{cmp, fmt::Display};

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
}
