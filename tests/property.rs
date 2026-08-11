//! Property-based tests.
//!
//! The suites elsewhere pin specific relations and specific proofs. These
//! quantify instead: over *every* relation shape the generator can build, and
//! over *every* corruption of a valid proof it can describe, the library must
//! keep the invariants of `docs/threat-model.md`.
//!
//! Two of those invariants get most of the attention here, because they are
//! the ones an adversary reaches:
//!
//! - **Verifier totality** (§2.1): no byte string makes a verifier panic. The
//!   corruption strategies below stand in for a fuzzer — they are directed by
//!   the proof's own structure, so they hit the parser at boundaries that
//!   uniform random bytes essentially never reach.
//! - **Soundness**: no corruption of a valid proof yields another accepted
//!   one, and no proof verifies under a tag or an instance it was not made
//!   for.
//!
//! Cases are kept modest so this stays a pull-request-time suite; the failing
//! seed is printed and can be replayed with `PROPTEST_CASES` turned up.

use curve25519_dalek::RistrettoPoint;
use group::Group;
use proptest::prelude::*;

use sigma_proofs::codec::ScalarCodec;
use sigma_proofs::linear_relation::{Instance, LinearCombination, LinearRelation};
use sigma_proofs::msm::{straus_ct, straus_vartime};
use sigma_proofs::{
    prove_batchable, prove_compact, verify_batchable, verify_compact, MultiScalarMul, ProverRng,
};

type G = RistrettoPoint;
type S = <RistrettoPoint as Group>::Scalar;

const BATCH_TAG: &[u8] = b"sigma-proofs property tests DSFS";
const COMPACT_TAG: &[u8] = b"sigma-proofs property tests CMPT";

// -- generating relations ----------------------------------------------------

/// The shape of a linear relation, independent of any group.
///
/// Only the shape is generated: the witness and the group elements are drawn
/// from the seeded prover RNG, so a shrunk counterexample stays reproducible
/// without carrying scalars through the strategy.
#[derive(Clone, Debug)]
struct Shape {
    num_scalars: usize,
    num_elements: usize,
    /// One entry per equation: the `(scalar_var, element_var)` terms summed on
    /// its right-hand side.
    equations: Vec<Vec<(usize, usize)>>,
}

/// Shapes are deliberately small and dense: the interesting cases are
/// repeated scalars, repeated elements, and several terms folding onto the
/// same element, none of which need size to appear.
///
/// Generated shapes are repaired to use every scalar they allocate.
/// `Instance::num_scalars` is `1 + max(scalar_index)` over the terms, so a
/// scalar allocated but never used simply shrinks the instance's arity, and
/// the witness would no longer match it — an artifact of the generator, not a
/// property of the library, and one that would otherwise mask real failures.
fn shape_strategy() -> impl Strategy<Value = Shape> {
    (1usize..4, 1usize..4).prop_flat_map(|(num_scalars, num_elements)| {
        let term = (0..num_scalars, 0..num_elements);
        let equation = prop::collection::vec(term, 1..4);
        prop::collection::vec(equation, 1..3).prop_map(move |mut equations| {
            for scalar in 0..num_scalars {
                let used = equations.iter().flatten().any(|&(s, _)| s == scalar);
                if !used {
                    // Appended to the last equation, so the repair is a
                    // function of the generated value and shrinking stays
                    // deterministic.
                    equations
                        .last_mut()
                        .expect("at least one equation")
                        .push((scalar, scalar % num_elements));
                }
            }
            Shape {
                num_scalars,
                num_elements,
                equations,
            }
        })
    })
}

/// Builds the relation the shape describes and solves it for a random witness.
///
/// Returns `None` when the shape compiles to an instance the specification
/// rejects — an equation whose image is the identity, most often, which
/// happens whenever the terms of an equation cancel. That is a valid outcome,
/// not a failure: it is the library refusing to make a degenerate statement.
fn build(shape: &Shape, rng: &mut ProverRng) -> Option<(Instance<G>, Vec<S>)> {
    let mut relation = LinearRelation::<G>::new();
    let scalar_vars = relation.allocate_scalars_vec(shape.num_scalars);
    let element_vars: Vec<_> = (0..shape.num_elements)
        .map(|_| relation.allocate_element_with(G::generator() * S::sample(rng)))
        .collect();

    for equation in &shape.equations {
        let lc: LinearCombination<G> = equation
            .iter()
            .map(|&(s, e)| (scalar_vars[s], element_vars[e]))
            .collect();
        relation.allocate_eq(lc);
    }

    let witness: Vec<S> = (0..shape.num_scalars).map(|_| S::sample(rng)).collect();
    let instance = relation.compile_with_witness(&witness).ok()?;
    Some((instance, witness))
}

fn seeded_rng(seed: [u8; 32]) -> ProverRng {
    ProverRng::from_seed(seed)
}

// -- soundness and completeness ---------------------------------------------

/// Well above proptest's default of 256. A full pass over every property
/// here costs well under a second, so the default buys coverage for nothing;
/// the nightly workflow raises it much further with `PROPTEST_CASES`, which
/// overrides this.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1024,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// Completeness: whatever the shape, a proof made from a satisfying
    /// witness verifies.
    #[test]
    fn honest_proofs_verify(shape in shape_strategy(), seed: [u8; 32]) {
        let mut rng = seeded_rng(seed);
        let Some((instance, witness)) = build(&shape, &mut rng) else { return Ok(()) };

        let batchable = prove_batchable(BATCH_TAG, &instance, &witness).unwrap();
        let compact = prove_compact(COMPACT_TAG, &instance, &witness).unwrap();
        prop_assert!(verify_batchable(BATCH_TAG, &instance, &batchable).is_ok());
        prop_assert!(verify_compact(COMPACT_TAG, &instance, &compact).is_ok());
    }

    /// Domain separation: the proof is bound to its tag. A verifier holding
    /// the right instance and the right proof, but a different tag, rejects.
    #[test]
    fn proofs_are_bound_to_their_tag(
        shape in shape_strategy(),
        seed: [u8; 32],
        other_tag in prop::collection::vec(any::<u8>(), 0..40),
    ) {
        prop_assume!(other_tag != BATCH_TAG);
        let mut rng = seeded_rng(seed);
        let Some((instance, witness)) = build(&shape, &mut rng) else { return Ok(()) };

        let proof = prove_batchable(BATCH_TAG, &instance, &witness).unwrap();
        prop_assert!(verify_batchable(&other_tag, &instance, &proof).is_err());
    }

    /// The proof is bound to its instance: one made for a *different* relation
    /// of the same shape does not verify, even though it parses.
    #[test]
    fn proofs_are_bound_to_their_instance(
        shape in shape_strategy(),
        seed_a: [u8; 32],
        seed_b: [u8; 32],
    ) {
        prop_assume!(seed_a != seed_b);
        let mut rng_a = seeded_rng(seed_a);
        let mut rng_b = seeded_rng(seed_b);
        let Some((instance_a, witness_a)) = build(&shape, &mut rng_a) else { return Ok(()) };
        let Some((instance_b, _)) = build(&shape, &mut rng_b) else { return Ok(()) };

        let proof = prove_batchable(BATCH_TAG, &instance_a, &witness_a).unwrap();
        prop_assert!(verify_batchable(BATCH_TAG, &instance_b, &proof).is_err());
    }
}

// -- verifier totality on corrupted input ------------------------------------

/// How to corrupt a valid proof.
///
/// Structure-directed rather than uniform: flipping one bit of a group
/// element reaches the codec's canonicity checks, and truncating at an
/// arbitrary offset reaches the length handling, whereas random bytes of the
/// right length almost always fail at the first element and exercise nothing
/// past it.
#[derive(Clone, Debug)]
enum Corruption {
    FlipBit { byte: usize, bit: u8 },
    Truncate { len: usize },
    Extend { extra: Vec<u8> },
    SetByte { byte: usize, value: u8 },
    Replace { bytes: Vec<u8> },
}

fn corruption_strategy() -> impl Strategy<Value = Corruption> {
    prop_oneof![
        (any::<usize>(), 0u8..8).prop_map(|(byte, bit)| Corruption::FlipBit { byte, bit }),
        any::<usize>().prop_map(|len| Corruption::Truncate { len }),
        prop::collection::vec(any::<u8>(), 1..8).prop_map(|extra| Corruption::Extend { extra }),
        (any::<usize>(), any::<u8>()).prop_map(|(byte, value)| Corruption::SetByte { byte, value }),
        prop::collection::vec(any::<u8>(), 0..200).prop_map(|bytes| Corruption::Replace { bytes }),
    ]
}

fn corrupt(proof: &[u8], how: &Corruption) -> Vec<u8> {
    let mut out = proof.to_vec();
    match how {
        // `%` against the length, so the generated index is always in range
        // and shrinking stays meaningful for any proof size.
        Corruption::FlipBit { byte, bit } => {
            if !out.is_empty() {
                let i = byte % out.len();
                out[i] ^= 1 << bit;
            }
        }
        Corruption::SetByte { byte, value } => {
            if !out.is_empty() {
                let i = byte % out.len();
                out[i] = *value;
            }
        }
        Corruption::Truncate { len } => {
            let n = len % (out.len() + 1);
            out.truncate(n);
        }
        Corruption::Extend { extra } => out.extend_from_slice(extra),
        Corruption::Replace { bytes } => out = bytes.clone(),
    }
    out
}

proptest! {
    #![proptest_config(config())]

    /// The central claim of §2.1: a verifier handed a corrupted proof returns.
    /// It may accept only if the corruption was a no-op, and it may never
    /// panic — the test harness turns a panic into a failure for us.
    #[test]
    fn corrupted_proofs_are_rejected_without_panicking(
        shape in shape_strategy(),
        seed: [u8; 32],
        how in corruption_strategy(),
    ) {
        let mut rng = seeded_rng(seed);
        let Some((instance, witness)) = build(&shape, &mut rng) else { return Ok(()) };

        for (proof, compact) in [
            (prove_batchable(BATCH_TAG, &instance, &witness).unwrap(), false),
            (prove_compact(COMPACT_TAG, &instance, &witness).unwrap(), true),
        ] {
            let corrupted = corrupt(&proof, &how);
            let accepted = if compact {
                verify_compact(COMPACT_TAG, &instance, &corrupted).is_ok()
            } else {
                verify_batchable(BATCH_TAG, &instance, &corrupted).is_ok()
            };
            prop_assert_eq!(
                accepted,
                corrupted == proof,
                "a proof that differs from the honest one was accepted"
            );
        }
    }

    /// Totality does not depend on the byte string having come from a prover
    /// at all. Arbitrary input, no valid proof anywhere in sight.
    #[test]
    fn arbitrary_bytes_never_verify(
        shape in shape_strategy(),
        seed: [u8; 32],
        bytes in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let mut rng = seeded_rng(seed);
        let Some((instance, _)) = build(&shape, &mut rng) else { return Ok(()) };

        prop_assert!(verify_batchable(BATCH_TAG, &instance, &bytes).is_err());
        prop_assert!(verify_compact(COMPACT_TAG, &instance, &bytes).is_err());
    }
}

// -- multi-scalar multiplication --------------------------------------------

/// `sum(base * scalar)`, the definition the optimized routines must match.
fn naive(scalars: &[S], bases: &[G]) -> G {
    core::iter::zip(bases, scalars).map(|(g, x)| *g * *x).sum()
}

proptest! {
    #![proptest_config(config())]

    /// Every multi-scalar multiplication path agrees with the definition.
    ///
    /// The unit tests in `src/msm.rs` pin the boundary cases the radix-16
    /// recoding cares about; this covers the space between them, and in
    /// particular the constant-time path, whose whole purpose is to reach the
    /// same answer without letting the scalars pick the route.
    #[test]
    fn msm_paths_agree(
        seed: [u8; 32],
        n in 0usize..12,
        small in prop::collection::vec(0u64..32, 0..12),
    ) {
        let mut rng = seeded_rng(seed);

        // A mix of random and small scalars: small ones keep the top digits
        // of the recoding zero, which is where the skip-leading-zeros logic
        // lives.
        let scalars: Vec<S> = (0..n)
            .map(|i| match small.get(i) {
                Some(&k) if k % 2 == 0 => S::from(k),
                _ => S::sample(&mut rng),
            })
            .collect();
        let bases: Vec<G> = (0..n).map(|_| G::generator() * S::sample(&mut rng)).collect();

        let expected = naive(&scalars, &bases);
        prop_assert_eq!(G::msm(&scalars, &bases), expected, "msm");
        prop_assert_eq!(G::msm_vartime(&scalars, &bases), expected, "msm_vartime");
        prop_assert_eq!(straus_ct(&scalars, &bases), expected, "straus_ct");
        prop_assert_eq!(straus_vartime(&scalars, &bases), expected, "straus_vartime");
    }
}

// -- guarding against vacuous properties -------------------------------------

/// The properties above return early when `build` declines a shape, so a
/// generator that mostly declined would let them all pass while testing
/// nothing. This pins the rate down.
#[test]
fn the_generator_mostly_produces_provable_instances() {
    use proptest::strategy::{Strategy as _, ValueTree};
    use proptest::test_runner::TestRunner;

    let mut runner = TestRunner::deterministic();
    let strategy = shape_strategy();
    let mut built = 0;
    let total = 500;

    for i in 0..total {
        let shape = strategy.new_tree(&mut runner).unwrap().current();
        let mut rng = seeded_rng([i as u8; 32]);
        if build(&shape, &mut rng).is_some() {
            built += 1;
        }
    }

    assert!(
        built * 2 > total,
        "only {built}/{total} generated shapes compiled to a provable instance; \
         the properties over them are close to vacuous"
    );
}
