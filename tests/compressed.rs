//! Compressed Σ-protocols: completeness, soundness, and verifier totality.
//!
//! The claim under test is that `Compressed` proves exactly the statements
//! `Instance` describes, at a NARG string logarithmic in the witness length,
//! and that its verifier is total on arbitrary bytes
//! (`docs/threat-model.md` §2.1).

use curve25519_dalek::RistrettoPoint as G;
use group::Group;
use spongefish::{Narg, SessionId};

use sigma_proofs::codec::{GroupCodec, ScalarCodec};
use sigma_proofs::compressed::Compressed;
use sigma_proofs::linear_relation::{Equation, Instance, Sum};
use sigma_proofs::{LinearRelation, ProverRng};

type S = <G as Group>::Scalar;

const SESSION: SessionId = SessionId::from_bytes(*b"sigma-proofs compressed tests !!");

/// An inner-product statement `image = <witness, bases>` over `n` scalars,
/// spread across `equations` equations so that the squashing step is exercised
/// for more than one row.
fn relation(n: usize, equations: usize, rng: &mut ProverRng) -> (Instance<G>, Vec<S>) {
    let mut relation = LinearRelation::<G>::new();
    let scalars = relation.allocate_scalars_vec(n);
    let bases: Vec<_> = (0..n)
        .map(|_| relation.allocate_element_with(G::generator() * S::sample(rng)))
        .collect();

    // Each equation takes a contiguous slice of the scalars, so every scalar
    // is used and `num_scalars` is `n`.
    let per = n.div_ceil(equations);
    for chunk in scalars.chunks(per) {
        let lc: Sum<_> = chunk
            .iter()
            .map(|x| {
                let i = scalars.iter().position(|s| s == x).expect("allocated");
                *x * bases[i]
            })
            .sum();
        relation.allocate_eq(lc);
    }

    let witness: Vec<S> = (0..n).map(|_| S::sample(rng)).collect();
    let instance = relation.compile_with_witness(&witness).unwrap();
    (instance, witness)
}

#[test]
fn multiple_equations_are_squashed() {
    let mut rng = ProverRng::from_os_entropy();
    // Single-equation completeness is covered by the exact round-count test.
    // These cases exercise squashing different numbers of rows instead.
    for (n, equations) in [(2usize, 2usize), (5, 2), (9, 3)] {
        let (instance, witness) = relation(n, equations, &mut rng);
        let (proof, ()) =
            Narg::prove_with_session_id::<Compressed<G>>(&SESSION, &instance, &witness).unwrap();
        assert!(
            Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &proof).is_ok(),
            "n = {n}, equations = {equations}"
        );
    }
}

#[test]
fn unused_scalar_slots_are_projected_out() {
    let one = S::ONE;
    let equation = Equation {
        image: vec![(1, one)],
        terms: vec![(2, 1, one)],
    };
    let instance = Instance::<G>::new(vec![], vec![equation]).unwrap();
    let witness = vec![S::from(7u64), S::from(8u64), one];

    let (proof, ()) =
        Narg::prove_with_session_id::<Compressed<G>>(&SESSION, &instance, &witness).unwrap();
    assert!(Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &proof).is_ok());
    assert_eq!(proof.len(), G::element_len() + S::scalar_len());
}

#[test]
#[cfg(target_pointer_width = "64")]
fn a_large_sparse_scalar_index_does_not_drive_verifier_allocation() {
    let one = S::ONE;
    let equation = Equation {
        image: vec![(1, one)],
        terms: vec![(u32::MAX, 1, one)],
    };
    let instance = Instance::<G>::new(vec![], vec![equation]).unwrap();

    // The verifier reaches squashing before it reads the proof. This small
    // input must reject without allocating `num_scalars()` group elements.
    assert!(Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &[]).is_err());
}

/// The round count is `⌈log2(n)⌉` for every `n`, not only for the powers of
/// two: halves that differ by one reach a single generator in the same number
/// of rounds that padding up to a power of two would have taken, so the odd
/// widths cost nothing in proof size.
#[test]
fn the_round_count_is_the_ceiling_of_the_logarithm() {
    let mut rng = ProverRng::from_os_entropy();
    for n in 1usize..=17 {
        let (instance, witness) = relation(n, 1, &mut rng);
        let (proof, ()) =
            Narg::prove_with_session_id::<Compressed<G>>(&SESSION, &instance, &witness).unwrap();

        // The nonce commitment, two elements per fold round, and the opening.
        let rounds = n.next_power_of_two().trailing_zeros() as usize;
        assert_eq!(
            proof.len(),
            (1 + 2 * rounds) * G::element_len() + S::scalar_len(),
            "n = {n}"
        );
        assert!(
            Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &proof).is_ok(),
            "n = {n}"
        );
    }
}

/// What the blinding round buys: the folded opening is the response, not the
/// witness.
///
/// At `n = 1` there is nothing to fold, so the whole proof is the nonce
/// commitment and one scalar — which is where an unblinded protocol would put
/// the witness itself, in the clear. It must be neither the witness nor the
/// same twice, since the nonces are drawn afresh for each proof.
#[test]
fn the_opening_is_blinded() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = relation(1, 1, &mut rng);

    let (proof, ()) =
        Narg::prove_with_session_id::<Compressed<G>>(&SESSION, &instance, &witness).unwrap();
    let (again, ()) =
        Narg::prove_with_session_id::<Compressed<G>>(&SESSION, &instance, &witness).unwrap();
    assert!(Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &proof).is_ok());
    assert!(Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &again).is_ok());
    assert_ne!(proof, again, "each proof draws its own nonces");

    let mut encoded = Vec::new();
    witness[0].serialize_scalar(&mut encoded);
    let opening = &proof[proof.len() - S::scalar_len()..];
    assert_ne!(opening, encoded, "the opening must not be the witness");
}

#[test]
fn a_wrong_witness_does_not_verify() {
    let mut rng = ProverRng::from_os_entropy();
    // An odd width as well as a power of two: the fold that leaves an entry
    // unpaired must be no less binding than the one that does not.
    for n in [5usize, 8] {
        let (instance, mut witness) = relation(n, 2, &mut rng);
        witness[3] += S::ONE;

        // Two outcomes are correct here, and which one occurs is a build
        // property rather than a protocol one. `Transcript::check` runs the
        // verification equation on the prover too when debug assertions are
        // on, as a completeness self-test, so the prover refuses; in a release
        // build the equation is never evaluated on that side and the prover
        // emits a NARG string that the verifier then rejects. What must never
        // happen is an accepted proof.
        match Narg::prove_with_session_id::<Compressed<G>>(&SESSION, &instance, &witness) {
            Ok((proof, ())) => {
                assert!(
                    Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &proof)
                        .is_err()
                )
            }
            // `cfg!` folds to a constant, which is the point: on a release
            // build this arm must be unreachable, and clippy would rather see
            // the constant spelled out than asserted.
            #[cfg(debug_assertions)]
            Err(_) => {}
            #[cfg(not(debug_assertions))]
            Err(_) => panic!("a release-build prover has no verification equation to fail"),
        }
    }
}

#[test]
fn the_proof_is_bound_to_its_session_and_instance() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = relation(8, 1, &mut rng);
    let (other, _) = relation(8, 1, &mut rng);
    let (proof, ()) =
        Narg::prove_with_session_id::<Compressed<G>>(&SESSION, &instance, &witness).unwrap();

    let mut elsewhere = *SESSION.as_bytes();
    elsewhere[0] ^= 1;
    let elsewhere = SessionId::from_bytes(elsewhere);
    assert!(Narg::verify_with_session_id::<Compressed<G>>(&elsewhere, &instance, &proof).is_err());
    assert!(Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &other, &proof).is_err());
}

/// §2.1: no byte string makes the verifier panic, and none but the honest
/// proof is accepted.
#[test]
fn corrupted_proofs_are_rejected_without_panicking() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = relation(8, 2, &mut rng);
    let (proof, ()) =
        Narg::prove_with_session_id::<Compressed<G>>(&SESSION, &instance, &witness).unwrap();
    assert!(Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &proof).is_ok());

    for i in 0..proof.len() * 8 {
        let mut corrupted = proof.clone();
        corrupted[i / 8] ^= 1 << (i % 8);
        assert!(
            Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &corrupted).is_err(),
            "should reject: bit {i} flipped"
        );
    }

    // Truncations, extensions, and arbitrary strings, including the ones that
    // are not a whole number of elements long.
    for len in 0..=proof.len() {
        let _ = Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &proof[..len]);
    }
    for extra in 1..=8 {
        let mut extended = proof.clone();
        extended.extend(core::iter::repeat_n(0u8, extra));
        assert!(
            Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &extended).is_err(),
            "trailing bytes must be rejected"
        );
    }
    for bytes in [vec![], vec![0u8; 1], vec![0xff; 200], vec![0x05; 33]] {
        let _ = Narg::verify_with_session_id::<Compressed<G>>(&SESSION, &instance, &bytes);
    }
}
