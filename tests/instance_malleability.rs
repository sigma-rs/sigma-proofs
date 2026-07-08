//! Regression test: the instance label must bind every group element of the
//! statement, including elements that appear only in constant (unit) terms.
//!
//! Consider a proof for the ElGamal-style statement `x * E0 - E1 = M`. The
//! canonical form rewrites this as `x * E0 = F` with `F = M + E1`. If only `F`
//! is bound by the Fiat-Shamir transcript, then a proof for `(E0, E1, M)` also
//! verifies for any `(E0, E1', M')` with `M' + E1' = M + E1`: the proof is
//! malleable across statements.

use group::Group;
use sigma_proofs::traits::ScalarRng;

use sigma_proofs::linear_relation::Instance;
use sigma_proofs::{LinearRelation, Nizk, ProofRng};

type G = bls12_381::G1Projective;
type Scalar = <G as Group>::Scalar;

/// Statement: knowledge of `x` such that `x * E0 - E1 = M`.
#[allow(non_snake_case)]
fn elgamal_statement(E0: G, E1: G, M: G) -> Instance<G> {
    let mut relation = LinearRelation::<G>::new();
    let var_x = relation.allocate_scalar();
    let [var_E0, var_E1, var_M] = relation.allocate_elements();
    relation.append_equation(var_M, var_x * var_E0 - var_E1);
    relation.set_elements([(var_E0, E0), (var_E1, E1), (var_M, M)]);
    relation.compile().unwrap()
}

#[test]
#[allow(non_snake_case)]
fn proof_does_not_transfer_to_mauled_statement() {
    let mut rng = ProofRng::from_os_entropy();

    let [x] = rng.random_scalars::<G, _>();
    let E0 = G::generator() * { let [t] = rng.random_scalars::<G, _>(); t };
    let E1 = G::generator() * { let [t] = rng.random_scalars::<G, _>(); t };
    let M = E0 * x - E1;

    let nizk = Nizk::new(b"test-malleability", elgamal_statement(E0, E1, M));
    let proof = nizk.prove_batchable(&vec![x], &mut rng).unwrap();
    nizk.verify_batchable(&proof).unwrap();

    // Maul the statement: (E1', M') = (E1 - D, M + D) satisfies M' + E1' = M + E1,
    // yet (E0, E1', M') is a different statement. A proof computed for the
    // original statement must not verify for the mauled one.
    let D = G::generator() * { let [t] = rng.random_scalars::<G, _>(); t };
    let mauled = Nizk::new(
        b"test-malleability",
        elgamal_statement(E0, E1 - D, M + D),
    );
    assert!(
        mauled.verify_batchable(&proof).is_err(),
        "proof for (E0, E1, M) verified for a different statement (E0, E1 - D, M + D): \
         the instance label does not bind E1 and M individually"
    );
}

/// Regression test for check 10 of instance validation: a scalar whose
/// effective base is the identity in every equation leaves its response
/// unconstrained, so the instance must be rejected.
#[test]
#[allow(non_snake_case)]
fn identity_effective_base_is_rejected() {
    let mut rng = ProofRng::from_os_entropy();
    let [a] = rng.random_scalars::<G, _>();
    let A = G::generator() * a;

    // X = x * A - x * A (+ y * A so the equation itself is provable):
    // the effective base of x is A - A = identity in the only equation.
    let mut relation = LinearRelation::<G>::new();
    let [var_x, var_y] = relation.allocate_scalars();
    let var_A = relation.allocate_element();
    let var_X = relation.allocate_eq(var_x * var_A - var_x * var_A + var_y * var_A);
    let [y] = rng.random_scalars::<G, _>();
    relation.set_elements([(var_A, A), (var_X, A * y)]);

    let err = relation.compile().unwrap_err();
    assert_eq!(err.check, Some(10));
}

/// Known limitation, documented by the specification: instance validation is
/// structural and cannot detect computationally dependent bases (an element
/// registered as a precomputed multiple of another). Such instances validate,
/// and their responses are malleable along the kernel of the linear map. The
/// specification therefore REQUIRES independent bases at the statement level;
/// this test documents that the library cannot enforce it.
#[test]
#[allow(non_snake_case)]
fn dependent_bases_still_validate() {
    let mut rng = ProofRng::from_os_entropy();
    let [a, x, y] = rng.random_scalars::<G, _>();
    let A = G::generator() * a;
    let B = A * Scalar::from(2u64); // dependent: B = 2A, violating the spec's independence requirement

    let mut relation = LinearRelation::<G>::new();
    let [var_x, var_y] = relation.allocate_scalars();
    let [var_A, var_B] = relation.allocate_elements();
    let var_X = relation.allocate_eq(var_x * var_A + var_y * var_B);
    relation.set_elements([(var_A, A), (var_B, B), (var_X, A * x + B * y)]);

    // Structurally valid: every check passes (the dependency between A and B
    // is not observable from the instance).
    assert!(relation.compile().is_ok());
}
