//! Definitions used in tests for this crate.

use ff::Field;
use group::prime::PrimeGroup;
use rand::rngs::OsRng;

use crate::linear_relation::{msm_pr, CanonicalLinearRelation, LinearRelation};

/// LinearMap for knowledge of a discrete logarithm relative to a fixed basepoint.
#[allow(non_snake_case)]
pub fn discrete_logarithm<G: PrimeGroup>() -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let x = G::Scalar::random(&mut OsRng);
    let mut relation = LinearRelation::new();

    let var_x = relation.allocate_scalar();
    let var_G = relation.allocate_element();

    let var_X = relation.allocate_eq(var_x * var_G);

    relation.set_element(var_G, G::generator());
    relation.compute_image(&[x]).unwrap();

    let X = relation.linear_map.group_elements.get(var_X).unwrap();

    assert_eq!(X, G::generator() * x);
    let witness = vec![x];
    let instance = (&relation).try_into().unwrap();
    (instance, witness)
}

/// LinearMap for knowledge of a shifted discrete logarithm relative to a fixed basepoint.
#[allow(non_snake_case)]
pub fn shifted_discrete_logarithm<G: PrimeGroup>() -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let x = G::Scalar::random(&mut OsRng);
    let mut relation = LinearRelation::new();

    let var_x = relation.allocate_scalar();
    let var_G = relation.allocate_element();

    let var_X = relation.allocate_eq((var_x + <G::Scalar as Field>::ONE) * var_G);

    relation.set_element(var_G, G::generator());
    relation.compute_image(&[x]).unwrap();

    let X = relation.linear_map.group_elements.get(var_X).unwrap();

    assert!(vec![X] == relation.linear_map.evaluate(&[x]).unwrap());
    let witness = vec![x];
    let instance = (&relation).try_into().unwrap();
    (instance, witness)
}

/// LinearMap for knowledge of a discrete logarithm equality between two pairs.
#[allow(non_snake_case)]
pub fn dleq<G: PrimeGroup>() -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let H = G::random(&mut OsRng);
    let x = G::Scalar::random(&mut OsRng);
    let mut relation = LinearRelation::new();

    let var_x = relation.allocate_scalar();
    let [var_G, var_H] = relation.allocate_elements();

    let var_X = relation.allocate_eq(var_x * var_G);
    let var_Y = relation.allocate_eq(var_x * var_H);

    relation.set_elements([(var_G, G::generator()), (var_H, H)]);
    relation.compute_image(&[x]).unwrap();

    let X = relation.linear_map.group_elements.get(var_X).unwrap();
    let Y = relation.linear_map.group_elements.get(var_Y).unwrap();

    assert_eq!(X, G::generator() * x);
    assert_eq!(Y, H * x);
    let witness = vec![x];
    let instance = (&relation).try_into().unwrap();
    (instance, witness)
}

/// LinearMap for knowledge of a shifted dleq.
#[allow(non_snake_case)]
pub fn shifted_dleq<G: PrimeGroup>() -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let H = G::random(&mut OsRng);
    let x = G::Scalar::random(&mut OsRng);
    let mut relation = LinearRelation::new();

    let var_x = relation.allocate_scalar();
    let [var_G, var_H] = relation.allocate_elements();

    let var_X = relation.allocate_eq(var_x * var_G + var_H);
    let var_Y = relation.allocate_eq(var_x * var_H + var_G);

    relation.set_elements([(var_G, G::generator()), (var_H, H)]);
    relation.compute_image(&[x]).unwrap();

    let X = relation.linear_map.group_elements.get(var_X).unwrap();
    let Y = relation.linear_map.group_elements.get(var_Y).unwrap();

    assert_eq!(X, G::generator() * x + H);
    assert_eq!(Y, H * x + G::generator());
    let witness = vec![x];
    let instance = (&relation).try_into().unwrap();
    (instance, witness)
}

/// LinearMap for knowledge of an opening to a Pedersen commitment.
#[allow(non_snake_case)]
pub fn pedersen_commitment<G: PrimeGroup>() -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let H = G::random(&mut OsRng);
    let x = G::Scalar::random(&mut OsRng);
    let r = G::Scalar::random(&mut OsRng);
    let mut relation = LinearRelation::new();

    let [var_x, var_r] = relation.allocate_scalars();
    let [var_G, var_H] = relation.allocate_elements();

    let var_C = relation.allocate_eq(var_x * var_G + var_r * var_H);

    relation.set_elements([(var_H, H), (var_G, G::generator())]);
    relation.compute_image(&[x, r]).unwrap();

    let C = relation.linear_map.group_elements.get(var_C).unwrap();

    let witness = vec![x, r];
    assert_eq!(C, G::generator() * x + H * r);
    let instance = (&relation).try_into().unwrap();
    (instance, witness)
}

/// LinearMap for knowledge of equal openings to two distinct Pedersen commitments.
#[allow(non_snake_case)]
pub fn pedersen_commitment_dleq<G: PrimeGroup>() -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let generators = [
        G::random(&mut OsRng),
        G::random(&mut OsRng),
        G::random(&mut OsRng),
        G::random(&mut OsRng),
    ];
    let witness = [G::Scalar::random(&mut OsRng), G::Scalar::random(&mut OsRng)];
    let mut relation = LinearRelation::new();

    let X = msm_pr::<G>(&witness, &[generators[0], generators[1]]);
    let Y = msm_pr::<G>(&witness, &[generators[2], generators[3]]);

    let [var_x, var_r] = relation.allocate_scalars();

    let var_Gs = relation.allocate_elements::<4>();
    let var_X = relation.allocate_eq(var_x * var_Gs[0] + var_r * var_Gs[1]);
    let var_Y = relation.allocate_eq(var_x * var_Gs[2] + var_r * var_Gs[3]);

    relation.set_elements([
        (var_Gs[0], generators[0]),
        (var_Gs[1], generators[1]),
        (var_Gs[2], generators[2]),
        (var_Gs[3], generators[3]),
    ]);
    relation.set_elements([(var_X, X), (var_Y, Y)]);

    assert!(vec![X, Y] == relation.linear_map.evaluate(&witness).unwrap());
    let witness_vec = witness.to_vec();
    let instance = (&relation).try_into().unwrap();
    (instance, witness_vec)
}

/// LinearMap for knowledge of an opening for use in a BBS commitment.
// BBS message length is 3
#[allow(non_snake_case)]
pub fn bbs_blind_commitment_computation<G: PrimeGroup>(
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let [Q_2, J_1, J_2, J_3] = [
        G::random(&mut OsRng),
        G::random(&mut OsRng),
        G::random(&mut OsRng),
        G::random(&mut OsRng),
    ];
    let [msg_1, msg_2, msg_3] = [
        G::Scalar::random(&mut OsRng),
        G::Scalar::random(&mut OsRng),
        G::Scalar::random(&mut OsRng),
    ];
    let secret_prover_blind = G::Scalar::random(&mut OsRng);
    let mut relation = LinearRelation::new();

    // these are computed before the proof in the specification
    let C = Q_2 * secret_prover_blind + J_1 * msg_1 + J_2 * msg_2 + J_3 * msg_3;

    // This is the part that needs to be changed in the specification of blind bbs.
    let [var_secret_prover_blind, var_msg_1, var_msg_2, var_msg_3] = relation.allocate_scalars();

    // Match Sage's allocation order: allocate all elements in the same order
    let [var_Q_2, var_J_1, var_J_2, var_J_3] = relation.allocate_elements();
    let var_C = relation.allocate_element(); // Allocate var_C separately, giving it index 4

    // Now append the equation separately (like Sage's append_equation)
    relation.append_equation(
        var_C,
        var_secret_prover_blind * var_Q_2
            + var_msg_1 * var_J_1
            + var_msg_2 * var_J_2
            + var_msg_3 * var_J_3,
    );

    relation.set_elements([
        (var_Q_2, Q_2),
        (var_J_1, J_1),
        (var_J_2, J_2),
        (var_J_3, J_3),
        (var_C, C),
    ]);

    let witness = vec![secret_prover_blind, msg_1, msg_2, msg_3];

    assert!(vec![C] == relation.linear_map.evaluate(&witness).unwrap());
    let instance = (&relation).try_into().unwrap();
    (instance, witness)
}

/// Test function with the requested LinearRelation code
#[allow(non_snake_case)]
pub fn test_linear_relation_example<G: PrimeGroup>() -> LinearRelation<G> {
    use ff::Field;

    let mut sigma__lr = LinearRelation::<G>::new();
    let x = sigma__lr.allocate_scalar();
    let B = sigma__lr.allocate_element();
    let _sigma__eq1 = sigma__lr.allocate_eq((x + (-<G::Scalar as Field>::ONE)) * B + (-B));

    sigma__lr
}

/// LinearMap for the user's specific relation: A * 1 + gen__disj1_x_r * B
#[allow(non_snake_case)]
pub fn user_specific_linear_combination<G: PrimeGroup>(
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let B = G::random(&mut OsRng);
    let gen__disj1_x_r = G::Scalar::random(&mut OsRng);
    let mut sigma__lr = LinearRelation::new();

    let gen__disj1_x_r_var = sigma__lr.allocate_scalar();
    let A = sigma__lr.allocate_element();
    let B_var = sigma__lr.allocate_element();

    let sigma__eq1 =
        sigma__lr.allocate_eq(A * <G::Scalar as ff::Field>::ONE + gen__disj1_x_r_var * B_var);

    // Set the group elements
    sigma__lr.set_elements([(A, G::generator()), (B_var, B)]);
    sigma__lr.compute_image(&[gen__disj1_x_r]).unwrap();

    let result = sigma__lr.linear_map.group_elements.get(sigma__eq1).unwrap();

    // Verify the relation computes correctly
    let expected = G::generator() + B * gen__disj1_x_r;
    assert_eq!(result, expected);

    let witness = vec![gen__disj1_x_r];
    let instance = (&sigma__lr).try_into().unwrap();
    (instance, witness)
}
