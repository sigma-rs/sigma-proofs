//! Definitions used in tests for this crate.

use group::{Group, GroupEncoding};

use crate::linear_relation::{msm_pr, LinearRelation};

/// LinearMap for knowledge of a discrete logarithm relative to a fixed basepoint.
#[allow(non_snake_case)]
pub fn discrete_logarithm<G: Group + GroupEncoding>(
    x: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut linear_map: LinearRelation<G> = LinearRelation::new();

    let var_x = linear_map.allocate_scalar();
    let var_G = linear_map.allocate_element();

    let var_X = linear_map.allocate_eq(var_x * var_G);

    linear_map.set_element(var_G, G::generator());
    linear_map.compute_image(&[x]).unwrap();

    let X = linear_map.linear_map.group_elements.get(var_X).unwrap();

    assert_eq!(X, G::generator() * x);
    (linear_map, vec![x])
}

/// LinearMap for knowledge of a discrete logarithm equality between two pairs.
#[allow(non_snake_case)]
pub fn dleq<G: Group + GroupEncoding>(H: G, x: G::Scalar) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut linear_map: LinearRelation<G> = LinearRelation::new();

    let var_x = linear_map.allocate_scalar();
    let [var_G, var_H] = linear_map.allocate_elements();

    let var_X = linear_map.allocate_eq(var_x * var_G);
    let var_Y = linear_map.allocate_eq(var_x * var_H);

    linear_map.set_elements([(var_G, G::generator()), (var_H, H)]);
    linear_map.compute_image(&[x]).unwrap();

    let X = linear_map.linear_map.group_elements.get(var_X).unwrap();
    let Y = linear_map.linear_map.group_elements.get(var_Y).unwrap();

    assert_eq!(X, G::generator() * x);
    assert_eq!(Y, H * x);
    (linear_map, vec![x])
}

/// LinearMap for knowledge of an opening to a Pederson commitment.
#[allow(non_snake_case)]
pub fn pedersen_commitment<G: Group + GroupEncoding>(
    H: G,
    x: G::Scalar,
    r: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut cs: LinearRelation<G> = LinearRelation::new();

    let [var_x, var_r] = cs.allocate_scalars();
    let [var_G, var_H] = cs.allocate_elements();

    let var_C = cs.allocate_eq(var_x * var_G + var_r * var_H);

    cs.set_elements([(var_H, H), (var_G, G::generator())]);
    cs.compute_image(&[x, r]).unwrap();

    let C = cs.linear_map.group_elements.get(var_C).unwrap();

    let witness = vec![x, r];
    assert_eq!(C, G::generator() * x + H * r);
    (cs, witness)
}

/// LinearMap for knowledge of equal openings to two distinct Pederson commitments.
#[allow(non_snake_case)]
pub fn pedersen_commitment_dleq<G: Group + GroupEncoding>(
    generators: [G; 4],
    witness: [G::Scalar; 2],
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut linear_map: LinearRelation<G> = LinearRelation::new();

    let X = msm_pr::<G>(&witness, &[generators[0], generators[1]]);
    let Y = msm_pr::<G>(&witness, &[generators[2], generators[3]]);

    let [var_x, var_r] = linear_map.allocate_scalars();

    let var_Gs = linear_map.allocate_elements::<4>();
    let [var_X, var_Y] = linear_map.allocate_elements();

    linear_map.set_elements([
        (var_Gs[0], generators[0]),
        (var_Gs[1], generators[1]),
        (var_Gs[2], generators[2]),
        (var_Gs[3], generators[3]),
    ]);
    linear_map.set_elements([(var_X, X), (var_Y, Y)]);

    linear_map.append_equation(var_X, [(var_x, var_Gs[0]), (var_r, var_Gs[1])]);
    linear_map.append_equation(var_Y, [(var_x, var_Gs[2]), (var_r, var_Gs[3])]);

    assert!(vec![X, Y] == linear_map.linear_map.evaluate(&witness).unwrap());
    (linear_map, witness.to_vec())
}

/// LinearMap for knowledge of an opening for use in a BBS commitment.
// BBS message length is 3
#[allow(non_snake_case)]
pub fn bbs_blind_commitment_computation<G: Group + GroupEncoding>(
    [Q_2, J_1, J_2, J_3]: [G; 4],
    [msg_1, msg_2, msg_3]: [G::Scalar; 3],
    secret_prover_blind: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut linear_map = LinearRelation::new();

    // these are computed before the proof in the specification
    let C = Q_2 * secret_prover_blind + J_1 * msg_1 + J_2 * msg_2 + J_3 * msg_3;

    // This is the part that needs to be changed in the specification of blind bbs.
    let [var_secret_prover_blind, var_msg_1, var_msg_2, var_msg_3] = linear_map.allocate_scalars();

    let [var_Q_2, var_J_1, var_J_2, var_J_3] = linear_map.allocate_elements();
    let var_C = linear_map.allocate_element();

    linear_map.set_elements([
        (var_Q_2, Q_2),
        (var_J_1, J_1),
        (var_J_2, J_2),
        (var_J_3, J_3),
        (var_C, C),
    ]);

    linear_map.append_equation(
        var_C,
        [
            (var_secret_prover_blind, var_Q_2),
            (var_msg_1, var_J_1),
            (var_msg_2, var_J_2),
            (var_msg_3, var_J_3),
        ],
    );

    let witness = vec![secret_prover_blind, msg_1, msg_2, msg_3];

    assert!(vec![C] == linear_map.linear_map.evaluate(&witness).unwrap());
    (linear_map, witness)
}
