//! Definitions used in tests for this crate.

use group::{Group, GroupEncoding};

use crate::{group_morphism::msm_pr, GroupMorphismPreimage};

/// Morphism for knowledge of a discrete logarithm relative to a fixed basepoint.
#[allow(non_snake_case)]
pub fn discrete_logarithm<G: Group + GroupEncoding>(
    x: G::Scalar,
) -> (GroupMorphismPreimage<G>, Vec<G::Scalar>) {
    let mut morphismp: GroupMorphismPreimage<G> = GroupMorphismPreimage::new();

    let var_x = morphismp.allocate_scalar();
    let [var_G, var_X] = morphismp.allocate_elements();

    morphismp.append_equation(var_X, &[(var_x, var_G)]);

    morphismp.assign_elements(&[(var_G, G::generator())]);

    let X = G::generator() * x;
    assert!(vec![X] == morphismp.morphism.evaluate(&[x]));

    morphismp.assign_elements(&[(var_X, X)]);
    (morphismp, vec![x])
}

/// Morphism for knowledge of a discrete logarithm equality between two pairs.
#[allow(non_snake_case)]
pub fn dleq<G: Group + GroupEncoding>(
    x: G::Scalar,
    H: G,
) -> (GroupMorphismPreimage<G>, Vec<G::Scalar>) {
    let mut morphismp: GroupMorphismPreimage<G> = GroupMorphismPreimage::new();

    let X = G::generator() * x;
    let Y = H * x;

    let var_x = morphismp.allocate_scalar();
    let [var_G, var_H, var_X, var_Y] = morphismp.allocate_elements();

    morphismp.assign_elements(&[(var_G, G::generator()), (var_H, H), (var_X, X), (var_Y, Y)]);
    morphismp.append_equation(var_X, &[(var_x, var_G)]);
    morphismp.append_equation(var_Y, &[(var_x, var_H)]);

    assert!(vec![X, Y] == morphismp.morphism.evaluate(&[x]));
    (morphismp, vec![x])
}

/// Morphism for knowledge of an opening to a Pederson commitment.
#[allow(non_snake_case)]
pub fn pedersen_commitment<G: Group + GroupEncoding>(
    H: G,
    x: G::Scalar,
    r: G::Scalar,
) -> (GroupMorphismPreimage<G>, Vec<G::Scalar>) {
    let mut cs: GroupMorphismPreimage<G> = GroupMorphismPreimage::new();

    let C = G::generator() * x + H * r;

    let [var_x, var_r] = cs.allocate_scalars();
    let [var_G, var_H, var_C] = cs.allocate_elements();

    cs.assign_elements(&[(var_H, H), (var_G, G::generator()), (var_C, C)]);
    cs.append_equation(var_C, &[(var_x, var_G), (var_r, var_H)]);

    let witness = vec![x, r];
    assert!(vec![C] == cs.morphism.evaluate(&witness));
    (cs, witness)
}

/// Morphism for knowledge of equal openings to two distinct Pederson commitments.
#[allow(non_snake_case)]
pub fn pedersen_commitment_dleq<G: Group + GroupEncoding>(
    generators: [G; 4],
    witness: [G::Scalar; 2],
) -> (GroupMorphismPreimage<G>, Vec<G::Scalar>) {
    let mut morphismp: GroupMorphismPreimage<G> = GroupMorphismPreimage::new();

    let X = msm_pr::<G>(&witness, &[generators[0], generators[1]]);
    let Y = msm_pr::<G>(&witness, &[generators[2], generators[3]]);

    let [var_x, var_r] = morphismp.allocate_scalars();

    let var_Gs = morphismp.allocate_elements::<4>();
    let [var_X, var_Y] = morphismp.allocate_elements();

    morphismp.assign_elements(&[
        (var_Gs[0], generators[0]),
        (var_Gs[1], generators[1]),
        (var_Gs[2], generators[2]),
        (var_Gs[3], generators[3]),
    ]);
    morphismp.assign_elements(&[(var_X, X), (var_Y, Y)]);

    morphismp.append_equation(var_X, &[(var_x, var_Gs[0]), (var_r, var_Gs[1])]);
    morphismp.append_equation(var_Y, &[(var_x, var_Gs[2]), (var_r, var_Gs[3])]);

    assert!(vec![X, Y] == morphismp.morphism.evaluate(&witness));
    (morphismp, witness.to_vec())
}

/// Morphism for knowledge of an opening for use in a BBS commitment.
// BBS messag length is 3
#[allow(non_snake_case)]
pub fn bbs_blind_commitment_computation<G: Group + GroupEncoding>(
    [Q_2, J_1, J_2, J_3]: [G; 4],
    [msg_1, msg_2, msg_3]: [G::Scalar; 3],
    secret_prover_blind: G::Scalar,
) -> (GroupMorphismPreimage<G>, Vec<G::Scalar>) {
    let mut morphismp = GroupMorphismPreimage::new();

    // QUESTION: Are these comments supposed to be placeholders of some kind?
    // BBS.create_generators(M + 1, "BLIND_" || api_id)
    // BBS.messages_to_scalars(committed_messages,  api_id)

    // these are computed before the proof in the specification
    let C = Q_2 * secret_prover_blind + J_1 * msg_1 + J_2 * msg_2 + J_3 * msg_3;

    // This is the part that needs to be changed in the specification of blind bbs.
    let [var_secret_prover_blind, var_msg_1, var_msg_2, var_msg_3] = morphismp.allocate_scalars();

    let [var_Q_2, var_J_1, var_J_2, var_J_3] = morphismp.allocate_elements();
    let var_C = morphismp.allocate_element();

    morphismp.assign_elements(&[
        (var_Q_2, Q_2),
        (var_J_1, J_1),
        (var_J_2, J_2),
        (var_J_3, J_3),
        (var_C, C),
    ]);

    morphismp.append_equation(
        var_C,
        &[
            (var_secret_prover_blind, var_Q_2),
            (var_msg_1, var_J_1),
            (var_msg_2, var_J_2),
            (var_msg_3, var_J_3),
        ],
    );

    let witness = vec![secret_prover_blind, msg_1, msg_2, msg_3];

    assert!(vec![C] == morphismp.morphism.evaluate(&witness));
    (morphismp, witness)
}
