//! Definitions used in tests for this crate.

use group::{Group, GroupEncoding};

use crate::linear_relation::{msm_pr, LinearRelation};

/// LinearMap for knowledge of a discrete logarithm relative to a fixed basepoint.
#[allow(non_snake_case)]
pub fn discrete_logarithm<G: Group + GroupEncoding>(
    x: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp: LinearRelation<G> = LinearRelation::new();

    let var_x = morphismp.allocate_scalar();
    let var_G = morphismp.allocate_element();

    let var_X = morphismp.allocate_eq(var_x * var_G);

    morphismp.set_element(var_G, G::generator());
    morphismp.compute_image(&[x]).unwrap();

    let X = morphismp.linear_map.group_elements.get(var_X).unwrap();

    assert_eq!(X, G::generator() * x);
    (morphismp, vec![x])
}

/// LinearMap for knowledge of a discrete logarithm equality between two pairs.
#[allow(non_snake_case)]
pub fn dleq<G: Group + GroupEncoding>(x: G::Scalar, H: G) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp: LinearRelation<G> = LinearRelation::new();

    let var_x = morphismp.allocate_scalar();
    let [var_G, var_H] = morphismp.allocate_elements();

    let var_X = morphismp.allocate_eq(var_x * var_G);
    let var_Y = morphismp.allocate_eq(var_x * var_H);

    morphismp.set_elements([(var_G, G::generator()), (var_H, H)]);
    morphismp.compute_image(&[x]).unwrap();

    let X = morphismp.linear_map.group_elements.get(var_X).unwrap();
    let Y = morphismp.linear_map.group_elements.get(var_Y).unwrap();

    assert_eq!(X, G::generator() * x);
    assert_eq!(Y, H * x);
    (morphismp, vec![x])
}

/// LinearMap for knowledge of a discrete logarithm equality between n pairs.
#[allow(non_snake_case)]
pub fn dleq_generalized<G: Group + GroupEncoding>(
    bases: &[G],
    x: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    assert!(
        !bases.is_empty(),
        "Cannot construct generalized DLEQ with zero basepoints"
    );

    let mut morphismp = LinearRelation::<G>::new();

    let var_x = morphismp.allocate_scalar();

    // Allocate one variable per basepoint H_i
    let var_Hi: Vec<_> = (0..bases.len())
        .map(|_| morphismp.allocate_element())
        .collect();

    // Add the equations: Y_i = x · H_i
    let var_Yi: Vec<_> = var_Hi
        .iter()
        .map(|&var_H| morphismp.allocate_eq([(var_x, var_H)]))
        .collect();

    // Set the basepoints
    morphismp.set_elements(var_Hi.iter().copied().zip(bases.iter().copied()));

    // Evaluate image of x under this relation
    morphismp.compute_image(&[x]).unwrap();

    // Check internal consistency
    let group_elements = &morphismp.linear_map.group_elements;
    for (&var_H, &var_Y) in var_Hi.iter().zip(var_Yi.iter()) {
        let H = group_elements.get(var_H).unwrap();
        let Y = group_elements.get(var_Y).unwrap();
        assert_eq!(Y, (H * x), "Y_i != x · H_i");
    }
    (morphismp, vec![x])
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

/// LinearMap for knowledge of an opening to a Pederson commitment generalized for n scalars.
#[allow(non_snake_case)]
pub fn pedersen_commitment_generalized<G: Group + GroupEncoding>(
    additional_generators: &[G],
    x: G::Scalar,
    blindings: &[G::Scalar],
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    assert!(
        additional_generators.len() == blindings.len(),
        "Generators and blindings must have the same length"
    );

    let mut morphismp = LinearRelation::<G>::new();

    // Allocate variables
    let var_x = morphismp.allocate_scalar();
    let var_r: Vec<_> = (0..blindings.len())
        .map(|_| morphismp.allocate_scalar())
        .collect();
    let var_G = morphismp.allocate_element();
    let var_H: Vec<_> = (0..blindings.len())
        .map(|_| morphismp.allocate_element())
        .collect();
    let var_C = morphismp.allocate_element();

    // Build the linear combination for the commitment
    let mut lin_comb = vec![(var_x, var_G)];
    lin_comb.extend(var_r.iter().zip(var_H.iter()).map(|(&r, &h)| (r, h)));

    morphismp.append_equation(var_C, lin_comb);

    // Set the generator and vector of elements
    morphismp.set_element(var_G, G::generator());
    morphismp.set_elements(
        var_H
            .iter()
            .copied()
            .zip(additional_generators.iter().copied()),
    );

    // Build the full witness vector
    let mut witness = vec![x];
    witness.extend_from_slice(blindings);

    morphismp.compute_image(&witness).unwrap();

    // Check commitment correctness
    let group_elements = &morphismp.linear_map.group_elements;
    let G_val = group_elements.get(var_G).unwrap();
    let H_vals: Vec<_> = var_H
        .iter()
        .map(|v| group_elements.get(*v).unwrap())
        .collect();
    let C = group_elements.get(var_C).unwrap();

    let expected_C = G_val * x
        + H_vals
            .iter()
            .zip(blindings.iter())
            .map(|(h, r)| *h * r)
            .fold(G::identity(), |acc, term| acc + term);

    assert_eq!(
        C, expected_C,
        "generalized Pedersen commitment check failed"
    );

    (morphismp, witness)
}

/// LinearMap for knowledge of equal openings to two distinct Pederson commitments.
#[allow(non_snake_case)]
pub fn pedersen_commitment_dleq<G: Group + GroupEncoding>(
    generators: [G; 4],
    witness: [G::Scalar; 2],
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp: LinearRelation<G> = LinearRelation::new();

    let X = msm_pr::<G>(&witness, &[generators[0], generators[1]]);
    let Y = msm_pr::<G>(&witness, &[generators[2], generators[3]]);

    let [var_x, var_r] = morphismp.allocate_scalars();

    let var_Gs = morphismp.allocate_elements::<4>();
    let [var_X, var_Y] = morphismp.allocate_elements();

    morphismp.set_elements([
        (var_Gs[0], generators[0]),
        (var_Gs[1], generators[1]),
        (var_Gs[2], generators[2]),
        (var_Gs[3], generators[3]),
    ]);
    morphismp.set_elements([(var_X, X), (var_Y, Y)]);

    morphismp.append_equation(var_X, [(var_x, var_Gs[0]), (var_r, var_Gs[1])]);
    morphismp.append_equation(var_Y, [(var_x, var_Gs[2]), (var_r, var_Gs[3])]);

    assert!(vec![X, Y] == morphismp.linear_map.evaluate(&witness).unwrap());
    (morphismp, witness.to_vec())
}

/// LinearMap for knowledge of multiplication proof for Pedersen Commitments.
#[allow(non_snake_case)]
pub fn pedersen_commitment_multiplication<G: Group + GroupEncoding>(
    G: G,
    B: G,
    H: G,
    x: G::Scalar,
    r1: G::Scalar,
    r2: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp: LinearRelation<G> = LinearRelation::new();

    let X = G * x + H * r1;
    let Y = B * x + H * r2;

    // Allocate variables
    let var_x = morphismp.allocate_scalar();
    let [var_r1, var_r2] = morphismp.allocate_scalars();
    let [var_G, var_B, var_H] = morphismp.allocate_elements();
    let [var_X, var_Y] = morphismp.allocate_elements();

    // Set values for basepoints
    morphismp.set_elements([(var_G, G), (var_B, B), (var_H, H), (var_X, X), (var_Y, Y)]);

    // Equations
    morphismp.append_equation(var_X, [(var_x, var_G), (var_r1, var_H)]);
    morphismp.append_equation(var_Y, [(var_x, var_B), (var_r2, var_H)]);

    let witness = vec![x, r1, r2];
    morphismp.compute_image(&witness).unwrap();

    assert_eq!(morphismp.linear_map.evaluate(&witness).unwrap(), vec![X, Y]);
    (morphismp, witness)
}

/// LinearMap for knowledge of equal openings to n distinct generalized Pederson commitments.
pub fn pedersen_commitment_multi_equation<G: Group + GroupEncoding>(
    base_G: G,
    commitment_terms: &[Vec<G>], // list of equations, each with list of H_j
    x: G::Scalar,
    blindings: &[G::Scalar],
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp = LinearRelation::<G>::new();

    let var_x = morphismp.allocate_scalar();
    let var_blindings: Vec<_> = (0..blindings.len())
        .map(|_| morphismp.allocate_scalar())
        .collect();

    let var_G = morphismp.allocate_element();
    morphismp.set_element(var_G, base_G);

    // Allocate all distinct H_j across all equations (flattened then deduplicated)
    let mut all_H: Vec<G> = commitment_terms.iter().flatten().copied().collect();
    all_H.sort_by(|a, b| a.to_bytes().as_ref().cmp(b.to_bytes().as_ref()));
    all_H.dedup();

    let mut var_H = vec![];
    for H in &all_H {
        let v = morphismp.allocate_element();
        morphismp.set_element(v, *H);
        var_H.push((H, v));
    }

    let resolve_var_H = |H: &G| var_H.iter().find(|(h, _)| *h == H).unwrap().1;

    for terms in commitment_terms {
        let var_C = morphismp.allocate_element();

        // Find indices of blindings r_j associated with terms
        let lincomb = terms
            .iter()
            .enumerate()
            .map(|(j, H)| (var_blindings[j], resolve_var_H(H)))
            .collect::<Vec<_>>();

        let mut full_comb = vec![(var_x, var_G)];
        full_comb.extend(lincomb);

        morphismp.append_equation(var_C, full_comb);
    }

    let mut witness = vec![x];
    witness.extend_from_slice(blindings);

    morphismp.compute_image(&witness).unwrap();
    (morphismp, witness)
}

/// LinearMap for knowledge of an opening for use in a BBS commitment.
// BBS message length is 3
#[allow(non_snake_case)]
pub fn bbs_blind_commitment_computation<G: Group + GroupEncoding>(
    [Q_2, J_1, J_2, J_3]: [G; 4],
    [msg_1, msg_2, msg_3]: [G::Scalar; 3],
    secret_prover_blind: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp = LinearRelation::new();

    // these are computed before the proof in the specification
    let C = Q_2 * secret_prover_blind + J_1 * msg_1 + J_2 * msg_2 + J_3 * msg_3;

    // This is the part that needs to be changed in the specification of blind bbs.
    let [var_secret_prover_blind, var_msg_1, var_msg_2, var_msg_3] = morphismp.allocate_scalars();

    let [var_Q_2, var_J_1, var_J_2, var_J_3] = morphismp.allocate_elements();
    let var_C = morphismp.allocate_element();

    morphismp.set_elements([
        (var_Q_2, Q_2),
        (var_J_1, J_1),
        (var_J_2, J_2),
        (var_J_3, J_3),
        (var_C, C),
    ]);

    morphismp.append_equation(
        var_C,
        [
            (var_secret_prover_blind, var_Q_2),
            (var_msg_1, var_J_1),
            (var_msg_2, var_J_2),
            (var_msg_3, var_J_3),
        ],
    );

    let witness = vec![secret_prover_blind, msg_1, msg_2, msg_3];

    assert!(vec![C] == morphismp.linear_map.evaluate(&witness).unwrap());
    (morphismp, witness)
}
