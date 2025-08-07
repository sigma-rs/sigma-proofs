use ff::Field;
use group::prime::PrimeGroup;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::codec::Shake128DuplexSponge;
use crate::fiat_shamir::Nizk;
use crate::linear_relation::CanonicalLinearRelation;
use crate::schnorr_protocol::SchnorrProof;

use crate::linear_relation::{LinearRelation, VariableMultiScalarMul};

/// LinearMap for knowledge of a discrete logarithm relative to a fixed basepoint.
#[allow(non_snake_case)]
pub fn discrete_logarithm<G: PrimeGroup, R: rand::RngCore>(
    rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let x = G::Scalar::random(rng);
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
pub fn shifted_dlog<G: PrimeGroup, R: RngCore>(
    rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let x = G::Scalar::random(rng);
    let mut relation = LinearRelation::new();

    let var_x = relation.allocate_scalar();
    let var_G = relation.allocate_element();

    let var_X = relation.allocate_eq(var_G * var_x + var_G * <G::Scalar as Field>::ONE);
    // another way of writing this is:
    relation.append_equation(var_X, (var_x + G::Scalar::from(1)) * var_G);

    relation.set_element(var_G, G::generator());
    relation.compute_image(&[x]).unwrap();

    let witness = vec![x];
    let instance = (&relation).try_into().unwrap();
    (instance, witness)
}

/// LinearMap for knowledge of a discrete logarithm equality between two pairs.
#[allow(non_snake_case)]
pub fn dleq<G: PrimeGroup, R: RngCore>(
    rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let H = G::random(&mut *rng);
    let x = G::Scalar::random(&mut *rng);
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
pub fn shifted_dleq<G: PrimeGroup, R: RngCore>(
    rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let H = G::random(&mut *rng);
    let x = G::Scalar::random(&mut *rng);
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
pub fn pedersen_commitment<G: PrimeGroup, R: RngCore>(
    rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let H = G::random(&mut *rng);
    let x = G::Scalar::random(&mut *rng);
    let r = G::Scalar::random(&mut *rng);
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

#[allow(non_snake_case)]
pub fn twisted_pedersen_commitment<G: PrimeGroup, R: RngCore>(
    rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let H = G::random(&mut *rng);
    let x = G::Scalar::random(&mut *rng);
    let r = G::Scalar::random(&mut *rng);
    let mut relation = LinearRelation::new();

    let [var_x, var_r] = relation.allocate_scalars();
    let [var_G, var_H] = relation.allocate_elements();

    relation.allocate_eq(
        (var_x * G::Scalar::from(3)) * var_G
            + (var_r * G::Scalar::from(2) + G::Scalar::from(3)) * var_H,
    );

    relation.set_elements([(var_H, H), (var_G, G::generator())]);
    relation.compute_image(&[x, r]).unwrap();

    let witness = vec![x, r];
    let instance = (&relation).try_into().unwrap();
    (instance, witness)
}

/// LinearMap for knowledge of equal openings to two distinct Pedersen commitments.
#[allow(non_snake_case)]
pub fn pedersen_commitment_dleq<G: PrimeGroup, R: RngCore>(
    rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let generators = [
        G::random(&mut *rng),
        G::random(&mut *rng),
        G::random(&mut *rng),
        G::random(&mut *rng),
    ];
    let witness = [G::Scalar::random(&mut *rng), G::Scalar::random(&mut *rng)];
    let mut relation = LinearRelation::new();

    let X = G::msm(&witness, &[generators[0], generators[1]]);
    let Y = G::msm(&witness, &[generators[2], generators[3]]);

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
pub fn bbs_blind_commitment<G: PrimeGroup, R: RngCore>(
    rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let [Q_2, J_1, J_2, J_3] = [
        G::random(&mut *rng),
        G::random(&mut *rng),
        G::random(&mut *rng),
        G::random(&mut *rng),
    ];
    let [msg_1, msg_2, msg_3] = [
        G::Scalar::random(&mut *rng),
        G::Scalar::random(&mut *rng),
        G::Scalar::random(&mut *rng),
    ];
    let secret_prover_blind = G::Scalar::random(&mut *rng);
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

/// LinearMap for the user's specific relation: A * 1 + gen__disj1_x_r * B
#[allow(non_snake_case)]
pub fn weird_linear_combination<G: PrimeGroup, R: RngCore>(
    rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let B = G::random(&mut *rng);
    let gen__disj1_x_r = G::Scalar::random(&mut *rng);
    let mut sigma__lr = LinearRelation::new();

    let gen__disj1_x_r_var = sigma__lr.allocate_scalar();
    let A = sigma__lr.allocate_element();
    let var_B = sigma__lr.allocate_element();

    let sigma__eq1 = sigma__lr.allocate_eq(A * G::Scalar::from(1) + gen__disj1_x_r_var * var_B);

    // Set the group elements
    sigma__lr.set_elements([(A, G::generator()), (var_B, B)]);
    sigma__lr.compute_image(&[gen__disj1_x_r]).unwrap();

    let result = sigma__lr.linear_map.group_elements.get(sigma__eq1).unwrap();

    // Verify the relation computes correctly
    let expected = G::generator() + B * gen__disj1_x_r;
    assert_eq!(result, expected);

    let witness = vec![gen__disj1_x_r];
    let instance = (&sigma__lr).try_into().unwrap();
    (instance, witness)
}

fn simple_subtractions<G: PrimeGroup, R: RngCore>(
    mut rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let x = G::Scalar::random(&mut rng);
    let B = G::random(&mut rng);
    let X = B * (x - G::Scalar::from(1));

    let mut linear_relation = LinearRelation::<G>::new();
    let var_x = linear_relation.allocate_scalar();
    let var_B = linear_relation.allocate_element();
    let var_X = linear_relation.allocate_eq((var_x + (-G::Scalar::from(1))) * var_B);
    linear_relation.set_element(var_B, B);
    linear_relation.set_element(var_X, X);

    let instance = (&linear_relation).try_into().unwrap();
    let witness = vec![x];
    (instance, witness)
}

fn subtractions_with_shift<G: PrimeGroup, R: RngCore>(
    rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let B = G::generator();
    let x = G::Scalar::random(rng);
    let X = B * (x - G::Scalar::from(2));

    let mut linear_relation = LinearRelation::<G>::new();
    let var_x = linear_relation.allocate_scalar();
    let var_B = linear_relation.allocate_element();
    let var_X = linear_relation.allocate_eq((var_x + (-G::Scalar::from(1))) * var_B + (-var_B));

    linear_relation.set_element(var_B, B);
    linear_relation.set_element(var_X, X);
    let instance = (&linear_relation).try_into().unwrap();
    let witness = vec![x];
    (instance, witness)
}

#[allow(non_snake_case)]
fn cmz_wallet_spend_relation<G: PrimeGroup, R: RngCore>(
    mut rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    // Simulate the wallet spend relation from cmz
    let P_W = G::random(&mut rng);
    let A = G::random(&mut rng);

    // Secret values
    let n_balance = G::Scalar::random(&mut rng);
    let i_price = G::Scalar::random(&mut rng);
    let fee = G::Scalar::from(5u64);
    let z_w_balance = G::Scalar::random(&mut rng);

    // W.balance = N.balance + I.price + fee
    let w_balance = n_balance + i_price + fee;

    let mut relation = LinearRelation::new();

    let var_n_balance = relation.allocate_scalar();
    let var_i_price = relation.allocate_scalar();
    let var_z_w_balance = relation.allocate_scalar();

    let var_P_W = relation.allocate_element();
    let var_A = relation.allocate_element();

    // C_show_Hattr_W_balance = (N.balance + I.price + fee) * P_W + z_w_balance * A
    let var_C = relation
        .allocate_eq((var_n_balance + var_i_price + fee) * var_P_W + var_z_w_balance * var_A);

    relation.set_elements([(var_P_W, P_W), (var_A, A)]);

    // Include fee in the witness
    relation
        .compute_image(&[n_balance, i_price, z_w_balance])
        .unwrap();

    let C = relation.linear_map.group_elements.get(var_C).unwrap();
    let expected = P_W * w_balance + A * z_w_balance;
    assert_eq!(C, expected);

    let witness = vec![n_balance, i_price, z_w_balance];
    let instance = (&relation).try_into().unwrap();
    (instance, witness)
}

fn nested_affine_relation<G: PrimeGroup, R: RngCore>(
    mut rng: &mut R,
) -> (CanonicalLinearRelation<G>, Vec<G::Scalar>) {
    let mut instance = LinearRelation::<G>::new();
    let var_r = instance.allocate_scalar();
    let var_A = instance.allocate_element();
    let var_B = instance.allocate_element();
    let eq1 = instance.allocate_eq(
        var_A * G::Scalar::from(4) + (var_r * G::Scalar::from(2) + G::Scalar::from(3)) * var_B,
    );

    let A = G::random(&mut rng);
    let B = G::random(&mut rng);
    let r = G::Scalar::random(&mut rng);
    let C = A * G::Scalar::from(4) + B * (r * G::Scalar::from(2) + G::Scalar::from(3));
    instance.set_element(var_A, A);
    instance.set_element(var_B, B);
    instance.set_element(eq1, C);

    let witness = vec![r];
    let instance = CanonicalLinearRelation::try_from(&instance).unwrap();
    (instance, witness)
}

#[test]
fn test_cmz_wallet_with_fee() {
    use group::Group;
    type G = bls12_381::G1Projective;

    let mut rng = OsRng;

    // This version should fail with InvalidInstanceWitnessPair
    // because it uses a scalar constant directly in the equation
    let P_W = G::random(&mut rng);
    let A = G::random(&mut rng);

    let n_balance = <G as Group>::Scalar::random(&mut rng);
    let i_price = <G as Group>::Scalar::random(&mut rng);
    let _fee = <G as Group>::Scalar::from(5u64);
    let z_w_balance = <G as Group>::Scalar::random(&mut rng);

    let mut relation = LinearRelation::<G>::new();

    let var_n_balance = relation.allocate_scalar();
    let var_i_price = relation.allocate_scalar();
    let var_z_w_balance = relation.allocate_scalar();

    let var_P_W = relation.allocate_element();
    let var_A = relation.allocate_element();

    // This equation has a scalar constant (fee) which causes the error
    let _var_C = relation.allocate_eq(
        (var_n_balance + var_i_price + <G as Group>::Scalar::from(5)) * var_P_W
            + var_z_w_balance * var_A,
    );

    relation.set_elements([(var_P_W, P_W), (var_A, A)]);
    relation
        .compute_image(&[n_balance, i_price, z_w_balance])
        .unwrap();

    // Try to convert to CanonicalLinearRelation - this should fail
    let nizk = relation.into_nizk(b"session_identifier").unwrap();
    let result = nizk.prove_batchable(&vec![n_balance, i_price, z_w_balance], &mut OsRng);
    assert!(result.is_ok());
    let proof = result.unwrap();
    let verify_result = nizk.verify_batchable(&proof);
    assert!(verify_result.is_ok());
}

/// Generic helper function to test both relation correctness and NIZK functionality
#[test]
fn test_relations() {
    use group::Group;
    type G = bls12_381::G1Projective;
    type RelationGenerator<G> =
        Box<dyn Fn(&mut OsRng) -> (CanonicalLinearRelation<G>, Vec<<G as Group>::Scalar>)>;

    let instance_generators: Vec<(&str, RelationGenerator<G>)> = vec![
        ("dlog", Box::new(discrete_logarithm)),
        ("shifted_dlog", Box::new(shifted_dlog)),
        ("dleq", Box::new(dleq)),
        ("shifted_dleq", Box::new(shifted_dleq)),
        ("pedersen_commitment", Box::new(pedersen_commitment)),
        (
            "twisted_pedersen_commitment",
            Box::new(twisted_pedersen_commitment),
        ),
        (
            "pedersen_commitment_dleq",
            Box::new(pedersen_commitment_dleq),
        ),
        ("bbs_blind_commitment", Box::new(bbs_blind_commitment)),
        (
            "weird_linear_combination",
            Box::new(weird_linear_combination),
        ),
        ("simple_subtractions", Box::new(simple_subtractions)),
        ("subtractions_with_shift", Box::new(subtractions_with_shift)),
        (
            "cmz_wallet_spend_relation",
            Box::new(cmz_wallet_spend_relation),
        ),
        ("nested_affine_relation", Box::new(nested_affine_relation)),
    ];

    for (relation_name, relation_sampler) in instance_generators.iter() {
        let mut rng = OsRng;
        let (canonical_relation, witness) = relation_sampler(&mut rng);

        // Test the NIZK protocol
        let protocol = SchnorrProof(canonical_relation);
        let domain_sep = format!("test-fiat-shamir-{relation_name}")
            .as_bytes()
            .to_vec();
        let nizk = Nizk::<SchnorrProof<G>, Shake128DuplexSponge<G>>::new(&domain_sep, protocol);

        // Test both proof types
        let proof_batchable = nizk
            .prove_batchable(&witness, &mut OsRng)
            .unwrap_or_else(|_| panic!("Failed to create batchable proof for {relation_name}"));
        let proof_compact = nizk
            .prove_compact(&witness, &mut OsRng)
            .unwrap_or_else(|_| panic!("Failed to create compact proof for {relation_name}"));

        // Verify both proof types
        assert!(
            nizk.verify_batchable(&proof_batchable).is_ok(),
            "Batchable proof verification failed for {relation_name}"
        );
        assert!(
            nizk.verify_compact(&proof_compact).is_ok(),
            "Compact proof verification failed for {relation_name}"
        );
    }
}
