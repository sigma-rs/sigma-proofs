use curve25519_dalek::{RistrettoPoint as G, Scalar};
use group::Group;

use sigma_proofs::LinearRelation;

#[test]
fn equation_with_value_has_the_same_wire_representation() {
    let secret = Scalar::from(42u64);
    let public_key = G::generator() * secret;

    let mut explicit = LinearRelation::<G>::new();
    let explicit_x = explicit.allocate_scalar();
    let explicit_output = explicit.allocate_eq(explicit_x * explicit.generator());
    explicit.set_element(explicit_output, public_key);

    let mut convenient = LinearRelation::<G>::new();
    let convenient_x = convenient.allocate_scalar();
    convenient.allocate_eq_with(public_key, convenient_x * convenient.generator());

    assert_eq!(
        explicit.compile().unwrap().serialize(),
        convenient.compile().unwrap().serialize()
    );
}

#[test]
fn relation_evaluation_requires_the_exact_witness_length() {
    let mut relation = LinearRelation::<G>::new();
    let x = relation.allocate_scalar();
    relation.allocate_eq(x * relation.generator());

    for witness in [&[][..], &[Scalar::ONE, Scalar::ONE][..]] {
        assert!(relation.linear_map.evaluate(witness).is_err());
        assert!(relation.compute_image(witness).is_err());
    }
    assert!(relation.compile().is_err());
}

#[test]
fn preassigned_images_are_checked_not_overwritten() {
    let witness = [Scalar::from(42u64)];
    let public_key = G::generator() * witness[0];

    let mut matching = LinearRelation::<G>::new();
    let x = matching.allocate_scalar();
    matching.allocate_eq_with(public_key, x * matching.generator());
    assert!(matching.compile_with_witness(&witness).is_ok());

    let wrong_public_key = G::generator() * Scalar::from(7u64);
    let mut relation = LinearRelation::<G>::new();
    let x = relation.allocate_scalar();
    relation.allocate_eq_with(wrong_public_key, x * relation.generator());

    assert!(relation.compute_image(&witness).is_err());
    assert_eq!(relation.compile().unwrap().image(), &[wrong_public_key]);
}

#[test]
fn image_assignment_is_transactional() {
    let mut relation = LinearRelation::<G>::new();
    let [x, y] = relation.allocate_scalars();
    let shared_output = relation.allocate_element();
    relation.append_equation(shared_output, x * relation.generator());
    relation.append_equation(shared_output, y * relation.generator());

    assert!(relation
        .compute_image(&[Scalar::from(1u64), Scalar::from(2u64)])
        .is_err());
    assert!(relation.compile().is_err());
}
