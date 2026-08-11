//! Instance validation tests for sigma protocols.
//!
//! This module tests that malformed or invalid instances are rejected
//! at construction time (before any proof is attempted).

#[cfg(test)]
mod instance_validation {
    use curve25519_dalek::ristretto::RistrettoPoint as G;
    use curve25519_dalek::scalar::Scalar;
    use group::Group;
    use sigma_proofs::codec::ScalarCodec;
    use sigma_proofs::linear_relation::{Instance, LinearRelation};
    use sigma_proofs::ProverRng;
    use spongefish::Encoding;

    #[test]
    fn test_unassigned_group_vars() {
        // Create a linear relation with unassigned group variables
        let mut relation = LinearRelation::<G>::new();

        // Allocate scalars and elements
        let [var_x] = relation.allocate_scalars();
        let [var_g, var_x_g] = relation.allocate_elements();

        // Set only one element, leaving var_g unassigned
        let x_val = G::generator() * Scalar::from(42u64);
        relation.set_element(var_x_g, x_val);

        // Add equation: X = x * G (but G is not set)
        relation.append_equation(var_x_g, var_x * var_g);

        // Try to convert to canonical form - should fail
        let result = Instance::try_from(&relation);
        assert!(result.is_err());
    }

    #[test]
    fn unassigned_equation_output_is_rejected() {
        let mut relation = LinearRelation::<G>::new();
        let x = relation.allocate_scalar();
        relation.allocate_eq(x * relation.generator());

        assert!(relation.compile().is_err());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_zero_image() {
        // 0 = x * G: the identity appears both as a statement element
        // (check 8) and as an image (check 9). Rejected.
        let mut relation = LinearRelation::<G>::new();
        let [var_x] = relation.allocate_scalars();
        let [var_G] = relation.allocate_elements();
        let var_X = relation.allocate_eq(var_G * var_x);
        relation.set_element(var_G, G::generator());
        relation.set_element(var_X, G::identity());
        let err = Instance::try_from(&relation).unwrap_err();
        assert_eq!(err.check, Some(8));

        // 0 = 0*x*C: same, with a zero-coefficient witness term. The zero
        // coefficient makes the scalar's effective base the identity in its
        // only equation (check 10), besides the identity image element.
        let mut relation = LinearRelation::<G>::new();
        let [var_x] = relation.allocate_scalars();
        let [var_C] = relation.allocate_elements();
        let var_X = relation.allocate_eq(var_C * var_x * Scalar::from(0u64));
        relation.set_element(var_C, G::generator());
        relation.set_element(var_X, G::identity());
        assert!(Instance::try_from(&relation).is_err());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_empty_relation_and_constant_equation() {
        // Check 1 requires at least one equation, so a relation with none has
        // no instance to compile to: there is no contentless instance for it
        // to become, and no empty NARG string anywhere in the library.
        let relation = LinearRelation::<G>::new();
        assert!(relation.compile().is_err());

        // An equation whose right-hand side carries no witness scalar is a
        // public claim, evaluated at compilation. A true one is stripped, and
        // stripping the only equation leaves nothing to prove — refused for
        // the same reason.
        let mut relation = LinearRelation::<G>::new();
        let var_B = relation.allocate_element();
        let var_C = relation.allocate_eq(var_B * Scalar::from(1u64));
        relation.set_elements([(var_B, G::generator()), (var_C, G::generator())]);
        assert!(Instance::try_from(&relation).is_err());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_statement_without_witness() {
        let pub_scalar = Scalar::from(42u64);
        let A = G::generator();
        let B = G::generator() * Scalar::from(42u64);
        let C = B * pub_scalar + A * Scalar::from(3u64);
        let X = G::generator() * Scalar::from(4u64);

        // Relations without witness scalars are all-constant equations,
        // evaluated at compilation: these do not hold, so compilation fails
        // (the statement is false), without any specification check number.
        let mut linear_relation = LinearRelation::<G>::new();
        let B_var = linear_relation.allocate_element();
        let C_var = linear_relation.allocate_eq(B_var);
        linear_relation.set_elements([(B_var, B), (C_var, C)]);
        assert_eq!(linear_relation.compile().unwrap_err().check, None);

        let mut linear_relation = LinearRelation::<G>::new();
        let [B_var, A_var] = linear_relation.allocate_elements();
        let X_var = linear_relation.allocate_eq(B_var * pub_scalar + A_var * Scalar::from(3u64));
        linear_relation.set_elements([(B_var, B), (A_var, A), (X_var, X)]);
        assert_eq!(linear_relation.compile().unwrap_err().check, None);

        // With a witness term present, constant terms are fine: they cross to
        // the image with their coefficient negated and every element stays
        // individually bound.
        // X = B * x + B * pub_scalar + A * 3
        let mut linear_relation = LinearRelation::<G>::new();
        let x_var = linear_relation.allocate_scalar();
        let [B_var, A_var] = linear_relation.allocate_elements();
        let X_var = linear_relation
            .allocate_eq(B_var * x_var + B_var * pub_scalar + A_var * Scalar::from(3u64));
        linear_relation.set_elements([(B_var, B), (A_var, A), (X_var, X)]);
        assert!(linear_relation.compile().is_ok());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_statement_with_trivial_image() {
        let mut rng = ProverRng::from_os_entropy();
        let mut linear_relation = LinearRelation::new();

        let [x_var, y_var] = linear_relation.allocate_scalars();
        let [Z_var, A_var, B_var, C_var] = linear_relation.allocate_elements();
        linear_relation.append_equation(Z_var, x_var * A_var + y_var * B_var + C_var);

        let [x, y] = core::array::from_fn(|_| <G as group::Group>::Scalar::sample(&mut rng));
        let A = {
            let [t] = core::array::from_fn(|_| <G as group::Group>::Scalar::sample(&mut rng));
            G::generator() * t
        };
        let B = G::generator();
        let C = -x * A - y * B;

        // The equation 0 = x*A + y*B + C has a non-trivial solution, but the
        // identity is a statement element, which the specification rejects
        // (check 8): an equation whose image evaluates to the identity is
        // satisfied by the all-zero witness and attests nothing.
        linear_relation.set_elements([(Z_var, G::identity()), (A_var, A), (B_var, B), (C_var, C)]);
        assert_eq!(linear_relation.compile().unwrap_err().check, Some(8));

        // Replacing the identity with a real image element makes the
        // relation valid: Z = x*A + y*B + C with Z = x*A + y*B + C.
        let mut linear_relation = LinearRelation::new();
        let [x_var, y_var] = linear_relation.allocate_scalars();
        let [Z_var, A_var, B_var, C_var] = linear_relation.allocate_elements();
        linear_relation.append_equation(Z_var, x_var * A_var + y_var * B_var + C_var);
        let C = {
            let [t] = core::array::from_fn(|_| <G as group::Group>::Scalar::sample(&mut rng));
            G::generator() * t
        };
        let Z = A * x + B * y + C;
        linear_relation.set_elements([(Z_var, Z), (A_var, A), (B_var, B), (C_var, C)]);
        assert!(linear_relation.compile().is_ok());
    }

    /// The cached encoding must be canonical on every path that
    /// produces an `Instance`, since it is what the transcript absorbs.
    #[test]
    fn encoding_is_canonical() {
        let mut rng = ProverRng::from_os_entropy();
        let mut relation = LinearRelation::<G>::new();
        let [var_x, var_r] = relation.allocate_scalars();
        let [var_g, var_h] = relation.allocate_elements();
        relation.allocate_eq(var_g * var_x + var_h * var_r);
        relation.set_elements([
            (var_g, G::generator()),
            (var_h, G::generator() * Scalar::sample(&mut rng)),
        ]);
        let witness = [Scalar::sample(&mut rng), Scalar::sample(&mut rng)];
        let compiled = relation.compile_with_witness(&witness).unwrap();
        assert_eq!(compiled.encode().as_ref(), compiled.serialize());

        let parsed = Instance::<G>::deserialize(&compiled.serialize()).unwrap();
        assert_eq!(parsed.encode().as_ref(), parsed.serialize());
        assert_eq!(parsed.encode().as_ref(), compiled.encode().as_ref());
    }
}
