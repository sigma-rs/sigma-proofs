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
    use sigma_proofs::linear_relation::{Equation, Instance, LinearRelation};
    use sigma_proofs::{
        prove_batchable, prove_compact, verify_batchable, verify_compact, ProverRng,
    };
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
        // 0 = x * G: the identity statement element is valid, but the image
        // still fails check 9.
        let mut relation = LinearRelation::<G>::new();
        let [var_x] = relation.allocate_scalars();
        let [var_G] = relation.allocate_elements();
        let var_X = relation.allocate_eq(var_G * var_x);
        relation.set_element(var_G, G::generator());
        relation.set_element(var_X, G::identity());
        let err = Instance::try_from(&relation).unwrap_err();
        assert_eq!(err.check, Some(9));

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
        // A relation with no equations compiles to the valid empty instance.
        let relation = LinearRelation::<G>::new();
        let instance = relation.compile().unwrap();
        assert_eq!(instance.num_equations(), 0);
        assert_eq!(instance.num_scalars(), 0);
        assert_eq!(instance.image(), []);
        let serialized = instance.serialize();
        assert_eq!(
            Instance::<G>::deserialize(&serialized).unwrap().serialize(),
            serialized
        );

        let batchable = prove_batchable(b"empty relation DSFS", &instance, &[]).unwrap();
        assert!(batchable.is_empty());
        verify_batchable(b"empty relation DSFS", &instance, &batchable).unwrap();

        let compact = prove_compact(b"empty relation CMPT", &instance, &[]).unwrap();
        verify_compact(b"empty relation CMPT", &instance, &compact).unwrap();

        // An equation whose right-hand side carries no witness scalar is a
        // public claim, evaluated at compilation. A true one is stripped and
        // leaves the empty relation.
        let mut relation = LinearRelation::<G>::new();
        let var_B = relation.allocate_element();
        let var_C = relation.allocate_eq(var_B * Scalar::from(1u64));
        relation.set_elements([(var_B, G::generator()), (var_C, G::generator())]);
        assert_eq!(Instance::try_from(&relation).unwrap().num_equations(), 0);
    }

    #[test]
    fn empty_equation_sides_are_well_formed() {
        let empty_terms = Equation {
            image: vec![(1, Scalar::from(1u64))],
            terms: vec![],
        };
        assert!(Instance::<G>::new(vec![], vec![empty_terms]).is_ok());

        // An empty image denotes the identity. It is syntactically valid and
        // reaches the separate identity-image check.
        let empty_image = Equation {
            image: vec![],
            terms: vec![(0, 1, Scalar::from(1u64))],
        };
        let err =
            Instance::<G>::new(vec![], vec![empty_image]).unwrap_err();
        assert_eq!(err.check, Some(9));
    }

    #[test]
    fn identity_statement_element_roundtrips() {
        let one = Scalar::from(1u64);
        let equation = Equation {
            image: vec![(1, one), (2, one)],
            terms: vec![(0, 1, one)],
        };
        let instance = Instance::new(vec![G::identity()], vec![equation]).unwrap();
        let encoded = instance.serialize();
        let decoded = Instance::<G>::deserialize(&encoded).unwrap();
        assert_eq!(decoded.elements(), instance.elements());
        assert_eq!(decoded.serialize(), encoded);
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

        // The identity is a valid statement element. Constant terms cross to
        // the image, so this compiles to -C = x*A + y*B.
        linear_relation.set_elements([(Z_var, G::identity()), (A_var, A), (B_var, B), (C_var, C)]);
        assert!(linear_relation.compile().is_ok());

        // A non-identity image element remains valid too.
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
