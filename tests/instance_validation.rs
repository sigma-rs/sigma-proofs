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
    use sigma_proofs::composition::{ComposedInstance, ComposedWitness};
    use sigma_proofs::linear_relation::{Equation, Instance, LinearRelation};
    use sigma_proofs::traits::{SigmaProtocol, SigmaProtocolSimulator};
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
        // M != 0 and Y = 0: the zero witness satisfies 0 = x * G.
        let mut relation = LinearRelation::<G>::new();
        let [var_x] = relation.allocate_scalars();
        let [var_G] = relation.allocate_elements();
        let var_X = relation.allocate_eq(var_G * var_x);
        relation.set_element(var_G, G::generator());
        relation.set_element(var_X, G::identity());
        let instance = Instance::try_from(&relation).unwrap();
        let proof = prove_batchable(
            b"nonzero map, zero image DSFS",
            &instance,
            &[Scalar::from(0u64)],
        )
        .unwrap();
        verify_batchable(b"nonzero map, zero image DSFS", &instance, &proof).unwrap();

        // M = 0 and Y = 0: a zero coefficient makes every witness valid.
        let mut relation = LinearRelation::<G>::new();
        let [var_x] = relation.allocate_scalars();
        let [var_C] = relation.allocate_elements();
        let var_X = relation.allocate_eq(var_C * var_x * Scalar::from(0u64));
        relation.set_element(var_C, G::generator());
        relation.set_element(var_X, G::identity());
        let instance = Instance::try_from(&relation).unwrap();
        let proof = prove_batchable(
            b"zero map, zero image DSFS",
            &instance,
            &[Scalar::from(42u64)],
        )
        .unwrap();
        verify_batchable(b"zero map, zero image DSFS", &instance, &proof).unwrap();
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
        // public claim. Compilation preserves it, even when it is true.
        let mut relation = LinearRelation::<G>::new();
        let var_B = relation.allocate_element();
        let var_C = relation.allocate_eq(var_B * Scalar::from(1u64));
        relation.set_elements([(var_B, G::generator()), (var_C, G::generator())]);
        let instance = Instance::try_from(&relation).unwrap();
        assert_eq!(instance.num_equations(), 1);
        assert_eq!(instance.num_scalars(), 0);
        assert!(instance.equations()[0].terms.is_empty());
        assert!(bool::from(instance.is_witness_valid(&[])));
    }

    #[test]
    fn empty_equation_sides_are_well_formed() {
        let empty_terms = Equation {
            image: vec![(1, Scalar::from(1u64))],
            terms: vec![],
        };
        assert!(Instance::<G>::new(vec![], vec![empty_terms]).is_ok());

        // An empty image denotes the identity.
        let empty_image = Equation {
            image: vec![],
            terms: vec![(0, 1, Scalar::from(1u64))],
        };
        assert!(Instance::<G>::new(vec![], vec![empty_image]).is_ok());
    }

    #[test]
    fn unused_scalar_indices_are_supported() {
        let one = Scalar::from(1u64);
        let equation = Equation {
            image: vec![(1, one)],
            terms: vec![(2, 1, one)],
        };
        let instance = Instance::<G>::new(vec![], vec![equation]).unwrap();
        assert_eq!(instance.num_scalars(), 3);

        let encoded = instance.serialize();
        let decoded = Instance::<G>::deserialize(&encoded).unwrap();
        assert_eq!(decoded.num_scalars(), 3);
        assert_eq!(decoded.equations(), instance.equations());
        assert_eq!(decoded.serialize(), encoded);

        let witness = [Scalar::from(7u64), Scalar::from(8u64), one];
        let proof = prove_batchable(b"unused scalars DSFS", &instance, &witness).unwrap();
        verify_batchable(b"unused scalars DSFS", &instance, &proof).unwrap();
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

        // False public equations are well-formed instances with no witness
        // scalars, just like their true counterparts.
        let mut linear_relation = LinearRelation::<G>::new();
        let B_var = linear_relation.allocate_element();
        let C_var = linear_relation.allocate_eq(B_var);
        linear_relation.set_elements([(B_var, B), (C_var, C)]);
        let instance = linear_relation.compile().unwrap();
        assert_eq!(instance.num_equations(), 1);
        assert_eq!(instance.num_scalars(), 0);
        assert!(!bool::from(instance.is_witness_valid(&[])));

        let mut linear_relation = LinearRelation::<G>::new();
        let [B_var, A_var] = linear_relation.allocate_elements();
        let X_var = linear_relation.allocate_eq(B_var * pub_scalar + A_var * Scalar::from(3u64));
        linear_relation.set_elements([(B_var, B), (A_var, A), (X_var, X)]);
        let instance = linear_relation.compile().unwrap();
        assert_eq!(instance.num_equations(), 1);
        assert_eq!(instance.num_scalars(), 0);
        assert!(!bool::from(instance.is_witness_valid(&[])));

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
    fn public_equations_preserve_truth_and_support_simulation() {
        for holds in [false, true] {
            let mut relation = LinearRelation::<G>::new();
            let image = G::generator() * Scalar::from(if holds { 1u64 } else { 2u64 });
            relation.allocate_eq_with(image, relation.generator());
            let instance = relation.compile().unwrap();
            assert_eq!(instance.num_equations(), 1);
            assert_eq!(instance.num_scalars(), 0);
            assert!(instance.equations()[0].terms.is_empty());
            assert_eq!(bool::from(instance.is_witness_valid(&[])), holds);

            let decoded = Instance::<G>::deserialize(&instance.serialize()).unwrap();
            assert_eq!(decoded.serialize(), instance.serialize());
            assert_eq!(decoded.equations(), instance.equations());
            let batchable = prove_batchable(b"public equation DSFS", &instance, &[]).unwrap();
            assert_eq!(
                verify_batchable(b"public equation DSFS", &decoded, &batchable).is_ok(),
                holds,
            );
            let compact = prove_compact(b"public equation CMPT", &instance, &[]).unwrap();
            assert_eq!(
                verify_compact(b"public equation CMPT", &decoded, &compact).is_ok(),
                holds,
            );

            // A false relation still admits a simulated transcript for a
            // chosen challenge, which is what OR and threshold branches need.
            let challenge = Scalar::from(7u64);
            let response = vec![];
            let commitment = instance.simulate_commitment(&challenge, &response).unwrap();
            instance
                .verifier(&commitment, &challenge, &response)
                .unwrap();
        }
    }

    #[test]
    fn false_public_equations_compose_with_true_branches() {
        let mut public = LinearRelation::<G>::new();
        public.allocate_eq_with(G::identity(), public.generator());
        let public = public.compile().unwrap();
        let secret = Scalar::from(42u64);
        let mut dlog = LinearRelation::<G>::new();
        let x = dlog.allocate_scalar();
        dlog.allocate_eq_with(G::generator() * secret, x * dlog.generator());
        let dlog = dlog.compile().unwrap();
        let branches = [public, dlog];
        let witnesses = [vec![], vec![secret]];
        for (instance, witness, holds) in [
            (
                ComposedInstance::or(branches.clone()).unwrap(),
                ComposedWitness::or(witnesses.clone()),
                true,
            ),
            (
                ComposedInstance::threshold(1, branches.clone()).unwrap(),
                ComposedWitness::threshold(witnesses.clone()),
                true,
            ),
            (
                ComposedInstance::threshold(2, branches.clone()).unwrap(),
                ComposedWitness::threshold(witnesses.clone()),
                false,
            ),
            (
                ComposedInstance::and(branches).unwrap(),
                ComposedWitness::and(witnesses),
                false,
            ),
        ] {
            let batchable = prove_batchable(b"public branch DSFS", &instance, &witness).unwrap();
            assert_eq!(
                verify_batchable(b"public branch DSFS", &instance, &batchable).is_ok(),
                holds
            );
            let compact = prove_compact(b"public branch CMPT", &instance, &witness).unwrap();
            assert_eq!(
                verify_compact(b"public branch CMPT", &instance, &compact).is_ok(),
                holds
            );
        }
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
