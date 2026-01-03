//! Validation criteria tests for sigma protocols
//!
//! This module contains tests for validating both instances and proofs,
//! ensuring that malformed inputs are properly rejected.

#[cfg(test)]
mod instance_validation {
    use bls12_381::{G1Projective as G, Scalar};
    use ff::Field;
    use group::Group;
    use sigma_proofs::{
        errors::Error,
        linear_relation::{CanonicalLinearRelation, LinearRelation},
    };

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
        let result = CanonicalLinearRelation::try_from(&relation);
        assert!(result.is_err());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_zero_image() {
        // Create a linear relation with zero elements in the image
        // 0 = x * G (which is invalid)
        let mut relation = LinearRelation::<G>::new();
        let [var_x] = relation.allocate_scalars();
        let [var_G] = relation.allocate_elements();
        let var_X = relation.allocate_eq(var_G * var_x);
        relation.set_element(var_G, G::generator());
        relation.set_element(var_X, G::identity());
        let result = CanonicalLinearRelation::try_from(&relation);
        assert!(result.is_err());

        // Create a trivially valid linear relation with zero elements in the image
        // 0 = 0*B
        let mut relation = LinearRelation::<G>::new();
        let [var_B] = relation.allocate_elements();
        let var_X = relation.allocate_eq(var_B * Scalar::from(0));
        relation.set_element(var_B, G::generator());
        relation.set_element(var_X, G::identity());
        let result = CanonicalLinearRelation::try_from(&relation);
        assert!(result.is_ok());

        // Create a valid linear relation with zero elements in the image
        // 0 = 0*x*C
        let mut relation = LinearRelation::<G>::new();
        let [var_x] = relation.allocate_scalars();
        let [var_C] = relation.allocate_elements();
        let var_X = relation.allocate_eq(var_C * var_x * Scalar::from(0));
        relation.set_element(var_C, G::generator());
        relation.set_element(var_X, G::identity());
        let result = CanonicalLinearRelation::try_from(&relation);
        assert!(result.is_ok());
    }

    #[test]
    #[allow(non_snake_case)]
    pub fn test_degenerate_equation() {
        // This relation should fail for two reasons:
        // 1. because var_B is not assigned
        let mut relation = LinearRelation::<G>::new();
        let x = relation.allocate_scalar();
        let var_B = relation.allocate_element();
        let var_X = relation.allocate_eq((x + (-Scalar::ONE)) * var_B + (-var_B));
        relation.set_element(var_X, G::identity());
        assert!(CanonicalLinearRelation::try_from(&relation).is_err());

        // 2. because var_X is not assigned
        let mut relation = LinearRelation::<G>::new();
        let x = relation.allocate_scalar();
        let var_B = relation.allocate_element();
        let _var_X = relation.allocate_eq((x + (-Scalar::ONE)) * var_B + (-var_B));
        relation.set_element(var_B, G::generator());
        assert!(CanonicalLinearRelation::try_from(&relation).is_err());
    }

    #[test]
    fn test_inconsistent_equation_count() {
        // Create a relation with mismatched equations and image elements
        let mut relation = LinearRelation::<G>::new();
        let [var_x] = relation.allocate_scalars();
        let [var_g, var_h] = relation.allocate_elements();
        relation.set_elements([
            (var_g, G::generator()),
            (var_h, G::generator() * Scalar::from(2u64)),
        ]);

        // Add two equations but only one image element
        let var_img_1 = relation.allocate_eq(var_x * var_g + var_h);
        relation.allocate_eq(var_x * var_h + var_g);
        relation.set_element(var_g, G::generator());
        relation.set_element(var_h, G::generator() * Scalar::from(2));
        relation.set_element(var_img_1, G::generator() * Scalar::from(3));
        assert!(relation.canonical().is_err());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_empty_string() {
        let rng = &mut rand::thread_rng();
        let relation = LinearRelation::<G>::new();
        let nizk = relation.into_nizk(b"test_session").unwrap();
        let narg_string = nizk.prove_batchable(&vec![], rng).unwrap();
        assert!(narg_string.is_empty());

        let mut relation = LinearRelation::<G>::new();
        let var_B = relation.allocate_element();
        let var_C = relation.allocate_eq(var_B * Scalar::from(1));
        relation.set_elements([(var_B, G::generator()), (var_C, G::generator())]);
        assert!(CanonicalLinearRelation::try_from(&relation).is_ok());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_statement_without_witness() {
        let rng = &mut rand::thread_rng();

        let pub_scalar = Scalar::from(42);
        let A = G::generator();
        let B = G::generator() * Scalar::from(42);
        let C = B * pub_scalar + A * Scalar::from(3);

        let X = G::generator() * Scalar::from(4);

        // The following relation is trivially invalid.
        // That is, we know that no witness will ever satisfy it.
        let mut linear_relation = LinearRelation::<G>::new();
        let B_var = linear_relation.allocate_element();
        let C_var = linear_relation.allocate_eq(B_var);
        linear_relation.set_elements([(B_var, B), (C_var, C)]);
        let nizk = linear_relation.into_nizk(b"test_session").unwrap();
        assert!(matches!(
            nizk.verify_batchable(&nizk.prove_batchable(&vec![], rng).unwrap())
                .unwrap_err(),
            Error::VerificationFailure
        ));

        // Also in this case, we know that no witness will ever satisfy the relation.
        // X != B * pub_scalar + A * 3
        let mut linear_relation = LinearRelation::<G>::new();
        let [B_var, A_var] = linear_relation.allocate_elements();
        let X_var = linear_relation.allocate_eq(B_var * pub_scalar + A_var * Scalar::from(3));
        linear_relation.set_elements([(B_var, B), (A_var, A), (X_var, X)]);
        assert!(matches!(
            nizk.verify_batchable(&nizk.prove_batchable(&vec![], rng).unwrap())
                .unwrap_err(),
            Error::VerificationFailure
        ));

        // The following relation is valid and should pass.
        let mut linear_relation = LinearRelation::<G>::new();
        let B_var = linear_relation.allocate_element();
        let C_var = linear_relation.allocate_eq(B_var);
        linear_relation.set_elements([(B_var, B), (C_var, B)]);
        assert!(linear_relation.canonical().is_ok());

        // The following relation is valid and should pass.
        // C = B * pub_scalar + A * 3
        let mut linear_relation = LinearRelation::<G>::new();
        let [B_var, A_var] = linear_relation.allocate_elements();
        let C_var = linear_relation.allocate_eq(B_var * pub_scalar + A_var * Scalar::from(3));
        linear_relation.set_elements([(B_var, B), (A_var, A), (C_var, C)]);
        assert!(linear_relation.canonical().is_ok());

        // The following relation is for
        // X = B * x + B * pub_scalar + A * 3
        // and should be considered a valid instance.
        let mut linear_relation = LinearRelation::<G>::new();
        let x_var = linear_relation.allocate_scalar();
        let [B_var, A_var] = linear_relation.allocate_elements();
        let X_var = linear_relation
            .allocate_eq(B_var * x_var + B_var * pub_scalar + A_var * Scalar::from(3));
        linear_relation.set_elements([(B_var, B), (A_var, A), (X_var, X)]);
        assert!(linear_relation.canonical().is_ok());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_statement_with_trivial_image() {
        let mut rng = rand::thread_rng();
        let mut linear_relation = LinearRelation::new();

        let [x_var, y_var] = linear_relation.allocate_scalars();
        let [Z_var, A_var, B_var, C_var] = linear_relation.allocate_elements();
        linear_relation.append_equation(Z_var, x_var * A_var + y_var * B_var + C_var);

        let [x, y] = [Scalar::random(&mut rng), Scalar::random(&mut rng)];
        let Z = G::identity();
        let A = G::random(&mut rng);
        let B = G::generator();
        let C = -x * A - y * B;

        // The equation 0 = x*A + y*B + C
        // Has a non-trivial solution.
        linear_relation.set_elements([(Z_var, Z), (A_var, A), (B_var, B), (C_var, C)]);
        assert!(linear_relation.canonical().is_ok());

        // Adding more non-trivial statements does not affect the validity of the relation.
        let F_var = linear_relation.allocate_element();
        let f_var = linear_relation.allocate_scalar();
        linear_relation.append_equation(F_var, f_var * A_var);
        let f = Scalar::random(&mut rng);
        let F = A * f;
        linear_relation.set_elements([(F_var, F), (A_var, A)]);
        assert!(linear_relation.canonical().is_ok());
    }
}

#[cfg(test)]
mod proof_validation {
    use bls12_381::{G1Projective as G, Scalar};
    use ff::Field;
    use rand::RngCore;
    use sigma_proofs::Nizk;
    use sigma_proofs::codec::KeccakByteSchnorrCodec;
    use sigma_proofs::composition::{ComposedRelation, ComposedWitness};
    use sigma_proofs::linear_relation::{CanonicalLinearRelation, LinearRelation};

    type TestNizk = Nizk<CanonicalLinearRelation<G>, KeccakByteSchnorrCodec<G>>;

    /// Helper function to create a simple discrete log proof
    fn create_valid_proof() -> (Vec<u8>, TestNizk) {
        let mut rng = rand::thread_rng();

        // Create a simple discrete log relation
        let mut relation = LinearRelation::<G>::new();
        let [var_x] = relation.allocate_scalars();
        let [var_g, var_x_g] = relation.allocate_elements::<2>();

        let x = Scalar::from(42u64);
        let x_g = G::generator() * x;

        relation.set_elements([(var_g, G::generator()), (var_x_g, x_g)]);
        relation.append_equation(var_x_g, var_x * var_g);

        let nizk = TestNizk::new(b"test_session", relation.canonical().unwrap());

        let witness = vec![x];
        let proof = nizk.prove_batchable(&witness, &mut rng).unwrap();

        (proof, nizk)
    }

    #[test]
    fn test_proof_bitflip() {
        let (mut proof, nizk) = create_valid_proof();

        // Verify the original proof is valid
        assert!(nizk.verify_batchable(&proof).is_ok());

        // Test bitflips at various positions
        for pos in 0..proof.len() {
            let original_byte = proof[pos];

            // Flip each bit in the byte
            for bit in 0..8 {
                proof[pos] ^= 1 << bit;

                // Verification should fail
                assert!(
                    nizk.verify_batchable(&proof).is_err(),
                    "Proof verification should fail with bit {bit} flipped at position {pos}"
                );

                // Restore original byte
                proof[pos] = original_byte;
            }
        }
    }

    #[test]
    fn test_proof_append_bytes() {
        let (mut proof, nizk) = create_valid_proof();

        // Verify the original proof is valid
        assert!(nizk.verify_batchable(&proof).is_ok());

        // Test appending various amounts of bytes
        let append_sizes = [1, 8, 32, 100];

        for &size in &append_sizes {
            let original_len = proof.len();

            // Append random bytes
            let mut rng = rand::thread_rng();
            let mut extra_bytes = vec![0u8; size];
            rng.fill_bytes(&mut extra_bytes);
            proof.extend_from_slice(&extra_bytes);

            // Verification should fail
            assert!(
                nizk.verify_batchable(&proof).is_err(),
                "Proof verification should fail with {size} bytes appended"
            );

            // Restore original proof
            proof.truncate(original_len);
        }
    }

    #[test]
    fn test_proof_prepend_bytes() {
        let (proof, nizk) = create_valid_proof();

        // Verify the original proof is valid
        assert!(nizk.verify_batchable(&proof).is_ok());

        // Test prepending various amounts of bytes
        let prepend_sizes = [1, 8, 32, 100];

        for &size in &prepend_sizes {
            // Create new proof with prepended bytes
            let mut rng = rand::thread_rng();
            let mut prepended_proof = vec![0u8; size];
            rng.fill_bytes(&mut prepended_proof);
            prepended_proof.extend_from_slice(&proof);

            // Verification should fail
            assert!(
                nizk.verify_batchable(&prepended_proof).is_err(),
                "Proof verification should fail with {size} bytes prepended"
            );
        }
    }

    #[test]
    fn test_proof_truncation() {
        let (proof, nizk) = create_valid_proof();

        // Verify the original proof is valid
        assert!(nizk.verify_batchable(&proof).is_ok());

        // Test truncating various amounts
        let truncate_sizes = [1, 8, proof.len() / 2, proof.len() - 1];

        for &size in &truncate_sizes {
            if size < proof.len() {
                let truncated_proof = &proof[..proof.len() - size];

                // Verification should fail
                assert!(
                    nizk.verify_batchable(truncated_proof).is_err(),
                    "Proof verification should fail with {size} bytes truncated"
                );
            }
        }
    }

    #[test]
    fn test_empty_proof() {
        let (_, nizk) = create_valid_proof();
        let empty_proof = vec![];

        // Verification should fail for empty proof
        assert!(
            nizk.verify_batchable(&empty_proof).is_err(),
            "Proof verification should fail for empty proof"
        );
    }

    #[test]
    fn test_random_bytes_as_proof() {
        let (valid_proof, nizk) = create_valid_proof();
        let proof_len = valid_proof.len();

        // Test with completely random bytes of the same length
        let mut rng = rand::thread_rng();
        let mut random_proof = vec![0u8; proof_len];
        rng.fill_bytes(&mut random_proof);

        // Verification should fail
        assert!(
            nizk.verify_batchable(&random_proof).is_err(),
            "Proof verification should fail for random bytes"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_or_relation() {
        // This test reproduces the issue from sigma_compiler's simple_or test
        // where an OR relation fails verification when using the wrong branch
        let mut rng = rand::thread_rng();

        // Create generators
        // For this test, we'll use two different multiples of the generator
        let B = G::generator();
        let A = B * Scalar::from(42u64); // Different generator

        // Create scalars
        let x = Scalar::random(&mut rng);
        let y = Scalar::random(&mut rng);

        // Set C = y*B (so the second branch should be satisfied)
        let C = B * y;

        // Create the first branch: C = x*A
        let mut lr1 = LinearRelation::new();
        let x_var = lr1.allocate_scalar();
        let A_var = lr1.allocate_element();
        let eq1 = lr1.allocate_eq(x_var * A_var);
        lr1.set_element(A_var, A);
        lr1.set_element(eq1, C);
        // Create the second branch: C = y*B
        let mut lr2 = LinearRelation::new();
        let y_var = lr2.allocate_scalar();
        let B_var = lr2.allocate_element();
        let eq2 = lr2.allocate_eq(y_var * B_var);
        lr2.set_element(B_var, B);
        lr2.set_element(eq2, C);

        // Create OR composition
        let or_relation =
            ComposedRelation::or([lr1.canonical().unwrap(), lr2.canonical().unwrap()]);
        let nizk = or_relation.into_nizk(b"test_or_relation");

        // Create a correct witness for branch 1 (C = y*B)
        // Note: x is NOT a valid witness for branch 0 because C ≠ x*A
        let witness_correct = ComposedWitness::Or(vec![
            ComposedWitness::Simple(vec![x]),
            ComposedWitness::Simple(vec![y]),
        ]);
        let proof = nizk.prove_batchable(&witness_correct, &mut rng).unwrap();
        assert!(
            nizk.verify_batchable(&proof).is_ok(),
            "Valid proof should verify"
        );

        // Now test with ONLY invalid witnesses (neither branch satisfied)
        // Branch 0 requires C = x*A, but we use random x
        // Branch 1 requires C = y*B, but we use a different random value
        let wrong_y = Scalar::random(&mut rng);
        let witness_wrong = ComposedWitness::Or(vec![
            ComposedWitness::Simple(vec![x]),
            ComposedWitness::Simple(vec![wrong_y]),
        ]);
        let proof_result = nizk.prove_batchable(&witness_wrong, &mut rng);
        assert!(
            proof_result.is_err(),
            "Proof should fail with invalid witnesses"
        );

        // Create a correct witness for both branches
        let witness_correct = ComposedWitness::Or(vec![
            ComposedWitness::Simple(vec![y]),
            ComposedWitness::Simple(vec![y]),
        ]);
        let proof = nizk.prove_batchable(&witness_correct, &mut rng).unwrap();
        assert!(
            nizk.verify_batchable(&proof).is_ok(),
            "Prover fails when all witnesses in an OR proof are valid"
        );
    }
}
