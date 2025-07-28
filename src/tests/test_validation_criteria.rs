//! Validation criteria tests for sigma protocols
//!
//! This module contains tests for validating both instances and proofs,
//! ensuring that malformed inputs are properly rejected.

#[cfg(test)]
mod instance_validation {
    use crate::linear_relation::{CanonicalLinearRelation, LinearRelation};
    use bls12_381::{G1Projective as G, Scalar};

    #[test]
    fn test_unassigned_group_vars() {
        // Create a linear relation with unassigned group variables
        let mut relation = LinearRelation::<G>::new();

        // Allocate scalars and elements
        let [var_x] = relation.allocate_scalars();
        let [var_g, var_x_g] = relation.allocate_elements::<2>();

        // Set only one element, leaving var_g unassigned
        let x_val = G::generator() * Scalar::from(42u64);
        relation.set_elements([(var_x_g, x_val)]);

        // Add equation: X = x * G (but G is not set)
        relation.append_equation(var_x_g, var_x * var_g);

        // Try to convert to canonical form - should fail
        let result = CanonicalLinearRelation::try_from(&relation);
        assert!(result.is_err());
    }

    #[test]
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
        // 0 = 0*B  (which is invalid)
        let mut relation = LinearRelation::<G>::new();
        let [var_B] = relation.allocate_elements();
        let var_X = relation.allocate_eq(var_B * Scalar::from(0));
        relation.set_element(var_B, G::generator());
        relation.set_element(var_X, G::identity());
        let result = CanonicalLinearRelation::try_from(&relation);
        assert!(result.is_ok());
    }

    #[test]
    #[allow(non_snake_case)]
    pub fn test_degenerate_equation() {
        use ff::Field;

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
        let [var_g, var_h] = relation.allocate_elements::<2>();
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

        // Try to convert - should fail due to inconsistency
        let result = CanonicalLinearRelation::try_from(&relation);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_string() {
        let rng = &mut rand::thread_rng();
        let relation = LinearRelation::<G>::new();
        let nizk = relation.into_nizk(b"test_session").unwrap();
        let narg_string = nizk.prove_batchable(&vec![], rng).unwrap();
        assert!(narg_string.is_empty());


        let mut relation = LinearRelation::<G>::new();
        let var_B = relation.allocate_element();
        let var_C = relation.allocate_eq(var_B * Scalar::from(1));
        relation.set_element(var_B, G::generator());
        relation.set_element(var_C, G::generator());
        assert!(CanonicalLinearRelation::try_from(&relation).is_ok());
    }

    #[test]
    fn test_statement_without_witness() {
        let pub_scalar = Scalar::from(42);
        let A = G::generator();
        let B = G::generator() * Scalar::from(42);
        let C = B * pub_scalar + A * Scalar::from(3);

        let X = G::generator() * Scalar::from(4);

        // The following relation is invalid and should trigger a fail.
        let mut linear_relation = LinearRelation::<G>::new();
        let B_var = linear_relation.allocate_element();
        let C_var = linear_relation.allocate_eq(B_var);
        linear_relation.set_element(B_var, B);
        linear_relation.set_element(C_var, C);
        let result = CanonicalLinearRelation::try_from(&linear_relation);
        assert!(result.is_err());

        // The following relation is valid and should pass.
        let mut linear_relation = LinearRelation::<G>::new();
        let B_var = linear_relation.allocate_element();
        let C_var = linear_relation.allocate_eq(B_var);
        linear_relation.set_element(B_var, B);
        linear_relation.set_element(C_var, B);
        let result = CanonicalLinearRelation::try_from(&linear_relation);
        assert!(result.is_ok());

        // The following relation is invalid and should trigger a fail.
        // X != B * pub_scalar + A * 3
        let mut linear_relation = LinearRelation::<G>::new();
        let B_var = linear_relation.allocate_element();
        let A_var = linear_relation.allocate_element();
        let X_var = linear_relation.allocate_eq(B_var * pub_scalar + A_var * Scalar::from(3));

        linear_relation.set_element(B_var, B);
        linear_relation.set_element(A_var, A);
        linear_relation.set_element(X_var, X);

        let result = CanonicalLinearRelation::try_from(&linear_relation);
        assert!(result.is_err());

        // The following relation is valid and should pass.
        // C = B * pub_scalar + A * 3
        let mut linear_relation = LinearRelation::<G>::new();
        let B_var = linear_relation.allocate_element();
        let A_var = linear_relation.allocate_element();
        let C_var = linear_relation.allocate_eq(B_var * pub_scalar + A_var * Scalar::from(3));

        linear_relation.set_element(B_var, B);
        linear_relation.set_element(A_var, A);
        linear_relation.set_element(C_var, C);

        let result = CanonicalLinearRelation::try_from(&linear_relation);
        assert!(result.is_ok());

        // The following relation is for
        // X = B * x + B * pub_scalar + A * 3
        // and should be considered a valid instance.
        let mut linear_relation = LinearRelation::<G>::new();

        let x_var = linear_relation.allocate_scalar();
        let B_var = linear_relation.allocate_element();
        let A_var = linear_relation.allocate_element();
        let X_var = linear_relation
            .allocate_eq(B_var * x_var + B_var * pub_scalar + A_var * Scalar::from(3));

        linear_relation.set_element(B_var, B);
        linear_relation.set_element(A_var, A);
        linear_relation.set_element(X_var, X);

        let result = CanonicalLinearRelation::try_from(&linear_relation);
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod proof_validation {
    use crate::codec::KeccakByteSchnorrCodec;
    use crate::composition::{ComposedRelation, ComposedWitness};
    use crate::fiat_shamir::Nizk;
    use crate::linear_relation::{CanonicalLinearRelation, LinearRelation};
    use crate::schnorr_protocol::SchnorrProof;
    use bls12_381::{G1Projective as G, Scalar};
    use ff::Field;
    use rand::{thread_rng, RngCore};
    use subtle::CtOption;

    type TestNizk = Nizk<SchnorrProof<G>, KeccakByteSchnorrCodec<G>>;

    /// Helper function to create a simple discrete log proof
    fn create_valid_proof() -> (Vec<u8>, TestNizk) {
        let mut rng = thread_rng();

        // Create a simple discrete log relation
        let mut relation = LinearRelation::<G>::new();
        let [var_x] = relation.allocate_scalars();
        let [var_g, var_x_g] = relation.allocate_elements::<2>();

        let x = Scalar::from(42u64);
        let x_g = G::generator() * x;

        relation.set_elements([(var_g, G::generator()), (var_x_g, x_g)]);
        relation.append_equation(var_x_g, var_x * var_g);

        let canonical = CanonicalLinearRelation::try_from(&relation).unwrap();
        let protocol = SchnorrProof(canonical);
        let nizk = TestNizk::new(b"test_session", protocol);

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
        let positions = [0, proof.len() / 2, proof.len() - 1];

        for &pos in &positions {
            let original_byte = proof[pos];

            // Flip each bit in the byte
            for bit in 0..8 {
                proof[pos] = original_byte ^ (1 << bit);

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
            let mut rng = thread_rng();
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
            let mut rng = thread_rng();
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
        let mut rng = thread_rng();
        let mut random_proof = vec![0u8; proof_len];
        rng.fill_bytes(&mut random_proof);

        // Verification should fail
        assert!(
            nizk.verify_batchable(&random_proof).is_err(),
            "Proof verification should fail for random bytes"
        );
    }

    #[test]
    fn test_or_relation() {
        // This test reproduces the issue from sigma_compiler's simple_or test
        // where an OR relation fails verification when using the wrong branch
        let mut rng = thread_rng();

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
        let mut lr1 = LinearRelation::<G>::new();
        let x_var = lr1.allocate_scalar();
        let A_var = lr1.allocate_element();
        let eq1 = lr1.allocate_eq(x_var * A_var);
        lr1.set_element(A_var, A);
        lr1.set_element(eq1, C);

        // Create the second branch: C = y*B
        let mut lr2 = LinearRelation::<G>::new();
        let y_var = lr2.allocate_scalar();
        let B_var = lr2.allocate_element();
        let eq2 = lr2.allocate_eq(y_var * B_var);
        lr2.set_element(B_var, B);
        lr2.set_element(eq2, C);

        // Create OR composition
        let or_relation = ComposedRelation::Or(vec![
            ComposedRelation::from(lr1),
            ComposedRelation::from(lr2),
        ]);

        let nizk = Nizk::<_, KeccakByteSchnorrCodec<G>>::new(b"test_or_bug", or_relation);

        // Create a correct witness for branch 1 (C = y*B)
        let witness_correct = ComposedWitness::Or(vec![
            CtOption::new(ComposedWitness::Simple(vec![x]), 0u8.into()), // branch 0 not used
            CtOption::new(ComposedWitness::Simple(vec![y]), 1u8.into()), // branch 1 is real
        ]);

        // This should succeed since branch 1 is correct
        let proof = nizk.prove_batchable(&witness_correct, &mut rng).unwrap();
        assert!(
            nizk.verify_batchable(&proof).is_ok(),
            "Valid proof should verify"
        );

        // Now test with wrong witness: using branch 0 when it's not satisfied
        // Branch 0 requires C = x*A, but C = y*B and A ≠ B, so x would need to be y/42
        let witness_wrong = ComposedWitness::Or(vec![
            CtOption::new(ComposedWitness::Simple(vec![x]), 1u8.into()), // branch 0 is real (but wrong!)
            CtOption::new(ComposedWitness::Simple(vec![y]), 0u8.into()), // branch 1 not used
        ]);
        let proof_result = nizk.prove_batchable(&witness_wrong, &mut rng);

        match proof_result {
            Ok(proof) => {
                let verify_result = nizk.verify_batchable(&proof);
                println!(
                    "Bug reproduced: Proof with wrong branch verified: {:?}",
                    verify_result.is_ok()
                );
                assert!(
                    verify_result.is_err(),
                    "BUG: Proof should fail when using wrong branch in OR relation, but it passed!"
                );
            }
            Err(e) => {
                println!("Proof generation failed as expected: {e:?}");
            }
        }
    }
}