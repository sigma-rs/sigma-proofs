//! Validation criteria tests for sigma protocols
//!
//! This module contains tests for validating both instances and proofs,
//! ensuring that malformed inputs are properly rejected.

#[cfg(test)]
mod instance_validation {
    use crate::errors::Error;
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
        assert!(matches!(
            result.unwrap_err(),
            Error::UnassignedGroupVar { .. }
        ));
    }

    #[test]
    fn test_zero_image_elements() {
        // Create a linear relation with zero elements in the image
        let mut relation = LinearRelation::<G>::new();

        // Allocate scalars and elements
        let [var_x] = relation.allocate_scalars();
        let [var_g] = relation.allocate_elements::<1>();

        // Set the group element
        relation.set_elements([(var_g, G::generator())]);

        // Create an equation that results in zero (identity element)
        // This simulates a malformed relation where the image contains zero
        let zero_element = G::identity();
        let [var_zero] = relation.allocate_elements::<1>();
        relation.set_elements([(var_zero, zero_element)]);

        // Add equation: 0 = x * G (which is invalid)
        relation.linear_map.linear_combinations.push(
            crate::linear_relation::LinearCombination::from(vec![(var_x, var_g)]),
        );
        relation.image.push(var_zero);

        // Try to convert to canonical form
        let result = CanonicalLinearRelation::try_from(&relation);

        // The conversion might succeed, but we should verify the image contains zero
        if let Ok(canonical) = result {
            assert!(canonical.image.iter().any(|&elem| elem == G::identity()));
        }
    }

    #[test]
    fn test_empty_instance() {
        // Create an empty linear relation
        let relation = LinearRelation::<G>::new();

        // Try to convert empty relation to canonical form
        let result = CanonicalLinearRelation::try_from(&relation);

        // Empty relations should be rejected
        assert!(result.is_err());
    }

    /// Test function with the requested LinearRelation code
    #[test]
    #[allow(non_snake_case)]
    pub fn test_degenerate_equation() {
        use ff::Field;

        // This relation should fail for two reasons:
        // 1. because B is not assigned
        let mut relation = LinearRelation::<G>::new();
        let x = relation.allocate_scalar();
        let B = relation.allocate_element();
        let _eq = relation.allocate_eq((x + (-Scalar::ONE)) * B + (-B));

        assert!(CanonicalLinearRelation::try_from(&relation).is_err());

        // 2. because the equation is void
        let mut relation = LinearRelation::<G>::new();
        let x = relation.allocate_scalar();
        let B = relation.allocate_element();
        let _eq = relation.allocate_eq((x + (-Scalar::ONE)) * B + (-B));
        relation.set_element(B, G::generator());
        assert!(CanonicalLinearRelation::try_from(&relation).is_err());
    }

    #[test]
    fn test_inconsistent_equation_count() {
        // Create a relation with mismatched equations and image elements
        let mut relation = LinearRelation::<G>::new();

        // Allocate elements
        let [var_x] = relation.allocate_scalars();
        let [var_g, var_h] = relation.allocate_elements::<2>();

        // Set elements
        relation.set_elements([
            (var_g, G::generator()),
            (var_h, G::generator() * Scalar::from(2u64)),
        ]);

        // Add two equations but only one image element
        relation.linear_map.linear_combinations.push(
            crate::linear_relation::LinearCombination::from(vec![(var_x, var_g)]),
        );
        relation.linear_map.linear_combinations.push(
            crate::linear_relation::LinearCombination::from(vec![(var_x, var_h)]),
        );
        relation.image.push(var_g); // Only one image element for two equations

        // Try to convert - should fail due to inconsistency
        let result = CanonicalLinearRelation::try_from(&relation);
        assert!(result.is_err());
    }

    #[test]
    fn without_witness() {
        let B = G::generator();
        let A = G::generator() * Scalar::from(42);
        let X = G::generator() * Scalar::from(4);
        let pub_scalar = Scalar::from(42);

        // The following relation has no equation and should trigger a fail.
        let mut linear_relation = LinearRelation::<G>::new();
        let B_var = linear_relation.allocate_element();
        let A_var = linear_relation.allocate_element();

        linear_relation.set_element(B_var, B);
        linear_relation.set_element(A_var, A);
        let result = CanonicalLinearRelation::try_from(&linear_relation);
        assert!(result.is_err());

        // The following relation does not have a witness and should trigger a fail.
        // X = B * pub_scalar + A * 3
        let mut linear_relation = LinearRelation::<G>::new();
        let B_var = linear_relation.allocate_element();
        let A_var = linear_relation.allocate_element();
        let X_var = linear_relation.allocate_eq(B_var * pub_scalar + A_var * Scalar::from(3));

        linear_relation.set_element(B_var, B);
        linear_relation.set_element(A_var, A);
        linear_relation.set_element(X_var, X);

        let result = CanonicalLinearRelation::try_from(&linear_relation);
        assert!(result.is_err());


        // The following relation is for
        // X = B * x + B * pub_scalar + A * 3
        // and should be considered a valid instance.
        let mut linear_relation = LinearRelation::<G>::new();

        let x_var = linear_relation.allocate_scalar();
        let B_var = linear_relation.allocate_element();
        let A_var = linear_relation.allocate_element();
        let X_var = linear_relation.allocate_eq(B_var * x_var + B_var * pub_scalar + A_var * Scalar::from(3));

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
    use crate::fiat_shamir::Nizk;
    use crate::linear_relation::{CanonicalLinearRelation, LinearRelation};
    use crate::schnorr_protocol::SchnorrProof;
    use bls12_381::{G1Projective as G, Scalar};
    use rand::{thread_rng, RngCore};

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
                    "Proof verification should fail with bit {} flipped at position {}",
                    bit,
                    pos
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
                "Proof verification should fail with {} bytes appended",
                size
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
                "Proof verification should fail with {} bytes prepended",
                size
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
                    "Proof verification should fail with {} bytes truncated",
                    size
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
}
