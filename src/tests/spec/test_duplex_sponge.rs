use crate::duplex_sponge::{keccak::KeccakDuplexSponge, DuplexSpongeInterface};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
struct TestVector {
    #[serde(rename = "Expected")]
    expected: String,
    #[serde(rename = "HashFunction")]
    hash_function: String,
    #[serde(rename = "Operations")]
    operations: Vec<Operation>,
    #[serde(rename = "Tag")]
    tag: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Operation {
    #[serde(rename = "type")]
    op_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    length: Option<usize>,
}

fn hex_decode(hex_str: &str) -> Vec<u8> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
        .collect()
}

fn load_test_vectors() -> HashMap<String, TestVector> {
    let json_data = include_str!("./duplexSpongeVectors.json");
    serde_json::from_str(json_data).expect("Failed to parse test vectors JSON")
}

fn run_test_vector(name: &str, test_vector: &TestVector) {
    let tag_bytes = hex_decode(&test_vector.tag);
    let mut tag_array = [0u8; 32];
    tag_array.copy_from_slice(&tag_bytes);

    let mut sponge = KeccakDuplexSponge::new(tag_array);
    let mut final_output = Vec::new();

    for operation in &test_vector.operations {
        match operation.op_type.as_str() {
            "absorb" => {
                if let Some(data_hex) = &operation.data {
                    let data = hex_decode(data_hex);
                    sponge.absorb(&data);
                }
            }
            "squeeze" => {
                if let Some(length) = operation.length {
                    let output = sponge.squeeze(length);
                    final_output = output;
                }
            }
            _ => panic!("Unknown operation type: {}", operation.op_type),
        }
    }

    let expected_output = hex_decode(&test_vector.expected);
    assert_eq!(final_output, expected_output, "Test vector '{name}' failed");
}

#[test]
fn test_all_duplex_sponge_vectors() {
    let test_vectors = load_test_vectors();

    for (name, test_vector) in test_vectors {
        run_test_vector(&name, &test_vector);
    }
}

#[test]
fn test_keccak_duplex_sponge_vector() {
    let test_vectors = load_test_vectors();
    let test_vector = test_vectors.get("test_keccak_duplex_sponge").unwrap();
    run_test_vector("test_keccak_duplex_sponge", test_vector);
}

#[test]
fn test_absorb_empty_before_vector() {
    let test_vectors = load_test_vectors();
    let test_vector = test_vectors
        .get("test_absorb_empty_before_does_not_break")
        .unwrap();
    run_test_vector("test_absorb_empty_before_does_not_break", test_vector);
}

#[test]
fn test_absorb_empty_after_vector() {
    let test_vectors = load_test_vectors();
    let test_vector = test_vectors
        .get("test_absorb_empty_after_does_not_break")
        .unwrap();
    run_test_vector("test_absorb_empty_after_does_not_break", test_vector);
}

#[test]
fn test_squeeze_zero_before_vector() {
    let test_vectors = load_test_vectors();
    let test_vector = test_vectors.get("test_squeeze_zero_behavior").unwrap();
    run_test_vector("test_squeeze_zero_behavior", test_vector);
}

#[test]
fn test_squeeze_zero_after_vector() {
    let test_vectors = load_test_vectors();
    let test_vector = test_vectors
        .get("test_squeeze_zero_after_behavior")
        .unwrap();
    run_test_vector("test_squeeze_zero_after_behavior", test_vector);
}

#[test]
fn test_absorb_squeeze_absorb_consistency_vector() {
    let test_vectors = load_test_vectors();
    let test_vector = test_vectors
        .get("test_absorb_squeeze_absorb_consistency")
        .unwrap();
    run_test_vector("test_absorb_squeeze_absorb_consistency", test_vector);
}

#[test]
fn test_associativity_of_absorb_vector() {
    let test_vectors = load_test_vectors();
    let test_vector = test_vectors.get("test_associativity_of_absorb").unwrap();
    run_test_vector("test_associativity_of_absorb", test_vector);
}

#[test]
fn test_tag_affects_output_vector() {
    let test_vectors = load_test_vectors();
    let test_vector = test_vectors.get("test_tag_affects_output").unwrap();
    run_test_vector("test_tag_affects_output", test_vector);
}

#[test]
fn test_multiple_blocks_absorb_squeeze_vector() {
    let test_vectors = load_test_vectors();
    let test_vector = test_vectors
        .get("test_multiple_blocks_absorb_squeeze")
        .unwrap();
    run_test_vector("test_multiple_blocks_absorb_squeeze", test_vector);
}
