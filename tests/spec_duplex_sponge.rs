use libtest_mimic::{Arguments, Failed, Trial};
use serde::{Deserialize, Serialize};
use sigma_proofs::{DuplexSpongeInterface, KeccakDuplexSponge, ShakeDuplexSponge};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
struct TestVector {
    #[serde(rename = "Expected")]
    expected: String,
    #[serde(rename = "HashFunction")]
    hash_function: String,
    #[serde(rename = "Operations")]
    operations: Vec<Operation>,
    #[serde(rename = "IV")]
    iv: String,
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
    let json_data = include_str!("./spec/testdata/duplexSpongeVectors.json");
    serde_json::from_str(json_data).expect("Failed to parse test vectors JSON")
}

fn run_test_vector(name: &str, test_vector: &TestVector) -> Result<(), Failed> {
    let iv_bytes = hex_decode(&test_vector.iv);
    let iv_array: [u8; 64] = iv_bytes.try_into().unwrap();

    let mut sponge: Box<dyn DuplexSpongeInterface> = match test_vector.hash_function.as_str() {
        "Keccak-f[1600] overwrite mode" => Box::new(KeccakDuplexSponge::new(iv_array)),
        "SHAKE128" => Box::new(ShakeDuplexSponge::new(iv_array)),
        _ => panic!("Unknown hash function: {}", test_vector.hash_function),
    };
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

    assert_eq!(
        hex::encode(final_output),
        test_vector.expected,
        "Test vector '{name}' failed"
    );
    Ok(())
}

#[test]
fn test_all_duplex_sponge_vectors() {
    let test_vectors = load_test_vectors();

    let tests = test_vectors
        .into_iter()
        .map(|(name, test_vector)| {
            Trial::test(
                format!("tests::spec::test_duplex_sponge::{}", name),
                move || run_test_vector(&name, &test_vector),
            )
        })
        .collect();

    libtest_mimic::run(&Arguments::from_args(), tests).exit();
}
