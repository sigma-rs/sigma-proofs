pub(crate) mod rng;
pub(crate) mod vectors;

pub(crate) fn read_vector_file(file_name: &str) -> String {
    match file_name {
        "duplexSpongeVectors.json" => include_str!("testdata/duplexSpongeVectors.json").to_string(),
        "sigma-proofs_Shake128_P256.json" => {
            include_str!("testdata/sigma-proofs_Shake128_P256.json").to_string()
        }
        "sigma-proofs_Shake128_BLS12381.json" => {
            include_str!("testdata/sigma-proofs_Shake128_BLS12381.json").to_string()
        }
        _ => panic!("unknown test vector file: {file_name}"),
    }
}
