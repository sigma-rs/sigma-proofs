use std::{fs, path::PathBuf};

pub(crate) mod rng;
pub(crate) mod vectors;

const SPEC_VECTOR_DIR: &str = "../draft-irtf-cfrg-sigma-protocols/poc/vectors";

pub(crate) fn vector_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(SPEC_VECTOR_DIR)
        .join(file_name)
}

pub(crate) fn read_vector_file(file_name: &str) -> String {
    let path = vector_path(file_name);
    fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "failed to read external test vector file {}: {err}",
            path.display()
        )
    })
}
