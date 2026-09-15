//! Public errors support generic error handling with and without `std`.

use sigma_proofs::errors::{InvalidInstance, InvalidWitness};

#[test]
fn public_errors_implement_core_error() {
    fn assert_error<T: core::error::Error>() {}

    assert_error::<InvalidInstance>();
    assert_error::<InvalidWitness>();
}
