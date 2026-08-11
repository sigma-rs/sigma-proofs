//! An invalid instance reaches both a prover and a verifier through `?`,
//! keeping the verifier's verdict opaque.

use curve25519_dalek::ristretto::RistrettoPoint as G;
use sigma_proofs::errors::{InvalidInstance, InvalidWitness, VerificationError};
use sigma_proofs::LinearRelation;

/// The shape the sigma-compiler generates: one fallible step over public
/// instance data, spliced into two functions with different error types.
fn instance_step(fail: bool) -> Result<(), InvalidInstance> {
    if fail {
        return Err(InvalidInstance::check(1, "the statement has no content"));
    }
    Ok(())
}

fn prover_side(fail: bool) -> Result<(), InvalidWitness> {
    instance_step(fail)?;
    Ok(())
}

fn verifier_side(fail: bool) -> Result<(), VerificationError> {
    instance_step(fail)?;
    Ok(())
}

#[test]
fn an_instance_error_reaches_both_sides_through_question_mark() {
    assert!(prover_side(false).is_ok());
    assert!(verifier_side(false).is_ok());
    assert_eq!(prover_side(true).unwrap_err(), InvalidWitness);
    assert!(verifier_side(true).is_err());
}

#[test]
fn the_verifier_verdict_carries_no_diagnostic() {
    let detailed = InvalidInstance::check(8, "element 3 is the identity");
    assert!(detailed.to_string().contains("element 3 is the identity"));

    // The conversion is the boundary the message does not cross: the verdict
    // on a statement the verifier could not validate is the same value as the
    // verdict on an invalid proof.
    let verdict = VerificationError::from(detailed);
    assert_eq!(verdict.to_string(), VerificationError.to_string());
}

#[test]
fn a_real_compile_failure_converts() {
    // An empty relation fails check 1, so this is the conversion running on an
    // error sigma-proofs raised itself rather than a hand-built one.
    fn compile_for_verifier() -> Result<(), VerificationError> {
        LinearRelation::<G>::new().compile()?;
        Ok(())
    }
    assert!(compile_for_verifier().is_err());
}
