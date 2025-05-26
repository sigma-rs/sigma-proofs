//! # ProofError: Error Types for Zero-Knowledge Proofs
//!
//! This module defines the [`ProofError`] enum, which encapsulates possible errors that may occur
//! during the execution of Sigma protocols or their non-interactive variants.
//!
//! These errors include:
//! - Verification failures (e.g., when a proof does not verify correctly).
//! - Mismatched parameters during batch verification.
//! - Unimplemented methods.
//! - Group element or scalar serialization failures.
use thiserror::Error;
/// An error during proving or verification, such as a verification failure.
#[derive(Debug, Error)]
pub enum ProofError {
    /// Something is wrong with the proof, causing a verification failure.
    #[error("Verification failed.")]
    VerificationFailure,
    /// Indicates a mismatch in parameter sizes during batch verification.
    #[error("Mismatched parameter sizes for batch verification.")]
    ProofSizeMismatch,
    /// Occurs when a feature has not been implemented yet.
    #[error("The method is not yet implemented for this struct.")]
    NotImplemented(&'static str),
    /// Serialization of a group element/scalar has failed.
    #[error("Serialization of a group element/scalar failed.")]
    GroupSerializationFailure,
    /// Other error.
    #[error("Other")]
    Other,
}
