//! # Error: Error Types for Zero-Knowledge Proofs.
//!
//! This module defines the [`Error`] enum, which enumerates the possible failure modes
//! encountered during the execution of interactive or non-interactive Sigma protocols.
//!
//! These errors include:
//! - Failed proof verification,
//! - Mismatched parameter lengths (e.g., during batch verification),
//! - Access to unassigned group variables in constraint systems.

/// Represents an invalid instance error.
#[derive(Debug, thiserror::Error)]
#[error("Invalid instance: {message}")]
pub struct InvalidInstance {
    /// The error message describing what's invalid about the instance.
    pub message: String,
}

impl InvalidInstance {
    /// Create a new InvalidInstance error with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl From<InvalidInstance> for Error {
    fn from(_err: InvalidInstance) -> Self {
        Error::InvalidInstanceWitnessPair
    }
}

/// Represents an error encountered during the execution of a Sigma protocol.
///
/// This may occur during proof generation, response computation, or verification.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The proof is invalid: verification failed.
    #[error("Verification failed.")]
    VerificationFailure,
    /// Indicates an invalid statement/witness pair
    #[error("Invalid instance/witness pair.")]
    InvalidInstanceWitnessPair,
    /// Uninitialized group element variable.
    #[error("Uninitialized group element variable: {var_debug}")]
    UnassignedGroupVar {
        /// Debug representation of the unassigned variable.
        var_debug: String,
    },
}
