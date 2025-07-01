//! # Error: Error Types for Zero-Knowledge Proofs.
//!
//! This module defines the [`Error`] enum, which enumerates the possible failure modes
//! encountered during the execution of interactive or non-interactive Sigma protocols.
//!
//! These errors include:
//! - Failed proof verification,
//! - Mismatched parameter lengths (e.g., during batch verification),
//! - Access to unassigned group variables in constraint systems.

/// Represents an error encountered during the execution of a Sigma protocol.
///
/// This may occur during proof generation, response computation, or verification.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The proof is invalid: verification failed.
    #[error("Verification failed.")]
    VerificationFailure,

    /// The sizes of input parameters (e.g., witnesses, commitments) do not match expected values.
    #[error("Mismatched parameter sizes in proof or batch verification.")]
    ProofSizeMismatch,

    /// Uninitialized group element variable.
    #[error("Uninitialized group element variable: {var_debug}")]
    UnassignedGroupVar {
        /// Debug representation of the unassigned variable.
        var_debug: String,
    },
}
