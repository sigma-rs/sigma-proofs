//! # Error: Error Types for Zero-Knowledge Proofs.
//!
//! This module defines the [`Error`] enum, which enumerates the possible failure modes
//! encountered during the execution of interactive or non-interactive Sigma protocols.
//!
//! These errors include:
//! - Failed proof verification,
//! - Mismatched parameter lengths (e.g., during batch verification),
//! - Access to unassigned group variables in constraint systems.

use alloc::string::String;
#[cfg(not(feature = "std"))]
use core::fmt;

/// Represents an invalid instance error.
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[cfg_attr(feature = "std", error("Invalid instance: {message}"))]
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
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    /// The proof is invalid: verification failed.
    #[cfg_attr(feature = "std", error("Verification failed."))]
    VerificationFailure,
    /// Indicates an invalid statement/witness pair
    #[cfg_attr(feature = "std", error("Invalid instance/witness pair."))]
    InvalidInstanceWitnessPair,
    /// Uninitialized group element variable.
    #[cfg_attr(feature = "std", error("Uninitialized group element variable: {var_debug}"))]
    UnassignedGroupVar {
        /// Debug representation of the unassigned variable.
        var_debug: String,
    },
}

// Manual Display implementation for no_std compatibility
#[cfg(not(feature = "std"))]
impl fmt::Display for InvalidInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid instance: {}", self.message)
    }
}

#[cfg(not(feature = "std"))]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::VerificationFailure => write!(f, "Verification failed."),
            Error::InvalidInstanceWitnessPair => write!(f, "Invalid instance/witness pair."),
            Error::UnassignedGroupVar { var_debug } => {
                write!(f, "Uninitialized group element variable: {}", var_debug)
            }
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Construct an `Ok` value of type `Result<T, sigma_rs::errors::Error>`.
pub const fn Ok<T>(value: T) -> Result<T> {
    Result::Ok(value)
}
