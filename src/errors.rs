//! Errors are separated by operation: [`InvalidInstance`] for statement
//! construction and decoding, [`InvalidWitness`] for proving, and
//! [`VerificationError`] for verification.

use alloc::string::String;
use core::fmt;

/// Represents an invalid instance error.
#[derive(Debug)]
pub struct InvalidInstance {
    /// The error message describing what's invalid about the instance.
    pub message: String,
    /// The instance-validation check of the specification
    /// (draft-irtf-cfrg-sigma-protocols, Section "Instance validation",
    /// checks 1-10) that failed, when the error corresponds to one.
    pub check: Option<u8>,
}

impl InvalidInstance {
    /// Create a new InvalidInstance error with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            check: None,
        }
    }

    /// Create an InvalidInstance error for a failed specification check
    /// (1 through 10, per the "Instance validation" section of the draft).
    pub fn check(check: u8, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            check: Some(check),
        }
    }
}

/// The supplied witness cannot prove the relation.
///
/// Verification deliberately uses the separate, opaque [`VerificationError`]
/// so callers cannot confuse a local prover-input error with an invalid proof
/// received from elsewhere.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidWitness;

/// A result produced by a prover operation.
pub type ProverResult<T> = core::result::Result<T, InvalidWitness>;

/// The opaque verification error and result used by spongefish transcripts.
pub use spongefish::{VerificationError, VerificationResult};

// `Display` is written by hand and unconditionally, rather than derived under
// `std`: the messages are the same either way, and a derive that only exists
// with a feature on means writing each of them twice.
impl fmt::Display for InvalidInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid instance: {}", self.message)
    }
}

impl fmt::Display for InvalidWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("The supplied witness cannot prove this relation.")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidInstance {}

#[cfg(feature = "std")]
impl std::error::Error for InvalidWitness {}
