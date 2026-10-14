//! Errors are separated by operation: [`InvalidInstance`] for statement
//! construction and decoding, [`InvalidWitness`] for proving, and
//! [`VerificationError`] for verification.
//!
//! A generic [`Error`] type is available for callers that perform more
//! than one operation.

use alloc::string::String;
use core::fmt;

/// Represents an invalid instance error.
#[derive(Debug)]
#[non_exhaustive]
pub struct InvalidInstance {
    /// The error message describing what's invalid about the instance.
    pub message: String,
    /// The instance-validation check of the specification
    /// (draft-irtf-cfrg-sigma-protocols, Section "Instance validation") that
    /// failed, when the error corresponds to one.
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

    /// Create an InvalidInstance error for a failed numbered specification
    /// check in the draft's "Instance validation" section.
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

/// The opaque verification error used by spongefish transcripts.
pub use spongefish::VerificationError;

/// A generic error during instance generation, proving, or verifying a proof.
///
/// Use the operation-specific types when only one operation is involved.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The statement or its parameters are invalid.
    InvalidInstance(InvalidInstance),
    /// The supplied witness cannot prove the relation.
    InvalidWitness(InvalidWitness),
    /// Proof verification failed.
    VerificationFailure(VerificationError),
}

impl From<InvalidInstance> for Error {
    fn from(error: InvalidInstance) -> Self {
        Self::InvalidInstance(error)
    }
}

impl From<InvalidWitness> for Error {
    fn from(error: InvalidWitness) -> Self {
        Self::InvalidWitness(error)
    }
}

impl From<VerificationError> for Error {
    fn from(error: VerificationError) -> Self {
        Self::VerificationFailure(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInstance(error) => error.fmt(f),
            Self::InvalidWitness(error) => error.fmt(f),
            Self::VerificationFailure(error) => error.fmt(f),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidInstance(error) => Some(error),
            Self::InvalidWitness(error) => Some(error),
            Self::VerificationFailure(error) => Some(error),
        }
    }
}

/// A statement the prover cannot validate is one it cannot prove.
///
/// The message is dropped: a prover that reached an invalid instance has no
/// proof to produce either way, and [`InvalidWitness`] carries no payload.
impl From<InvalidInstance> for InvalidWitness {
    fn from(_: InvalidInstance) -> Self {
        Self
    }
}

/// Verification is total: a statement the verifier cannot validate is
/// rejected, under the same opaque verdict as an invalid proof.
///
/// This is what makes `?` the whole of a verifier's error handling — an
/// instance it built or decoded itself and one that arrived on the wire reach
/// the same answer, so neither the message nor the failed check number can
/// leak into the verdict.
impl From<InvalidInstance> for VerificationError {
    fn from(_: InvalidInstance) -> Self {
        Self
    }
}

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

impl core::error::Error for InvalidInstance {}

impl core::error::Error for InvalidWitness {}
