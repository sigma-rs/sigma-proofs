//! # Proof Builder for Sigma Protocols
//!
//! This module defines the [`ProofBuilder`] struct, a high-level utility that simplifies
//! the construction and interaction with zero-knowledge proofs based on Sigma protocols.
//!
//! It abstracts over the underlying Schnorr protocol, Fiat-Shamir transformation,
//! and serialization concerns, making it easier to create proofs from linear
//! relations over cryptographic groups.
//!
//! ## Features
//! - Allocates scalar and point variables for constructing group equations.
//! - Appends equations representing statements to be proven.
//! - Supports element assignment to statement variables.
//! - Offers one-shot `prove` and `verify` methods.

use crate::{codec::ShakeCodec, fiat_shamir::NISigmaProtocol, schnorr_protocol::SchnorrProtocol};

/// An alias for a [`SchnorrProtocol`] over a [`GroupMorphismPreimage`] and applies
/// the Fiat-Shamir transform via [`NISigmaProtocol`].
///
/// # Type Parameters
/// - `G`: A group that implements both [`Group`] and [`GroupEncoding`].
///
/// [`GroupMorphismPreimage`]: crate::GroupMorphismPreimage
pub type NISchnorr<G> = NISigmaProtocol<SchnorrProtocol<G>, ShakeCodec<G>, G>;
