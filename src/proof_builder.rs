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
//! - Composes multiple protocols via AND and OR connections
//! - Offers one-shot `prove` and `verify` methods.

use crate::{codec::ShakeCodec, composition::Protocol, fiat_shamir::NISigmaProtocol};

/// An alias for a [`Protocol`] on [`GroupMorphismPreimage`] and applies
/// the Fiat-Shamir transform via [`NISigmaProtocol`].composition
///
/// # Type Parameters
/// - `G`: A group that implements both [`Group`] and [`GroupEncoding`].
///
/// [`GroupMorphismPreimage`]: crate::GroupMorphismPreimage
pub type NIProtocol<G> = NISigmaProtocol<Protocol<G>, ShakeCodec<G>>;
