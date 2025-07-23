//! # Σ-rs: Sigma Protocols in Rust
//!
//! **Σ-rs** is a Rust library for constructing zero-knowledge proofs using Sigma protocols (Σ-protocols).
//! It allows proving knowledge of secret data without revealing the data itself.
//!
//! ---
//!
//! ## What are Sigma Protocols?
//!
//! Sigma protocols are interactive cryptographic protocols that allow a prover to convince
//! a verifier they know a secret (like a private key) without revealing the secret itself.
//! They follow a simple three-step pattern: commitment, challenge, response.
//!
//! ---
//!
//! ## Key Features
//!
//! - **Composable**: Combine multiple proofs into compound statements
//! - **Generic**: Works with any cryptographic group supporting the required operations
//! - **Flexible Hashing**: Multiple hash function backends for different use cases
//! - **Non-Interactive Ready**: Support for Fiat–Shamir transformation
//!
//! ---
//!
//! ## Basic Usage
//!
//! The library provides building blocks for creating zero-knowledge proofs:
//!
//! 1. Define your mathematical relation using [`LinearRelation`]
//! 2. Create a Sigma protocol with [`schnorr_protocol::SchnorrProof`]
//! 3. Convert to non-interactive using [`fiat_shamir::Nizk`]
//! 4. Generate and verify proofs using the protocol interface
//!
//! ---
//!
//! ## Core Components
//!
//! - **[`traits::SigmaProtocol`]**: The fundamental three-move protocol interface
//! - **[`linear_relation::LinearRelation`]**: Express mathematical relations over groups
//! - **[`fiat_shamir::Nizk`]**: Convert interactive proofs to standalone proofs
//! - **[`composition::Protocol`]**: Combine multiple proofs together
//! - **[`codec`]**: Hash function backends for proof generation
//!
//! ---
//!
//! Σ-rs is designed to be modular, extensible, and easy to integrate into zero-knowledge applications.

#![allow(non_snake_case)]
#![doc(html_logo_url = "https://mmaker.github.io/sigma-rs/")]
#![deny(unused_variables)]
#![deny(unused_mut)]

pub mod composition;
pub mod errors;
pub mod fiat_shamir;
pub mod linear_relation;
pub mod schnorr_protocol;
pub mod serialization;
pub mod traits;

pub mod codec;
pub mod duplex_sponge;

#[cfg(test)]
pub mod tests;

pub use fiat_shamir::Nizk;
pub use linear_relation::LinearRelation;
