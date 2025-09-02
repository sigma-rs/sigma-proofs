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
//! ## Basic Usage
//!
//! ```rust
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::scalar::Scalar;
//! # use group::Group;
//!
//! let mut instance = sigma_rs::LinearRelation::new();
//! let mut rng = rand::thread_rng();
//! let witness = vec![Scalar::random(&mut rng), Scalar::random(&mut rng)];
//!
//! let [var_x, var_r] = instance.allocate_scalars();
//! let [var_G, var_H] = instance.allocate_elements();
//! instance.allocate_eq(var_G * var_x + var_H * var_r);
//! instance.set_elements([(var_G, RistrettoPoint::generator()), (var_H, RistrettoPoint::random(&mut rng))]);
//! instance.compute_image(&witness);
//! let narg_string: Vec<u8> = instance.into_nizk(b"your session identifier").unwrap().prove_batchable(&witness, &mut rng).unwrap();
//! println!("{}", hex::encode(narg_string));
//! ```
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
//! - **[`composition::ComposedRelation`]**: Combine multiple proofs together
//! - **[`codec`]**: Hash function backends for proof generation
//!
//! ---
//!
//! Σ-rs is designed to be modular, extensible, and easy to integrate into zero-knowledge applications.

#![allow(non_snake_case)]
#![doc(html_logo_url = "https://mmaker.github.io/sigma-rs/")]
#![deny(unused_variables)]
#![deny(unused_mut)]

pub mod codec;
pub mod composition;
pub mod errors;
pub mod linear_relation;
pub mod traits;

pub(crate) mod duplex_sponge;
pub(crate) mod fiat_shamir;
pub(crate) mod group;
pub(crate) mod schnorr_protocol;

#[cfg(test)]
pub mod tests;

pub use fiat_shamir::Nizk;
pub use linear_relation::LinearRelation;

#[deprecated = "Use sigma_rs::group::serialization instead"]
pub use group::serialization;
