//! A Rust library for zero-knowledge proofs built from Sigma protocols.
//!
//! The README's Quick Example is compiled as a doctest and is the canonical
//! introduction to building, proving, and verifying a relation.
//!
//! ## Core Components
//!
//! - **[`linear_relation::LinearRelation`]**: express relations over groups,
//!   compiled into a validated [`Instance`]
//! - **[`composition::ComposedInstance`]**: combine instances with AND/OR
//! - **[`fiat_shamir`]**: prove and verify, as batchable or compact NARG strings
//! - **[`traits::SigmaProtocol`]**: the three-move interface both of the above
//!   implement, and the extension point for new relations

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Kani's single-threaded trace helper is the only permitted unsafe code.
#![cfg_attr(not(kani), forbid(unsafe_code))]
#![allow(non_snake_case)]
#![doc(html_logo_url = "https://mmaker.github.io/sigma-rs/")]
#![deny(unused_variables)]
#![deny(unused_mut)]
// Panic policy (docs/threat-model.md §2.1). The verifier must never panic.
// `assert!` and `unreachable!` remain available for invariants that hold by
// construction, but out-of-bounds indexing is denied.
//
// The MSM module opts out because its indexing bounds come from the loop
// structure and rewriting them as fallible lookups obscures the arithmetic
// without proving anything. It is covered instead by the overflow-checked CI
// job and by the Kani harnesses.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unwrap_used,
    )
)]

extern crate alloc;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub mod codec;
pub mod composition;
pub mod compressed;
pub mod errors;
pub mod fiat_shamir;
pub mod linear_relation;
/// Implementation of multi-scalar multiplication (MSM) over scalars and points.
pub mod msm;
pub mod traits;

pub use fiat_shamir::{
    derive_session_id, prove_batchable, prove_batchable_with, prove_compact, prove_compact_with,
    verify_batch, verify_batch_with, verify_batchable, verify_batchable_with, verify_compact,
    verify_compact_with, NargCodec, SessionId,
};
pub use linear_relation::{Instance, LinearRelation};
pub use msm::MultiScalarMul;
pub use spongefish::{DefaultHash, DuplexSpongeInit, PrivateRng};

/// The prover's random number generator.
///
/// Seed from OS entropy via [`PrivateRng::from_os_entropy`] or a fixed seed
/// [`PrivateRng::from_seed`] for tests.
pub type ProverRng = PrivateRng;
