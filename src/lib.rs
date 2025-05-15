// -*- coding: utf-8; mode: rust; -*-
//
// Authors:
// - Nugzari Uzoevi <nougzarm@icloud.com>
// - Michele Orrù <m@orru.net>
// - Lénaïck Gouriou <lg@leanear.io>

#![allow(non_snake_case)]
#![doc(html_logo_url = "https://mmaker.github.io/sigma-rs/")]
//! ## Note
//!

#![deny(unused_variables)]
#![deny(unused_mut)]

pub mod errors;
pub mod fiat_shamir;
pub mod group_morphism;
pub mod group_serialisation;
pub mod proof_composition;
pub mod schnorr_proof;
pub mod r#trait;
pub mod proof_builder;
pub mod serialisation;

pub use errors::*;
pub use fiat_shamir::*;
pub use group_morphism::*;
pub use proof_composition::*;
pub use schnorr_proof::*;
pub use r#trait::*;
pub use proof_builder::*;

pub mod codec;
pub mod old;
