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
pub mod proof_builder;
pub mod proof_composition;
pub mod schnorr_protocol;
pub mod r#trait;

pub use errors::*;
pub use fiat_shamir::*;
pub use group_morphism::*;
pub use group_serialisation::*;
pub use proof_builder::*;
pub use proof_composition::*;
pub use r#trait::*;
pub use schnorr_protocol::*;

pub mod codec;
#[deprecated(
    since = "0.2.0",
    note = "This module contains the old implementation of Sigma protocols from Henry de Valence."
)]
pub mod old;
