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
pub mod group_serialization;
pub mod proof_builder;
pub mod protocol;
pub mod schnorr_protocol;
pub mod traits;

pub mod codec;

#[cfg(feature = "test-utils")]
pub mod test_utils;
