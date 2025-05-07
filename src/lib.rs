// -*- coding: utf-8; mode: rust; -*-
//
// To the extent possible under law, the authors have waived all
// copyright and related or neighboring rights to zkp,
// using the Creative Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/1.0/> for full
// details.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>

#![allow(non_snake_case)]
#![doc(html_logo_url = "https://doc.dalek.rs/assets/dalek-logo-clear.png")]
//! ## Note
//!

#![deny(unused_variables)]
#![deny(unused_mut)]

pub use merlin::Transcript;

mod errors;
mod proofs;
mod util;

pub use crate::errors::*;
pub use crate::proofs::*;

pub mod toolbox;

#[macro_use]
mod macros;
