pub mod r#trait;
pub mod proof_composition;
pub mod fiat_shamir;
pub mod GroupMorphismPreimage;
pub mod schnorr_proof;
pub mod transcript;

pub use r#trait::SigmaProtocol;
pub use proof_composition::{AndProtocol, OrProtocol};