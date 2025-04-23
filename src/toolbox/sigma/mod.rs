pub mod r#trait;
pub mod proof_composition;
pub mod fiat_shamir;
pub mod GroupMorphismPreimage;

pub use r#trait::SigmaProtocol;
pub use proof_composition::{AndProtocol, OrProtocol};