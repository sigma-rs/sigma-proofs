pub mod r#trait;
pub mod proof_composition;
pub mod fiat_shamir;

pub use r#trait::SigmaProtocol;
pub use proof_composition::{AndProof, OrProof};