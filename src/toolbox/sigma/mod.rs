pub mod r#trait;
pub mod proof_composition;
pub mod preimage_protocol;
pub mod fiat_shamir;

pub use r#trait::SigmaProtocol;
pub use proof_composition::{AndProof, OrProof};
pub use preimage_protocol::{GroupMorphism, SchnorrPreimage};