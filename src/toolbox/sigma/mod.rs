pub mod r#trait;
pub mod proof_composition;
pub mod fiat_shamir;
pub mod group_mophism;
pub mod schnorr_proof;
pub mod transcript;

pub use r#trait::SigmaProtocol;
pub use proof_composition::{AndProtocol, OrProtocol};
pub use fiat_shamir::NISigmaProtocol;
pub use schnorr_proof::SchnorrProof;
pub use group_mophism::GroupMorphismPreimage;