//! Encoding and decoding utilities for Fiat-Shamir and group operations.
pub mod keccak_codec;
pub mod shake_codec;
pub mod traits;

pub use keccak_codec::{ByteSchnorrCodec, KeccakDuplexSponge};
pub use shake_codec::ShakeCodec;
pub use traits::Codec;
