pub mod keccak_codec;
pub mod shake_codec;
pub mod r#trait;

pub use keccak_codec::{ByteSchnorrCodec, KeccakDuplexSponge};
pub use shake_codec::ShakeCodec;
pub use r#trait::Codec;
