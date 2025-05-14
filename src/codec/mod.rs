pub mod keccak_codec;
pub mod shake_codec;
pub mod r#trait;

pub use keccak_codec::{ByteSchnorrCodec, KeccakDuplexSponge};
pub use r#trait::Codec;
pub use shake_codec::ShakeCodec;
