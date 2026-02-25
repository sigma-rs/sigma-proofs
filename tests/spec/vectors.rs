use serde::{Deserialize, Serialize};
use serde_with::{hex, serde_as};

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hex(#[serde_as(as = "hex::Hex")] pub Vec<u8>);

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TestVector {
    pub protocol: String,
    pub ciphersuite: String,
    pub session_id: Hex,
    pub statement: Hex,
    pub witness: Vec<Hex>,
    pub randomness: Vec<Hex>,
    pub proof_batchable: Hex,
}
