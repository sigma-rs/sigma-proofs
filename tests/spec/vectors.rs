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
    pub hash: String,
    pub session_id: Hex,
    pub statement: Hex,
    pub witness: Vec<Hex>,
    pub randomness_chal_resp: Vec<Hex>,
    pub proof_chal_resp: Hex,
    pub randomness_comm_resp: Vec<Hex>,
    pub proof_comm_resp: Hex,
}
