use serde::{Deserialize, Serialize};
use serde_with::{hex, serde_as};

#[allow(dead_code)]
#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hex(#[serde_as(as = "hex::Hex")] pub Vec<u8>);

#[allow(dead_code)]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TestVector {
    #[serde(rename = "Relation")]
    pub relation: String,
    #[serde(rename = "Ciphersuite")]
    pub ciphersuite: String,
    #[serde(rename = "SessionId")]
    pub session_id: Hex,
    #[serde(rename = "Statement")]
    pub statement: Hex,
    #[serde(rename = "Witness")]
    pub witness: Hex,
    #[serde(rename = "Proof")]
    pub proof: Hex,
    #[serde(rename = "Batchable Proof")]
    pub batchable_proof: Hex,
}
