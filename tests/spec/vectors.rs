use serde::{Deserialize, Serialize};
use serde_with::{hex, serde_as};

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hex(#[serde_as(as = "hex::Hex")] pub Vec<u8>);

/// One vector of the specification's "Test Vectors" appendix, valid or
/// adversarial. `BaseId` names the valid vector an adversarial one is derived
/// from; `Relation`, `SessionId`, and `Witness` appear on valid vectors only.
#[derive(Debug, Deserialize)]
pub struct TestVector {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "BaseId", default)]
    pub base_id: Option<String>,
    #[serde(rename = "Ciphersuite")]
    pub ciphersuite: String,
    #[serde(rename = "Relation", default)]
    pub relation: Option<String>,
    #[serde(rename = "Flavor")]
    pub flavor: String,
    #[serde(rename = "Tag")]
    pub tag: String,
    #[serde(rename = "SessionId", default)]
    pub session_id: Option<Hex>,
    #[serde(rename = "Instance")]
    pub instance: Hex,
    #[serde(rename = "Witness", default)]
    pub witness: Option<Hex>,
    #[serde(rename = "NargString")]
    pub narg_string: Hex,
    #[serde(rename = "Expected")]
    pub expected: String,
}
