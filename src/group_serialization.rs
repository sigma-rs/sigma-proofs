use ff::PrimeField;
use group::{Group, GroupEncoding};

use crate::ProofError;

pub fn serialize_element<G: Group + GroupEncoding>(element: &G) -> Vec<u8> {
    element.to_bytes().as_ref().to_vec()
}

pub fn deserialize_element<G: Group + GroupEncoding>(data: &[u8]) -> Result<G, ProofError> {
    let element_len = G::Repr::default().as_ref().len();
    if data.len() != element_len {
        return Err(ProofError::GroupSerializationFailure);
    }

    let mut repr = G::Repr::default();
    repr.as_mut().copy_from_slice(data);
    let ct_point = G::from_bytes(&repr);
    if ct_point.is_some().into() {
        let point = ct_point.unwrap();
        Ok(point)
    } else {
        Err(ProofError::GroupSerializationFailure)
    }
}

pub fn serialize_scalar<G: Group>(scalar: &G::Scalar) -> Vec<u8> {
    let mut scalar_bytes = scalar.to_repr().as_ref().to_vec();
    scalar_bytes.reverse();
    scalar_bytes
}

pub fn deserialize_scalar<G: Group>(data: &[u8]) -> Result<G::Scalar, ProofError> {
    let scalar_len = <<G as Group>::Scalar as PrimeField>::Repr::default()
        .as_ref()
        .len();
    if data.len() != scalar_len {
        return Err(ProofError::GroupSerializationFailure);
    }

    let mut repr = <<G as Group>::Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&{
        let mut tmp = data.to_vec();
        tmp.reverse();
        tmp
    });
    let ct_scalar = G::Scalar::from_repr(repr);
    if ct_scalar.is_some().into() {
        let scalar = ct_scalar.unwrap();
        Ok(scalar)
    } else {
        Err(ProofError::GroupSerializationFailure)
    }
}
