//! Serialization and deserialization utilities for group elements and scalars.
//!
//! This module provides functions to convert group elements and scalars to and from
//! byte representations using canonical encodings.

use ff::PrimeField;
use group::{Group, GroupEncoding};

use crate::ProofError;

/// Serialize a group element into a byte vector.
///
/// # Inputs
/// - `element`: A reference to the group element to serialize.
///
/// # Outputs
/// - A `Vec<u8>` containing the canonical compressed byte representation of the element.
pub fn serialize_element<G: Group + GroupEncoding>(element: &G) -> Vec<u8> {
    element.to_bytes().as_ref().to_vec()
}

/// Deserialize a byte slice into a group element.
///
/// # Parameters
/// - `data`: A byte slice containing the serialized representation of the group element.
///
/// # Returns
/// - `Ok(G)`: The deserialized group element if the input is valid.
/// - `Err(ProofError::GroupSerializationFailure)`: If the byte slice length is incorrect or the data
///   does not represent a valid group element.
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

/// Serialize a scalar field element into a byte vector
///
/// # Parameters
/// - `scalar`: A reference to the scalar field element to serialize.
///
/// # Outputs
/// - A `Vec<u8>` containing the scalar bytes in little-endian order.
pub fn serialize_scalar<G: Group>(scalar: &G::Scalar) -> Vec<u8> {
    let mut scalar_bytes = scalar.to_repr().as_ref().to_vec();
    scalar_bytes.reverse();
    scalar_bytes
}
/// Deserialize a byte slice into a scalar field element.
///
/// # Parameters
/// - `data`: A byte slice containing the serialized scalar in little-endian order.
///
/// # Returns
/// - `Ok(G::Scalar)`: The deserialized scalar if the input is valid.
/// - `Err(ProofError::GroupSerializationFailure)`: If the byte slice length is incorrect or the data
///   does not represent a valid scalar.
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
