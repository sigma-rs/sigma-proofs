//! Serialization and deserialization utilities for group elements and scalars.
//!
//! This module provides functions to convert group elements and scalars to and from
//! byte representations using canonical encodings.

use ff::PrimeField;
use group::{Group, GroupEncoding};

/// Returns the byte size of a field element.
#[inline]
#[allow(clippy::manual_div_ceil)]
pub fn scalar_byte_size<F: PrimeField>() -> usize {
    (F::NUM_BITS as usize + 7) / 8
}

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
/// - `Some(G)`: The deserialized group element if the input is valid.
/// - `None`: If the byte slice length is incorrect or the data
///   does not represent a valid group element.
pub fn deserialize_element<G: Group + GroupEncoding>(data: &[u8]) -> Option<G> {
    let mut repr = G::Repr::default();
    let element_len = repr.as_ref().len();

    let slice = data.get(..element_len)?;
    repr.as_mut().copy_from_slice(slice);
    G::from_bytes(&repr).into()
}

/// Serialize a scalar field element into a byte vector.
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
/// - `Some(G::Scalar)`: The deserialized scalar if the input is valid.
/// - `None`: If the byte slice length is incorrect or the data
///   does not represent a valid scalar.
pub fn deserialize_scalar<G: Group>(data: &[u8]) -> Option<G::Scalar> {
    let scalar_len = scalar_byte_size::<G::Scalar>();
    let slice = data.get(..scalar_len)?;

    let mut repr = <<G as Group>::Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(slice);
    repr.as_mut().reverse();

    G::Scalar::from_repr(repr).into()
}
