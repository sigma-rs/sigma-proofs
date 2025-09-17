//! Serialization and deserialization utilities for group elements and scalars.
//!
//! This module provides functions to convert group elements and scalars to and from
//! byte representations using canonical encodings.

use alloc::vec::Vec;
use ff::PrimeField;
use group::prime::PrimeGroup;

/// Get the serialized length of a group element in bytes.
///
/// # Returns
/// The number of bytes required to serialize a group element.
pub fn group_elt_serialized_len<G: PrimeGroup>() -> usize {
    G::Repr::default().as_ref().len()
}

/// Serialize a slice of group elements into a byte vector.
///
/// # Parameters
/// - `elements`: A slice of group elements to serialize.
///
/// # Returns
/// - A `Vec<u8>` containing the concatenated canonical compressed byte representations.
pub fn serialize_elements<G: PrimeGroup>(elements: &[G]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for element in elements {
        bytes.extend_from_slice(element.to_bytes().as_ref());
    }
    bytes
}

/// Deserialize a byte slice into a vector of group elements.
///
/// # Parameters
/// - `data`: A byte slice containing the serialized representations of group elements.
/// - `count`: The number of elements to deserialize.
///
/// # Returns
/// - `Some(Vec<G>)`: The deserialized group elements if all are valid.
/// - `None`: If the byte slice length is incorrect or any element is invalid.
pub fn deserialize_elements<G: PrimeGroup>(data: &[u8], count: usize) -> Option<Vec<G>> {
    let element_len = group_elt_serialized_len::<G>();
    let expected_len = count * element_len;

    if data.len() < expected_len {
        return None;
    }

    let mut elements = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * element_len;
        let end = start + element_len;
        let slice = &data[start..end];

        let mut repr = G::Repr::default();
        repr.as_mut().copy_from_slice(slice);
        let element = G::from_bytes(&repr).into();
        let element: Option<G> = element;
        elements.push(element?);
    }

    Some(elements)
}

/// Serialize a slice of scalar field elements into a byte vector.
///
/// This method internally relies on the underlying group serialization function,
/// and is meant to match the Internet Draft for point compression.
///
/// # Parameters
/// - `scalars`: A slice of scalar field elements to serialize.
///
/// # Returns
/// - A `Vec<u8>` containing the scalar bytes in big-endian order.
pub fn serialize_scalars<G: PrimeGroup>(scalars: &[G::Scalar]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for scalar in scalars {
        let mut scalar_bytes = scalar.to_repr().as_ref().to_vec();
        scalar_bytes.reverse();
        bytes.extend_from_slice(&scalar_bytes);
    }
    bytes
}

/// Deserialize a byte slice into a vector of scalar field elements.
///
/// # Parameters
/// - `data`: A byte slice containing the serialized scalars in little-endian order.
/// - `count`: The number of scalars to deserialize.
///
/// # Returns
/// - `Some(Vec<G::Scalar>)`: The deserialized scalars if all are valid.
/// - `None`: If the byte slice length is incorrect or any scalar is invalid.
pub fn deserialize_scalars<G: PrimeGroup>(data: &[u8], count: usize) -> Option<Vec<G::Scalar>> {
    #[allow(clippy::manual_div_ceil)]
    let scalar_len = (G::Scalar::NUM_BITS as usize + 7) / 8;
    let expected_len = count * scalar_len;

    if data.len() < expected_len {
        return None;
    }

    let mut scalars = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * scalar_len;
        let end = start + scalar_len;
        let slice = &data[start..end];

        let mut repr = <G::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(slice);
        repr.as_mut().reverse();

        let scalar = G::Scalar::from_repr(repr).into();
        let scalar: Option<G::Scalar> = scalar;
        scalars.push(scalar?);
    }

    Some(scalars)
}

// xxx adjust serialization for batch conversion but also for returning the length read
pub(crate) fn read_elements<G: PrimeGroup>(data: &[u8], count: usize) -> Option<(Vec<G>, &[u8])> {
    let element_len = group_elt_serialized_len::<G>();
    let elements = deserialize_elements::<G>(data, count)?;
    Some((elements, &data[count * element_len..]))
}
