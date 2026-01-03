//! Serialization and deserialization utilities for group elements and scalars.
//!
//! This module provides functions to convert group elements and scalars to and from
//! byte representations using canonical encodings.

use alloc::vec::Vec;
use ff::PrimeField;
use group::prime::PrimeGroup;

// TODO: If we constrain G::Repr to be Sized, then we can drop this function and make this whole
// thing a bit less fragile.
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
pub fn serialize_elements<'a, G: PrimeGroup>(elements: impl IntoIterator<Item = &'a G>) -> Vec<u8> {
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
pub fn deserialize_elements<G: PrimeGroup>(data: &mut &[u8], count: usize) -> Option<Vec<G>> {
    let mut elements = Vec::with_capacity(count);
    for _ in 0..count {
        let mut repr = G::Repr::default();
        let repr_mut = repr.as_mut();
        let slice = data.split_off(..repr_mut.len())?;
        repr_mut.copy_from_slice(slice);

        let element: Option<G> = G::from_bytes(&repr).into();
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
pub fn serialize_scalars<F: PrimeField>(scalars: &[F]) -> Vec<u8> {
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
pub fn deserialize_scalars<F: PrimeField>(data: &mut &[u8], count: usize) -> Option<Vec<F>> {
    let mut scalars = Vec::with_capacity(count);
    for _ in 0..count {
        let mut repr = F::Repr::default();
        let repr_mut = repr.as_mut();
        let slice = data.split_off(..repr_mut.len())?;
        repr_mut.copy_from_slice(slice);
        repr_mut.reverse();

        let scalar = F::from_repr_vartime(repr);
        scalars.push(scalar?);
    }

    Some(scalars)
}
