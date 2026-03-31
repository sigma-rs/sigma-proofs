//! Serialization and deserialization utilities for group elements and scalars.
//!
//! This module is retained only as a backward-compatible shim for callers that
//! still import `sigma_proofs::serialization::*`.
//!
//! For new code, prefer `spongefish::Encoding` /
//! `spongefish::NargSerialize` / `spongefish::NargDeserialize` for proof and
//! transcript bytes. Only use direct `GroupEncoding::to_bytes` /
//! `GroupEncoding::from_bytes` loops when you need fixed-width group-byte labels
//! outside the transcript path.

use alloc::vec::Vec;
use ff::PrimeField;
use group::prime::PrimeGroup;

/// Legacy helper for the serialized length of a group element in bytes.
///
/// Prefer `G::Repr::default().as_ref().len()` directly.
#[deprecated(
    note = "Use `G::Repr::default().as_ref().len()` directly. For transcript data, migrate to `spongefish::{Encoding, NargSerialize, NargDeserialize}`; for fixed-width labels, use direct `GroupEncoding` loops."
)]
pub fn group_elt_serialized_len<G: PrimeGroup>() -> usize {
    G::Repr::default().as_ref().len()
}

/// Legacy helper for serializing a slice of group elements into a byte vector.
///
/// Prefer `spongefish::NargSerialize` for transcript bytes, or direct
/// `GroupEncoding::to_bytes` loops for fixed-width labels.
#[deprecated(
    note = "Use `spongefish::NargSerialize` for transcript bytes. If you need fixed-width label bytes instead, loop over `GroupEncoding::to_bytes` directly."
)]
pub fn serialize_elements<'a, G: PrimeGroup>(elements: impl IntoIterator<Item = &'a G>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for element in elements {
        bytes.extend_from_slice(element.to_bytes().as_ref());
    }
    bytes
}

/// Legacy helper for deserializing a byte slice into a vector of group elements.
///
/// Prefer `spongefish::NargDeserialize` for transcript bytes, or direct
/// `GroupEncoding::from_bytes` loops for fixed-width labels.
#[deprecated(
    note = "Use `spongefish::NargDeserialize` for transcript bytes. If you need fixed-width label bytes instead, loop over `GroupEncoding::from_bytes` directly."
)]
pub fn deserialize_elements<G: PrimeGroup>(data: &[u8], count: usize) -> Option<Vec<G>> {
    let element_len = G::Repr::default().as_ref().len();
    let expected_len = count * element_len;

    if data.len() != expected_len {
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

/// Legacy helper for serializing a slice of scalar field elements into a byte vector.
///
/// Prefer `spongefish::Encoding` / `spongefish::NargSerialize`.
#[deprecated(
    note = "Use `spongefish::Encoding`, `spongefish::NargSerialize`, or `spongefish::NargDeserialize` for transcript semantics instead of this helper."
)]
pub fn serialize_scalars<G: PrimeGroup>(scalars: &[G::Scalar]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for scalar in scalars {
        let mut scalar_bytes = scalar.to_repr().as_ref().to_vec();
        scalar_bytes.reverse();
        bytes.extend_from_slice(&scalar_bytes);
    }
    bytes
}

/// Legacy helper for deserializing a byte slice into a vector of scalar field elements.
///
/// Prefer `spongefish::NargDeserialize`.
#[deprecated(
    note = "Use `spongefish::Encoding`, `spongefish::NargSerialize`, or `spongefish::NargDeserialize` for transcript semantics instead of this helper."
)]
pub fn deserialize_scalars<G: PrimeGroup>(data: &[u8], count: usize) -> Option<Vec<G::Scalar>> {
    #[allow(clippy::manual_div_ceil)]
    let scalar_len = (G::Scalar::NUM_BITS as usize + 7) / 8;
    let expected_len = count * scalar_len;

    if data.len() != expected_len {
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

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::G1Projective as G;
    use ff::Field;
    use group::Group;

    #[test]
    fn rejects_trailing_bytes() {
        let element = G::generator();
        let mut elements = serialize_elements::<G>([&element]);
        elements.push(0);
        assert!(deserialize_elements::<G>(&elements, 1).is_none());
        let scalar = <G as Group>::Scalar::ONE;
        let mut scalars = serialize_scalars::<G>(&[scalar]);
        scalars.push(0);
        assert!(deserialize_scalars::<G>(&scalars, 1).is_none());
    }
}
