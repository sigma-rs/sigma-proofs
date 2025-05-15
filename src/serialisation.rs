//! Serialization for Group Elements and Scalars
//!
//! This module defines the [`GroupSerialisation`] trait, which provides a unified interface
//! for serializing and deserializing group elements and their associated scalar field elements.
//!
//! It is used throughout the Sigma protocol framework for encoding proof data, hashing to transcripts,
//! and verifying correctness of received data.

use group::{Group, GroupEncoding};

/// Trait for serializing and deserializing group elements and scalar field elements.
///
/// This trait provides protocol-agnostic methods for:
/// - Serializing group elements (e.g., elliptic curve points)
/// - Serializing scalars (e.g., elements from the group’s scalar field)
/// - Deserializing both formats with built-in validity checks
///
/// ## Requirements
/// - Serialization must be canonical and deterministic.
/// - Deserialization must reject invalid or malformed input by returning `None`.
///
/// ## Use Cases
/// - Encoding Sigma protocol proofs for transmission
/// - Fiat-Shamir challenge generation
/// - Deserializing proofs during verification
///
/// ## Notes
/// This trait requires the implementor to also implement [`Group`] and [`GroupEncoding`].
///
/// ## Methods
/// - `serialize_element`: Encodes a group element into bytes
/// - `deserialize_element`: Attempts to decode a group element from bytes
/// - `serialize_scalar`: Encodes a scalar field element into bytes
/// - `deserialize_scalar`: Attempts to decode a scalar from bytes
pub trait GroupSerialisation: Group + GroupEncoding {
    /// Serializes a group element (e.g., elliptic curve point) into a canonical byte representation.
    ///
    /// This representation must be deterministic and compatible with the corresponding
    /// deserialization method.
    fn serialize_element(point: &Self) -> Vec<u8>;

    /// Deserializes a group element from a byte slice.
    ///
    /// Returns `Some(element)` if the bytes represent a valid point in the group, or `None`
    /// if decoding fails (e.g., invalid encoding or not on the curve).
    fn deserialize_element(bytes: &[u8]) -> Option<Self>;

    /// Serializes a scalar (field element) into a canonical byte representation.
    ///
    /// This must match the encoding used by the group's scalar field (e.g., little-endian for Ristretto).
    fn serialize_scalar(scalar: &Self::Scalar) -> Vec<u8>;

    /// Deserializes a scalar from a byte slice.
    ///
    /// Returns `Some(scalar)` if the bytes form a valid scalar, or `None` if decoding fails.
    fn deserialize_scalar(bytes: &[u8]) -> Option<Self::Scalar>;
}
