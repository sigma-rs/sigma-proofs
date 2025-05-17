//! Serialization for Group Elements and Scalars
//!
//! This module defines the [`GroupSerialisation`] trait, which provides a unified interface
//! for serializing and deserializing group elements and their associated scalar field elements.
//!
//! It is used throughout the Sigma protocol framework for encoding proof data, hashing to transcripts,
//! and verifying correctness of received data.

use group::{Group, GroupEncoding};
use ff::PrimeField;
use std::convert::TryInto;

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


use bls12_381::{G1Affine, G1Projective, Scalar as BlsScalar};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as RistrettoScalar,
};


impl GroupSerialisation for RistrettoPoint {
    /// Serializes a `RistrettoPoint` to 32-byte compressed form.
    fn serialize_element(point: &Self) -> Vec<u8> {
        point.compress().to_bytes().to_vec()
    }

    /// Attempts to decompress a 32-byte slice into a `RistrettoPoint`.
    /// Returns `None` if the input is not a valid compressed point.
    fn deserialize_element(bytes: &[u8]) -> Option<Self> {
        let point_size = 32;
        if bytes.len() != point_size {
            return None;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        CompressedRistretto(buf).decompress()
    }

    /// Serializes a `RistrettoScalar` to 32 bytes (little-endian).
    fn serialize_scalar(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_bytes().to_vec()
    }

    /// Deserializes a 32-byte little-endian encoding into a `RistrettoScalar`.
    /// Returns `None` if the encoding is not canonical or invalid.
    fn deserialize_scalar(bytes: &[u8]) -> Option<Self::Scalar> {
        if bytes.len() != 32 {
            return None;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        RistrettoScalar::from_canonical_bytes(buf).into()
    }
}

impl GroupSerialisation for G1Projective {
    /// Serializes a `G1Projective` element using compressed affine representation (48 bytes).
    fn serialize_element(point: &G1Projective) -> Vec<u8> {
        let affine = G1Affine::from(point);
        affine.to_compressed().as_ref().to_vec()
    }

    /// Deserializes a 48-byte compressed affine representation into a `G1Projective`.
    /// Returns `None` if the point is invalid or not on the curve.
    fn deserialize_element(bytes: &[u8]) -> Option<G1Projective> {
        if bytes.len() != 48 {
            return None;
        }
        let mut buf = [0u8; 48];
        buf.copy_from_slice(bytes);
        let affine_ctoption = G1Affine::from_compressed(&buf);
        if affine_ctoption.is_some().into() {
            let affine = affine_ctoption.unwrap();
            Some(G1Projective::from(&affine))
        } else {
            None
        }
    }

    /// Serializes a `bls12_381::Scalar` using its canonical representation.
    fn serialize_scalar(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_repr().as_ref().to_vec()
    }

    /// Deserializes a canonical byte representation into a `bls12_381::Scalar`.
    /// Returns `None` if the scalar is malformed or out of range.
    fn deserialize_scalar(bytes: &[u8]) -> Option<Self::Scalar> {
        let repr = bytes.try_into().ok()?;
        let result_ctoption = BlsScalar::from_repr(repr);
        if result_ctoption.is_some().into() {
            Some(result_ctoption.unwrap())
        } else {
            None
        }
    }
}