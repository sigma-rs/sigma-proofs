//! # Group Serialization Implementations
//!
//! This module implements the [`GroupSerialisation`] trait for specific elliptic curve.
//!
//! Supported groups:
//! - [`RistrettoPoint`] from `curve25519-dalek`
//! - [`G1Projective`] from `bls12_381`
//!
//! ## Trait Overview
//!
//! The [`GroupSerialisation`] trait defines:
//! - `serialize_element` / `deserialize_element` for group points
//! - `serialize_scalar` / `deserialize_scalar` for field elements (scalars)
//!
//! Implementations must guarantee:
//! - Canonical and deterministic serialization
//! - Rejection of malformed or non-canonical encodings on deserialization
use std::convert::TryInto;

use crate::serialisation::GroupSerialisation;
use bls12_381::{G1Affine, G1Projective, Scalar as BlsScalar};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as RistrettoScalar,
};
use ff::PrimeField;

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
