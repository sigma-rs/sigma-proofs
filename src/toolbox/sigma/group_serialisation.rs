use std::convert::TryInto;

use curve25519_dalek::{ristretto::{CompressedRistretto, RistrettoPoint}, scalar::Scalar as RistrettoScalar};
use bls12_381::{G1Affine, G1Projective, Scalar as BlsScalar};
use ff::PrimeField;
use super::r#trait::GroupSerialisation;

pub struct RistrettoSerialisation;

impl GroupSerialisation<RistrettoPoint> for RistrettoSerialisation {
    type Scalar = RistrettoScalar;

    fn serialize_element(point: &RistrettoPoint) -> Vec<u8> {
        point.compress().to_bytes().to_vec()
    }
    
    fn deserialize_element(bytes: &[u8]) -> Option<RistrettoPoint> {
        let point_size = 32;
        if bytes.len() != point_size {
            return None;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        CompressedRistretto(buf).decompress()
    }
    
    fn serialize_scalar(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_bytes().to_vec()
    }
    
    fn deserialize_scalar(bytes: &[u8]) -> Option<Self::Scalar> {
        if bytes.len() != 32 {
            return None;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        RistrettoScalar::from_canonical_bytes(buf).into()
    }
}

pub struct Bls12381Serialisation;

impl GroupSerialisation<G1Projective> for Bls12381Serialisation {
    type Scalar = BlsScalar;

    fn serialize_element(point: &G1Projective) -> Vec<u8> {
        let affine = G1Affine::from(point);
        affine.to_compressed().as_ref().to_vec()
    }

    fn deserialize_element(bytes: &[u8]) -> Option<G1Projective> {
        if bytes.len() != 48 {
            return None;
        }
        let mut buf = [0u8; 48];
        buf.copy_from_slice(bytes);
        let affine = G1Affine::from_compressed(&buf).into_option()?;
        Some(G1Projective::from(&affine))
    }

    fn serialize_scalar(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_repr().as_ref().to_vec()
    }

    fn deserialize_scalar(bytes: &[u8]) -> Option<Self::Scalar> {
        let repr = bytes.try_into().ok()?;
        BlsScalar::from_repr(repr).into_option()
    }    
}