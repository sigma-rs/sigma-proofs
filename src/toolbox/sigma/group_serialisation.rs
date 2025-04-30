use std::convert::TryInto;

use curve25519_dalek::{ristretto::{CompressedRistretto, RistrettoPoint}, scalar::Scalar as RistrettoScalar};
use bls12_381::{G1Affine, G1Projective, Scalar as BlsScalar};
use ff::PrimeField;
use super::r#trait::GroupSerialisation;

impl GroupSerialisation for RistrettoPoint {
    fn serialize_element(point: &Self) -> Vec<u8> {
        point.compress().to_bytes().to_vec()
    }
    
    fn deserialize_element(bytes: &[u8]) -> Option<Self> {
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


impl GroupSerialisation for G1Projective {
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
        let affine_ctoption = G1Affine::from_compressed(&buf);
        if affine_ctoption.is_some().into() {
            let affine = affine_ctoption.unwrap();
            Some(G1Projective::from(&affine))
        }
        else {
            None
        }
    }

    fn serialize_scalar(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_repr().as_ref().to_vec()
    }

    fn deserialize_scalar(bytes: &[u8]) -> Option<Self::Scalar> {
        let repr = bytes.try_into().ok()?;
        let result_ctoption = BlsScalar::from_repr(repr);
        if result_ctoption.is_some().into() {
            Some(result_ctoption.unwrap())
        }
        else {
            None
        }
    }    
}