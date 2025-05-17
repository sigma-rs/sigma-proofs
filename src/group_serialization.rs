use ff::PrimeField;
use group::{Group, GroupEncoding};

pub fn serialize_element<G: Group + GroupEncoding>(element: &G) -> Vec<u8> {
    element.to_bytes().as_ref().to_vec()
}

pub fn deserialize_element<G: Group + GroupEncoding>(data: &[u8]) -> Option<G> {
    let element_len = G::Repr::default().as_ref().len();
    if data.len() != element_len {
        return None;
    }

    let mut repr = G::Repr::default();
    repr.as_mut().copy_from_slice(data);
    let ct_point = G::from_bytes(&repr);

    if ct_point.is_some().into() {
        let point = ct_point.unwrap();
        Some(point)
    } else {
        None
    }
}

pub fn serialize_scalar<G: Group>(scalar: &G::Scalar) -> Vec<u8> {
    let mut scalar_bytes = scalar.to_repr().as_ref().to_vec();
    scalar_bytes.reverse();
    scalar_bytes
}

pub fn deserialize_scalar<G: Group>(data: &[u8]) -> Option<G::Scalar> {
    let scalar_len = <<G as Group>::Scalar as PrimeField>::Repr::default()
        .as_ref()
        .len();
    if data.len() != scalar_len {
        return None;
    }

    let mut repr = <<G as Group>::Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&{
        let mut tmp = data.to_vec();
        tmp.reverse();
        tmp
    });

    G::Scalar::from_repr(repr).into()
}
