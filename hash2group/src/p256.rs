use elliptic_curve::{array::Array, ops::Reduce};
use hash2curve::MapToCurve;
use p256::{NistP256, ProjectivePoint};

use crate::FromUniformBytes;

impl FromUniformBytes for ProjectivePoint {
    type Bytes = [u8; 96];

    fn from_uniform_bytes(bytes: &Self::Bytes) -> Self {
        fn to_curve_nonuniform(bytes: &[u8; 48]) -> ProjectivePoint {
            let element = <NistP256 as MapToCurve>::FieldElement::reduce(&Array::from(*bytes));
            NistP256::map_to_curve(element)
        }
        let [b0, b1] = bytemuck::cast_ref(bytes);
        to_curve_nonuniform(b0) + to_curve_nonuniform(b1)
    }
}

crate::impl_from_hash!(ProjectivePoint);
