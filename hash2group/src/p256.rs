use elliptic_curve::hash2curve::{FromOkm, MapToCurve};
use p256::{FieldElement, ProjectivePoint};

use crate::FromUniformBytes;

impl FromUniformBytes for ProjectivePoint {
    type Bytes = [u8; 96];

    fn from_uniform_bytes(bytes: &Self::Bytes) -> Self {
        fn to_curve_nonuniform(bytes: &[u8; 48]) -> ProjectivePoint {
            FieldElement::from_okm(bytes.into()).map_to_curve()
        }
        let [b0, b1] = bytemuck::cast_ref(bytes);
        to_curve_nonuniform(b0) + to_curve_nonuniform(b1)
    }
}

crate::impl_from_hash!(ProjectivePoint);
