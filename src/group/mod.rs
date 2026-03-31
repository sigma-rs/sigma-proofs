/// Implementation of multi-scalar multiplication (MSM) over scalars and points.
pub mod msm;

/// Deprecated compatibility helpers for scalars and points.
///
/// Prefer `spongefish::Encoding` / `spongefish::NargSerialize` /
/// `spongefish::NargDeserialize` for proof and transcript bytes. Only use
/// direct `GroupEncoding::to_bytes` / `GroupEncoding::from_bytes` loops for
/// fixed-width group-byte labels outside the transcript path.
#[deprecated(
    note = "Use `spongefish::{Encoding, NargSerialize, NargDeserialize}` for proof and transcript bytes. Only use direct `GroupEncoding` loops for fixed-width group-byte labels."
)]
pub mod serialization;
