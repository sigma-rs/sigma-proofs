//! Batch verification of batchable NARG strings (Section "Batch verification").

// Runs on untrusted NARG strings; see the panic policy in
// `docs/threat-model.md` §2.1.
#![deny(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use alloc::vec::Vec;
use group::prime::PrimeGroup;
use spongefish::{DuplexSpongeInit, VerifierState};

use super::{NargCodec, PrefixFree, SessionId, SqueezeChallenge};
use crate::codec::{GroupCodec, ScalarCodec};
use crate::errors::VerificationError;
use crate::linear_relation::Instance;
use crate::traits::SigmaProtocol;
use crate::{MultiScalarMul, StdHash};

/// The tag of the batching sponge for batch verification
/// (Section "Batch verification").
const BATCH_VERIFY_TAG: &[u8] = b"irtf-cfrg-sigma-protocols/batch-verify";

/// Batch verification of batchable NARG strings with [`StdHash`] (Section
/// "Batch verification"): each entry is
/// `(session_id, instance, narg_string)`.
///
/// A batch is heterogeneous — its entries may come from unrelated tags — so
/// this is the one entry point that takes session identifiers rather than
/// tags. Derive each with [`derive_session_id::<StdHash>`][crate::derive_session_id]
/// ([module documentation][super]).
pub fn verify_batch<G>(batch: &[(&SessionId, &Instance<G>, &[u8])]) -> Result<(), VerificationError>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    verify_batch_with::<StdHash, G>(batch)
}

/// [`verify_batch`] with a caller-selected transcript sponge.
///
/// Derive every session identifier over the same `H` passed here.
///
/// Each NARG string's challenge is re-derived individually; a single random
/// linear combination of all verification equations is then checked with one
/// multi-scalar multiplication. The 128-bit batching randomness elements are
/// squeezed from a dedicated duplex sponge only after absorbing, for every
/// proof, its session identifier, its serialized instance, and its NARG
/// string — so the randomness is unpredictable to the prover(s).
///
/// Instances are validated by construction. Empty batches are valid. Upon
/// failure, the offending NARG string is not identified; an application may
/// fall back to verifying the NARG strings individually.
///
// The only index here is `i`, which comes from `which`, whose entries are
// positions in `distinct` that were pushed as `distinct` grew; `instance_bytes`
// and `weights` are both built by mapping over `distinct`. The equations' own
// indices are `Equation::accumulate_weights`'s, under the bound argument stated
// there; the one length that came off the wire, `response`, is checked below.
#[allow(clippy::indexing_slicing)]
pub fn verify_batch_with<H, G>(
    batch: &[(&SessionId, &Instance<G>, &[u8])],
) -> Result<(), VerificationError>
where
    H: DuplexSpongeInit<U = u8>,
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    use ff::{Field, PrimeField};
    use itertools::Itertools;

    let count = batch.len();
    if count == 0 {
        return Ok(());
    }
    if u32::try_from(count).is_err() {
        return Err(VerificationError);
    }

    // The distinct instances of the batch, by identity. A server verifying
    // many proofs of one statement passes the same `&Instance` every time, and
    // then both the serialization below and the scalar accumulator further
    // down are computed once for the whole batch rather than once per proof.
    let mut distinct: Vec<&Instance<G>> = Vec::new();
    let mut which: Vec<usize> = Vec::with_capacity(count);
    for (_, instance, _) in batch {
        which.push(
            match distinct.iter().position(|d| core::ptr::eq(*d, *instance)) {
                Some(i) => i,
                None => {
                    distinct.push(instance);
                    distinct.len() - 1
                }
            },
        );
    }

    // The serialized instances: absorbed into the batching sponge below, then
    // again as each NARG string's transcript prefix.
    let instance_bytes = distinct
        .iter()
        .map(|instance| instance.encode_instance())
        .collect::<Vec<_>>();

    // Absorb every value of the batched equation before squeezing any
    // batching randomness: session ids, instances, and NARG strings
    // (including the responses!).
    let batching_sid = spongefish::derive_session_id::<H>(BATCH_VERIFY_TAG);
    let mut sponge = H::init(batching_sid.as_bytes());
    for ((session_id, _, narg_string), &i) in batch.iter().zip_eq(&which) {
        sponge.absorb(session_id.as_bytes());
        sponge.absorb(instance_bytes[i].as_ref());
        sponge.absorb(narg_string);
    }

    // Check sum over i, j of
    //   r[i][j] * commitment[i][j]
    //   + r[i][j] * challenge[i] * image(instances[i])[j]
    //   - r[i][j] * map(instances[i], response[i])[j]  == identity,
    // with each r[i][j] a 16-byte squeeze read as a little-endian
    // integer, in row-major order (consecutive squeezes continue one
    // output stream, so this equals one `16 * K`-byte squeeze).
    //
    // Every image and every term is a coefficient on one of its instance's
    // group elements, so the whole sum is accumulated per element — one MSM
    // entry per distinct group element of the batch, plus one per transmitted
    // commitment — instead of one entry per term of every proof.
    let mut weights = distinct
        .iter()
        .map(|instance| alloc::vec![G::Scalar::ZERO; instance.num_elements()])
        .collect::<Vec<_>>();
    let mut scalars = Vec::new();
    let mut bases = Vec::new();
    for ((session_id, instance, narg_string), &i) in batch.iter().zip_eq(&which) {
        let mut verifier = VerifierState::<H>::new(
            session_id,
            &PrefixFree(instance_bytes[i].as_ref()),
            narg_string,
        );
        let commitment =
            verifier.prover_message_as(|reader| instance.deserialize_commitment(reader))?;
        let challenge = verifier.challenge::<G::Scalar>();
        let response =
            verifier.last_prover_message_as(|reader| instance.deserialize_response(reader))?;

        // This check holds by construction (instance deserialization) should be redundant.
        // Added for completeness.
        if response.len() != instance.num_scalars() {
            return Err(VerificationError);
        }

        let weights = &mut weights[i];
        for (equation, commitment_j) in instance.equations().iter().zip_eq(commitment) {
            let mut randomness = [0u8; 16];
            sponge.squeeze(&mut randomness);
            let r = G::Scalar::from_u128(u128::from_le_bytes(randomness));

            scalars.push(r);
            bases.push(commitment_j);
            equation.accumulate_weights(r, &challenge, &response, weights);
        }
    }

    for (instance, weights) in distinct.iter().zip_eq(&weights) {
        instance.push_weighted_elements(weights, &mut scalars, &mut bases);
    }

    match G::msm_vartime(&scalars, &bases) == G::identity() {
        true => Ok(()),
        false => Err(VerificationError),
    }
}
