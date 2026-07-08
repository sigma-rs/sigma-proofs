//! Non-interactive Sigma Protocols (draft-irtf-cfrg-sigma-protocols,
//! Section "Non-interactive Sigma Protocols").
//!
//! This module defines [`Nizk`], the non-interactive argument obtained by
//! applying the duplex-sponge Fiat-Shamir transformation of
//! draft-irtf-cfrg-fiat-shamir to a [`SigmaProtocol`].
//!
//! The verifier challenge is `DeriveChallenge(tag, instance,
//! commitment_bytes)`: the 32-byte session identifier is derived from the
//! `tag` via `DeriveSessionID`, the SHAKE128 duplex sponge is seeded with it,
//! the serialized instance and the serialized commitment are absorbed, and
//! the challenge scalar is decoded from `Ns + 16` squeezed bytes
//! (little-endian wide reduction).

use crate::errors::Error;
use crate::linear_relation::Instance;
use crate::traits::ScalarRng;
use crate::traits::SigmaProtocol;
use crate::traits::SigmaProtocolSimulator;
use crate::MultiScalarMul;
use alloc::vec::Vec;
use ff::PrimeField;
use itertools::Itertools;
use group::prime::PrimeGroup;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, StdHash};

/// The session identifier of the batching sponge for batch verification
/// (Section "Batch verification").
const BATCH_VERIFY_TAG: &[u8] = b"irtf-cfrg-sigma-protocols/batch-verify";

/// A non-interactive Sigma protocol, transformed via the duplex-sponge
/// Fiat-Shamir transformation.
///
/// # Type Parameters
/// - `P`: the Sigma protocol implementation.
#[derive(Debug)]
pub struct Nizk<P>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
{
    /// The 32-byte session identifier seeding the duplex sponge.
    pub session_id: [u8; 32],
    /// Underlying interactive proof.
    pub interactive_proof: P,
}

/// `DeriveChallenge` of the specification, minus the session-id derivation:
/// seed the duplex sponge with `session_id`, absorb the serialized instance
/// and the serialized commitment, and decode the challenge.
pub(crate) fn derive_challenge<C: Decoding<[u8]>>(
    session_id: &[u8; 32],
    instance_label: &[u8],
    commitment_bytes: &[u8],
) -> C {
    let mut sponge = StdHash::new(session_id);
    sponge.absorb(instance_label);
    sponge.absorb(commitment_bytes);
    let mut repr = C::Repr::default();
    sponge.squeeze(repr.as_mut());
    C::decode(repr)
}

impl<P> Nizk<P>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
{
    /// Constructs a new [`Nizk`] for the given application `tag`.
    ///
    /// The session identifier is derived from `tag` via the `DeriveSessionID`
    /// of draft-irtf-cfrg-fiat-shamir. Per the specification, the tag must
    /// uniquely identify the argument, its codecs, and the application
    /// context, and must contain the flavor marker (`DSFS` for batchable,
    /// `CMPT` for compact NARG strings) and the ciphersuite identifier
    /// verbatim.
    pub fn new(tag: &[u8], interactive_proof: P) -> Self {
        Self {
            session_id: spongefish::derive_session_id(tag),
            interactive_proof,
        }
    }

    /// Constructs a new [`Nizk`] from a pre-derived 32-byte session
    /// identifier. The identifier must satisfy the same requirements as a
    /// tag-derived one and must come from trusted input.
    pub fn from_session_id(session_id: [u8; 32], interactive_proof: P) -> Self {
        Self {
            session_id,
            interactive_proof,
        }
    }
}

impl<P> Nizk<P>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    P::Commitment: NargSerialize + NargDeserialize + Encoding,
    P::Response: NargSerialize + NargDeserialize + Encoding,
{
    /// `ProveBatchable`: generates a batchable NARG string,
    /// `serialize(commitment) || serialize(response)`.
    pub fn prove_batchable(
        &self,
        witness: &P::Witness,
        rng: &mut impl ScalarRng,
    ) -> Result<Vec<u8>, Error> {
        let instance_label = self.interactive_proof.instance_label();
        let (commitment, ip_state) = self.interactive_proof.prover_commit(witness, rng)?;
        let commitment_bytes = serialize_messages(&commitment);
        let challenge = derive_challenge::<P::Challenge>(
            &self.session_id,
            instance_label.as_ref(),
            &commitment_bytes,
        );
        let response = self
            .interactive_proof
            .prover_response(ip_state, &challenge)?;

        let mut narg_string = commitment_bytes;
        serialize_messages_into(&response, &mut narg_string);
        Ok(narg_string)
    }

    /// `VerifyBatchable`: verifies a batchable NARG string.
    ///
    /// Instance validity is enforced by construction of the instance type;
    /// the NARG string length is enforced by the fixed-size deserialization
    /// plus the trailing-bytes check.
    pub fn verify_batchable(&self, narg_string: &[u8]) -> Result<(), Error> {
        let instance_label = self.interactive_proof.instance_label();
        let commitment_len = self.interactive_proof.commitment_len();
        let response_len = self.interactive_proof.response_len();

        let mut cursor = narg_string;
        let commitment = deserialize_messages::<P::Commitment>(commitment_len, &mut cursor)?;
        self.interactive_proof.check_commitment(&commitment)?;
        let commitment_bytes_len = narg_string.len() - cursor.len();
        let response = deserialize_messages::<P::Response>(response_len, &mut cursor)?;
        if !cursor.is_empty() {
            return Err(Error::VerificationFailure);
        }

        // Absorbing the received bytes and absorbing the serialized
        // commitment are interchangeable for these encodings.
        let challenge = derive_challenge::<P::Challenge>(
            &self.session_id,
            instance_label.as_ref(),
            &narg_string[..commitment_bytes_len],
        );
        self.interactive_proof
            .verifier(&commitment, &challenge, &response)
    }
}

impl<P> Nizk<P>
where
    P: SigmaProtocol + SigmaProtocolSimulator,
    P::Challenge: PartialEq + NargDeserialize + NargSerialize,
{
    /// `ProveCompact`: generates a compact NARG string,
    /// `serialize(challenge) || serialize(response)`.
    pub fn prove_compact(
        &self,
        witness: &P::Witness,
        rng: &mut impl ScalarRng,
    ) -> Result<Vec<u8>, Error> {
        let instance_label = self.interactive_proof.instance_label();
        let (commitment, ip_state) = self.interactive_proof.prover_commit(witness, rng)?;
        let commitment_bytes = serialize_messages(&commitment);
        let challenge = derive_challenge::<P::Challenge>(
            &self.session_id,
            instance_label.as_ref(),
            &commitment_bytes,
        );
        let response = self
            .interactive_proof
            .prover_response(ip_state, &challenge)?;

        let mut narg_string = Vec::new();
        challenge.serialize_into_narg(&mut narg_string);
        serialize_messages_into(&response, &mut narg_string);
        Ok(narg_string)
    }

    /// `VerifyCompact`: recomputes the commitment from `(challenge, response)`
    /// via the simulator, rejects identity commitments (step 7 of the
    /// specification), and accepts only if the re-derived challenge matches.
    pub fn verify_compact(&self, narg_string: &[u8]) -> Result<(), Error> {
        let instance_label = self.interactive_proof.instance_label();
        let response_len = self.interactive_proof.response_len();

        let mut cursor = narg_string;
        let challenge = P::Challenge::deserialize_from_narg(&mut cursor)?;
        let response = deserialize_messages::<P::Response>(response_len, &mut cursor)?;
        if !cursor.is_empty() {
            return Err(Error::VerificationFailure);
        }

        let commitment = self
            .interactive_proof
            .simulate_commitment(&challenge, &response)?;
        // Step 7: maintain consistency with group deserialization, which
        // rejects the identity element.
        self.interactive_proof.check_commitment(&commitment)?;

        let commitment_bytes = serialize_messages(&commitment);
        let expected_challenge = derive_challenge::<P::Challenge>(
            &self.session_id,
            instance_label.as_ref(),
            &commitment_bytes,
        );
        if challenge != expected_challenge {
            return Err(Error::VerificationFailure);
        }
        // Since the simulator always outputs accepting transcripts, running
        // the interactive verifier here would be redundant.
        Ok(())
    }
}

impl<G> Nizk<Instance<G>>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    /// Batch verification of batchable NARG strings (Section "Batch
    /// verification").
    ///
    /// Each NARG string's challenge is re-derived individually with
    /// `DeriveChallenge`; a single random linear combination of all
    /// verification equations is then checked with one multi-scalar
    /// multiplication. The 128-bit batching randomness elements are squeezed
    /// from a dedicated duplex sponge only after absorbing, for every proof,
    /// its session identifier, its serialized instance, and its NARG string —
    /// so the randomness is unpredictable to the prover(s).
    ///
    /// Instances are validated by construction. Empty batches are valid.
    /// Upon failure, the offending NARG string is not identified; an
    /// application may fall back to verifying the NARG strings individually
    /// with [`Nizk::verify_batchable`].
    pub fn verify_batch(proofs: &[(&Nizk<Instance<G>>, &[u8])]) -> Result<(), Error> {
        if proofs.is_empty() {
            return Ok(());
        }
        if u32::try_from(proofs.len()).is_err() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        // Absorb every value of the batched equation before squeezing any
        // batching randomness: session ids, instances, and NARG strings
        // (including the responses!).
        let batching_sid = spongefish::derive_session_id(BATCH_VERIFY_TAG);
        let mut sponge = StdHash::new(&batching_sid);
        for (nizk, narg_string) in proofs {
            sponge.absorb(&nizk.session_id);
            sponge.absorb(&nizk.interactive_proof.serialize());
            sponge.absorb(narg_string);
        }

        // Check sum over i, j of
        //   r[i][j] * commitment[i][j]
        //   + r[i][j] * challenge[i] * image(instances[i])[j]
        //   - r[i][j] * map(instances[i], response[i])[j]  == identity,
        // with each r[i][j] a 16-byte squeeze read as a little-endian
        // integer, in row-major order (consecutive squeezes continue one
        // output stream, so this equals one `16 * K`-byte squeeze).
        let mut scalars = Vec::new();
        let mut bases = Vec::new();
        for (nizk, narg_string) in proofs {
            let instance = &nizk.interactive_proof;
            let mut cursor = *narg_string;
            let commitment =
                deserialize_messages::<G>(instance.num_equations(), &mut cursor)?;
            instance.check_commitment(&commitment)?;
            let commitment_bytes_len = narg_string.len() - cursor.len();
            let response =
                deserialize_messages::<G::Scalar>(instance.num_scalars(), &mut cursor)?;
            if !cursor.is_empty() {
                return Err(Error::VerificationFailure);
            }
            let challenge = derive_challenge::<G::Scalar>(
                &nizk.session_id,
                instance.serialize().as_ref(),
                &narg_string[..commitment_bytes_len],
            );

            for (equation, commitment_j) in instance.equations().iter().zip_eq(commitment) {
                let mut randomness = [0u8; 16];
                sponge.squeeze(&mut randomness);
                let r = G::Scalar::from_u128(u128::from_le_bytes(randomness));

                scalars.push(r);
                bases.push(commitment_j);
                for &(element_index, coeff) in &equation.image {
                    scalars.push(r * challenge * coeff);
                    bases.push(instance.elements()[element_index as usize]);
                }
                for &(scalar_index, element_index, coeff) in &equation.terms {
                    scalars.push(-(r * response[scalar_index as usize] * coeff));
                    bases.push(instance.elements()[element_index as usize]);
                }
            }
        }

        match G::msm(&scalars, &bases) == G::identity() {
            true => Ok(()),
            false => Err(Error::VerificationFailure),
        }
    }
}

pub(crate) fn serialize_messages_into<T: NargSerialize>(messages: &[T], out: &mut Vec<u8>) {
    for message in messages {
        message.serialize_into_narg(out);
    }
}

pub(crate) fn serialize_messages<T: NargSerialize>(messages: &[T]) -> Vec<u8> {
    let mut out = Vec::new();
    serialize_messages_into(messages, &mut out);
    out
}

pub(crate) fn deserialize_messages<T: NargDeserialize>(
    len: usize,
    buf: &mut &[u8],
) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    for _ in 0..len {
        out.push(T::deserialize_from_narg(buf).map_err(|_| Error::VerificationFailure)?);
    }
    Ok(out)
}
