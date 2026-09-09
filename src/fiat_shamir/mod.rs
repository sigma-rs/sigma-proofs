//! Non-interactive Sigma Protocols (draft-irtf-cfrg-sigma-protocols,
//! Section "Non-interactive Sigma Protocols").
//!
//! At the core of this module are the spec-shaped functions
//! [`prove_batchable`], [`verify_batchable`], [`prove_compact`],
//! [`verify_compact`], and [`verify_batch`]. Each is written once, generic
//! over [`NargCodec`]: the round structure and the challenge derivation are
//! the protocol's, and only the wire format of the prover messages varies
//! per relation. They serve the linear relation's
//! [`Instance`] and the
//! [`ComposedInstance`][crate::composition::ComposedInstance] alike.
//!
//! The application-facing entry points take a tag and use
//! [`StdHash`], deriving the [`SessionId`] internally and seeding the prover's
//! randomness from OS entropy. Their `_with` variants make every one of those
//! choices the caller's: the transcript sponge, an already-derived identifier,
//! and — when proving — the randomness. They serve registered ciphersuites,
//! test vectors, and applications that need a different hash.
//!
//! A different sponge in [`derive_session_id`] produces a different session
//! identifier from the same tag, and hence a proof that verifies only against
//! itself. The explicit variants also make it natural to reuse one identifier
//! across a batch, a test-vector suite, or repeated proofs under one tag.
//!
//! [`SessionId`] is a newtype rather than a bare array, so a caller cannot
//! accidentally pass a tag where an identifier belongs or silently derive a
//! second identifier from an identifier's raw bytes.
//!
//! The transcript follows draft-irtf-cfrg-fiat-shamir over a duplex sponge:
//! [`StdHash`] for the application-facing functions, or the
//! caller's `H` in the explicit variants. Use
//! [`Shake128`][spongefish::instantiations::Shake128] for the
//! specification's registered ciphersuites. The sponge is seeded with the
//! session identifier, the serialized instance
//! ([`SigmaProtocol::encode_instance`]) is the first
//! absorbed value, prover messages are absorbed as they are serialized, and
//! the challenge is decoded from
//! [`challenge_len()`][ScalarCodec::challenge_len] squeezed bytes
//! (little-endian wide reduction). Every flavor here — batchable, compact,
//! and batch — squeezes that same width through the same decoding map, which
//! is what makes prover and verifier agree by construction.
//!
//! Every message crosses the transcript through spongefish's one-off closure
//! forms, because in each direction the codec is a function of the relation
//! rather than of the message type, which is what a trait implementation would
//! have to be:
//!
//! - Writing a prover message hands spongefish [`NargCodec`]'s serializer, so
//!   the bytes are absorbed and appended in the one call that produces them.
//!   The serializers are total; proving samples until
//!   [`NargCodec::is_valid_commitment`] accepts before encoding.
//! - Reading one is directed by the instance, and
//!   [`NargDeserialize`][spongefish::NargDeserialize] is a function of the
//!   type alone. The shape — how many elements, which branches — comes from
//!   `self`, never from the bytes being read, which is the property the whole
//!   parser is built on.
//! - A challenge is decoded from `Ns + 16` bytes, a width
//!   [`Decoding::Repr`][spongefish::Decoding] cannot name for a generic
//!   field. Both sides squeeze it through `SqueezeChallenge`, so the width
//!   and the decoding map are written once.
//!
//! The orphan rule would bite anyway: `Encoding`/`Decoding` are foreign traits
//! and `G`/`G::Scalar` foreign types, so a generic relation cannot implement
//! them for its own message types without a local newtype.
//!
//! # Tag requirements
//!
//! The specification REQUIRES the tag to contain, verbatim, the flavor
//! marker (`DSFS` for batchable, `CMPT` for compact NARG strings) and the
//! ciphersuite identifier, alongside the application's own context. With
//! application-supplied tags this library cannot enforce that: batchable and
//! compact proofs of the same statement must use different tags, and a proof
//! verifies only under the tag it was produced for.

use crate::codec::{
    deserialize_elements, deserialize_scalars, serialize_elements_allowing_identity,
    serialize_scalars, GroupCodec, ScalarCodec,
};
use crate::errors::{InvalidWitness, VerificationError};
use crate::linear_relation::Instance;
use crate::traits::{SigmaProtocol, SigmaProtocolSimulator};
use crate::{MultiScalarMul, StdHash};
use alloc::vec::Vec;
use group::prime::PrimeGroup;
use spongefish::PrivateRng;
use spongefish::{
    DuplexSpongeInit, DuplexSpongeInterface, Encoding, NargReader, ProverState, VerifierState,
};

/// The typed session identifier used by the explicit entry points, and the
/// draft's `DeriveSessionID(tag)` that produces one. Both are spongefish's —
/// the transcript layer defines them, and this crate only passes them through.
pub use spongefish::{derive_session_id, SessionId};

mod batch;

pub use batch::{verify_batch, verify_batch_with};

/// An identity encoding for byte strings whose length is fixed by the
/// relation. Bare byte slices deliberately do not implement [`Encoding`]:
/// their length is not part of their type, so they are not prefix-free in
/// general. Every use here is an encoded instance or the compact flavor's
/// untransmitted commitment — values whose length both sides fix before the
/// transcript is parsed, and which are absorbed rather than serialized.
pub(super) struct PrefixFree<'a>(pub(super) &'a [u8]);

impl Encoding<[u8]> for PrefixFree<'_> {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0
    }
}

/// The wire format of a relation's prover messages.
///
/// Serialization is kept out of [`SigmaProtocol`]: it belongs to the NARG
/// string rather than the interactive protocol. Deserialization is directed
/// by `self`, so the expected shape is never read from untrusted bytes.
///
/// Implementing this on top of [`SigmaProtocol`] is all a relation owes the
/// non-interactive layer: both NARG flavors and batch verification are written
/// once against this trait.
pub trait NargCodec: SigmaProtocol {
    /// Whether the commitment has a canonical encoding for this relation.
    fn is_valid_commitment(&self, commitment: &Self::Commitment) -> bool;

    /// Serialization function for the commitment message.
    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8>;

    /// Serialization function for the response message.
    fn serialize_response(&self, response: &Self::Response) -> Vec<u8>;

    /// Deserialization function for the commitment message.
    fn deserialize_commitment(
        &self,
        reader: &mut NargReader<'_>,
    ) -> Result<Self::Commitment, VerificationError>;

    /// Deserialization function for the response message.
    fn deserialize_response(
        &self,
        reader: &mut NargReader<'_>,
    ) -> Result<Self::Response, VerificationError>;
}

/// Squeezing a challenge, stated once for both sides of the transcript.
///
/// The width and the decoding map are the two halves that prover and verifier
/// must agree on, and every flavor here squeezes the same pair. Written as an
/// extension trait rather than repeated at each call site so that the
/// agreement is a property of one function.
pub(crate) trait SqueezeChallenge {
    fn challenge<F: ScalarCodec>(&mut self) -> F;
}

impl<H: DuplexSpongeInterface<U = u8>> SqueezeChallenge for ProverState<H> {
    fn challenge<F: ScalarCodec>(&mut self) -> F {
        self.verifier_message_as(F::challenge_len(), F::from_uniform_bytes)
    }
}

impl<H: DuplexSpongeInterface<U = u8>> SqueezeChallenge for VerifierState<'_, H> {
    fn challenge<F: ScalarCodec>(&mut self) -> F {
        self.verifier_message_as(F::challenge_len(), F::from_uniform_bytes)
    }
}

impl<G> NargCodec for Instance<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    fn is_valid_commitment(&self, _commitment: &Vec<G>) -> bool {
        true
    }

    fn serialize_commitment(&self, commitment: &Vec<G>) -> Vec<u8> {
        serialize_elements_allowing_identity(commitment)
    }

    fn serialize_response(&self, response: &Vec<G::Scalar>) -> Vec<u8> {
        serialize_scalars(response)
    }

    fn deserialize_commitment(
        &self,
        reader: &mut NargReader<'_>,
    ) -> Result<Vec<G>, VerificationError> {
        deserialize_elements(reader, self.num_equations())
    }

    fn deserialize_response(
        &self,
        reader: &mut NargReader<'_>,
    ) -> Result<Vec<G::Scalar>, VerificationError> {
        deserialize_scalars(reader, self.num_scalars())
    }
}

/// Draws a prover commitment until its relation-directed wire encoding is
/// valid. Every commitment of the built-in prime-order protocols is valid.
fn sample_valid_commitment<P>(
    instance: &P,
    witness: &P::Witness,
    rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
) -> core::result::Result<(P::Commitment, P::ProverState), InvalidWitness>
where
    P: NargCodec,
{
    loop {
        let candidate = instance.prover_commit(witness, rng)?;
        if instance.is_valid_commitment(&candidate.0) {
            return Ok(candidate);
        }
    }
}

/// Generates a batchable NARG string with [`StdHash`].
///
/// The session identifier is derived from `tag`. The tag must contain the
/// `DSFS` flavor marker and ciphersuite identifier
/// ([module documentation][self#tag-requirements]).
///
/// The prover randomness is a [`PrivateRng`] seeded from OS entropy. Use
/// [`prove_batchable_with`] to choose the sponge, the session identifier, and
/// the randomness yourself.
pub fn prove_batchable<P>(
    tag: &[u8],
    instance: &P,
    witness: &P::Witness,
) -> core::result::Result<Vec<u8>, InvalidWitness>
where
    P: NargCodec,
    P::Challenge: ScalarCodec,
{
    let session_id = derive_session_id::<StdHash>(tag);
    prove_batchable_with::<StdHash, P>(
        &session_id,
        instance,
        witness,
        &mut PrivateRng::<StdHash>::from_os_entropy(),
    )
}

/// [`prove_batchable`] with a caller-selected transcript sponge, an
/// already-derived session identifier, and caller-supplied randomness
/// (registered ciphersuites, deterministic test vectors, custom entropy
/// policies).
pub fn prove_batchable_with<H, P>(
    session_id: &SessionId,
    instance: &P,
    witness: &P::Witness,
    rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
) -> core::result::Result<Vec<u8>, InvalidWitness>
where
    H: DuplexSpongeInit<U = u8>,
    P: NargCodec,
    P::Challenge: ScalarCodec,
{
    let instance_bytes = instance.encode_instance();
    let mut prover = ProverState::<H>::new(session_id, &PrefixFree(instance_bytes.as_ref()));
    let (commitment, prover_state) = sample_valid_commitment(instance, witness, rng)?;
    prover.prover_message_as(&commitment, |c| instance.serialize_commitment(c));
    let challenge = prover.challenge::<P::Challenge>();
    let response = instance.prover_response(prover_state, &challenge)?;
    Ok(prover.last_prover_message_as(&response, |r| instance.serialize_response(r)))
}

/// `challenge = Squeeze(Absorb(commitment))` for the compact flavor, where
/// the commitment is absorbed but never transmitted. Prover and verifier
/// derive it here, through one function, so the two cannot drift.
fn compact_challenge<H, P>(
    session_id: &SessionId,
    instance: &P,
    commitment_bytes: &[u8],
) -> P::Challenge
where
    H: DuplexSpongeInit<U = u8>,
    P: NargCodec,
    P::Challenge: ScalarCodec,
{
    // A transcript that transmits nothing: the NARG string of the compact
    // flavor carries the challenge and the response, neither of which is
    // absorbed, so this state is the sponge alone.
    let instance_bytes = instance.encode_instance();
    let mut state = VerifierState::<H>::new(session_id, &PrefixFree(instance_bytes.as_ref()), &[]);
    state.public_message(&PrefixFree(commitment_bytes));
    state.challenge::<P::Challenge>()
}

/// Verifies a batchable NARG string with [`StdHash`], deriving its session
/// identifier from `tag`.
///
/// Instance validity is enforced by construction; the NARG string length is
/// enforced by the instance-directed deserialization plus the trailing-bytes
/// check. Parsing walks the relation in lockstep with the buffer: the
/// verifier knows the shape, and nothing shape-related is read from the
/// untrusted bytes.
pub fn verify_batchable<P>(
    tag: &[u8],
    instance: &P,
    narg_string: &[u8],
) -> Result<(), VerificationError>
where
    P: NargCodec,
    P::Challenge: ScalarCodec,
{
    let session_id = derive_session_id::<StdHash>(tag);
    verify_batchable_with::<StdHash, P>(&session_id, instance, narg_string)
}

/// [`verify_batchable`] with a caller-selected transcript sponge and an
/// already-derived session identifier.
pub fn verify_batchable_with<H, P>(
    session_id: &SessionId,
    instance: &P,
    narg_string: &[u8],
) -> Result<(), VerificationError>
where
    H: DuplexSpongeInit<U = u8>,
    P: NargCodec,
    P::Challenge: ScalarCodec,
{
    let instance_bytes = instance.encode_instance();
    let mut verifier = VerifierState::<H>::new(
        session_id,
        &PrefixFree(instance_bytes.as_ref()),
        narg_string,
    );
    let commitment =
        verifier.prover_message_as(|reader| instance.deserialize_commitment(reader))?;
    let challenge = verifier.challenge::<P::Challenge>();
    let response = verifier.prover_message_as(|reader| instance.deserialize_response(reader))?;
    // One more squeeze, taken only after the entire NARG string has been
    // absorbed, so it is unpredictable to the prover: relations that can
    // collapse their verification equations into a single multi-scalar
    // multiplication use it as the combining randomness
    // ([`SigmaProtocol::verifier_with_randomness`]). It comes after the
    // challenge and absorbs nothing, so it changes neither the NARG string
    // nor the challenge derivation.
    let randomness = verifier.challenge::<P::Challenge>();
    verifier.check_eof()?;
    instance.verifier_with_randomness(&commitment, &challenge, &response, &randomness)
}

/// Generates a compact NARG string with [`StdHash`].
///
/// The session identifier is derived from `tag`. The tag must contain the
/// `CMPT` flavor marker and ciphersuite
/// identifier ([module documentation][self#tag-requirements]).
///
/// The prover randomness is a [`PrivateRng`] seeded from OS entropy. Use
/// [`prove_compact_with`] to choose the sponge, the session identifier, and
/// the randomness yourself.
pub fn prove_compact<P>(
    tag: &[u8],
    instance: &P,
    witness: &P::Witness,
) -> core::result::Result<Vec<u8>, InvalidWitness>
where
    P: NargCodec + SigmaProtocolSimulator,
    P::Challenge: ScalarCodec,
{
    let session_id = derive_session_id::<StdHash>(tag);
    prove_compact_with::<StdHash, P>(
        &session_id,
        instance,
        witness,
        &mut PrivateRng::<StdHash>::from_os_entropy(),
    )
}

/// [`prove_compact`] with a caller-selected transcript sponge, an
/// already-derived session identifier, and caller-supplied randomness
/// (registered ciphersuites, deterministic test vectors, custom entropy
/// policies).
pub fn prove_compact_with<H, P>(
    session_id: &SessionId,
    instance: &P,
    witness: &P::Witness,
    rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
) -> core::result::Result<Vec<u8>, InvalidWitness>
where
    H: DuplexSpongeInit<U = u8>,
    P: NargCodec + SigmaProtocolSimulator,
    P::Challenge: ScalarCodec,
{
    let (commitment, prover_state) = sample_valid_commitment(instance, witness, rng)?;
    let commitment_bytes = instance.serialize_commitment(&commitment);
    let challenge = compact_challenge::<H, P>(session_id, instance, &commitment_bytes);
    let response = instance.prover_response(prover_state, &challenge)?;

    let mut narg_string = Vec::new();
    challenge.serialize_scalar(&mut narg_string);
    narg_string.extend_from_slice(&instance.serialize_response(&response));
    Ok(narg_string)
}

/// Verifies a compact NARG string with [`StdHash`], deriving its session
/// identifier from `tag`.
pub fn verify_compact<P>(
    tag: &[u8],
    instance: &P,
    narg_string: &[u8],
) -> Result<(), VerificationError>
where
    P: NargCodec + SigmaProtocolSimulator,
    P::Challenge: ScalarCodec,
{
    let session_id = derive_session_id::<StdHash>(tag);
    verify_compact_with::<StdHash, P>(&session_id, instance, narg_string)
}

/// [`verify_compact`] with a caller-selected transcript sponge and an
/// already-derived session identifier.
///
/// Recomputes the commitment from `(challenge, response)` via the simulator,
/// then re-derives the challenge and accepts only on a match.
pub fn verify_compact_with<H, P>(
    session_id: &SessionId,
    instance: &P,
    narg_string: &[u8],
) -> Result<(), VerificationError>
where
    H: DuplexSpongeInit<U = u8>,
    P: NargCodec + SigmaProtocolSimulator,
    P::Challenge: ScalarCodec,
{
    let mut reader = NargReader::new(narg_string);
    let challenge = P::Challenge::deserialize_scalar(&mut reader)?;
    let response = instance.deserialize_response(&mut reader)?;
    if !reader.is_empty() {
        return Err(VerificationError);
    }

    let commitment = instance.simulate_commitment(&challenge, &response)?;
    if !instance.is_valid_commitment(&commitment) {
        return Err(VerificationError);
    }
    let commitment_bytes = instance.serialize_commitment(&commitment);
    let expected_challenge = compact_challenge::<H, P>(session_id, instance, &commitment_bytes);
    // The simulator always outputs accepting transcripts, so running the
    // interactive verifier here would be redundant.
    match challenge == expected_challenge {
        true => Ok(()),
        false => Err(VerificationError),
    }
}
