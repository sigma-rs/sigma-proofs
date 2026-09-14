use core::cell::Cell;

use curve25519_dalek::{RistrettoPoint as G, Scalar};
use group::Group;
use sigma_proofs::codec::{GroupCodec, ScalarCodec};
use sigma_proofs::composition::{ComposedInstance, ComposedWitness};
use sigma_proofs::errors::{InvalidWitness, VerificationError};
use sigma_proofs::traits::{SigmaProtocol, SigmaProtocolSimulator, Transcript};
use sigma_proofs::{
    derive_session_id, prove_batchable, prove_batchable_with, prove_compact, prove_compact_with,
    verify_batchable, verify_compact, DefaultHash, DuplexSpongeInit, LinearRelation, NargCodec,
    PrivateRng, ProverRng,
};
use spongefish::NargReader;

/// A toy external protocol used to exercise the codec contract in both flavors.
struct ExternalCodec {
    attempts: Cell<u8>,
    commitment: G,
}

impl SigmaProtocol for ExternalCodec {
    type Commitment = G;
    type Challenge = Scalar;
    type Response = Scalar;
    type ProverState = ();
    type Witness = bool;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        _rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> core::result::Result<(Self::Commitment, Self::ProverState), InvalidWitness> {
        let attempt = self.attempts.get();
        self.attempts.set(attempt + 1);
        // Bound the test double even if a retry loop is accidentally restored.
        if attempt > 0 || !witness {
            return Err(InvalidWitness);
        }
        Ok((self.commitment, ()))
    }

    fn prover_response(
        &self,
        _state: Self::ProverState,
        _challenge: &Self::Challenge,
    ) -> core::result::Result<Self::Response, InvalidWitness> {
        Ok(Scalar::ZERO)
    }

    fn verifier(
        &self,
        _commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        _response: &Self::Response,
    ) -> Result<(), VerificationError> {
        Ok(())
    }

    fn encode_instance(&self) -> impl AsRef<[u8]> {
        b"external-codec"
    }
}

impl NargCodec for ExternalCodec {
    fn serialize_commitment_into(&self, commitment: &Self::Commitment, out: &mut Vec<u8>) {
        commitment.serialize_element(out);
    }

    fn serialize_response_into(&self, response: &Self::Response, out: &mut Vec<u8>) {
        response.serialize_scalar(out);
    }

    fn deserialize_commitment(
        &self,
        reader: &mut NargReader<'_>,
    ) -> Result<Self::Commitment, VerificationError> {
        G::deserialize_element(reader)
    }

    fn deserialize_response(
        &self,
        reader: &mut NargReader<'_>,
    ) -> Result<Self::Response, VerificationError> {
        Scalar::deserialize_scalar(reader)
    }
}

impl SigmaProtocolSimulator for ExternalCodec {
    fn simulate_response(&self, _rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>) -> Scalar {
        Scalar::ZERO
    }

    fn simulate_commitment(
        &self,
        _challenge: &Scalar,
        _response: &Scalar,
    ) -> Result<G, VerificationError> {
        Ok(self.commitment)
    }

    fn simulate_transcript(
        &self,
        rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> Result<Transcript<Self>, VerificationError> {
        Ok((self.commitment, Scalar::sample(rng), Scalar::ZERO))
    }
}

const BATCH_TAG: &[u8] = b"external codec DSFS";
const COMPACT_TAG: &[u8] = b"external codec CMPT";

fn prove_external(
    compact: bool,
    relation: &ExternalCodec,
    witness: bool,
) -> Result<Vec<u8>, InvalidWitness> {
    let mut rng = ProverRng::from_seed([7u8; 32]);
    if compact {
        let session_id = derive_session_id::<DefaultHash>(COMPACT_TAG);
        prove_compact_with::<DefaultHash, _>(&session_id, relation, &witness, &mut rng)
    } else {
        let session_id = derive_session_id::<DefaultHash>(BATCH_TAG);
        prove_batchable_with::<DefaultHash, _>(&session_id, relation, &witness, &mut rng)
    }
}

#[test]
fn a_valid_external_commitment_is_generated_once() {
    for compact in [false, true] {
        let relation = ExternalCodec {
            attempts: Cell::new(0),
            commitment: G::generator(),
        };
        let proof = prove_external(compact, &relation, true).unwrap();
        assert_eq!(relation.attempts.get(), 1);
        if compact {
            verify_compact(COMPACT_TAG, &relation, &proof).unwrap();
        } else {
            verify_batchable(BATCH_TAG, &relation, &proof).unwrap();
        }
    }
}

#[test]
fn invalid_witness_errors_are_propagated_without_retrying() {
    for compact in [false, true] {
        let relation = ExternalCodec {
            attempts: Cell::new(0),
            commitment: G::generator(),
        };
        assert!(matches!(
            prove_external(compact, &relation, false),
            Err(InvalidWitness)
        ));
        assert_eq!(relation.attempts.get(), 1);
    }
}

#[test]
fn malformed_message_encodings_return_errors() {
    let relation = ExternalCodec {
        attempts: Cell::new(0),
        commitment: G::generator(),
    };
    // Invalid Ristretto encoding, followed by a valid response.
    let mut proof = vec![0xff; G::element_len()];
    relation.serialize_response_into(&Scalar::ZERO, &mut proof);
    assert!(verify_batchable(BATCH_TAG, &relation, &proof).is_err());

    // A valid scalar challenge, followed by a non-canonical response scalar.
    let mut proof = Vec::new();
    Scalar::ZERO.serialize_scalar(&mut proof);
    proof.extend_from_slice(&vec![0xff; Scalar::scalar_len()]);
    assert!(verify_compact(COMPACT_TAG, &relation, &proof).is_err());
    assert_eq!(relation.attempts.get(), 0);
}

#[test]
fn identity_commitments_verify_in_both_narg_flavors() {
    // A zero map has an identity commitment for every nonce, so this tests
    // the actual built-in prover without relying on a negligible RNG event.
    let mut builder = LinearRelation::<G>::new();
    let x = builder.allocate_scalar();
    builder.allocate_eq_with(G::identity(), x * builder.generator() * Scalar::ZERO);
    let instance = builder.compile().unwrap();
    let witness = vec![Scalar::from(42u64)];
    let mut rng = ProverRng::from_seed([11u8; 32]);
    let (commitment, _) = instance.prover_commit(&witness, &mut rng).unwrap();
    assert_eq!(commitment, vec![G::identity()]);

    let batchable = prove_batchable(BATCH_TAG, &instance, &witness).unwrap();
    let mut reader = NargReader::new(&batchable);
    assert_eq!(
        instance.deserialize_commitment(&mut reader).unwrap(),
        commitment
    );
    verify_batchable(BATCH_TAG, &instance, &batchable).unwrap();
    let compact = prove_compact(COMPACT_TAG, &instance, &witness).unwrap();
    verify_compact(COMPACT_TAG, &instance, &compact).unwrap();

    let composed = ComposedInstance::and([instance.clone(), instance]).unwrap();
    let witness = ComposedWitness::and([witness.clone(), witness]);
    let batchable = prove_batchable(BATCH_TAG, &composed, &witness).unwrap();
    verify_batchable(BATCH_TAG, &composed, &batchable).unwrap();
    let compact = prove_compact(COMPACT_TAG, &composed, &witness).unwrap();
    verify_compact(COMPACT_TAG, &composed, &compact).unwrap();
}

fn assert_serializers_append<P: NargCodec>(
    instance: &P,
    commitment: &P::Commitment,
    response: &P::Response,
) {
    let commitment_bytes = instance.serialize_commitment(commitment);
    let response_bytes = instance.serialize_response(response);
    let prefix = b"existing bytes";
    let mut out = Vec::with_capacity(prefix.len() + commitment_bytes.len() + response_bytes.len());
    out.extend_from_slice(prefix);
    let pointer = out.as_ptr();
    let capacity = out.capacity();

    instance.serialize_commitment_into(commitment, &mut out);
    instance.serialize_response_into(response, &mut out);
    assert_eq!(
        out,
        [prefix.as_slice(), &commitment_bytes, &response_bytes].concat()
    );
    assert_eq!(out.as_ptr(), pointer);
    assert_eq!(out.capacity(), capacity);

    // Parse exactly one commitment and one response from a shared buffer.
    let mut reader = NargReader::new(&out[prefix.len()..]);
    let decoded_commitment = instance.deserialize_commitment(&mut reader).unwrap();
    let decoded_response = instance.deserialize_response(&mut reader).unwrap();
    assert!(reader.is_empty());
    assert_eq!(
        instance.serialize_commitment(&decoded_commitment),
        commitment_bytes
    );
    assert_eq!(
        instance.serialize_response(&decoded_response),
        response_bytes
    );

    // Clearing permits reuse for a different message without retaining bytes.
    out.clear();
    instance.serialize_response_into(response, &mut out);
    assert_eq!(out, response_bytes);
    assert_eq!(out.as_ptr(), pointer);
}

#[test]
fn external_codec_serializers_append_to_a_reusable_buffer() {
    let relation = ExternalCodec {
        attempts: Cell::new(0),
        commitment: G::generator(),
    };
    assert_serializers_append(&relation, &G::generator(), &Scalar::from(42u64));
}

#[test]
fn built_in_codecs_append_to_a_reusable_buffer() {
    let mut builder = LinearRelation::<G>::new();
    let x = builder.allocate_scalar();
    let witness = vec![Scalar::from(42u64)];
    builder.allocate_eq_with(G::generator() * witness[0], x * builder.generator());
    let instance = builder.compile().unwrap();
    let mut rng = ProverRng::from_seed([7u8; 32]);
    let (commitment, state) = instance.prover_commit(&witness, &mut rng).unwrap();
    let response = instance
        .prover_response(state, &Scalar::from(5u64))
        .unwrap();
    assert_serializers_append(&instance, &commitment, &response);

    let composed = ComposedInstance::or([instance.clone(), instance]).unwrap();
    let witness = ComposedWitness::or([witness.clone(), witness]);
    let (commitment, state) = composed.prover_commit(&witness, &mut rng).unwrap();
    let response = composed
        .prover_response(state, &Scalar::from(5u64))
        .unwrap();
    assert_serializers_append(&composed, &commitment, &response);
}
