use core::cell::Cell;

use curve25519_dalek::{RistrettoPoint as G, Scalar};
use group::Group;
use sigma_proofs::codec::{GroupCodec, ScalarCodec};
use sigma_proofs::composition::{ComposedInstance, ComposedWitness};
use sigma_proofs::errors::{InvalidWitness, VerificationError};
use sigma_proofs::traits::SigmaProtocol;
use sigma_proofs::{
    derive_session_id, prove_batchable_with, verify_batchable, DefaultHash, DuplexSpongeInit,
    LinearRelation, NargCodec, PrivateRng, ProverRng,
};
use spongefish::NargReader;

/// An external codec whose first commitment cannot appear on the wire. This
/// pins both extension-trait usability and prover-side rejection sampling.
struct RetryCodec {
    attempts: Cell<u8>,
}

impl SigmaProtocol for RetryCodec {
    type Commitment = G;
    type Challenge = Scalar;
    type Response = Scalar;
    type ProverState = ();
    type Witness = ();

    fn prover_commit(
        &self,
        _witness: &Self::Witness,
        _rng: &mut PrivateRng<impl DuplexSpongeInit<U = u8>>,
    ) -> core::result::Result<(Self::Commitment, Self::ProverState), InvalidWitness> {
        let attempt = self.attempts.get();
        self.attempts.set(attempt + 1);
        let commitment = match attempt {
            0 => G::identity(),
            _ => G::generator(),
        };
        Ok((commitment, ()))
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
        b"retry-codec"
    }
}

impl NargCodec for RetryCodec {
    fn is_valid_commitment(&self, commitment: &Self::Commitment) -> bool {
        !bool::from(commitment.is_identity())
    }

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

#[test]
fn an_invalid_commitment_is_resampled_without_becoming_an_api_error() {
    const TAG: &[u8] = b"external retry codec DSFS";
    let relation = RetryCodec {
        attempts: Cell::new(0),
    };
    let mut rng = ProverRng::from_seed([7u8; 32]);

    let session_id = derive_session_id::<DefaultHash>(TAG);
    let proof =
        prove_batchable_with::<DefaultHash, _>(&session_id, &relation, &(), &mut rng).unwrap();

    assert_eq!(relation.attempts.get(), 2);
    verify_batchable(TAG, &relation, &proof).unwrap();
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
    let relation = RetryCodec {
        attempts: Cell::new(1),
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
