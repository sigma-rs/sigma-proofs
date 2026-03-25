use bls12_381::G1Projective as Bls12381G1;
use group::{ff::PrimeField, prime::PrimeGroup};
use p256::ProjectivePoint as P256ProjectivePoint;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::{
    linear_relation::CanonicalLinearRelation, traits::SigmaProtocol, DuplexSpongeInterface,
    MultiScalarMul, Nizk, ShakeDuplexSponge,
};

mod spec;
use spec::{rng::MockScalarRng, vectors::TestVector};

#[test]
fn test_spec_vectors_p256() {
    testvectors::<P256ProjectivePoint>(include_str!(
        "./spec/testdata/sigma-proofs_Shake128_P256.json"
    ));
}

#[test]
fn test_spec_vectors_bls12381() {
    testvectors::<Bls12381G1>(include_str!(
        "./spec/testdata/sigma-proofs_Shake128_BLS12381.json"
    ));
}

fn deserialize_messages<T: NargDeserialize>(len: usize, buf: &mut &[u8]) -> Vec<T> {
    (0..len)
        .map(|_| T::deserialize_from_narg(buf).expect("failed to deserialize message"))
        .collect()
}

fn decode_scalars<G>(bytes: &[u8]) -> Vec<G::Scalar>
where
    G: PrimeGroup,
    G::Scalar: NargDeserialize,
{
    let mut cursor = bytes;
    let mut scalars = Vec::new();
    while !cursor.is_empty() {
        scalars.push(
            G::Scalar::deserialize_from_narg(&mut cursor).expect("failed to deserialize scalar"),
        );
    }
    scalars
}

fn scalar_bytes<F: PrimeField>(scalar: &F) -> Vec<u8> {
    scalar.to_repr().as_ref().to_vec()
}

fn recover_nonces<G>(
    witness: &[G::Scalar],
    challenge: &G::Scalar,
    responses: &[G::Scalar],
) -> Vec<Vec<u8>>
where
    G: PrimeGroup,
{
    responses
        .iter()
        .zip(witness.iter())
        .map(|(response, witness)| scalar_bytes(&(*response - (*witness * *challenge))))
        .collect()
}

fn padded_identifier(value: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..value.len()].copy_from_slice(value.as_bytes());
    out
}

fn derive_session_id(session: &[u8]) -> [u8; 64] {
    let mut session_state = ShakeDuplexSponge::new(padded_identifier("fiat-shamir/session-id"));
    session_state.absorb(session);

    let mut session_id = [0u8; 64];
    session_id[32..].copy_from_slice(&session_state.squeeze(32));
    session_id
}

fn derive_batchable_challenge<G>(nizk: &Nizk<CanonicalLinearRelation<G>>, proof: &[u8]) -> G::Scalar
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let instance_label = nizk.interactive_proof.instance_label();
    let mut cursor = proof;
    let _commitments =
        deserialize_messages::<G>(nizk.interactive_proof.commitment_len(), &mut cursor);
    let commitment_bytes_len = proof.len().saturating_sub(cursor.len());

    let mut sponge = ShakeDuplexSponge::new(nizk.interactive_proof.protocol_identifier());
    sponge.absorb(&derive_session_id(&nizk.session_id));
    sponge.absorb(instance_label.as_ref());

    let mut repr = <G::Scalar as Decoding<[u8]>>::Repr::default();
    sponge.absorb(&proof[..commitment_bytes_len]);
    let challenge_bytes = sponge.squeeze(repr.as_mut().len());
    repr.as_mut().copy_from_slice(&challenge_bytes);
    G::Scalar::decode(repr)
}

fn testvectors<G>(vectors_json: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Encoding<[u8]> + NargSerialize + NargDeserialize + Decoding<[u8]>,
{
    let test_vectors: Vec<TestVector> = serde_json::from_str(vectors_json)
        .map_err(|e| format!("JSON parsing error: {e}"))
        .unwrap();

    for vector in test_vectors {
        let test_name = vector.relation;
        let parsed_instance = CanonicalLinearRelation::<G>::from_label(&vector.statement.0)
            .expect("failed to parse statement");

        assert_eq!(
            parsed_instance.protocol_identifier(),
            padded_identifier(&vector.ciphersuite),
            "protocol identifier mismatch for {test_name}"
        );

        let witness = decode_scalars::<G>(&vector.witness.0);
        assert_eq!(
            witness.len(),
            parsed_instance.num_scalars,
            "witness length doesn't match instance scalars",
        );

        assert_eq!(
            parsed_instance.label(),
            vector.statement.0,
            "parsed statement doesn't match original for {test_name}"
        );

        let nizk = Nizk::new(&vector.session_id.0, parsed_instance);

        assert!(
            nizk.verify_batchable(&vector.batchable_proof.0).is_ok(),
            "batchable proof from vectors did not verify for {test_name}"
        );
        assert!(
            nizk.verify_compact(&vector.proof.0).is_ok(),
            "compact proof from vectors did not verify for {test_name}"
        );

        let mut compact_cursor = vector.proof.0.as_slice();
        let compact_challenge =
            G::Scalar::deserialize_from_narg(&mut compact_cursor).expect("missing challenge");
        let compact_responses = deserialize_messages::<G::Scalar>(
            nizk.interactive_proof.response_len(),
            &mut compact_cursor,
        );
        assert!(
            compact_cursor.is_empty(),
            "unexpected trailing bytes in compact proof for {test_name}"
        );
        let compact_nonces = recover_nonces::<G>(&witness, &compact_challenge, &compact_responses);
        let mut compact_rng = MockScalarRng(compact_nonces.into_iter());
        let compact_proof = nizk.prove_compact(&witness, &mut compact_rng).unwrap();
        assert_eq!(
            compact_proof, vector.proof.0,
            "compact proof bytes do not match for {test_name}"
        );

        let mut batchable_cursor = vector.batchable_proof.0.as_slice();
        let _commitments = deserialize_messages::<G>(
            nizk.interactive_proof.commitment_len(),
            &mut batchable_cursor,
        );
        let batchable_responses = deserialize_messages::<G::Scalar>(
            nizk.interactive_proof.response_len(),
            &mut batchable_cursor,
        );
        assert!(
            batchable_cursor.is_empty(),
            "unexpected trailing bytes in batchable proof for {test_name}"
        );
        let batchable_challenge = derive_batchable_challenge::<G>(&nizk, &vector.batchable_proof.0);
        let batchable_nonces =
            recover_nonces::<G>(&witness, &batchable_challenge, &batchable_responses);
        let mut batchable_rng = MockScalarRng(batchable_nonces.into_iter());
        let batchable_proof = nizk.prove_batchable(&witness, &mut batchable_rng).unwrap();
        assert_eq!(
            batchable_proof, vector.batchable_proof.0,
            "batchable proof bytes do not match for {test_name}"
        );
    }
}
