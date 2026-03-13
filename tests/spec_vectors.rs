use bls12_381::G1Projective as BLS12381_Group;
use ff::PrimeField;
use group::prime::PrimeGroup;
use num_bigint::BigUint;
use num_traits::Num;
use p256::ProjectivePoint as P256_Group;
use rand::thread_rng;
use spongefish::{Codec, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::errors::Error;
use sigma_proofs::traits::{SigmaProtocol, SigmaProtocolSimulator, CSRNG};
use sigma_proofs::{
    linear_relation::CanonicalLinearRelation, DuplexSpongeInterface, MultiScalarMul,
    ShakeDuplexSponge,
};

mod spec;
use spec::{read_vector_file, vectors::TestVector};

#[test]
fn test_spec_testvectors_bls12381() {
    testvectors::<BLS12381_Group>("sigma-proofs_Shake128_BLS12381.json");
}

#[test]
fn test_spec_testvectors_p256() {
    testvectors::<P256_Group>("sigma-proofs_Shake128_P256.json");
}

fn decode_witness<G>(bytes: &[u8]) -> Vec<G::Scalar>
where
    G: PrimeGroup,
    G::Scalar: Codec,
{
    let mut witness = Vec::new();
    let mut cursor = bytes;
    while !cursor.is_empty() {
        witness.push(G::Scalar::deserialize_from_narg(&mut cursor).unwrap());
    }
    witness
}

fn poc_protocol_identifier(ciphersuite: &str) -> [u8; 64] {
    let mut protocol_id = [0u8; 64];
    let bytes = ciphersuite.as_bytes();
    assert!(bytes.len() <= protocol_id.len());
    protocol_id[..bytes.len()].copy_from_slice(bytes);
    protocol_id
}

fn poc_session_id(session_identifier: &[u8]) -> [u8; 64] {
    let mut protocol_id = [0u8; 64];
    let session_domain = b"fiat-shamir/session-id";
    protocol_id[..session_domain.len()].copy_from_slice(session_domain);

    let mut sponge = ShakeDuplexSponge::new(protocol_id);
    sponge.absorb(session_identifier);

    let mut session_id = [0u8; 64];
    session_id[32..].copy_from_slice(&sponge.squeeze(32));
    session_id
}

fn initialize_poc_sponge(
    ciphersuite: &str,
    session_identifier: &[u8],
    instance_label: &[u8],
) -> ShakeDuplexSponge {
    let mut sponge = ShakeDuplexSponge::new(poc_protocol_identifier(ciphersuite));
    sponge.absorb(&poc_session_id(session_identifier));
    sponge.absorb(instance_label);
    sponge
}

fn derive_challenge<F: PrimeField>(sponge: &mut ShakeDuplexSponge) -> F {
    let scalar_byte_length = (F::NUM_BITS as usize).div_ceil(8);
    let uniform_bytes = sponge.squeeze(scalar_byte_length + 16);
    let scalar = BigUint::from_bytes_be(&uniform_bytes);
    let mut order_str = F::MODULUS;
    if order_str.starts_with("0x") {
        order_str = &order_str[2..];
    }
    let order = BigUint::from_str_radix(order_str, 16).unwrap();
    let reduced = scalar % order;
    F::from_str_vartime(&reduced.to_string()).unwrap()
}

fn serialize_messages_into<T: NargSerialize>(messages: &[T], out: &mut Vec<u8>) {
    for message in messages {
        message.serialize_into_narg(out);
    }
}

fn serialize_messages<T: NargSerialize>(messages: &[T]) -> Vec<u8> {
    let mut out = Vec::new();
    serialize_messages_into(messages, &mut out);
    out
}

fn deserialize_messages<T: NargDeserialize>(len: usize, buf: &mut &[u8]) -> Result<Vec<T>, Error> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(T::deserialize_from_narg(buf).map_err(|_| Error::VerificationFailure)?);
    }
    Ok(out)
}

fn verify_batchable_poc<P>(
    protocol: &P,
    ciphersuite: &str,
    session_identifier: &[u8],
    proof: &[u8],
) -> Result<(), Error>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq + PrimeField,
    P::Commitment: NargSerialize + NargDeserialize + Encoding,
    P::Response: NargSerialize + NargDeserialize + Encoding,
{
    let instance_label = protocol.instance_label();
    let mut cursor = proof;
    let commitment = deserialize_messages(protocol.commitment_len(), &mut cursor)?;
    let commitment_bytes_len = proof.len().saturating_sub(cursor.len());
    let mut sponge =
        initialize_poc_sponge(ciphersuite, session_identifier, instance_label.as_ref());
    sponge.absorb(&proof[..commitment_bytes_len]);
    let challenge = derive_challenge::<P::Challenge>(&mut sponge);
    let response = deserialize_messages(protocol.response_len(), &mut cursor)?;
    if !cursor.is_empty() {
        return Err(Error::VerificationFailure);
    }
    protocol.verifier(&commitment, &challenge, &response)
}

fn verify_compact_poc<P>(
    protocol: &P,
    ciphersuite: &str,
    session_identifier: &[u8],
    proof: &[u8],
) -> Result<(), Error>
where
    P: SigmaProtocol + SigmaProtocolSimulator,
    P::Challenge: PartialEq + NargDeserialize + PrimeField,
    P::Commitment: NargSerialize + NargDeserialize + Encoding,
    P::Response: NargSerialize + NargDeserialize + Encoding,
{
    let instance_label = protocol.instance_label();
    let mut cursor = proof;
    let challenge =
        P::Challenge::deserialize_from_narg(&mut cursor).map_err(|_| Error::VerificationFailure)?;
    let response = deserialize_messages(protocol.response_len(), &mut cursor)?;
    if !cursor.is_empty() {
        return Err(Error::VerificationFailure);
    }

    let commitment = protocol.simulate_commitment(&challenge, &response)?;
    let mut sponge =
        initialize_poc_sponge(ciphersuite, session_identifier, instance_label.as_ref());
    sponge.absorb(&serialize_messages(&commitment));
    let expected_challenge = derive_challenge::<P::Challenge>(&mut sponge);
    if challenge != expected_challenge {
        return Err(Error::VerificationFailure);
    }

    Ok(())
}

fn prove_batchable_poc<P>(
    protocol: &P,
    ciphersuite: &str,
    session_identifier: &[u8],
    witness: &P::Witness,
    rng: &mut impl CSRNG,
) -> Result<Vec<u8>, Error>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq + PrimeField,
    P::Commitment: NargSerialize + NargDeserialize + Encoding,
    P::Response: NargSerialize + NargDeserialize + Encoding,
{
    let instance_label = protocol.instance_label();
    let mut sponge =
        initialize_poc_sponge(ciphersuite, session_identifier, instance_label.as_ref());
    let (commitment, prover_state) = protocol.prover_commit(witness, rng)?;
    let commitment_bytes = serialize_messages(&commitment);
    sponge.absorb(&commitment_bytes);
    let challenge = derive_challenge::<P::Challenge>(&mut sponge);
    let response = protocol.prover_response(prover_state, &challenge)?;
    let mut proof = commitment_bytes;
    serialize_messages_into(&response, &mut proof);
    Ok(proof)
}

fn prove_compact_poc<P>(
    protocol: &P,
    ciphersuite: &str,
    session_identifier: &[u8],
    witness: &P::Witness,
    rng: &mut impl CSRNG,
) -> Result<Vec<u8>, Error>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq + PrimeField + NargSerialize,
    P::Commitment: NargSerialize + NargDeserialize + Encoding,
    P::Response: NargSerialize + NargDeserialize + Encoding,
{
    let instance_label = protocol.instance_label();
    let mut sponge =
        initialize_poc_sponge(ciphersuite, session_identifier, instance_label.as_ref());
    let (commitment, prover_state) = protocol.prover_commit(witness, rng)?;
    sponge.absorb(&serialize_messages(&commitment));
    let challenge = derive_challenge::<P::Challenge>(&mut sponge);
    let response = protocol.prover_response(prover_state, &challenge)?;

    let mut proof = Vec::new();
    challenge.serialize_into_narg(&mut proof);
    serialize_messages_into(&response, &mut proof);
    Ok(proof)
}

fn testvectors<G>(file_name: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Codec,
{
    let vectors_json = read_vector_file(file_name);
    let test_vectors: Vec<TestVector> = serde_json::from_str(&vectors_json)
        .map_err(|e| format!("JSON parsing error: {e}"))
        .unwrap();

    for vector in test_vectors {
        let test_name = vector.relation;
        // Parse the statement from the test vector
        let parsed_instance = CanonicalLinearRelation::<G>::from_label(&vector.statement.0)
            .expect("Failed to parse statement");

        // Decode the witness from the test vector
        let witness = decode_witness::<G>(&vector.witness.0);
        assert_eq!(
            witness.len(),
            parsed_instance.num_scalars,
            "witness length doesn't match instance scalars"
        );

        // Verify the parsed instance can be re-serialized to the same label
        assert_eq!(
            parsed_instance.label(),
            vector.statement.0,
            "parsed statement doesn't match original for {test_name}"
        );

        let verification_result = verify_batchable_poc(
            &parsed_instance,
            &vector.ciphersuite,
            &vector.session_id.0,
            &vector.batchable_proof.0,
        );
        assert!(
            verification_result.is_ok(),
            "batchable proof from vectors did not verify for {test_name}: {verification_result:?}"
        );

        let verification_result = verify_compact_poc(
            &parsed_instance,
            &vector.ciphersuite,
            &vector.session_id.0,
            &vector.proof.0,
        );
        assert!(
            verification_result.is_ok(),
            "compact proof from vectors did not verify for {test_name}: {verification_result:?}"
        );

        let mut rng = thread_rng();
        let proof_batchable = prove_batchable_poc(
            &parsed_instance,
            &vector.ciphersuite,
            &vector.session_id.0,
            &witness,
            &mut rng,
        )
        .unwrap();
        assert!(
            verify_batchable_poc(
                &parsed_instance,
                &vector.ciphersuite,
                &vector.session_id.0,
                &proof_batchable
            )
            .is_ok(),
            "locally generated batchable proof verification failed for {test_name}"
        );

        let proof_compact = prove_compact_poc(
            &parsed_instance,
            &vector.ciphersuite,
            &vector.session_id.0,
            &witness,
            &mut rng,
        )
        .unwrap();
        assert!(
            verify_compact_poc(
                &parsed_instance,
                &vector.ciphersuite,
                &vector.session_id.0,
                &proof_compact
            )
            .is_ok(),
            "locally generated compact proof verification failed for {test_name}"
        );
    }
}
