use core::cell::Cell;

use curve25519_dalek::{RistrettoPoint as G, Scalar};
use group::Group;
use sigma_proofs::codec::{GroupCodec, ScalarCodec};
use sigma_proofs::errors::{InvalidWitness, VerificationResult};
use sigma_proofs::traits::SigmaProtocol;
use sigma_proofs::{
    derive_session_id, prove_batchable_with, verify_batchable, DuplexSpongeInit, NargCodec,
    PrivateRng, ProverRng, StdHash,
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
    ) -> VerificationResult<()> {
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

    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8> {
        let mut out = Vec::new();
        commitment.serialize_element_allowing_identity(&mut out);
        out
    }

    fn serialize_response(&self, response: &Self::Response) -> Vec<u8> {
        let mut out = Vec::new();
        response.serialize_scalar(&mut out);
        out
    }

    fn deserialize_commitment(
        &self,
        reader: &mut NargReader<'_>,
    ) -> VerificationResult<Self::Commitment> {
        G::deserialize_element(reader)
    }

    fn deserialize_response(
        &self,
        reader: &mut NargReader<'_>,
    ) -> VerificationResult<Self::Response> {
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

    let session_id = derive_session_id::<StdHash>(TAG);
    let proof = prove_batchable_with::<StdHash, _>(&session_id, &relation, &(), &mut rng).unwrap();

    assert_eq!(relation.attempts.get(), 2);
    verify_batchable(TAG, &relation, &proof).unwrap();
}
