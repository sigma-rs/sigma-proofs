use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};

use crate::{
    deserialize_scalar, serialize_scalar, ProofError, SchnorrProtocol, SigmaProtocol,
    SigmaProtocolSimulator,
};

#[derive(Default)]
pub struct AndProtocol<G: Group + GroupEncoding>(pub Vec<SchnorrProtocol<G>>);

impl<G: Group + GroupEncoding> AndProtocol<G> {
    pub fn new() -> Self {
        AndProtocol(Vec::<SchnorrProtocol<G>>::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn append_protocol(&mut self, protocol: SchnorrProtocol<G>) {
        self.0.push(protocol);
    }
}

impl<G: Group + GroupEncoding> SigmaProtocol for AndProtocol<G> {
    type Commitment = Vec<G>;
    type ProverState = Vec<(Vec<<G as Group>::Scalar>, Vec<<G as Group>::Scalar>)>;
    type Response = Vec<<G as Group>::Scalar>;
    type Witness = Vec<<G as Group>::Scalar>;
    type Challenge = <G as Group>::Scalar;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), ProofError> {
        let expected_w_len: usize = self.0.iter().map(|p| p.scalars_nb()).sum();
        if expected_w_len != witness.len() || self.is_empty() {
            return Err(ProofError::Other);
        }

        let mut cursor = 0;
        let mut commitment = Vec::with_capacity(self.0.iter().map(|p| p.statements_nb()).sum());
        let mut state = Vec::with_capacity(self.len());

        for proto in &self.0 {
            let n = proto.scalars_nb();
            let proto_witness = witness[cursor..(cursor + n)].to_vec();
            let (proto_commit, proto_state) = proto.prover_commit(&proto_witness, rng)?;
            commitment.extend(proto_commit);
            state.push(proto_state);
            cursor += n;
        }
        Ok((commitment, state))
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, ProofError> {
        if state.len() != self.len() {
            return Err(ProofError::Other);
        }

        let mut response = Vec::with_capacity(self.0.iter().map(|p| p.scalars_nb()).sum());
        for (proto, proto_state) in self.0.iter().zip(state) {
            let proto_response = proto.prover_response(proto_state, challenge)?;
            response.extend(proto_response);
        }
        Ok(response)
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ProofError> {
        let expected_c_len: usize = self.0.iter().map(|p| p.statements_nb()).sum();
        let expected_r_len: usize = self.0.iter().map(|p| p.scalars_nb()).sum();
        if commitment.len() != expected_c_len || response.len() != expected_r_len {
            return Err(ProofError::Other);
        }

        let mut c_cursor = 0;
        let mut r_cursor = 0;
        for proto in &self.0 {
            let c_len = proto.statements_nb();
            let r_len = proto.scalars_nb();

            let proto_commit = commitment[c_cursor..(c_cursor + c_len)].to_vec();
            let proto_resp = response[r_cursor..(r_cursor + r_len)].to_vec();

            proto.verifier(&proto_commit, challenge, &proto_resp)?;

            c_cursor += c_len;
            r_cursor += r_len
        }
        Ok(())
    }

    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, ProofError> {
        let expected_c_len: usize = self.0.iter().map(|p| p.statements_nb()).sum();
        let expected_r_len: usize = self.0.iter().map(|p| p.scalars_nb()).sum();
        if commitment.len() != expected_c_len || response.len() != expected_r_len {
            return Err(ProofError::Other);
        }

        let mut bytes = Vec::new();
        let mut c_cursor = 0;
        let mut r_cursor = 0;
        for proto in &self.0 {
            let c_len = proto.statements_nb();
            let r_len = proto.scalars_nb();

            let proto_commit = commitment[c_cursor..(c_cursor + c_len)].to_vec();
            let proto_resp = response[r_cursor..(r_cursor + r_len)].to_vec();

            bytes.extend(proto.serialize_batchable(&proto_commit, challenge, &proto_resp)?);

            c_cursor += c_len;
            r_cursor += r_len;
        }
        Ok(bytes)
    }

    fn deserialize_batchable(
        &self,
        data: &[u8],
    ) -> Result<(Self::Commitment, Self::Response), ProofError> {
        let mut cursor = 0;
        let mut commitment = Vec::with_capacity(self.0.iter().map(|p| p.statements_nb()).sum());
        let mut response = Vec::with_capacity(self.0.iter().map(|p| p.scalars_nb()).sum());

        let point_size = G::generator().to_bytes().as_ref().len();
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        for proto in &self.0 {
            let c_nb = proto.statements_nb();
            let r_nb = proto.scalars_nb();
            let proof_len = r_nb * scalar_size + c_nb * point_size;
            let (proto_commit, proto_resp) =
                proto.deserialize_batchable(&data[cursor..(cursor + proof_len)])?;
            commitment.extend(proto_commit);
            response.extend(proto_resp);
            cursor += proof_len;
        }
        Ok((commitment, response))
    }
}

#[derive(Default)]
pub struct OrProtocol<G: Group + GroupEncoding>(pub Vec<SchnorrProtocol<G>>);

pub struct Transcript<G: Group> {
    challenge: <G as Group>::Scalar,
    response: Vec<<G as Group>::Scalar>,
}

impl<G: Group + GroupEncoding> OrProtocol<G> {
    pub fn new() -> Self {
        OrProtocol(Vec::<SchnorrProtocol<G>>::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn append_protocol(&mut self, protocol: SchnorrProtocol<G>) {
        self.0.push(protocol);
    }
}

impl<G: Group + GroupEncoding> SigmaProtocol for OrProtocol<G> {
    type Commitment = Vec<G>; // Vec(commitment)
    type ProverState = (
        usize,
        (Vec<<G as Group>::Scalar>, Vec<<G as Group>::Scalar>),
        Vec<Transcript<G>>,
    ); // ( real_index, ( real_nonce, real_witness ), Vec( fake_transcriptions = (challenge, resp) ) )
    type Response = (Vec<<G as Group>::Scalar>, Vec<<G as Group>::Scalar>); // Vec(challenge, response)
    type Witness = (usize, Vec<<G as Group>::Scalar>); // (real_index, real_witness)
    type Challenge = <G as Group>::Scalar; // Challenge

    #[warn(clippy::type_complexity)]
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), ProofError> {
        let real_index = witness.0;
        let expected_w_len = self.0[real_index].scalars_nb();
        if real_index >= self.len() || witness.1.len() != expected_w_len {
            return Err(ProofError::Other);
        }

        let mut fake_transcripts = Vec::with_capacity(self.len() - 1);
        let mut commitment = Vec::with_capacity(self.0.iter().map(|p| p.statements_nb()).sum());
        let (real_commit, real_state) = self.0[real_index].prover_commit(&witness.1, rng)?;
        for (i, proto) in self.0.iter().enumerate() {
            if i != real_index {
                let (commit, challenge, resp) = proto.simulate_transcript(rng);
                fake_transcripts.push(Transcript {
                    challenge,
                    response: resp,
                });
                commitment.extend(commit);
            } else {
                commitment.extend(&real_commit);
            }
        }
        Ok((commitment, (real_index, real_state, fake_transcripts)))
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, ProofError> {
        let (real_index, real_state, fake_transcripts) = state;
        let mut response = (
            Vec::with_capacity(self.len()),
            Vec::with_capacity(self.0.iter().map(|p| p.scalars_nb()).sum()),
        );

        let mut real_challenge = *challenge;
        for transcript in &fake_transcripts {
            real_challenge -= transcript.challenge;
        }
        let real_response = self.0[real_index].prover_response(real_state, &real_challenge)?;

        for (i, _) in self.0.iter().enumerate() {
            if i == real_index {
                response.0.push(real_challenge);
                response.1.extend(&real_response);
            } else {
                let fake_index = if i < real_index { i } else { i - 1 };
                let transcript = &fake_transcripts[fake_index];
                response.0.push(transcript.challenge);
                response.1.extend(&transcript.response);
            }
        }
        Ok(response)
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ProofError> {
        let expected_c_len: usize = self.0.iter().map(|p| p.statements_nb()).sum();
        let expected_ch_nb = self.len();
        let expected_r_len: usize = self.0.iter().map(|p| p.scalars_nb()).sum();
        if commitment.len() != expected_c_len
            || response.0.len() != expected_ch_nb
            || response.1.len() != expected_r_len
        {
            return Err(ProofError::Other);
        }

        let mut expected_difference = *challenge;
        let mut c_cursor = 0;
        let mut r_cursor = 0;
        for (i, proto) in self.0.iter().enumerate() {
            let c_len = proto.statements_nb();
            let r_len = proto.scalars_nb();
            let proto_commit = commitment[c_cursor..(c_cursor + c_len)].to_vec();
            let proto_resp = response.1[r_cursor..(r_cursor + r_len)].to_vec();
            proto.verifier(&proto_commit, &response.0[i], &proto_resp)?;
            c_cursor += c_len;
            r_cursor += r_len;

            expected_difference -= response.0[i];
        }
        match expected_difference.is_zero_vartime() {
            true => Ok(()),
            false => Err(ProofError::VerificationFailure),
        }
    }

    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, ProofError> {
        let expected_c_len: usize = self.0.iter().map(|p| p.statements_nb()).sum();
        let expected_ch_nb = self.len();
        let expected_r_len: usize = self.0.iter().map(|p| p.scalars_nb()).sum();
        if commitment.len() != expected_c_len
            || response.0.len() != expected_ch_nb
            || response.1.len() != expected_r_len
        {
            return Err(ProofError::Other);
        }

        let mut bytes = Vec::new();
        let mut c_cursor = 0;
        let mut r_cursor = 0;

        for (i, proto) in self.0.iter().enumerate() {
            let c_len = proto.statements_nb();
            let r_len = proto.scalars_nb();

            let proto_commit = commitment[c_cursor..(c_cursor + c_len)].to_vec();
            let proto_resp = response.1[r_cursor..(r_cursor + r_len)].to_vec();
            bytes.extend(proto.serialize_batchable(&proto_commit, &response.0[i], &proto_resp)?);
            bytes.extend(&serialize_scalar::<G>(&response.0[i]));
            c_cursor += c_len;
            r_cursor += r_len;
        }
        Ok(bytes)
    }

    fn deserialize_batchable(
        &self,
        data: &[u8],
    ) -> Result<(Self::Commitment, Self::Response), ProofError> {
        let point_size = G::generator().to_bytes().as_ref().len();
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        let expected_d_len: usize = self
            .0
            .iter()
            .map(|p| (p.scalars_nb() + 1) * scalar_size + p.statements_nb() * point_size)
            .sum();
        if data.len() != expected_d_len {
            return Err(ProofError::ProofSizeMismatch);
        }

        let mut cursor = 0;
        let mut commitment = Vec::with_capacity(self.0.iter().map(|p| p.statements_nb()).sum());
        let mut response = (
            Vec::with_capacity(self.len()),
            Vec::with_capacity(self.0.iter().map(|p| p.scalars_nb()).sum()),
        );

        for proto in &self.0 {
            let c_nb = proto.statements_nb();
            let r_nb = proto.scalars_nb();
            let proof_len = r_nb * scalar_size + c_nb * point_size;
            let (proto_commit, proto_resp) =
                proto.deserialize_batchable(&data[cursor..(cursor + proof_len)])?;
            let proto_challenge = deserialize_scalar::<G>(
                &data[(cursor + proof_len)..(cursor + proof_len + scalar_size)],
            )
            .unwrap();
            commitment.extend(proto_commit);
            response.1.extend(proto_resp);
            response.0.push(proto_challenge);

            cursor += proof_len + scalar_size;
        }
        Ok((commitment, response))
    }
}
