use ff::PrimeField;
use group::{Group, GroupEncoding};

use crate::{
    deserialize_scalar, serialize_scalar, ProofError, SchnorrProtocol, SigmaProtocol,
    SigmaProtocolSimulator,
};

pub struct AndProtocol<G: Group + GroupEncoding>(pub Vec<SchnorrProtocol<G>>);

impl<G: Group + GroupEncoding> Default for AndProtocol<G> {
    fn default() -> Self {
        Self::new()
    }
}

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
        let mut commitment = Vec::new();
        let mut state = Vec::new();
        let mut cursor = 0;

        for protocol in &self.0 {
            let witness_len = protocol.scalars_nb();
            let p_witness = &witness[cursor..(cursor + witness_len)];
            let (commit, pr_state) = protocol.prover_commit(&p_witness.to_vec(), rng)?;
            commitment.extend(commit);
            state.push(pr_state);

            cursor += witness_len;
        }
        Ok((commitment, state))
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, ProofError> {
        let mut response = Vec::new();
        for (i, protocol) in self.0.iter().enumerate() {
            let resp = protocol.prover_response(state[i].clone(), challenge)?;
            response.extend(resp);
        }
        Ok(response)
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ProofError> {
        let mut commit_cursor = 0;
        let mut resp_cursor = 0;

        for protocol in &self.0 {
            let commit_len = protocol.statements_nb();
            let resp_len = protocol.scalars_nb();

            let commit = &commitment[commit_cursor..(commit_cursor + commit_len)];
            let resp = &response[resp_cursor..(resp_cursor + resp_len)];

            protocol.verifier(&commit.to_vec(), challenge, &resp.to_vec())?;

            commit_cursor += commit_len;
            resp_cursor += resp_len
        }
        Ok(())
    }

    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, ProofError> {
        let mut bytes = Vec::new();
        let mut commit_cursor = 0;
        let mut resp_cursor = 0;

        for protocol in &self.0 {
            let commit_len = protocol.statements_nb();
            let resp_len = protocol.scalars_nb();

            let commit = &commitment[commit_cursor..(commit_cursor + commit_len)];
            let resp = &response[resp_cursor..(resp_cursor + resp_len)];
            bytes.extend_from_slice(&protocol.serialize_batchable(
                &commit.to_vec(),
                challenge,
                &resp.to_vec(),
            )?);
            commit_cursor += commit_len;
            resp_cursor += resp_len;
        }
        Ok(bytes)
    }

    fn deserialize_batchable(
        &self,
        data: &[u8],
    ) -> Result<(Self::Commitment, Self::Response), ProofError> {
        let mut commitment = Vec::new();
        let mut response = Vec::new();
        let mut cursor = 0;

        let point_size = G::generator().to_bytes().as_ref().len();
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        for protocol in &self.0 {
            let commit_nb = protocol.statements_nb();
            let response_nb = protocol.scalars_nb();
            let proof_len = response_nb * scalar_size + commit_nb * point_size;
            let (commit, resp) =
                protocol.deserialize_batchable(&data[cursor..(cursor + proof_len)])?;
            commitment.extend(commit);
            response.extend(resp);
            cursor += proof_len;
        }
        Ok((commitment, response))
    }
}

pub struct OrProtocol<G: Group + GroupEncoding>(pub Vec<SchnorrProtocol<G>>);

pub struct Transcript<G: Group> {
    challenge: <G as Group>::Scalar,
    response: Vec<<G as Group>::Scalar>,
}

impl<G: Group + GroupEncoding> Default for OrProtocol<G> {
    fn default() -> Self {
        Self::new()
    }
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
        if real_index >= self.len() {
            return Err(ProofError::Other);
        }

        let mut fake_transcripts = Vec::new();
        let mut commitment = Vec::new();
        let (real_commit, real_state) = self.0[real_index].prover_commit(&witness.1, rng)?;
        for (i, protocol) in self.0.iter().enumerate() {
            if i != real_index {
                let (commit, challenge, resp) = protocol.simulate_transcript(rng);
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
        let mut response = (Vec::new(), Vec::new());

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
        let mut expected_difference = *challenge;

        let mut commit_cursor = 0;
        let mut resp_cursor = 0;
        for (i, protocol) in self.0.iter().enumerate() {
            let commit_len = protocol.statements_nb();
            let resp_len = protocol.scalars_nb();
            let commit = &commitment[commit_cursor..(commit_cursor + commit_len)];
            let resp = &response.1[resp_cursor..(resp_cursor + resp_len)];
            protocol.verifier(&commit.to_vec(), &response.0[i], &resp.to_vec())?;
            commit_cursor += commit_len;
            resp_cursor += resp_len;

            expected_difference += response.0[i];
        }
        Ok(())
    }

    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, ProofError> {
        let mut bytes = Vec::new();
        let mut commit_cursor = 0;
        let mut resp_cursor = 0;

        for (i, protocol) in self.0.iter().enumerate() {
            let commit_len = protocol.statements_nb();
            let resp_len = protocol.scalars_nb();

            let commit = &commitment[commit_cursor..(commit_cursor + commit_len)];
            let resp = &response.1[resp_cursor..(resp_cursor + resp_len)];
            bytes.extend_from_slice(&protocol.serialize_batchable(
                &commit.to_vec(),
                &response.0[i],
                &resp.to_vec(),
            )?);
            bytes.extend_from_slice(&serialize_scalar::<G>(&response.0[i]));
            commit_cursor += commit_len;
            resp_cursor += resp_len;
        }
        Ok(bytes)
    }

    fn deserialize_batchable(
        &self,
        data: &[u8],
    ) -> Result<(Self::Commitment, Self::Response), ProofError> {
        let mut commitment = Vec::new();
        let mut response = (Vec::new(), Vec::new());
        let mut cursor = 0;

        let point_size = G::generator().to_bytes().as_ref().len();
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default()
            .as_ref()
            .len();

        for protocol in &self.0 {
            let commit_nb = protocol.statements_nb();
            let response_nb = protocol.scalars_nb();
            let proof_len = response_nb * scalar_size + commit_nb * point_size;
            let (commit, resp) =
                protocol.deserialize_batchable(&data[cursor..(cursor + proof_len)])?;
            let challenge = deserialize_scalar::<G>(
                &data[(cursor + proof_len)..(cursor + proof_len + scalar_size)],
            )
            .unwrap();
            commitment.extend(commit);
            response.1.extend(resp);
            response.0.push(challenge);

            cursor += proof_len + scalar_size;
        }
        Ok((commitment, response))
    }
}
