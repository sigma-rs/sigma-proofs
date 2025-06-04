use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};

use crate::codec::Codec;
use crate::{
    errors::Error, fiat_shamir::FiatShamir, group_serialization::{deserialize_scalar, serialize_scalar}, schnorr_protocol::SchnorrProtocol, traits::{SigmaProtocol, SigmaProtocolSimulator}
};

#[derive(Clone)]
pub enum Protocol<G: Group + GroupEncoding> {
    Simple(SchnorrProtocol<G>),
    And(Vec<Protocol<G>>),
    Or(Vec<Protocol<G>>),
}

/// Types associated

#[derive(Clone)]
pub enum ProtocolCommitment<G: Group + GroupEncoding> {
    Simple(<SchnorrProtocol<G> as SigmaProtocol>::Commitment),
    And(Vec<ProtocolCommitment<G>>),
    Or(Vec<ProtocolCommitment<G>>),
}

#[derive(Clone)]
pub enum ProtocolProverState<G: Group + GroupEncoding> {
    Simple(<SchnorrProtocol<G> as SigmaProtocol>::ProverState),
    And(Vec<ProtocolProverState<G>>),
    Or(
        usize,                                                 // real index
        Vec<ProtocolProverState<G>>,                           // real ProverState
        (Vec<ProtocolChallenge<G>>, Vec<ProtocolResponse<G>>), // fake transcripts
    ),
}

#[derive(Clone)]
pub enum ProtocolResponse<G: Group + GroupEncoding> {
    Simple(<SchnorrProtocol<G> as SigmaProtocol>::Response),
    And(Vec<ProtocolResponse<G>>),
    Or(Vec<ProtocolChallenge<G>>, Vec<ProtocolResponse<G>>),
}

pub enum ProtocolWitness<G: Group + GroupEncoding> {
    Simple(<SchnorrProtocol<G> as SigmaProtocol>::Witness),
    And(Vec<ProtocolWitness<G>>),
    Or(usize, Vec<ProtocolWitness<G>>),
}

type ProtocolChallenge<G> = <SchnorrProtocol<G> as SigmaProtocol>::Challenge;

impl<G: Group + GroupEncoding> SigmaProtocol for Protocol<G> {
    type Commitment = ProtocolCommitment<G>;
    type ProverState = ProtocolProverState<G>;
    type Response = ProtocolResponse<G>;
    type Witness = ProtocolWitness<G>;
    type Challenge = ProtocolChallenge<G>;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), Error> {
        match (self, witness) {
            (Protocol::Simple(p), ProtocolWitness::Simple(w)) => {
                let (c, s) = p.prover_commit(w, rng)?;
                Ok((
                    ProtocolCommitment::Simple(c),
                    ProtocolProverState::Simple(s),
                ))
            }
            (Protocol::And(ps), ProtocolWitness::And(ws)) => {
                if ps.len() != ws.len() {
                    return Err(Error::ProofSizeMismatch);
                }
                let mut commitments = Vec::with_capacity(ps.len());
                let mut prover_states = Vec::with_capacity(ps.len());

                for (p, w) in ps.iter().zip(ws.iter()) {
                    let (c, s) = p.prover_commit(w, rng)?;
                    commitments.push(c);
                    prover_states.push(s);
                }

                Ok((
                    ProtocolCommitment::And(commitments),
                    ProtocolProverState::And(prover_states),
                ))
            }
            (Protocol::Or(ps), ProtocolWitness::Or(w_index, w)) => {
                let mut commitments = Vec::with_capacity(ps.len());
                let mut fake_challenges = Vec::new();
                let mut fake_responses = Vec::new();
                let (real_commit, real_state) = ps[*w_index].prover_commit(&w[0], rng)?;
                for i in 0..ps.len() {
                    if i != *w_index {
                        let (c, ch, r) = ps[i].simulate_transcript(rng);
                        commitments.push(c);
                        fake_challenges.push(ch);
                        fake_responses.push(r);
                    } else {
                        commitments.push(real_commit.clone());
                    }
                }
                Ok((
                    ProtocolCommitment::Or(commitments),
                    ProtocolProverState::Or(
                        *w_index,
                        vec![real_state],
                        (fake_challenges, fake_responses),
                    ),
                ))
            }
            _ => panic!(),
        }
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, Error> {
        match (self, state) {
            (Protocol::Simple(p), ProtocolProverState::Simple(state)) => {
                let response = p.prover_response(state, challenge)?;
                Ok(ProtocolResponse::Simple(response))
            }
            (Protocol::And(ps), ProtocolProverState::And(states)) => {
                if ps.len() != states.len() {
                    return Err(Error::ProofSizeMismatch);
                }
                let mut responses = Vec::with_capacity(ps.len());
                for (i, p) in ps.iter().enumerate() {
                    let r = p.prover_response(states[i].clone(), challenge)?;
                    responses.push(r);
                }
                Ok(ProtocolResponse::And(responses))
            }
            (
                Protocol::Or(ps),
                ProtocolProverState::Or(w_index, real_state, (f_challenges, f_responses)),
            ) => {
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());

                let mut real_challenge = *challenge;
                for ch in &f_challenges {
                    real_challenge -= ch;
                }
                let real_response =
                    ps[w_index].prover_response(real_state[0].clone(), &real_challenge)?;

                for (i, _) in ps.iter().enumerate() {
                    if i == w_index {
                        challenges.push(real_challenge);
                        responses.push(real_response.clone());
                    } else {
                        let fake_index = if i < w_index { i } else { i - 1 };
                        challenges.push(f_challenges[fake_index]);
                        responses.push(f_responses[fake_index].clone());
                    }
                }
                Ok(ProtocolResponse::Or(challenges, responses))
            }
            _ => panic!(),
        }
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), Error> {
        match (self, commitment, response) {
            (Protocol::Simple(p), ProtocolCommitment::Simple(c), ProtocolResponse::Simple(r)) => {
                p.verifier(c, challenge, r)
            }
            (
                Protocol::And(ps),
                ProtocolCommitment::And(commitments),
                ProtocolResponse::And(responses),
            ) => {
                for (i, p) in ps.iter().enumerate() {
                    p.verifier(&commitments[i], challenge, &responses[i])?;
                }
                Ok(())
            }
            (
                Protocol::Or(ps),
                ProtocolCommitment::Or(commitments),
                ProtocolResponse::Or(challenges, responses),
            ) => {
                let mut expected_difference = *challenge;
                for (i, p) in ps.iter().enumerate() {
                    p.verifier(&commitments[i], &challenges[i], &responses[i])?;
                    expected_difference -= challenges[i];
                }
                match expected_difference.is_zero_vartime() {
                    true => Ok(()),
                    false => Err(Error::VerificationFailure),
                }
            }
            _ => panic!(),
        }
    }

    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, Error> {
        match (self, commitment, response) {
            (Protocol::Simple(p), ProtocolCommitment::Simple(c), ProtocolResponse::Simple(r)) => {
                p.serialize_batchable(c, challenge, r)
            }
            (
                Protocol::And(ps),
                ProtocolCommitment::And(commitments),
                ProtocolResponse::And(responses),
            ) => {
                let mut bytes = Vec::new();
                for (i, p) in ps.iter().enumerate() {
                    bytes.extend(p.serialize_batchable(
                        &commitments[i],
                        challenge,
                        &responses[i],
                    )?);
                }
                Ok(bytes)
            }
            (
                Protocol::Or(ps),
                ProtocolCommitment::Or(commitments),
                ProtocolResponse::Or(challenges, responses),
            ) => {
                let mut bytes = Vec::new();
                for (i, p) in ps.iter().enumerate() {
                    bytes.extend(p.serialize_batchable(
                        &commitments[i],
                        &challenges[i],
                        &responses[i],
                    )?);
                    bytes.extend(&serialize_scalar::<G>(&challenges[i]))
                }
                Ok(bytes)
            }
            _ => panic!(),
        }
    }

    fn deserialize_batchable(
        &self,
        data: &[u8],
    ) -> Result<(Self::Commitment, Self::Response), Error> {
        match self {
            Protocol::Simple(p) => {
                let (c, r) = p.deserialize_batchable(data)?;
                Ok((ProtocolCommitment::Simple(c), ProtocolResponse::Simple(r)))
            }
            Protocol::And(ps) => {
                let mut cursor = 0;
                let mut commitments = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());
                for p in ps {
                    let (p_commit, p_resp) = p.deserialize_batchable(&data[cursor..])?;
                    let serialized = p.serialize_batchable(
                        &p_commit,
                        &p.simulate_transcript(&mut rand::thread_rng()).1,
                        &p_resp,
                    )?;
                    cursor += serialized.len();

                    commitments.push(p_commit);
                    responses.push(p_resp);
                }
                Ok((
                    ProtocolCommitment::And(commitments),
                    ProtocolResponse::And(responses),
                ))
            }
            Protocol::Or(ps) => {
                let mut cursor = 0;
                let mut commitments = Vec::with_capacity(ps.len());
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());

                let ch_bytes_len = <<G as Group>::Scalar as PrimeField>::Repr::default()
                    .as_ref()
                    .len();

                for p in ps.iter() {
                    let (c, r) = p.deserialize_batchable(&data[cursor..])?;

                    let serialized_cr = p.serialize_batchable(
                        &c,
                        &p.simulate_transcript(&mut rand::thread_rng()).1,
                        &r,
                    )?;
                    cursor += serialized_cr.len();

                    if data.len() < cursor + ch_bytes_len {
                        return Err(Error::ProofSizeMismatch);
                    }
                    let ch_bytes = &data[cursor..cursor + ch_bytes_len];
                    let ch = deserialize_scalar::<G>(ch_bytes)?;
                    cursor += ch_bytes_len;

                    commitments.push(c);
                    responses.push(r);
                    challenges.push(ch);
                }

                Ok((
                    ProtocolCommitment::Or(commitments),
                    ProtocolResponse::Or(challenges, responses),
                ))
            }
        }
    }
}

impl<G: Group + GroupEncoding> SigmaProtocolSimulator for Protocol<G> {
    fn simulate_proof(
        &self,
        challenge: &Self::Challenge,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> (Self::Commitment, Self::Response) {
        match self {
            Protocol::Simple(p) => {
                let (c, r) = p.simulate_proof(challenge, rng);
                (ProtocolCommitment::Simple(c), ProtocolResponse::Simple(r))
            }
            Protocol::And(ps) => {
                let mut commitments = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());

                for p in ps.iter() {
                    let (c, r) = p.simulate_proof(challenge, rng);
                    commitments.push(c);
                    responses.push(r);
                }
                (
                    ProtocolCommitment::And(commitments),
                    ProtocolResponse::And(responses),
                )
            }
            Protocol::Or(ps) => {
                let mut commitments = Vec::with_capacity(ps.len());
                let mut challenges = Vec::new();
                let mut responses = Vec::with_capacity(ps.len());

                for i in 0..(ps.len() - 1) {
                    let (c, ch, r) = ps[i].simulate_transcript(rng);
                    commitments.push(c);
                    challenges.push(ch);
                    responses.push(r);
                }
                let last_ch: <G as Group>::Scalar = challenges.iter().map(|sc| sc).sum();
                let (last_c, last_r) = ps[ps.len() - 1].simulate_proof(&last_ch, rng);
                commitments.push(last_c);
                challenges.push(last_ch);
                responses.push(last_r);

                (
                    ProtocolCommitment::Or(commitments),
                    ProtocolResponse::Or(challenges, responses),
                )
            }
        }
    }

    fn simulate_transcript(
        &self,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> (Self::Commitment, Self::Challenge, Self::Response) {
        match self {
            Protocol::Simple(p) => {
                let (c, ch, r) = p.simulate_transcript(rng);
                (
                    ProtocolCommitment::Simple(c),
                    ch,
                    ProtocolResponse::Simple(r),
                )
            }
            Protocol::And(ps) => {
                let mut commitments = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());

                let (c, challenge, r) = ps[0].simulate_transcript(rng);
                commitments.push(c);
                responses.push(r);

                for i in 1..ps.len() {
                    let (c, r) = ps[i].simulate_proof(&challenge, rng);
                    commitments.push(c);
                    responses.push(r);
                }
                (
                    ProtocolCommitment::And(commitments),
                    challenge,
                    ProtocolResponse::And(responses),
                )
            }
            Protocol::Or(ps) => {
                let mut commitments = Vec::with_capacity(ps.len());
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());

                for p in ps.iter() {
                    let (c, ch, r) = p.simulate_transcript(rng);
                    commitments.push(c);
                    challenges.push(ch);
                    responses.push(r);
                }
                let challenge = challenges.iter().map(|sc| sc).sum();
                (
                    ProtocolCommitment::Or(commitments),
                    challenge,
                    ProtocolResponse::Or(challenges, responses),
                )
            }
        }
    }
}

impl<G, C> FiatShamir<C> for Protocol<G> 
where 
    G: Group + GroupEncoding,
    C: Codec<Challenge = ProtocolChallenge<G>>
{
    fn push_commitment(
        &self,
        codec: &mut C,
        commitment: &Self::Commitment
    ) -> Result<(), ()> {
        match (self, commitment) {
            (Protocol::Simple(p), ProtocolCommitment::Simple(c)) => {
                p.push_commitment(codec, c)
            },
            (Protocol::And(ps), ProtocolCommitment::And(cs)) => {
                for (i, p) in ps.iter().enumerate() {
                    p.push_commitment(codec, &cs[i])?;
                }
                Ok(())
            }
            (Protocol::Or(ps), ProtocolCommitment::Or(cs)) => {
                for (i, p) in ps.iter().enumerate() {
                    p.push_commitment(codec, &cs[i])?;
                }
                Ok(())
            }
            _ => panic!()
        }
    }
    
    fn get_challenge(
        &self,
        codec: &mut C
    ) -> Result<Self::Challenge, Error> {
        Ok(codec.verifier_challenge())
    }
}