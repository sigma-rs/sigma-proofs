//! # Protocol Composition with AND/OR Logic
//!
//! This module defines the [`ComposedRelation`] enum, which generalizes the [`SchnorrProof`]
//! by enabling compositional logic between multiple proof instances.
//!
//! Specifically, it supports:
//! - Simple atomic proofs (e.g., discrete logarithm, Pedersen commitments)
//! - Conjunctions (`And`) of multiple sub-protocols
//! - Disjunctions (`Or`) of multiple sub-protocols
//!
//! ## Example Composition
//!
//! ```ignore
//! And(
//!    Or(dleq, pedersen_commitment),
//!    Simple(discrete_logarithm),
//!    And(pedersen_commitment_dleq, bbs_blind_commitment_computation)
//! )
//! ```

use ff::{Field, PrimeField};
use group::prime::PrimeGroup;
use sha3::Digest;
use sha3::Sha3_256;

use crate::{
    codec::Shake128DuplexSponge,
    errors::Error,
    fiat_shamir::Nizk,
    linear_relation::LinearRelation,
    schnorr_protocol::SchnorrProof,
    serialization::{deserialize_scalars, serialize_scalars},
    traits::{SigmaProtocol, SigmaProtocolSimulator},
};

/// A protocol proving knowledge of a witness for a composition of SchnorrProof's.
///
/// This implementation generalizes [`SchnorrProof`] by using AND/OR links.
///
/// # Type Parameters
/// - `G`: A cryptographic group implementing [`group::Group`] and [`group::GroupEncoding`].
#[derive(Clone)]
pub enum ComposedRelation<G: PrimeGroup> {
    Simple(SchnorrProof<G>),
    And(Vec<ComposedRelation<G>>),
    Or(Vec<ComposedRelation<G>>),
}

impl<G> From<SchnorrProof<G>> for ComposedRelation<G>
where
    G: PrimeGroup,
{
    fn from(value: SchnorrProof<G>) -> Self {
        ComposedRelation::Simple(value)
    }
}

impl<G> From<LinearRelation<G>> for ComposedRelation<G>
where
    G: PrimeGroup,
{
    fn from(value: LinearRelation<G>) -> Self {
        Self::Simple(
            SchnorrProof::try_from(value)
                .expect("Failed to convert LinearRelation to SchnorrProof"),
        )
    }
}

// Structure representing the Commitment type of Protocol as SigmaProtocol
#[derive(Clone)]
pub enum ComposedCommitment<G: PrimeGroup> {
    Simple(<SchnorrProof<G> as SigmaProtocol>::Commitment),
    And(Vec<ComposedCommitment<G>>),
    Or(Vec<ComposedCommitment<G>>),
}

// Structure representing the ProverState type of Protocol as SigmaProtocol
#[derive(Clone)]
pub enum ComposedProverState<G: PrimeGroup> {
    Simple(<SchnorrProof<G> as SigmaProtocol>::ProverState),
    And(Vec<ComposedProverState<G>>),
    Or(
        usize,                                                 // real index
        Vec<ComposedProverState<G>>,                           // real ProverState
        (Vec<ComposedChallenge<G>>, Vec<ComposedResponse<G>>), // simulated transcripts
    ),
}

// Structure representing the Response type of Protocol as SigmaProtocol
#[derive(Clone)]
pub enum ComposedResponse<G: PrimeGroup> {
    Simple(<SchnorrProof<G> as SigmaProtocol>::Response),
    And(Vec<ComposedResponse<G>>),
    Or(Vec<ComposedChallenge<G>>, Vec<ComposedResponse<G>>),
}

// Structure representing the Witness type of Protocol as SigmaProtocol
pub enum ComposedWitness<G: PrimeGroup> {
    Simple(<SchnorrProof<G> as SigmaProtocol>::Witness),
    And(Vec<ComposedWitness<G>>),
    Or(usize, Vec<ComposedWitness<G>>),
}

// Structure representing the Challenge type of Protocol as SigmaProtocol
type ComposedChallenge<G> = <SchnorrProof<G> as SigmaProtocol>::Challenge;

impl<G: PrimeGroup> SigmaProtocol for ComposedRelation<G> {
    type Commitment = ComposedCommitment<G>;
    type ProverState = ComposedProverState<G>;
    type Response = ComposedResponse<G>;
    type Witness = ComposedWitness<G>;
    type Challenge = ComposedChallenge<G>;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), Error> {
        match (self, witness) {
            (ComposedRelation::Simple(p), ComposedWitness::Simple(w)) => {
                p.prover_commit(w, rng).map(|(c, s)| {
                    (
                        ComposedCommitment::Simple(c),
                        ComposedProverState::Simple(s),
                    )
                })
            }
            (ComposedRelation::And(ps), ComposedWitness::And(ws)) => {
                if ps.len() != ws.len() {
                    return Err(Error::InvalidInstanceWitnessPair);
                }
                let mut commitments = Vec::with_capacity(ps.len());
                let mut prover_states = Vec::with_capacity(ps.len());

                for (p, w) in ps.iter().zip(ws.iter()) {
                    let (c, s) = p.prover_commit(w, rng)?;
                    commitments.push(c);
                    prover_states.push(s);
                }

                Ok((
                    ComposedCommitment::And(commitments),
                    ComposedProverState::And(prover_states),
                ))
            }
            (ComposedRelation::Or(ps), ComposedWitness::Or(w_index, w)) => {
                let mut commitments = Vec::new();
                let mut simulated_challenges = Vec::new();
                let mut simulated_responses = Vec::new();

                let (real_commitment, real_state) = ps[*w_index].prover_commit(&w[0], rng)?;

                for i in (0..ps.len()).filter(|i| i != w_index) {
                    let (commitment, challenge, response) = ps[i].simulate_transcript(rng)?;
                    commitments.push(commitment);
                    simulated_challenges.push(challenge);
                    simulated_responses.push(response);
                }
                commitments.insert(*w_index, real_commitment);

                Ok((
                    ComposedCommitment::Or(commitments),
                    ComposedProverState::Or(
                        *w_index,
                        vec![real_state],
                        (simulated_challenges, simulated_responses),
                    ),
                ))
            }
            _ => unreachable!(),
        }
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, Error> {
        match (self, state) {
            (ComposedRelation::Simple(p), ComposedProverState::Simple(state)) => p
                .prover_response(state, challenge)
                .map(ComposedResponse::Simple),
            (ComposedRelation::And(ps), ComposedProverState::And(states)) => {
                if ps.len() != states.len() {
                    return Err(Error::InvalidInstanceWitnessPair);
                }
                let responses: Result<Vec<_>, _> = ps
                    .iter()
                    .zip(states)
                    .map(|(p, s)| p.prover_response(s, challenge))
                    .collect();

                Ok(ComposedResponse::And(responses?))
            }
            (
                ComposedRelation::Or(ps),
                ComposedProverState::Or(
                    w_index,
                    real_state,
                    (simulated_challenges, simulated_responses),
                ),
            ) => {
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());

                let mut real_challenge = *challenge;
                for ch in &simulated_challenges {
                    real_challenge -= ch;
                }
                let real_response =
                    ps[w_index].prover_response(real_state[0].clone(), &real_challenge)?;

                for (i, _) in ps.iter().enumerate() {
                    if i == w_index {
                        challenges.push(real_challenge);
                        responses.push(real_response.clone());
                    } else {
                        let simulated_index = if i < w_index { i } else { i - 1 };
                        challenges.push(simulated_challenges[simulated_index]);
                        responses.push(simulated_responses[simulated_index].clone());
                    }
                }
                Ok(ComposedResponse::Or(challenges, responses))
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
            (
                ComposedRelation::Simple(p),
                ComposedCommitment::Simple(c),
                ComposedResponse::Simple(r),
            ) => p.verifier(c, challenge, r),
            (
                ComposedRelation::And(ps),
                ComposedCommitment::And(commitments),
                ComposedResponse::And(responses),
            ) => ps
                .iter()
                .zip(commitments)
                .zip(responses)
                .try_for_each(|((p, c), r)| p.verifier(c, challenge, r)),
            (
                ComposedRelation::Or(ps),
                ComposedCommitment::Or(commitments),
                ComposedResponse::Or(challenges, responses),
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

    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8> {
        match (self, commitment) {
            (ComposedRelation::Simple(p), ComposedCommitment::Simple(c)) => {
                p.serialize_commitment(c)
            }
            (ComposedRelation::And(ps), ComposedCommitment::And(commitments))
            | (ComposedRelation::Or(ps), ComposedCommitment::Or(commitments)) => ps
                .iter()
                .zip(commitments)
                .flat_map(|(p, c)| p.serialize_commitment(c))
                .collect(),
            _ => panic!(),
        }
    }

    fn serialize_challenge(&self, challenge: &Self::Challenge) -> Vec<u8> {
        serialize_scalars::<G>(&[*challenge])
    }

    fn instance_label(&self) -> impl AsRef<[u8]> {
        match self {
            ComposedRelation::Simple(p) => {
                let label = p.instance_label();
                label.as_ref().to_vec()
            }
            ComposedRelation::And(ps) => {
                let mut bytes = Vec::new();
                for p in ps {
                    bytes.extend(p.instance_label().as_ref());
                }
                bytes
            }
            ComposedRelation::Or(ps) => {
                let mut bytes = Vec::new();
                for p in ps {
                    bytes.extend(p.instance_label().as_ref());
                }
                bytes
            }
        }
    }

    fn protocol_identifier(&self) -> impl AsRef<[u8]> {
        let mut hasher = Sha3_256::new();

        match self {
            ComposedRelation::Simple(p) => {
                // take the digest of the simple protocol id
                hasher.update([0u8; 32]);
                hasher.update(p.protocol_identifier());
            }
            ComposedRelation::And(protocols) => {
                let mut hasher = Sha3_256::new();
                hasher.update([1u8; 32]);
                for p in protocols {
                    hasher.update(p.protocol_identifier());
                }
            }
            ComposedRelation::Or(protocols) => {
                let mut hasher = Sha3_256::new();
                hasher.update([2u8; 32]);
                for p in protocols {
                    hasher.update(p.protocol_identifier());
                }
            }
        }

        hasher.finalize()
    }

    fn serialize_response(&self, response: &Self::Response) -> Vec<u8> {
        match (self, response) {
            (ComposedRelation::Simple(p), ComposedResponse::Simple(r)) => p.serialize_response(r),
            (ComposedRelation::And(ps), ComposedResponse::And(responses)) => {
                let mut bytes = Vec::new();
                for (i, p) in ps.iter().enumerate() {
                    bytes.extend(p.serialize_response(&responses[i]));
                }
                bytes
            }
            (ComposedRelation::Or(ps), ComposedResponse::Or(challenges, responses)) => {
                let mut bytes = Vec::new();
                for (i, p) in ps.iter().enumerate() {
                    bytes.extend(&serialize_scalars::<G>(&[challenges[i]]));
                    bytes.extend(p.serialize_response(&responses[i]));
                }
                bytes
            }
            _ => panic!(),
        }
    }

    fn deserialize_commitment(&self, data: &[u8]) -> Result<Self::Commitment, Error> {
        match self {
            ComposedRelation::Simple(p) => {
                let c = p.deserialize_commitment(data)?;
                Ok(ComposedCommitment::Simple(c))
            }
            ComposedRelation::And(ps) | ComposedRelation::Or(ps) => {
                let mut cursor = 0;
                let mut commitments = Vec::with_capacity(ps.len());

                for p in ps {
                    let c = p.deserialize_commitment(&data[cursor..])?;
                    let size = p.serialize_commitment(&c).len();
                    cursor += size;
                    commitments.push(c);
                }

                Ok(match self {
                    ComposedRelation::And(_) => ComposedCommitment::And(commitments),
                    ComposedRelation::Or(_) => ComposedCommitment::Or(commitments),
                    _ => unreachable!(),
                })
            }
        }
    }

    fn deserialize_challenge(&self, data: &[u8]) -> Result<Self::Challenge, Error> {
        let scalars = deserialize_scalars::<G>(data, 1).ok_or(Error::VerificationFailure)?;
        Ok(scalars[0])
    }

    fn deserialize_response(&self, data: &[u8]) -> Result<Self::Response, Error> {
        match self {
            ComposedRelation::Simple(p) => {
                let r = p.deserialize_response(data)?;
                Ok(ComposedResponse::Simple(r))
            }
            ComposedRelation::And(ps) => {
                let mut cursor = 0;
                let mut responses = Vec::with_capacity(ps.len());
                for p in ps {
                    let r = p.deserialize_response(&data[cursor..])?;
                    let size = p.serialize_response(&r).len();
                    cursor += size;
                    responses.push(r);
                }
                Ok(ComposedResponse::And(responses))
            }
            ComposedRelation::Or(ps) => {
                let ch_bytes_len = <G::Scalar as PrimeField>::Repr::default().as_ref().len();
                let mut cursor = 0;
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());
                for p in ps {
                    let ch_vec = deserialize_scalars::<G>(&data[cursor..cursor + ch_bytes_len], 1)
                        .ok_or(Error::VerificationFailure)?;
                    let ch = ch_vec[0];
                    cursor += ch_bytes_len;
                    let r = p.deserialize_response(&data[cursor..])?;
                    let size = p.serialize_response(&r).len();
                    cursor += size;
                    challenges.push(ch);
                    responses.push(r);
                }
                Ok(ComposedResponse::Or(challenges, responses))
            }
        }
    }
}

impl<G: PrimeGroup> SigmaProtocolSimulator for ComposedRelation<G> {
    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Self::Commitment, Error> {
        match (self, response) {
            (ComposedRelation::Simple(p), ComposedResponse::Simple(r)) => Ok(
                ComposedCommitment::Simple(p.simulate_commitment(challenge, r)?),
            ),
            (ComposedRelation::And(ps), ComposedResponse::And(rs)) => {
                let commitments = ps
                    .iter()
                    .zip(rs)
                    .map(|(p, r)| p.simulate_commitment(challenge, r))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ComposedCommitment::And(commitments))
            }
            (ComposedRelation::Or(ps), ComposedResponse::Or(challenges, rs)) => {
                let commitments = ps
                    .iter()
                    .zip(challenges)
                    .zip(rs)
                    .map(|((p, ch), r)| p.simulate_commitment(ch, r))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ComposedCommitment::Or(commitments))
            }
            _ => panic!(),
        }
    }

    fn simulate_response<R: rand::Rng + rand::CryptoRng>(&self, rng: &mut R) -> Self::Response {
        match self {
            ComposedRelation::Simple(p) => ComposedResponse::Simple(p.simulate_response(rng)),
            ComposedRelation::And(ps) => {
                ComposedResponse::And(ps.iter().map(|p| p.simulate_response(rng)).collect())
            }
            ComposedRelation::Or(ps) => {
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());
                for _ in 0..ps.len() {
                    challenges.push(G::Scalar::random(&mut *rng));
                }
                for p in ps.iter() {
                    responses.push(p.simulate_response(&mut *rng));
                }
                ComposedResponse::Or(challenges, responses)
            }
        }
    }

    fn simulate_transcript<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Commitment, Self::Challenge, Self::Response), Error> {
        match self {
            ComposedRelation::Simple(p) => {
                let (c, ch, r) = p.simulate_transcript(rng)?;
                Ok((
                    ComposedCommitment::Simple(c),
                    ch,
                    ComposedResponse::Simple(r),
                ))
            }
            ComposedRelation::And(ps) => {
                let challenge = G::Scalar::random(&mut *rng);
                let mut responses = Vec::with_capacity(ps.len());
                for p in ps.iter() {
                    responses.push(p.simulate_response(&mut *rng));
                }
                let commitments = ps
                    .iter()
                    .enumerate()
                    .map(|(i, p)| p.simulate_commitment(&challenge, &responses[i]))
                    .collect::<Result<Vec<_>, Error>>()?;

                Ok((
                    ComposedCommitment::And(commitments),
                    challenge,
                    ComposedResponse::And(responses),
                ))
            }
            ComposedRelation::Or(ps) => {
                let mut commitments = Vec::with_capacity(ps.len());
                let mut challenges = Vec::with_capacity(ps.len());
                let mut responses = Vec::with_capacity(ps.len());

                for p in ps.iter() {
                    let (c, ch, r) = p.simulate_transcript(rng)?;
                    commitments.push(c);
                    challenges.push(ch);
                    responses.push(r);
                }
                let challenge = challenges.iter().sum();
                Ok((
                    ComposedCommitment::Or(commitments),
                    challenge,
                    ComposedResponse::Or(challenges, responses),
                ))
            }
        }
    }
}

impl<G: PrimeGroup> ComposedRelation<G> {
    /// Convert this Protocol into a non-interactive zero-knowledge proof
    /// using the Shake128DuplexSponge codec and a specified session identifier.
    ///
    /// This method provides a convenient way to create a NIZK from a Protocol
    /// without exposing the specific codec type to the API caller.
    ///
    /// # Parameters
    /// - `session_identifier`: Domain separator bytes for the Fiat-Shamir transform
    ///
    /// # Returns
    /// A `Nizk` instance ready for proving and verification
    pub fn into_nizk(
        self,
        session_identifier: &[u8],
    ) -> Nizk<ComposedRelation<G>, Shake128DuplexSponge<G>> {
        Nizk::new(session_identifier, self)
    }
}
