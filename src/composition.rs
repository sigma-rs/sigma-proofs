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
use subtle::CtOption;

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

impl<G: PrimeGroup> From<SchnorrProof<G>> for ComposedRelation<G> {
    fn from(value: SchnorrProof<G>) -> Self {
        ComposedRelation::Simple(value)
    }
}

impl<G: PrimeGroup> From<LinearRelation<G>> for ComposedRelation<G> {
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
pub enum ComposedProverState<G: PrimeGroup> {
    Simple(<SchnorrProof<G> as SigmaProtocol>::ProverState),
    And(Vec<ComposedProverState<G>>),
    Or(ComposedOrProverState<G>),
}

type ComposedOrProverState<G> = (
    Vec<Option<ComposedProverState<G>>>,
    Vec<Option<ComposedChallenge<G>>>,
    Vec<Option<ComposedResponse<G>>>,
);

// Structure representing the Response type of Protocol as SigmaProtocol
#[derive(Clone)]
pub enum ComposedResponse<G: PrimeGroup> {
    Simple(<SchnorrProof<G> as SigmaProtocol>::Response),
    And(Vec<ComposedResponse<G>>),
    Or(Vec<ComposedChallenge<G>>, Vec<ComposedResponse<G>>),
}

// Structure representing the Witness type of Protocol as SigmaProtocol
#[derive(Clone)]
pub enum ComposedWitness<G: PrimeGroup> {
    Simple(<SchnorrProof<G> as SigmaProtocol>::Witness),
    And(Vec<ComposedWitness<G>>),
    Or(Vec<CtOption<ComposedWitness<G>>>),
}

type ComposedChallenge<G> = <SchnorrProof<G> as SigmaProtocol>::Challenge;

const fn composed_challenge_size<G: PrimeGroup>() -> usize {
    (G::Scalar::NUM_BITS as usize + 7) / 8
}

impl<G: PrimeGroup> ComposedRelation<G> {
    fn prover_commit_simple(
        protocol: &SchnorrProof<G>,
        witness: &<SchnorrProof<G> as SigmaProtocol>::Witness,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Result<(ComposedCommitment<G>, ComposedProverState<G>), Error> {
        protocol.prover_commit(witness, rng).map(|(c, s)| {
            (
                ComposedCommitment::Simple(c),
                ComposedProverState::Simple(s),
            )
        })
    }

    fn prover_response_simple(
        instance: &SchnorrProof<G>,
        state: <SchnorrProof<G> as SigmaProtocol>::ProverState,
        challenge: &<SchnorrProof<G> as SigmaProtocol>::Challenge,
    ) -> Result<ComposedResponse<G>, Error> {
        instance
            .prover_response(state, challenge)
            .map(ComposedResponse::Simple)
    }

    fn prover_commit_and(
        protocols: &[ComposedRelation<G>],
        witnesses: &[ComposedWitness<G>],
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Result<(ComposedCommitment<G>, ComposedProverState<G>), Error> {
        if protocols.len() != witnesses.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let mut commitments = Vec::with_capacity(protocols.len());
        let mut prover_states = Vec::with_capacity(protocols.len());

        for (p, w) in protocols.iter().zip(witnesses.iter()) {
            let (c, s) = p.prover_commit(w, rng)?;
            commitments.push(c);
            prover_states.push(s);
        }

        Ok((
            ComposedCommitment::And(commitments),
            ComposedProverState::And(prover_states),
        ))
    }

    fn prover_response_and(
        instances: &[ComposedRelation<G>],
        prover_state: Vec<ComposedProverState<G>>,
        challenge: &ComposedChallenge<G>,
    ) -> Result<ComposedResponse<G>, Error> {
        if instances.len() != prover_state.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let responses: Result<Vec<_>, _> = instances
            .iter()
            .zip(prover_state)
            .map(|(p, s)| p.prover_response(s, challenge))
            .collect();

        Ok(ComposedResponse::And(responses?))
    }

    fn prover_commit_or(
        instances: &[ComposedRelation<G>],
        witnesses: &[CtOption<ComposedWitness<G>>],
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Result<(ComposedCommitment<G>, ComposedProverState<G>), Error> {
        if instances.len() != witnesses.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let mut simulated_challenges = Vec::new();
        let mut simulated_responses = Vec::new();
        let mut commitments = Vec::<ComposedCommitment<G>>::with_capacity(instances.len());
        let mut prover_states = Vec::new();

        for (i, witness) in witnesses.iter().enumerate() {
            // let (simulated_commitment, simulated_challenge, simulated_response) = instances[i].simulate_transcript(rng)?;
            let witness = witness.clone().into_option();
            match witness {
                Some(w) => {
                    let (commitment, prover_state) = instances[i].prover_commit(&w, rng)?;
                    commitments.push(commitment);
                    prover_states.push(Some(prover_state));
                    simulated_challenges.push(None);
                    simulated_responses.push(None);
                }
                None => {
                    let (simulated_commitment, simulated_challenge, simulated_response) =
                        instances[i].simulate_transcript(rng)?;
                    commitments.push(simulated_commitment);
                    prover_states.push(None);
                    simulated_challenges.push(Some(simulated_challenge));
                    simulated_responses.push(Some(simulated_response));
                }
            }
        }
        let prover_state: ComposedOrProverState<G> =
            (prover_states, simulated_challenges, simulated_responses);
        Ok((
            ComposedCommitment::Or(commitments),
            ComposedProverState::Or(prover_state),
        ))
    }

    fn prover_response_or(
        instances: &[ComposedRelation<G>],
        prover_state: ComposedOrProverState<G>,
        &challenge: &ComposedChallenge<G>,
    ) -> Result<ComposedResponse<G>, Error> {
        let mut result_challenges = Vec::with_capacity(instances.len());
        let mut result_responses = Vec::with_capacity(instances.len());

        // Calculate the real challenge by subtracting all simulated challenges
        let (child_states, simulated_challenges, simulated_responses) = prover_state;

        let real_challenge = challenge - simulated_challenges.iter().flatten().sum::<G::Scalar>();

        let it = instances
            .iter()
            .zip(child_states)
            .zip(simulated_challenges)
            .zip(simulated_responses);
        for (((i, prover_state), simulated_challenge), simulated_response) in it {
            if let Some(state) = prover_state {
                // Real case: compute response with real challenge
                let response = i.prover_response(state, &real_challenge)?;
                result_challenges.push(real_challenge);
                result_responses.push(response);
            } else {
                result_challenges.push(simulated_challenge.unwrap());
                result_responses.push(simulated_response.unwrap());
            }
        }
        result_challenges.pop();

        Ok(ComposedResponse::Or(result_challenges, result_responses))
    }
}

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
                Self::prover_commit_simple(p, w, rng)
            }
            (ComposedRelation::And(ps), ComposedWitness::And(ws)) => {
                Self::prover_commit_and(ps, ws, rng)
            }
            (ComposedRelation::Or(ps), ComposedWitness::Or(witnesses)) => {
                Self::prover_commit_or(ps, witnesses, rng)
            }
            _ => Err(Error::InvalidInstanceWitnessPair),
        }
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, Error> {
        match (self, state) {
            (ComposedRelation::Simple(instance), ComposedProverState::Simple(state)) => {
                Self::prover_response_simple(instance, state, challenge)
            }
            (ComposedRelation::And(instances), ComposedProverState::And(prover_state)) => {
                Self::prover_response_and(instances, prover_state, challenge)
            }
            (ComposedRelation::Or(instances), ComposedProverState::Or(prover_state)) => {
                Self::prover_response_or(instances, prover_state, challenge)
            }
            _ => Err(Error::InvalidInstanceWitnessPair),
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
                let last_challenge = *challenge - challenges.iter().sum::<G::Scalar>();
                ps.iter()
                    .zip(commitments)
                    .zip(challenges.iter().chain(&Some(last_challenge)))
                    .zip(responses)
                    .try_for_each(|(((p, commitment), challenge), response)| {
                        p.verifier(commitment, challenge, response)
                    })
            }
            _ => Err(Error::InvalidInstanceWitnessPair),
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
            _ => unreachable!(),
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
            (ComposedRelation::Or(instances), ComposedResponse::Or(challenges, responses)) => {
                let mut bytes = Vec::new();

                // write challenges first
                for (x, c) in instances.iter().zip(challenges) {
                    bytes.extend(x.serialize_challenge(c));
                }

                for (x, r) in instances.iter().zip(responses) {
                    bytes.extend(x.serialize_response(r));
                }

                bytes
            }
            _ => unreachable!(),
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
                let ch_bytes_len = composed_challenge_size::<G>();
                let challenges_size = (ps.len() - 1) * ch_bytes_len;
                let challenges_bytes = &data[..challenges_size];
                let response_bytes = &data[challenges_size..];
                let challenges = deserialize_scalars::<G>(challenges_bytes, ps.len() - 1)
                    .ok_or(Error::VerificationFailure)?;

                let mut cursor = 0;
                let mut responses = Vec::with_capacity(ps.len());
                for p in ps {
                    let r = p.deserialize_response(&response_bytes[cursor..])?;
                    let size = p.serialize_response(&r).len();
                    cursor += size;
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
                let last_challenge = *challenge - challenges.iter().sum::<G::Scalar>();
                let commitments = ps
                    .iter()
                    .zip(challenges.iter().chain(&Some(last_challenge)))
                    .zip(rs)
                    .map(|((p, ch), r)| p.simulate_commitment(ch, r))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ComposedCommitment::Or(commitments))
            }
            _ => unreachable!(),
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
