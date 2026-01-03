use ff::{Field, PrimeField};
use sha3::{Digest, Sha3_512};
use subtle::{Choice, ConditionallySelectable};

use crate::{
    errors::Error,
    serialization::{deserialize_scalars, serialize_scalars},
    traits::{SigmaProtocol, SigmaProtocolSimulator},
};

// TODO: Should this perhaps be based around a tuple or (hybrid) array instead?
#[derive(Clone)]
pub struct Or<R>(Vec<R>);

// TODO: If we move the valid flag out of this struct, then we may be able to ensure the only-one
// constraint without as much trouble.
pub struct OrProverState<R: SigmaProtocol> {
    valid: Choice,
    state: R::ProverState,
    simulated_challenge: R::Challenge,
    simulated_response: R::Response,
}

impl<R> SigmaProtocol for Or<R>
where
    R: SigmaProtocol + SigmaProtocolSimulator,
    R::Commitment: ConditionallySelectable,
    R::Response: ConditionallySelectable,
    R::Challenge: PrimeField,
{
    type Commitment = Vec<R::Commitment>;
    type ProverState = Vec<OrProverState<R>>;
    // Response contains one fewer challenge than there are branches in the or proof.
    // TODO: Can we encode that into the type system?
    type Response = (Vec<R::Challenge>, Vec<R::Response>);
    type Witness = Vec<R::Witness>;
    type Challenge = R::Challenge;

    fn prover_commit(
        &self,
        witness: Self::Witness,
        rng: &mut (impl rand::Rng + rand::CryptoRng),
    ) -> Result<(Self::Commitment, Self::ProverState), Error> {
        if self.0.len() != witness.len() {
            return Err(Error::InvalidInstanceWitnessPair);
        }

        let mut commitments = Vec::new();
        let mut prover_states = Vec::new();

        // Selector value set when the first valid witness is found.
        let mut valid_witness_found = Choice::from(0);
        for (i, w) in witness.into_iter().enumerate() {
            // Determine whether or not to use the real witness for this relation. This rule uses
            // the first valid witness found in the given list.
            // TODO: Checking the validity of the witness takes a non-trvial amount of time. Is
            // there a way to implement Or proving without this while maintaining
            // constant-timedness and decent API ergonomics?
            let select_witness = self.0[i].is_witness_valid(&w) & !valid_witness_found;

            let (commitment, prover_state) = self.0[i].prover_commit(w, rng)?;
            let (simulated_commitment, simulated_challenge, simulated_response) =
                self.0[i].simulate_transcript(rng)?;

            let commitment = R::Commitment::conditional_select(
                &simulated_commitment,
                &commitment,
                select_witness,
            );

            commitments.push(commitment);
            prover_states.push(OrProverState {
                valid: select_witness,
                state: prover_state,
                simulated_challenge,
                simulated_response,
            });

            valid_witness_found |= select_witness;
        }

        if valid_witness_found.unwrap_u8() == 0 {
            Err(Error::InvalidInstanceWitnessPair)
        } else {
            Ok((commitments, prover_states))
        }
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::Response, crate::errors::Error> {
        let mut result_challenges = Vec::with_capacity(self.0.len());
        let mut result_responses = Vec::with_capacity(self.0.len());

        let mut witness_challenge = *challenge;
        for OrProverState {
            valid,
            state: _prover_state,
            simulated_challenge,
            simulated_response: _simulated_response,
        } in &state
        {
            let c =
                R::Challenge::conditional_select(simulated_challenge, &R::Challenge::ZERO, *valid);
            witness_challenge -= c;
        }
        for (
            instance,
            OrProverState {
                valid,
                state,
                simulated_challenge,
                simulated_response,
            },
        ) in self.0.iter().zip(state)
        {
            let challenge_i =
                R::Challenge::conditional_select(&simulated_challenge, &witness_challenge, valid);

            let response = instance.prover_response(state, &challenge_i)?;
            let response = R::Response::conditional_select(&simulated_response, &response, valid);

            result_challenges.push(challenge_i);
            result_responses.push(response);
        }

        result_challenges.pop();
        Ok((result_challenges, result_responses))
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), crate::errors::Error> {
        let last_challenge = *challenge - response.0.iter().sum::<R::Challenge>();
        self.0
            .iter()
            .zip(commitment)
            .zip(response.0.iter().chain(&Some(last_challenge)))
            .zip(&response.1)
            .try_for_each(|(((p, commitment), challenge), response)| {
                p.verifier(commitment, challenge, response)
            })
    }

    fn serialize_commitment(&self, commitment: &Self::Commitment) -> Vec<u8> {
        itertools::zip_eq(&self.0, commitment)
            .flat_map(|(relation, commitment)| relation.serialize_commitment(commitment))
            .collect()
    }

    fn serialize_challenge(&self, challenge: &Self::Challenge) -> Vec<u8> {
        serialize_scalars(&[*challenge])
    }

    fn serialize_response(&self, response: &Self::Response) -> Vec<u8> {
        let mut bytes = Vec::new();

        // write challenges first
        for (x, c) in self.0.iter().zip(&response.0) {
            bytes.extend(x.serialize_challenge(c));
        }

        for (x, r) in self.0.iter().zip(&response.1) {
            bytes.extend(x.serialize_response(r));
        }

        bytes
    }

    fn deserialize_commitment(
        &self,
        data: &mut &[u8],
    ) -> Result<Self::Commitment, crate::errors::Error> {
        self.0
            .iter()
            .map(|relation| relation.deserialize_commitment(data))
            .collect()
    }

    fn deserialize_challenge(
        &self,
        data: &mut &[u8],
    ) -> Result<Self::Challenge, crate::errors::Error> {
        Ok(deserialize_scalars(data, 1).ok_or(Error::VerificationFailure)?[0])
    }

    fn deserialize_response(
        &self,
        data: &mut &[u8],
    ) -> Result<Self::Response, crate::errors::Error> {
        let challenges = deserialize_scalars(data, self.0.len().checked_sub(1).unwrap())
            .ok_or(Error::VerificationFailure)?;

        let mut responses = Vec::with_capacity(self.0.len());
        for p in &self.0 {
            let r = p.deserialize_response(data)?;
            responses.push(r);
        }
        Ok((challenges, responses))
    }

    fn protocol_identifier(&self) -> [u8; 64] {
        let mut hasher = Sha3_512::new();
        hasher.update([2u8; 32]);
        for p in &self.0 {
            hasher.update(p.protocol_identifier().as_ref());
        }
        let mut protocol_id = [0u8; 64];
        protocol_id.clone_from_slice(&hasher.finalize());
        protocol_id
    }

    fn instance_label(&self) -> impl AsRef<[u8]> {
        let mut bytes = Vec::new();
        for p in &self.0 {
            bytes.extend(p.instance_label().as_ref());
        }
        bytes
    }
}
