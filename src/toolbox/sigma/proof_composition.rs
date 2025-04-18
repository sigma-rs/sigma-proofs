use std::marker::PhantomData;

use crate::toolbox::sigma::SigmaProtocol;
use rand::{Rng, CryptoRng};
use group::{Group, ff::Field};


pub struct AndProof<P, G> 
where
    G: Group,
    P: SigmaProtocol<G>
{
    pub protocols: Vec<P>,
    _group: PhantomData<G>
}

impl<P, G> AndProof<P, G>
where
    G: Group,
    P: SigmaProtocol<G>,
{
    pub fn new(protocols: Vec<P>) -> Self {
        Self {
            protocols,
            _group: std::marker::PhantomData,
        }
    }
}

impl<P, G> Default for AndProof<P, G>
where
    G: Group,
    P: SigmaProtocol<G>,
{
    fn default() -> Self {
        Self {
            protocols: Vec::new(),
            _group: PhantomData,
        }
    }
}

impl<P, G> SigmaProtocol<G> for AndProof<P,G> 
where 
    P: SigmaProtocol<G>,
    G: Group
     {
    type Commitment = Vec<P::Commitment>;
    type ProverState = Vec<P::ProverState>;
    type Response = Vec<P::Response>;
    type Witness = Vec<P::Witness>;

    fn prover_commit(
        &self,
        witnesses: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        assert_eq!(self.protocols.len(), witnesses.len());

        let mut commitments = Vec::with_capacity(self.protocols.len());
        let mut states = Vec::with_capacity(self.protocols.len());

        for (protocol, witness) in self.protocols.iter().zip(witnesses.iter()) {
            let (commit, state) = protocol.prover_commit(witness, rng);
            commitments.push(commit);
            states.push(state);
        }

        (commitments, states)
    }

    fn prover_response(
            &self,
            state: &Self::ProverState,
            challenge: &G::Scalar,
        ) -> Self::Response {

        self.protocols
        .iter()
        .zip(state.iter())
        .map(|(protocol, state)| protocol.prover_response(state, challenge))
        .collect()
    }

    fn verifier(
            &self,
            commitment: &Self::Commitment,
            challenge: &G::Scalar,
            response: &Self::Response,
        ) -> bool {
        
        self.protocols
        .iter()
        .zip(commitment.iter())
        .zip(response.iter())
        .all(|((protocol, commit), response)| {
            protocol.verifier(commit, challenge, response)
        })
    }
}

pub struct OrProof<P, G>
where
    P: SigmaProtocol<G>,
    G: Group 
{
    pub protocols: [P;2],
    _group: PhantomData<G>
}

impl<P, G> OrProof<P, G>
where
    G: Group,
    P: SigmaProtocol<G>,
{
    pub fn new(protocols: [P;2]) -> Self {
        Self {
            protocols,
            _group: std::marker::PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct OrProofState<P, G>
where 
    P: SigmaProtocol<G>,
    G: Group {
    real_index: usize, // Index of the real proof
    real_state: P::ProverState, // Scalar commitment of the prover
    _fake_commit: P::Commitment, // Simulated commit created by simulate_proof
    fake_challenge: G::Scalar, // Simulated challenge created at random
    fake_response: P::Response // Simutaled response created vy simulate_proof
}

impl<P,G> SigmaProtocol<G> for OrProof<P,G> 
where 
    P: SigmaProtocol<G>,
    P::Commitment: Clone,
    P::Response: Clone,
    G: Group
    {
    type Commitment = [P::Commitment; 2]; // Both commitments in order
    type ProverState = OrProofState<P,G>;
    type Response = ([P::Response; 2], G::Scalar); // The two responses, and the derived challenge
    type Witness = (usize, P::Witness); // Index of the witness and witness

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        let (real_index, real_witness) = witness;

        // Simulate the fake proof
        let fake_index = 1 - real_index;
        let fake_challenge = G::Scalar::random(&mut *rng);
        let (_fake_commit, fake_response) = self.protocols[fake_index].simulate_proof(&fake_challenge, rng);

        // Real commitment
        let (real_commit, real_state) = self.protocols[*real_index].prover_commit(real_witness, rng);

        // Order commitments
        let mut commitments = [_fake_commit.clone(), real_commit];
        if *real_index == 0 {
            commitments.swap(0,1);
        }

        let prover_state = OrProofState {
            real_index: *real_index, 
            real_state, 
            _fake_commit, 
            fake_challenge, 
            fake_response
        };
        (commitments, prover_state)
    }

    fn prover_response(
        &self,
        state: &Self::ProverState,
        challenge: &G::Scalar,
    ) -> Self::Response {
        let real_challenge = *challenge - state.fake_challenge;

        let real_response = self.protocols[state.real_index].prover_response(&state.real_state, &real_challenge);

        let mut responses = [state.fake_response.clone(), real_response];
        if state.real_index == 0 {
            responses.swap(0,1);
            return (responses, real_challenge);
        }
        (responses, state.fake_challenge)
    }

    fn verifier(
        &self,
        commitments: &Self::Commitment,
        challenge: &G::Scalar,
        responses: &Self::Response,
    ) -> bool {
        let ([response_0, response_1], challenge_0) = responses;
        let challenge_1 = *challenge - challenge_0;

        self.protocols[0].verifier(&commitments[0], challenge_0, response_0) && self.protocols[1].verifier(&commitments[1], &challenge_1, response_1)
    }
    
}