use crate::toolbox::sigma::SigmaProtocol;
use rand::{Rng, CryptoRng};
use curve25519_dalek::{Scalar};

pub struct AndProof<P: SigmaProtocol> {
    pub protocols: Vec<P>,
}

impl<P> SigmaProtocol for AndProof<P> where P: SigmaProtocol {
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
            challenge: &Scalar,
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
            challenge: &Scalar,
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

pub struct OrProof<P: SigmaProtocol> {
    pub protocols: [P;2]
}
#[derive(Clone)]
pub struct OrProofState<P: SigmaProtocol> {
    real_index: usize, // Index of the real proof
    real_state: P::ProverState, // Scalar commitment of the prover
    fake_commit: P::Commitment, // Simulated commit created by simulate_proof
    fake_challenge: Scalar, // Simulated challenge created at random
    fake_response: P::Response // Simutaled response created vy simulate_proof
}

impl<P> SigmaProtocol for OrProof<P> 
where 
    P: SigmaProtocol,
    P::Commitment: Clone,
    P::Response: Clone 
    {
    type Commitment = [P::Commitment; 2]; // Both commitments in order
    type ProverState = OrProofState<P>;
    type Response = ([P::Response; 2], Scalar); // The two responses, and the derived challenge
    type Witness = (usize, P::Witness); // Index of the witness and witness

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        let (real_index, real_witness) = witness;

        // Simulate the fake proof
        let fake_index = 1 - real_index;
        let fake_challenge = Scalar::random(rng);
        let (fake_commit, fake_response) = self.protocols[fake_index].simulate_proof(&fake_challenge, rng);

        // Real commitment
        let (real_commit, real_state) = self.protocols[*real_index].prover_commit(real_witness, rng);

        // Order commitments
        let mut commitments = [fake_commit.clone(), real_commit];
        if *real_index == 0 {
            commitments.swap(0,1);
        }

        let prover_state = OrProofState {
            real_index: *real_index, 
            real_state, 
            fake_commit, 
            fake_challenge, 
            fake_response
        };
        (commitments, prover_state)
    }

    fn prover_response(
        &self,
        state: &Self::ProverState,
        challenge: &Scalar,
    ) -> Self::Response {
        let real_challenge = challenge - state.fake_challenge;

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
        challenge: &Scalar,
        responses: &Self::Response,
    ) -> bool {
        let ([response_0, response_1], challenge_0) = responses;
        let challenge_1 = challenge - challenge_0;

        self.protocols[0].verifier(&commitments[0], challenge_0, response_0) && self.protocols[1].verifier(&commitments[1], &challenge_1, response_1)
    }
    
}