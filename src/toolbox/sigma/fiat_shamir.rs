use std::marker::PhantomData;
use rand::{RngCore, CryptoRng};
use crate::toolbox::sigma::SigmaProtocol;
use crate::toolbox::sigma::transcript::TranscriptCodec;
use group::Group;

pub struct NISigmaProtocol<P, C, G>
where
    G: Group,
    P: SigmaProtocol<Commitment = G, Challenge = <G as Group>::Scalar>,
    C: TranscriptCodec<G>,
{
    hash_state: C,
    sigmap: P,
    _marker: PhantomData<<G as Group>::Scalar>,
}

impl<P, C, G> NISigmaProtocol<P, C, G>
where
    G: Group,
    P: SigmaProtocol<Commitment = G, Challenge = <G as Group>::Scalar>,
    C: TranscriptCodec<G>,
{
    // Create new NIZK transformator.
    pub fn new(iv: &[u8], instance: P) -> Self {
        let hash_state = C::new(iv);
        Self { hash_state, sigmap: instance, _marker: PhantomData }
    }

    // Generate new non-interactive proof
    pub fn prove(
        &mut self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (G, <G as Group>::Scalar, <P as SigmaProtocol>::Response) {
        let (commitment, prover_state) = self.sigmap.prover_commit(witness, rng);
        // Fiat Shamir challenge
        let challenge = self
            .hash_state
            .prover_message(&[commitment])
            .verifier_challenge();
        // Prouver's response
        let response = self.sigmap.prover_response(&prover_state, &challenge);
        // Local verification of the proof
        assert!(self.sigmap.verifier(&commitment, &challenge, &response));
        (commitment, challenge, response)
    }

    /// Verification of non-interactive proof
    pub fn verify(&mut self, proof: (G, <G as Group>::Scalar, <P as SigmaProtocol>::Response)) -> bool {
        // Recompute the challenge
        let challenge = self
            .hash_state
            .prover_message(&[proof.0])
            .verifier_challenge();
        // Verification of challenge and the proof
        let cond0 = challenge == proof.1;
        let cond1 = self.sigmap.verifier(&proof.0, &proof.1, &proof.2);
        cond0 & cond1
        
    }
}