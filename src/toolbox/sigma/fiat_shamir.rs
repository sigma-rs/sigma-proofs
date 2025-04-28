use rand::{RngCore, CryptoRng};
use crate::toolbox::sigma::SigmaProtocol;
use crate::toolbox::sigma::transcript::TranscriptCodec;
use group::Group;

pub struct NISigmaProtocol<P, C, G>
where
    G: Group,
    P: SigmaProtocol<Commitment = Vec<G>, Challenge = <G as Group>::Scalar>,
    C: TranscriptCodec<G>,
{
    domain_sep: Vec<u8>,
    hash_state: C,
    sigmap: P,
}

impl<P, C, G> NISigmaProtocol<P, C, G>
where
    G: Group,
    P: SigmaProtocol<Commitment = Vec<G>, Challenge = <G as Group>::Scalar>,
    C: TranscriptCodec<G>,
{
    // Create new NIZK transformator.
    pub fn new(iv: &[u8], instance: P) -> Self {
        let domain_sep = iv.to_vec();
        let hash_state = C::new(iv);
        Self { domain_sep, hash_state, sigmap: instance }
    }

    // Generate new non-interactive proof
    pub fn prove(
        &mut self,
        witness: &P::Witness,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Vec<u8> {
        self.hash_state = C::new(&self.domain_sep);

        let (commitment, prover_state) = self.sigmap.prover_commit(witness, rng);
        // Fiat Shamir challenge
        let challenge = self
            .hash_state
            .prover_message(&commitment)
            .verifier_challenge();
        println!("Prover's challenge : {:?}", challenge);
        // Prouver's response
        let response = self.sigmap.prover_response(&prover_state, &challenge);
        // Local verification of the proof
        assert!(self.sigmap.verifier(&commitment, &challenge, &response) == Ok(()));
        self.sigmap.serialize_batchable(&commitment, &challenge, &response)
    }

    /// Verification of non-interactive proof
    pub fn verify(&mut self, proof: &Vec<u8>) -> Result<(), ()> {
        self.hash_state = C::new(&self.domain_sep);

        let (commitment, response) = self.sigmap.deserialize_batchable(proof).unwrap();
        // Recompute the challenge
        let challenge = self
            .hash_state
            .prover_message(&commitment)
            .verifier_challenge();
        println!("Verifier's challenge : {:?}", challenge);
        // Verification of the proof
        self.sigmap.verifier(&commitment, &challenge, &response)

    }
}