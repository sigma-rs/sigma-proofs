use rand::{CryptoRng, Rng};
use group::{Group, GroupEncoding};
use ff::{PrimeField,Field};
use crate::toolbox::sigma::SigmaProtocol;

/// A generic Schnorr protocol over a group `G` implementing the Group trait.
pub struct SchnorrProof<G: Group> {
    pub generator: G,
    pub target: G,
}

/// Internal prover state: (random nonce, witness)
pub struct SchnorrState<S> {
    pub nonces: S,
    pub witness: S,
}

impl<G> SchnorrProof<G>
where 
    G: Group + GroupEncoding
{
    pub fn serialize_batchable(commitment: &G, response: &G::Scalar) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(commitment.to_bytes().as_ref());
        bytes.extend_from_slice(response.to_repr().as_ref());
        bytes
    }

    pub fn deserialize_batchable(
        data: &[u8],
    ) -> Option<(G, G::Scalar)>
    {
        {
            let point_len = G::Repr::default().as_ref().len();
            let scalar_len = <<G as Group>::Scalar as PrimeField>::Repr::default().as_ref().len();
        
            if data.len() != point_len + scalar_len {
                return None;
            }
    
        let (commit_bytes, resp_bytes) = data.split_at(point_len);

        // 1. Deserialize group element
        let mut commit_array = G::Repr::default();
        commit_array.as_mut().copy_from_slice(commit_bytes);
        let commitment_ct = G::from_bytes(&commit_array);
        if !bool::from(commitment_ct.is_some()) {           
            return None;
        }
        let commitment = commitment_ct.unwrap();

        // 2. Deserialize scalar
        let mut scalar_array = <<G as Group>::Scalar as PrimeField>::Repr::default();
        scalar_array.as_mut().copy_from_slice(resp_bytes);
        let scalar_ct = G::Scalar::from_repr(scalar_array);
        if !bool::from(scalar_ct.is_some()) {
            return None;
        }
        let response = scalar_ct.unwrap();
    
        Some((commitment, response))
        }
    }
}

impl<G> SigmaProtocol for SchnorrProof<G>
where
    G: Group,
    G::Scalar: Field + rand::distributions::uniform::SampleUniform + Clone,
{
    type Commitment = G;
    type ProverState = SchnorrState<G::Scalar>;
    type Response = G::Scalar;
    type Witness = G::Scalar;
    type Challenge = G::Scalar;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        let r = G::Scalar::random(rng);
        let R = self.generator * r;
        (R, SchnorrState { nonces:r, witness: witness.clone() })
    }

    fn prover_response(
        &self,
        state: &Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Self::Response {
        state.nonces + *challenge * state.witness
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> bool {
        let lhs = self.generator * *response;
        let rhs = *commitment + self.target * *challenge;
        lhs == rhs
    }

    fn simulate_proof(
        &self,
        challenge: &Self::Challenge,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::Response) {
        let z = G::Scalar::random(rng);
        let R = self.generator * z - self.target * *challenge;
        (R, z)
    }
}