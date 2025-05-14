use group::Group;
use rand::{RngCore, CryptoRng};

use crate::{
    codec::{ShakeCodec},
    GroupMorphismPreimage,
    GroupSerialisation,
    NISigmaProtocol,
    SchnorrProof,
    PointVar,
    ScalarVar,
    ProofError,
};

pub struct ProofBuilder<G>
where
    G: Group + GroupSerialisation,
{
    pub protocol: NISigmaProtocol<SchnorrProof<G>, ShakeCodec<G>, G>,
}

impl<G> ProofBuilder<G>
where
    G: Group + GroupSerialisation,
{
    pub fn new(domain_sep: &[u8]) -> Self {
        let schnorr_proof = SchnorrProof(GroupMorphismPreimage::<G>::new());
        let protocol = NISigmaProtocol::<SchnorrProof<G>, ShakeCodec<G>, G>::new(domain_sep, schnorr_proof);
        Self{ protocol }
    }

    pub fn append_equation(&mut self, lhs: PointVar, rhs: &[(ScalarVar, PointVar)]) {
        self.protocol.sigmap.0.append_equation(lhs, rhs);
    }

    pub fn allocate_scalars(&mut self, n: usize) -> Vec<ScalarVar> {
        self.protocol.sigmap.0.allocate_scalars(n)
    }

    pub fn allocate_elements(&mut self, n: usize) -> Vec<PointVar> {
        self.protocol.sigmap.0.allocate_elements(n)
    }

    pub fn set_elements(&mut self, elements: &[(PointVar, G)]) {
        self.protocol.sigmap.0.set_elements(elements);
    }

    pub fn image(&self) -> Vec<G> {
        self.protocol.sigmap.0.image()
    }

    pub fn prove(&mut self, witness: &[<G as Group>::Scalar], rng: &mut (impl RngCore + CryptoRng)) -> Vec<u8> {
        let witness_tmp = witness.to_vec();
        self.protocol.prove(&witness_tmp, rng)
    }

    pub fn verify(&mut self, proof: &[u8]) -> Result<(), ProofError> {
        self.protocol.verify(proof)
    }
}