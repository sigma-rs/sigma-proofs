use crate::toolbox::sigma::SigmaProtocol;
use rand::{CryptoRng, Rng};
use group::Group;

pub trait GroupMorphism {
    type Domain: Group;
    type Codomain: Group;

    fn map(&self, x: &Self::Domain) -> Self::Codomain;
}

pub struct SchnorrPreimage<M: GroupMorphism> {
    pub morphism: M,
    pub target: M::Codomain,
}

impl<M: GroupMorphism> SigmaProtocol for SchnorrPreimage<M> {
    type Witness = <M as GroupMorphism>::Domain;    // Morphism Domain type
    type Commitment = <M as GroupMorphism>::Codomain;   // Morphism Codomain type
    type ProverState = (<M as GroupMorphism>::Domain, <M as GroupMorphism>::Domain);
    type Response = <M as GroupMorphism>::Domain;
    type Challenge = u64;


    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        let r = Self::Witness::random(rng);
        let R: Self::Commitment = self.morphism.map(&r);
        (R, (r, *witness))
    }

    fn prover_response(
        &self,
        state: &Self::ProverState,
        challenge: &Self::Challenge, // Method to implement
    ) -> Self::Response {
        let (r, x) = *state;
        // Convert challenge to Domain::Scalar
        let challenge_scalar = <<M as GroupMorphism>::Domain as Group>::Scalar::from(*challenge);
        x * challenge_scalar + r
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> bool {
        // Convert challenge to Codomain::Scalar
        let challenge_scalar = <<M as GroupMorphism>::Codomain as Group>::Scalar::from(*challenge);
        self.morphism.map(response) == self.target * challenge_scalar + commitment
    }

    fn simulate_proof(
        &self,
        challenge: &Self::Challenge,
        rng: &mut (impl Rng + CryptoRng)
    ) -> (Self::Commitment, Self::Response) {
        let z = Self::Response::random(rng);
        // Convert challenge to Codomain::Scalar
        let challenge_scalar = <<M as GroupMorphism>::Codomain as Group>::Scalar::from(*challenge);
        let R = self.morphism.map(&z) - self.target * challenge_scalar;
        (R, z)
    }
}