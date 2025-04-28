//! Implementation of the generic Schnorr Sigma Protocol over a group `G`.
//!
//! This module defines the [`SchnorrProof`] structure, which implements
//! a Sigma protocol proving different types of discrete logarithm relations (eg. Schnorr, Pedersen's commitments)
//! through a group morphism abstraction (see Maurer09).

use rand::{CryptoRng, Rng};
use group::{Group, GroupEncoding};
use ff::{PrimeField,Field};
use crate::toolbox::sigma::{SigmaProtocol, GroupMorphismPreimage};

/// A Schnorr protocol proving knowledge some discrete logarithm relation.
///
/// The specific proof instance is defined by a [`GroupMorphismPreimage`] over a group `G`.
pub struct SchnorrProof<G: Group + GroupEncoding> {
    /// The public instance and its associated group morphism.
    pub morphismp: GroupMorphismPreimage<G>,
}

/// Internal prover state during the protocol execution: (random nonce, witness)
pub struct SchnorrState<S> {
    /// Random nonces generated during commitment.
    pub nonces: Vec<S>,
    /// The witness scalars corresponding to the statement.
    pub witness: Vec<S>,
}

impl<G> SigmaProtocol for SchnorrProof<G>
where
    G: Group + GroupEncoding, 
    G::Scalar: Field + Clone,
{
    type Commitment = Vec<G>;
    type ProverState = (Vec<<G as Group>::Scalar>, Vec<<G as Group>::Scalar>);
    type Response = Vec<<G as Group>::Scalar>;
    type Witness = Vec<<G as Group>::Scalar>;
    type Challenge = <G as Group>::Scalar;

    /// Prover's first message: generates a random commitment based on random nonces.
    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        let mut nonces: Vec<G::Scalar> = Vec::new();
        for _i in 0..self.morphismp.morphism.num_scalars {
            nonces.push(<G as Group>::Scalar::random(&mut *rng));
        }
        let prover_state = (nonces.clone(), witness.clone());
        let commitment = self.morphismp.morphism.evaluate(&nonces);
        (commitment, prover_state)
    }

    /// Prover's last message: computes the response to a given challenge.
    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Self::Response {
        let mut responses = Vec::new();
        for i in 0..self.morphismp.morphism.num_scalars {
            responses.push(state.0[i] + *challenge * state.1[i]);
        }
        responses
    }

    /// Verifier checks that the provided response satisfies the verification equations.
    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ()> {
        let lhs = self.morphismp.morphism.evaluate(&response);
        let mut rhs = Vec::new();
        for i in 0..self.morphismp.morphism.num_scalars {
            rhs.push(commitment[i] + self.morphismp.morphism.group_elements[self.morphismp.image[i]] * *challenge);
        }
        match lhs == rhs {
            true => Ok(()),
            false => Err(()), 
        }
    }

    /// Serializes the proof (`commitment`, `response`) into a batchable format for transmission.
    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        _challenge: &Self::Challenge,
        response: &Self::Response
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        let scalar_nb = self.morphismp.morphism.num_scalars.clone();
        // Serialize commitments
        for i in 0..scalar_nb {
            bytes.extend_from_slice(commitment[i].to_bytes().as_ref());
        }
        // Serialize responses
        for i in 0..scalar_nb {
            bytes.extend_from_slice(response[i].to_repr().as_ref());
        }
        bytes
    }

    /// Deserializes a batchable proof format back into (`commitment`, `response`).
    fn deserialize_batchable(&self,
        data: &[u8],
    ) -> Option<(Self::Commitment, Self::Response)>
    {
        let scalar_nb = self.morphismp.morphism.num_scalars;
        let point_size = G::generator().to_bytes().as_ref().len();
        let scalar_size = <<G as Group>::Scalar as PrimeField>::Repr::default().as_ref().len();
        
        let expected_len = scalar_nb * (point_size + scalar_size);
        if data.len() != expected_len {
            return None;
        }

        let mut commitments: Self::Commitment = Vec::new();
        let mut responses: Self::Response = Vec::new();

        for i in 0..scalar_nb {
            let start = i * point_size;
            let end = start + point_size;

            let mut buf = vec![0u8; point_size];
            buf.copy_from_slice(&data[start..end]);

            let mut repr_array = G::Repr::default();
            repr_array.as_mut().copy_from_slice(&buf);
    
            let elem_ct = G::from_bytes(&repr_array);
            if !bool::from(elem_ct.is_some()) {           
                return None;
            }
            let elem = elem_ct.unwrap();
            commitments.push(elem);
        }

        for i in 0..scalar_nb {
            let start = scalar_nb * point_size + i * scalar_size;
            let end = start + scalar_size;

            let mut buf = vec![0u8; scalar_size];
            buf.copy_from_slice(&data[start..end]);
            
            let mut repr_array = <<G as Group>::Scalar as PrimeField>::Repr::default();
            repr_array.as_mut().copy_from_slice(&buf);
            
            let scalar_ct = G::Scalar::from_repr(repr_array);
            if !bool::from(scalar_ct.is_some()) {           
                return None;
            }
            let scalar = scalar_ct.unwrap();
            responses.push(scalar);
        }
    
        Some((commitments, responses)) 
    }
}